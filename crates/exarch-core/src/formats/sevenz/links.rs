//! Reading the stored targets of 7z links without extracting them.

use super::admit::RefusalScope;
use super::admit::sevenz_refusals;
use super::decode::EntryResult;
use super::decode::decode_block_entries;
use super::decode::is_sevenz_payload;
use super::decode::skip_payload;
use super::lzma2::DecodeKnobs;
use crate::ArchiveError;
use crate::EntryCompression;
use crate::Result;
use crate::SecurityConfig;
use crate::config::Validated;
use crate::copy::CopyError;
use crate::formats::common;
use crate::inspection::integrity::Charge;
use crate::inspection::integrity::DecodeFailure;
use crate::inspection::integrity::DecodeOutcome;
use crate::inspection::integrity::IntegrityPass;
use crate::inspection::integrity::Slot;
use crate::inspection::manifest::EntryPosition;
use crate::inspection::manifest::LinkTarget;
use crate::inspection::report::UnverifiedReason;
use crate::security::fs_view::LinkKind;
use crate::security::zipbomb::validate_entry_compression;
use sevenz_rust2::Archive;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io;
use std::io::Read;
use std::io::Seek;
use std::path::PathBuf;

/// A symlink target as its 7z entry stores it, consumed as soon as it is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredLinkTarget {
    /// The target, within the stored-target size limit.
    Read(PathBuf),
    /// The entry holds more bytes than a target may; none were read.
    Oversized {
        /// Size of the stored target in bytes.
        bytes: u64,
    },
}

/// Why a stored link target was not read. `list` and `verify` report such a
/// target as unreadable; `extract` fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkReadFailure {
    /// The block holding the target is refused for decoding.
    BlockRefused,
    /// The decoder failed before the target was complete.
    Decode(String),
    /// The target's data ended before its declared size.
    Truncated,
    /// The target's data failed its checksum.
    Checksum,
}

impl LinkReadFailure {
    /// Classifies a decode failure; a failing disk read is not a property of
    /// the archive and stays an error.
    fn from_decode(failure: DecodeFailure) -> Result<Self> {
        match failure {
            DecodeFailure::Checksum => Ok(Self::Checksum),
            DecodeFailure::Truncated { .. } => Ok(Self::Truncated),
            DecodeFailure::Io(e) => Err(ArchiveError::Io(e)),
            other => Ok(Self::Decode(other.to_string())),
        }
    }

    /// The error `extract` fails with for the link named `name`.
    pub(crate) fn into_extract_error(self, name: &str) -> ArchiveError {
        let why = match self {
            Self::BlockRefused => "its block is not admitted for decoding".to_owned(),
            Self::Decode(detail) => detail,
            Self::Truncated => "its data ends early".to_owned(),
            Self::Checksum => "checksum mismatch".to_owned(),
        };
        ArchiveError::InvalidArchive(format!("failed to read 7z symlink target {name}: {why}"))
    }
}

/// What reading one link's target yields: the target, or why it stays unread.
pub type LinkOutcome = std::result::Result<StoredLinkTarget, LinkReadFailure>;

/// Reads the target of the link whose data `reader` yields, `size` bytes.
///
/// A target larger than the stored-target limit is not read. Only a failing
/// disk read or a target that is not UTF-8 is an error: the former is not a
/// property of the archive, the latter is refused in every mode as in ZIP.
pub(super) fn read_sevenz_link_target(reader: &mut dyn Read, size: u64) -> Result<LinkOutcome> {
    if size > common::MAX_STORED_SYMLINK_TARGET {
        return Ok(Ok(StoredLinkTarget::Oversized { bytes: size }));
    }
    let mut bytes = Vec::new();
    match (&mut *reader).take(size).read_to_end(&mut bytes) {
        Ok(_) if bytes.len() as u64 == size => {}
        Ok(_) => return Ok(Err(LinkReadFailure::Truncated)),
        Err(e) => {
            let failure = DecodeFailure::from_copy(CopyError::Read(e), size);
            return LinkReadFailure::from_decode(failure).map(Err);
        }
    }
    common::symlink_target_from_bytes(&bytes).map(|target| Ok(StoredLinkTarget::Read(target)))
}

/// How a link entry's target is stored.
pub(super) enum LinkStorage {
    /// No data: the target is empty.
    Empty,
    /// More data than a target may hold.
    Oversized(u64),
    /// Within a block, within the limit.
    Stream,
}

pub(super) fn link_storage(file: &sevenz_rust2::ArchiveEntry) -> LinkStorage {
    if !is_sevenz_payload(file) {
        LinkStorage::Empty
    } else if file.size > common::MAX_STORED_SYMLINK_TARGET {
        LinkStorage::Oversized(file.size)
    } else {
        LinkStorage::Stream
    }
}

/// The link entries of a 7z archive keyed by archive file index.
///
/// Entries can only be added in ascending index order, so lookups can bisect
/// and every walk visits links in file order.
#[derive(Debug)]
pub struct LinkTable<T> {
    entries: Vec<(usize, T)>,
}

impl<T> Default for LinkTable<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<T> LinkTable<T> {
    /// Adds the link at `file_index`.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArchive` unless `file_index` is above every index
    /// already added.
    pub(crate) fn push(&mut self, file_index: usize, value: T) -> Result<()> {
        if self
            .entries
            .last()
            .is_some_and(|&(last, _)| last >= file_index)
        {
            return Err(ArchiveError::InvalidArchive(
                "7z link entries are out of order".into(),
            ));
        }
        self.entries.push((file_index, value));
        Ok(())
    }

    /// The value added for `file_index`, if any.
    pub(crate) fn get(&self, file_index: usize) -> Option<&T> {
        self.entries
            .binary_search_by_key(&file_index, |&(index, _)| index)
            .ok()
            .map(|at| &self.entries[at].1)
    }

    /// The archive file indices, ascending.
    pub(crate) fn indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.entries.iter().map(|&(index, _)| index)
    }
}

/// Hands `each` the targets of the links at `indices` (ascending archive file
/// indices) that need no decoding, and returns the links that do.
pub fn deliver_undecoded_links(
    archive: &Archive,
    indices: impl Iterator<Item = usize>,
    each: &mut impl FnMut(usize, LinkOutcome) -> Result<()>,
) -> Result<Vec<usize>> {
    let mut streamed = Vec::new();
    for index in indices {
        match link_storage(&archive.files[index]) {
            LinkStorage::Empty => each(index, Ok(StoredLinkTarget::Read(PathBuf::new())))?,
            LinkStorage::Oversized(bytes) => {
                each(index, Ok(StoredLinkTarget::Oversized { bytes }))?;
            }
            LinkStorage::Stream => streamed.push(index),
        }
    }
    Ok(streamed)
}

/// Marks the blocks the walk must not decode: every block under an archive
/// refusal or its own, and every block holding a file over the ratio limit.
pub(super) fn blocks_closed_to_links(
    archive: &Archive,
    compression: &[EntryCompression],
    config: &SecurityConfig<Validated>,
) -> Vec<bool> {
    let mut closed = vec![false; archive.blocks.len()];
    for refusal in sevenz_refusals(archive, config) {
        match refusal.scope {
            RefusalScope::Archive => closed.fill(true),
            RefusalScope::Block(index) => closed[index] = true,
        }
    }
    for (index, file) in archive.files.iter().enumerate() {
        if let Some(block) = archive.stream_map.file_block_index[index]
            && validate_entry_compression(&compression[index], file.size, config).is_err()
        {
            closed[block] = true;
        }
    }
    closed
}

/// Whether `error` is the checksum failure sevenz-rust2 raises for an entry
/// whose data was read to its end, which leaves the block stream aligned.
pub(super) fn is_entry_checksum_error(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<sevenz_rust2::Error>())
        .is_some_and(|inner| matches!(inner, sevenz_rust2::Error::ChecksumVerificationFailed))
}

/// Reads past a file the walk does not want, ignoring its own checksum failure
/// so the rest of its block stays aligned.
pub(super) fn drain_unwanted(
    file: &sevenz_rust2::ArchiveEntry,
    reader: &mut dyn Read,
) -> EntryResult {
    if is_sevenz_payload(file) {
        match io::copy(&mut (&mut *reader).take(file.size), &mut io::sink()) {
            Ok(_) => {}
            Err(e) if is_entry_checksum_error(&e) => {}
            Err(e) => return Err(sevenz_rust2::Error::Io(e, "link walk".into())),
        }
    }
    Ok(true)
}

/// Hands `each` the target of every link in `links`, one at a time in file
/// order, reading blocks only after the caller's header checks.
///
/// A block is decoded only when admission allows it and none of its files is
/// over the ratio limit, so decoding stays within what `extract` would admit;
/// a refused block yields [`LinkReadFailure::BlockRefused`] without any decode.
/// Files of a block that are not wanted are drained so the stream stays
/// aligned, and decoding stops after the block's last wanted link. A decoder
/// error abandons the block: its remaining links get
/// [`LinkReadFailure::Decode`]. An error returned by `each` ends the walk.
///
/// # Errors
///
/// Returns the first error of `each`, a non-UTF-8 target, or a failing disk
/// read.
pub fn walk_sevenz_links<R: Read + Seek, T>(
    archive: &Archive,
    source: &mut R,
    compression: &[EntryCompression],
    config: &SecurityConfig<Validated>,
    links: &LinkTable<T>,
    each: &mut impl FnMut(usize, LinkOutcome) -> Result<()>,
) -> Result<()> {
    let streamed = deliver_undecoded_links(archive, links.indices(), each)?;
    if streamed.is_empty() {
        return Ok(());
    }
    let closed = blocks_closed_to_links(archive, compression, config);
    let mut by_block: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for index in streamed {
        match archive.stream_map.file_block_index[index] {
            Some(block) => by_block.entry(block).or_default().push(index),
            None => each(index, Err(LinkReadFailure::BlockRefused))?,
        }
    }
    for (block, wanted) in by_block {
        if closed[block] {
            for index in wanted {
                each(index, Err(LinkReadFailure::BlockRefused))?;
            }
        } else {
            walk_block_links(archive, source, config, block, &wanted, each)?;
        }
    }
    Ok(())
}

pub(super) fn walk_block_links<R: Read + Seek>(
    archive: &Archive,
    source: &mut R,
    config: &SecurityConfig<Validated>,
    block: usize,
    wanted: &[usize],
    each: &mut impl FnMut(usize, LinkOutcome) -> Result<()>,
) -> Result<()> {
    let mut next_file = archive.stream_map.block_first_file_index[block];
    let mut delivered = 0;
    let mut abort = None;
    let result = decode_block_entries(
        source,
        archive,
        block,
        config.parallel_decode,
        DecodeKnobs::production(),
        &mut |file, reader| {
            let index = next_file;
            next_file += 1;
            if wanted.get(delivered) != Some(&index) {
                return drain_unwanted(file, reader);
            }
            let outcome = match read_sevenz_link_target(reader, file.size) {
                Ok(outcome) => outcome,
                Err(e) => {
                    abort = Some(e);
                    return Ok(false);
                }
            };
            delivered += 1;
            let aligned = !matches!(
                outcome,
                Err(LinkReadFailure::Truncated | LinkReadFailure::Decode(_))
            );
            if let Err(e) = each(index, outcome) {
                abort = Some(e);
                return Ok(false);
            }
            Ok(aligned && delivered < wanted.len())
        },
    );
    if let Some(e) = abort {
        return Err(e);
    }
    let failure = match result {
        Err(e) => LinkReadFailure::Decode(e.to_string()),
        Ok(_) => LinkReadFailure::Decode("the entry was not decoded".to_owned()),
    };
    for &index in &wanted[delivered..] {
        each(index, Err(failure.clone()))?;
    }
    Ok(())
}

/// Where an integrity pass hands the link targets it reads while decoding.
pub struct LinkCapture<'a> {
    /// The manifest position of every listed link.
    pub(crate) links: &'a LinkTable<EntryPosition>,
    /// Receives the manifest position and target of each link the pass tried
    /// to read: the target, or [`LinkTarget::Unreadable`].
    pub(crate) set: &'a mut dyn FnMut(EntryPosition, LinkTarget),
}

impl LinkCapture<'_> {
    /// The position of `file` when it is a listed link whose target sits in a
    /// block and is read here.
    fn position(
        &self,
        file_index: usize,
        file: &sevenz_rust2::ArchiveEntry,
    ) -> Option<EntryPosition> {
        matches!(link_storage(file), LinkStorage::Stream)
            .then(|| self.links.get(file_index).copied())
            .flatten()
    }

    /// Marks the listed links among the archive files at `indices`, whose
    /// blocks the pass refuses to decode, as unreadable.
    pub(super) fn mark_unreadable(
        &mut self,
        archive: &Archive,
        indices: impl Iterator<Item = usize>,
    ) {
        for index in indices {
            if let Some(position) = self.position(index, &archive.files[index]) {
                (self.set)(position, LinkTarget::Unreadable);
            }
        }
    }
}

/// Per-block state while decoding one 7z block for an integrity pass.
pub(super) struct BlockScan<'a, 'c> {
    pub(super) pass: &'a mut IntegrityPass<'c>,
    pub(super) slots: &'a [Option<Slot>],
    pub(super) links: Option<LinkCapture<'a>>,
    pub(super) next_file: usize,
    pub(super) visited: BTreeSet<usize>,
    pub(super) stop: Option<BlockStop>,
}

/// Why the scan of a block ended early.
#[derive(Debug)]
pub(super) enum BlockStop {
    /// A decode failure left the rest of the block undecodable; its remaining
    /// payload entries are unverified for this reason.
    Abandoned(UnverifiedReason),
    /// A disk read failed; not a property of the archive.
    Fatal(ArchiveError),
}

impl BlockScan<'_, '_> {
    /// Decodes one file of the block; returns whether the scan continues.
    pub(super) fn visit(
        &mut self,
        file: &sevenz_rust2::ArchiveEntry,
        reader: &mut dyn Read,
    ) -> bool {
        let file_index = self.next_file;
        self.next_file += 1;
        let Some(Some(slot)) = self.slots.get(file_index).copied() else {
            return !is_sevenz_payload(file) || skip_payload(file, reader);
        };
        if !is_sevenz_payload(file) {
            return true;
        }
        self.visited.insert(file_index);
        let path = PathBuf::from(common::normalize_entry_name(&file.name));
        let link_position = self
            .links
            .as_ref()
            .and_then(|c| c.position(file_index, file));
        let outcome = match link_position {
            Some(position) => match self.read_link(position, slot, file, reader) {
                Ok(outcome) => outcome,
                Err(e) => {
                    self.stop = Some(BlockStop::Fatal(e));
                    return false;
                }
            },
            None => self.pass.decode(slot, reader, file.size, Charge::Free),
        };
        let abandon = match &outcome {
            DecodeOutcome::Failed(DecodeFailure::ResourceLimit(_)) => {
                Some(BlockStop::Abandoned(UnverifiedReason::ResourceLimit))
            }
            DecodeOutcome::Verified
            | DecodeOutcome::Unverified(_)
            | DecodeOutcome::Failed(DecodeFailure::Checksum | DecodeFailure::Io(_)) => None,
            DecodeOutcome::Failed(_) => Some(BlockStop::Abandoned(UnverifiedReason::NotDecodable)),
        };
        if let Err(e) = self.pass.record(slot, &path, outcome) {
            self.stop = Some(BlockStop::Fatal(e));
            return false;
        }
        let keep_going = abandon.is_none();
        self.stop = abandon;
        keep_going
    }

    /// Decodes a link's data into its target, which is handed to the capture
    /// only when the data verified: a target whose checksum failed is
    /// unreadable, as bytes the decoder withheld would pass for a shorter
    /// target. A link the pass does not admit is never read and stays unread.
    fn read_link(
        &mut self,
        position: EntryPosition,
        slot: Slot,
        file: &sevenz_rust2::ArchiveEntry,
        reader: &mut dyn Read,
    ) -> Result<DecodeOutcome> {
        if !self.pass.is_admitted(slot) {
            return Ok(DecodeOutcome::Unverified(UnverifiedReason::ResourceLimit));
        }
        let mut bytes = Vec::new();
        match self.pass.copy_into(reader, &mut bytes, file.size) {
            Ok(_) => {
                if let Some(capture) = self.links.as_mut() {
                    let target = common::symlink_target_from_bytes(&bytes)?;
                    (capture.set)(position, LinkTarget::classify(target, LinkKind::Symlink));
                }
                Ok(DecodeOutcome::Verified)
            }
            Err(failure) => {
                if let Some(capture) = self.links.as_mut() {
                    (capture.set)(position, LinkTarget::Unreadable);
                }
                Ok(DecodeOutcome::Failed(failure))
            }
        }
    }
}
