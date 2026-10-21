//! Structural census of a ZIP archive.
//!
//! The `zip` crate follows the central directory, collapses records that share
//! a name, trusts the end record's entry count and ignores bytes between
//! entries. A streaming reader follows the local headers instead, so any of
//! those gaps lets two readers disagree about what an archive contains. This
//! module finds them once, when the archive is opened, and records them as
//! [`ZipInconsistency`] findings; whether a finding is fatal is decided per
//! operation by the caller's
//! [`ZipConsistencyPolicy`](crate::ZipConsistencyPolicy).
//!
//! The census runs on one parse of the central directory:
//!
//! 1. every entry is opened with the crate's header-consistency check, which
//!    also yields each entry's byte layout and fills the crate's offset cache;
//! 2. the raw central directory is walked from its start through a second
//!    handle on the same reader, which exposes duplicate names and records
//!    beyond the end record's count, and must agree with the crate's map;
//! 3. the bytes before the archive start, between entries and before the
//!    directory are searched for local headers no record maps and for central
//!    directory signatures before an entry;
//! 4. the end of the file is searched for end records the crate rejected before
//!    settling on the one it used.
//!
//! The archive handed back is the one that was admitted, so no later
//! operation can see a directory the admission checks did not.
//!
//! # Limitations
//!
//! The checks cover what a streaming reader would find outside the entries the
//! central directory maps. Not covered:
//!
//! - a descriptor, local header and data hidden inside the declared range of a
//!   data-descriptor entry (streaming readers end such an entry at the end of
//!   its compressed stream, the central directory at the declared size). Only
//!   an integrity check finds it, because that takes decoding the entry (see
//!   `zip_tail`), and only under the enforcing policy; plain `verify`, `list`
//!   and `extract` do not. A tail that cannot be decided (budget, a raw decode
//!   that disagrees with the crate's) is counted as unverified.
//!
//! The bytes before the first entry (the stub of a self-extractor, whether or
//! not its offsets were rewritten) are searched with a stricter judge than the
//! gaps, because stubs embed the signature as code: a hit counts only when the
//! header looks like a producer wrote it and its whole entry fits inside the
//! prefix; central directory signatures are not searched there at all, which is
//! a residual. A stub never starts with a local header, so one at offset 0 is
//! judged like a header in a gap. The end of the file is searched back as far
//! as the `zip` crate looks for end records; if the record the crate used
//! cannot be identified and others exist, the archive is reported as
//! ambiguous.
//!
//! Pre-ZIP64 archives with more than 65535 entries wrap the end record's count
//! and are reported as uncounted records, as are orphaned local headers left
//! behind by in-place updaters. A central directory signature before an entry,
//! in the gaps or in a prefix that starts with `PK`, is reported as a stray
//! record: a streaming reader that stops listing at the first central record
//! never sees the entries after it. The signature alone counts, because that
//! reader reads no field of the record; one behind the last entry hides
//! nothing and is not reported. An end record signature in a gap stops such a
//! reader the same way and is not searched, which is a residual (#682). With
//! duplicate names the local headers are not compared with the central
//! directory and the gaps are not searched. Each kind of finding keeps a
//! bounded number of entries; the rest are counted.

use std::collections::HashSet;
use std::io::BufReader;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;

use zip::ZipArchive as ZipReader;
use zip::ZipReadOptions;
use zip::result::ZipError;

use super::common;
use super::zip::admit_zip_entry;
use super::zip::is_password_required;
use crate::ArchiveError;
use crate::Result;
use crate::error::CentralRecordOrdinal;
use crate::error::HiddenRegion;
use crate::error::ZipEntryIndex;
use crate::error::ZipHeaderField;
use crate::error::ZipInconsistency;
use crate::security::zipbomb::DeclaredCompressedBudget;

const CDFH_SIGNATURE: [u8; 4] = *b"PK\x01\x02";
pub(super) const LFH_SIGNATURE: [u8; 4] = *b"PK\x03\x04";
pub(super) const DATA_DESCRIPTOR_SIGNATURE: [u8; 4] = *b"PK\x07\x08";
const EOCD_SIGNATURE: [u8; 4] = *b"PK\x05\x06";
const CDFH_FIXED_LEN: usize = 46;
pub(super) const LFH_FIXED_LEN: usize = 30;
const EOCD_FIXED_LEN: usize = 22;
/// Bytes from the end of the file in which the `zip` crate looks for an end
/// record: the fixed part plus the longest comment.
const EOCD_SEARCH_WINDOW: u64 = EOCD_FIXED_LEN as u64 + 4 + 65_536;
const ZIP64_LOCATOR_SIGNATURE: [u8; 4] = *b"PK\x06\x07";
const ZIP64_LOCATOR_LEN: usize = 20;
const ZIP64_END_SIGNATURE: [u8; 4] = *b"PK\x06\x06";
const ZIP64_END_FIXED_LEN: usize = 56;
const ZIP64_END_DIRECTORY_AT: usize = 48;
const ZIP64_EXTRA_ID: u16 = 0x0001;

const HEADER_INCONSISTENCY_PREFIX: &str = "header inconsistency detected: ";
const DUPLICATE_NAMES: &str = "duplicate file names";

/// Field names the `zip` crate puts after [`HEADER_INCONSISTENCY_PREFIX`].
///
/// Matched with `starts_with`, never `contains`: several messages embed
/// attacker-controlled names.
const FIELD_MESSAGES: [(&str, ZipHeaderField); 9] = [
    (
        "Local file header filename mismatch",
        ZipHeaderField::FileName,
    ),
    (
        "UnicodePath (0x7075) extra field mismatch",
        ZipHeaderField::UnicodePath,
    ),
    (
        "compression method mismatch",
        ZipHeaderField::CompressionMethod,
    ),
    ("encryption flag mismatch", ZipHeaderField::EncryptionFlag),
    (
        "data descriptor flag mismatch",
        ZipHeaderField::DataDescriptorFlag,
    ),
    ("last modified time mismatch", ZipHeaderField::ModifiedTime),
    ("CRC32 checksum mismatch", ZipHeaderField::Crc32),
    ("compressed size mismatch", ZipHeaderField::CompressedSize),
    (
        "uncompressed size mismatch",
        ZipHeaderField::UncompressedSize,
    ),
];

/// Kinds of finding, each with its own retention limit so that one kind cannot
/// push another out of the report.
#[derive(Debug, Clone, Copy)]
enum Slot {
    Mismatch,
    Duplicate,
    Hidden,
    StrayCentral,
    Overlap,
    Uncounted,
    IgnoredEnd,
}

impl Slot {
    const ALL: [Self; 7] = [
        Self::Mismatch,
        Self::Duplicate,
        Self::Hidden,
        Self::StrayCentral,
        Self::Overlap,
        Self::Uncounted,
        Self::IgnoredEnd,
    ];

    const fn limit(self) -> usize {
        match self {
            Self::Mismatch => 24,
            Self::Duplicate | Self::Hidden | Self::StrayCentral => 16,
            Self::Overlap | Self::Uncounted | Self::IgnoredEnd => 1,
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// Most findings kept per archive; later ones are only counted.
#[cfg(test)]
pub const MAX_RETAINED_FINDINGS: usize = {
    let mut total = 0;
    let mut i = 0;
    while i < Slot::ALL.len() {
        total += Slot::ALL[i].limit();
        i += 1;
    }
    total
};

/// Findings of one archive, capped per kind so a crafted archive cannot make
/// the report grow with its record count.
#[derive(Debug, Default)]
pub struct Findings {
    items: Vec<ZipInconsistency>,
    kept: [usize; Slot::ALL.len()],
    omitted: usize,
}

impl Findings {
    /// Keeps the finding unless its kind is full, in which case it is only
    /// counted and `false` is returned.
    fn try_push(&mut self, slot: Slot, make: impl FnOnce() -> ZipInconsistency) -> bool {
        if self.kept[slot.index()] < slot.limit() {
            self.kept[slot.index()] += 1;
            self.items.push(make());
            true
        } else {
            self.omitted = self.omitted.saturating_add(1);
            false
        }
    }

    fn push_with(&mut self, slot: Slot, make: impl FnOnce() -> ZipInconsistency) {
        self.try_push(slot, make);
    }

    fn extend(&mut self, other: &Self) {
        self.omitted = self.omitted.saturating_add(other.omitted);
        for (slot, kept) in Slot::ALL.into_iter().zip(other.kept) {
            let items = other
                .items
                .iter()
                .filter(|f| slot_of(f).index() == slot.index());
            for item in items.take(kept) {
                self.push_with(slot, || item.clone());
            }
        }
    }
}

fn slot_of(finding: &ZipInconsistency) -> Slot {
    match finding {
        ZipInconsistency::HeaderMismatch { .. } => Slot::Mismatch,
        ZipInconsistency::DuplicateName { .. } => Slot::Duplicate,
        ZipInconsistency::HiddenLocalHeader { .. } => Slot::Hidden,
        ZipInconsistency::StrayCentralRecord { .. } => Slot::StrayCentral,
        ZipInconsistency::OverlappingEntries => Slot::Overlap,
        ZipInconsistency::UncountedCentralRecords { .. } => Slot::Uncounted,
        ZipInconsistency::IgnoredEndRecord { .. } => Slot::IgnoredEnd,
    }
}

/// A reader that the archive and the census can both use.
///
/// The `zip` crate takes its reader by value and offers no way to borrow it
/// back, and parsing the directory twice (once for the census, once for the
/// operations) would let a file that changes in between show the operations a
/// directory the admission checks never saw. Sharing one handle keeps a single
/// parse, and with it the crate's cache of entry data offsets.
///
/// It also remembers the first I/O error the reader itself raised. The `zip`
/// crate reports parse failures and reader failures alike as errors from its
/// own calls; the record is what tells them apart, so a failing disk is never
/// mistaken for a malformed archive.
#[derive(Debug)]
pub struct Shared<R> {
    reader: Arc<Mutex<Windowed<R>>>,
    fault: Arc<Mutex<Option<(std::io::ErrorKind, String)>>>,
}

impl<R> Shared<R> {
    /// Wraps `reader`; short reads are served from a window, see [`Windowed`].
    pub fn new(reader: R) -> Self {
        Self {
            reader: Arc::new(Mutex::new(Windowed::new(reader))),
            fault: Arc::new(Mutex::new(None)),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Windowed<R>> {
        self.reader.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn note(&self, error: std::io::Error) -> std::io::Error {
        let mut fault = self.fault.lock().unwrap_or_else(PoisonError::into_inner);
        fault.get_or_insert_with(|| (error.kind(), error.to_string()));
        error
    }

    /// The first error the reader raised, if any.
    fn take_fault(&self) -> Option<std::io::Error> {
        let mut fault = self.fault.lock().unwrap_or_else(PoisonError::into_inner);
        fault
            .take()
            .map(|(kind, message)| std::io::Error::new(kind, message))
    }
}

impl<R> Clone for Shared<R> {
    fn clone(&self) -> Self {
        Self {
            reader: Arc::clone(&self.reader),
            fault: Arc::clone(&self.fault),
        }
    }
}

/// Bytes read from the underlying reader per refill of the window.
const WINDOW: usize = 32 * 1024;

/// Reads at least this long skip the window: they come from decoders that
/// buffer for themselves, so caching them would only add a copy.
const WINDOW_BYPASS: usize = 4 * 1024;

/// A reader that serves the many short reads of header parsing from one
/// window.
///
/// The `zip` crate and the census read the central directory and the local
/// headers a few dozen bytes at a time, seeking between them. On an unbuffered
/// file every read and seek is a system call, which dominated the cost of
/// opening an archive with many entries. Seeking here only moves a cursor; the
/// underlying reader is positioned when a read is not covered by the window.
#[derive(Debug)]
struct Windowed<R> {
    inner: R,
    window: Vec<u8>,
    window_start: u64,
    cursor: u64,
    /// Where the underlying reader is, when known.
    inner_position: Option<u64>,
}

impl<R> Windowed<R> {
    const fn new(inner: R) -> Self {
        Self {
            inner,
            window: Vec::new(),
            window_start: 0,
            cursor: 0,
            inner_position: None,
        }
    }

    fn cached(&self) -> &[u8] {
        let offset = self.cursor.wrapping_sub(self.window_start);
        usize::try_from(offset)
            .ok()
            .and_then(|offset| self.window.get(offset..))
            .unwrap_or(&[])
    }
}

impl<R: Read + Seek> Windowed<R> {
    fn position_inner(&mut self) -> std::io::Result<()> {
        if self.inner_position != Some(self.cursor) {
            self.inner_position = None;
            self.inner.seek(SeekFrom::Start(self.cursor))?;
            self.inner_position = Some(self.cursor);
        }
        Ok(())
    }

    fn advance(&mut self, read: usize) {
        self.cursor += read as u64;
        self.inner_position = self.inner_position.map(|p| p + read as u64);
    }
}

impl<R: Read + Seek> Read for Windowed<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let cached = self.cached();
        if !cached.is_empty() {
            let n = cached.len().min(buf.len());
            buf[..n].copy_from_slice(&cached[..n]);
            self.cursor += n as u64;
            return Ok(n);
        }
        self.position_inner()?;
        if buf.len() >= WINDOW_BYPASS {
            let n = self
                .inner
                .read(buf)
                .inspect_err(|_| self.inner_position = None)?;
            self.advance(n);
            return Ok(n);
        }
        self.window.clear();
        self.window.resize(WINDOW, 0);
        self.window_start = self.cursor;
        let filled = self.inner.read(&mut self.window).inspect_err(|_| {
            self.window.clear();
            self.inner_position = None;
        })?;
        self.window.truncate(filled);
        let n = filled.min(buf.len());
        buf[..n].copy_from_slice(&self.window[..n]);
        self.advance(n);
        self.inner_position = self.inner_position.map(|p| p + (filled - n) as u64);
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for Windowed<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::Current(delta) => self.cursor.checked_add_signed(delta),
            SeekFrom::End(_) => {
                self.inner_position = None;
                let end = self.inner.seek(pos)?;
                self.inner_position = Some(end);
                Some(end)
            }
        };
        self.cursor = target.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid seek to a negative or overflowing position",
            )
        })?;
        Ok(self.cursor)
    }
}

impl<R: Read + Seek> Read for Shared<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.lock().read(buf);
        read.map_err(|e| self.note(e))
    }
}

impl<R: Read + Seek> Seek for Shared<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let sought = self.lock().seek(pos);
        sought.map_err(|e| self.note(e))
    }
}

/// What the census found out about an archive.
#[derive(Debug)]
pub struct ZipStructure {
    central_entries: usize,
    findings: Findings,
    #[cfg(test)]
    gap_reads: usize,
}

impl ZipStructure {
    /// A structure with no findings, for tests that bypass the census.
    #[cfg(test)]
    pub(crate) fn unchecked(central_entries: usize) -> Self {
        Self {
            central_entries,
            findings: Findings::default(),
            gap_reads: 0,
        }
    }

    /// Number of records in the raw central directory, which can exceed what
    /// the `zip` crate lists.
    pub(crate) const fn central_entries(&self) -> usize {
        self.central_entries
    }

    /// Retained findings, in discovery order.
    pub(crate) fn findings(&self) -> &[ZipInconsistency] {
        &self.findings.items
    }

    /// Findings beyond the per-kind retention limits, which were only counted.
    pub(crate) const fn omitted_findings(&self) -> usize {
        self.findings.omitted
    }

    /// Reads that were needed to search the gaps between entries.
    #[cfg(test)]
    pub(crate) const fn gap_reads(&self) -> usize {
        self.gap_reads
    }
}

/// Byte range of one entry, from its local header to the end of its data.
#[derive(Debug, Clone, Copy)]
struct EntryLayout {
    header_start: u64,
    end: u64,
    data_descriptor: bool,
}

/// The central directory as the `zip` crate maps it.
#[derive(Debug)]
struct DirectoryMap {
    directory_start: u64,
    archive_offset: u64,
    central_starts: Vec<u64>,
    comment: Vec<u8>,
}

impl DirectoryMap {
    fn of<R: Read + Seek>(archive: &ZipReader<R>) -> Result<Self> {
        let central_starts = (0..archive.len())
            .map(|index| {
                archive
                    .by_index_data(index)
                    .map(|entry| entry.central_header_start())
                    .map_err(|e| {
                        ArchiveError::InvalidArchive(format!("failed to read entry {index}: {e}"))
                    })
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            directory_start: archive.central_directory_start(),
            archive_offset: archive.offset(),
            central_starts,
            comment: archive.comment().to_vec(),
        })
    }
}

/// Opens `reader` as a ZIP archive and runs the census.
///
/// Returns the archive, parsed once and already admitted, and its structure.
///
/// # Errors
///
/// Fails on unparseable, encrypted or unsupported archives, and when the
/// raw central directory and the `zip` crate's map of it disagree.
pub fn open<R: Read + Seek>(reader: R) -> Result<(ZipReader<Shared<R>>, ZipStructure)> {
    let shared = Shared::new(reader);
    let mut archive = open_reader(shared.clone()).map_err(|e| reader_fault(&shared, e))?;
    let scan = scan_entries(&mut archive, &shared).map_err(|e| reader_fault(&shared, e))?;
    let map = DirectoryMap::of(&archive).map_err(|e| reader_fault(&shared, e))?;

    let mut census_reader = shared.clone();
    let census =
        Census::run(&mut census_reader, &map, &scan).map_err(|e| reader_fault(&shared, e))?;

    if let Some(fault) = shared.take_fault() {
        return Err(ArchiveError::Io(fault));
    }

    let mut findings = scan.findings;
    findings.extend(&census.findings);
    Ok((
        archive,
        ZipStructure {
            central_entries: census.central_entries,
            findings,
            #[cfg(test)]
            gap_reads: census.gap_reads,
        },
    ))
}

/// Prefers the reader's own I/O error over the verdict the `zip` crate drew
/// from it.
fn reader_fault<R>(shared: &Shared<R>, error: ArchiveError) -> ArchiveError {
    shared.take_fault().map_or(error, ArchiveError::Io)
}

fn open_reader<R: Read + Seek>(reader: R) -> Result<ZipReader<R>> {
    ZipReader::new(reader)
        .map_err(|e| ArchiveError::InvalidArchive(format!("failed to open ZIP archive: {e}")))
}

fn census_disagreement() -> ArchiveError {
    ArchiveError::InvalidArchive("ZIP central directory census disagrees with reader".into())
}

/// Result of opening every entry.
#[derive(Debug, Default)]
struct Scan {
    layouts: Vec<EntryLayout>,
    findings: Findings,
    crate_duplicates: bool,
}

/// Opens every entry once with the crate's header-consistency check.
///
/// An archive the crate validates in one pass has no mismatch to attribute, so
/// its entries are opened raw, without building a decoder for each. Any other
/// archive is checked entry by entry to find the one that fails.
///
/// An entry that fails the check is opened again without it, so admission
/// (encryption, method, declared compressed size) still runs for it and a
/// forged header cannot skip those limits. With duplicate names the check is
/// skipped altogether: the crate rejects every entry then.
fn scan_entries<R: Read + Seek>(
    archive: &mut ZipReader<Shared<R>>,
    shared: &Shared<R>,
) -> Result<Scan> {
    let mut budget = DeclaredCompressedBudget::new(archive.central_directory_start());
    let mut scan = Scan::default();
    let consistent = archive.validate_header_consistency().is_ok();

    for index in 0..archive.len() {
        if consistent {
            let file = archive.by_index_raw(index).map_err(|e| {
                ArchiveError::InvalidArchive(format!("failed to read entry {index}: {e}"))
            })?;
            admit_zip_entry(&file, &mut budget)?;
            scan.layouts.push(layout_of(&file)?);
            continue;
        }

        let mut mismatch = None;
        if !scan.crate_duplicates {
            let options = ZipReadOptions::new().enforce_header_consistency(true);
            match archive.by_index_with_options(index, options) {
                Ok(file) => {
                    admit_zip_entry(&file, &mut budget)?;
                    scan.layouts.push(layout_of(&file)?);
                    continue;
                }
                Err(e) if index == 0 && is_duplicate_names(&e) => scan.crate_duplicates = true,
                Err(e) => {
                    if let Some(fault) = shared.take_fault() {
                        return Err(ArchiveError::Io(fault));
                    }
                    mismatch = Some(e);
                }
            }
        }

        let file = archive.by_index(index).map_err(|e| {
            if is_password_required(&e) {
                common::encrypted_archive_error()
            } else {
                ArchiveError::InvalidArchive(format!("failed to read entry {index}: {e}"))
            }
        })?;
        admit_zip_entry(&file, &mut budget)?;
        scan.layouts.push(layout_of(&file)?);
        if let Some(error) = mismatch {
            scan.findings
                .push_with(Slot::Mismatch, || ZipInconsistency::HeaderMismatch {
                    entry: ZipEntryIndex::new(index),
                    field: classify(&error),
                    name: String::from_utf8_lossy(file.name_raw()).into_owned(),
                });
        }
    }

    if overlaps(&scan.layouts, archive.central_directory_start()) {
        scan.findings
            .push_with(Slot::Overlap, || ZipInconsistency::OverlappingEntries);
    }
    Ok(scan)
}

fn layout_of<R: Read>(file: &zip::read::ZipFile<'_, R>) -> Result<EntryLayout> {
    let invalid =
        || ArchiveError::InvalidArchive("ZIP entry data range is not representable".into());
    let data_start = file.data_start().ok_or_else(invalid)?;
    Ok(EntryLayout {
        header_start: file.header_start(),
        end: data_start
            .checked_add(file.compressed_size())
            .ok_or_else(invalid)?,
        data_descriptor: file.flags().is_using_data_descriptor(),
    })
}

/// Whether any byte belongs to two entries (header included) or an entry
/// reaches into the central directory.
fn overlaps(layouts: &[EntryLayout], directory_start: u64) -> bool {
    let mut ranges: Vec<_> = layouts.iter().map(|l| (l.header_start, l.end)).collect();
    ranges.sort_unstable();
    ranges.iter().any(|&(_, end)| end > directory_start)
        || ranges.windows(2).any(|w| w[0].1 > w[1].0)
}

fn is_duplicate_names(error: &ZipError) -> bool {
    matches!(
        error,
        ZipError::InvalidArchive(msg)
            if msg.strip_prefix(HEADER_INCONSISTENCY_PREFIX)
                .is_some_and(|rest| rest.starts_with(DUPLICATE_NAMES))
    )
}

/// Names the field behind a failed header-consistency check.
///
/// An error without the crate's prefix (for example an I/O error while
/// parsing the local header's extra fields) means the header could not be
/// compared at all.
pub fn classify(error: &ZipError) -> ZipHeaderField {
    let ZipError::InvalidArchive(msg) = error else {
        return ZipHeaderField::Unparseable;
    };
    let Some(rest) = msg.strip_prefix(HEADER_INCONSISTENCY_PREFIX) else {
        return ZipHeaderField::Unparseable;
    };
    FIELD_MESSAGES
        .iter()
        .find(|(text, _)| rest.starts_with(text))
        .map_or(ZipHeaderField::Unrecognized, |&(_, field)| field)
}

/// Raw central directory and gap findings.
#[derive(Debug)]
struct Census {
    central_entries: usize,
    findings: Findings,
    #[cfg(test)]
    gap_reads: usize,
}

/// Lengths of the variable part of a central directory record.
struct CentralRecord {
    name_len: u16,
    extra_len: u16,
    comment_len: u16,
    local_offset: u32,
}

impl CentralRecord {
    /// Reads the fixed part of a record, or `None` when the bytes are not one.
    fn read(reader: &mut impl Read) -> Option<Self> {
        let mut header = [0u8; CDFH_FIXED_LEN];
        if reader.read_exact(&mut header).is_err() || header[..4] != CDFH_SIGNATURE {
            return None;
        }
        let field = |at: usize| le_u16(&header, at);
        Some(Self {
            name_len: field(28),
            extra_len: field(30),
            comment_len: field(32),
            local_offset: le_u32(&header, 42),
        })
    }

    fn variable_len(&self) -> u64 {
        u64::from(self.name_len) + u64::from(self.extra_len) + u64::from(self.comment_len)
    }
}

impl Census {
    fn run<R: Read + Seek>(reader: &mut R, map: &DirectoryMap, scan: &Scan) -> Result<Self> {
        let file_len = reader.seek(SeekFrom::End(0))?;
        let mut findings = Findings::default();

        let mut walker = BufReader::new(&mut *reader);
        walker.seek(SeekFrom::Start(map.directory_start))?;
        let walk = walk_directory(&mut walker, map, &mut findings)?;
        drop(walker);

        if walk.crate_duplicates() != scan.crate_duplicates {
            return Err(census_disagreement());
        }
        if walk.uncounted > 0 {
            findings.push_with(Slot::Uncounted, || {
                ZipInconsistency::UncountedCentralRecords {
                    counted: walk.counted,
                    found: walk.counted.saturating_add(walk.uncounted),
                }
            });
        }

        let mut gaps = GapChecker::new(reader, map, &scan.layouts, &walk, file_len);
        gaps.run(&mut findings)?;
        #[cfg(test)]
        let reads = gaps.reads;
        drop(gaps);

        find_ignored_end_records(reader, file_len, map, &mut findings)?;

        Ok(Self {
            central_entries: walk.counted.saturating_add(walk.uncounted),
            findings,
            #[cfg(test)]
            gap_reads: reads,
        })
    }
}

/// Outcome of walking the raw central directory.
struct Walk {
    /// Records the crate parsed, mapped or shadowed by a later duplicate.
    counted: usize,
    shadowed: usize,
    /// Local header offsets of the shadowed records, already reported as
    /// duplicates and so not hidden.
    shadowed_headers: HashSet<u64>,
    /// Well-formed records past the last one the crate parsed.
    uncounted: usize,
}

impl Walk {
    const fn crate_duplicates(&self) -> bool {
        self.shadowed > 0
    }
}

/// Walks every record from the directory start through the last mapped one,
/// then keeps going while the next bytes are another record.
///
/// Records the crate maps are skipped; any other record up to the last mapped
/// one was collapsed into a later record with the same name.
fn walk_directory<R: Read + Seek>(
    reader: &mut BufReader<&mut R>,
    map: &DirectoryMap,
    findings: &mut Findings,
) -> Result<Walk> {
    let mapped: HashSet<u64> = map.central_starts.iter().copied().collect();
    if mapped.len() != map.central_starts.len() {
        return Err(census_disagreement());
    }
    let last_mapped = map.central_starts.iter().copied().max();

    let mut position = map.directory_start;
    let mut walk = Walk {
        counted: 0,
        shadowed: 0,
        shadowed_headers: HashSet::new(),
        uncounted: 0,
    };
    let mut visited = 0;

    while last_mapped.is_some_and(|last| position <= last) {
        let record = CentralRecord::read(reader).ok_or_else(census_disagreement)?;
        if mapped.contains(&position) {
            visited += 1;
            skip(reader, record.variable_len())?;
        } else {
            let ordinal = CentralRecordOrdinal::new(walk.counted);
            let mut name = vec![0u8; usize::from(record.name_len)];
            reader.read_exact(&mut name)?;
            findings.push_with(Slot::Duplicate, || ZipInconsistency::DuplicateName {
                record: ordinal,
                name: String::from_utf8_lossy(&name).into_owned(),
            });
            walk.shadowed += 1;
            walk.shadowed_headers
                .insert(u64::from(record.local_offset).saturating_add(map.archive_offset));
            skip(
                reader,
                u64::from(record.extra_len) + u64::from(record.comment_len),
            )?;
        }
        walk.counted += 1;
        position = position
            .checked_add(CDFH_FIXED_LEN as u64 + record.variable_len())
            .ok_or_else(census_disagreement)?;
    }
    if visited != mapped.len() {
        return Err(census_disagreement());
    }

    while let Some(record) = CentralRecord::read(reader) {
        skip(reader, record.variable_len())?;
        walk.uncounted += 1;
    }
    Ok(walk)
}

fn skip<R: Read + Seek>(reader: &mut BufReader<&mut R>, len: u64) -> std::io::Result<()> {
    let len =
        i64::try_from(len).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    reader.seek_relative(len)
}

/// Bytes read per request while searching a gap.
const GAP_CHUNK: usize = 64 * 1024;

/// Bytes read per request while searching the prefix; larger than the longest
/// local header so a hit that starts in the first half is complete.
const PREFIX_CHUNK: usize = 128 * 1024;

/// Bytes two prefix chunks share, so a signature split by a chunk end is seen.
const PREFIX_OVERLAP: usize = 3;

/// Highest "version needed to extract" a producer writes today.
const MAX_VERSION_NEEDED: u16 = 63;

/// General purpose flag bits the specification leaves unused or reserved.
const RESERVED_FLAG_BITS: u16 = 0xD780;

const DATA_DESCRIPTOR_FLAG: u16 = 0x0008;

/// Compression methods assigned to a format the ecosystem uses.
const KNOWN_METHODS: [u16; 9] = [0, 8, 9, 12, 14, 93, 95, 98, 99];

/// Bytes two consecutive chunks share, so a header that starts near the end of
/// one chunk is complete in the next.
const GAP_OVERLAP: usize = LFH_FIXED_LEN + 3;

/// Looks for local headers and central directory records in the gaps between
/// entries.
///
/// A streaming reader walks the file from its start and resynchronises on the
/// next local header signature it finds, so unmapped headers matter wherever
/// they sit between the entries the central directory maps. It also stops
/// listing at a central directory signature, so one before an entry hides that
/// entry; the signature alone is the finding, since the reader reads no field
/// of the record. Archives without gaps cost no read, except that a data
/// descriptor wider than the shortest one is resolved with up to three reads.
///
/// The search is bounded whatever the gaps hold: bytes are read in large
/// chunks and every signature hit is judged from the chunk, state is a single
/// offset, and the search stops at the first hit beyond the retention limit of
/// either kind of finding, which also ends the search for the other kind.
struct GapChecker<'a, R> {
    reader: &'a mut R,
    map: &'a DirectoryMap,
    layouts: &'a [EntryLayout],
    known_headers: HashSet<u64>,
    search_gaps: bool,
    file_len: u64,
    buf: Vec<u8>,
    /// Signature hits below this offset were already judged.
    next_unjudged: u64,
    exhausted: bool,
    reads: usize,
}

impl<'a, R: Read + Seek> GapChecker<'a, R> {
    /// With duplicate names the gaps are not searched, only the position right
    /// after each entry is looked at, since the shadowed records' own extents
    /// are not known.
    fn new(
        reader: &'a mut R,
        map: &'a DirectoryMap,
        layouts: &'a [EntryLayout],
        walk: &Walk,
        file_len: u64,
    ) -> Self {
        Self {
            reader,
            map,
            layouts,
            known_headers: layouts
                .iter()
                .map(|l| l.header_start)
                .chain(walk.shadowed_headers.iter().copied())
                .collect(),
            search_gaps: !walk.crate_duplicates(),
            file_len,
            buf: Vec::new(),
            next_unjudged: 0,
            exhausted: false,
            reads: 0,
        }
    }

    /// A position that needs no read: a header some record accounts for, or
    /// the directory.
    fn is_known(&self, position: u64) -> bool {
        position == self.map.directory_start || self.known_headers.contains(&position)
    }

    fn run(&mut self, findings: &mut Findings) -> Result<()> {
        let mut order = self.layouts.to_vec();
        order.sort_unstable_by_key(|l| l.header_start);
        let prefix_end = if self.map.archive_offset > 0 {
            self.map.archive_offset
        } else {
            order
                .first()
                .map_or(self.map.directory_start, |l| l.header_start)
        };
        let prefix_followed = if order.is_empty() {
            Followed::ByDirectory
        } else {
            Followed::ByEntry
        };
        self.scan_prefix(prefix_end, prefix_followed, findings)?;

        let mut starts: Vec<u64> = order.iter().map(|l| l.header_start).collect();
        starts.push(self.map.directory_start);
        starts.dedup();

        let mut cursor = prefix_end;
        for layout in &order {
            if self.exhausted {
                return Ok(());
            }
            self.gap(cursor, layout.header_start, Followed::ByEntry, findings)?;
            if layout.end > self.map.directory_start {
                continue;
            }
            let next = starts
                .get(starts.partition_point(|&s| s <= layout.header_start))
                .copied()
                .unwrap_or(self.map.directory_start);
            let resume = if layout.data_descriptor {
                self.after_descriptor(layout, next)?
            } else {
                layout.end
            };
            cursor = cursor.max(resume);
        }
        self.gap(
            cursor,
            self.map.directory_start,
            Followed::ByDirectory,
            findings,
        )
    }

    /// Searches `[0, end)`, the bytes before the first entry, for local
    /// headers, and, when the file starts with `PK`, for central directory
    /// signatures.
    ///
    /// A stub never starts with a local header or any other `PK` marker (a
    /// streaming reader skips a leading one to the next header), so when the
    /// file starts with `PK`, or a header sits at offset 0, the headers are
    /// judged like those in a gap. Otherwise, past offset 0, a hit counts only
    /// if the header looks like a producer wrote it and its whole entry
    /// fits in the prefix, since stubs embed the signature as code. Hits
    /// whose name is cut off by the end of a chunk are re-read from the
    /// hit, so each judgment sees the full name and every read advances the
    /// scan.
    fn scan_prefix(&mut self, end: u64, followed: Followed, findings: &mut Findings) -> Result<()> {
        if end == 0 {
            return Ok(());
        }
        if end < LFH_FIXED_LEN as u64 {
            self.probe(0, HiddenRegion::Prefix, findings)?;
        }
        let mut position = 0u64;
        let mut lenient = false;
        while position + 4 <= end && !self.exhausted {
            let want =
                usize::try_from(end - position).map_or(PREFIX_CHUNK, |n| n.min(PREFIX_CHUNK));
            let last = position + want as u64 >= end;
            self.fill(position, want)?;
            if position == 0 {
                lenient = self.buf[..want].starts_with(b"PK");
            }
            let mut next = 0;
            let mut resume = None;
            while let Some((relative, kind)) = find_signature(&self.buf[next..want]) {
                let index = next + relative;
                next = index + 1;
                if kind == Signature::CentralRecord {
                    if lenient {
                        self.stray_central(position + index as u64, followed, findings);
                    }
                    continue;
                }
                if lenient || position + index as u64 == 0 {
                    let mut header = [0u8; LFH_FIXED_LEN];
                    if let Some(bytes) = self.buf[..want].get(index..index + LFH_FIXED_LEN) {
                        header.copy_from_slice(bytes);
                        let found = position + index as u64;
                        self.judge(found, &header, HiddenRegion::Prefix, findings);
                    } else if !last {
                        resume = Some(index);
                        break;
                    }
                    continue;
                }
                let name_len = self.buf[..want]
                    .get(index + 26..index + 28)
                    .map(|b| usize::from(le_u16(b, 0)));
                let Some(name_len) = name_len.filter(|n| index + LFH_FIXED_LEN + n <= want) else {
                    if !last {
                        resume = Some(index);
                        break;
                    }
                    continue;
                };
                let candidate = &self.buf[index..index + LFH_FIXED_LEN + name_len];
                let found = position + index as u64;
                if is_plausible_prefix_header(candidate, end - found)
                    && !findings.try_push(Slot::Hidden, || ZipInconsistency::HiddenLocalHeader {
                        offset: found,
                        region: HiddenRegion::Prefix,
                    })
                {
                    self.exhausted = true;
                    return Ok(());
                }
            }
            if last {
                break;
            }
            position += resume.unwrap_or(want - PREFIX_OVERLAP).max(1) as u64;
        }
        Ok(())
    }

    /// Searches `[from, to)` for local headers and, unless the directory
    /// follows, central directory signatures.
    fn gap(
        &mut self,
        from: u64,
        to: u64,
        followed: Followed,
        findings: &mut Findings,
    ) -> Result<()> {
        if self.exhausted || from >= to || self.is_known(from) {
            return Ok(());
        }
        if !self.search_gaps {
            return self.probe(from, HiddenRegion::Gap, findings);
        }
        let mut position = from;
        while position + 4 <= to && !self.exhausted {
            let want = usize::try_from(to - position).map_or(GAP_CHUNK, |n| n.min(GAP_CHUNK));
            let last = position + want as u64 >= to;
            self.fill(position, want)?;
            let mut next = 0;
            while let Some((relative, kind)) = find_signature(&self.buf[next..want]) {
                let index = next + relative;
                next = index + 1;
                let found = position + index as u64;
                if kind == Signature::CentralRecord {
                    self.stray_central(found, followed, findings);
                } else if index + LFH_FIXED_LEN <= want {
                    let mut header = [0u8; LFH_FIXED_LEN];
                    header.copy_from_slice(&self.buf[index..index + LFH_FIXED_LEN]);
                    self.judge(found, &header, HiddenRegion::Gap, findings);
                } else if last {
                    self.probe(found, HiddenRegion::Gap, findings)?;
                } else {
                    break;
                }
                if self.exhausted {
                    return Ok(());
                }
            }
            if last {
                break;
            }
            position += (want - GAP_OVERLAP) as u64;
        }
        Ok(())
    }

    /// Where the next header can start after a data descriptor.
    ///
    /// The descriptor's length depends on its optional signature and on
    /// ZIP64, so the next header can sit at four distinct offsets. A known
    /// position right behind the shortest descriptor leaves nothing to
    /// search and costs no read. Any other candidate can leave bytes between
    /// the descriptor a streaming reader consumes and the next header (a stray
    /// record hides there), so the width is resolved by emulating that reader
    /// and the search resumes where its descriptor ends.
    fn after_descriptor(&mut self, layout: &EntryLayout, next: u64) -> Result<u64> {
        let candidates = [12u64, 16, 20, 24].map(|width| layout.end.checked_add(width));
        let known = candidates
            .iter()
            .flatten()
            .copied()
            .filter(|&p| p == next || self.is_known(p))
            .min();
        if let Some(k) = known
            && known == candidates[0]
        {
            return Ok(k);
        }
        let signed = self.peek(layout.end)? == Some(DATA_DESCRIPTOR_SIGNATURE);
        let shortest = if signed { 16 } else { 12 };
        if let Some(k) = known.filter(|&k| Some(k) == layout.end.checked_add(shortest)) {
            return Ok(k);
        }
        let sizes = if self.has_zip64_extra(layout.header_start)? {
            20
        } else {
            12
        };
        let width = sizes + if signed { 4 } else { 0 };
        let streaming = layout.end.saturating_add(width);
        Ok(known.map_or(streaming, |k| k.min(streaming)))
    }

    /// Judges the bytes at one position as a possible local header.
    fn probe(
        &mut self,
        position: u64,
        region: HiddenRegion,
        findings: &mut Findings,
    ) -> Result<()> {
        if self.is_known(position) || position < self.next_unjudged {
            return Ok(());
        }
        let mut header = [0u8; LFH_FIXED_LEN];
        if position.saturating_add(LFH_FIXED_LEN as u64) > self.file_len {
            return Ok(());
        }
        self.read_at(position, &mut header)?;
        if header[..4] == LFH_SIGNATURE {
            self.judge(position, &header, region, findings);
        }
        Ok(())
    }

    /// Reports a central directory signature that a streaming reader would
    /// stop at before an entry.
    ///
    /// The signature alone is the finding: such a reader reads no field of
    /// the record, so name, version and offsets are not judged.
    fn stray_central(&mut self, position: u64, followed: Followed, findings: &mut Findings) {
        if followed == Followed::ByDirectory || position < self.next_unjudged {
            return;
        }
        self.next_unjudged = position + 1;
        if !findings.try_push(Slot::StrayCentral, || {
            ZipInconsistency::StrayCentralRecord { offset: position }
        }) {
            self.exhausted = true;
        }
    }

    /// Reports a signature hit as a hidden header when the header it starts
    /// has a name and fits before the directory.
    fn judge(
        &mut self,
        position: u64,
        header: &[u8; LFH_FIXED_LEN],
        region: HiddenRegion,
        findings: &mut Findings,
    ) {
        if position < self.next_unjudged || self.is_known(position) {
            return;
        }
        self.next_unjudged = position + 1;
        let name_len = u64::from(le_u16(header, 26));
        let extra_len = u64::from(le_u16(header, 28));
        let end = position + LFH_FIXED_LEN as u64 + name_len + extra_len;
        if name_len > 0
            && end <= self.map.directory_start
            && !findings.try_push(Slot::Hidden, || ZipInconsistency::HiddenLocalHeader {
                offset: position,
                region,
            })
        {
            self.exhausted = true;
        }
    }

    fn fill(&mut self, position: u64, len: usize) -> Result<()> {
        let mut buf = std::mem::take(&mut self.buf);
        if buf.len() < len {
            buf.resize(len, 0);
        }
        let read = self.read_at(position, &mut buf[..len]);
        self.buf = buf;
        read
    }

    fn read_at(&mut self, position: u64, buf: &mut [u8]) -> Result<()> {
        self.reads += 1;
        self.reader.seek(SeekFrom::Start(position))?;
        self.reader.read_exact(buf)?;
        Ok(())
    }

    fn peek(&mut self, position: u64) -> Result<Option<[u8; 4]>> {
        if position.saturating_add(4) > self.file_len {
            return Ok(None);
        }
        let mut bytes = [0u8; 4];
        self.read_at(position, &mut bytes)?;
        Ok(Some(bytes))
    }

    /// Whether the local header at `header_start` carries a ZIP64 extra field,
    /// which makes its data descriptor use 8-byte sizes.
    fn has_zip64_extra(&mut self, header_start: u64) -> Result<bool> {
        if header_start.saturating_add(LFH_FIXED_LEN as u64) > self.file_len {
            return Ok(false);
        }
        let mut header = [0u8; LFH_FIXED_LEN];
        self.read_at(header_start, &mut header)?;
        let name_len = u64::from(le_u16(&header, 26));
        let extra_len = usize::from(le_u16(&header, 28));
        let extra_start = header_start + LFH_FIXED_LEN as u64 + name_len;
        if extra_start.saturating_add(extra_len as u64) > self.file_len {
            return Ok(false);
        }
        let mut extra = vec![0u8; extra_len];
        self.read_at(extra_start, &mut extra)?;
        Ok(extra_ids(&extra).any(|id| id == ZIP64_EXTRA_ID))
    }
}

/// Whether the bytes at a prefix signature hit read like a local header a ZIP
/// producer wrote, rather than code or data that embeds the signature.
///
/// `candidate` is the fixed header and the name it declares; `room` is the
/// number of prefix bytes from the hit to the archive start, which the
/// header, extra field and (without a data descriptor) data must fit in.
fn is_plausible_prefix_header(candidate: &[u8], room: u64) -> bool {
    let field = |at: usize| le_u16(candidate, at);
    let name_len = usize::from(field(26));
    let flags = field(6);
    if name_len == 0
        || field(4) > MAX_VERSION_NEEDED
        || flags & RESERVED_FLAG_BITS != 0
        || !KNOWN_METHODS.contains(&field(8))
    {
        return false;
    }
    let mut needed = (LFH_FIXED_LEN + name_len) as u64 + u64::from(field(28));
    if flags & DATA_DESCRIPTOR_FLAG == 0 {
        let compressed = le_u32(candidate, 18);
        if compressed != u32::MAX {
            needed += u64::from(compressed);
        }
    }
    // Last, because it is the only check that costs more than a field read: a
    // header that passed the others has a zero high version byte, so in a run
    // of such headers each name scan ends at the next one.
    needed <= room
        && candidate
            .get(LFH_FIXED_LEN..LFH_FIXED_LEN + name_len)
            .is_some_and(|name| !name.contains(&0))
}

/// Reports end records after the one the `zip` crate used.
///
/// The crate tries candidates from the end of the file backwards and keeps
/// the first that yields a readable directory, so every later candidate that
/// could be a record was rejected, while a reader with other checks may take
/// it. The used record is the one whose comment matches and whose directory
/// offset leads to the directory the crate returned (through the ZIP64
/// records when the 32-bit field holds the escape value).
///
/// When no record can be identified as the used one, the archive is
/// ambiguous if it holds more than one candidate, and the last is reported.
fn find_ignored_end_records<R: Read + Seek>(
    reader: &mut R,
    file_len: u64,
    map: &DirectoryMap,
    findings: &mut Findings,
) -> Result<()> {
    let start = file_len.saturating_sub(EOCD_SEARCH_WINDOW);
    let mut window = vec![0u8; usize::try_from(file_len - start).unwrap_or(0)];
    reader.seek(SeekFrom::Start(start))?;
    reader.read_exact(&mut window)?;

    let mut candidates = Vec::new();
    for at in (0..window.len().saturating_sub(EOCD_FIXED_LEN - 1)).rev() {
        if window[at..at + 4] != EOCD_SIGNATURE {
            continue;
        }
        let comment_len = usize::from(le_u16(&window, at + 20));
        let Some(comment) = window.get(at + EOCD_FIXED_LEN..at + EOCD_FIXED_LEN + comment_len)
        else {
            continue;
        };
        if comment == map.comment && is_used_record(reader, &window, at, file_len, map)? {
            for offset in candidates {
                findings.push_with(Slot::IgnoredEnd, || ZipInconsistency::IgnoredEndRecord {
                    offset,
                });
            }
            return Ok(());
        }
        candidates.push(start + at as u64);
    }
    if candidates.len() > 1 {
        findings.push_with(Slot::IgnoredEnd, || ZipInconsistency::IgnoredEndRecord {
            offset: candidates[0],
        });
    }
    Ok(())
}

/// Whether the end record at `at` in `window` leads to the directory the
/// crate returned.
fn is_used_record<R: Read + Seek>(
    reader: &mut R,
    window: &[u8],
    at: usize,
    file_len: u64,
    map: &DirectoryMap,
) -> Result<bool> {
    let directory = le_u32(window, at + 16);
    if directory != u32::MAX {
        return Ok(u64::from(directory).saturating_add(map.archive_offset) == map.directory_start);
    }
    let Some(locator) = at
        .checked_sub(ZIP64_LOCATOR_LEN)
        .and_then(|from| window.get(from..at))
    else {
        return Ok(false);
    };
    if locator[..4] != ZIP64_LOCATOR_SIGNATURE {
        return Ok(false);
    }
    let end_record = le_u64(locator, 8);
    for position in [end_record.saturating_add(map.archive_offset), end_record] {
        if position.saturating_add(ZIP64_END_FIXED_LEN as u64) > file_len {
            continue;
        }
        let mut record = [0u8; ZIP64_END_FIXED_LEN];
        reader.seek(SeekFrom::Start(position))?;
        reader.read_exact(&mut record)?;
        if record[..4] != ZIP64_END_SIGNATURE {
            continue;
        }
        let directory = le_u64(&record, ZIP64_END_DIRECTORY_AT);
        return Ok(directory.saturating_add(map.archive_offset) == map.directory_start);
    }
    Ok(false)
}

/// Little-endian `u16` at `at`.
pub(super) fn le_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

/// Little-endian `u32` at `at`.
pub(super) fn le_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Little-endian `u64` at `at`.
pub(super) fn le_u64(bytes: &[u8], at: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(raw)
}

/// A record kind the gap and prefix searches look for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Signature {
    LocalHeader,
    CentralRecord,
}

/// Offset and kind of the first local header or central record signature in
/// `bytes`.
fn find_signature(bytes: &[u8]) -> Option<(usize, Signature)> {
    bytes.windows(4).enumerate().find_map(|(index, w)| {
        if w == LFH_SIGNATURE {
            Some((index, Signature::LocalHeader))
        } else if w == CDFH_SIGNATURE {
            Some((index, Signature::CentralRecord))
        } else {
            None
        }
    })
}

/// What follows a searched region, which decides whether a central record in
/// it hides anything: a streaming reader stops at the record and so never
/// reaches an entry behind it, but the directory behind the last entry holds
/// nothing to hide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Followed {
    ByEntry,
    ByDirectory,
}

/// Header ids of the well-formed prefix of an extra field block.
fn extra_ids(mut extra: &[u8]) -> impl Iterator<Item = u16> + '_ {
    std::iter::from_fn(move || {
        let (head, rest) = extra.split_first_chunk::<4>()?;
        let id = le_u16(head, 0);
        let len = usize::from(le_u16(head, 2));
        extra = rest.get(len..)?;
        Some(id)
    })
}

#[cfg(test)]
mod tests;
