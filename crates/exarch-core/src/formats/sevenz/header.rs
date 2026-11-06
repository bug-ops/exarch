//! The one place a 7z header is opened.
//!
//! `sevenz-rust2` 0.25 builds `Archive::stream_map` with every per-block
//! table sized to the blocks, every per-file table sized to the files, and
//! pack-stream and file spans that lie within the archive, and rejects a header
//! with streams info and no files info. [`SevenZHeader`] can only be obtained
//! from [`read_sevenz_header`], so the accessors below index without a bounds
//! check at the call site. The one gap upstream leaves, pack streams without
//! blocks, is closed in `SevenZHeader::check`.

use crate::ArchiveError;
use crate::Malformation;
use crate::QuotaResource;
use crate::Result;
use crate::formats::common;
use crate::formats::source_fault::SourceRead;
use crate::formats::source_fault::SourceTap;
use sevenz_rust2::Archive;
use sevenz_rust2::Block;
use sevenz_rust2::Password;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::num::NonZeroU64;
use std::sync::OnceLock;

/// The six signature bytes every 7z archive starts with.
pub(crate) const SEVENZ_MAGIC: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

/// A valid empty 7z archive is exactly 32 bytes: signature (6) + version (2) +
/// start header CRC (4) + start header (20). Shorter files are truncated.
const EMPTY_ARCHIVE_SIZE: u64 = 32;

/// Index of a block of a [`SevenZHeader`], in range for that header.
///
/// Only [`SevenZHeader`] mints one, so an accessor that takes it needs no
/// bounds check. It is only meaningful for the header that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BlockIndex(usize);

impl BlockIndex {
    /// The position of the block in the archive's block list.
    pub(crate) const fn get(self) -> usize {
        self.0
    }
}

/// A parsed 7z header whose stream map is consistent with its blocks and files.
///
/// Holds, for every block, an entry in `block_first_pack_stream_index` and
/// `block_first_file_index`, for every file an entry in `file_block_index`, and
/// for every pack stream an offset; every mapped block and every block's file
/// span lies within the archive. Obtained only from [`read_sevenz_header`].
#[derive(Debug, Clone)]
pub(crate) struct SevenZHeader {
    archive: Archive,
    unchecked_crc: OnceLock<Archive>,
}

impl SevenZHeader {
    /// Checks that `archive`'s stream map holds an offset for every pack
    /// stream.
    ///
    /// Upstream leaves the offsets empty when the header lists pack streams
    /// but no blocks; no block then reads them, but the accessor promises one
    /// offset per pack stream, so such a header is refused.
    fn check(archive: Archive) -> Result<Self> {
        let offsets = archive.stream_map.pack_stream_offsets().len();
        let pack_streams = archive.pack_sizes().len();
        if offsets != pack_streams {
            return Err(ArchiveError::from(
                Malformation::SevenZPackStreamOffsetMismatch {
                    offsets,
                    pack_streams,
                },
            ));
        }
        Ok(Self::new(archive))
    }

    /// The header of the valid empty archive.
    fn empty() -> Self {
        Self::new(Archive::default())
    }

    fn new(archive: Archive) -> Self {
        Self {
            archive,
            unchecked_crc: OnceLock::new(),
        }
    }

    /// Wraps a hand-built archive without checking it, for tests that
    /// construct inconsistent-looking archives on purpose.
    #[cfg(test)]
    pub(crate) fn assume_checked(archive: Archive) -> Self {
        Self::new(archive)
    }

    /// The parsed archive, for `sevenz-rust2` calls that take it whole.
    pub(crate) const fn archive(&self) -> &Archive {
        &self.archive
    }

    /// The archive with every file checksum marked absent, for
    /// `sevenz-rust2` block decoding.
    ///
    /// Since 0.25 the block decoder keeps failing every read of an entry after
    /// a checksum mismatch and ends the block, so entries after a corrupt one
    /// would go unchecked. Decoding through this view lets the caller verify
    /// each entry's checksum itself and carry on, as the parallel path does;
    /// the block checksum and the declared-size checks stay with the decoder.
    pub(crate) fn unchecked_crc_archive(&self) -> &Archive {
        self.unchecked_crc.get_or_init(|| {
            let mut archive = self.archive.clone();
            archive.files.iter_mut().for_each(|f| f.has_crc = false);
            archive
        })
    }

    /// The archive's file entries.
    pub(crate) fn files(&self) -> &[sevenz_rust2::ArchiveEntry] {
        &self.archive.files
    }

    /// Whether the archive is solid.
    pub(crate) const fn is_solid(&self) -> bool {
        self.archive.is_solid
    }

    /// Number of blocks.
    pub(crate) fn block_count(&self) -> usize {
        self.archive.blocks.len()
    }

    /// Every block index, ascending.
    pub(crate) fn block_indices(&self) -> impl Iterator<Item = BlockIndex> + use<> {
        (0..self.archive.blocks.len()).map(BlockIndex)
    }

    /// The block at `index`.
    pub(crate) fn block(&self, index: BlockIndex) -> &Block {
        &self.archive.blocks[index.0]
    }

    /// The block holding the data of `file`, or `None` for a file without data
    /// or an index past the file list.
    pub(crate) fn file_block(&self, file: usize) -> Option<BlockIndex> {
        self.archive
            .stream_map
            .file_block_index
            .get(file)
            .copied()
            .flatten()
            .map(BlockIndex)
    }

    /// The index of the first file `block` decodes.
    pub(crate) fn block_first_file(&self, block: BlockIndex) -> usize {
        self.archive.stream_map.block_first_file_index[block.0]
    }

    /// The index of the first pack stream of `block`.
    pub(crate) fn block_first_pack(&self, block: BlockIndex) -> usize {
        self.archive.stream_map.block_first_pack_stream_index()[block.0]
    }

    /// The first pack stream of the block after `block`, if there is one.
    pub(crate) fn next_block_first_pack(&self, block: BlockIndex) -> Option<usize> {
        self.archive
            .stream_map
            .block_first_pack_stream_index()
            .get(block.0 + 1)
            .copied()
    }

    /// Offset of each pack stream from the first one.
    pub(crate) fn pack_stream_offsets(&self) -> &[u64] {
        self.archive.stream_map.pack_stream_offsets()
    }
}

/// The header limit in KiB, rounded down so a limit below 1 KiB refuses every
/// header, and saturated where `usize` is narrower than the limit.
fn header_limit_kib(limit: NonZeroU64) -> usize {
    usize::try_from(limit.get() / 1024).unwrap_or(usize::MAX)
}

/// A header limit that never refuses, for tests of other behaviour.
#[cfg(test)]
pub(crate) const UNLIMITED: NonZeroU64 = NonZeroU64::MAX;

/// Opens the 7z header of `source`, the only place one is parsed.
///
/// `max_decoder_memory` bounds what an encoded header may allocate: the plain
/// and decoded header sizes and, for the header coder, its declared
/// dictionary (not the output-bounded window that blocks are charged). Block
/// decoding is not limited here; admission estimates each block's window
/// separately.
///
/// A password requirement is [`common::encrypted_archive_error`]. The valid
/// 32-byte empty archive, which `sevenz-rust2` reports as `UnexpectedEof`,
/// opens as an empty header.
///
/// # Errors
///
/// Returns [`ArchiveError::InvalidArchive`] for a header that does not parse
/// or that lists pack streams without a stream-map offset for each, and
/// [`ArchiveError::QuotaExceeded`] with [`QuotaResource::DecoderMemory`] when
/// the header needs more than `max_decoder_memory`.
pub(crate) fn read_sevenz_header<R: Read + Seek>(
    source: &mut R,
    max_decoder_memory: NonZeroU64,
) -> Result<SevenZHeader> {
    let tap = SourceTap::default();
    let parsed = Archive::read_with_memory_limit(
        &mut SourceRead::new(&mut *source, tap.clone()),
        &Password::empty(),
        header_limit_kib(max_decoder_memory),
    );
    match parsed {
        Ok(archive) => SevenZHeader::check(archive),
        Err(error) => header_failure(&error, &tap, source, max_decoder_memory),
    }
}

/// The result of a header parse that failed with `error`: a fault the source
/// raised is I/O, never a verdict on the header.
fn header_failure<R: Read + Seek>(
    error: &sevenz_rust2::Error,
    tap: &SourceTap,
    source: &mut R,
    max_decoder_memory: NonZeroU64,
) -> Result<SevenZHeader> {
    if let Some(fault) = tap.fault() {
        return Err(ArchiveError::Io(fault));
    }
    if matches!(error, sevenz_rust2::Error::MaxMemLimited { .. }) {
        return Err(ArchiveError::QuotaExceeded {
            resource: QuotaResource::DecoderMemory {
                max: max_decoder_memory.get(),
            },
        });
    }
    if super::is_password_error(error) {
        return Err(common::encrypted_archive_error());
    }
    if is_empty_sevenz_archive(error, source) {
        return Ok(SevenZHeader::empty());
    }
    Err(ArchiveError::from(Malformation::SevenZHeaderUnreadable {
        detail: error.to_string().into(),
    }))
}

/// Whether a `sevenz-rust2` parse failure is a valid empty 7z archive: an
/// `UnexpectedEof` on a 32-byte source that starts with the 7z signature.
fn is_empty_sevenz_archive<R: Read + Seek>(err: &sevenz_rust2::Error, source: &mut R) -> bool {
    let is_eof = matches!(err, sevenz_rust2::Error::Io(io_err, _) if io_err.kind() == ErrorKind::UnexpectedEof);
    if !is_eof {
        return false;
    }
    let Ok(size) = source.seek(SeekFrom::End(0)) else {
        return false;
    };
    if size != EMPTY_ARCHIVE_SIZE {
        return false;
    }
    if source.seek(SeekFrom::Start(0)).is_err() {
        return false;
    }
    let mut magic = [0u8; 6];
    source.read_exact(&mut magic).is_ok() && magic == SEVENZ_MAGIC
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::assert_matches;
    use std::io::Cursor;

    const NO_FILES_INFO: &[u8] =
        include_bytes!("../../../../../tests/fixtures/streams-without-files-info.7z");
    const SIMPLE: &[u8] = include_bytes!("../../../../../tests/fixtures/simple.7z");

    fn parsed(bytes: &[u8]) -> Archive {
        Archive::read(&mut Cursor::new(bytes), &Password::empty()).unwrap()
    }

    fn crc32(data: &[u8]) -> u32 {
        !data.iter().fold(!0u32, |mut crc, &byte| {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xEDB8_8320 & 0u32.wrapping_sub(crc & 1));
            }
            crc
        })
    }

    /// A plain header that lists one pack stream and no blocks or files.
    fn archive_with_pack_stream_and_no_blocks() -> Vec<u8> {
        let header = [0x01, 0x04, 0x06, 0x00, 0x01, 0x09, 0x01, 0x00, 0x00, 0x00];
        let mut start = Vec::new();
        start.extend_from_slice(&0u64.to_le_bytes());
        start.extend_from_slice(&(header.len() as u64).to_le_bytes());
        start.extend_from_slice(&crc32(&header).to_le_bytes());
        let mut bytes = SEVENZ_MAGIC.to_vec();
        bytes.extend_from_slice(&[0, 4]);
        bytes.extend_from_slice(&crc32(&start).to_le_bytes());
        bytes.extend_from_slice(&start);
        bytes.extend_from_slice(&header);
        bytes
    }

    #[test]
    fn header_limit_rounds_down_to_whole_kib_and_saturates() {
        let kib = |bytes| header_limit_kib(NonZeroU64::new(bytes).unwrap());
        assert_eq!(kib(1), 0);
        assert_eq!(kib(1023), 0);
        assert_eq!(kib(1024), 1);
        assert_eq!(kib(2047), 1);
        assert_eq!(
            kib(u64::MAX),
            usize::try_from(u64::MAX / 1024).unwrap_or(usize::MAX)
        );
    }

    #[test]
    fn upstream_rejects_streams_without_files_info() {
        let err = Archive::read(&mut Cursor::new(NO_FILES_INFO), &Password::empty()).unwrap_err();
        assert!(err.to_string().contains("no files info"), "{err}");
    }

    #[test]
    fn upstream_leaves_pack_offsets_empty_without_blocks() {
        let bytes = archive_with_pack_stream_and_no_blocks();
        let archive = parsed(&bytes);
        assert!(archive.blocks.is_empty());
        assert_eq!(archive.pack_sizes().len(), 1);
        assert!(archive.stream_map.pack_stream_offsets().is_empty());
    }

    #[test]
    fn check_rejects_pack_streams_without_blocks() {
        let bytes = archive_with_pack_stream_and_no_blocks();
        let err = read_sevenz_header(&mut Cursor::new(bytes), UNLIMITED).unwrap_err();
        assert_matches!(&err, ArchiveError::InvalidArchive(m) if m.to_string().starts_with("failed to open 7z archive: "),
            "{err:?}"
        );
    }

    #[test]
    fn check_accepts_a_valid_archive() {
        let header = SevenZHeader::check(parsed(SIMPLE)).unwrap();
        assert!(header.block_indices().count() > 0);
        assert!(
            header
                .files()
                .iter()
                .enumerate()
                .all(|(i, f)| { header.file_block(i).is_some() == f.has_stream })
        );
    }

    #[test]
    fn check_accepts_an_archive_without_blocks() {
        assert!(SevenZHeader::check(Archive::default()).is_ok());
    }

    #[test]
    fn file_block_ignores_an_index_past_the_files() {
        let header = SevenZHeader::check(parsed(SIMPLE)).unwrap();
        assert_eq!(header.file_block(usize::MAX), None);
    }

    #[test]
    fn read_header_rejects_the_vector_as_invalid_archive() {
        let err = read_sevenz_header(&mut Cursor::new(NO_FILES_INFO), UNLIMITED).unwrap_err();
        assert_matches!(&err, ArchiveError::InvalidArchive(m) if m.to_string().starts_with("failed to open 7z archive: "),
            "{err:?}"
        );
    }

    #[test]
    fn read_header_opens_the_empty_archive() {
        let bytes = include_bytes!("../../../../../tests/fixtures/empty.7z");
        let header = read_sevenz_header(&mut Cursor::new(&bytes[..]), UNLIMITED).unwrap();
        assert!(header.files().is_empty());
        assert_eq!(header.block_count(), 0);
    }
}
