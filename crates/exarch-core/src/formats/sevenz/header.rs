//! The one place a 7z header is opened, and the proof that its stream map
//! covers every block and file.
//!
//! `sevenz-rust2` builds `Archive::stream_map` only while it reads the files
//! info, so a header with streams info and no files info parses to an archive
//! whose map is empty while `blocks` is not. [`SevenZHeader`] can only be
//! obtained from [`read_sevenz_header`], which rejects such an archive, so the
//! accessors below index without a bounds check at the call site.

use crate::ArchiveError;
use crate::Result;
use crate::formats::common;
use sevenz_rust2::Archive;
use sevenz_rust2::Block;
use sevenz_rust2::BlockDecoder;
use sevenz_rust2::Password;
use std::fmt;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

/// The six signature bytes every 7z archive starts with.
pub const SEVENZ_MAGIC: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

/// A valid empty 7z archive is exactly 32 bytes: signature (6) + version (2) +
/// start header CRC (4) + start header (20). Shorter files are truncated.
const EMPTY_ARCHIVE_SIZE: u64 = 32;

/// Index of a block of a [`SevenZHeader`], in range for that header.
///
/// Only [`SevenZHeader`] mints one, so an accessor that takes it needs no
/// bounds check. It is only meaningful for the header that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlockIndex(usize);

impl BlockIndex {
    /// The position of the block in the archive's block list.
    pub const fn get(self) -> usize {
        self.0
    }
}

/// A parsed 7z header whose stream map is consistent with its blocks and files.
///
/// Holds, for every block, an entry in `block_first_pack_stream_index` and
/// `block_first_file_index`, and for every file an entry in
/// `file_block_index`; every mapped block and every block's file span lies
/// within the archive. Obtained only from [`read_sevenz_header`].
#[derive(Debug, Clone)]
pub struct SevenZHeader {
    archive: Archive,
}

/// Which per-block table of the stream map a [`StreamMapDefect`] concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockTable {
    FirstPackStream,
    FirstFile,
}

impl fmt::Display for BlockTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::FirstPackStream => "first pack stream",
            Self::FirstFile => "first file",
        })
    }
}

/// Why a parsed header's stream map does not cover its blocks and files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamMapDefect {
    BlockTableLen {
        table: BlockTable,
        len: usize,
        blocks: usize,
    },
    FileTableLen {
        len: usize,
        files: usize,
    },
    PackOffsetsLen {
        len: usize,
        pack_streams: usize,
    },
    FileBlockOutOfRange {
        file: usize,
        block: usize,
        blocks: usize,
    },
    BlockSpanOutOfRange {
        block: usize,
        files: usize,
    },
    PackSpanOutOfRange {
        block: usize,
        start: usize,
        pack_streams: usize,
    },
}

impl fmt::Display for StreamMapDefect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::BlockTableLen { table, len, blocks } => {
                write!(f, "the {table} table has {len} entries for {blocks} blocks")
            }
            Self::FileTableLen { len, files } => {
                write!(
                    f,
                    "the file-to-block table has {len} entries for {files} files"
                )
            }
            Self::PackOffsetsLen { len, pack_streams } => write!(
                f,
                "the pack stream offsets have {len} entries for {pack_streams} pack streams"
            ),
            Self::FileBlockOutOfRange {
                file,
                block,
                blocks,
            } => write!(f, "file {file} maps to block {block} of {blocks}"),
            Self::BlockSpanOutOfRange { block, files } => {
                write!(f, "block {block} spans files beyond the {files} listed")
            }
            Self::PackSpanOutOfRange {
                block,
                start,
                pack_streams,
            } => write!(
                f,
                "block {block} starts at pack stream {start} of {pack_streams}"
            ),
        }
    }
}

impl From<StreamMapDefect> for ArchiveError {
    fn from(defect: StreamMapDefect) -> Self {
        Self::InvalidArchive(format!("failed to open 7z archive: {defect}"))
    }
}

impl SevenZHeader {
    /// Checks that `archive`'s stream map covers its blocks and files.
    ///
    /// `sevenz-rust2` rejects most inconsistent maps itself; a header with
    /// streams info and no files info (upstream commits b7093c37 and df5b7a96,
    /// unreleased as of 0.24.1) and the later indexing by file and block are
    /// what this guards in exarch.
    fn check(archive: Archive) -> std::result::Result<Self, StreamMapDefect> {
        let map = &archive.stream_map;
        let blocks = archive.blocks.len();
        let files = archive.files.len();
        let block_tables = [
            (
                BlockTable::FirstPackStream,
                map.block_first_pack_stream_index().len(),
            ),
            (BlockTable::FirstFile, map.block_first_file_index.len()),
        ];
        for (table, len) in block_tables {
            if len != blocks {
                return Err(StreamMapDefect::BlockTableLen { table, len, blocks });
            }
        }
        if map.file_block_index.len() != files {
            return Err(StreamMapDefect::FileTableLen {
                len: map.file_block_index.len(),
                files,
            });
        }
        if map.pack_stream_offsets().len() != archive.pack_sizes().len() {
            return Err(StreamMapDefect::PackOffsetsLen {
                len: map.pack_stream_offsets().len(),
                pack_streams: archive.pack_sizes().len(),
            });
        }
        for (file, mapped) in map.file_block_index.iter().enumerate() {
            if let Some(block) = *mapped
                && block >= blocks
            {
                return Err(StreamMapDefect::FileBlockOutOfRange {
                    file,
                    block,
                    blocks,
                });
            }
        }
        check_pack_spans(
            map.block_first_pack_stream_index(),
            archive.pack_sizes().len(),
        )?;
        let password = Password::empty();
        let mut no_source = std::io::Cursor::new(&[][..]);
        for (block, &first) in map.block_first_file_index.iter().enumerate() {
            let count =
                BlockDecoder::new(1, block, &archive, &password, &mut no_source).entry_count();
            if first.checked_add(count).is_none_or(|end| end > files) {
                return Err(StreamMapDefect::BlockSpanOutOfRange { block, files });
            }
        }
        Ok(Self { archive })
    }

    /// The header of the valid empty archive.
    fn empty() -> Self {
        Self {
            archive: Archive::default(),
        }
    }

    /// Wraps a hand-built archive without checking it, for tests that
    /// construct inconsistent-looking archives on purpose.
    #[cfg(test)]
    pub fn assume_checked(archive: Archive) -> Self {
        Self { archive }
    }

    /// The parsed archive, for `sevenz-rust2` calls that take it whole.
    pub const fn archive(&self) -> &Archive {
        &self.archive
    }

    /// The archive's file entries.
    pub fn files(&self) -> &[sevenz_rust2::ArchiveEntry] {
        &self.archive.files
    }

    /// Whether the archive is solid.
    pub const fn is_solid(&self) -> bool {
        self.archive.is_solid
    }

    /// Number of blocks.
    pub fn block_count(&self) -> usize {
        self.archive.blocks.len()
    }

    /// Every block index, ascending.
    pub fn block_indices(&self) -> impl Iterator<Item = BlockIndex> + use<> {
        (0..self.archive.blocks.len()).map(BlockIndex)
    }

    /// The block at `index`.
    pub fn block(&self, index: BlockIndex) -> &Block {
        &self.archive.blocks[index.0]
    }

    /// The block holding the data of `file`, or `None` for a file without data
    /// or an index past the file list.
    pub fn file_block(&self, file: usize) -> Option<BlockIndex> {
        self.archive
            .stream_map
            .file_block_index
            .get(file)
            .copied()
            .flatten()
            .map(BlockIndex)
    }

    /// The index of the first file `block` decodes.
    pub fn block_first_file(&self, block: BlockIndex) -> usize {
        self.archive.stream_map.block_first_file_index[block.0]
    }

    /// The index of the first pack stream of `block`.
    pub fn block_first_pack(&self, block: BlockIndex) -> usize {
        self.archive.stream_map.block_first_pack_stream_index()[block.0]
    }

    /// The first pack stream of the block after `block`, if there is one.
    pub fn next_block_first_pack(&self, block: BlockIndex) -> Option<usize> {
        self.archive
            .stream_map
            .block_first_pack_stream_index()
            .get(block.0 + 1)
            .copied()
    }

    /// Offset of each pack stream from the first one.
    pub fn pack_stream_offsets(&self) -> &[u64] {
        self.archive.stream_map.pack_stream_offsets()
    }
}

/// Opens the 7z header of `source`, the only place one is parsed.
///
/// A password requirement is [`common::encrypted_archive_error`]. The valid
/// 32-byte empty archive, which `sevenz-rust2` reports as `UnexpectedEof`,
/// opens as an empty header.
///
/// # Errors
///
/// Returns [`ArchiveError::InvalidArchive`] for a header that does not parse
/// or whose stream map does not cover its blocks and files.
pub fn read_sevenz_header<R: Read + Seek>(source: &mut R) -> Result<SevenZHeader> {
    match Archive::read(&mut *source, &Password::empty()) {
        Ok(archive) => Ok(SevenZHeader::check(archive)?),
        Err(e) if super::is_password_error(&e) => Err(common::encrypted_archive_error()),
        Err(e) if is_empty_sevenz_archive(&e, source) => Ok(SevenZHeader::empty()),
        Err(e) => Err(ArchiveError::InvalidArchive(format!(
            "failed to open 7z archive: {e}"
        ))),
    }
}

/// Checks that the first pack stream of every block lies within the pack
/// streams and does not pass the next block's, so slicing the pack sizes from
/// one block's start to the next never goes out of range.
///
/// `sevenz-rust2` 0.24.1 enforces this while building the map; re-evaluate the
/// check after its next release (#751).
fn check_pack_spans(
    first_packs: &[usize],
    pack_streams: usize,
) -> std::result::Result<(), StreamMapDefect> {
    let mut previous = 0;
    for (block, &start) in first_packs.iter().enumerate() {
        if start < previous || start > pack_streams {
            return Err(StreamMapDefect::PackSpanOutOfRange {
                block,
                start,
                pack_streams,
            });
        }
        previous = start;
    }
    Ok(())
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
    use std::io::Cursor;

    const NO_FILES_INFO: &[u8] =
        include_bytes!("../../../../../tests/fixtures/streams-without-files-info.7z");
    const SIMPLE: &[u8] = include_bytes!("../../../../../tests/fixtures/simple.7z");

    fn parsed(bytes: &[u8]) -> Archive {
        Archive::read(&mut Cursor::new(bytes), &Password::empty()).unwrap()
    }

    #[test]
    fn upstream_vector_parses_with_blocks_and_no_map() {
        let archive = parsed(NO_FILES_INFO);
        assert_eq!(archive.blocks.len(), 1);
        assert!(archive.files.is_empty());
        assert!(
            archive
                .stream_map
                .block_first_pack_stream_index()
                .is_empty()
        );
    }

    #[test]
    fn check_rejects_streams_without_files_info() {
        let defect = SevenZHeader::check(parsed(NO_FILES_INFO)).unwrap_err();
        assert_eq!(
            defect,
            StreamMapDefect::BlockTableLen {
                table: BlockTable::FirstPackStream,
                len: 0,
                blocks: 1,
            }
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
    fn check_rejects_short_first_file_table() {
        let mut archive = parsed(SIMPLE);
        archive.stream_map.block_first_file_index.clear();
        assert!(matches!(
            SevenZHeader::check(archive),
            Err(StreamMapDefect::BlockTableLen {
                table: BlockTable::FirstFile,
                ..
            })
        ));
    }

    #[test]
    fn check_rejects_short_file_table() {
        let mut archive = parsed(SIMPLE);
        archive.stream_map.file_block_index.pop();
        assert!(matches!(
            SevenZHeader::check(archive),
            Err(StreamMapDefect::FileTableLen { .. })
        ));
    }

    #[test]
    fn check_rejects_out_of_range_block() {
        let mut archive = parsed(SIMPLE);
        let blocks = archive.blocks.len();
        archive.stream_map.file_block_index[0] = Some(blocks);
        assert!(matches!(
            SevenZHeader::check(archive),
            Err(StreamMapDefect::FileBlockOutOfRange { file: 0, .. })
        ));
    }

    #[test]
    fn check_rejects_block_span_past_the_files() {
        let mut archive = parsed(SIMPLE);
        let files = archive.files.len();
        archive.stream_map.block_first_file_index[0] = files;
        assert!(matches!(
            SevenZHeader::check(archive),
            Err(StreamMapDefect::BlockSpanOutOfRange { block: 0, .. })
        ));
    }

    #[test]
    fn pack_spans_must_ascend_within_the_pack_streams() {
        assert_eq!(check_pack_spans(&[0, 1, 1, 3], 3), Ok(()));
        assert_eq!(check_pack_spans(&[], 0), Ok(()));
        assert_eq!(
            check_pack_spans(&[0, 4], 3),
            Err(StreamMapDefect::PackSpanOutOfRange {
                block: 1,
                start: 4,
                pack_streams: 3
            })
        );
        assert!(matches!(
            check_pack_spans(&[2, 1], 3),
            Err(StreamMapDefect::PackSpanOutOfRange { block: 1, .. })
        ));
    }

    #[test]
    fn file_block_ignores_an_index_past_the_files() {
        let header = SevenZHeader::check(parsed(SIMPLE)).unwrap();
        assert_eq!(header.file_block(usize::MAX), None);
    }

    #[test]
    fn read_header_rejects_the_vector_as_invalid_archive() {
        let err = read_sevenz_header(&mut Cursor::new(NO_FILES_INFO)).unwrap_err();
        assert!(
            matches!(&err, ArchiveError::InvalidArchive(m) if m.starts_with("failed to open 7z archive: ")),
            "{err:?}"
        );
    }

    #[test]
    fn read_header_opens_the_empty_archive() {
        let bytes = include_bytes!("../../../../../tests/fixtures/empty.7z");
        let header = read_sevenz_header(&mut Cursor::new(&bytes[..])).unwrap();
        assert!(header.files().is_empty());
        assert_eq!(header.block_count(), 0);
    }
}
