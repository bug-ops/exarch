//! The one place a 7z header is opened.
//!
//! `sevenz-rust2` 0.25 builds `Archive::stream_map` with every per-block
//! table sized to the blocks, every per-file table sized to the files, and
//! pack-stream and file spans that lie within the archive, and rejects a header
//! with streams info and no files info. [`SevenZHeader`] can only be obtained
//! from [`read_sevenz_header`], so the accessors below index without a bounds
//! check at the call site. The one gap upstream leaves, pack streams without
//! blocks, is closed in `SevenZHeader::check`.

use super::header_probe::DeclaredHeader;
use super::header_probe::HeaderEntries;
use super::header_probe::Refusal;
use super::header_probe::header_entries;
use super::header_probe::probe;
use crate::ArchiveError;
use crate::EncryptionRefusal;
use crate::Malformation;
use crate::QuotaResource;
use crate::Result;
use crate::Violation;
use crate::encryption::Credentials;
use crate::encryption::kdf::KdfRuns;
use crate::encryption::kdf::KeyMode;
use crate::encryption::kdf::KeySource;
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
    /// The first block, for tests.
    #[cfg(test)]
    pub(crate) const fn first() -> Self {
        Self(0)
    }

    /// The position of the block in the archive's block list.
    pub(crate) const fn get(self) -> usize {
        self.0
    }
}

/// Index of a file of a [`SevenZHeader`], in range for that header.
///
/// Only [`SevenZHeader`] mints one, so [`SevenZHeader::file`] needs no bounds
/// check. It is only meaningful for the header that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FileIndex(usize);

impl FileIndex {
    /// The file at `position`, for tests that build tables without a header.
    #[cfg(test)]
    pub(crate) const fn at(position: usize) -> Self {
        Self(position)
    }

    /// The position of the file in the archive's file list.
    pub(crate) const fn get(self) -> usize {
        self.0
    }
}

/// One `T` per block of a [`SevenZHeader`], indexed by [`BlockIndex`].
///
/// Only [`SevenZHeader::per_block`] builds one, sized to that header's blocks,
/// so indexing it with a [`BlockIndex`] of the same header cannot go out of
/// range.
#[derive(Debug, Clone)]
pub(crate) struct PerBlock<T>(Vec<T>);

impl<T> PerBlock<T> {
    /// The entries in block order.
    pub(crate) fn iter(&self) -> std::slice::Iter<'_, T> {
        self.0.iter()
    }

    /// Sets every entry to `value`.
    pub(crate) fn fill(&mut self, value: T)
    where
        T: Clone,
    {
        self.0.fill(value);
    }
}

impl<T> std::ops::Index<BlockIndex> for PerBlock<T> {
    type Output = T;

    #[expect(
        clippy::indexing_slicing,
        reason = "the table is sized to the header whose blocks mint the index"
    )]
    fn index(&self, block: BlockIndex) -> &T {
        &self.0[block.0]
    }
}

impl<T> std::ops::IndexMut<BlockIndex> for PerBlock<T> {
    #[expect(
        clippy::indexing_slicing,
        reason = "the table is sized to the header whose blocks mint the index"
    )]
    fn index_mut(&mut self, block: BlockIndex) -> &mut T {
        &mut self.0[block.0]
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
    credentials: Credentials,
    header_encrypted: bool,
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
            credentials: Credentials::default(),
            header_encrypted: false,
        }
    }

    /// Keeps the password the archive was opened with, and whether its header
    /// was encrypted, for the decoding and admission that follow.
    fn opened_with(mut self, credentials: Credentials, header_encrypted: bool) -> Self {
        self.credentials = credentials;
        self.header_encrypted = header_encrypted;
        self
    }

    /// The password the archive was opened with.
    pub(crate) const fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    /// Whether the header itself was encrypted, which costs one key
    /// derivation `exarch` cannot observe.
    pub(crate) const fn header_encrypted(&self) -> bool {
        self.header_encrypted
    }

    /// Whether the block holds AES-encrypted content.
    pub(crate) fn is_block_encrypted(&self, index: BlockIndex) -> bool {
        block_is_encrypted(self.block(index))
    }

    /// The password block decoding passes to `sevenz-rust2`.
    ///
    /// Empty when none was supplied or when the supplied bytes are not text a
    /// 7z password can be: admission has already refused every encrypted
    /// block in that case, so no block reads it.
    pub(crate) fn block_password(&self) -> Password {
        self.credentials
            .sevenz_secret()
            .ok()
            .flatten()
            .unwrap_or_else(Password::empty)
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
    ///
    /// Clones the archive once per header, on first use.
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

    /// Every file index, ascending.
    pub(crate) fn file_indices(&self) -> impl Iterator<Item = FileIndex> + use<> {
        (0..self.archive.files.len()).map(FileIndex)
    }

    /// The index of the file at `position`, or `None` past the file list.
    pub(crate) fn file_index(&self, position: usize) -> Option<FileIndex> {
        (position < self.archive.files.len()).then_some(FileIndex(position))
    }

    /// The file at `index`.
    #[expect(
        clippy::indexing_slicing,
        reason = "a FileIndex is minted only by this header from its own file list and never crosses headers"
    )]
    pub(crate) fn file(&self, index: FileIndex) -> &sevenz_rust2::ArchiveEntry {
        &self.archive.files[index.0]
    }

    /// Whether the archive is solid.
    pub(crate) const fn is_solid(&self) -> bool {
        self.archive.is_solid
    }

    /// Number of blocks.
    pub(crate) fn block_count(&self) -> usize {
        self.archive.blocks.len()
    }

    /// A table with `value` for every block.
    pub(crate) fn per_block<T: Clone>(&self, value: T) -> PerBlock<T> {
        PerBlock(vec![value; self.block_count()])
    }

    /// Every block index, ascending.
    pub(crate) fn block_indices(&self) -> impl Iterator<Item = BlockIndex> + use<> {
        (0..self.archive.blocks.len()).map(BlockIndex)
    }

    /// The block at `index`.
    #[expect(
        clippy::indexing_slicing,
        reason = "sevenz-rust2 >= 0.24.2 sizes its block tables to the blocks"
    )]
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
    #[expect(
        clippy::indexing_slicing,
        reason = "sevenz-rust2 >= 0.24.2 sizes its block tables to the blocks"
    )]
    pub(crate) fn block_first_file(&self, block: BlockIndex) -> usize {
        self.archive.stream_map.block_first_file_index[block.0]
    }

    /// The index of the first pack stream of `block`.
    #[expect(
        clippy::indexing_slicing,
        reason = "sevenz-rust2 >= 0.24.2 sizes its block tables to the blocks"
    )]
    pub(crate) fn block_first_pack(&self, block: BlockIndex) -> usize {
        self.archive.stream_map.block_first_pack_stream_index()[block.0]
    }

    /// The first pack stream of the block after `block`, if there is one.
    pub(crate) fn next_block_first_pack(&self, block: BlockIndex) -> Option<usize> {
        self.archive
            .stream_map
            .block_first_pack_stream_index()
            .get(block.0.saturating_add(1))
            .copied()
    }

    /// Offset of each pack stream from the first one.
    pub(crate) fn pack_stream_offsets(&self) -> &[u64] {
        self.archive.stream_map.pack_stream_offsets()
    }
}

/// Header bytes a 7z archive may spend per permitted entry (`max_file_count`).
///
/// 7-Zip, py7zr and the sevenz-rust2 writer spend about `2 * (path length + 1)`
/// plus 20 to 45 bytes per entry, so 256 admits an average path of about 120
/// characters in an archive that holds exactly `max_file_count` entries (an
/// archive with fewer entries gets proportionally more room per entry). This
/// bounds the buffer that holds the header; the number of entries the header
/// declares, which sizes the entry table, is held to `max_file_count`
/// separately.
const HEADER_BYTES_PER_ENTRY: u64 = 256;

/// Header bytes allowed on top of the per-entry budget: stream and folder
/// descriptions.
const HEADER_BYTES_BASE: u64 = 64 * 1024;

fn block_is_encrypted(block: &Block) -> bool {
    block
        .coders
        .iter()
        .any(|coder| coder.encoder_method_id() == sevenz_rust2::EncoderMethod::ID_AES256_SHA256)
}

/// Header entries allowed on top of `max_file_count`: entries extraction does
/// not count against it (anti items) and small archives.
///
/// The table bounds are relative to the declared entry count, which an
/// unbounded `max_file_count` leaves free; only the header length and the
/// decoder memory limit bound the tables then.
pub(super) const HEADER_ENTRIES_BASE: u64 = 1024;

/// What the parse of a 7z header may use.
///
/// `memory` is what sevenz-rust2 holds the raw and decoded header sizes and
/// the header coder's declared dictionary or model to, in whole KiB.
/// `entry_bytes` additionally caps the plain or decoded header, which bounds
/// the entry table; it is checked here from the declared sizes ([`probe`]) so
/// that it does not also cap the header dictionary, which some writers set to
/// 8 MiB or more for small archives. `entries` caps the number of entries the
/// header declares, which the header size alone does not bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeaderLimit {
    memory: NonZeroU64,
    entry_bytes: NonZeroU64,
    entries: u64,
    kdf_work: NonZeroU64,
}

impl HeaderLimit {
    /// A limit that never refuses, for tests of other behaviour.
    #[cfg(test)]
    pub(crate) const UNLIMITED: Self = Self {
        memory: NonZeroU64::MAX,
        entry_bytes: NonZeroU64::MAX,
        entries: u64::MAX,
        kdf_work: NonZeroU64::MAX,
    };

    /// The limit of `config`: `max_decoder_memory`, and the header bytes its
    /// `max_file_count` entries may take.
    pub(crate) fn from_config(config: &crate::SecurityConfig) -> Self {
        let files = u64::try_from(config.max_file_count.ceiling()).unwrap_or(u64::MAX);
        Self {
            kdf_work: config.max_kdf_work,
            ..Self::from_limits(config.max_decoder_memory, files)
        }
    }

    fn from_limits(max_decoder_memory: NonZeroU64, max_file_count: u64) -> Self {
        let entry_bytes = max_file_count
            .saturating_mul(HEADER_BYTES_PER_ENTRY)
            .saturating_add(HEADER_BYTES_BASE);
        Self {
            memory: max_decoder_memory,
            entry_bytes: NonZeroU64::new(entry_bytes).unwrap_or(NonZeroU64::MAX),
            entries: max_file_count.saturating_add(HEADER_ENTRIES_BASE),
            kdf_work: NonZeroU64::MAX,
        }
    }

    /// The most a plain or decoded header may take, and the limit it comes
    /// from.
    fn header_cap(self) -> HeaderCap {
        if self.entry_bytes < self.memory {
            HeaderCap::EntryBudget(self.entry_bytes)
        } else {
            HeaderCap::Memory(self.memory)
        }
    }
}

/// The limit a header size is held to, named by where it comes from so that a
/// refusal says which limit was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderCap {
    /// `max_decoder_memory`.
    Memory(NonZeroU64),
    /// The header bytes `max_file_count` entries may take.
    EntryBudget(NonZeroU64),
}

impl HeaderCap {
    const fn bytes(self) -> NonZeroU64 {
        match self {
            Self::Memory(bytes) | Self::EntryBudget(bytes) => bytes,
        }
    }

    fn refusal(self) -> ArchiveError {
        let resource = match self {
            Self::Memory(bytes) => QuotaResource::DecoderMemory { max: bytes.get() },
            Self::EntryBudget(bytes) => QuotaResource::HeaderSize { max: bytes.get() },
        };
        ArchiveError::QuotaExceeded { resource }
    }
}

/// `limit` in KiB, rounded down so a limit below 1 KiB refuses every header,
/// and saturated where `usize` is narrower than the limit.
fn kib(limit: NonZeroU64) -> usize {
    usize::try_from(limit.get() / 1024).unwrap_or(usize::MAX)
}

/// Opens the 7z header of `source`, the only place one is parsed.
///
/// A plain header, or an encoded header's declared decoded size, over
/// [`HeaderLimit`]'s entry cap is refused before the parse. The entry table
/// sevenz-rust2 builds has one slot per entry the header declares, so the
/// declared count is read first (a plain header, or an encoded header with one
/// copy, LZMA or LZMA2 coder) and a header that declares more entries than
/// `max_file_count` plus a small allowance is refused whatever its size. A
/// header that is present but whose count cannot be read (another coder, a
/// layout the probe does not follow, a zeroed start header on a file longer
/// than an empty archive) is refused as unreadable rather than parsed. The
/// parse itself is held to `max_decoder_memory` on the raw header size, the
/// decoded header size and the header coder's declared dictionary or model
/// (not the output-bounded window that blocks are charged). Not bounded: the
/// buffer that receives the decoded header (about twice its limit at most) and
/// block decoding, whose windows admission estimates separately.
///
/// An encrypted header needs `credentials`: without a password the error is
/// [`common::encrypted_archive_error`]; the key derivation it costs is
/// reserved against `max_kdf_work` before the parse. The raw record and every
/// unpack size the encoded header declares are held to the entry cap before
/// the parse, which then runs under `max_decoder_memory`. The entry count of
/// such a header cannot be probed, so it is held to `max_file_count` after the
/// parse. A parse that fails on the memory limit is the quota refusal; any
/// other failure is a wrong password or corrupt data. The valid 32-byte empty
/// archive, which `sevenz-rust2` reports as `UnexpectedEof`, opens as an empty
/// header.
///
/// # Errors
///
/// Returns [`ArchiveError::InvalidArchive`] for a header that does not parse
/// or that lists pack streams without a stream-map offset for each or whose
/// entry count cannot be read, and
/// [`ArchiveError::QuotaExceeded`] with [`QuotaResource::HeaderSize`] when the
/// header is larger than `max_file_count` permits,
/// [`QuotaResource::HeaderEntryCount`] when it declares more entries than
/// `max_file_count` plus a small allowance and
/// [`QuotaResource::DecoderMemory`] when it needs more than
/// `max_decoder_memory`. A header whose block, sub-stream or pack-stream
/// table is longer than its entries and blocks account for is refused as
/// [`Malformation::SevenZHeaderTableTooLarge`] before the parse.
pub(crate) fn open_sevenz_header<R: Read + Seek>(
    source: &mut R,
    limit: HeaderLimit,
    credentials: &Credentials,
) -> Result<SevenZHeader> {
    let cap = limit.header_cap();
    let parse_limit = match probe(source, cap.bytes().get()) {
        DeclaredHeader::Plain { bytes: size } | DeclaredHeader::Encoded { decoded: size } => {
            if size > cap.bytes().get() {
                return Err(cap.refusal());
            }
            HeaderCap::Memory(limit.memory)
        }
        DeclaredHeader::Unrecognized => cap,
    };
    let mut header_password = None;
    match header_entries(source, cap.bytes().get(), kib(limit.memory)) {
        HeaderEntries::Declared(tables) if tables.entries() > limit.entries => {
            return Err(ArchiveError::QuotaExceeded {
                resource: QuotaResource::HeaderEntryCount {
                    declared: tables.entries(),
                    max: limit.entries,
                },
            });
        }
        HeaderEntries::Declared(tables) => {
            tables
                .within_bounds(HEADER_ENTRIES_BASE)
                .map_err(ArchiveError::from)?;
        }
        HeaderEntries::Unmodelled => {
            return Err(ArchiveError::from(Malformation::SevenZHeaderUnreadable {
                detail: "unsupported header layout: the number of entries cannot be read".into(),
            }));
        }
        HeaderEntries::Refused(Refusal::Encrypted(key)) => {
            header_password = Some(admit_encrypted_header(credentials, limit, key)?);
        }
        HeaderEntries::Refused(Refusal::Memory) => {
            return Err(HeaderCap::Memory(limit.memory).refusal());
        }
        HeaderEntries::NotApplicable => {}
    }
    let header_encrypted = header_password.is_some();
    let password = header_password.unwrap_or_else(Password::empty);
    source.seek(SeekFrom::Start(0)).map_err(ArchiveError::Io)?;
    let tap = SourceTap::default();
    let parsed = Archive::read_with_memory_limit(
        &mut SourceRead::new(&mut *source, tap.clone()),
        &password,
        kib(parse_limit.bytes()),
    );
    match parsed {
        Ok(archive) => {
            let declared = u64::try_from(archive.files.len()).unwrap_or(u64::MAX);
            if header_encrypted && declared > limit.entries {
                return Err(ArchiveError::QuotaExceeded {
                    resource: QuotaResource::HeaderEntryCount {
                        declared,
                        max: limit.entries,
                    },
                });
            }
            Ok(SevenZHeader::check(archive)?.opened_with(credentials.clone(), header_encrypted))
        }
        Err(error) => header_failure(&error, &tap, source, parse_limit, header_encrypted),
    }
}

/// Opens the header with no password, for tests of the header itself.
#[cfg(test)]
pub(crate) fn read_sevenz_header<R: Read + Seek>(
    source: &mut R,
    limit: HeaderLimit,
) -> Result<SevenZHeader> {
    open_sevenz_header(source, limit, &Credentials::default())
}

fn encryption_refusal(reason: EncryptionRefusal) -> ArchiveError {
    Violation::Encrypted { reason, name: None }.into()
}

/// Admits an encrypted header and returns the password to parse it with.
///
/// The refusal order is [`KdfRuns::admit_key`]'s; the key derivation is
/// reserved at its worst case because the header's own power is not visible.
fn admit_encrypted_header(
    credentials: &Credentials,
    limit: HeaderLimit,
    key: KeyMode,
) -> Result<Password> {
    Ok(KdfRuns::new(limit.kdf_work, true).admit_key(credentials, KeySource::Header(key))?)
}

/// The result of a header parse that failed with `error`: a fault the source
/// raised is I/O, never a verdict on the header. A memory-limit failure is the
/// quota refusal, whether or not the header is encrypted. Any other failed
/// parse of an encrypted header is a wrong password or corrupt data: 7z has no
/// verifier.
fn header_failure<R: Read + Seek>(
    error: &sevenz_rust2::Error,
    tap: &SourceTap,
    source: &mut R,
    limit: HeaderCap,
    header_encrypted: bool,
) -> Result<SevenZHeader> {
    if let Some(fault) = tap.fault() {
        return Err(ArchiveError::Io(fault));
    }
    if matches!(error, sevenz_rust2::Error::MaxMemLimited { .. }) {
        return Err(limit.refusal());
    }
    if header_encrypted {
        return Err(encryption_refusal(
            EncryptionRefusal::WrongPasswordOrCorrupt,
        ));
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
mod tests {
    use super::*;
    use std::assert_matches;
    use std::io::Cursor;

    const NO_FILES_INFO: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/streams-without-files-info.7z"
    ));
    const SIMPLE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/simple.7z"
    ));

    fn header_with_blocks(count: usize) -> SevenZHeader {
        let mut archive = Archive::default();
        archive.blocks = vec![Block::default(); count];
        SevenZHeader::assume_checked(archive)
    }

    #[test]
    fn per_block_is_sized_to_the_header_blocks() {
        let header = header_with_blocks(3);
        let table = header.per_block(0u8);
        assert_eq!(table.iter().count(), header.block_count());
        assert!(header.block_indices().all(|block| table[block] == 0));
    }

    #[test]
    fn per_block_index_mut_writes_only_the_addressed_block() {
        let header = header_with_blocks(3);
        let mut table = header.per_block(0u8);
        let second = header.block_indices().nth(1).unwrap();
        table[second] = 1;
        let expected: Vec<u8> = header
            .block_indices()
            .map(|block| u8::from(block == second))
            .collect();
        assert_eq!(table.iter().copied().collect::<Vec<_>>(), expected);
    }

    #[test]
    fn per_block_fill_sets_every_entry() {
        let header = header_with_blocks(3);
        let mut table = header.per_block(false);
        table.fill(true);
        assert!(table.iter().all(|&set| set));
    }

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
    fn the_entry_cap_follows_max_file_count_and_leaves_the_memory_limit() {
        let memory = NonZeroU64::new(1 << 30).unwrap();
        let limit = HeaderLimit::from_limits(memory, 1000);
        assert_eq!(
            limit.entry_bytes.get(),
            1000 * HEADER_BYTES_PER_ENTRY + HEADER_BYTES_BASE
        );
        assert_eq!(limit.memory, memory);
        assert_eq!(
            limit.header_cap(),
            HeaderCap::EntryBudget(limit.entry_bytes)
        );
        let zero = HeaderLimit::from_limits(memory, 0);
        assert_eq!(zero.entry_bytes.get(), HEADER_BYTES_BASE);
    }

    #[test]
    fn the_entry_limit_is_max_file_count_plus_the_allowance_and_saturates() {
        let memory = NonZeroU64::new(1 << 30).unwrap();
        assert_eq!(
            HeaderLimit::from_limits(memory, 1000).entries,
            1000 + HEADER_ENTRIES_BASE
        );
        assert_eq!(HeaderLimit::from_limits(memory, u64::MAX).entries, u64::MAX);
    }

    #[test]
    fn the_header_cap_is_the_lower_of_memory_and_entry_bytes() {
        let small = NonZeroU64::new(100 * 1024).unwrap();
        let limit = HeaderLimit::from_limits(small, 1_000_000);
        assert_eq!(limit.header_cap(), HeaderCap::Memory(small));
    }

    #[test]
    fn an_unbounded_entry_count_saturates_instead_of_overflowing() {
        let memory = NonZeroU64::new(256 << 20).unwrap();
        let limit = HeaderLimit::from_limits(memory, u64::MAX);
        assert_eq!(limit.entry_bytes, NonZeroU64::MAX);
        assert_eq!(limit.header_cap(), HeaderCap::Memory(memory));
    }

    #[test]
    fn header_limit_rounds_down_to_whole_kib_and_saturates() {
        let kib = |bytes| kib(NonZeroU64::new(bytes).unwrap());
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
        let err = read_sevenz_header(&mut Cursor::new(bytes), HeaderLimit::UNLIMITED).unwrap_err();
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
        let err = read_sevenz_header(&mut Cursor::new(NO_FILES_INFO), HeaderLimit::UNLIMITED)
            .unwrap_err();
        assert_matches!(&err, ArchiveError::InvalidArchive(m) if m.to_string().starts_with("failed to open 7z archive: "),
            "{err:?}"
        );
    }

    #[test]
    fn read_header_opens_the_empty_archive() {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/empty.7z"
        ));
        let header =
            read_sevenz_header(&mut Cursor::new(&bytes[..]), HeaderLimit::UNLIMITED).unwrap();
        assert!(header.files().is_empty());
        assert_eq!(header.block_count(), 0);
    }
}
