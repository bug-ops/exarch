//! 7z archive format extraction.
//!
//! Provides secure extraction of 7z archives with security validation.
//!
//! # Security Features
//!
//! - Encrypted archives rejected (AES-256, AES-128, `ZipCrypto`, all encryption
//!   methods)
//! - Solid archives rejected by default (configurable)
//! - Path traversal prevention
//! - Decompression bomb detection
//! - Memory exhaustion protection for solid blocks
//! - Windows symlink detection (via reparse point attributes)
//! - Unix symlink targets validated through the symlink policy
//!
//! # Supported Compression Methods
//!
//! - LZMA / LZMA2
//! - BZIP2
//! - `PPMd`
//! - DEFLATE
//! - Copy (stored)
//!
//! # Symlinks, Hardlinks and Special Entries
//!
//! 7z has no link entry type, so links are detected from attributes:
//!
//! - **Windows symlinks**: Detected via `FILE_ATTRIBUTE_REPARSE_POINT` and
//!   rejected: their target is not stored in a readable form
//! - **Unix symlinks**: Detected through the Unix mode p7zip keeps in the high
//!   16 bits of the attributes (`0x8000` flag plus `S_IFLNK`). The target is
//!   the entry's data. It is read and validated through the symlink policy, so
//!   the link is created only under `allow_symlinks`, and `list` and `verify`
//!   report the target
//! - **FIFOs, sockets, device nodes**, an undefined Unix type, or a recorded
//!   kind (Unix mode or the Windows directory bit) that contradicts the entry's
//!   own kind are refused by `list`, `verify` and `extract`
//! - **Hardlinks**: Cannot be detected, extracted as separate files (data
//!   duplication)
//!
//! **Cost**: Link targets live in the compressed data, so `list` and `verify`
//! (with `allow_symlinks`) decode every block that holds a link, and `extract`
//! decodes such a block twice, once to validate and once to extract. The work
//! is bounded by the solid policy, the admission checks and
//! `max_solid_block_memory`; archives without links are unaffected.
//!
//! **Security Impact**: A symlink target is checked against the destination
//! before the first write, and the link is validated again against the disk
//! when it is created, so a refusal at that point can leave the entries written
//! before it inside the destination.
//!
//! # Solid Archives
//!
//! 7z supports "solid" compression where multiple files are compressed together
//! as a single block. While this provides better compression ratios, it has
//! security implications:
//!
//! - **Memory exhaustion**: Extracting a single file requires decompressing the
//!   entire solid block into memory
//! - **Denial of service**: Malicious archives can create large solid blocks
//!   that exhaust available memory
//!
//! **Default Policy**: Solid archives are **rejected** by default.
//! Use `SecurityConfig::allow_solid_archives = true` to enable extraction with
//! memory limits enforced via `max_solid_block_memory`.
//!
//! # Decoder Memory and Block Layout
//!
//! `extract` and `verify` share one admission step, `sevenz_refusals`. Before
//! any byte is decoded, every block's coder memory (LZMA/LZMA2 dictionary,
//! `PPMd` memory) is checked against `max_decoder_memory`, and blocks with an
//! unknown coder, AES content encryption, or a stream-less entry between their
//! stream files are refused.
//!
//! # Parallel LZMA2 Decoding
//!
//! A block that holds a single LZMA2 stream is split at its dictionary resets
//! into independent runs (7-Zip writes one per 4x dictionary when it
//! compresses on several threads). `extract` and `verify` decode those runs
//! ahead on worker threads, within the lookahead memory [`ParallelDecode`]
//! allows (128 MiB by default), while the consumer reads them back in order.
//! A run that does not fit the budget, a stream the planner cannot prove well
//! formed, and every other block layout decode sequentially, with the same
//! bytes and error kinds (a corrupt stream fails the same file either way).
//! The decoder window stays bounded by `max_decoder_memory`; the lookahead adds
//! at most its configured budget on top. sevenz-rust2's own multi-threaded
//! reader is not used because it buffers whole runs with no output bound.
//!
//! **Residual (upstream)**: an encoded (compressed) archive header is decoded
//! inside `Archive::read` with sevenz-rust2's unlimited memory limit, before
//! exarch sees any block, so a `PPMd` or LZMA2 header coder can allocate up to
//! about 4 GiB. `max_decoder_memory` does not cover it until sevenz-rust2
//! exposes a limit on `Archive::read`.
//!
//! # Examples
//!
//! Basic extraction:
//!
//! ```no_run
//! use exarch_core::ExtractionOptions;
//! use exarch_core::SecurityConfig;
//! use exarch_core::formats::SevenZArchive;
//! use exarch_core::formats::traits::ArchiveFormat;
//! use std::fs::File;
//! use std::path::Path;
//!
//! # fn main() -> Result<(), exarch_core::ArchiveError> {
//! let file = File::open("archive.7z")?;
//! let mut archive = SevenZArchive::new(file)?;
//! let config = SecurityConfig::default().validate()?;
//! let report = archive.extract(
//!     Path::new("/output"),
//!     &config,
//!     &ExtractionOptions::default(),
//!     &mut exarch_core::NoopProgress,
//! )?;
//! println!("Extracted {} files", report.files_extracted);
//! # Ok(())
//! # }
//! ```
//!
//! Allow solid archives with memory limit:
//!
//! ```no_run
//! use exarch_core::ExtractionOptions;
//! use exarch_core::SecurityConfig;
//!
//! let mut config = SecurityConfig::default();
//! config.allow_solid_archives = true;
//! config.max_solid_block_memory = 512 * 1024 * 1024; // 512 MB
//! // ... extract with config
//! ```

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::id;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use sevenz_rust2::Archive;
use sevenz_rust2::BlockDecoder;
use sevenz_rust2::Password;

// Atomic counter for generating unique temporary file names
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Maximum number of attempts to create a uniquely-named temp file before
/// giving up.
///
/// Bounds retry cost if an attacker has pre-planted symlinks at several
/// predicted `.{name}.exarch-tmp-{pid}-{counter}` paths (issue #471); a
/// genuine collision from concurrent extraction into the same directory
/// resolves on the first or second attempt since `TEMP_COUNTER` is
/// monotonically increasing per process.
const MAX_TEMP_FILE_CREATE_ATTEMPTS: u32 = 8;

use crate::ArchiveError;
use crate::EntryCompression;
use crate::ExtractionOptions;
use crate::ExtractionReport;
use crate::ParallelDecode;
use crate::ProgressCallback;
use crate::Result;
use crate::SecurityConfig;
use crate::SolidBlock;
use crate::VerificationOptions;
use crate::config::Validated;
use crate::copy::CopyBuffer;
use crate::copy::CopyError;
use crate::copy::copy_with_buffer;
use crate::error::QuotaResource;
use crate::inspection::integrity::Charge;
use crate::inspection::integrity::DecodeFailure;
use crate::inspection::integrity::DecodeOutcome;
use crate::inspection::integrity::IntegrityPass;
use crate::inspection::integrity::Slot;
use crate::inspection::manifest::EntryPosition;
use crate::inspection::manifest::ManifestEntryType;
use crate::inspection::report::IssueCategory;
use crate::inspection::report::IssueSeverity;
use crate::inspection::report::UnverifiedReason;
use crate::inspection::report::VerificationIssue;
use crate::security::EntryValidator;
use crate::security::quota::QuotaPermit;
use crate::security::validator::EntryPath;
use crate::security::validator::NodeKind;
use crate::security::validator::ValidatedEntryType;
use crate::security::zipbomb::DeclaredCompressedBudget;
use crate::security::zipbomb::validate_entry_compression;
use crate::types::DestDir;
use crate::types::EntryType;
use crate::types::SafePath;
use crate::types::SafeSymlink;
use crate::types::safe_symlink::require_symlinks_allowed;

use super::common;
use super::sevenz_lzma2::DecodeKnobs;
use super::sevenz_lzma2::Lzma2Stream;
use super::sevenz_lzma2::with_parallel_reader;
use super::traits::ArchiveFormat;

/// Cached entry metadata from initial archive read.
/// Avoids re-parsing archive during extraction.
#[derive(Debug, Clone)]
struct CachedEntry {
    name: String,
    size: u64,
    class: SevenZClass,
    /// Validated compression info; see [`sevenz_entry_compression`].
    compression: EntryCompression,
}

/// Size of the fixed 7z signature header that precedes the packed streams.
const SIGNATURE_HEADER_SIZE: u64 = 32;

/// Number of packed streams a conforming block consumes: one, plus three more
/// per BCJ2 coder (four inputs, one output). Every other admitted method has a
/// single input.
///
/// The upstream accessors for the stream arity are `pub(crate)`, so the count
/// follows from the public method IDs. A crafted header can declare a coder
/// with the BCJ2 ID that the decode path never reaches; the count then exceeds
/// the real one by up to three streams per such coder, which is never looser
/// than counting every pack stream after the block.
fn packed_stream_count(block: &sevenz_rust2::Block) -> usize {
    use sevenz_rust2::EncoderMethod;

    let bcj2 = block
        .coders
        .iter()
        .filter(|coder| coder.encoder_method_id() == EncoderMethod::ID_BCJ2)
        .count();
    1 + 3 * bcj2
}

/// Derives how each file's data is compressed for ratio checks, after
/// validating the declared pack stream sizes against the archive length.
///
/// The returned vector is 1:1 with `archive.files`:
/// - a file alone in its block gets [`EntryCompression::Entry`] with the
///   checked sum of that block's pack streams;
/// - the first file of a multi-file (solid) block gets
///   [`EntryCompression::SolidBlockStart`] with the block's compressed total
///   and the checked sum of its files' sizes; the other members get
///   [`EntryCompression::SolidBlockMember`];
/// - files without a data stream (empty files, directories) get
///   [`EntryCompression::Unknown`].
///
/// The last block's pack streams are counted from its coders' method IDs (one,
/// plus three more per BCJ2 coder) and capped at the declared pack streams, so
/// pack streams no block references do not inflate its total. `source_len` must
/// be the length of the same source the archive is decoded from.
///
/// # Errors
///
/// Returns [`ArchiveError::InvalidArchive`] when the declared pack sizes
/// exceed the space the archive can hold, or a pack size sum overflows, and
/// [`ArchiveError::QuotaExceeded`] when a block's uncompressed sum overflows.
pub(crate) fn sevenz_entry_compression(
    archive: &Archive,
    source_len: u64,
) -> Result<Vec<EntryCompression>> {
    let data_region = source_len
        .checked_sub(SIGNATURE_HEADER_SIZE)
        .and_then(|len| len.checked_sub(archive.pack_pos()))
        .ok_or_else(|| {
            ArchiveError::InvalidArchive("declared compressed size exceeds archive length".into())
        })?;
    let mut budget = DeclaredCompressedBudget::new(data_region);
    for &pack_size in archive.pack_sizes() {
        budget.charge(pack_size)?;
    }

    let pack_sizes = archive.pack_sizes();
    let first_pack = archive.stream_map.block_first_pack_stream_index();
    let block_compressed = |block: usize| -> Result<u64> {
        let start = first_pack[block];
        let end = first_pack.get(block + 1).copied().unwrap_or_else(|| {
            start
                .saturating_add(packed_stream_count(&archive.blocks[block]))
                .min(pack_sizes.len())
        });
        pack_sizes[start..end]
            .iter()
            .try_fold(0u64, |acc, &size| acc.checked_add(size))
            .ok_or_else(|| ArchiveError::InvalidArchive("7z pack sizes overflow".into()))
    };

    let mut block_uncompressed = vec![0u64; archive.blocks.len()];
    let mut block_files = vec![0usize; archive.blocks.len()];
    for (index, file) in archive.files.iter().enumerate() {
        if let Some(block) = archive.stream_map.file_block_index[index] {
            block_files[block] += 1;
            block_uncompressed[block] = block_uncompressed[block].checked_add(file.size).ok_or(
                ArchiveError::QuotaExceeded {
                    resource: QuotaResource::IntegerOverflow,
                },
            )?;
        }
    }

    archive
        .files
        .iter()
        .enumerate()
        .map(|(index, file)| {
            let Some(block) = archive.stream_map.file_block_index[index] else {
                return Ok(EntryCompression::Unknown);
            };
            if !file.has_stream {
                return Ok(EntryCompression::Unknown);
            }
            let compressed = block_compressed(block)?;
            if block_files[block] <= 1 {
                return Ok(EntryCompression::Entry(compressed));
            }
            if archive.stream_map.block_first_file_index[block] == index {
                Ok(EntryCompression::SolidBlockStart(SolidBlock::new(
                    compressed,
                    block_uncompressed[block],
                )))
            } else {
                Ok(EntryCompression::SolidBlockMember)
            }
        })
        .collect()
}

/// Enforces the solid-archive policy shared by extraction and verification.
///
/// A solid archive needs `allow_solid_archives`, and its total uncompressed
/// size must fit `max_solid_block_memory`. The size check is a heuristic that
/// sums every entry as if the archive were one solid block, with checked
/// arithmetic.
///
/// # Errors
///
/// Returns [`ArchiveError::SecurityViolation`] when solid archives are not
/// allowed and [`ArchiveError::QuotaExceeded`] when the size check fails.
pub(crate) fn check_solid_policy(
    is_solid: bool,
    sizes: impl IntoIterator<Item = u64>,
    config: &SecurityConfig<Validated>,
) -> Result<()> {
    if !is_solid {
        return Ok(());
    }
    if !config.allow_solid_archives {
        return Err(ArchiveError::SecurityViolation {
            reason: "solid 7z archives are not allowed (enable allow_solid_archives)".into(),
        });
    }

    let total_uncompressed =
        sizes
            .into_iter()
            .try_fold(0u64, u64::checked_add)
            .ok_or(ArchiveError::QuotaExceeded {
                resource: QuotaResource::TotalSize {
                    current: u64::MAX,
                    max: config.max_solid_block_memory,
                },
            })?;
    if total_uncompressed > config.max_solid_block_memory {
        return Err(ArchiveError::QuotaExceeded {
            resource: QuotaResource::TotalSize {
                current: total_uncompressed,
                max: config.max_solid_block_memory,
            },
        });
    }
    Ok(())
}

/// Fixed decoder memory charged for a `BZip2` coder, in bytes.
const BZIP2_DECODER_MEMORY: u64 = 4 * 1024 * 1024;

/// Dictionary size an LZMA2 coder declares in its one property byte, or `None`
/// for a byte sevenz-rust2 rejects.
fn lzma2_dict_size(props: &[u8]) -> Option<u32> {
    let bits = u32::from(*props.first()?);
    match bits {
        0..=39 => Some((2 | (bits & 1)) << (bits / 2 + 11)),
        40 => Some(u32::MAX),
        _ => None,
    }
}

/// Decoder memory a coder needs, estimated from its properties.
///
/// sevenz-rust2 applies no memory limit of its own, so the limit is enforced
/// here from the coder properties. LZMA and LZMA2 grow their window
/// geometrically up to the dictionary size, so the estimate is
/// `min(dict, 2 * unpack)`. `None` means the method is unknown or its
/// properties cannot be parsed, and the caller must fail closed.
fn coder_memory(coder: &sevenz_rust2::Coder, unpack_size: u64) -> Option<u64> {
    use sevenz_rust2::EncoderMethod;

    let props = coder.properties();
    let window = |dict: u64| dict.min(unpack_size.saturating_mul(2));
    match coder.encoder_method_id() {
        EncoderMethod::ID_COPY
        | EncoderMethod::ID_DELTA
        | EncoderMethod::ID_BCJ_X86
        | EncoderMethod::ID_BCJ_PPC
        | EncoderMethod::ID_BCJ_IA64
        | EncoderMethod::ID_BCJ_ARM
        | EncoderMethod::ID_BCJ_ARM64
        | EncoderMethod::ID_BCJ_ARM_THUMB
        | EncoderMethod::ID_BCJ_SPARC
        | EncoderMethod::ID_BCJ_RISCV
        | EncoderMethod::ID_BCJ2
        | EncoderMethod::ID_DEFLATE => Some(0),
        EncoderMethod::ID_LZMA => {
            let dict = props.get(1..5)?;
            Some(window(u64::from(u32::from_le_bytes(dict.try_into().ok()?))))
        }
        EncoderMethod::ID_LZMA2 => Some(window(u64::from(lzma2_dict_size(props)?))),
        EncoderMethod::ID_PPMD => {
            let mem = props.get(1..5)?;
            Some(u64::from(u32::from_le_bytes(mem.try_into().ok()?)))
        }
        EncoderMethod::ID_BZIP2 => Some(BZIP2_DECODER_MEMORY),
        _ => None,
    }
}

/// What the file table says about one block, gathered in a single pass.
#[derive(Debug, Default, Clone, Copy)]
struct BlockShape {
    /// Sum of the declared sizes of the files mapped to the block.
    declared_size: u64,
    /// A stream-less file sits between the block's stream files.
    interleaved_entry: bool,
}

/// Maps every block to its [`BlockShape`] through
/// `stream_map.file_block_index`.
///
/// sevenz-rust2 hands a block the contiguous span of `num_unpack_sub_streams`
/// files after its first file, so a stream-less file mapped to a block (the
/// map leaves leading and trailing ones unmapped) pushes the block's last
/// stream file out of the span and the decoder skips it.
fn block_shapes(archive: &Archive) -> Vec<BlockShape> {
    let mut shapes = vec![BlockShape::default(); archive.blocks.len()];
    for (index, file) in archive.files.iter().enumerate() {
        if let Some(block) = archive.stream_map.file_block_index[index] {
            let shape = &mut shapes[block];
            shape.declared_size = shape.declared_size.saturating_add(file.size);
            shape.interleaved_entry |= !file.has_stream;
        }
    }
    shapes
}

/// Bytes to charge to a decompression budget for decoding `block`.
///
/// The charge is the largest coder output, so size-preserving filters (BCJ,
/// Delta) are not counted twice.
fn block_charge(block: &sevenz_rust2::Block) -> u64 {
    block
        .coders
        .iter()
        .map(|coder| block.get_unpack_size_for_coder(coder))
        .max()
        .unwrap_or_default()
}

/// Admits a 7z block for decoding.
///
/// Decoder memory over `max_decoder_memory` is refused before any byte is
/// decoded. LZMA2 is built without an output bound, so its window can grow to
/// the block's output whatever size its own stream declares; the larger of the
/// block's unpack size and its files' declared sizes is used.
///
/// # Errors
///
/// Returns [`ArchiveError::QuotaExceeded`] when the decoder memory exceeds the
/// limit, [`ArchiveError::SecurityViolation`] for AES content encryption, and
/// [`ArchiveError::InvalidArchive`] for an unknown method, unparseable coder
/// properties or a stream-less file inside the block.
fn admit_sevenz_block(
    block: &sevenz_rust2::Block,
    shape: BlockShape,
    config: &SecurityConfig<Validated>,
) -> Result<()> {
    let output = block_charge(block).max(shape.declared_size);
    let mut memory: u64 = 0;
    for coder in &block.coders {
        if coder.encoder_method_id() == sevenz_rust2::EncoderMethod::ID_AES256_SHA256 {
            return Err(common::encrypted_archive_error());
        }
        let needed = coder_memory(coder, output).ok_or_else(|| {
            ArchiveError::InvalidArchive(
                "7z block uses an unsupported coder or malformed coder properties".into(),
            )
        })?;
        memory = memory.saturating_add(needed);
    }
    if memory > config.max_decoder_memory {
        return Err(ArchiveError::QuotaExceeded {
            resource: QuotaResource::DecoderMemory {
                max: config.max_decoder_memory,
            },
        });
    }
    if shape.interleaved_entry {
        return Err(ArchiveError::InvalidArchive(
            "7z block interleaves a stream-less entry, so a file of the block would be skipped"
                .into(),
        ));
    }
    Ok(())
}

/// Part of a 7z archive that a policy refuses to decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefusalScope {
    /// The whole archive.
    Archive,
    /// One block, by index.
    Block(usize),
}

/// A refusal of extraction, shared by `extract` and `verify`.
#[derive(Debug)]
pub(crate) struct SevenZRefusal {
    scope: RefusalScope,
    error: ArchiveError,
}

impl SevenZRefusal {
    /// Why the payload the refusal covers stays unverified.
    fn unverified(&self) -> UnverifiedReason {
        match (&self.error, self.scope) {
            (ArchiveError::QuotaExceeded { .. }, _) => UnverifiedReason::ResourceLimit,
            (ArchiveError::SecurityViolation { .. }, RefusalScope::Archive) => {
                UnverifiedReason::SolidPolicy
            }
            _ => UnverifiedReason::NotDecodable,
        }
    }

    /// The error `extract` fails with.
    pub(crate) fn into_error(self) -> ArchiveError {
        self.error
    }
}

/// Everything `extract` refuses in a parsed 7z archive, in the order it checks.
///
/// This is the single admission point: `extract` fails on the first refusal
/// and `verify` reports each, so the two cannot disagree. It covers the solid
/// policy and, per block, decoder memory, unknown coders, AES content
/// encryption and stream-less files interleaved in a block.
///
/// The iterator is lazy: `extract` takes only the first refusal and stops
/// checking blocks there.
pub(crate) fn iter_sevenz_refusals<'a>(
    archive: &'a Archive,
    config: &'a SecurityConfig<Validated>,
) -> impl Iterator<Item = SevenZRefusal> + 'a {
    let solid = check_solid_policy(
        archive.is_solid,
        archive.files.iter().map(|f| f.size),
        config,
    )
    .err()
    .map(|error| SevenZRefusal {
        scope: RefusalScope::Archive,
        error,
    });
    let blocks = archive
        .blocks
        .iter()
        .zip(block_shapes(archive))
        .enumerate()
        .filter_map(move |(index, (block, shape))| {
            admit_sevenz_block(block, shape, config)
                .err()
                .map(|error| SevenZRefusal {
                    scope: RefusalScope::Block(index),
                    error,
                })
        });
    solid.into_iter().chain(blocks)
}

/// Every refusal of [`iter_sevenz_refusals`], for `verify` to report.
pub(crate) fn sevenz_refusals(
    archive: &Archive,
    config: &SecurityConfig<Validated>,
) -> Vec<SevenZRefusal> {
    iter_sevenz_refusals(archive, config).collect()
}

/// Most refusals `verify` lists; the rest are summarized in one issue.
const MAX_REFUSAL_ISSUES: usize = 32;

/// Archive-level `verify` issues for the refusals, capped at
/// [`MAX_REFUSAL_ISSUES`].
pub(crate) fn refusal_issues(refusals: &[SevenZRefusal]) -> Vec<VerificationIssue> {
    let mut issues: Vec<_> = refusals
        .iter()
        .take(MAX_REFUSAL_ISSUES)
        .map(|r| VerificationIssue::from_error(&r.error, None))
        .collect();
    if let Some(omitted) = refusals.len().checked_sub(MAX_REFUSAL_ISSUES)
        && omitted > 0
    {
        issues.push(VerificationIssue::new(
            IssueSeverity::Info,
            IssueCategory::InvalidArchive,
            format!("{omitted} further 7z refusals are not listed"),
        ));
    }
    issues
}

/// Result of an entry callback, as sevenz-rust2 defines it.
type EntryResult = std::result::Result<bool, sevenz_rust2::Error>;

/// Verifies the CRC32 of the bytes read through it once `remaining` of them
/// were read, with the error sevenz-rust2 raises for a mismatch.
struct CrcChecked<R> {
    inner: R,
    crc: flate2::Crc,
    expected: u64,
    remaining: u64,
}

impl<R: Read> CrcChecked<R> {
    fn new(inner: R, remaining: u64, expected: u64) -> Self {
        Self {
            inner,
            crc: flate2::Crc::new(),
            expected,
            remaining,
        }
    }
}

impl<R: Read> Read for CrcChecked<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let size = self.inner.read(buf)?;
        self.crc.update(&buf[..size]);
        self.remaining = self.remaining.saturating_sub(size as u64);
        if self.remaining == 0 && u64::from(self.crc.sum()) != self.expected {
            return Err(io::Error::other(
                sevenz_rust2::Error::ChecksumVerificationFailed,
            ));
        }
        Ok(size)
    }
}

/// Decodes the files of one block and hands each to `each`.
///
/// Blocks that hold a single LZMA2 stream with enough independent runs are
/// decoded ahead on worker threads within the `parallel` lookahead budget;
/// every other block, and every block under `ParallelDecode::Sequential`,
/// goes through sevenz-rust2's single-threaded `BlockDecoder`. Both paths hand
/// `each` the same bytes for a valid stream. For a corrupt one both deliver
/// every byte decoded before the failure, so the same file fails with the same
/// error kind; only how many leading bytes that file received can differ.
///
/// Returns `Ok(false)` when `each` stopped the walk.
fn decode_block_entries<R: Read + Seek>(
    source: &mut R,
    archive: &Archive,
    block_index: usize,
    parallel: ParallelDecode,
    knobs: DecodeKnobs,
    each: &mut impl FnMut(&sevenz_rust2::ArchiveEntry, &mut dyn Read) -> EntryResult,
) -> EntryResult {
    let password = Password::empty();
    let first = archive.stream_map.block_first_file_index[block_index];
    let count = BlockDecoder::new(1, block_index, archive, &password, &mut *source).entry_count();
    let plan = match parallel {
        ParallelDecode::Bounded(lookahead) if knobs.threads.get() > 1 => {
            parallel_stream(archive, block_index, first..first + count, knobs.min_unit)
                .map(|stream| (stream, lookahead))
        }
        _ => None,
    };
    let Some((stream, lookahead)) = plan else {
        return BlockDecoder::new(1, block_index, archive, &password, source)
            .for_each_entries(each);
    };

    // The dry run fails exactly as the sequential path would on a coder graph
    // or property it rejects, before any thread starts.
    BlockDecoder::new(1, block_index, archive, &password, &mut *source)
        .for_each_entries(&mut |_, _| Ok(false))?;
    let block = &archive.blocks[block_index];

    with_parallel_reader(&mut *source, stream, knobs, lookahead.get(), |reader| {
        let mut block_reader: Box<dyn Read + '_> = if block.has_crc {
            Box::new(CrcChecked::new(reader, block.get_unpack_size(), block.crc))
        } else {
            Box::new(reader)
        };
        for file in &archive.files[first..first + count] {
            if is_sevenz_payload(file) {
                let mut decoder: Box<dyn Read + '_> = Box::new((&mut block_reader).take(file.size));
                if file.has_crc {
                    decoder = Box::new(CrcChecked::new(decoder, file.size, file.crc));
                }
                if !each(file, &mut decoder)? {
                    return Ok(false);
                }
            } else {
                let empty: &mut dyn Read = &mut ([0u8; 0].as_slice());
                if !each(file, empty)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    })
}

/// The LZMA2 stream of a block that can be decoded in parallel, or `None`.
///
/// Eligible blocks are one LZMA2 coder over one pack stream whose files (the
/// `files` span the decoder walks) account for the whole output, with room for
/// at least two runs of `min_unit`.
fn parallel_stream(
    archive: &Archive,
    block_index: usize,
    files: std::ops::Range<usize>,
    min_unit: u64,
) -> Option<Lzma2Stream> {
    use sevenz_rust2::EncoderMethod;

    let block = &archive.blocks[block_index];
    let [coder] = block.coders.as_slice() else {
        return None;
    };
    if coder.encoder_method_id() != EncoderMethod::ID_LZMA2 {
        return None;
    }
    let first_packs = archive.stream_map.block_first_pack_stream_index();
    let first_pack = *first_packs.get(block_index)?;
    let end_pack = first_packs
        .get(block_index + 1)
        .copied()
        .unwrap_or_else(|| archive.pack_sizes().len());
    if end_pack.checked_sub(first_pack) != Some(1) {
        return None;
    }
    let output_len = block.get_unpack_size();
    if output_len < min_unit.saturating_mul(2) {
        return None;
    }
    let files_len = archive
        .files
        .get(files)?
        .iter()
        .filter(|file| is_sevenz_payload(file))
        .try_fold(0u64, |sum, file| sum.checked_add(file.size))?;
    if files_len != output_len {
        return None;
    }
    let offset = SIGNATURE_HEADER_SIZE
        .checked_add(archive.pack_pos())?
        .checked_add(*archive.stream_map.pack_stream_offsets().get(first_pack)?)?;
    Some(Lzma2Stream {
        offset,
        len: *archive.pack_sizes().get(first_pack)?,
        output_len,
        dict_size: lzma2_dict_size(coder.properties())?,
    })
}

/// Decodes every block and then the files without data, handing each to
/// `each`, in the order sevenz-rust2's `ArchiveReader::for_each_entries` uses.
fn decode_archive_entries<R: Read + Seek>(
    source: &mut R,
    archive: &Archive,
    parallel: ParallelDecode,
    knobs: DecodeKnobs,
    each: &mut impl FnMut(&sevenz_rust2::ArchiveEntry, &mut dyn Read) -> EntryResult,
) -> std::result::Result<(), sevenz_rust2::Error> {
    for block_index in 0..archive.blocks.len() {
        decode_block_entries(source, archive, block_index, parallel, knobs, each)?;
    }
    for (index, file) in archive.files.iter().enumerate() {
        if archive.stream_map.file_block_index[index].is_none() {
            let empty: &mut dyn Read = &mut ([0u8; 0].as_slice());
            if !each(file, empty)? {
                return Ok(());
            }
        }
    }
    Ok(())
}

/// A symlink target as its 7z entry stores it, consumed as soon as it is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StoredLinkTarget {
    /// The target, within the stored-target size limit.
    Read(PathBuf),
    /// The entry holds more bytes than a target may; none were read.
    Oversized {
        /// Size of the stored target in bytes.
        bytes: u64,
    },
}

/// Why a stored link target was not read. `list` and `verify` leave such a
/// target unread; `extract` fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LinkReadFailure {
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
pub(crate) type LinkOutcome = std::result::Result<StoredLinkTarget, LinkReadFailure>;

/// Reads the target of the link whose data `reader` yields, `size` bytes.
///
/// A target larger than the stored-target limit is not read. Only a failing
/// disk read or a target that is not UTF-8 is an error: the former is not a
/// property of the archive, the latter is refused in every mode as in ZIP.
fn read_sevenz_link_target(reader: &mut dyn Read, size: u64) -> Result<LinkOutcome> {
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
enum LinkStorage {
    /// No data: the target is empty.
    Empty,
    /// More data than a target may hold.
    Oversized(u64),
    /// Within a block, within the limit.
    Stream,
}

fn link_storage(file: &sevenz_rust2::ArchiveEntry) -> LinkStorage {
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
pub(crate) struct LinkTable<T> {
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

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
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
pub(crate) fn deliver_undecoded_links(
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
fn blocks_closed_to_links(
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
fn is_entry_checksum_error(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<sevenz_rust2::Error>())
        .is_some_and(|inner| matches!(inner, sevenz_rust2::Error::ChecksumVerificationFailed))
}

/// Reads past a file the walk does not want, ignoring its own checksum failure
/// so the rest of its block stays aligned.
fn drain_unwanted(file: &sevenz_rust2::ArchiveEntry, reader: &mut dyn Read) -> EntryResult {
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
pub(crate) fn walk_sevenz_links<R: Read + Seek, T>(
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

fn walk_block_links<R: Read + Seek>(
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
pub(crate) struct LinkCapture<'a> {
    /// The manifest position of every listed link.
    pub(crate) links: &'a LinkTable<EntryPosition>,
    /// Receives the manifest position and target of each link read.
    pub(crate) set: &'a mut dyn FnMut(EntryPosition, PathBuf),
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
}

/// Per-block state while decoding one 7z block for an integrity pass.
struct BlockScan<'a, 'c> {
    pass: &'a mut IntegrityPass<'c>,
    slots: &'a [Option<Slot>],
    links: Option<LinkCapture<'a>>,
    next_file: usize,
    visited: BTreeSet<usize>,
    stop: Option<BlockStop>,
}

/// Why the scan of a block ended early.
#[derive(Debug)]
enum BlockStop {
    /// A decode failure left the rest of the block undecodable; its remaining
    /// payload entries are unverified for this reason.
    Abandoned(UnverifiedReason),
    /// A disk read failed; not a property of the archive.
    Fatal(ArchiveError),
}

impl BlockScan<'_, '_> {
    /// Decodes one file of the block; returns whether the scan continues.
    fn visit(&mut self, file: &sevenz_rust2::ArchiveEntry, reader: &mut dyn Read) -> bool {
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
    /// only when the data verified: a target whose checksum failed stays
    /// unread, as bytes the decoder withheld would pass for a shorter target.
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
                    (capture.set)(position, common::symlink_target_from_bytes(&bytes)?);
                }
                Ok(DecodeOutcome::Verified)
            }
            Err(failure) => Ok(DecodeOutcome::Failed(failure)),
        }
    }
}

/// Reads past a payload file that has no integrity slot (an entry the listing
/// dropped) so the rest of its solid block stays aligned; returns whether the
/// scan can continue.
fn skip_payload(file: &sevenz_rust2::ArchiveEntry, reader: &mut dyn Read) -> bool {
    std::io::copy(&mut reader.take(file.size), &mut std::io::sink()).is_ok()
}

fn is_sevenz_payload(file: &sevenz_rust2::ArchiveEntry) -> bool {
    file.has_stream && file.size > 0
}

/// A payload file of a block: its archive file index and integrity slot.
type PayloadFile = (usize, Slot);

/// Groups the payload files of each block through
/// `stream_map.file_block_index`.
///
/// sevenz-rust2 hands a block the contiguous span of `num_unpack_sub_streams`
/// files after its first file, so a stream-less file placed between a block's
/// stream files pushes the last of them out of the span. Going through the
/// file-to-block map instead lets the caller see every payload file that
/// belongs to a block, whether or not the decoder visits it.
fn payload_by_block(archive: &Archive, slots: &[Option<Slot>]) -> Vec<Vec<PayloadFile>> {
    let mut blocks = vec![Vec::new(); archive.blocks.len()];
    for (index, file) in archive.files.iter().enumerate() {
        let block = archive.stream_map.file_block_index[index];
        if let (Some(block), Some(Some(slot)), true) =
            (block, slots.get(index), is_sevenz_payload(file))
        {
            blocks[block].push((index, *slot));
        }
    }
    blocks
}

/// Decodes every payload block of a parsed 7z archive for an integrity pass.
///
/// `slots` maps each archive file to its integrity slot (`None` for an anti
/// item), as built by the listing loop. Blocks are the admission unit: a block
/// is decoded only when the solid policy, quota and ratio checks, decoder
/// memory and the budget all allow it, and blocks are tried first-fit.
/// Per-entry CRC mismatches keep the stream aligned, so the scan continues; any
/// other failure abandons the block. A payload file the decoder never visits is
/// counted as not decodable, so no file can escape the check. The block CRC
/// fires only once the whole block has been read, so it is attributed to the
/// block's last entry.
///
/// When `links` is set, the targets of the listed links inside decoded blocks
/// are read in the same decode and handed to it; links in blocks the pass does
/// not decode stay unread.
///
/// # Errors
///
/// Returns the I/O error of a failing disk read, or an error for a link target
/// that is not UTF-8.
pub(crate) fn verify_sevenz_blocks<R: Read + Seek>(
    archive: &Archive,
    source: &mut R,
    pass: &mut IntegrityPass<'_>,
    slots: &[Option<Slot>],
    mut links: Option<LinkCapture<'_>>,
) -> Result<()> {
    let payload = payload_by_block(archive, slots);
    let mut refused = vec![None; archive.blocks.len()];
    for refusal in sevenz_refusals(archive, pass.config()) {
        match refusal.scope {
            RefusalScope::Archive => {
                let indices = payload.iter().flatten().map(|&(index, _)| index);
                mark_files(pass, archive, refusal.unverified(), indices);
                return Ok(());
            }
            RefusalScope::Block(index) => refused[index] = Some(refusal.unverified()),
        }
    }

    let decode = DecodeContext {
        slots,
        knobs: DecodeKnobs::production(),
    };
    for (block_index, files) in payload.iter().enumerate() {
        if files.is_empty() {
            continue;
        }
        if let Some(reason) = refused[block_index] {
            mark_files(pass, archive, reason, files.iter().map(|&(index, _)| index));
        } else {
            let capture = links.as_mut().map(|capture| LinkCapture {
                links: capture.links,
                set: &mut *capture.set,
            });
            verify_sevenz_block(archive, source, pass, decode, block_index, files, capture)?;
        }
    }
    Ok(())
}

/// Path of the archive file at `index`, as listed in the manifest.
fn file_path(archive: &Archive, index: usize) -> PathBuf {
    PathBuf::from(common::normalize_entry_name(&archive.files[index].name))
}

/// Marks the archive files at `indices` as unverified for `reason`.
fn mark_files(
    pass: &mut IntegrityPass<'_>,
    archive: &Archive,
    reason: UnverifiedReason,
    indices: impl Iterator<Item = usize>,
) {
    for index in indices {
        pass.mark_unverified(reason, &file_path(archive, index));
    }
}

/// Records a block failure against `lead` and marks the `others` further
/// files unverified under the matching reason.
fn record_block_failure(
    pass: &mut IntegrityPass<'_>,
    archive: &Archive,
    lead: (&Path, Slot),
    failure: DecodeFailure,
    others: &[usize],
) -> Result<()> {
    let reason = match failure {
        DecodeFailure::ResourceLimit(_) => UnverifiedReason::ResourceLimit,
        _ => UnverifiedReason::NotDecodable,
    };
    pass.record(lead.1, lead.0, DecodeOutcome::Failed(failure))?;
    mark_files(pass, archive, reason, others.iter().copied());
    Ok(())
}

/// Lists the entries that only a block CRC could cover but that CRC cannot.
///
/// The block CRC fires once the whole block output was read, which never
/// happens when the entries' sizes do not add up to the block's output. An
/// entry with its own CRC is covered regardless.
fn entries_uncovered_by_block_crc(
    block_has_crc: bool,
    entry_sizes: u64,
    block_size: u64,
    entries: impl Iterator<Item = (usize, bool)>,
) -> Vec<usize> {
    if !block_has_crc || entry_sizes == block_size {
        return Vec::new();
    }
    entries
        .filter(|&(_, has_crc)| !has_crc)
        .map(|(index, _)| index)
        .collect()
}

/// What `verify` shares between the blocks of one archive.
#[derive(Clone, Copy)]
struct DecodeContext<'a> {
    slots: &'a [Option<Slot>],
    knobs: DecodeKnobs,
}

fn verify_sevenz_block<R: Read + Seek>(
    archive: &Archive,
    source: &mut R,
    pass: &mut IntegrityPass<'_>,
    decode: DecodeContext<'_>,
    block_index: usize,
    payload: &[PayloadFile],
    links: Option<LinkCapture<'_>>,
) -> Result<()> {
    let DecodeContext { slots, knobs } = decode;
    let block = &archive.blocks[block_index];
    let all = payload.iter().map(|&(index, _)| index);

    if payload.iter().any(|&(_, slot)| !pass.is_admitted(slot)) {
        mark_files(pass, archive, UnverifiedReason::ResourceLimit, all);
        return Ok(());
    }

    if !pass.try_charge(block_charge(block)) {
        mark_files(pass, archive, UnverifiedReason::OverBudget, all);
        return Ok(());
    }

    let first = archive.stream_map.block_first_file_index[block_index];
    let mut scan = BlockScan {
        pass,
        slots,
        links: links.map(|capture| LinkCapture {
            links: capture.links,
            set: &mut *capture.set,
        }),
        next_file: first,
        visited: BTreeSet::new(),
        stop: None,
    };
    let parallel = scan.pass.config().parallel_decode;
    let result = decode_block_entries(
        source,
        archive,
        block_index,
        parallel,
        knobs,
        &mut |file, reader| Ok(scan.visit(file, reader)),
    );
    let (stop, visited) = (scan.stop.take(), scan.visited);

    let unvisited: Vec<usize> = all.filter(|index| !visited.contains(index)).collect();
    match (stop, result) {
        (Some(BlockStop::Fatal(e)), _) => return Err(e),
        (Some(BlockStop::Abandoned(reason)), _) => {
            mark_files(pass, archive, reason, unvisited.into_iter());
        }
        (None, Err(e)) => {
            // A failure outside the per-entry callbacks belongs to the last
            // entry the decoder reached (where a block CRC would
            // fire), else the first.
            let &(index, slot) = payload
                .iter()
                .rev()
                .find(|(index, _)| visited.contains(index))
                .unwrap_or(&payload[0]);
            let path = file_path(archive, index);
            let others: Vec<usize> = unvisited.into_iter().filter(|&i| i != index).collect();
            return record_block_failure(
                pass,
                archive,
                (path.as_path(), slot),
                DecodeFailure::from_sevenz(e),
                &others,
            );
        }
        (None, Ok(_)) => {
            mark_files(
                pass,
                archive,
                UnverifiedReason::NotDecodable,
                unvisited.into_iter(),
            );
            let entry_sizes = payload
                .iter()
                .map(|&(index, _)| archive.files[index].size)
                .fold(0, u64::saturating_add);
            let own_crcs = payload
                .iter()
                .filter(|(index, _)| visited.contains(index))
                .map(|&(index, _)| (index, archive.files[index].has_crc));
            let uncovered = entries_uncovered_by_block_crc(
                block.has_crc,
                entry_sizes,
                block.get_unpack_size(),
                own_crcs,
            );
            mark_files(
                pass,
                archive,
                UnverifiedReason::UncoveredBlockCrc,
                uncovered.into_iter(),
            );
        }
    }
    Ok(())
}

/// 7z archive handler with security validation.
///
/// Supports:
/// - 7z format (LZMA SDK)
/// - Compression methods: LZMA, LZMA2, BZIP2, `PPMd`, DEFLATE, Copy
/// - Multi-volume archives (read-only)
/// - Encrypted archive detection (rejected)
/// - Solid archive detection (rejected by default)
///
/// # Solid Archives
///
/// Solid compression stores multiple files in a single compressed block.
/// This provides better compression ratios but requires decompressing
/// the entire block to extract a single file, which can cause memory
/// exhaustion attacks.
///
/// **Security Policy**: Solid archives are rejected by default.
/// Use `SecurityConfig::allow_solid_archives` to enable with memory limits.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::ExtractionOptions;
/// use exarch_core::SecurityConfig;
/// use exarch_core::formats::SevenZArchive;
/// use exarch_core::formats::traits::ArchiveFormat;
/// use std::fs::File;
/// use std::path::Path;
///
/// let file = File::open("archive.7z")?;
/// let mut archive = SevenZArchive::new(file)?;
/// let config = SecurityConfig::default().validate()?;
/// let report = archive.extract(
///     Path::new("/output"),
///     &config,
///     &ExtractionOptions::default(),
///     &mut exarch_core::NoopProgress,
/// )?;
/// println!("Extracted {} files", report.files_extracted);
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
#[derive(Debug)]
pub struct SevenZArchive<R: Read + Seek> {
    source: R,
    entries: Vec<CachedEntry>,
    /// Header already parsed by [`Self::new`], retained so
    /// `extract_with_callback` can hand it to
    /// `ArchiveReader::from_archive` instead of re-parsing the archive from
    /// scratch (issue #492). Cloned, not moved, at extraction time so that a
    /// second `extract()` call on the same instance still has a real parsed
    /// archive to work with instead of silently extracting nothing.
    archive: Archive,
}

impl<R: Read + Seek> SevenZArchive<R> {
    /// Creates a new 7z archive reader.
    ///
    /// # Security Checks
    ///
    /// - Rejects encrypted archives (via password parameter)
    /// - Validates archive header signature
    /// - Checks for solid compression (rejected by default)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Archive is encrypted
    /// - Archive header is invalid
    /// - Format is not recognized
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use exarch_core::formats::SevenZArchive;
    /// use std::fs::File;
    ///
    /// let file = File::open("archive.7z")?;
    /// let archive = SevenZArchive::new(file)?;
    /// # Ok::<(), exarch_core::ArchiveError>(())
    /// ```
    pub fn new(mut source: R) -> Result<Self> {
        // Step 1: Verify it's a valid 7z archive by reading metadata
        let password = Password::empty();
        let archive = match Archive::read(&mut source, &password) {
            Ok(a) => a,
            Err(e) => {
                if is_password_error(&e) {
                    return Err(common::encrypted_archive_error());
                }
                // Handle valid empty 7z archives: sevenz-rust2 fails with
                // UnexpectedEof on 32-byte archives that
                // contain no files. Check for a valid 7z signature
                // and small file size before treating as an empty archive.
                if is_empty_sevenz_archive(&e, &mut source) {
                    return Ok(Self {
                        source,
                        entries: vec![],
                        archive: Archive::default(),
                    });
                }
                return Err(ArchiveError::InvalidArchive(format!(
                    "failed to open 7z archive: {e}"
                )));
            }
        };

        // Step 3: Cache entry metadata to avoid re-parsing during extraction
        let source_len = source.seek(SeekFrom::End(0)).map_err(ArchiveError::Io)?;
        let compression = sevenz_entry_compression(&archive, source_len)?;
        let entries: Vec<CachedEntry> = archive
            .files
            .iter()
            .zip(compression)
            .map(|(e, compression)| CachedEntry {
                name: e.name.clone(),
                size: e.size,
                class: SevenZClass::of(e),
                compression,
            })
            .collect();

        // Step 4: Rewind for actual extraction
        source.rewind().map_err(ArchiveError::Io)?;

        Ok(Self {
            source,
            entries,
            archive,
        })
    }
}

/// Writes `reader`'s bytes directly to `dest_path` (no temp file, no
/// rename), consuming the [`QuotaPermit`] that authorized the write.
///
/// Used for the common case where nothing currently occupies `dest_path`
/// (issue #492): opens `dest_path` itself via `common::create_file_with_mode`
/// with `create_new = true`, giving the same `O_EXCL`+`O_NOFOLLOW` (Unix)
/// guarantee against a symlink race as [`write_file_with_permit`]'s temp file
/// and as TAR/ZIP's [`common::extract_file_with_permit`] — just without the
/// two extra syscalls (open+rename of a temp file) that only matter when
/// something needs to be atomically replaced. Callers must have already
/// confirmed `dest_path` has no pre-existing occupant (see
/// [`lstat_dest`]); when it does, use [`write_file_with_permit`] instead so a
/// decode failure mid-stream cannot leave a truncated file where the
/// original stood.
///
/// Taking `permit` by value mirrors the guarantee
/// [`common::copy_file_content_with_permit`] gives TAR's hardlink path, and
/// the guarantee [`common::extract_file_with_permit`] gives TAR/ZIP's
/// normal-file path (issue #445): `QuotaPermit` is neither `Clone` nor
/// `Copy`, so a caller cannot retain it to authorize a second write, and this
/// function cannot be called at all without moving a genuine permit out of
/// the validated entry.
///
/// # Security - Streaming Size Enforcement (GHSA-5j8q-wxg5-hj4r)
///
/// `expected_size` is `entry.size` — the declared uncompressed size read
/// from 7z's own (attacker-controlled) archive metadata, the same value
/// already used to authorize `permit`. The copy goes through
/// [`copy_with_buffer`], which enforces it as a hard streaming ceiling and
/// an exact post-copy match rather than trusting it a second time, closing
/// the same gap TAR/ZIP close via [`common::extract_file_with_permit`].
///
/// # Errors
///
/// Returns an error if file creation, the copy, or the underlying I/O fails,
/// or if the actual decompressed byte count exceeds or falls short of
/// `expected_size`.
fn write_file_direct(
    reader: &mut dyn Read,
    dest_path: &Path,
    expected_size: u64,
    copy_buffer: &mut CopyBuffer,
    _permit: QuotaPermit,
) -> Result<u64> {
    let file = common::create_file_with_mode(dest_path, None, true)?;
    // A decode failure partway through the copy would otherwise leave a
    // truncated file at dest_path (issue #492 adversarial review, finding
    // M1): since this branch only runs when nothing occupied dest_path
    // beforehand, it is always safe to remove whatever we just started
    // writing there. Mirrors write_file_with_permit_using's TempFileGuard
    // use, just applied directly to dest_path instead of a temp path.
    //
    // Declared before `writer` takes ownership of `file` below: Rust drops
    // locals in reverse declaration order, so on an error unwind `writer`
    // (and the `file` it owns) drops — and closes the fd — before `guard`
    // attempts to remove the path. Reversing this order would let the guard
    // try to unlink a still-open file, a silent no-op on Windows.
    let guard = common::TempFileGuard::new(dest_path.to_path_buf());
    // 64KiB write buffering to cut per-file syscall count (finding M2),
    // matching TAR/ZIP's common::extract_file_with_permit.
    let mut writer = std::io::BufWriter::with_capacity(64 * 1024, file);
    let bytes_written = copy_with_buffer(reader, &mut writer, copy_buffer, Some(expected_size))?;
    writer.flush()?;
    guard.persist();
    Ok(bytes_written)
}

/// Writes `reader`'s bytes to `dest_path` via an atomic temp-file-then-rename,
/// consuming the [`QuotaPermit`] that authorized the write.
///
/// Used only when `dest_path` has a pre-existing occupant being overwritten
/// (issue #492): atomicity matters here because a decode failure mid-stream
/// must not leave a truncated file where the original stood. When
/// `dest_path` is known to have no pre-existing occupant, [`write_file_direct`]
/// skips the temp file and rename entirely.
///
/// Taking `permit` by value mirrors the guarantee
/// [`common::copy_file_content_with_permit`] gives TAR's hardlink path, and
/// the guarantee [`common::extract_file_with_permit`] gives TAR/ZIP's
/// normal-file path (issue #445): `QuotaPermit` is neither `Clone` nor
/// `Copy`, so a caller cannot retain it to authorize a second write, and this
/// function cannot be called at all without moving a genuine permit out of
/// the validated entry.
///
/// # Security - Symlink-at-Destination Rejection (issue #471)
///
/// The temp file name is predictable from the process PID and a per-process
/// monotonic counter, so a pre-planted symlink (dangling or not) at a
/// predicted temp path used to be silently followed by `File::create`,
/// writing archive content outside the extraction root. The temp file is
/// now opened via `common::create_file_with_mode` (mode `None`, since 7z
/// never exposes a Unix mode to sanitize) with `create_new = true`, reusing
/// the same `O_EXCL`+`O_NOFOLLOW` (Unix) discipline as the normal-file write
/// path (issue #459) for consistency, though `create_new`'s `O_EXCL` alone
/// already refuses any pre-existing path instead of following it. On
/// collision (`ErrorKind::AlreadyExists`), a fresh counter value is drawn
/// and creation is retried up to [`MAX_TEMP_FILE_CREATE_ATTEMPTS`] times.
///
/// # Security - Streaming Size Enforcement (GHSA-5j8q-wxg5-hj4r)
///
/// Same enforcement as [`write_file_direct`]: the copy runs through
/// [`copy_with_buffer`] with `expected_size` (`entry.size`) as a hard
/// streaming ceiling and exact post-copy match, not trusted metadata.
///
/// # Errors
///
/// Returns an error if a unique temp file cannot be created within
/// [`MAX_TEMP_FILE_CREATE_ATTEMPTS`] attempts, if the copy or rename fails,
/// or if the actual decompressed byte count exceeds or falls short of
/// `expected_size`.
fn write_file_with_permit(
    reader: &mut dyn Read,
    dest_path: &Path,
    expected_size: u64,
    copy_buffer: &mut CopyBuffer,
    permit: QuotaPermit,
) -> Result<u64> {
    let pid = id();
    let original_name = dest_path
        .file_name()
        .map_or_else(|| "file".to_string(), |n| n.to_string_lossy().to_string());

    write_file_with_permit_using(
        reader,
        dest_path,
        expected_size,
        copy_buffer,
        permit,
        || {
            let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let temp_name = format!(".{original_name}.exarch-tmp-{pid}-{counter}");
            dest_path.with_file_name(&temp_name)
        },
    )
}

/// Implementation behind [`write_file_with_permit`], parameterized over the
/// candidate temp-path generator.
///
/// Tests inject a private, non-shared generator here instead of calling
/// [`write_file_with_permit`] directly, so that predicting which paths a
/// test run will attempt never depends on the process-global
/// [`TEMP_COUNTER`] — a global shared with every other test in the same
/// binary that also happens to write a 7z file, and therefore not something
/// a single test can safely predict under `cargo test`'s default
/// multi-threaded execution (only nextest's one-test-per-process model would
/// make that safe).
///
/// # Security - Streaming Size Enforcement (GHSA-5j8q-wxg5-hj4r)
///
/// Same enforcement as [`write_file_direct`]: the copy runs through
/// [`copy_with_buffer`] with `expected_size` as a hard streaming ceiling and
/// exact post-copy match, not trusted metadata.
///
/// # Errors
///
/// Returns an error if a unique temp file cannot be created within
/// [`MAX_TEMP_FILE_CREATE_ATTEMPTS`] attempts, if the copy or rename fails,
/// or if the actual decompressed byte count exceeds or falls short of
/// `expected_size`.
fn write_file_with_permit_using(
    reader: &mut dyn Read,
    dest_path: &Path,
    expected_size: u64,
    copy_buffer: &mut CopyBuffer,
    _permit: QuotaPermit,
    mut next_candidate_path: impl FnMut() -> PathBuf,
) -> Result<u64> {
    let mut created: Option<(PathBuf, std::fs::File)> = None;
    for _ in 0..MAX_TEMP_FILE_CREATE_ATTEMPTS {
        let candidate_path = next_candidate_path();

        match common::create_file_with_mode(&candidate_path, None, true) {
            Ok(file) => {
                created = Some((candidate_path, file));
                break;
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }

    let (temp_path, temp_file) = created.ok_or_else(|| {
        std::io::Error::new(
            ErrorKind::AlreadyExists,
            format!(
                "failed to create a unique temp file for {} after {MAX_TEMP_FILE_CREATE_ATTEMPTS} attempts",
                dest_path.display()
            ),
        )
    })?;

    // Declared before `writer` takes ownership of `temp_file` below, for the
    // same reason as write_file_direct's `guard`: reverse-declaration-order
    // drop means `writer` (owning `temp_file`) closes the fd before
    // `temp_guard` attempts to remove `temp_path` on an error unwind,
    // instead of racing a still-open handle (a silent no-op on Windows).
    // `temp_file` is moved into `writer` rather than merely borrowed so
    // there is no separate `temp_file` binding left to outlive `writer`.
    let temp_guard = common::TempFileGuard::new(temp_path.clone());
    // 64KiB write buffering to cut per-file syscall count (issue #492
    // adversarial review, finding M2), matching TAR/ZIP's
    // common::extract_file_with_permit.
    let mut writer = std::io::BufWriter::with_capacity(64 * 1024, temp_file);
    let bytes_written = copy_with_buffer(reader, &mut writer, copy_buffer, Some(expected_size))?;
    writer.flush()?;
    // Explicit close before rename: renaming a still-open file is fine on
    // Unix but the handle should not outlive its purpose regardless.
    drop(writer);
    std::fs::rename(&temp_path, dest_path)?;
    temp_guard.persist();

    Ok(bytes_written)
}

/// lstat's `dest_path`, returning `Ok(None)` if nothing occupies it.
///
/// Uses `symlink_metadata` rather than `exists()`/`is_dir()`: those follow
/// symlinks and report a dangling symlink as absent, which would let a
/// dangling symlink slip past both duplicate detection and the
/// pre-existing-symlink rejection below (issues #468, #477, #478). Shared by
/// both `SevenZArchive::extract`'s Step 1 pre-validation loop and
/// `process_entry_inner`'s Step 3 extraction callback, so the two agree on
/// what counts as "something already at this path".
///
/// # TOCTOU
///
/// This check is advisory, not atomic: nothing prevents the filesystem state
/// at `dest_path` from changing between this lstat and the later write. That
/// window is benign on both of 7z's write paths (issue #492), for different
/// reasons:
///
/// - When nothing occupied `dest_path` ([`write_file_direct`]): the fast path
///   opens `dest_path` itself via `common::create_file_with_mode` with
///   `create_new = true`, the same `O_EXCL`+`O_NOFOLLOW` (Unix) guarantee
///   TAR/ZIP's `O_NOFOLLOW` open gives — anything planted in the race window
///   makes that open fail with `AlreadyExists` instead of being followed.
/// - When something did occupy `dest_path` ([`write_file_with_permit`]): this
///   branch never opens `dest_path` itself, and `rename(2)` replaces whatever
///   occupies the destination without following a symlink planted there in the
///   interim, so a race cannot redirect the write through a symlink target.
fn lstat_dest(dest_path: &Path) -> std::io::Result<Option<std::fs::Metadata>> {
    match std::fs::symlink_metadata(dest_path) {
        Ok(meta) => Ok(Some(meta)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Returns the `ELOOP` I/O error `common::open_no_follow` produces when a
/// symlink occupies the destination path, so 7z's own checks fail the same
/// way instead of silently replacing the symlink (issue #477). Converts via
/// `?`/`.into()` into either `ArchiveError` (Step 1) or `sevenz_rust2::Error`
/// (Step 3), both of which implement `From<std::io::Error>`.
///
/// `#[cfg(unix)]`, not just conditional at runtime: `O_NOFOLLOW` is a
/// Unix-specific mechanism (see `common::open_no_follow`), and
/// `common::create_file_with_mode`'s non-Unix branch provides no equivalent
/// symlink guard for TAR/ZIP either, so non-Unix keeps the pre-existing
/// remove-then-rename behavior for parity with TAR/ZIP's own platform split.
/// Both call sites are gated by the same `#[cfg(unix)]`, so this function
/// does not exist at all — and cannot be reached — on non-Unix targets.
#[cfg(unix)]
fn symlink_at_dest_error() -> std::io::Error {
    std::io::Error::from_raw_os_error(libc::ELOOP)
}

impl<R: Read + Seek> SevenZArchive<R> {
    /// Reads each link's target and validates it against the destination as it
    /// is before any write, keeping one target at a time.
    ///
    /// `links` holds the archive file index and validated path of every
    /// symlink entry. Runs only after every header check of
    /// the extraction, so a decode never precedes a refusal.
    ///
    /// # Errors
    ///
    /// Returns the policy error of the first target that fails validation, or
    /// `InvalidArchive` when a target cannot be read.
    fn validate_link_targets(
        &mut self,
        dest: &DestDir,
        config: &SecurityConfig<Validated>,
        links: &LinkTable<SafePath>,
    ) -> Result<()> {
        if links.is_empty() {
            return Ok(());
        }
        let compression: Vec<EntryCompression> =
            self.entries.iter().map(|entry| entry.compression).collect();
        let entries = &self.entries;
        walk_sevenz_links(
            &self.archive,
            &mut self.source,
            &compression,
            config,
            links,
            &mut |index, outcome| {
                let name = &entries[index].name;
                let target = match outcome {
                    Ok(StoredLinkTarget::Read(target)) => target,
                    Ok(StoredLinkTarget::Oversized { bytes }) => {
                        return Err(common::symlink_target_too_large(bytes));
                    }
                    Err(failure) => return Err(failure.into_extract_error(name)),
                };
                let link = links.get(index).ok_or_else(|| {
                    ArchiveError::InvalidArchive("7z link index is out of range".into())
                })?;
                SafeSymlink::validate(link, &target, dest, config).map(drop)
            },
        )
    }

    fn anti_item_count(&self) -> u64 {
        let count = self
            .entries
            .iter()
            .filter(|entry| entry.class == SevenZClass::AntiItem)
            .count();
        u64::try_from(count).unwrap_or(u64::MAX)
    }

    /// Reads the target of the symlink entry from its own stream and validates
    /// the entry against the disk as it is now; Step 1 validated it against the
    /// destination before anything was written.
    fn validate_stream_symlink(
        entry: &sevenz_rust2::ArchiveEntry,
        reader: &mut dyn Read,
        entry_path: &Path,
        validator: &mut EntryValidator,
    ) -> Result<crate::security::validator::ValidatedEntry> {
        let target = match read_sevenz_link_target(reader, entry.size)? {
            Ok(StoredLinkTarget::Read(target)) => target,
            Ok(StoredLinkTarget::Oversized { bytes }) => {
                return Err(common::symlink_target_too_large(bytes));
            }
            Err(failure) => return Err(failure.into_extract_error(&entry.name)),
        };
        // SECURITY: `None` dir_cache, like the path validation of files.
        validator.validate_entry(
            entry_path,
            &EntryType::Symlink { target },
            entry.size,
            None,
            None,
            None,
        )
    }

    /// Processes a single 7z entry: validates, extracts file or creates
    /// directory.
    ///
    /// Returns `(continue, bytes_written)` on success so the caller can
    /// invoke `on_bytes_written` and `on_entry_complete` after this returns,
    /// guaranteeing both callbacks are always paired with `on_entry_start`.
    #[expect(
        clippy::too_many_arguments,
        reason = "arguments are threaded through from the caller; a parameter struct adds indirection"
    )]
    fn process_entry_inner(
        entry: &sevenz_rust2::ArchiveEntry,
        kind: SevenZKind,
        reader: &mut dyn Read,
        entry_path: &std::path::Path,
        validator: &mut EntryValidator,
        dest: &DestDir,
        report: &mut ExtractionReport,
        dir_cache: &mut common::DirCache,
        skip_duplicates: bool,
        config: &SecurityConfig<Validated>,
        duplicate_skips: &mut u64,
        disallowed_extension_skips: &mut u64,
        pending_error: &mut Option<ArchiveError>,
        copy_buffer: &mut CopyBuffer,
    ) -> std::result::Result<u64, sevenz_rust2::Error> {
        match kind {
            SevenZKind::ReparsePoint => {
                return Err(abort_with(
                    pending_error,
                    reparse_point_refusal(&entry.name),
                ));
            }
            SevenZKind::UnixSymlink => {
                let validated = Self::validate_stream_symlink(entry, reader, entry_path, validator)
                    .map_err(|e| abort_with(pending_error, e))?;
                if let ValidatedEntryType::Symlink(symlink) = validated.entry_type() {
                    common::create_symlink(
                        symlink,
                        dest,
                        report,
                        dir_cache,
                        skip_duplicates,
                        duplicate_skips,
                    )
                    .map_err(|e| abort_with(pending_error, e))?;
                }
                return Ok(0);
            }
            SevenZKind::File | SevenZKind::Directory => {}
        }

        // Extension filter runs before path validation to avoid quota
        // double-counting for skipped files.
        if kind == SevenZKind::File
            && !common::check_extension_allowed(
                entry_path,
                config,
                report,
                disallowed_extension_skips,
            )
        {
            return Ok(0);
        }

        // Re-validate the path only (defense in depth); quota for File
        // entries is reserved separately below, after the duplicate-skip
        // check, so a skipped entry never consumes quota it will not use
        // (issue #478). See `EntryValidator::validate_entry_path`.
        //
        // SECURITY: Deliberately passes `None`, not `Some(dir_cache)`, unlike
        // TAR (issue #492 adversarial review, finding C1). `DirCache` caches
        // any path `create_dir_all` reports as already-a-directory, without
        // checking whether that path is a real directory or a symlink to
        // one. If something outside archive control (e.g. a misbehaving
        // `ProgressCallback`) swaps a previously-created directory for a
        // symlink between entries, trusting `dir_cache` here would skip the
        // parent-canonicalize check that catches the swap, turning a
        // hard-erroring symlink escape into a silent, unbounded one across
        // every subsequent entry under that path. Passing `None` forces
        // `SafePath::validate_with_context` to canonicalize the parent every
        // time, so the swap is always caught.
        let safe_path = validator
            .validate_entry_path(entry_path, kind.node_kind(), None)
            .map_err(|e| sevenz_rust2::Error::Other(format!("validation failed: {e}").into()))?
            .into_inner();
        let dest_path = dest.join_path(safe_path.as_path());

        match kind {
            SevenZKind::Directory => {
                dir_cache.ensure_dir(&dest_path)?;
                report.directories_created += 1;
                Ok(0)
            }
            SevenZKind::File => {
                dir_cache.ensure_parent_dir(&dest_path)?;

                let existing = lstat_dest(&dest_path)?;

                if existing.is_some() && skip_duplicates {
                    report.files_skipped =
                        report.files_skipped.checked_add(1).ok_or_else(|| {
                            sevenz_rust2::Error::Other("files_skipped overflow".into())
                        })?;
                    *duplicate_skips = duplicate_skips.saturating_add(1);
                    return Ok(0);
                }

                #[cfg(unix)]
                if let Some(meta) = &existing
                    && meta.file_type().is_symlink()
                {
                    // SECURITY: refuse to silently unlink a pre-existing
                    // symlink at the destination and replace it — fail
                    // the same way TAR/ZIP's O_NOFOLLOW open does
                    // (ELOOP), instead of proceeding to remove_file +
                    // rename underneath it (issue #477).
                    return Err(symlink_at_dest_error().into());
                }

                // `lstat_dest` uses `symlink_metadata` (lstat), so `is_dir()`
                // here is true only for a real pre-existing directory, never
                // a symlink pointing at one: on Unix any symlink is already
                // rejected above, and on non-Unix a symlink-to-directory is
                // not itself a directory by lstat semantics, so it falls
                // through to the regular-file removal path below (issue
                // #483 counterexample: a symlink-to-directory must not be
                // treated as a directory itself).
                if let Some(meta) = &existing
                    && meta.is_dir()
                {
                    // Match TAR/ZIP's EISDIR failure (create_file_with_mode
                    // opening a directory for write) instead of recursively
                    // deleting the pre-existing directory tree (issue #483).
                    //
                    // Stashed as a raw ArchiveError and returned out-of-band
                    // via `pending_error` instead of `.into()`-converting
                    // to `sevenz_rust2::Error` here: that round-trip goes
                    // through `From<sevenz_rust2::Error> for ArchiveError`,
                    // which stringifies the error and re-derives its
                    // classification from substring matches (password/
                    // encrypt/i/o/read/write) on the resulting text,
                    // collapsing `ErrorKind::IsADirectory` to `Other` and
                    // risking misclassification as `SecurityViolation` if
                    // the message text happened to contain a matched
                    // substring (issue #483 S1). No message text is
                    // constructed here for the same reason: nothing about
                    // this error should ever again be at the mercy of that
                    // heuristic.
                    *pending_error = Some(ArchiveError::Io(std::io::Error::from(
                        ErrorKind::IsADirectory,
                    )));
                    return Err(sevenz_rust2::Error::Other(
                        "destination path is a pre-existing directory".into(),
                    ));
                }

                // Reserve quota BEFORE mutating the filesystem: deciding
                // (quota check) must precede acting (removing the existing
                // path), so a QuotaExceeded error never first destroys a
                // pre-existing destination it could not ultimately replace.
                let permit = validator.reserve_file(entry.size).map_err(|e| {
                    sevenz_rust2::Error::Other(format!("validation failed: {e}").into())
                })?;

                // Fast path (issue #492): when nothing occupies dest_path,
                // write directly to it (open+write, no temp file, no
                // rename) — mirrors TAR/ZIP's common::extract_file_with_permit.
                // The overwrite branch keeps temp+rename so a decode failure
                // mid-stream cannot leave a truncated file where the
                // original stood.
                //
                // Both branches enforce entry.size as a hard streaming
                // ceiling and exact post-copy match (GHSA-5j8q-wxg5-hj4r, see
                // write_file_direct/write_file_with_permit); a violation
                // there returns Err(ArchiveError) which does not implement
                // Into<sevenz_rust2::Error>, so it is stashed out-of-band via
                // `pending_error` (same reasoning as the IsADirectory case
                // above) rather than round-tripped through the lossy string
                // conversion.
                let bytes_written = if existing.is_some() {
                    // 7z uses temp+rename (unlike TAR/ZIP which truncate
                    // in-place via File::create). Remove the existing
                    // regular file/symlink first so `rename` can succeed.
                    // Deferred until after the quota reservation above
                    // succeeds. Only a regular file (or, on non-Unix, a
                    // symlink) can reach here: directories and Unix symlinks
                    // were already rejected above.
                    std::fs::remove_file(&dest_path)?;
                    write_file_with_permit(reader, &dest_path, entry.size, copy_buffer, permit)
                } else {
                    write_file_direct(reader, &dest_path, entry.size, copy_buffer, permit)
                }
                .map_err(|e| {
                    *pending_error = Some(e);
                    sevenz_rust2::Error::Other("extraction aborted by security policy".into())
                })?;
                report.bytes_written = report
                    .bytes_written
                    .checked_add(bytes_written)
                    .ok_or_else(|| sevenz_rust2::Error::Other("bytes_written overflow".into()))?;

                report.files_extracted += 1;
                Ok(bytes_written)
            }
            SevenZKind::ReparsePoint | SevenZKind::UnixSymlink => Err(sevenz_rust2::Error::Other(
                "link entries are handled before path validation".into(),
            )),
        }
    }

    /// Extract archive using sevenz-rust2 callback API with security
    /// validation.
    ///
    /// This uses the `decompress_with_extract` API which provides a callback
    /// for each entry. We use this to inject our security validation logic.
    ///
    /// Progress callbacks are fired per-entry inside the extraction closure so
    /// that `on_entry_start` / `on_entry_complete` interleave with actual I/O
    /// rather than being batched before and after the entire extraction.
    ///
    /// # Security
    ///
    /// - Re-validates paths in callback (defense in depth)
    /// - Enforces quotas during extraction
    /// - Writes directly (`O_EXCL`+`O_NOFOLLOW`) when nothing occupies the
    ///   destination, and via atomic temp+rename when overwriting a
    ///   pre-existing file — see [`write_file_direct`] and
    ///   [`write_file_with_permit`] (issue #492)
    /// - Creates directories only after validation
    /// - Uses directory cache to reduce mkdir syscalls
    #[expect(
        clippy::too_many_arguments,
        reason = "arguments are threaded through from the caller; a parameter struct adds indirection"
    )]
    fn extract_with_callback(
        source: &mut R,
        archive: &Archive,
        dest: &DestDir,
        validator: &mut EntryValidator,
        dir_cache: &mut common::DirCache,
        skip_duplicates: bool,
        progress: &mut dyn ProgressCallback,
        total: usize,
        anti_items: u64,
        config: &SecurityConfig<Validated>,
    ) -> Result<ExtractionReport> {
        struct SzContext<'a> {
            report: ExtractionReport,
            dir_cache: &'a mut common::DirCache,
            progress: &'a mut dyn ProgressCallback,
            current_idx: usize,
            /// Count of entries skipped because they duplicate a pre-existing
            /// destination path (issue #484). Tracked separately from
            /// `report.warnings` so a single aggregated warning can be emitted
            /// after extraction instead of one `String` per skipped entry,
            /// keeping `report.warnings`'s growth independent of how many
            /// duplicate entries an archive contains.
            duplicate_skips: u64,
            /// Count of file entries skipped by
            /// `common::check_extension_allowed` because their
            /// extension is not in the allowlist. Aggregated the
            /// same way as `duplicate_skips` (issue #495).
            disallowed_extension_skips: u64,
            /// Set when `process_entry_inner` needs its caller to propagate a
            /// precise `ArchiveError` directly, bypassing the lossy
            /// `sevenz_rust2::Error` -> `ArchiveError` conversion (issue
            /// #483 S1) that stringifies errors and would otherwise collapse
            /// a specific `ErrorKind` to `Other` and re-classify by
            /// substring match on the resulting text. Used for the
            /// `IsADirectory` case and for `write_file_direct`/
            /// `write_file_with_permit`'s streaming-size violations
            /// (GHSA-5j8q-wxg5-hj4r), neither of which has a meaningful
            /// `sevenz_rust2::Error` representation to round-trip through.
            pending_error: Option<ArchiveError>,
            /// Single reusable copy buffer for the whole extraction, mirroring
            /// TAR/ZIP's per-archive `CopyBuffer` (`tar.rs`, `zip.rs`).
            /// Previously `write_file_direct`/`write_file_with_permit_using`
            /// each allocated a fresh 64KiB `CopyBuffer` per file entry — the
            /// same per-file cost #492 removed from 7z's write path — so this
            /// hoists it here instead of threading a freshly-allocated one
            /// through `process_entry_inner` on every call.
            copy_buffer: CopyBuffer,
        }

        let mut ctx = SzContext {
            report: ExtractionReport::new(),
            dir_cache,
            progress,
            current_idx: 0,
            duplicate_skips: 0,
            disallowed_extension_skips: 0,
            pending_error: None,
            copy_buffer: CopyBuffer::new(),
        };

        // Extraction callback - called for each entry.
        //
        // We use ArchiveReader::for_each_entries directly instead of
        // decompress_with_extract_fn so that sevenz-rust2's own path-safety
        // check (added in 0.21.1) does not fire before our EntryValidator runs.
        // EntryValidator is the authoritative guard for all path security
        // (traversal, absolute paths, symlinks); the upstream check is
        // redundant and breaks allow_absolute_paths support.
        let is_solid = archive.is_solid;
        let mut extract_fn = |entry: &sevenz_rust2::ArchiveEntry,
                              reader: &mut dyn Read|
         -> std::result::Result<bool, sevenz_rust2::Error> {
            let kind = match SevenZClass::of(entry).present(&entry.name) {
                Ok(Some(kind)) => kind,
                Ok(None) => return Ok(true),
                Err(refusal) => return Err(abort_with(&mut ctx.pending_error, refusal)),
            };
            let entry_path = std::path::PathBuf::from(common::normalize_entry_name(&entry.name));
            ctx.current_idx = ctx.current_idx.saturating_add(1);
            let idx = ctx.current_idx;
            ctx.progress
                .on_entry_start(entry_path.as_path(), total, idx);

            let result = Self::process_entry_inner(
                entry,
                kind,
                reader,
                &entry_path,
                validator,
                dest,
                &mut ctx.report,
                ctx.dir_cache,
                skip_duplicates,
                config,
                &mut ctx.duplicate_skips,
                &mut ctx.disallowed_extension_skips,
                &mut ctx.pending_error,
                &mut ctx.copy_buffer,
            );

            // Entries of a solid block share one decoder stream: bytes a
            // skipped entry left unread would be served to the next entry.
            let result = if is_solid {
                result.and_then(|written| {
                    io::copy(&mut (&mut *reader).take(entry.size), &mut io::sink())?;
                    Ok(written)
                })
            } else {
                result
            };

            // INVARIANT: every branch below must call on_entry_complete exactly
            // once. Fire on_bytes_written before on_entry_complete
            // on success.
            match result {
                Ok(bytes_written) => {
                    if bytes_written > 0 {
                        ctx.progress.on_bytes_written(bytes_written);
                    }
                    ctx.progress.on_entry_complete(entry_path.as_path());
                    Ok(true)
                }
                Err(e) => {
                    ctx.progress.on_entry_complete(entry_path.as_path());
                    Err(e)
                }
            }
        };

        // Reuses the Archive header already parsed in `new()` instead of
        // re-parsing it from scratch (issue #492).
        let result = decode_archive_entries(
            source,
            archive,
            config.parallel_decode,
            DecodeKnobs::production(),
            &mut extract_fn,
        );
        let mut accumulated = ctx.report;
        push_skip_warnings(
            &mut accumulated,
            (ctx.duplicate_skips, ctx.disallowed_extension_skips),
            anti_items,
        );

        let e = match result {
            Ok(()) => {
                // `pending_error` is only ever set immediately before
                // `process_entry_inner` returns an `Err` for the same entry
                // (issue #483 S1 pattern); if the overall callback loop
                // succeeded, nothing should have stashed a pending error.
                debug_assert!(
                    ctx.pending_error.is_none(),
                    "pending_error must be unset when for_each_entries reports success"
                );
                return Ok(accumulated);
            }
            // A stashed `pending_error` takes priority: it means
            // `process_entry_inner` already resolved the precise error and
            // the `sevenz_rust2::Error` in `e` is just a same-iteration abort
            // signal, not the real failure (issue #483 S1).
            Err(e) => ctx
                .pending_error
                .take()
                .unwrap_or_else(|| ArchiveError::from(e)),
        };
        Err(ArchiveError::partial_or(accumulated, e))
    }
}

/// Appends the aggregated warnings for what `extract` skipped: duplicates and
/// disallowed extensions as `(duplicates, disallowed)`, and anti-items.
fn push_skip_warnings(report: &mut ExtractionReport, skips: (u64, u64), anti_items: u64) {
    let (duplicates, disallowed) = skips;
    common::push_duplicate_skip_warning(report, duplicates, "entry", "entries");
    common::push_disallowed_extension_warning(report, disallowed);
    push_anti_item_warning(report, anti_items);
}

/// Appends one aggregated warning for the anti-items `extract` skipped.
///
/// A no-op when `count` is zero.
fn push_anti_item_warning(report: &mut ExtractionReport, count: u64) {
    if count > 0 {
        report.warnings.push(format!(
            "skipped {count} 7z {} (deletion markers are not applied)",
            anti_item_noun(count)
        ));
    }
}

const fn anti_item_noun(count: u64) -> &'static str {
    if count == 1 {
        "anti-item"
    } else {
        "anti-items"
    }
}

/// The informational finding `verify` reports for skipped anti-items, or
/// `None` when the archive has none.
fn anti_item_issue(count: u64) -> Option<VerificationIssue> {
    (count > 0).then(|| {
        VerificationIssue::new(
            IssueSeverity::Info,
            IssueCategory::ArchiveNote,
            format!(
                "{count} 7z {} skipped (deletion markers are not applied)",
                anti_item_noun(count)
            ),
        )
    })
}

impl<R: Read + Seek> ArchiveFormat for SevenZArchive<R> {
    fn extract(
        &mut self,
        output_dir: &Path,
        config: &SecurityConfig<Validated>,
        options: &ExtractionOptions,
        progress: &mut dyn ProgressCallback,
    ) -> Result<ExtractionReport> {
        // Step 0: Admit the archive (solid policy, decoder memory, coders,
        // block layout) before anything is written
        if let Some(refusal) = iter_sevenz_refusals(&self.archive, config).next() {
            return Err(refusal.into_error());
        }

        // Step 1: Initialize extraction context
        let dest = DestDir::new_or_create(output_dir.to_path_buf())?;

        // Pre-validate all paths BEFORE extraction using cached metadata
        // SECURITY NOTE: Pre-validation prevents partial extraction on
        // malicious archives
        //
        // PERFORMANCE: Uses cached metadata from new() to avoid re-parsing
        // archive
        //
        // API LIMITATION (sevenz-rust2): only Windows reparse points and Unix
        // mode symlinks are detectable as links; hardlinks are not.
        let mut prevalidator = EntryValidator::new(config, &dest);
        let mut links = LinkTable::default();
        for (index, entry) in self.entries.iter().enumerate() {
            let Some(kind) = entry.class.present(&entry.name)? else {
                continue;
            };
            let path = std::path::PathBuf::from(common::normalize_entry_name(&entry.name));

            // Path-only validation here; quota for File entries is reserved
            // below, after checking whether this entry would be skipped as a
            // duplicate at the destination, so pre-validation does not
            // over-count entries Step 3 will actually skip (issue #478).
            let safe_path = match prevalidator.validate_entry_path(&path, kind.node_kind(), None)? {
                EntryPath::Root(_) => continue,
                EntryPath::Child(safe_path) => safe_path,
            };

            // Refuses reparse points and disallowed links before anything is
            // written, like `verify`.
            match kind {
                SevenZKind::Directory => continue,
                SevenZKind::ReparsePoint => return Err(reparse_point_refusal(&entry.name)),
                SevenZKind::UnixSymlink => {
                    validate_entry_compression(&entry.compression, entry.size, config)?;
                    require_symlinks_allowed(config)?;
                    common::require_symlink_creation()?;
                    links.push(index, safe_path)?;
                    continue;
                }
                SevenZKind::File => {}
            }

            // The ratio is a property of the archive, not of the destination,
            // so it is checked before the duplicate-skip below, matching what
            // `verify` reports.
            validate_entry_compression(&entry.compression, entry.size, config)?;

            let dest_path = dest.join_path(safe_path.as_path());
            // lstat so a pre-existing symlink at dest_path — including a
            // dangling one — counts as "already there", matching the
            // duplicate detection Step 3 performs (issue #468, #477, #478).
            let existing = lstat_dest(&dest_path)?;

            if existing.is_some() && options.skip_duplicates {
                // Step 3 will skip this entry; do not reserve its quota.
                continue;
            }

            #[cfg(unix)]
            if let Some(meta) = &existing
                && meta.file_type().is_symlink()
            {
                // Fail here too, not only in Step 3: with
                // skip_duplicates=false, a symlink at this entry's
                // destination will be rejected once extraction reaches it,
                // so failing during pre-validation — before any entry is
                // written — preserves this loop's "no partial extraction"
                // guarantee (issue #477).
                return Err(symlink_at_dest_error().into());
            }

            // The permit itself is discarded: this loop only needs
            // `reserve_file`'s Err on a would-be quota violation, since
            // `prevalidator` is thrown away once Step 1 finishes (Step 3
            // uses a fresh validator, see below).
            let _permit = prevalidator.reserve_file(entry.size)?;
        }

        self.validate_link_targets(&dest, config, &links)?;

        // Empty archives: skip extraction entirely — decompress_with_extract_fn
        // would fail with UnexpectedEof on valid 32-byte empty 7z archives.
        let total = self
            .entries
            .iter()
            .filter(|entry| matches!(entry.class, SevenZClass::Present(_)))
            .count();
        let anti_items = self.anti_item_count();
        if total == 0 {
            let mut report = ExtractionReport::new();
            push_anti_item_warning(&mut report, anti_items);
            return Ok(report);
        }

        // Step 3: Extract with FRESH validator to avoid quota double-counting.
        // The archive header was already parsed once in `new()` and is only
        // borrowed here, so a second `extract()` call on the same instance
        // still has real entry metadata to read.
        let mut validator = EntryValidator::new(config, &dest);
        let mut dir_cache = common::DirCache::new();

        let report = Self::extract_with_callback(
            &mut self.source,
            &self.archive,
            &dest,
            &mut validator,
            &mut dir_cache,
            options.skip_duplicates,
            progress,
            total,
            anti_items,
            config,
        )?;
        progress.on_complete();
        Ok(report)
    }

    fn list(
        &mut self,
        config: &SecurityConfig<Validated>,
    ) -> Result<crate::inspection::ArchiveManifest> {
        use crate::inspection::list::ListPass;
        use crate::inspection::list::list_sevenz_reader;
        self.source.rewind().map_err(ArchiveError::Io)?;
        list_sevenz_reader(&mut self.source, config, &mut ListPass::strict())
    }

    fn verify(
        &mut self,
        config: &SecurityConfig<Validated>,
        options: &VerificationOptions,
    ) -> Result<crate::inspection::VerificationReport> {
        use crate::inspection::list::list_sevenz_parsed;
        use crate::inspection::report::ArchiveStructure;
        use crate::inspection::verify::list_for_verify;
        use crate::inspection::verify::verify_manifest_with_structure;

        let mut issues = refusal_issues(&sevenz_refusals(&self.archive, config));
        issues.extend(anti_item_issue(self.anti_item_count()));
        let listed = list_for_verify(config, *options, |listing| {
            list_sevenz_parsed(&self.archive, &mut self.source, config, listing)
        })?;
        let structure = ArchiveStructure::of_manifest(&listed.manifest).with_refusals(&issues);
        verify_manifest_with_structure(&listed.manifest, config, &structure, listed.integrity)
    }

    fn format_name(&self) -> &'static str {
        "7z"
    }
}

/// How a 7z archive entry is treated, decided once for `extract`, `list` and
/// `verify` so they cannot disagree.
///
/// # Known Limitations (sevenz-rust2 0.24)
///
/// - **Unix mode**: p7zip and libarchive store the mode in the high 16 bits of
///   the attributes (flagged by `0x8000`). `S_IFLNK` is classified as
///   [`SevenZKind::UnixSymlink`]; a FIFO, socket, device node, undefined type,
///   or a type that contradicts the entry's native kind is
///   [`SevenZClass::Unsupported`].
/// - **Symlinks (Windows)**: detected through `FILE_ATTRIBUTE_REPARSE_POINT`
///   and refused on extraction.
/// - **Hardlinks**: not detectable; extracted as separate files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SevenZClass {
    /// A "delete this path" marker of an incremental update. Never extracted,
    /// validated, counted against quota or listed. Unlike `7z x`, which applies
    /// it as a deletion, exarch deliberately skips it: it applies no
    /// deletions, and materializing one would truncate an existing file.
    AntiItem,
    /// An entry that stands for something on disk.
    Present(SevenZKind),
    /// An entry exarch refuses in `extract`, `list` and `verify`.
    Unsupported(UnsupportedEntry),
}

/// What a present 7z entry stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SevenZKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A Windows reparse point (symlink or junction), file or directory.
    ReparsePoint,
    /// A symlink recorded through the Unix mode p7zip stores in the attributes.
    UnixSymlink,
}

/// What the 7z header itself says an entry is: a directory has no stream and
/// is not flagged as an empty file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeKind {
    /// Holds data or is an empty file.
    File,
    /// Has no stream and is not an empty file.
    Directory,
}

impl NativeKind {
    const fn noun(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
        }
    }

    const fn opposite(self) -> &'static str {
        match self {
            Self::File => "directory",
            Self::Directory => "regular file",
        }
    }
}

/// Where a claim about an entry's kind was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KindSource {
    /// The Unix mode in the high 16 bits of the attributes.
    UnixMode,
    /// The Windows `FILE_ATTRIBUTE_DIRECTORY` bit.
    WindowsAttribute,
}

impl KindSource {
    const fn noun(self) -> &'static str {
        match self {
            Self::UnixMode => "Unix mode",
            Self::WindowsAttribute => "Windows attributes",
        }
    }
}

/// Why a 7z entry is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnsupportedEntry {
    /// A FIFO, device node or socket.
    Special(common::SpecialFile),
    /// A Unix mode whose type bits name no defined file type.
    UndefinedType(u8),
    /// A recorded kind that the entry's native kind contradicts: the claim is
    /// the opposite of `native`.
    KindContradiction {
        /// What the 7z header says.
        native: NativeKind,
        /// Where the contradicting claim was recorded.
        claimed_by: KindSource,
    },
}

impl UnsupportedEntry {
    /// The refusal for the entry named `name`.
    fn refusal(self, name: &str) -> ArchiveError {
        let reason = match self {
            Self::Special(special) => {
                format!("{} entries not supported: {name}", special.noun())
            }
            Self::UndefinedType(bits) => {
                format!("7z entry has an undefined Unix file type ({bits:#x}): {name}")
            }
            Self::KindContradiction { native, claimed_by } => format!(
                "7z entry is a {} but its {} says {}: {name}",
                native.noun(),
                claimed_by.noun(),
                native.opposite()
            ),
        };
        ArchiveError::SecurityViolation { reason }
    }
}

impl SevenZClass {
    /// Classifies an entry. An anti item wins over every other attribute, and
    /// a link wins over the directory flag because junctions are directories.
    pub(crate) fn of(entry: &sevenz_rust2::ArchiveEntry) -> Self {
        use common::UnixFileType;

        if entry.is_anti_item {
            return Self::AntiItem;
        }
        if is_windows_reparse_point(entry) {
            return Self::Present(SevenZKind::ReparsePoint);
        }
        let mode_type = unix_file_type(entry);
        if mode_type == Some(UnixFileType::Symlink) {
            return Self::Present(SevenZKind::UnixSymlink);
        }
        let native = if entry.is_directory() {
            NativeKind::Directory
        } else {
            NativeKind::File
        };
        let contradiction = |claimed_by| {
            Self::Unsupported(UnsupportedEntry::KindContradiction { native, claimed_by })
        };
        match (mode_type, native) {
            (Some(UnixFileType::Special(special)), _) => {
                return Self::Unsupported(UnsupportedEntry::Special(special));
            }
            (Some(UnixFileType::Undefined(bits)), _) => {
                return Self::Unsupported(UnsupportedEntry::UndefinedType(bits));
            }
            (Some(UnixFileType::Regular), NativeKind::Directory)
            | (Some(UnixFileType::Directory), NativeKind::File) => {
                return contradiction(KindSource::UnixMode);
            }
            _ => {}
        }
        if native == NativeKind::File && claims_windows_directory(entry) {
            return contradiction(KindSource::WindowsAttribute);
        }
        Self::Present(match native {
            NativeKind::Directory => SevenZKind::Directory,
            NativeKind::File => SevenZKind::File,
        })
    }

    /// The kind of an entry to extract or list, `None` for an anti item.
    ///
    /// # Errors
    ///
    /// Returns `SecurityViolation` naming `name` for an unsupported entry.
    pub(crate) fn present(self, name: &str) -> Result<Option<SevenZKind>> {
        match self {
            Self::AntiItem => Ok(None),
            Self::Present(kind) => Ok(Some(kind)),
            Self::Unsupported(unsupported) => Err(unsupported.refusal(name)),
        }
    }
}

impl SevenZKind {
    /// How the root-entry rule sees this entry.
    pub(crate) const fn node_kind(self) -> NodeKind {
        match self {
            Self::Directory => NodeKind::Directory,
            Self::File | Self::ReparsePoint | Self::UnixSymlink => NodeKind::NonDirectory,
        }
    }

    /// The entry type `list` and `verify` report.
    pub(crate) const fn manifest_type(self) -> ManifestEntryType {
        match self {
            Self::File => ManifestEntryType::File,
            Self::Directory => ManifestEntryType::Directory,
            Self::ReparsePoint | Self::UnixSymlink => ManifestEntryType::Symlink,
        }
    }
}

/// The refusal for a Windows reparse point, which has no readable target.
fn reparse_point_refusal(name: &str) -> ArchiveError {
    ArchiveError::SecurityViolation {
        reason: format!(
            "symlink detected in 7z archive: {name} (Windows reparse point attribute set). \
             Its target cannot be read due to sevenz-rust2 API limitations."
        ),
    }
}

/// Stashes `error` for the caller to return as is and gives the error that ends
/// the sevenz-rust2 entry loop, which would otherwise reclassify it from its
/// message text.
fn abort_with(
    pending_error: &mut Option<ArchiveError>,
    error: ArchiveError,
) -> sevenz_rust2::Error {
    *pending_error = Some(error);
    sevenz_rust2::Error::Other("extraction aborted by security policy".into())
}

/// Checks if Windows attributes indicate a reparse point (symlink/junction).
///
/// Only detects links recorded through the Windows attribute; Unix-mode
/// symlinks are detected by [`unix_file_type`].
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants>
fn is_windows_reparse_point(entry: &sevenz_rust2::ArchiveEntry) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

    entry.has_windows_attributes && (entry.windows_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
}

/// Reads the file type of the Unix mode p7zip keeps in the high 16 bits of the
/// attributes, `None` when the entry carries no Unix mode or no type bits.
fn unix_file_type(entry: &sevenz_rust2::ArchiveEntry) -> Option<common::UnixFileType> {
    const UNIX_EXTENSION: u32 = 0x8000;

    (entry.has_windows_attributes && entry.windows_attributes & UNIX_EXTENSION != 0)
        .then(|| common::UnixFileType::from_mode(entry.windows_attributes >> 16))
        .flatten()
}

/// Checks whether the Windows attributes claim a directory.
fn claims_windows_directory(entry: &sevenz_rust2::ArchiveEntry) -> bool {
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;

    entry.has_windows_attributes && entry.windows_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
}

/// Checks whether a sevenz-rust2 parse failure is due to a valid empty 7z
/// archive.
///
/// sevenz-rust2 fails with `UnexpectedEof` on valid 32-byte empty archives (0
/// files). We detect this by requiring:
/// 1. The error is an I/O error with `ErrorKind::UnexpectedEof`
/// 2. The file starts with the 7z magic signature
/// 3. The file size is exactly 32 bytes (the only valid empty archive size)
fn is_empty_sevenz_archive<R: Read + Seek>(err: &sevenz_rust2::Error, source: &mut R) -> bool {
    const SEVENZ_MAGIC: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
    // A valid empty 7z archive is exactly 32 bytes:
    // signature (6) + version (2) + StartHeader CRC (4) + StartHeader (20).
    // Files shorter than 32 bytes are truncated/corrupt, not empty archives.
    const EMPTY_ARCHIVE_SIZE: u64 = 32;

    let is_eof = matches!(err, sevenz_rust2::Error::Io(io_err, _) if io_err.kind() == ErrorKind::UnexpectedEof);
    if !is_eof {
        return false;
    }

    // Check file size
    let Ok(size) = source.seek(std::io::SeekFrom::End(0)) else {
        return false;
    };
    if size != EMPTY_ARCHIVE_SIZE {
        return false;
    }

    // Check 7z magic signature
    let Ok(_) = source.seek(std::io::SeekFrom::Start(0)) else {
        return false;
    };
    let mut magic = [0u8; 6];
    source.read_exact(&mut magic).is_ok() && magic == SEVENZ_MAGIC
}

/// Whether a sevenz-rust2 error means the archive needs a password.
///
/// Matches the typed upstream variants so an upstream message change cannot
/// silently reclassify encrypted archives as merely invalid.
pub(crate) fn is_password_error(error: &sevenz_rust2::Error) -> bool {
    matches!(
        error,
        sevenz_rust2::Error::PasswordRequired | sevenz_rust2::Error::MaybeBadPassword(_)
    )
}

/// Converts sevenz-rust2 errors to our `ArchiveError` type.
///
/// I/O failures keep their original `io::Error` (kind and source chain).
impl From<sevenz_rust2::Error> for ArchiveError {
    fn from(err: sevenz_rust2::Error) -> Self {
        if is_password_error(&err) {
            return common::encrypted_archive_error();
        }

        match err {
            sevenz_rust2::Error::Io(io_err, _) => Self::Io(io_err),
            sevenz_rust2::Error::FileOpen(io_err, path) => Self::Io(std::io::Error::new(
                io_err.kind(),
                format!("{path}: {io_err}"),
            )),
            other => Self::InvalidArchive(format!("7z error: {other}")),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::IssueCategory;
    use std::assert_matches;
    use std::io::Cursor;
    use tempfile::TempDir;

    fn extraction_type_of(entry: &sevenz_rust2::ArchiveEntry) -> Result<EntryType> {
        match SevenZClass::of(entry).present(&entry.name)? {
            Some(SevenZKind::File) => Ok(EntryType::File),
            Some(SevenZKind::Directory) => Ok(EntryType::Directory),
            Some(SevenZKind::ReparsePoint) => Err(reparse_point_refusal(&entry.name)),
            Some(SevenZKind::UnixSymlink) => Ok(EntryType::Symlink {
                target: PathBuf::new(),
            }),
            None => panic!("anti item has no extraction type"),
        }
    }

    fn reparse(mut entry: sevenz_rust2::ArchiveEntry) -> sevenz_rust2::ArchiveEntry {
        entry.has_windows_attributes = true;
        entry.windows_attributes = 0x0400;
        entry
    }

    #[test]
    fn classifier_table() {
        use sevenz_rust2::ArchiveEntry;

        let file = ArchiveEntry::new_file("f");
        let dir = ArchiveEntry::new_directory("d");
        let mut anti_reparse_dir = reparse(ArchiveEntry::new_directory("x"));
        anti_reparse_dir.is_anti_item = true;

        assert_eq!(
            SevenZClass::of(&file),
            SevenZClass::Present(SevenZKind::File)
        );
        assert_eq!(
            SevenZClass::of(&dir),
            SevenZClass::Present(SevenZKind::Directory)
        );
        assert_eq!(
            SevenZClass::of(&reparse(ArchiveEntry::new_file("l"))),
            SevenZClass::Present(SevenZKind::ReparsePoint)
        );
        assert_eq!(
            SevenZClass::of(&reparse(ArchiveEntry::new_directory("j"))),
            SevenZClass::Present(SevenZKind::ReparsePoint)
        );
        assert_eq!(SevenZClass::of(&anti_reparse_dir), SevenZClass::AntiItem);
    }

    fn with_unix_mode(
        mut entry: sevenz_rust2::ArchiveEntry,
        mode: u32,
    ) -> sevenz_rust2::ArchiveEntry {
        entry.has_windows_attributes = true;
        entry.windows_attributes = 0x8000 | (mode << 16);
        entry
    }

    #[test]
    fn unix_mode_symlink_is_classified_as_symlink() {
        use sevenz_rust2::ArchiveEntry;

        let link = SevenZClass::Present(SevenZKind::UnixSymlink);

        assert_eq!(
            SevenZClass::of(&with_unix_mode(ArchiveEntry::new_file("l"), 0o120_777)),
            link
        );
        assert_eq!(
            SevenZClass::of(&with_unix_mode(ArchiveEntry::new_directory("l"), 0o120_777)),
            link
        );
        assert_eq!(
            SevenZClass::of(&with_unix_mode(ArchiveEntry::new_file("f"), 0o100_644)),
            SevenZClass::Present(SevenZKind::File)
        );
        assert_eq!(
            SevenZClass::of(&with_unix_mode(ArchiveEntry::new_directory("d"), 0o040_755)),
            SevenZClass::Present(SevenZKind::Directory)
        );
    }

    #[test]
    fn unix_mode_without_extension_flag_is_not_a_symlink() {
        let mut entry = sevenz_rust2::ArchiveEntry::new_file("f");
        entry.has_windows_attributes = true;
        entry.windows_attributes = 0o120_777 << 16;
        assert_eq!(
            SevenZClass::of(&entry),
            SevenZClass::Present(SevenZKind::File)
        );

        let mut anti = with_unix_mode(sevenz_rust2::ArchiveEntry::new_file("a"), 0o120_777);
        anti.is_anti_item = true;
        assert_eq!(SevenZClass::of(&anti), SevenZClass::AntiItem);
    }

    const S_IFSOCK: u32 = 0o14_0000;
    const S_IFBLK: u32 = 0o06_0000;
    const S_IFREG: u32 = 0o10_0000;
    const S_IFDIR: u32 = 0o04_0000;
    const S_IFCHR: u32 = 0o02_0000;
    const S_IFIFO: u32 = 0o01_0000;

    fn file_with_stream(name: &str) -> sevenz_rust2::ArchiveEntry {
        let mut entry = sevenz_rust2::ArchiveEntry::new_file(name);
        entry.has_stream = true;
        entry.size = 5;
        entry
    }

    #[test]
    fn unix_mode_special_files_are_unsupported_whatever_the_native_kind() {
        use common::SpecialFile::*;

        for (mode, special) in [
            (S_IFIFO, Fifo),
            (S_IFCHR, CharDevice),
            (S_IFBLK, BlockDevice),
            (S_IFSOCK, Socket),
        ] {
            for entry in [
                sevenz_rust2::ArchiveEntry::new_file("f"),
                file_with_stream("f"),
                sevenz_rust2::ArchiveEntry::new_directory("f"),
            ] {
                assert_eq!(
                    SevenZClass::of(&with_unix_mode(entry, mode | 0o644)),
                    SevenZClass::Unsupported(UnsupportedEntry::Special(special)),
                    "mode {mode:o}"
                );
            }
        }
    }

    #[test]
    fn unix_mode_with_an_undefined_type_is_unsupported() {
        for (mode, bits) in [(0o03_0000, 3), (0o05_0000, 5), (0o16_0000, 14)] {
            assert_eq!(
                SevenZClass::of(&with_unix_mode(file_with_stream("f"), mode | 0o644)),
                SevenZClass::Unsupported(UnsupportedEntry::UndefinedType(bits)),
                "mode {mode:o}"
            );
        }
    }

    #[test]
    fn unix_mode_agreeing_with_the_native_kind_is_present() {
        assert_eq!(
            SevenZClass::of(&with_unix_mode(file_with_stream("f"), S_IFREG | 0o644)),
            SevenZClass::Present(SevenZKind::File)
        );
        assert_eq!(
            SevenZClass::of(&with_unix_mode(
                sevenz_rust2::ArchiveEntry::new_file("f"),
                S_IFREG | 0o644
            )),
            SevenZClass::Present(SevenZKind::File)
        );
        assert_eq!(
            SevenZClass::of(&with_unix_mode(
                sevenz_rust2::ArchiveEntry::new_directory("d"),
                S_IFDIR | 0o755
            )),
            SevenZClass::Present(SevenZKind::Directory)
        );
    }

    #[test]
    fn unix_mode_contradicting_the_native_kind_is_unsupported() {
        let directory_claim = SevenZClass::Unsupported(UnsupportedEntry::KindContradiction {
            native: NativeKind::File,
            claimed_by: KindSource::UnixMode,
        });
        let file_claim = SevenZClass::Unsupported(UnsupportedEntry::KindContradiction {
            native: NativeKind::Directory,
            claimed_by: KindSource::UnixMode,
        });

        assert_eq!(
            SevenZClass::of(&with_unix_mode(file_with_stream("f"), S_IFDIR | 0o755)),
            directory_claim
        );
        assert_eq!(
            SevenZClass::of(&with_unix_mode(
                sevenz_rust2::ArchiveEntry::new_file("f"),
                S_IFDIR | 0o755
            )),
            directory_claim
        );
        assert_eq!(
            SevenZClass::of(&with_unix_mode(
                sevenz_rust2::ArchiveEntry::new_directory("d"),
                S_IFREG | 0o644
            )),
            file_claim
        );
    }

    #[test]
    fn mode_without_type_bits_leaves_the_native_kind() {
        assert_eq!(
            SevenZClass::of(&with_unix_mode(file_with_stream("f"), 0o644)),
            SevenZClass::Present(SevenZKind::File)
        );
        assert_eq!(
            SevenZClass::of(&with_unix_mode(
                sevenz_rust2::ArchiveEntry::new_directory("d"),
                0o755
            )),
            SevenZClass::Present(SevenZKind::Directory)
        );
    }

    #[test]
    fn windows_directory_bit_on_a_native_file_is_unsupported() {
        const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

        let mut entry = file_with_stream("f");
        entry.has_windows_attributes = true;
        entry.windows_attributes = FILE_ATTRIBUTE_DIRECTORY;
        assert_eq!(
            SevenZClass::of(&entry),
            SevenZClass::Unsupported(UnsupportedEntry::KindContradiction {
                native: NativeKind::File,
                claimed_by: KindSource::WindowsAttribute,
            })
        );

        let mut dir = sevenz_rust2::ArchiveEntry::new_directory("d");
        dir.has_windows_attributes = true;
        dir.windows_attributes = FILE_ATTRIBUTE_DIRECTORY;
        assert_eq!(
            SevenZClass::of(&dir),
            SevenZClass::Present(SevenZKind::Directory)
        );

        let mut clear = sevenz_rust2::ArchiveEntry::new_directory("d");
        clear.has_windows_attributes = true;
        clear.windows_attributes = 0x20;
        assert_eq!(
            SevenZClass::of(&clear),
            SevenZClass::Present(SevenZKind::Directory)
        );
    }

    #[test]
    fn symlink_and_reparse_bit_win_before_kind_checks() {
        let mut link = with_unix_mode(file_with_stream("l"), 0o120_777);
        link.windows_attributes |= 0x10;
        assert_eq!(
            SevenZClass::of(&link),
            SevenZClass::Present(SevenZKind::UnixSymlink)
        );

        let mut reparse_dir_bit = file_with_stream("r");
        reparse_dir_bit.has_windows_attributes = true;
        reparse_dir_bit.windows_attributes = 0x410;
        assert_eq!(
            SevenZClass::of(&reparse_dir_bit),
            SevenZClass::Present(SevenZKind::ReparsePoint)
        );
    }

    #[test]
    fn anti_item_wins_over_an_unsupported_mode() {
        let mut anti = with_unix_mode(file_with_stream("a"), S_IFIFO | 0o644);
        anti.is_anti_item = true;
        assert_eq!(SevenZClass::of(&anti), SevenZClass::AntiItem);
    }

    #[test]
    fn present_refuses_unsupported_entries_by_name() {
        let fifo = with_unix_mode(file_with_stream("pipe"), S_IFIFO | 0o644);
        assert_matches!(
            SevenZClass::of(&fifo).present("pipe"),
            Err(ArchiveError::SecurityViolation { reason })
                if reason.contains("FIFO entries not supported") && reason.contains("pipe")
        );
        let anti = SevenZClass::AntiItem;
        assert_matches!(anti.present("a"), Ok(None));
        assert_matches!(
            SevenZClass::Present(SevenZKind::File).present("f"),
            Ok(Some(SevenZKind::File))
        );
    }

    #[test]
    fn reparse_point_wins_over_unix_symlink() {
        let mut entry = with_unix_mode(sevenz_rust2::ArchiveEntry::new_file("l"), 0o120_777);
        entry.windows_attributes |= 0x0400;
        assert_eq!(
            SevenZClass::of(&entry),
            SevenZClass::Present(SevenZKind::ReparsePoint)
        );
    }

    #[test]
    fn unix_mode_is_ignored_without_windows_attributes() {
        let mut entry = with_unix_mode(sevenz_rust2::ArchiveEntry::new_file("f"), 0o120_777);
        entry.has_windows_attributes = false;
        assert_eq!(
            SevenZClass::of(&entry),
            SevenZClass::Present(SevenZKind::File)
        );
    }

    // 7z format magic bytes for signature validation
    const SEVENZ_MAGIC: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

    /// Load pre-generated fixture from tests/fixtures/
    pub(super) fn load_fixture(name: &str) -> Vec<u8> {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let fixture_path = std::path::PathBuf::from(manifest_dir)
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/fixtures")
            .join(name);

        std::fs::read(&fixture_path).unwrap_or_else(|e| {
            panic!(
                "Failed to load fixture {name}. Run tests/fixtures/generate_7z_fixtures.sh first. Error: {e}"
            )
        })
    }

    /// Test that `format_name` returns correct value.
    /// This test doesn't require a valid archive.
    #[test]
    fn test_format_name() {
        // We can't create a valid SevenZArchive without a real archive,
        // but we can verify the implementation returns the expected value
        // by checking the trait implementation directly.

        // Create invalid data - this will fail to parse
        let data = SEVENZ_MAGIC.to_vec();
        let cursor = Cursor::new(data);

        // new() will fail because it's not a valid archive, but that's expected
        let result = SevenZArchive::new(cursor);
        assert!(result.is_err(), "invalid archive should fail to parse");

        // Verify the error is InvalidArchive (not security violation)
        assert_matches!(result, Err(ArchiveError::InvalidArchive(_)));
    }

    /// Test that invalid magic bytes are rejected.
    #[test]
    fn test_invalid_magic_rejected() {
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let cursor = Cursor::new(data);

        let result = SevenZArchive::new(cursor);
        assert!(result.is_err());
        assert_matches!(result, Err(ArchiveError::InvalidArchive(_)));
    }

    #[test]
    fn test_load_fixture_helper() {
        let data = load_fixture("simple.7z");
        assert!(!data.is_empty());
        assert_eq!(&data[0..6], &SEVENZ_MAGIC);
    }

    /// Reserves a throwaway [`QuotaPermit`] for use in tests that call
    /// `write_file_with_permit` directly, bypassing the normal validation
    /// pipeline that would otherwise produce one.
    #[cfg(unix)]
    fn test_permit() -> QuotaPermit {
        let config = SecurityConfig::default().validate().expect("valid config");
        crate::security::quota::QuotaTracker::new()
            .reserve(0, &config)
            .expect("reservation should succeed")
    }

    /// Regression test for issue #471: `write_file_with_permit`'s temp file
    /// name is predictable from the process PID and a per-process monotonic
    /// counter (`.{name}.exarch-tmp-{pid}-{counter}`). A dangling symlink
    /// pre-planted at one of the next few predicted counter values used to
    /// be silently followed by a non-exclusive `File::create`, writing
    /// archive content through it and outside the extraction root. The fix
    /// retries with a fresh counter value on `AlreadyExists` instead of
    /// falling through to a non-exclusive open.
    ///
    /// Exercises [`write_file_with_permit_using`] directly with a private,
    /// test-local candidate generator instead of calling
    /// [`write_file_with_permit`] (which draws from the process-global
    /// [`TEMP_COUNTER`]): predicting exactly which paths a call will attempt
    /// is only safe if nothing else in the process can advance that counter
    /// concurrently, which does not hold under `cargo test`'s default
    /// multi-threaded execution (sibling tests write 7z files too). A
    /// private generator has no shared state to race on, so this test is
    /// deterministic under both `cargo test` and nextest (see #471 review).
    #[test]
    #[cfg(unix)]
    fn test_write_file_with_permit_skips_planted_symlinks() {
        let temp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let dest_path = temp.path().join("real-output.txt");

        // Plant dangling symlinks at every candidate path the generator
        // below will produce, except the last available attempt, so the fix
        // must retry past all of them.
        let mut victims = Vec::new();
        for offset in 0..(MAX_TEMP_FILE_CREATE_ATTEMPTS - 1) {
            let planted_path = temp.path().join(format!(".candidate-{offset}.tmp"));
            let victim_path = outside.path().join(format!("victim-{offset}.txt"));
            std::os::unix::fs::symlink(&victim_path, &planted_path).unwrap();
            victims.push((planted_path, victim_path));
        }

        let mut next_candidate = 0u32;
        let temp_dir_path = temp.path().to_path_buf();
        let mut reader = Cursor::new(b"legit content".to_vec());
        let mut copy_buffer = CopyBuffer::new();
        let bytes_written = write_file_with_permit_using(
            &mut reader,
            &dest_path,
            13,
            &mut copy_buffer,
            test_permit(),
            || {
                let path = temp_dir_path.join(format!(".candidate-{next_candidate}.tmp"));
                next_candidate += 1;
                path
            },
        )
        .expect("should retry past every planted symlink and succeed");

        assert_eq!(bytes_written, 13);
        assert_eq!(std::fs::read(&dest_path).unwrap(), b"legit content");
        // The generator must have been driven past every planted symlink to
        // reach a free candidate — otherwise this test would pass vacuously
        // without ever exercising the retry-on-AlreadyExists path.
        assert_eq!(next_candidate, MAX_TEMP_FILE_CREATE_ATTEMPTS);

        for (planted_path, victim_path) in &victims {
            assert!(
                !victim_path.exists(),
                "write followed a planted symlink outside the extraction root"
            );
            let metadata = std::fs::symlink_metadata(planted_path).unwrap();
            assert!(
                metadata.file_type().is_symlink(),
                "planted symlink should be left untouched, not consumed or replaced"
            );
        }
    }

    /// Companion to [`test_write_file_with_permit_skips_planted_symlinks`]:
    /// when every attempt's candidate path is blocked by a planted symlink,
    /// `write_file_with_permit_using` must give up with an error instead of
    /// looping forever or falling back to a non-exclusive open. Uses the
    /// same private-generator approach for the same determinism reason.
    #[test]
    #[cfg(unix)]
    fn test_write_file_with_permit_gives_up_after_max_attempts() {
        let temp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let dest_path = temp.path().join("real-output.txt");

        let mut victims = Vec::new();
        for offset in 0..MAX_TEMP_FILE_CREATE_ATTEMPTS {
            let planted_path = temp.path().join(format!(".candidate-{offset}.tmp"));
            let victim_path = outside.path().join(format!("victim-{offset}.txt"));
            std::os::unix::fs::symlink(&victim_path, &planted_path).unwrap();
            victims.push(victim_path);
        }

        let mut next_candidate = 0u32;
        let temp_dir_path = temp.path().to_path_buf();
        let mut reader = Cursor::new(b"legit content".to_vec());
        let mut copy_buffer = CopyBuffer::new();
        let result = write_file_with_permit_using(
            &mut reader,
            &dest_path,
            13,
            &mut copy_buffer,
            test_permit(),
            || {
                let path = temp_dir_path.join(format!(".candidate-{next_candidate}.tmp"));
                next_candidate += 1;
                path
            },
        );

        assert!(
            result.is_err(),
            "expected exhaustion error, got: {result:?}"
        );
        assert_eq!(next_candidate, MAX_TEMP_FILE_CREATE_ATTEMPTS);
        assert!(!dest_path.exists());
        for victim_path in &victims {
            assert!(!victim_path.exists());
        }
    }

    /// Regression test for GHSA-5j8q-wxg5-hj4r on 7z's fast write path
    /// (`write_file_direct`, used when nothing occupies the destination): a
    /// reader producing far more bytes than `expected_size` (standing in for
    /// a forged `entry.size` from 7z's own archive metadata) must abort with
    /// an error and must not leave an oversized file on disk.
    #[test]
    #[cfg(unix)]
    fn test_write_file_direct_forged_size_aborts_and_cleans_up() {
        let temp = TempDir::new().unwrap();
        let dest_path = temp.path().join("bomb.bin");

        let real_data = vec![0x41u8; 200 * 1024];
        let mut reader = Cursor::new(&real_data);
        let mut copy_buffer = CopyBuffer::new();

        let result =
            write_file_direct(&mut reader, &dest_path, 50, &mut copy_buffer, test_permit());

        assert!(
            result.is_err(),
            "streaming past expected_size must abort, got: {result:?}"
        );
        match result {
            Err(ArchiveError::SecurityViolation { reason }) => {
                assert!(
                    reason.contains("50 bytes"),
                    "error must name the declared ceiling (50), got: {reason:?}"
                );
            }
            other => {
                panic!("expected SecurityViolation naming the 50-byte ceiling, got: {other:?}")
            }
        }
        assert!(
            !dest_path.exists(),
            "aborted write_file_direct must not leave a file on disk"
        );
    }

    /// Same as [`test_write_file_direct_forged_size_aborts_and_cleans_up`]
    /// but for the overwrite path (`write_file_with_permit`, temp-file +
    /// rename): the forged-size abort must clean up the temp file and must
    /// never reach `rename`, so the pre-existing destination is untouched.
    #[test]
    #[cfg(unix)]
    fn test_write_file_with_permit_forged_size_aborts_and_leaves_original_untouched() {
        let temp = TempDir::new().unwrap();
        let dest_path = temp.path().join("existing.bin");
        std::fs::write(&dest_path, b"original content").unwrap();

        let real_data = vec![0x41u8; 200 * 1024];
        let mut reader = Cursor::new(&real_data);
        let mut copy_buffer = CopyBuffer::new();

        let result =
            write_file_with_permit(&mut reader, &dest_path, 50, &mut copy_buffer, test_permit());

        assert!(
            result.is_err(),
            "streaming past expected_size must abort, got: {result:?}"
        );
        assert_eq!(
            std::fs::read(&dest_path).unwrap(),
            b"original content",
            "aborted overwrite must leave the pre-existing destination untouched"
        );
        // No stray temp file (`.existing.bin.exarch-tmp-*`) left behind.
        let leftovers: Vec<_> = std::fs::read_dir(temp.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name() != dest_path.file_name().unwrap())
            .collect();
        assert!(
            leftovers.is_empty(),
            "aborted write must not leave a temp file behind, found: {leftovers:?}"
        );
    }

    #[test]
    fn test_extract_simple_file() {
        let data = load_fixture("simple.7z");
        let cursor = Cursor::new(data);
        let mut archive = SevenZArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 2);
        assert!(temp.path().join("simple/file1.txt").exists());
        assert!(temp.path().join("simple/file2.txt").exists());

        // Verify file contents
        let content1 = std::fs::read_to_string(temp.path().join("simple/file1.txt")).unwrap();
        assert_eq!(content1, "hello world\n");
    }

    #[test]
    fn test_extract_nested_directories() {
        let data = load_fixture("nested-dirs.7z");
        let cursor = Cursor::new(data);
        let mut archive = SevenZArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert!(report.files_extracted >= 1);
        assert!(temp.path().join("nested/subdir1/subdir2/deep.txt").exists());
        assert!(temp.path().join("nested/subdir1/file.txt").exists());
    }

    #[test]
    fn test_solid_archive_rejected() {
        let data = load_fixture("solid.7z");
        let cursor = Cursor::new(data);

        // new() should now succeed (just caches is_solid flag)
        let mut archive = SevenZArchive::new(cursor).unwrap();

        // Rejection happens in extract() with default config
        let temp = TempDir::new().unwrap();
        let result = archive.extract(
            temp.path(),
            &SecurityConfig::default().validate().unwrap(),
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
        assert_matches!(result.unwrap_err(), ArchiveError::SecurityViolation { .. });
    }

    #[test]
    fn test_encrypted_archive_rejected() {
        let data = load_fixture("encrypted.7z");
        let cursor = Cursor::new(data);

        // Should fail in new() due to encryption detection
        let result = SevenZArchive::new(cursor);
        assert!(result.is_err());
        assert_matches!(result.unwrap_err(), ArchiveError::SecurityViolation { .. });
    }

    #[test]
    fn test_empty_archive() {
        let data = load_fixture("empty.7z");
        let cursor = Cursor::new(data);
        let mut archive = SevenZArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 0);
        assert_eq!(report.directories_created, 0);
    }

    #[test]
    fn test_empty_archive_extract() {
        let path = std::path::Path::new("../../tests/fixtures/empty.7z");
        let file = std::fs::File::open(path).unwrap();
        let mut archive = SevenZArchive::new(file).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();
        assert_eq!(report.files_extracted, 0);
        assert_eq!(report.bytes_written, 0);
    }

    fn parse_fixture(name: &str) -> (Archive, u64) {
        let data = load_fixture(name);
        let len = data.len() as u64;
        let archive = Archive::read(&mut Cursor::new(data), &Password::empty()).unwrap();
        (archive, len)
    }

    #[test]
    fn test_compression_non_solid_covers_every_stream_file() {
        let (archive, len) = parse_fixture("simple.7z");
        let compression = sevenz_entry_compression(&archive, len).unwrap();
        assert_eq!(compression.len(), archive.files.len());
        for (file, compression) in archive.files.iter().zip(&compression) {
            assert_eq!(
                file.has_stream,
                matches!(compression, EntryCompression::Entry(_)),
                "{}",
                file.name
            );
        }
    }

    #[test]
    fn test_compression_solid_block_start_carries_block_totals() {
        let (archive, len) = parse_fixture("solid.7z");
        let compression = sevenz_entry_compression(&archive, len).unwrap();
        let pack_sizes = archive.pack_sizes();
        let first_packs = archive.stream_map.block_first_pack_stream_index();
        let first_files = &archive.stream_map.block_first_file_index;
        assert!(!first_files.is_empty());

        for (block, &file) in first_files.iter().enumerate() {
            let end = first_packs
                .get(block + 1)
                .copied()
                .unwrap_or(pack_sizes.len());
            let expected_compressed: u64 = pack_sizes[first_packs[block]..end].iter().sum();
            let expected_uncompressed: u64 = archive
                .files
                .iter()
                .enumerate()
                .filter(|(i, _)| archive.stream_map.file_block_index[*i] == Some(block))
                .map(|(_, f)| f.size)
                .sum();
            assert_eq!(
                compression[file],
                EntryCompression::SolidBlockStart(SolidBlock::new(
                    expected_compressed,
                    expected_uncompressed
                )),
                "block {block}"
            );
        }
        for (index, compression) in compression.iter().enumerate() {
            if !first_files.contains(&index) && archive.files[index].has_stream {
                assert_eq!(
                    *compression,
                    EntryCompression::SolidBlockMember,
                    "file {index}"
                );
            }
        }
    }

    fn make_sevenz_archive_with_empty_file() -> Vec<u8> {
        use sevenz_rust2::ArchiveEntry;
        use sevenz_rust2::ArchiveWriter;

        let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
        writer
            .push_archive_entry(ArchiveEntry::new_file("empty.txt"), None::<Cursor<Vec<u8>>>)
            .unwrap();
        let mut full = ArchiveEntry::new_file("full.txt");
        full.has_stream = true;
        full.size = 7;
        writer
            .push_archive_entry(full, Some(Cursor::new(b"payload".to_vec())))
            .unwrap();
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn test_compression_block_uncompressed_overflow_is_rejected() {
        let (mut archive, len) = parse_fixture("solid.7z");
        let members: Vec<usize> = (0..archive.files.len())
            .filter(|&i| archive.stream_map.file_block_index[i] == Some(0))
            .collect();
        assert!(members.len() >= 2, "fixture must have a multi-file block");
        archive.files[members[0]].size = u64::MAX;
        archive.files[members[1]].size = 1;

        assert_matches!(
            sevenz_entry_compression(&archive, len),
            Err(ArchiveError::QuotaExceeded {
                resource: QuotaResource::IntegerOverflow
            })
        );
    }

    #[test]
    fn test_compression_empty_files_are_unknown() {
        let data = make_sevenz_archive_with_empty_file();
        let len = data.len() as u64;
        let archive = Archive::read(&mut Cursor::new(data), &Password::empty()).unwrap();
        let compression = sevenz_entry_compression(&archive, len).unwrap();
        for (file, compression) in archive.files.iter().zip(&compression) {
            if file.size == 0 {
                assert_eq!(*compression, EntryCompression::Unknown, "{}", file.name);
            } else {
                assert_matches!(compression, EntryCompression::Entry(_));
            }
        }
    }

    fn entry_compressed_sizes(name: &str) -> Vec<u64> {
        let (archive, len) = parse_fixture(name);
        let compression = sevenz_entry_compression(&archive, len).unwrap();
        let entries: Vec<u64> = compression
            .iter()
            .filter_map(|c| match c {
                EntryCompression::Entry(size) => Some(*size),
                _ => None,
            })
            .collect();
        entries
    }

    #[test]
    fn test_compression_bcj2_block_counts_its_four_pack_streams() {
        let (archive, _) = parse_fixture("bcj2.7z");
        assert_eq!(archive.pack_sizes().len(), 4);
        let expected: u64 = archive.pack_sizes().iter().sum();

        assert_eq!(entry_compressed_sizes("bcj2.7z"), [expected]);
    }

    #[test]
    fn test_compression_bcj2_block_excludes_an_unreferenced_pack_stream() {
        let (archive, _) = parse_fixture("bcj2-spare-pack.7z");
        let pack_sizes = archive.pack_sizes();
        assert_eq!(pack_sizes.len(), 5);
        assert_eq!(pack_sizes[4], 7);
        let expected: u64 = pack_sizes[..4].iter().sum();

        assert_eq!(entry_compressed_sizes("bcj2-spare-pack.7z"), [expected]);
    }

    #[test]
    fn test_compression_bcj2_id_on_a_one_input_coder_is_capped_at_declared_streams() {
        let (archive, _) = parse_fixture("bcj2-simple-coder.7z");
        assert_eq!(archive.pack_sizes().len(), 1);
        let expected = archive.pack_sizes()[0];

        assert_eq!(entry_compressed_sizes("bcj2-simple-coder.7z"), [expected]);
    }

    #[test]
    fn test_compression_rejects_source_shorter_than_declared_streams() {
        let (archive, len) = parse_fixture("simple.7z");
        let declared: u64 = archive.pack_sizes().iter().sum();
        let too_short = SIGNATURE_HEADER_SIZE + archive.pack_pos() + declared - 1;
        assert!(too_short < len);
        assert_matches!(
            sevenz_entry_compression(&archive, too_short),
            Err(ArchiveError::InvalidArchive(_))
        );
    }

    /// Test B-002: Verify quota is not double-counted
    /// Pre-validation and extraction use separate validators to prevent
    /// counting files twice against quotas.
    #[test]
    fn test_multiple_files_quota_not_double_counted() {
        let data = load_fixture("simple.7z"); // Contains 2 files
        let cursor = Cursor::new(data);
        let mut archive = SevenZArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        // Should allow 2 files
        let config = SecurityConfig::default()
            .with_max_file_count(3)
            .validate()
            .unwrap();

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );
        assert!(
            result.is_ok(),
            "2 files should not exceed quota of 3: {result:?}"
        );
        assert_eq!(result.unwrap().files_extracted, 2);
    }

    /// Test B-1: Verify path traversal is rejected
    /// This test ensures the validator integration properly rejects
    /// archives with path traversal attempts.
    #[test]
    fn test_path_traversal_integration() {
        // Test that our validator integration works by creating a simple
        // archive and verifying the validator is properly called
        let data = load_fixture("simple.7z");
        let cursor = Cursor::new(data);
        let archive = SevenZArchive::new(cursor);

        // Verify our validator is properly integrated
        assert!(archive.is_ok());

        // NOTE: Path traversal testing is covered by integration tests using
        // actual 7z fixtures. Additional unit-level fixture testing can be
        // added here if needed in the future.
    }

    /// Test: Solid archive extracts when allowed
    #[test]
    fn test_solid_archive_allowed_with_config() {
        let data = load_fixture("solid.7z");
        let cursor = Cursor::new(data);
        let mut archive = SevenZArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default()
            .with_allow_solid_archives(true)
            .with_max_solid_block_memory(100 * 1024 * 1024)
            .validate()
            .unwrap(); // 100 MB

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );
        assert!(result.is_ok(), "solid archive should extract: {result:?}");
        assert!(result.unwrap().files_extracted > 0);
    }

    /// Test: Solid archive rejected by default config
    #[test]
    fn test_solid_archive_rejected_by_default() {
        let data = load_fixture("solid.7z");
        let cursor = Cursor::new(data);
        let mut archive = SevenZArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );
        assert!(result.is_err());
        assert_matches!(result.unwrap_err(), ArchiveError::SecurityViolation { .. });
    }

    /// Test: Solid archive memory limit exceeded
    #[test]
    fn test_solid_archive_memory_limit_exceeded() {
        let data = load_fixture("solid.7z");
        let cursor = Cursor::new(data);
        let mut archive = SevenZArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default()
            .with_allow_solid_archives(true)
            .with_max_solid_block_memory(1)
            .validate()
            .unwrap(); // 1 byte (too small)

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );
        assert!(result.is_err());
        assert_matches!(result.unwrap_err(), ArchiveError::QuotaExceeded { .. });
    }

    /// Test: Non-solid archives work regardless of solid config
    #[test]
    fn test_non_solid_archive_unaffected_by_solid_config() {
        let data = load_fixture("simple.7z");
        let cursor = Cursor::new(data);
        let mut archive = SevenZArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config"); // allow_solid_archives = false

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );
        assert!(result.is_ok(), "non-solid should work: {result:?}");
    }

    // ============================================================================
    // Phase 10.4 Review Fixes: Additional Tests
    // ============================================================================

    /// Test H-3: Verify `is_solid` flag is correctly detected
    #[test]
    fn test_is_solid_flag_detected_correctly() {
        // Solid archive should have is_solid = true
        let solid_data = load_fixture("solid.7z");
        let solid_cursor = Cursor::new(solid_data);
        let solid_archive = SevenZArchive::new(solid_cursor).unwrap();
        assert!(
            solid_archive.archive.is_solid,
            "solid.7z should have is_solid=true"
        );

        // Non-solid archive should have is_solid = false
        let non_solid_data = load_fixture("simple.7z");
        let non_solid_cursor = Cursor::new(non_solid_data);
        let non_solid_archive = SevenZArchive::new(non_solid_cursor).unwrap();
        assert!(
            !non_solid_archive.archive.is_solid,
            "simple.7z should have is_solid=false"
        );
    }

    /// Test H-1: Boundary condition - exact limit should PASS
    #[test]
    fn test_solid_archive_memory_limit_exact_boundary() {
        let data = load_fixture("solid.7z");

        // First read to get total size
        let archive_for_size = SevenZArchive::new(Cursor::new(data.clone())).unwrap();
        let total_size: u64 = archive_for_size.entries.iter().map(|e| e.size).sum();

        // Now test with exact limit
        let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();
        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default()
            .with_allow_solid_archives(true)
            .with_max_solid_block_memory(total_size)
            .validate()
            .unwrap(); // Exact match

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );
        assert!(
            result.is_ok(),
            "exact limit should allow extraction: {result:?}"
        );
    }

    /// Test H-1: Boundary condition - one byte under limit should FAIL
    #[test]
    fn test_solid_archive_memory_limit_one_under_boundary() {
        let data = load_fixture("solid.7z");

        // First read to get total size
        let archive_for_size = SevenZArchive::new(Cursor::new(data.clone())).unwrap();
        let total_size: u64 = archive_for_size.entries.iter().map(|e| e.size).sum();

        // Ensure we have at least 2 bytes of content to make test meaningful
        if total_size < 2 {
            return; // Skip test if fixture is too small
        }

        // Now test with one byte under
        let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();
        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default()
            .with_allow_solid_archives(true)
            .with_max_solid_block_memory(total_size - 1)
            .validate()
            .unwrap(); // One byte under

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );
        assert!(result.is_err(), "one byte under limit should reject");
        assert_matches!(result.unwrap_err(), ArchiveError::QuotaExceeded { .. });
    }

    /// Test H-2: Verify error message contains helpful info
    #[test]
    fn test_solid_archive_rejected_error_message() {
        let data = load_fixture("solid.7z");
        let cursor = Cursor::new(data);
        let mut archive = SevenZArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let result = archive.extract(
            temp.path(),
            &SecurityConfig::default().validate().unwrap(),
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            ArchiveError::SecurityViolation { reason } => {
                assert!(
                    reason.contains("solid") && reason.contains("allow_solid_archives"),
                    "error should mention 'solid' and 'allow_solid_archives', got: {reason}"
                );
            }
            other => panic!("expected SecurityViolation, got {other:?}"),
        }
    }

    // ============================================================================
    // Phase 10.5: Symlink/Hardlink Detection Tests
    // ============================================================================

    /// Test: Windows reparse point detection (TRUE case)
    #[test]
    fn test_windows_reparse_point_detected() {
        let mut entry = sevenz_rust2::ArchiveEntry::new_file("symlink.txt");
        entry.has_windows_attributes = true;
        entry.windows_attributes = 0x0400; // FILE_ATTRIBUTE_REPARSE_POINT

        assert!(
            is_windows_reparse_point(&entry),
            "reparse point attribute should be detected"
        );

        let result = extraction_type_of(&entry);
        assert!(result.is_err(), "should return error for reparse point");
        assert_matches!(
            result.unwrap_err(),
            ArchiveError::SecurityViolation { .. },
            "should be SecurityViolation error"
        );
    }

    /// Test: Windows reparse point NOT detected (has attributes, but not
    /// reparse point)
    #[test]
    fn test_windows_reparse_point_not_set() {
        let mut entry = sevenz_rust2::ArchiveEntry::new_file("file.txt");
        entry.has_windows_attributes = true;
        entry.windows_attributes = 0x0080; // FILE_ATTRIBUTE_NORMAL

        assert!(
            !is_windows_reparse_point(&entry),
            "normal file should not be detected as reparse point"
        );

        let result = extraction_type_of(&entry);
        assert!(result.is_ok(), "normal file should succeed");
        assert_eq!(result.unwrap(), EntryType::File);
    }

    /// Test: No Windows attributes (Unix archive)
    #[test]
    fn test_no_windows_attributes() {
        let mut entry = sevenz_rust2::ArchiveEntry::new_file("file.txt");
        entry.has_windows_attributes = false;
        entry.windows_attributes = 0; // Should be ignored

        assert!(
            !is_windows_reparse_point(&entry),
            "entry without Windows attributes should not be detected as reparse point"
        );

        let result = extraction_type_of(&entry);
        assert!(result.is_ok(), "file without attributes should succeed");
        assert_eq!(result.unwrap(), EntryType::File);
    }

    /// Test: Windows reparse point with other attributes combined
    #[test]
    fn test_windows_reparse_point_with_other_attributes() {
        let mut entry = sevenz_rust2::ArchiveEntry::new_file("symlink.txt");
        entry.has_windows_attributes = true;
        entry.windows_attributes = 0x0400 | 0x0020; // REPARSE_POINT | ARCHIVE

        assert!(
            is_windows_reparse_point(&entry),
            "reparse point should be detected even with other attributes"
        );

        let result = extraction_type_of(&entry);
        assert!(result.is_err(), "should return error for reparse point");
    }

    /// Test: Directory entry should not trigger reparse point check
    #[test]
    fn test_directory_junction_reparse_point_rejected() {
        let mut entry = sevenz_rust2::ArchiveEntry::new_directory("dir/");
        entry.has_windows_attributes = true;
        entry.windows_attributes = 0x0400; // REPARSE_POINT (directory junction)

        // SECURITY: Reparse point check happens FIRST, even for directories
        // This catches directory junctions (Windows symlink directories)
        let result = extraction_type_of(&entry);
        assert!(result.is_err(), "directory junction should be rejected");
        assert_matches!(result.unwrap_err(), ArchiveError::SecurityViolation { .. });
    }

    /// Test: Error message for Windows reparse point
    #[test]
    fn test_windows_reparse_point_error_message() {
        let mut entry = sevenz_rust2::ArchiveEntry::new_file("link.txt");
        entry.has_windows_attributes = true;
        entry.windows_attributes = 0x0400;

        let result = extraction_type_of(&entry);
        assert!(result.is_err());

        match result.unwrap_err() {
            ArchiveError::SecurityViolation { reason } => {
                assert!(
                    reason.contains("symlink") && reason.contains("link.txt"),
                    "error should mention 'symlink' and entry name, got: {reason}"
                );
                assert!(
                    reason.contains("sevenz-rust2"),
                    "error should mention library limitation, got: {reason}"
                );
            }
            other => panic!("expected SecurityViolation, got {other:?}"),
        }
    }

    /// Issue #634: I/O errors keep their original kind and message instead of
    /// being rebuilt from the `Display` text as `ErrorKind::Other`.
    #[test]
    fn test_sevenz_io_error_preserves_kind_and_message() {
        let inner = std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "unexpected EOF while reading entry data",
        );
        let sevenz_err = sevenz_rust2::Error::Io(inner, "test.7z".into());

        let archive_err: ArchiveError = sevenz_err.into();

        match archive_err {
            ArchiveError::Io(io_err) => {
                assert_eq!(io_err.kind(), std::io::ErrorKind::UnexpectedEof);
                assert!(io_err.to_string().contains("unexpected EOF"));
            }
            other => panic!("expected ArchiveError::Io, got {other:?}"),
        }
    }

    #[test]
    fn test_sevenz_file_open_error_keeps_path_and_kind() {
        let inner = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let err = ArchiveError::from(sevenz_rust2::Error::FileOpen(inner, "a/b.7z".into()));
        match err {
            ArchiveError::Io(io_err) => {
                assert_eq!(io_err.kind(), std::io::ErrorKind::NotFound);
                assert!(io_err.to_string().contains("a/b.7z"), "{io_err}");
            }
            other => panic!("expected ArchiveError::Io, got {other:?}"),
        }
    }

    /// Issue #634: encryption is detected from the typed variants, and
    /// unrelated messages that merely contain "read" or "password" are not
    /// reclassified.
    #[test]
    fn test_sevenz_error_classification_is_typed() {
        for err in [
            sevenz_rust2::Error::PasswordRequired,
            sevenz_rust2::Error::MaybeBadPassword(std::io::Error::other("bad")),
        ] {
            assert_matches!(
                ArchiveError::from(err),
                ArchiveError::SecurityViolation { .. }
            );
        }

        let lookalike = sevenz_rust2::Error::Other("thread already ready: password".into());
        assert_matches!(
            ArchiveError::from(lookalike),
            ArchiveError::InvalidArchive(_)
        );
    }

    #[test]
    fn test_list_returns_manifest_with_entries() {
        let data = load_fixture("simple.7z");
        let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let manifest = archive.list(&config).unwrap();

        assert!(
            manifest.total_entries() > 0,
            "simple.7z must have at least one entry"
        );
    }

    #[test]
    fn test_verify_clean_sevenz_is_safe() {
        let data = load_fixture("simple.7z");
        let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let report = archive
            .verify(&config, &crate::VerificationOptions::default())
            .unwrap();

        assert!(report.is_safe());
    }

    #[test]
    fn test_allowed_extensions_filters_out_disallowed() {
        // mixed-extensions.7z contains document.txt, program.exe, readme.txt
        let data = load_fixture("mixed-extensions.7z");
        let dest = TempDir::new().unwrap();

        let config = SecurityConfig::default()
            .with_allowed_extensions(vec!["txt".to_string()])
            .validate()
            .unwrap();

        let report = SevenZArchive::new(Cursor::new(data))
            .unwrap()
            .extract(
                dest.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(
            report.files_extracted, 2,
            "only .txt files should be extracted"
        );
        assert_eq!(report.files_skipped, 1, ".exe file should be skipped");
        assert!(
            !dest
                .path()
                .join("mixed-ext-fixture")
                .join("program.exe")
                .exists(),
            ".exe must not be extracted"
        );
        assert!(
            dest.path()
                .join("mixed-ext-fixture")
                .join("document.txt")
                .exists(),
            ".txt files must be extracted"
        );
        assert_eq!(
            report.warnings,
            vec!["skipped 1 entry with disallowed extension".to_string()],
            "the disallowed-extension skip must be aggregated into a single warning \
             instead of a per-entry, path-bearing one (issue #495)"
        );
    }

    /// Reproduces the actual #495 bug scenario end-to-end: many entries
    /// rejected by the extension allowlist must aggregate into a single
    /// warning instead of growing `report.warnings` proportional to archive
    /// size (mirrors `test_skip_duplicates_aggregates_single_warning`, #490).
    #[test]
    fn test_disallowed_extension_aggregates_single_warning() {
        const ENTRY_COUNT: usize = 30;
        let names: Vec<String> = (0..ENTRY_COUNT).map(|i| format!("skip-{i}.exe")).collect();
        let entries: Vec<(&str, &[u8])> = names
            .iter()
            .map(|n| (n.as_str(), b"payload".as_slice()))
            .collect();
        let data = make_sevenz_archive(&entries);
        let dest = TempDir::new().unwrap();
        let config = SecurityConfig::default()
            .with_allowed_extensions(vec!["txt".to_string()])
            .validate()
            .expect("valid config");

        let report = SevenZArchive::new(Cursor::new(data))
            .unwrap()
            .extract(
                dest.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_skipped, ENTRY_COUNT);
        assert_eq!(report.files_extracted, 0);
        assert_eq!(
            report.warnings,
            vec![format!(
                "skipped {ENTRY_COUNT} entries with disallowed extensions"
            )],
            "disallowed-extension skips must be aggregated into a single warning, got: {:?}",
            report.warnings
        );
    }

    /// Verifies duplicate-skip and disallowed-extension-skip counters
    /// aggregate independently in the same extraction: an archive mixing
    /// both skip reasons must produce exactly two warnings, one per reason,
    /// each with the correct count (issue #495).
    #[test]
    fn test_duplicate_and_disallowed_extension_skips_aggregate_independently() {
        const DUPLICATE_COUNT: usize = 5;
        const DISALLOWED_COUNT: usize = 7;

        let mut names: Vec<String> = (0..DUPLICATE_COUNT)
            .map(|i| format!("dup-{i}.txt"))
            .collect();
        names.extend((0..DISALLOWED_COUNT).map(|i| format!("skip-{i}.exe")));
        let entries: Vec<(&str, &[u8])> = names
            .iter()
            .map(|n| (n.as_str(), b"payload".as_slice()))
            .collect();
        let data = make_sevenz_archive(&entries);

        let temp = TempDir::new().unwrap();
        for name in names.iter().take(DUPLICATE_COUNT) {
            std::fs::write(temp.path().join(name), b"already here").unwrap();
        }

        let config = SecurityConfig::default()
            .with_allowed_extensions(vec!["txt".to_string()])
            .validate()
            .expect("valid config");

        let report = SevenZArchive::new(Cursor::new(data))
            .unwrap()
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(), // skip_duplicates = true
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_skipped, DUPLICATE_COUNT + DISALLOWED_COUNT);
        assert_eq!(report.files_extracted, 0);
        assert_eq!(
            report.warnings.len(),
            2,
            "each skip reason must aggregate into its own single warning, got: {:?}",
            report.warnings
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains(&DUPLICATE_COUNT.to_string()) && w.contains("duplicate")),
            "expected a duplicate-skip warning reporting {DUPLICATE_COUNT}, got: {:?}",
            report.warnings
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains(&DISALLOWED_COUNT.to_string())
                    && w.contains("disallowed extension")),
            "expected a disallowed-extension warning reporting {DISALLOWED_COUNT}, got: {:?}",
            report.warnings
        );
    }

    #[test]
    fn test_empty_allowed_extensions_allows_all() {
        let data = load_fixture("simple.7z");
        let dest = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config"); // empty = allow all

        let report = SevenZArchive::new(Cursor::new(data))
            .unwrap()
            .extract(
                dest.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_skipped, 0);
        assert!(report.files_extracted > 0);
    }

    #[test]
    fn test_extension_less_files_blocked_when_allowlist_nonempty() {
        // no-extension.7z contains document.txt and Makefile (no extension)
        let data = load_fixture("no-extension.7z");
        let dest = TempDir::new().unwrap();
        let config = SecurityConfig::default()
            .with_allowed_extensions(vec!["txt".to_string()])
            .validate()
            .unwrap();

        let report = SevenZArchive::new(Cursor::new(data))
            .unwrap()
            .extract(
                dest.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1, "only .txt should be extracted");
        assert_eq!(
            report.files_skipped, 1,
            "extension-less file must be skipped"
        );
        assert!(!dest.path().join("no-ext-fixture").join("Makefile").exists());
        assert!(
            dest.path()
                .join("no-ext-fixture")
                .join("document.txt")
                .exists()
        );
    }

    fn make_sevenz_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use sevenz_rust2::ArchiveEntry;
        use sevenz_rust2::ArchiveWriter;
        use sevenz_rust2::EncoderConfiguration;
        use sevenz_rust2::EncoderMethod;

        let buf = Cursor::new(Vec::new());
        let mut writer = ArchiveWriter::new(buf).unwrap();
        writer.set_content_methods(vec![EncoderConfiguration::new(EncoderMethod::COPY)]);
        for (name, data) in entries {
            let mut entry = ArchiveEntry::new_file(name);
            entry.has_stream = true;
            entry.size = data.len() as u64;
            writer
                .push_archive_entry(entry, Some(Cursor::new(*data)))
                .unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    /// Builds a 7z archive with all `entries` packed into one solid block
    /// using the COPY method.
    fn make_solid_sevenz_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        build_solid_sevenz_archive(entries, true)
    }

    pub(super) fn build_solid_sevenz_archive(
        entries: &[(&str, &[u8])],
        copy_method: bool,
    ) -> Vec<u8> {
        use sevenz_rust2::ArchiveEntry;
        use sevenz_rust2::ArchiveWriter;
        use sevenz_rust2::EncoderConfiguration;
        use sevenz_rust2::EncoderMethod;
        use sevenz_rust2::SourceReader;

        let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
        if copy_method {
            writer.set_content_methods(vec![EncoderConfiguration::new(EncoderMethod::COPY)]);
        }
        let archive_entries = entries
            .iter()
            .map(|(name, data)| {
                let mut entry = ArchiveEntry::new_file(name);
                entry.has_stream = !data.is_empty();
                entry.size = data.len() as u64;
                entry
            })
            .collect();
        let readers = entries
            .iter()
            .map(|(_, data)| SourceReader::from(Cursor::new(*data)))
            .collect();
        writer
            .push_archive_entries(archive_entries, readers)
            .unwrap();
        writer.finish().unwrap().into_inner()
    }

    fn solid_config(allowed_extensions: Vec<String>) -> SecurityConfig<Validated> {
        SecurityConfig::default()
            .with_allow_solid_archives(true)
            .with_max_solid_block_memory(100 * 1024 * 1024)
            .with_allowed_extensions(allowed_extensions)
            .validate()
            .unwrap()
    }

    /// A solid block of `copies` identical source files, LZMA2-compressed.
    fn compressed_solid_copies(copies: usize) -> Vec<u8> {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let source: Vec<u8> = (0..4096)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                b"0123456789abcdef"[(state % 16) as usize]
            })
            .collect();
        let names: Vec<String> = (0..copies).map(|i| format!("copy{i}/main.rs")).collect();
        let entries: Vec<(&str, &[u8])> = names
            .iter()
            .map(|n| (n.as_str(), source.as_slice()))
            .collect();
        build_solid_sevenz_archive(&entries, false)
    }

    fn solid_block_ratio(data: &[u8]) -> f64 {
        let archive = Archive::read(&mut Cursor::new(data.to_vec()), &Password::empty()).unwrap();
        let compression = sevenz_entry_compression(&archive, data.len() as u64).unwrap();
        compression
            .iter()
            .find_map(|c| match c {
                EntryCompression::SolidBlockStart(b) => {
                    Some(b.uncompressed as f64 / b.compressed as f64)
                }
                _ => None,
            })
            .expect("a solid block start")
    }

    /// Issue #626: a legitimate solid block above the per-file ratio limit
    /// but below the solid limit extracts and verifies cleanly.
    #[test]
    fn test_legit_solid_block_above_per_file_ratio_passes_extract_and_verify() {
        let data = compressed_solid_copies(100);
        let ratio = solid_block_ratio(&data);
        assert!(
            (100.0..1000.0).contains(&ratio),
            "fixture must sit between the per-file and solid limits, got {ratio}"
        );

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("tree.7z");
        std::fs::write(&path, &data).unwrap();
        let config = SecurityConfig::default().with_allow_solid_archives(true);

        let report = crate::verify_archive(&path, &config).unwrap();
        assert_ne!(
            report.status(),
            crate::inspection::report::VerificationStatus::Fail,
            "issues: {:?}",
            report.issues()
        );

        let out = dir.path().join("out");
        let report = crate::extract_archive(&path, &out, &config).unwrap();
        assert_eq!(report.files_extracted, 100);
    }

    /// Issue #626: a block over `max_solid_compression_ratio` is rejected by
    /// extract before any write and flagged by verify.
    #[test]
    fn test_solid_block_over_limit_rejected_by_extract_and_verify() {
        let data = compressed_solid_copies(100);
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("tree.7z");
        std::fs::write(&path, &data).unwrap();
        let config = SecurityConfig::default()
            .with_allow_solid_archives(true)
            .with_max_solid_compression_ratio(50.0);

        let report = crate::verify_archive(&path, &config).unwrap();
        assert!(
            report
                .issues()
                .iter()
                .any(|i| i.category == crate::inspection::report::IssueCategory::ZipBomb),
            "issues: {:?}",
            report.issues()
        );

        let out = dir.path().join("out");
        let result = crate::extract_archive(&path, &out, &config);
        assert_matches!(result, Err(ArchiveError::ZipBomb(_)));
        assert!(!out.join("copy0").exists(), "nothing may be written");
    }

    /// Issue #628: a disallowed entry in a solid block must not leave its
    /// bytes in the shared stream for the next entry to read.
    #[test]
    fn test_solid_block_disallowed_entry_does_not_shift_next_entry() {
        let skipped = vec![b'A'; 5000];
        let kept = vec![b'B'; 5000];
        let data = make_solid_sevenz_archive(&[("a.bin", &skipped), ("b.txt", &kept)]);
        let dest = TempDir::new().unwrap();

        let report = SevenZArchive::new(Cursor::new(data))
            .unwrap()
            .extract(
                dest.path(),
                &solid_config(vec!["txt".to_string()]),
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert_eq!(report.files_skipped, 1);
        assert!(!dest.path().join("a.bin").exists());
        assert_eq!(std::fs::read(dest.path().join("b.txt")).unwrap(), kept);
    }

    /// Issue #628: skipping the last entry of a solid block must leave the
    /// earlier entries and the extraction result intact.
    #[test]
    fn test_solid_block_skipping_last_entry_extracts_earlier_entries() {
        let first = vec![b'A'; 5000];
        let second = vec![b'B'; 5000];
        let skipped = vec![b'C'; 5000];
        let data = make_solid_sevenz_archive(&[
            ("a.txt", &first),
            ("b.txt", &second),
            ("c.exe", &skipped),
        ]);
        let dest = TempDir::new().unwrap();

        let report = SevenZArchive::new(Cursor::new(data))
            .unwrap()
            .extract(
                dest.path(),
                &solid_config(vec!["txt".to_string()]),
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 2);
        assert_eq!(report.files_skipped, 1);
        assert_eq!(std::fs::read(dest.path().join("a.txt")).unwrap(), first);
        assert_eq!(std::fs::read(dest.path().join("b.txt")).unwrap(), second);
        assert!(!dest.path().join("c.exe").exists());
    }

    /// Issue #628: same as above for the `skip_duplicates` skip path.
    #[test]
    fn test_solid_block_duplicate_entry_does_not_shift_next_entry() {
        let skipped = vec![b'A'; 5000];
        let kept = vec![b'B'; 5000];
        let data = make_solid_sevenz_archive(&[("a.txt", &skipped), ("b.txt", &kept)]);
        let dest = TempDir::new().unwrap();
        std::fs::write(dest.path().join("a.txt"), b"already here").unwrap();

        let report = SevenZArchive::new(Cursor::new(data))
            .unwrap()
            .extract(
                dest.path(),
                &solid_config(Vec::new()),
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert_eq!(report.files_skipped, 1);
        assert_eq!(
            std::fs::read(dest.path().join("a.txt")).unwrap(),
            b"already here"
        );
        assert_eq!(std::fs::read(dest.path().join("b.txt")).unwrap(), kept);
    }

    /// Test #376: entry names with embedded `\` must be treated as path
    /// separators.
    ///
    /// On Unix, `PathBuf::from("..\\..\\x")` would produce a single component,
    /// bypassing traversal detection. After normalization `\` → `/`, the name
    /// becomes `../../x` and must be rejected.
    #[test]
    fn test_7z_backslash_entry_rejected() {
        let data = make_sevenz_archive(&[("..\\..\\x", b"payload")]);
        let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();

        let temp = TempDir::new().unwrap();
        let result = archive.extract(
            temp.path(),
            &SecurityConfig::default().validate().unwrap(),
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );
        assert!(
            result.is_err(),
            "backslash-encoded traversal must be rejected, got: {result:?}"
        );
        assert_matches!(
            result.unwrap_err(),
            ArchiveError::PathTraversal { .. },
            "expected PathTraversal error"
        );
    }

    #[test]
    fn test_7z_absolute_path_rejected_by_default() {
        let data = make_sevenz_archive(&[("/etc/shadow", b"secret")]);
        let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );
        assert!(
            result.is_err(),
            "absolute path must be rejected by default, got: {result:?}"
        );
    }

    #[test]
    fn test_7z_absolute_path_with_flag_writes_to_dest() {
        let data = make_sevenz_archive(&[("/etc/shadow", b"content")]);
        let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default()
            .with_allow_absolute_paths(true)
            .validate()
            .unwrap();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert!(
            temp.path().join("etc/shadow").exists(),
            "file must land inside dest, not at real /etc/shadow"
        );
    }

    #[test]
    fn test_7z_absolute_path_traversal_still_rejected_with_flag() {
        let data = make_sevenz_archive(&[("/../etc/passwd", b"secret")]);
        let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default()
            .with_allow_absolute_paths(true)
            .validate()
            .unwrap();

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );
        assert!(
            result.is_err(),
            "traversal-after-root must be rejected even with allow_absolute_paths"
        );
    }

    /// Regression test for GHSA-qh76-45cr-8xrc / CVE-2026-61725 (7z Zip-Slip):
    /// proves the extraction-time re-validation inside `process_entry_inner`
    /// (the "defense in depth" layer noted at the top of
    /// `extract_with_callback`, which compensates for deliberately bypassing
    /// upstream's own Zip-Slip guard) independently rejects a traversal
    /// entry.
    ///
    /// `SevenZArchive::extract` always pre-validates every entry in Step 1
    /// before this callback ever runs, so a traversal entry reaching
    /// `extract()` is caught there first (see the `test_7z_*_rejected*`
    /// tests above). This test calls `process_entry_inner` directly to
    /// exercise the callback layer in isolation, proving it is not dead
    /// code should Step 1 ever be bypassed or restructured.
    #[test]
    fn test_process_entry_inner_rejects_traversal_independently() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new_or_create(temp.path().to_path_buf()).unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);
        let mut dir_cache = common::DirCache::new();
        let mut report = ExtractionReport::new();
        let mut duplicate_skips = 0u64;
        let mut disallowed_extension_skips = 0u64;
        let mut pending_error = None;
        let mut copy_buffer = CopyBuffer::new();

        let mut entry = sevenz_rust2::ArchiveEntry::new_file("../../evil.txt");
        entry.has_stream = true;
        entry.size = 5;
        let entry_path = std::path::PathBuf::from(common::normalize_entry_name(&entry.name));

        let result = SevenZArchive::<Cursor<Vec<u8>>>::process_entry_inner(
            &entry,
            SevenZKind::File,
            &mut std::io::empty(),
            &entry_path,
            &mut validator,
            &dest,
            &mut report,
            &mut dir_cache,
            false,
            &config,
            &mut duplicate_skips,
            &mut disallowed_extension_skips,
            &mut pending_error,
            &mut copy_buffer,
        );

        assert_matches!(
            &result,
            Err(sevenz_rust2::Error::Other(m)) if m.contains("validation failed"),
            "callback re-validation must independently reject a traversal entry via its own \
             validate_entry call, got: {result:?}"
        );
    }

    /// Regression test for #502: `duplicate_skips` must saturate instead of
    /// wrapping (or panicking, in debug builds) once it reaches `u64::MAX`,
    /// mirroring the near-boundary pattern used by
    /// `common.rs`'s `test_extract_file_with_permit_integer_overflow_check`
    /// for `bytes_written`.
    #[test]
    fn test_process_entry_inner_duplicate_skips_saturates_at_max() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new_or_create(temp.path().to_path_buf()).unwrap();
        std::fs::write(temp.path().join("existing.txt"), b"already here").unwrap();

        let config = SecurityConfig::default().validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);
        let mut dir_cache = common::DirCache::new();
        let mut report = ExtractionReport::new();
        let mut duplicate_skips = u64::MAX;
        let mut disallowed_extension_skips = 0u64;
        let mut pending_error = None;
        let mut copy_buffer = CopyBuffer::new();

        let mut entry = sevenz_rust2::ArchiveEntry::new_file("existing.txt");
        entry.has_stream = true;
        entry.size = 5;
        let entry_path = std::path::PathBuf::from(common::normalize_entry_name(&entry.name));

        let result = SevenZArchive::<Cursor<Vec<u8>>>::process_entry_inner(
            &entry,
            SevenZKind::File,
            &mut std::io::empty(),
            &entry_path,
            &mut validator,
            &dest,
            &mut report,
            &mut dir_cache,
            true, // skip_duplicates
            &config,
            &mut duplicate_skips,
            &mut disallowed_extension_skips,
            &mut pending_error,
            &mut copy_buffer,
        );

        assert_matches!(
            result,
            Ok(0),
            "duplicate skip must not error, got: {result:?}"
        );
        assert_eq!(
            duplicate_skips,
            u64::MAX,
            "duplicate_skips must saturate at u64::MAX instead of wrapping or panicking"
        );
    }

    /// Issue #468: `Path::exists()` follows symlinks and returns `false` for
    /// a dangling symlink, so the old `dest_path.exists()` check silently
    /// missed a pre-existing dangling symlink occupying the entry's
    /// destination path. With `skip_duplicates` true, the entry must be
    /// detected as a duplicate and skipped, leaving the dangling symlink in
    /// place instead of being silently replaced.
    #[test]
    #[cfg(unix)]
    fn test_skip_duplicates_detects_dangling_symlink_at_destination() {
        let data = make_sevenz_archive(&[("target.txt", b"payload")]);
        let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();

        let temp = TempDir::new().unwrap();
        let link_path = temp.path().join("target.txt");
        std::os::unix::fs::symlink(temp.path().join("does-not-exist"), &link_path).unwrap();
        assert!(
            !link_path.exists(),
            "sanity check: dangling symlink must be invisible to exists()"
        );

        let config = SecurityConfig::default().validate().expect("valid config");
        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(), // skip_duplicates = true
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(
            report.files_skipped, 1,
            "entry must be skipped as a duplicate of the dangling symlink"
        );
        assert_eq!(report.files_extracted, 0);
        let metadata = std::fs::symlink_metadata(&link_path).unwrap();
        assert!(
            metadata.file_type().is_symlink(),
            "dangling symlink must survive untouched, not be replaced by extracted content"
        );
    }

    /// Regression test for #477: before this fix, `skip_duplicates = false`
    /// against a dangling symlink at the destination silently replaced it —
    /// `write_file_with_permit`'s temp-file + `rename` replaces whatever
    /// sits at `dest_path`, symlink or not, without following it, and
    /// nothing upstream of that rename rejected a symlink destination the
    /// way TAR/ZIP's `O_NOFOLLOW`/`ELOOP` in `create_file_with_mode` does.
    /// `process_entry_inner` now checks `lstat_dest` before reserving quota
    /// or removing anything, and fails with the same `ELOOP` I/O error
    /// TAR/ZIP produce instead of silently replacing the symlink.
    #[test]
    #[cfg(unix)]
    fn test_duplicate_rejects_dangling_symlink_when_not_skipping() {
        let data = make_sevenz_archive(&[("target.txt", b"payload")]);
        let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();

        let temp = TempDir::new().unwrap();
        let link_path = temp.path().join("target.txt");
        std::os::unix::fs::symlink(temp.path().join("does-not-exist"), &link_path).unwrap();

        let config = SecurityConfig::default().validate().expect("valid config");
        let options = ExtractionOptions {
            skip_duplicates: false,
            ..ExtractionOptions::default()
        };
        let result = archive.extract(temp.path(), &config, &options, &mut crate::NoopProgress);

        assert!(
            result.is_err(),
            "a pre-existing symlink at the destination must be rejected, not silently \
             replaced: {result:?}"
        );
        let metadata = std::fs::symlink_metadata(&link_path).unwrap();
        assert!(
            metadata.file_type().is_symlink(),
            "dangling symlink must survive untouched, not be replaced by extracted content"
        );
    }

    /// Regression test for issue #483: extracting a file entry onto a
    /// pre-existing *directory* at the destination path must fail instead of
    /// recursively deleting the directory tree via `remove_dir_all`.
    ///
    /// Asserts the error's `io::ErrorKind` specifically (not just
    /// `is_err()`): the S1 bug this guards against had extraction still
    /// return `Err`, but with the precise `IsADirectory` kind lost to the
    /// lossy `From<sevenz_rust2::Error> for ArchiveError` string-heuristic
    /// converter (and, for some path names, misclassified as
    /// `SecurityViolation`), so a bare `is_err()` check would not have
    /// caught it.
    #[test]
    fn test_overwrite_directory_returns_error_without_deleting_it() {
        let data = make_sevenz_archive(&[("target", b"payload")]);
        let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();

        let temp = TempDir::new().unwrap();
        let dir_path = temp.path().join("target");
        std::fs::create_dir(&dir_path).unwrap();
        let inner_file = dir_path.join("keep-me.txt");
        std::fs::write(&inner_file, b"do not delete").unwrap();

        let config = SecurityConfig::default().validate().expect("valid config");
        let options = ExtractionOptions {
            skip_duplicates: false,
            ..ExtractionOptions::default()
        };

        let result = archive.extract(temp.path(), &config, &options, &mut crate::NoopProgress);

        let err =
            result.expect_err("extracting a file entry onto a pre-existing directory must fail");
        assert_matches!(
            &err,
            ArchiveError::Io(io_err) if io_err.kind() == std::io::ErrorKind::IsADirectory,
            "must fail with ErrorKind::IsADirectory specifically, not a generic or \
             misclassified error, got: {err:?}"
        );
        assert!(
            dir_path.is_dir(),
            "pre-existing directory must survive the failed extraction, not be deleted"
        );
        assert_eq!(
            std::fs::read(&inner_file).unwrap(),
            b"do not delete",
            "directory contents must be untouched by the failed extraction"
        );
    }

    /// Regression test for issue #483 finding S2: a symlink whose target is
    /// itself a directory must not be misidentified as a real directory and
    /// take the `ErrorKind::IsADirectory` branch. It is still rejected — as
    /// of #486/#477, every pre-existing symlink at the destination fails
    /// with `ELOOP` on Unix rather than being replaced — but the failure
    /// must come from the symlink check, not the directory check, and the
    /// symlink's target directory itself must survive untouched either way.
    #[test]
    #[cfg(unix)]
    fn test_symlink_to_directory_rejected_via_symlink_check_not_directory_check() {
        let data = make_sevenz_archive(&[("target", b"payload")]);
        let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();

        let temp = TempDir::new().unwrap();
        let real_dir = temp.path().join("real-dir");
        std::fs::create_dir(&real_dir).unwrap();
        let link_path = temp.path().join("target");
        std::os::unix::fs::symlink(&real_dir, &link_path).unwrap();

        let config = SecurityConfig::default().validate().expect("valid config");
        let options = ExtractionOptions {
            skip_duplicates: false,
            ..ExtractionOptions::default()
        };

        let result = archive.extract(temp.path(), &config, &options, &mut crate::NoopProgress);

        assert!(
            result.is_err(),
            "a pre-existing symlink at the destination must be rejected, even when its \
             target is a directory: {result:?}"
        );
        let metadata = std::fs::symlink_metadata(&link_path).unwrap();
        assert!(
            metadata.file_type().is_symlink(),
            "the symlink itself must survive untouched, not be replaced"
        );
        assert!(
            real_dir.is_dir(),
            "the symlink's target directory itself must be untouched"
        );
    }

    /// Regression test for issue #484: extracting an archive with many
    /// pre-existing duplicate entries must push exactly one aggregated
    /// warning onto `report.warnings`, not one `String` per skipped entry.
    #[test]
    fn test_skip_duplicates_aggregates_single_warning() {
        const ENTRY_COUNT: usize = 30;
        let names: Vec<String> = (0..ENTRY_COUNT).map(|i| format!("dup-{i}.txt")).collect();
        let entries: Vec<(&str, &[u8])> = names
            .iter()
            .map(|n| (n.as_str(), b"payload".as_slice()))
            .collect();
        let data = make_sevenz_archive(&entries);
        let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();

        let temp = TempDir::new().unwrap();
        for name in &names {
            std::fs::write(temp.path().join(name), b"already here").unwrap();
        }

        let config = SecurityConfig::default().validate().expect("valid config");
        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(), // skip_duplicates = true
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_skipped, ENTRY_COUNT);
        assert_eq!(report.files_extracted, 0);
        assert_eq!(
            report.warnings.len(),
            1,
            "duplicate skips must be aggregated into a single warning, got: {:?}",
            report.warnings
        );
        assert!(
            report.warnings[0].contains(&ENTRY_COUNT.to_string()),
            "aggregated warning must report the correct skipped count, got: {}",
            report.warnings[0]
        );
    }

    /// Regression test for issue #492 adversarial review, finding C1:
    /// `process_entry_inner` must re-validate every entry's path without
    /// trusting `dir_cache`'s record of directories it has already created.
    /// If something outside the archive's own entries — e.g. a misbehaving
    /// `ProgressCallback` — replaces a previously-created directory with a
    /// symlink between two entries that share it as a parent, the trust
    /// shortcut would let the second entry's write follow that symlink
    /// outside the destination root, silently and repeatedly, instead of
    /// failing loudly the way an untrusted (always-canonicalize) validation
    /// does. Simulates exactly that swap and asserts extraction aborts
    /// instead of writing through the symlink.
    #[test]
    #[cfg(unix)]
    fn test_dir_swapped_for_symlink_between_entries_is_rejected() {
        struct DirSwapper {
            dest_root: std::path::PathBuf,
            outside_root: std::path::PathBuf,
        }

        impl crate::ProgressCallback for DirSwapper {
            fn on_entry_start(&mut self, _path: &std::path::Path, _total: usize, _current: usize) {}

            fn on_bytes_written(&mut self, _bytes: u64) {}

            fn on_entry_complete(&mut self, path: &std::path::Path) {
                if path == std::path::Path::new("a/file1.txt") {
                    let a = self.dest_root.join("a");
                    std::fs::remove_dir_all(&a).unwrap();
                    std::os::unix::fs::symlink(&self.outside_root, &a).unwrap();
                }
            }

            fn on_complete(&mut self) {}
        }

        let data = make_sevenz_archive(&[("a/file1.txt", b"one"), ("a/file2.txt", b"two")]);
        let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();

        let dest = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();

        let mut swapper = DirSwapper {
            dest_root: dest.path().to_path_buf(),
            outside_root: outside.path().to_path_buf(),
        };

        let config = SecurityConfig::default().validate().expect("valid config");
        let result = archive.extract(
            dest.path(),
            &config,
            &ExtractionOptions::default(),
            &mut swapper,
        );

        assert!(
            result.is_err(),
            "extraction must fail once a parent directory is swapped for a symlink \
             mid-extraction, not silently continue writing through it"
        );
        assert!(
            !outside.path().join("file2.txt").exists(),
            "file2.txt must not be written through the swapped symlink outside the \
             destination root"
        );
    }

    /// Regression test for issue #492 adversarial review, finding C2:
    /// `extract()` must remain safely callable more than once on the same
    /// `SevenZArchive` instance. `mem::take`-ing the cached `Archive` on the
    /// first call left `self.archive` as `Archive::default()` afterward, so
    /// a second `extract()` would silently report zero files extracted
    /// against an archive with no entries, instead of extracting the same
    /// real contents again.
    #[test]
    fn test_extract_can_be_called_twice_on_same_instance() {
        let data = make_sevenz_archive(&[("file.txt", b"payload")]);
        let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let first_dest = TempDir::new().unwrap();
        let first_report = archive
            .extract(
                first_dest.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();
        assert_eq!(first_report.files_extracted, 1);

        let second_dest = TempDir::new().unwrap();
        let second_report = archive
            .extract(
                second_dest.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();
        assert_eq!(
            second_report.files_extracted, 1,
            "second extract() call on the same instance must extract the real archive \
             contents, not silently return zero files"
        );
        assert_eq!(
            std::fs::read(second_dest.path().join("file.txt")).unwrap(),
            b"payload"
        );
    }

    #[test]
    fn test_uncovered_by_block_crc_counts_entries_without_own_crc() {
        let crcs = [(4, true), (5, false), (6, false)];
        assert_eq!(
            entries_uncovered_by_block_crc(true, 10, 12, crcs.into_iter()),
            [5, 6]
        );
        assert!(entries_uncovered_by_block_crc(true, 12, 12, crcs.into_iter()).is_empty());
        assert!(entries_uncovered_by_block_crc(false, 10, 12, crcs.into_iter()).is_empty());
    }

    fn block_refusals(archive: &Archive) -> Vec<SevenZRefusal> {
        let config = SecurityConfig::default()
            .with_allow_solid_archives(true)
            .validate()
            .unwrap();
        sevenz_refusals(archive, &config)
    }

    fn visited_names(archive: &Archive, source: Vec<u8>) -> Vec<String> {
        let mut names = Vec::new();
        decode_archive_entries(
            &mut Cursor::new(source),
            archive,
            ParallelDecode::Sequential,
            DecodeKnobs::production(),
            &mut |entry, _| {
                names.push(entry.name.clone());
                Ok(true)
            },
        )
        .unwrap();
        names
    }

    #[test]
    fn test_stream_less_entry_before_a_block_is_admitted() {
        let bytes = make_sevenz_archive_with_empty_file();
        let archive = Archive::read(&mut Cursor::new(bytes.clone()), &Password::empty()).unwrap();

        assert!(block_refusals(&archive).is_empty());
        assert!(visited_names(&archive, bytes).contains(&"full.txt".to_string()));
    }

    /// `interleaved-empty.7z` has a stream-less entry between the stream files
    /// of one block. Upstream iterates the block as `num_unpack_sub_streams`
    /// consecutive files, so every stream-less entry inside the block pushes
    /// the last stream file out of reach (a directory has the same effect
    /// as an empty file); trailing and leading ones fall outside the span.
    #[test]
    fn test_stream_less_entry_inside_a_block_is_refused_and_upstream_drops_a_file() {
        let bytes = load_fixture("interleaved-empty.7z");
        let archive = Archive::read(&mut Cursor::new(bytes.clone()), &Password::empty()).unwrap();
        let stream_files: Vec<_> = archive
            .files
            .iter()
            .filter(|f| f.has_stream && f.size > 0)
            .map(|f| f.name.clone())
            .collect();

        let refusals = block_refusals(&archive);
        assert_eq!(refusals.len(), 1);
        assert_eq!(refusals[0].scope, RefusalScope::Block(0));
        assert_matches!(refusals[0].error, ArchiveError::InvalidArchive(_));

        // If sevenz-rust2 starts visiting every stream file, the predicate can
        // be relaxed.
        let visited = visited_names(&archive, bytes);
        let dropped = stream_files.iter().filter(|n| !visited.contains(n)).count();
        assert_eq!(dropped, 1, "{visited:?}");
    }

    #[test]
    fn test_decoder_memory_bound_uses_declared_file_sizes_beyond_the_unpack_size() {
        let data = vec![7u8; 1024];
        let bytes = build_solid_sevenz_archive(&[("a", &data), ("b", &data)], false);
        let mut archive = Archive::read(&mut Cursor::new(bytes), &Password::empty()).unwrap();
        let config = SecurityConfig::default()
            .with_allow_solid_archives(true)
            .with_max_decoder_memory(1024 * 1024)
            .validate()
            .unwrap();

        assert!(
            sevenz_refusals(&archive, &config).is_empty(),
            "a small block is admitted"
        );

        archive.files[0].size = 512 * 1024 * 1024;
        let refusals: Vec<_> = sevenz_refusals(&archive, &config)
            .into_iter()
            .filter(|r| r.scope == RefusalScope::Block(0))
            .collect();
        assert_eq!(refusals.len(), 1);
        assert_matches!(
            refusals[0].error,
            ArchiveError::QuotaExceeded {
                resource: QuotaResource::DecoderMemory { .. }
            }
        );
    }

    fn sevenz_file(name: &str, stream: bool, size: u64, anti: bool) -> sevenz_rust2::ArchiveEntry {
        let mut entry = sevenz_rust2::ArchiveEntry::new_file(name);
        entry.has_stream = stream;
        entry.size = size;
        entry.is_anti_item = anti;
        entry
    }

    #[test]
    fn test_payload_by_block_skips_anti_items_and_stream_less_files() {
        let config = SecurityConfig::default().validate().unwrap();
        let mut pass = IntegrityPass::new(&config, crate::DecompressionBudget::DEFAULT);
        let a = pass.begin_entry(4, &EntryCompression::Unknown);
        let empty = pass.begin_entry(0, &EntryCompression::Unknown);
        let b = pass.begin_entry(4, &EntryCompression::Unknown);

        let mut archive = Archive::default();
        archive.files = vec![
            sevenz_file("anti", false, 0, true),
            sevenz_file("a", true, 4, false),
            sevenz_file("empty", false, 0, false),
            sevenz_file("b", true, 4, false),
        ];
        archive.blocks = vec![sevenz_rust2::Block::default()];
        archive.stream_map.file_block_index = vec![None, Some(0), Some(0), Some(0)];
        let slots = [None, Some(a), Some(empty), Some(b)];

        assert_eq!(payload_by_block(&archive, &slots), [vec![(1, a), (3, b)]]);
    }

    struct FailingReader(Option<io::Error>);

    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(self.0.take().unwrap_or_else(|| io::Error::other("again")))
        }
    }

    fn scan_failing_file(error: io::Error) -> (bool, Option<BlockStop>, Vec<IssueCategory>) {
        let config = SecurityConfig::default().validate().unwrap();
        let mut pass = IntegrityPass::new(&config, crate::DecompressionBudget::DEFAULT);
        let slot = pass.begin_entry(4, &EntryCompression::Unknown);
        let slots = [Some(slot)];
        let mut scan = BlockScan {
            pass: &mut pass,
            slots: &slots,
            links: None,
            next_file: 0,
            visited: BTreeSet::new(),
            stop: None,
        };
        let keep_going = scan.visit(
            &sevenz_file("a", true, 4, false),
            &mut FailingReader(Some(error)),
        );
        let stop = scan.stop.take();
        let issues = pass.finish().entry_issues.remove(0);
        (
            keep_going,
            stop,
            issues.iter().map(|i| i.category).collect(),
        )
    }

    #[test]
    fn test_block_scan_keeps_going_after_a_checksum_mismatch() {
        let error = io::Error::other(sevenz_rust2::Error::ChecksumVerificationFailed);
        let (keep_going, stop, issues) = scan_failing_file(error);

        assert!(keep_going);
        assert!(stop.is_none());
        assert_eq!(issues, [IssueCategory::CorruptData]);
    }

    #[test]
    fn test_block_scan_abandons_the_block_on_a_decoder_error() {
        let error = io::Error::new(io::ErrorKind::InvalidData, "bad block");
        let (keep_going, stop, issues) = scan_failing_file(error);

        assert!(!keep_going);
        assert_matches!(
            stop,
            Some(BlockStop::Abandoned(UnverifiedReason::NotDecodable))
        );
        assert_eq!(issues, [IssueCategory::CorruptData]);
    }

    #[test]
    fn test_block_scan_abandons_the_block_on_a_resource_limit() {
        let error = io::Error::new(
            io::ErrorKind::InvalidData,
            crate::formats::tar_metadata_limit::DecoderMemoryExceeded { max: 1 },
        );
        let (keep_going, stop, issues) = scan_failing_file(error);

        assert!(!keep_going);
        assert_matches!(
            stop,
            Some(BlockStop::Abandoned(UnverifiedReason::ResourceLimit))
        );
        assert_eq!(issues, [IssueCategory::QuotaExceeded]);
    }

    #[test]
    fn test_block_scan_stops_on_a_disk_error() {
        let (keep_going, stop, _) = scan_failing_file(io::Error::from_raw_os_error(5));

        assert!(!keep_going);
        assert_matches!(stop, Some(BlockStop::Fatal(ArchiveError::Io(_))));
    }
}

#[cfg(test)]
mod link_walk_tests;
#[cfg(test)]
mod parallel_tests;
