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
//!   the entry's data. `extract` reads and validates it through the symlink
//!   policy, so the link is created only under `allow_symlinks`. `list` leaves
//!   it unread unless asked (`StoredTargets::Read`), and `verify` reads it only
//!   under an integrity check
//! - **FIFOs, sockets, device nodes**, an undefined Unix type, or a recorded
//!   kind (Unix mode or the Windows directory bit) that contradicts the entry's
//!   own kind are refused by `list`, `verify` and `extract`
//! - **Hardlinks**: Cannot be detected, extracted as separate files (data
//!   duplication)
//!
//! **Cost**: Link targets live in the compressed data. By default `list`
//! decodes nothing for them, `verify` decodes them only inside its integrity
//! pass (no extra decode), and `extract` decodes each block once, reading a
//! target as it creates the link. Reading targets in `list` decodes the blocks
//! that hold links, bounded by the solid policy, the admission checks and
//! the solid block limit.
//!
//! **Security Impact**: `extract` validates a symlink target against the disk
//! as it creates the link, so a refusal for the target's content (escape,
//! corrupt data, not UTF-8) is a `PartialExtraction` that leaves the entries
//! written before it inside the destination; `atomic` makes the extraction
//! all-or-nothing. A link whose target is empty or too large is refused from
//! the file table before any write. `verify` without an integrity check cannot
//! validate targets: it reports one Medium issue counting the unread links.
//!
//! # Solid Archives
//!
//! 7z supports "solid" compression where multiple files are compressed together
//! as a single block. While this provides better compression ratios, it has
//! security implications:
//!
//! - **Wasted work**: Extracting a single file requires decoding the entire
//!   solid block up to that file
//! - **Denial of service**: Malicious archives can declare very large solid
//!   blocks that exhaust CPU time and disk space
//!
//! **Default Policy**: Solid archives are **rejected** by default.
//! Use `SecurityConfig::with_allow_solid_archives(true)` to enable extraction
//! with the declared decoded size of every block bounded by
//! `SolidLimits::max_block_memory`. The limit bounds decoded volume per block,
//! not resident memory.
//!
//! # Decoder Memory and Block Layout
//!
//! `extract` and `verify` share one admission step, `sevenz_refusals`. Before
//! any byte is decoded, every block's coder memory (LZMA/LZMA2 dictionary,
//! `PPMd` memory) is checked against `max_decoder_memory`, and blocks with an
//! unknown coder, AES content encryption, or whose files do not add up
//! to the decoded size are refused. A header whose sub-stream count differs
//! from its number of streamed files (a directory that owns a sub-stream, an
//! orphan block) is refused when the archive is opened, by `list` as well.
//!
//! # Parallel LZMA2 Decoding
//!
//! A block that holds a single LZMA2 stream is split at its dictionary resets
//! into independent runs (7-Zip writes one per 4x dictionary when it
//! compresses on several threads). `extract` and `verify` decode those runs
//! ahead on worker threads, within the lookahead memory
//! [`ParallelDecode`](crate::ParallelDecode) allows (128 MiB by default), while
//! the consumer reads them back in order. A run that does not fit the budget, a
//! stream the planner cannot prove well formed, and every other block layout
//! decode sequentially, with the same bytes and error kinds (a corrupt stream
//! fails the same file either way). The decoder window stays bounded by
//! `max_decoder_memory`; the lookahead adds at most its configured budget on
//! top. sevenz-rust2's own multi-threaded reader is not used because it buffers
//! whole runs with no output bound.
//!
//! The archive header is read under a byte limit, the lower of
//! `max_decoder_memory` and 256 bytes per `max_file_count` entry plus 64 KiB
//! (with an unbounded `max_file_count`, `max_decoder_memory` alone).
//! The limit holds the raw header size, the decoded size of an encoded header
//! and that header coder's declared dictionary or model, and, because the
//! entry table sevenz-rust2 builds grows with the decoded header, it bounds
//! that table too. A refusal of the size derived from `max_file_count` is
//! `QuotaExceeded { HeaderSize }`, any other `QuotaExceeded { DecoderMemory }`.
//! The number of entries the header declares sizes the entry table, so it is
//! read before the table is built (a plain header, or an encoded header with
//! one copy, LZMA or LZMA2 coder) and held to `max_file_count` plus a small
//! allowance, as `QuotaExceeded { HeaderEntryCount }`. A header that is present
//! but whose count cannot be read (another coder, several coders, an
//! unfollowable layout, a missing start header on a file longer than an empty
//! archive) is refused as `InvalidArchive` before it is parsed. The count is
//! read in a separate pass from the parse, the same window the header size
//! probe already has; a source that changes between the two reads is outside
//! the model. Not bounded: the buffer that receives the decoded header (about
//! twice the limit at most). Unlike a block, whose window is charged as
//! `min(dictionary, 2 * unpack size)`, the header coder is charged its declared
//! dictionary, so a very small `max_decoder_memory` refuses most 7-Zip
//! archives at open (see [`crate::SecurityConfig::max_decoder_memory`]).
//!
//! # Examples
//!
//! Allow solid archives with a block limit:
//!
//! ```no_run
//! use exarch_core::SecurityConfig;
//! use exarch_core::SolidArchives;
//! use exarch_core::SolidLimits;
//! use exarch_core::non_zero;
//!
//! let limits = SolidLimits::DEFAULT.with_max_block_memory(non_zero!(512 * 1024 * 1024));
//! let config = SecurityConfig::default().with_solid_archives(SolidArchives::Allow(limits));
//! // ... extract with config
//! ```

use super::common;
use super::traits::ArchiveFormat;
use super::traits::sealed;
use crate::ArchiveError;
use crate::EntryCompression;
use crate::ExtractionOptions;
use crate::ExtractionReport;
use crate::ExtractionWarning;
use crate::Malformation;
use crate::ProgressCallback;
use crate::Result;
use crate::SecurityConfig;
use crate::SinkOptions;
use crate::VerificationOptions;
use crate::inspection::report::Finding;
use crate::inspection::report::Heuristic;
use crate::inspection::report::IssueSeverity;
use crate::inspection::report::VerificationIssue;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::Path;
use std::sync::Arc;

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
const SIGNATURE_HEADER_LEN: usize = 32;
const SIGNATURE_HEADER_SIZE: u64 = SIGNATURE_HEADER_LEN as u64;

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
/// Use `SecurityConfig::with_allow_solid_archives` to enable with block limits.
#[derive(Debug)]
pub(crate) struct SevenZArchive<R: Read + Seek> {
    source: R,
    entries: Vec<CachedEntry>,
    /// Header already parsed by [`Self::new`], borrowed by extraction, `list`
    /// and `verify` instead of re-parsing the archive (issues #492, #742), so a
    /// second call on the same instance still has a real parsed archive to
    /// work with.
    header: SevenZHeader,
    /// The policy every operation of the handle enforces.
    config: Arc<SecurityConfig>,
}

impl<R: Read + Seek> SevenZArchive<R> {
    /// Creates a 7z archive reader that enforces `config`.
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
    pub(crate) fn new(mut source: R, config: &SecurityConfig) -> Result<Self> {
        let header = read_sevenz_header(&mut source, HeaderLimit::from_config(config))?;

        let source_len = source.seek(SeekFrom::End(0)).map_err(ArchiveError::Io)?;
        let compression = sevenz_entry_compression(&header, source_len)?;
        let entries: Vec<CachedEntry> = header
            .files()
            .iter()
            .zip(compression)
            .map(|(e, compression)| CachedEntry {
                name: e.name.clone(),
                size: e.size,
                class: SevenZClass::of(e),
                compression,
            })
            .collect();

        source.rewind().map_err(ArchiveError::Io)?;

        Ok(Self {
            source,
            entries,
            header,
            config: Arc::new(config.clone()),
        })
    }
}

impl<R: Read + Seek> SevenZArchive<R> {
    fn anti_item_count(&self) -> u64 {
        let count = self
            .entries
            .iter()
            .filter(|entry| entry.class == SevenZClass::AntiItem)
            .count();
        u64::try_from(count).unwrap_or(u64::MAX)
    }
}

/// Appends one warning for the anti-items `extract` skipped.
///
/// A no-op when `count` is zero.
fn push_anti_item_warning(report: &mut ExtractionReport, count: u64) {
    if count > 0 {
        report.add_warning(ExtractionWarning::AntiItemsSkipped { count });
    }
}

/// The informational finding `verify` reports for skipped anti-items, or
/// `None` when the archive has none.
fn anti_item_issue(count: u64) -> Option<VerificationIssue> {
    (count > 0).then(|| {
        VerificationIssue::new(
            IssueSeverity::Info,
            Finding::Heuristic(Heuristic::AntiItemsSkipped { count }),
        )
    })
}

impl<R: Read + Seek> sealed::Sealed for SevenZArchive<R> {}

impl<R: Read + Seek> ArchiveFormat for SevenZArchive<R> {
    fn extract(
        mut self,
        output_dir: &Path,
        options: &ExtractionOptions,
        progress: &mut dyn ProgressCallback,
    ) -> Result<ExtractionReport> {
        let config = Arc::clone(&self.config);
        self.admit(&config)?.extract_with(
            |config| SevenZHostTarget::create(output_dir, config),
            SinkOptions::existing_files_of(options),
            progress,
        )
    }

    #[cfg(test)]
    fn list(mut self) -> Result<crate::inspection::ArchiveManifest> {
        use crate::inspection::list::ListPass;
        use crate::inspection::list::list_sevenz_parsed;
        let config = Arc::clone(&self.config);
        list_sevenz_parsed(
            &self.header,
            &mut self.source,
            &config,
            &mut ListPass::strict(),
        )
    }

    #[cfg(test)]
    fn verify(
        mut self,
        options: VerificationOptions,
    ) -> Result<crate::inspection::VerificationReport> {
        let config = Arc::clone(&self.config);
        self.verify_with_progress(&config, options, &mut crate::NoopProgress)
    }
}

impl<R: Read + Seek> SevenZArchive<R> {
    /// Verifies the archive, reporting each scanned entry to `progress`.
    pub(crate) fn verify_with_progress(
        &mut self,
        config: &SecurityConfig,
        options: VerificationOptions,
        progress: &mut dyn ProgressCallback,
    ) -> Result<crate::inspection::VerificationReport> {
        use crate::inspection::list::list_sevenz_parsed;
        use crate::inspection::report::ArchiveStructure;
        use crate::inspection::verify::list_for_verify;
        use crate::inspection::verify::verify_manifest_with_structure;

        let mut issues = refusal_issues(&sevenz_refusals(&self.header, config));
        issues.extend(anti_item_issue(self.anti_item_count()));
        let listed = list_for_verify(config, options, progress, |listing| {
            list_sevenz_parsed(&self.header, &mut self.source, config, listing)
        })?;
        let structure = ArchiveStructure::of_manifest(&listed.manifest).with_refusals(&issues);
        Ok(verify_manifest_with_structure(
            &listed.manifest,
            config,
            &structure,
            listed.integrity,
        ))
    }
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
                crate::IoContext::new("failed to open a 7z file", format!("{path}: {io_err}")),
            )),
            other => Self::from(Malformation::SevenZLibraryError {
                detail: other.to_string().into(),
            }),
        }
    }
}

#[cfg(test)]
mod link_walk_tests;

#[cfg(test)]
mod parallel_tests;

#[cfg(test)]
mod sequential_crc_tests;

pub(crate) use admit::iter_sevenz_refusals;
pub(crate) use admit::refusal_issues;
pub(crate) use admit::sevenz_entry_compression;
pub(crate) use admit::sevenz_refusals;
pub(crate) use classify::SevenZClass;
pub(crate) use classify::SevenZKind;
pub(crate) use header::HeaderLimit;
pub(crate) use header::SEVENZ_MAGIC;
pub(crate) use header::SevenZHeader;
pub(crate) use header::read_sevenz_header;
use host::SevenZHostTarget;
pub(crate) use links::LinkCapture;
pub(crate) use links::LinkOutcome;
pub(crate) use links::LinkTable;
pub(crate) use links::StoredLinkTarget;
pub(crate) use links::deliver_undecoded_links;
pub(crate) use links::walk_sevenz_links;
pub(crate) use verify::is_decode_announced;
pub(crate) use verify::verify_sevenz_blocks;

mod admit;
mod classify;
mod decode;
mod extract;
mod header;
mod header_probe;
mod host;
mod links;
mod lzma2;
mod sink;
mod verify;
mod write;

#[cfg(test)]
mod tests;
