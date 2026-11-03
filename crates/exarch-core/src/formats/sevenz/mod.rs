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
//! `max_solid_block_memory`.
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
//! unknown coder, AES content encryption, or whose files do not add up
//! to the decoded size (an orphan block, or sub-streams shifted by an
//! entry without data) are refused.
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

use super::common;
use super::traits::ArchiveFormat;
use crate::ArchiveError;
use crate::EntryCompression;
use crate::ExtractionOptions;
use crate::ExtractionReport;
use crate::ProgressCallback;
use crate::Result;
use crate::SecurityConfig;
use crate::SinkOptions;
use crate::VerificationOptions;
use crate::config::Validated;
use crate::inspection::report::IssueCategory;
use crate::inspection::report::IssueSeverity;
use crate::inspection::report::VerificationIssue;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::Path;

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
    /// Header already parsed by [`Self::new`], borrowed by extraction, `list`
    /// and `verify` instead of re-parsing the archive (issues #492, #742), so a
    /// second call on the same instance still has a real parsed archive to
    /// work with.
    header: SevenZHeader,
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
        let header = read_sevenz_header(&mut source)?;

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
        self.admit(config)?.extract_with(
            |config| SevenZHostTarget::create(output_dir, config),
            SinkOptions::duplicates_of(options),
            progress,
        )
    }

    fn list(
        &mut self,
        config: &SecurityConfig<Validated>,
    ) -> Result<crate::inspection::ArchiveManifest> {
        use crate::inspection::list::ListPass;
        use crate::inspection::list::list_sevenz_parsed;
        list_sevenz_parsed(
            &self.header,
            &mut self.source,
            config,
            &mut ListPass::strict(),
        )
    }

    fn verify(
        &mut self,
        config: &SecurityConfig<Validated>,
        options: &VerificationOptions,
    ) -> Result<crate::inspection::VerificationReport> {
        self.verify_with_progress(config, *options, &mut crate::NoopProgress)
    }

    fn format_name(&self) -> &'static str {
        "7z"
    }
}

impl<R: Read + Seek> SevenZArchive<R> {
    /// Verifies the archive, reporting each scanned entry to `progress`.
    pub(crate) fn verify_with_progress(
        &mut self,
        config: &SecurityConfig<Validated>,
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
                format!("{path}: {io_err}"),
            )),
            other => Self::InvalidArchive(format!("7z error: {other}")),
        }
    }
}

#[cfg(test)]
mod link_walk_tests;

#[cfg(test)]
mod parallel_tests;

pub(crate) use admit::iter_sevenz_refusals;
pub(crate) use admit::refusal_issues;
pub(crate) use admit::sevenz_entry_compression;
pub(crate) use admit::sevenz_refusals;
pub(crate) use classify::SevenZClass;
pub(crate) use classify::SevenZKind;
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
mod host;
mod links;
mod lzma2;
mod sink;
mod verify;
mod write;

#[cfg(test)]
mod tests;
