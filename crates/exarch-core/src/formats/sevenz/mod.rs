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
//! unknown coder, AES content encryption, a stream-less entry between their
//! stream files, or a stream count that disagrees with the files mapped to
//! them (an orphan block) are refused.
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

use classify::abort_with;
use classify::reparse_point_refusal;
use decode::decode_archive_entries;
use links::read_sevenz_link_target;
use write::lstat_dest;
use write::refuse_undecoded_target;
use write::symlink_at_dest_error;
use write::write_file_direct;
use write::write_file_with_permit;

use std::io;

use std::io::ErrorKind;

use std::io::Read;

use std::io::Seek;

use std::io::SeekFrom;

use std::path::Path;

use sevenz_rust2::Archive;

use sevenz_rust2::Password;

use crate::ArchiveError;

use crate::EntryCompression;

use crate::ExtractionOptions;

use crate::ExtractionReport;

use crate::ProgressCallback;

use crate::Result;

use crate::SecurityConfig;

use crate::VerificationOptions;

use crate::config::Validated;

use crate::copy::CopyBuffer;

use crate::inspection::report::IssueCategory;

use crate::inspection::report::IssueSeverity;

use crate::inspection::report::VerificationIssue;

use crate::security::EntryValidator;

use crate::security::validator::EntryPath;

use crate::security::validator::ValidatedEntryType;

use crate::security::zipbomb::validate_entry_compression;

use crate::types::DestDir;

use crate::types::EntryType;

use crate::types::safe_symlink::require_symlinks_allowed;

use super::common;

use lzma2::DecodeKnobs;

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

impl<R: Read + Seek> SevenZArchive<R> {
    fn anti_item_count(&self) -> u64 {
        let count = self
            .entries
            .iter()
            .filter(|entry| entry.class == SevenZClass::AntiItem)
            .count();
        u64::try_from(count).unwrap_or(u64::MAX)
    }

    /// Reads the target of the symlink entry from its own stream and validates
    /// the entry against the disk as it is now. This is the only place a
    /// target's content is validated, so a refusal leaves the entries extracted
    /// before it in place, as in TAR and ZIP.
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
                    refuse_undecoded_target(&safe_path, &self.archive.files[index], &dest, config)?;
                    prevalidator.reserve_symlink(entry.size)?;
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
mod link_walk_tests;

#[cfg(test)]
mod parallel_tests;

pub(crate) use admit::iter_sevenz_refusals;
pub(crate) use admit::refusal_issues;
pub(crate) use admit::sevenz_entry_compression;
pub(crate) use admit::sevenz_refusals;
pub(crate) use classify::SevenZClass;
pub(crate) use classify::SevenZKind;
pub(crate) use links::LinkCapture;
pub(crate) use links::LinkOutcome;
pub(crate) use links::LinkTable;
pub(crate) use links::StoredLinkTarget;
pub(crate) use links::deliver_undecoded_links;
pub(crate) use links::walk_sevenz_links;
pub(crate) use verify::verify_sevenz_blocks;

mod admit;
mod classify;
mod decode;
mod links;
mod lzma2;
mod verify;
mod write;

#[cfg(test)]
mod tests;
