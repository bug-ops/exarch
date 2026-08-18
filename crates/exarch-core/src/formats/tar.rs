//! TAR archive format extraction.
//!
//! This module provides secure extraction of TAR archives with comprehensive
//! security validation. Supported formats:
//!
//! - **ustar** (POSIX.1-1988): Standard Unix tar format
//! - **pax** (POSIX.1-2001): Extended header format for long paths/metadata
//! - **gnu** (GNU tar): GNU extensions for sparse files and incremental backups
//!
//! # Format Detection
//!
//! The TAR format is auto-detected based on header magic bytes. No explicit
//! format selection is required.
//!
//! # Compression Support
//!
//! Transparent decompression is supported via:
//!
//! - **gzip** (.tar.gz, .tgz): Via `flate2` crate
//! - **bzip2** (.tar.bz2, .tbz2): Via `bzip2` crate
//! - **xz** (.tar.xz, .txz): Via `xz2` crate
//! - **zstd** (.tar.zst, .tzst): Via `zstd` crate
//!
//! # Security Features
//!
//! All entries are validated through the security layer:
//!
//! - Path traversal prevention (rejects `../`, absolute paths)
//! - Quota enforcement (file size, count, total size)
//! - Symlink escape detection (symlinks must point within extraction directory)
//! - Hardlink escape detection (hardlink targets must be within extraction
//!   directory)
//! - Permission sanitization (strips setuid/setgid bits)
//! - Device file rejection (char, block devices not supported)
//! - FIFO rejection (named pipes not supported)
//!
//! # Entry Type Support
//!
//! | Entry Type | Supported | Notes |
//! |------------|-----------|-------|
//! | Regular files | ✅ Yes | Full support with streaming |
//! | Directories | ✅ Yes | Created recursively |
//! | Symlinks | ✅ Yes | Unix only, requires `config.allowed.symlinks = true` |
//! | Hardlinks | ✅ Yes | Two-pass extraction, requires `config.allowed.hardlinks = true` |
//! | Continuous | ✅ Yes | Treated as regular file |
//! | GNU sparse | ✅ Yes | Treated as regular file |
//! | PAX headers (`XHeader`, `XGlobalHeader`) | Skipped | Format-internal metadata |
//! | GNU metadata (`GNULongName`, `GNULongLink`) | Skipped | Format-internal metadata |
//! | Char devices | ❌ No | Rejected with `UnsupportedFeature` error |
//! | Block devices | ❌ No | Rejected with `UnsupportedFeature` error |
//! | FIFOs | ❌ No | Rejected with `UnsupportedFeature` error |
//!
//! # Performance Characteristics
//!
//! - **Streaming**: Processes entries one at a time without buffering entire
//!   archive
//! - **Memory usage**: O(1) for archive processing, O(n) for hardlink tracking
//! - **Two-pass extraction**: Files/directories first, hardlinks second
//!
//! # Examples
//!
//! Basic extraction:
//!
//! ```no_run
//! use exarch_core::ExtractionOptions;
//! use exarch_core::SecurityConfig;
//! use exarch_core::formats::TarArchive;
//! use exarch_core::formats::traits::ArchiveFormat;
//! use std::fs::File;
//! use std::path::Path;
//!
//! let file = File::open("archive.tar")?;
//! let mut archive = TarArchive::new(file);
//! let config = SecurityConfig::default().validate()?;
//! let report = archive.extract(
//!     Path::new("/output"),
//!     &config,
//!     &ExtractionOptions::default(),
//!     &mut exarch_core::NoopProgress,
//! )?;
//! println!("Extracted {} files", report.files_extracted);
//! # Ok::<(), exarch_core::ArchiveError>(())
//! ```
//!
//! Gzip-compressed TAR:
//!
//! ```no_run
//! use exarch_core::ExtractionOptions;
//! use exarch_core::SecurityConfig;
//! use exarch_core::formats::TarArchive;
//! use exarch_core::formats::traits::ArchiveFormat;
//! use flate2::read::GzDecoder;
//! use std::fs::File;
//! use std::path::Path;
//!
//! let file = File::open("archive.tar.gz")?;
//! let decoder = GzDecoder::new(file);
//! let mut archive = TarArchive::new(decoder);
//! let config = SecurityConfig::default().validate()?;
//! let report = archive.extract(
//!     Path::new("/output"),
//!     &config,
//!     &ExtractionOptions::default(),
//!     &mut exarch_core::NoopProgress,
//! )?;
//! # Ok::<(), exarch_core::ArchiveError>(())
//! ```

use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::path::Path;
use std::time::Instant;

use smallvec::SmallVec;
use tar::Archive;

use crate::ArchiveError;
use crate::ExtractionOptions;
use crate::ExtractionReport;
use crate::ProgressCallback;
use crate::Result;
use crate::SecurityConfig;
use crate::config::Validated;
use crate::copy::CopyBuffer;
use crate::security::permissions::SanitizedMode;
use crate::security::quota::QuotaPermit;
use crate::security::validator::EntryValidator;
use crate::security::validator::ValidatedEntryType;
use crate::types::DestDir;
use crate::types::EntryType;
use crate::types::SafePath;
use crate::types::safe_symlink::resolve_through_symlinks;

use super::common;
use super::tar_metadata_limit::budget_violation;
use super::tar_metadata_limit::budgeted_reader;
use super::tar_metadata_limit::budgeted_tar_entries;
use super::traits::ArchiveFormat;

/// TAR archive handler with streaming extraction.
///
/// Supports ustar, pax, and gnu TAR formats with automatic detection.
/// The archive is processed in a streaming fashion to minimize memory usage.
///
/// # Type Parameters
///
/// - `R`: Reader type that must implement `Read`
///
/// # Examples
///
/// ```no_run
/// use exarch_core::ExtractionOptions;
/// use exarch_core::SecurityConfig;
/// use exarch_core::formats::TarArchive;
/// use exarch_core::formats::traits::ArchiveFormat;
/// use std::fs::File;
/// use std::path::Path;
///
/// let file = File::open("archive.tar")?;
/// let mut archive = TarArchive::new(file);
/// let config = SecurityConfig::default().validate()?;
/// let report = archive.extract(
///     Path::new("/output"),
///     &config,
///     &ExtractionOptions::default(),
///     &mut exarch_core::NoopProgress,
/// )?;
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
pub struct TarArchive<R: Read> {
    /// Raw underlying reader; `None` after `extract()`/`list()` consumes it.
    ///
    /// Wrapped in a metadata-size-limiting reader (using the config supplied
    /// to `extract()`/`list()`) and only then handed to `tar::Archive`, so the
    /// cap is applied fresh with whatever `SecurityConfig` each call uses.
    inner: Option<R>,
}

impl<R: Read> TarArchive<R> {
    /// Creates a new TAR archive handler from a reader.
    ///
    /// The reader will be consumed during extraction. For file-based
    /// archives, wrap in `BufReader` for optimal performance.
    ///
    /// # Performance Notes
    ///
    /// - Input: Wrap file readers in `BufReader::new()` for 10x faster reads
    /// - Output: File writes use `BufWriter` internally for optimal throughput
    /// - Memory: O(1) for archive processing, O(n) for hardlink tracking
    /// - Typical throughput: 100-500 MB/s on modern SSDs
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use exarch_core::formats::TarArchive;
    /// use std::fs::File;
    /// use std::io::BufReader;
    ///
    /// let file = File::open("archive.tar")?;
    /// let reader = BufReader::new(file);
    /// let archive = TarArchive::new(reader);
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn new(reader: R) -> Self {
        Self {
            inner: Some(reader),
        }
    }

    /// Processes a single TAR entry.
    fn process_entry<ER: Read>(
        entry: &mut tar::Entry<'_, ER>,
        ctx: &mut ExtractionContext<'_, '_>,
    ) -> Result<Option<HardlinkInfo>> {
        // Skip TAR metadata entries (PAX headers, GNU long names/links, sparse)
        if TarEntryAdapter::is_metadata_entry(entry) {
            return Ok(None);
        }

        let path = entry
            .path()
            .map_err(|e| ArchiveError::InvalidArchive(format!("invalid path: {e}")))?
            .into_owned();

        let entry_type = TarEntryAdapter::to_entry_type(entry)?;
        let size = TarEntryAdapter::get_uncompressed_size(entry);
        let mode = entry.header().mode().ok();

        if matches!(entry_type, EntryType::File)
            && !common::check_extension_allowed(
                &path,
                ctx.config,
                ctx.report,
                ctx.disallowed_extension_skips,
            )
        {
            return Ok(None);
        }

        let validated = ctx.validator.validate_entry(
            &path,
            &entry_type,
            size,
            None,
            mode,
            Some(ctx.dir_cache),
        )?;

        // `into_parts()` consumes `validated` so the File arm can move its
        // QuotaPermit by value into extract_file (mirrors 7z's
        // process_entry_inner, issue #445), rather than only observing it
        // through entry_type()'s shared reference.
        match validated.into_parts() {
            (safe_path, ValidatedEntryType::File(permit), mode) => {
                Self::extract_file(entry, &safe_path, mode, permit, ctx)?;
                Ok(None)
            }

            (safe_path, ValidatedEntryType::Directory, _) => {
                common::create_directory(&safe_path, ctx.dest, ctx.report, ctx.dir_cache)?;
                Ok(None)
            }

            (_, ValidatedEntryType::Symlink(safe_symlink), _) => {
                common::create_symlink(
                    &safe_symlink,
                    ctx.dest,
                    ctx.report,
                    ctx.dir_cache,
                    ctx.skip_duplicates,
                    ctx.duplicate_skips,
                )?;
                Ok(None)
            }

            (safe_path, ValidatedEntryType::Hardlink { target }, _) => {
                // Two-pass: defer hardlink creation until target files exist
                Ok(Some(HardlinkInfo {
                    link_path: safe_path,
                    target_path: target,
                }))
            }
        }
    }

    /// Extracts a regular file to disk.
    fn extract_file<ER: Read>(
        entry: &mut tar::Entry<'_, ER>,
        safe_path: &SafePath,
        mode: Option<SanitizedMode>,
        permit: QuotaPermit,
        ctx: &mut ExtractionContext<'_, '_>,
    ) -> Result<()> {
        let size = Some(entry.size());
        common::extract_file_with_permit(
            entry,
            safe_path,
            mode,
            permit,
            ctx.dest,
            ctx.report,
            size,
            ctx.copy_buffer,
            ctx.dir_cache,
            ctx.skip_duplicates,
            ctx.duplicate_skips,
            ctx.progress,
        )
    }

    /// Creates a hardlink in the second pass by copying content.
    ///
    /// Uses a content copy instead of `fs::hard_link` to avoid shared-inode
    /// corruption: a real OS hardlink would allow a subsequent write to
    /// `link_path` to silently overwrite `target_path` (GHSA-2367-c296-3mp2
    /// variant, issue #130).
    ///
    /// # Security - Symlink-at-Destination Rejection (issue #467)
    ///
    /// `Path::exists()` returns `false` for a dangling symlink, so a
    /// pre-planted symlink at `link_path` used to bypass the old
    /// existence-based duplicate check, and the subsequent `fs::copy`
    /// followed it, writing archive content outside the extraction root.
    /// The destination is now opened via `common::create_file_with_mode`
    /// (mode `None`, since permissions are copied from the target's bytes
    /// afterward, not set at creation) with `create_new = true`, which
    /// atomically fails with `ErrorKind::AlreadyExists` for any pre-existing
    /// path at `link_path` — symlink (dangling or not), regular file, or
    /// directory — folding the duplicate check into the `open()` call
    /// itself instead of a separate, bypassable `exists()` probe. This
    /// reuses the same `O_EXCL`+`O_NOFOLLOW` (Unix) discipline as the
    /// normal-file write path (issue #459) for consistency, though
    /// `create_new`'s `O_EXCL` alone already refuses any pre-existing path.
    ///
    /// # Security - Target Read TOCTOU and Quota TOCTOU (issue #467)
    ///
    /// Hardlinks are validated in two passes: `EntryValidator::validate_entry`
    /// (via `HardlinkTracker::validate_hardlink`) resolves `target` through
    /// any on-disk symlinks and checks containment in pass one, but this
    /// function — pass two — runs later, after every entry in the archive has
    /// been validated and every non-hardlink entry extracted. Nothing
    /// re-validates `target_path` in between. A plain path-based `File::open`
    /// (or `std::fs::metadata`, as this function used to do to size the quota
    /// reservation) would silently follow whatever is at `target_path` by the
    /// time pass two runs — which, given an attacker-writable destination
    /// directory, may not be what pass one validated at all (the target
    /// swapped for a symlink escaping `dest` in between the two passes).
    /// Separately, sizing the quota reservation from a path-based `stat` and
    /// then copying from a *different*, separately-opened handle left its own
    /// TOCTOU window: swapping `target_path` between the two operations could
    /// charge the quota for N bytes while actually copying an unbounded
    /// amount.
    ///
    /// Both are narrowed the same way: [`common::open_no_follow`] opens
    /// `target_path` once, refusing to follow a symlink (Unix, via
    /// `O_NOFOLLOW`) rather than a separate `stat`-then-`open`; the quota
    /// reservation is sized from that same open handle's `fstat`, and the
    /// copy reads from that same handle — never re-touching the path
    /// afterward. A symlink at `target_path` is not automatically rejected,
    /// though: it is a legitimate, common archive shape for a hardlink's
    /// target to itself be a symlink created earlier in the *same*
    /// extraction (already pass-one-validated). On `ErrorKind::FilesystemLoop`
    /// from `open_no_follow`, [`resolve_through_symlinks`] re-runs the exact
    /// containment check pass one already trusts, against the *current*
    /// on-disk state; if it still resolves inside `dest`, the resolved
    /// (symlink-free, since `canonicalize` dereferences fully) path is opened
    /// instead. This narrows the TOCTOU window from "the entire gap between
    /// pass one and pass two" down to "between this re-check and the open" —
    /// consistent with the check-then-act discipline the rest of the pipeline
    /// already accepts elsewhere (e.g. `DirCache`'s documented TOCTOU). If the
    /// re-resolution instead lands outside `dest`, that is a genuine escape
    /// attempt and is reported as such, not as a raw OS errno.
    fn create_hardlink(info: &HardlinkInfo, ctx: &mut ExtractionContext<'_, '_>) -> Result<()> {
        let link_path = ctx.dest.join(&info.link_path);
        let target_path = ctx.dest.join(&info.target_path);

        if !target_path.exists() {
            return Err(ArchiveError::InvalidArchive(format!(
                "hardlink target does not exist: {}",
                info.target_path.as_path().display()
            )));
        }

        // Create parent directories using cache
        ctx.dir_cache.ensure_parent_dir(&link_path)?;

        let link_file = match common::create_file_with_mode(&link_path, None, true) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if ctx.skip_duplicates {
                    common::checked_increment_files_skipped(ctx.report)?;
                    *ctx.hardlink_duplicate_skips = ctx.hardlink_duplicate_skips.saturating_add(1);
                    return Ok(());
                }
                return Err(ArchiveError::InvalidArchive(format!(
                    "duplicate entry: {}",
                    info.link_path.as_path().display()
                )));
            }
            Err(e) => return Err(ArchiveError::Io(e)),
        };
        let cleanup_guard = common::TempFileGuard::new(link_path);

        // Opened once, refusing to follow a symlink at `target_path`; the
        // quota reservation below and the copy further down both operate on
        // this same handle instead of re-touching the path (issue #467).
        let target_file = match common::open_no_follow(&target_path) {
            Ok(file) => file,
            Err(e) if common::is_filesystem_loop_error(&e) => {
                // `target_path`'s final component is a symlink. Re-run pass
                // one's own containment check against the current on-disk
                // state; a symlink created by an earlier entry in this same
                // extraction resolves safely inside `dest` and is opened at
                // its resolved (symlink-free) location, while a genuine
                // escape attempt is rejected as HardlinkEscape rather than
                // surfacing as a raw ELOOP.
                let resolved = resolve_through_symlinks(
                    ctx.dest.as_path(),
                    info.target_path.as_path(),
                    ctx.dest.as_path(),
                    info.link_path.as_path(),
                )
                .map_err(|_| ArchiveError::HardlinkEscape {
                    path: info.link_path.as_path().to_path_buf(),
                })?;
                common::open_no_follow(&resolved)?
            }
            Err(e) => return Err(ArchiveError::Io(e)),
        };

        // Every hardlink copies the target's real bytes to a new inode, so it
        // must be charged against the same quota tracker as regular files
        // (issue #426): otherwise N hardlinks to one small file extract N
        // full copies with no size or count enforcement. Reserved after the
        // duplicate-check above (mirroring `extract_file_generic`) so a
        // `skip_duplicates=true` archive is not spuriously charged for an
        // entry that is ultimately never copied. The permit is consumed by
        // value below, so this reservation cannot be spent twice.
        let target_size = target_file.metadata()?.len();
        let permit = ctx.validator.reserve_hardlink(target_size)?;

        // Copy content between the two handles opened above. Any subsequent
        // write to `link_path` cannot corrupt `target_path` because they are
        // separate files.
        let bytes_copied = common::copy_file_content_with_permit(target_file, link_file, permit)?;
        cleanup_guard.persist();

        ctx.report.files_extracted =
            ctx.report
                .files_extracted
                .checked_add(1)
                .ok_or(ArchiveError::QuotaExceeded {
                    resource: crate::QuotaResource::IntegerOverflow,
                })?;
        ctx.report.bytes_written = ctx.report.bytes_written.checked_add(bytes_copied).ok_or(
            ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::IntegerOverflow,
            },
        )?;
        ctx.progress.on_bytes_written(bytes_copied);

        Ok(())
    }
}

impl<R: Read> ArchiveFormat for TarArchive<R> {
    /// Extracts the archive contents to `output_dir`.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidArchive`] if [`list`](Self::list) was
    /// called on this instance before `extract`. Because TAR is a forward-only
    /// stream, `list` consumes the internal reader; calling `extract` afterward
    /// is not possible. Open a fresh [`TarArchive`] instance instead.
    fn extract(
        &mut self,
        output_dir: &Path,
        config: &SecurityConfig<Validated>,
        options: &ExtractionOptions,
        progress: &mut dyn ProgressCallback,
    ) -> Result<ExtractionReport> {
        let start = Instant::now();
        let skip_duplicates = options.skip_duplicates;

        let dest = DestDir::new_or_create(output_dir.to_path_buf())?;

        let mut validator = EntryValidator::new(config, &dest);

        let mut report = ExtractionReport::new();

        let mut hardlinks: SmallVec<[HardlinkInfo; 8]> = SmallVec::new();

        let mut copy_buffer = CopyBuffer::new();

        let mut dir_cache = common::DirCache::new();

        let mut current_entry: usize = 0;

        // Aggregated once, at every exit point, into a single warning per
        // counter instead of one warning per skipped entry — keeps
        // `report.warnings`'s growth independent of how many duplicate
        // entries an archive contains (issue #490). Hardlinks are counted
        // separately since they are format-specific to TAR (ZIP has no
        // hardlink entry type) and go through `create_hardlink` directly
        // rather than `common::extract_file_with_permit`/`create_symlink`.
        let mut duplicate_skips: u64 = 0;
        let mut hardlink_duplicate_skips: u64 = 0;
        // Same aggregation, for entries rejected by the extension allowlist
        // (issue #495).
        let mut disallowed_extension_skips: u64 = 0;

        let reader = self.inner.take().ok_or_else(|| {
            ArchiveError::InvalidArchive("archive reader already consumed by list()".into())
        })?;
        let (budgeted, budget) = budgeted_reader(reader, config.max_tar_metadata_bytes);
        let mut inner_archive = Archive::new(budgeted);
        let mut entries = budgeted_tar_entries(&mut inner_archive, budget)
            .map_err(|e| ArchiveError::InvalidArchive(format!("failed to read entries: {e}")))?;

        let mut ctx = ExtractionContext {
            validator: &mut validator,
            dest: &dest,
            report: &mut report,
            copy_buffer: &mut copy_buffer,
            dir_cache: &mut dir_cache,
            skip_duplicates,
            duplicate_skips: &mut duplicate_skips,
            hardlink_duplicate_skips: &mut hardlink_duplicate_skips,
            disallowed_extension_skips: &mut disallowed_extension_skips,
            config,
            progress,
        };

        while let Some(entry_result) = entries.next_entry() {
            let mut guard = entry_result.map_err(|e| {
                let raw = budget_violation(&e).unwrap_or_else(|| {
                    ArchiveError::InvalidArchive(format!("failed to read entry: {e}"))
                });
                push_duplicate_skip_warnings(
                    ctx.report,
                    *ctx.duplicate_skips,
                    *ctx.hardlink_duplicate_skips,
                    *ctx.disallowed_extension_skips,
                );
                ArchiveError::partial_or(std::mem::take(ctx.report), raw)
            })?;

            // TAR is streaming: total entry count is not known upfront, so pass 0.
            let entry_path = guard
                .path()
                .ok()
                .map(std::borrow::Cow::into_owned)
                .unwrap_or_default();
            current_entry = current_entry.saturating_add(1);
            ctx.progress.on_entry_start(&entry_path, 0, current_entry);

            // INVARIANT: every branch below must call on_entry_complete exactly once.
            match Self::process_entry(&mut guard, &mut ctx) {
                Ok(Some(hardlink_info)) => {
                    ctx.progress.on_entry_complete(&entry_path);
                    hardlinks.push(hardlink_info);
                }
                Ok(None) => {
                    ctx.progress.on_entry_complete(&entry_path);
                }
                Err(e) => {
                    ctx.progress.on_entry_complete(&entry_path);
                    // Abandoning: no further `next_entry()` calls follow, so
                    // the guard's usual bounded drain is pointless I/O, not a
                    // correctness requirement (see `TarEntryGuard::abandon`).
                    guard.abandon();
                    push_duplicate_skip_warnings(
                        ctx.report,
                        *ctx.duplicate_skips,
                        *ctx.hardlink_duplicate_skips,
                        *ctx.disallowed_extension_skips,
                    );
                    return Err(ArchiveError::partial_or(std::mem::take(ctx.report), e));
                }
            }
        }

        // Two-pass extraction: create hardlinks after all target files exist
        for hardlink_info in &hardlinks {
            if let Err(e) = Self::create_hardlink(hardlink_info, &mut ctx) {
                push_duplicate_skip_warnings(
                    ctx.report,
                    *ctx.duplicate_skips,
                    *ctx.hardlink_duplicate_skips,
                    *ctx.disallowed_extension_skips,
                );
                return Err(ArchiveError::partial_or(std::mem::take(ctx.report), e));
            }
        }

        push_duplicate_skip_warnings(
            ctx.report,
            *ctx.duplicate_skips,
            *ctx.hardlink_duplicate_skips,
            *ctx.disallowed_extension_skips,
        );
        ctx.progress.on_complete();
        report.duration = start.elapsed();

        Ok(report)
    }

    /// Lists the entries in the archive without extracting them.
    ///
    /// # Reader consumption
    ///
    /// TAR is a forward-only stream format. This method consumes the internal
    /// reader via `self.inner.take()`. After `list()` returns, the reader is
    /// gone and any subsequent call to [`extract`](Self::extract) on **the same
    /// instance** will return `Err(ArchiveError::InvalidArchive(...))`.
    ///
    /// To extract after listing, open a **new** [`TarArchive`] from the
    /// original source:
    ///
    /// ```ignore
    /// // Correct: two independent instances
    /// let mut archive1 = TarArchive::open(&path)?;
    /// let manifest = archive1.list(&config)?;
    ///
    /// let mut archive2 = TarArchive::open(&path)?;
    /// let report = archive2.extract(&dest, &config, &options, &mut NoopProgress)?;
    /// ```
    fn list(
        &mut self,
        config: &SecurityConfig<Validated>,
    ) -> Result<crate::inspection::ArchiveManifest> {
        use crate::formats::detect::ArchiveType;
        use crate::inspection::list::list_tar_reader;

        // Consume the inner reader — TAR readers are forward-only streams.
        // After list() returns, extract() will return an error if called.
        let reader = self.inner.take().ok_or_else(|| {
            crate::ArchiveError::InvalidArchive("archive reader already consumed by list()".into())
        })?;
        let (budgeted, budget) = budgeted_reader(reader, config.max_tar_metadata_bytes);
        list_tar_reader(budgeted, budget, ArchiveType::Tar, config)
    }

    fn verify(
        &mut self,
        config: &SecurityConfig<Validated>,
    ) -> Result<crate::inspection::VerificationReport> {
        let manifest = self.list(&crate::inspection::verify::listing_config_for_verify(
            config,
        ))?;
        crate::inspection::verify::verify_manifest(&manifest, config)
    }

    fn format_name(&self) -> &'static str {
        "tar"
    }
}

struct ExtractionContext<'a, 'v> {
    validator: &'a mut EntryValidator<'v>,
    dest: &'a DestDir,
    report: &'a mut ExtractionReport,
    copy_buffer: &'a mut CopyBuffer,
    dir_cache: &'a mut common::DirCache,
    skip_duplicates: bool,
    /// Count of file/symlink entries skipped as pre-existing duplicates,
    /// threaded through `common::extract_file_with_permit` and
    /// `common::create_symlink`. Aggregated into a single warning by
    /// [`push_duplicate_skip_warnings`] instead of one warning per entry
    /// (issue #490).
    duplicate_skips: &'a mut u64,
    /// Count of hardlinks skipped as pre-existing duplicates in
    /// [`TarArchive::create_hardlink`]. Tracked separately from
    /// `duplicate_skips` because hardlinks are TAR-specific (ZIP has no
    /// hardlink entry type) and are not routed through `common.rs`.
    hardlink_duplicate_skips: &'a mut u64,
    /// Count of file entries skipped by `common::check_extension_allowed`
    /// because their extension is not in the allowlist. Aggregated into a
    /// single warning by [`push_duplicate_skip_warnings`] instead of one
    /// warning per entry (issue #495).
    disallowed_extension_skips: &'a mut u64,
    config: &'v SecurityConfig<Validated>,
    progress: &'a mut dyn ProgressCallback,
}

/// Appends aggregated duplicate-skip and disallowed-extension warnings to
/// `report`, one entry per non-zero counter, mirroring 7z's single
/// end-of-extraction warning (`SevenZArchive::extract_with_callback`)
/// instead of one warning per skipped entry (issues #490, #495).
fn push_duplicate_skip_warnings(
    report: &mut ExtractionReport,
    duplicate_skips: u64,
    hardlink_duplicate_skips: u64,
    disallowed_extension_skips: u64,
) {
    common::push_duplicate_skip_warning(report, duplicate_skips, "entry", "entries");
    common::push_duplicate_skip_warning(report, hardlink_duplicate_skips, "hardlink", "hardlinks");
    common::push_disallowed_extension_warning(report, disallowed_extension_skips);
}

#[allow(dead_code)] // Fields used only on Unix
struct HardlinkInfo {
    link_path: SafePath,
    target_path: SafePath,
}

/// Adapter to convert `tar::Entry` to our `EntryType`.
struct TarEntryAdapter;

impl TarEntryAdapter {
    /// Returns `true` for TAR metadata entries that should be skipped.
    ///
    /// PAX extended headers and GNU long name/link entries are format-internal
    /// records, not user files. The `tar` crate consumes `XHeader`,
    /// `GNULongName`, and `GNULongLink` internally in `next_entry()`, so
    /// they normally never reach our iterator. `XGlobalHeader` does reach
    /// us. All four are checked here as defense-in-depth.
    fn is_metadata_entry<R: Read>(tar_entry: &tar::Entry<'_, R>) -> bool {
        use tar::EntryType as TarType;

        matches!(
            tar_entry.header().entry_type(),
            TarType::XHeader | TarType::XGlobalHeader | TarType::GNULongName | TarType::GNULongLink
        )
    }

    /// Converts `tar::EntryType` to our `EntryType` enum.
    fn to_entry_type<R: Read>(tar_entry: &tar::Entry<'_, R>) -> Result<EntryType> {
        use tar::EntryType as TarType;

        match tar_entry.header().entry_type() {
            TarType::Regular | TarType::Continuous | TarType::GNUSparse => Ok(EntryType::File),

            TarType::Directory => Ok(EntryType::Directory),

            TarType::Symlink => {
                let target = tar_entry
                    .link_name()
                    .map_err(|e| {
                        ArchiveError::InvalidArchive(format!("failed to read symlink name: {e}"))
                    })?
                    .ok_or_else(|| ArchiveError::InvalidArchive("symlink missing target".into()))?
                    .into_owned();
                Ok(EntryType::Symlink { target })
            }

            TarType::Link => {
                let target = tar_entry
                    .link_name()
                    .map_err(|e| {
                        ArchiveError::InvalidArchive(format!("failed to read hardlink name: {e}"))
                    })?
                    .ok_or_else(|| ArchiveError::InvalidArchive("hardlink missing target".into()))?
                    .into_owned();
                Ok(EntryType::Hardlink { target })
            }

            TarType::Char => Err(ArchiveError::SecurityViolation {
                reason: "character device entries not supported".into(),
            }),

            TarType::Block => Err(ArchiveError::SecurityViolation {
                reason: "block device entries not supported".into(),
            }),

            TarType::Fifo => Err(ArchiveError::SecurityViolation {
                reason: "FIFO entries not supported".into(),
            }),

            _ => Err(ArchiveError::SecurityViolation {
                reason: format!(
                    "unsupported entry type: {:?}",
                    tar_entry.header().entry_type()
                ),
            }),
        }
    }

    /// Gets uncompressed size from TAR entry.
    fn get_uncompressed_size<R: Read>(tar_entry: &tar::Entry<'_, R>) -> u64 {
        tar_entry.size()
    }
}

/// Opens a gzip-compressed TAR archive (.tar.gz).
///
/// The file is wrapped in `BufReader` for optimal performance.
///
/// # Errors
///
/// Returns an error if the file cannot be opened.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::ExtractionOptions;
/// use exarch_core::SecurityConfig;
/// use exarch_core::formats::tar::open_tar_gz;
/// use exarch_core::formats::traits::ArchiveFormat;
/// use std::path::Path;
///
/// let mut archive = open_tar_gz("archive.tar.gz")?;
/// let config = SecurityConfig::default().validate()?;
/// let report = archive.extract(
///     Path::new("/output"),
///     &config,
///     &ExtractionOptions::default(),
///     &mut exarch_core::NoopProgress,
/// )?;
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
pub fn open_tar_gz<P: AsRef<Path>>(
    path: P,
) -> Result<TarArchive<flate2::read::GzDecoder<BufReader<File>>>> {
    let file = File::open(path)?;
    let buffered = BufReader::new(file);
    let decoder = flate2::read::GzDecoder::new(buffered);
    Ok(TarArchive::new(decoder))
}

/// Opens a bzip2-compressed TAR archive (.tar.bz2).
///
/// The file is wrapped in `BufReader` for optimal performance.
///
/// # Errors
///
/// Returns an error if the file cannot be opened.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::ExtractionOptions;
/// use exarch_core::SecurityConfig;
/// use exarch_core::formats::tar::open_tar_bz2;
/// use exarch_core::formats::traits::ArchiveFormat;
/// use std::path::Path;
///
/// let mut archive = open_tar_bz2("archive.tar.bz2")?;
/// let config = SecurityConfig::default().validate()?;
/// let report = archive.extract(
///     Path::new("/output"),
///     &config,
///     &ExtractionOptions::default(),
///     &mut exarch_core::NoopProgress,
/// )?;
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
pub fn open_tar_bz2<P: AsRef<Path>>(
    path: P,
) -> Result<TarArchive<bzip2::read::BzDecoder<BufReader<File>>>> {
    let file = File::open(path)?;
    let buffered = BufReader::new(file);
    let decoder = bzip2::read::BzDecoder::new(buffered);
    Ok(TarArchive::new(decoder))
}

/// Opens an xz-compressed TAR archive (.tar.xz).
///
/// The file is wrapped in `BufReader` for optimal performance.
///
/// # Errors
///
/// Returns an error if the file cannot be opened.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::ExtractionOptions;
/// use exarch_core::SecurityConfig;
/// use exarch_core::formats::tar::open_tar_xz;
/// use exarch_core::formats::traits::ArchiveFormat;
/// use std::path::Path;
///
/// let mut archive = open_tar_xz("archive.tar.xz")?;
/// let config = SecurityConfig::default().validate()?;
/// let report = archive.extract(
///     Path::new("/output"),
///     &config,
///     &ExtractionOptions::default(),
///     &mut exarch_core::NoopProgress,
/// )?;
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
pub fn open_tar_xz<P: AsRef<Path>>(
    path: P,
) -> Result<TarArchive<xz2::read::XzDecoder<BufReader<File>>>> {
    let file = File::open(path)?;
    let buffered = BufReader::new(file);
    let decoder = xz2::read::XzDecoder::new(buffered);
    Ok(TarArchive::new(decoder))
}

/// Opens a zstd-compressed TAR archive (.tar.zst).
///
/// The file is wrapped in `BufReader` for optimal performance.
///
/// # Errors
///
/// Returns an error if the file cannot be opened or if decompression
/// initialization fails.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::ExtractionOptions;
/// use exarch_core::SecurityConfig;
/// use exarch_core::formats::tar::open_tar_zst;
/// use exarch_core::formats::traits::ArchiveFormat;
/// use std::path::Path;
///
/// let mut archive = open_tar_zst("archive.tar.zst")?;
/// let config = SecurityConfig::default().validate()?;
/// let report = archive.extract(
///     Path::new("/output"),
///     &config,
///     &ExtractionOptions::default(),
///     &mut exarch_core::NoopProgress,
/// )?;
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
pub fn open_tar_zst<P: AsRef<Path>>(
    path: P,
) -> Result<TarArchive<zstd::Decoder<'static, BufReader<File>>>> {
    let file = File::open(path)?;
    let buffered = BufReader::new(file);
    let decoder = zstd::Decoder::with_buffer(buffered)?;
    Ok(TarArchive::new(decoder))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::NoopProgress;
    use crate::test_utils::create_test_tar;
    use std::assert_matches;
    use std::io::Cursor;
    use std::io::Write;
    #[cfg(unix)]
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_tar_archive_new() {
        let tar_data = create_test_tar(vec![]);
        let archive = TarArchive::new(Cursor::new(tar_data));
        assert_eq!(archive.format_name(), "tar");
    }

    #[test]
    fn test_extract_simple_file() {
        let tar_data = create_test_tar(vec![("file.txt", b"hello world")]);
        let mut archive = TarArchive::new(Cursor::new(tar_data));

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

        assert_eq!(report.files_extracted, 1);
        assert_eq!(report.directories_created, 0);
        assert!(temp.path().join("file.txt").exists());
    }

    #[test]
    fn test_extract_nested_structure() {
        let mut builder = tar::Builder::new(Vec::new());

        // Add directories explicitly
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_cksum();
        builder
            .append_data(&mut header, "dir1/", &[] as &[u8])
            .unwrap();

        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_cksum();
        builder
            .append_data(&mut header, "dir1/dir2/", &[] as &[u8])
            .unwrap();

        // Add file
        let mut header = tar::Header::new_gnu();
        header.set_size(6);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "dir1/dir2/file.txt", &b"nested"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

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

        assert_eq!(report.files_extracted, 1);
        assert_eq!(report.directories_created, 2);
        assert!(temp.path().join("dir1/dir2/file.txt").exists());
    }

    #[test]
    #[cfg(unix)]
    fn test_extract_symlink() {
        let mut builder = tar::Builder::new(Vec::new());

        // Add target file
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "target.txt", &b"data\n"[..])
            .unwrap();

        // Add symlink
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("target.txt").unwrap();
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "link.txt", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = true;
        let config = config.validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert_eq!(report.symlinks_created, 1);
        assert!(temp.path().join("link.txt").exists());
    }

    #[test]
    #[cfg(unix)]
    fn test_extract_hardlink_two_pass() {
        let mut builder = tar::Builder::new(Vec::new());

        // Add hardlink BEFORE target (tests two-pass)
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_link_name("target.txt").unwrap();
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "hardlink.txt", &[] as &[u8])
            .unwrap();

        // Add target file
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "target.txt", &b"data\n"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        let config = config.validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 2);
        assert!(temp.path().join("hardlink.txt").exists());
        assert!(temp.path().join("target.txt").exists());
    }

    #[test]
    fn test_quota_file_size_exceeded() {
        let tar_data = create_test_tar(vec![("large.bin", &vec![0u8; 1000])]);
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default()
            .with_max_file_size(100)
            .validate()
            .unwrap();

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_unsupported_entry_type_block_device() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Block);
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "dev/sda", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_unsupported_entry_type_char_device() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Char);
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "dev/tty", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_unsupported_entry_type_fifo() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Fifo);
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "fifo", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_extract_pax_headers_skipped() {
        let mut builder = tar::Builder::new(Vec::new());

        // Add a PAX global header entry
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::XGlobalHeader);
        let pax_data = b"16 comment=hi\n";
        header.set_size(pax_data.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, "././@PaxHeader", &pax_data[..])
            .unwrap();

        // Add a PAX extended header entry
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::XHeader);
        header.set_size(pax_data.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, "././@PaxHeader", &pax_data[..])
            .unwrap();

        // Add a regular file
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "hello.txt", &b"hello"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

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

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("hello.txt").exists());
    }

    #[test]
    fn test_extract_gnu_long_name_skipped() {
        let mut builder = tar::Builder::new(Vec::new());

        // Add a GNU long name entry
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::GNULongName);
        let long_name = b"very_long_filename.txt";
        header.set_size(long_name.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, "././@LongLink", &long_name[..])
            .unwrap();

        // Add a regular file
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "file.txt", &b"data"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

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

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("very_long_filename.txt").exists());
    }

    #[test]
    fn test_extract_gnu_long_link_skipped() {
        let mut builder = tar::Builder::new(Vec::new());

        // Add a GNU long link entry (metadata, should be skipped)
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::GNULongLink);
        let long_link = b"target.txt";
        header.set_size(long_link.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, "././@LongLink", &long_link[..])
            .unwrap();

        // Add a regular file
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "file.txt", &b"data"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

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

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("file.txt").exists());
    }

    #[test]
    fn test_extract_gnu_sparse_as_file() {
        let mut builder = tar::Builder::new(Vec::new());

        // GNUSparse entries are treated as regular files by to_entry_type().
        // The `tar` crate may reject a malformed sparse header at read time,
        // which would manifest as an InvalidArchive error rather than a
        // SecurityViolation. Either outcome is acceptable — we verify the
        // entry type mapping is handled without panicking.
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::GNUSparse);
        header.set_size(6);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "sparse.txt", &b"sparse"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        // Either succeeds (extracted as regular file) or fails with
        // InvalidArchive due to missing GNU sparse extension headers.
        // A SecurityViolation must NOT be returned for this entry type.
        match archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        ) {
            Ok(report) => {
                assert_eq!(report.files_extracted, 1);
                assert!(temp.path().join("sparse.txt").exists());
            }
            Err(ArchiveError::InvalidArchive(_)) => {
                // Acceptable: tar crate rejects malformed sparse header
            }
            Err(e) => panic!("unexpected error for GNUSparse entry: {e}"),
        }
    }

    #[test]
    fn test_unsupported_entry_type_unknown_byte() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        // b'Z' is not a known entry type byte
        header.set_entry_type(tar::EntryType::__Nonexhaustive(b'Z'));
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "unknown", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert_matches!(
            result,
            Err(ArchiveError::SecurityViolation { .. }),
            "expected SecurityViolation, got: {result:?}"
        );
    }

    #[test]
    fn test_extract_continuous_entry_as_file() {
        let mut builder = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Continuous);
        header.set_size(7);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "cont.txt", &b"content"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

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

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("cont.txt").exists());
    }

    #[test]
    fn test_extract_gzip_compressed() {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        // Create TAR archive
        let tar_data = create_test_tar(vec![("file.txt", b"compressed")]);

        // Compress with gzip
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let gz_data = encoder.finish().unwrap();

        // Extract
        let decoder = flate2::read::GzDecoder::new(Cursor::new(gz_data));
        let mut archive = TarArchive::new(decoder);

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

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("file.txt").exists());
    }

    #[test]
    fn test_extract_bzip2_compressed() {
        use bzip2::Compression;
        use bzip2::write::BzEncoder;

        // Create TAR archive
        let tar_data = create_test_tar(vec![("file.txt", b"compressed")]);

        // Compress with bzip2
        let mut encoder = BzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let bz2_data = encoder.finish().unwrap();

        // Extract
        let decoder = bzip2::read::BzDecoder::new(Cursor::new(bz2_data));
        let mut archive = TarArchive::new(decoder);

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

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("file.txt").exists());
    }

    #[test]
    fn test_extract_xz_compressed() {
        use xz2::write::XzEncoder;

        // Create TAR archive
        let tar_data = create_test_tar(vec![("file.txt", b"compressed")]);

        // Compress with xz
        let mut encoder = XzEncoder::new(Vec::new(), 6);
        encoder.write_all(&tar_data).unwrap();
        let xz_data = encoder.finish().unwrap();

        // Extract
        let decoder = xz2::read::XzDecoder::new(Cursor::new(xz_data));
        let mut archive = TarArchive::new(decoder);

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

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("file.txt").exists());
    }

    #[test]
    fn test_extract_zstd_compressed() {
        // Create TAR archive
        let tar_data = create_test_tar(vec![("file.txt", b"compressed")]);

        // Compress with zstd
        let zst_data = zstd::encode_all(&tar_data[..], 3).unwrap();

        // Extract
        let decoder = zstd::Decoder::with_buffer(Cursor::new(zst_data)).unwrap();
        let mut archive = TarArchive::new(decoder);

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

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("file.txt").exists());
    }

    #[test]
    fn test_empty_tar_archive() {
        let tar_data = create_test_tar(vec![]);
        let mut archive = TarArchive::new(Cursor::new(tar_data));

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
    fn test_extract_empty_file() {
        let tar_data = create_test_tar(vec![("empty.txt", b"")]);
        let mut archive = TarArchive::new(Cursor::new(tar_data));

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

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("empty.txt").exists());
        assert_eq!(
            std::fs::metadata(temp.path().join("empty.txt"))
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn test_extract_multiple_files() {
        let tar_data = create_test_tar(vec![
            ("file1.txt", b"content1"),
            ("file2.txt", b"content2"),
            ("file3.txt", b"content3"),
        ]);
        let mut archive = TarArchive::new(Cursor::new(tar_data));

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

        assert_eq!(report.files_extracted, 3);
        assert!(temp.path().join("file1.txt").exists());
        assert!(temp.path().join("file2.txt").exists());
        assert!(temp.path().join("file3.txt").exists());
    }

    #[test]
    fn test_quota_file_count_exceeded() {
        let tar_data = create_test_tar(vec![
            ("file1.txt", b"a"),
            ("file2.txt", b"b"),
            ("file3.txt", b"c"),
        ]);
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default()
            .with_max_file_count(2)
            .validate()
            .unwrap();

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_quota_total_size_exceeded() {
        let tar_data = create_test_tar(vec![
            ("file1.txt", &vec![0u8; 500]),
            ("file2.txt", &vec![0u8; 600]),
        ]);
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default()
            .with_max_total_size(1000)
            .validate()
            .unwrap();

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
    }

    #[test]
    #[cfg(unix)]
    fn test_file_permissions_preserved() {
        use std::os::unix::fs::PermissionsExt;

        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, "script.sh", &b"#!/bin/sh"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

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

        assert_eq!(report.files_extracted, 1);

        let metadata = std::fs::metadata(temp.path().join("script.sh")).unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o755);
    }

    #[test]
    #[cfg(unix)]
    fn test_permissions_sanitized_setuid_removed() {
        use std::os::unix::fs::PermissionsExt;

        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o4755); // setuid bit set
        header.set_cksum();
        builder
            .append_data(&mut header, "binary", &b"data"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

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

        assert_eq!(report.files_extracted, 1);

        let metadata = std::fs::metadata(temp.path().join("binary")).unwrap();
        let permissions = metadata.permissions();
        // setuid bit should be stripped
        assert_eq!(permissions.mode() & 0o7777, 0o755);
    }

    #[test]
    fn test_bytes_written_tracking() {
        let tar_data = create_test_tar(vec![("file1.txt", b"12345"), ("file2.txt", b"67890")]);
        let mut archive = TarArchive::new(Cursor::new(tar_data));

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

        assert_eq!(report.bytes_written, 10);
    }

    #[test]
    fn test_extract_directory_only() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_cksum();
        builder
            .append_data(&mut header, "mydir/", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

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
        assert_eq!(report.directories_created, 1);
        assert!(temp.path().join("mydir").is_dir());
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_disabled_by_default() {
        let mut builder = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("target.txt").unwrap();
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "link.txt", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config"); // symlinks disabled by default

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
    }

    #[test]
    #[cfg(unix)]
    fn test_hardlink_disabled_by_default() {
        let mut builder = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_link_name("target.txt").unwrap();
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "hardlink.txt", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config"); // hardlinks disabled by default

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_extraction_duration_recorded() {
        let tar_data = create_test_tar(vec![("file.txt", b"test")]);
        let mut archive = TarArchive::new(Cursor::new(tar_data));

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

        assert!(report.duration.as_nanos() > 0);
    }

    #[test]
    fn test_path_traversal_via_dotdot_rejected() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);

        // Manually set path with .. (bypassing tar crate validation)
        let path_bytes = b"subdir/../etc/passwd";
        let mut name_field = [0u8; 100];
        name_field[..path_bytes.len()].copy_from_slice(path_bytes);
        header.as_gnu_mut().unwrap().name = name_field;
        header.set_cksum();

        builder.append(&header, &b"evil\n"[..]).unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
        match result {
            Err(ArchiveError::PathTraversal { .. }) => {}
            _ => panic!("Expected PathTraversal error"),
        }
    }

    #[test]
    fn test_absolute_path_rejected() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);

        // Manually set absolute path (bypassing tar crate validation)
        let path_bytes = b"/etc/shadow";
        let mut name_field = [0u8; 100];
        name_field[..path_bytes.len()].copy_from_slice(path_bytes);
        header.as_gnu_mut().unwrap().name = name_field;
        header.set_cksum();

        builder.append(&header, &b"evil\n"[..]).unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
        match result {
            Err(ArchiveError::PathTraversal { .. }) => {}
            _ => panic!("Expected PathTraversal error for absolute path"),
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_escape_rejected() {
        let mut builder = tar::Builder::new(Vec::new());

        // Add directory first
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_cksum();
        builder
            .append_data(&mut header, "subdir/", &[] as &[u8])
            .unwrap();

        // Add symlink in subdir pointing outside extraction directory
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("../../etc/passwd").unwrap();
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "subdir/evil_link.txt", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = true;
        let config = config.validate().expect("valid config");

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
        // A directory was created before the symlink escape, so the error is
        // wrapped in PartialExtraction. Unwrap one level to check the source.
        match result {
            Err(ArchiveError::PartialExtraction { source, .. }) => {
                assert_matches!(*source, ArchiveError::SymlinkEscape { .. });
            }
            Err(ArchiveError::SymlinkEscape { .. }) => {}
            other => panic!("Expected SymlinkEscape error for symlink escape, got: {other:?}"),
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_hardlink_target_missing_error() {
        let mut builder = tar::Builder::new(Vec::new());

        // Add hardlink without target file (should fail in second pass)
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_link_name("nonexistent.txt").unwrap();
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "hardlink.txt", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        let config = config.validate().expect("valid config");

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
        match result {
            Err(ArchiveError::InvalidArchive(msg)) => {
                assert!(msg.contains("hardlink target does not exist"));
            }
            _ => panic!("Expected InvalidArchive error for missing hardlink target"),
        }
    }

    /// Builds a TAR with a regular file entry (`target.txt`) followed by a
    /// hardlink entry (`hardlink.txt`) pointing at it.
    #[cfg(unix)]
    fn create_hardlink_tar(target_content: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());

        let mut file_header = tar::Header::new_gnu();
        file_header.set_entry_type(tar::EntryType::Regular);
        file_header.set_size(target_content.len() as u64);
        file_header.set_mode(0o644);
        file_header.set_cksum();
        builder
            .append_data(&mut file_header, "target.txt", target_content)
            .unwrap();

        let mut link_header = tar::Header::new_gnu();
        link_header.set_entry_type(tar::EntryType::Link);
        link_header.set_link_name("target.txt").unwrap();
        link_header.set_size(0);
        link_header.set_cksum();
        builder
            .append_data(&mut link_header, "hardlink.txt", &[] as &[u8])
            .unwrap();

        builder.into_inner().unwrap()
    }

    /// Regression test for issue #467: a dangling symlink pre-planted at the
    /// hardlink's destination path used to bypass the old `Path::exists()`
    /// duplicate check (which returns `false` for a dangling symlink) and a
    /// subsequent `fs::copy` followed it, writing archive content outside
    /// the extraction root. With `skip_duplicates=true` (the default), the
    /// pre-existing path at `hardlink.txt` must now be treated as a
    /// duplicate and skipped instead of being written through.
    #[test]
    #[cfg(unix)]
    fn test_hardlink_dangling_symlink_at_destination_skipped() {
        let temp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let victim_path = outside.path().join("victim.txt");

        // Pre-plant a dangling symlink at the hardlink's destination path,
        // pointing outside the extraction root at a file that does not exist.
        let link_dest = temp.path().join("hardlink.txt");
        std::os::unix::fs::symlink(&victim_path, &link_dest).unwrap();
        assert!(!victim_path.exists());

        let tar_data = create_hardlink_tar(b"pwned!");
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        let config = config.validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(), // skip_duplicates = true
                &mut crate::NoopProgress,
            )
            .expect("extraction should succeed by skipping the duplicate");

        assert_eq!(report.files_skipped, 1);
        assert!(
            !victim_path.exists(),
            "hardlink write followed the pre-planted symlink outside the extraction root"
        );

        // The pre-planted symlink itself must be left untouched, not followed
        // or replaced.
        let link_metadata = std::fs::symlink_metadata(&link_dest).unwrap();
        assert!(link_metadata.file_type().is_symlink());
    }

    /// Companion to [`test_hardlink_dangling_symlink_at_destination_skipped`]
    /// with `skip_duplicates=false`: the pre-planted symlink must still be
    /// rejected as a duplicate-entry error rather than followed.
    #[test]
    #[cfg(unix)]
    fn test_hardlink_dangling_symlink_at_destination_errors_when_skip_disabled() {
        let temp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let victim_path = outside.path().join("victim.txt");

        let link_dest = temp.path().join("hardlink.txt");
        std::os::unix::fs::symlink(&victim_path, &link_dest).unwrap();

        let tar_data = create_hardlink_tar(b"pwned!");
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        let config = config.validate().expect("valid config");
        let options = ExtractionOptions {
            atomic: false,
            skip_duplicates: false,
        };

        let result = archive.extract(temp.path(), &config, &options, &mut crate::NoopProgress);

        assert!(!victim_path.exists());
        // The regular `target.txt` entry extracts successfully before the
        // hardlink entry fails, so the error arrives wrapped in
        // PartialExtraction; unwrap one level to check the source.
        match result {
            Err(ArchiveError::PartialExtraction { source, .. }) => match *source {
                ArchiveError::InvalidArchive(msg) => assert!(msg.contains("duplicate entry")),
                other => panic!("Expected InvalidArchive duplicate-entry error, got: {other:?}"),
            },
            Err(ArchiveError::InvalidArchive(msg)) => {
                assert!(msg.contains("duplicate entry"));
            }
            other => panic!("Expected InvalidArchive duplicate-entry error, got: {other:?}"),
        }

        let link_metadata = std::fs::symlink_metadata(&link_dest).unwrap();
        assert!(link_metadata.file_type().is_symlink());
    }

    /// Regression test for issue #467's pass-1-to-pass-2 TOCTOU: a hardlink
    /// target that is safe when `EntryValidator::validate_entry`
    /// (`HardlinkTracker::validate_hardlink`) runs in pass one, but gets
    /// swapped for a symlink escaping `dest` before `create_hardlink` (pass
    /// two) actually reads it, must not have its escape-target content
    /// copied into the destination.
    ///
    /// Calls `create_hardlink` directly with a hand-built `HardlinkInfo`
    /// instead of going through `TarArchive::extract`, since the two passes
    /// run back-to-back within a single `extract()` call with no way for a
    /// test to inject a filesystem change in between. This is deliberate: a
    /// plain pre-planted symlink present *before* pass one runs is already
    /// rejected by pass one's own `resolve_through_symlinks` check
    /// (`HardlinkTracker::validate_hardlink`, issue #116) and never reaches
    /// `create_hardlink` at all — asserting against that scenario would
    /// pass identically on the pre-#467-fix code and prove nothing about
    /// this change. Simulating the race directly is the only way to
    /// exercise `open_no_follow`'s `ErrorKind::FilesystemLoop` retry path
    /// and its `resolve_through_symlinks` re-validation.
    #[test]
    #[cfg(unix)]
    fn test_hardlink_target_swapped_for_escaping_symlink_between_passes() {
        let temp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let sentinel_path = outside.path().join("sentinel.txt");
        std::fs::write(&sentinel_path, b"top secret").unwrap();

        let dest = DestDir::new_or_create(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        let config = config.validate().expect("valid config");

        // Simulates: pass one validated "target.txt" as a safe relative
        // target (it did not exist yet, or was something innocuous) and
        // recorded this `HardlinkInfo` for pass two. Between the two passes,
        // an attacker with write access to `dest` swaps in a symlink
        // escaping the destination — exactly the window pass one's
        // point-in-time check cannot see across.
        let info = HardlinkInfo {
            link_path: SafePath::new_unchecked(PathBuf::from("loot.txt")),
            target_path: SafePath::new_unchecked(PathBuf::from("target.txt")),
        };
        std::os::unix::fs::symlink(&sentinel_path, dest.as_path().join("target.txt")).unwrap();

        let mut validator = EntryValidator::new(&config, &dest);
        let mut report = ExtractionReport::new();
        let mut copy_buffer = CopyBuffer::new();
        let mut dir_cache = common::DirCache::new();
        let mut progress = crate::NoopProgress;
        let mut duplicate_skips = 0u64;
        let mut hardlink_duplicate_skips = 0u64;
        let mut disallowed_extension_skips = 0u64;
        let mut ctx = ExtractionContext {
            validator: &mut validator,
            dest: &dest,
            report: &mut report,
            copy_buffer: &mut copy_buffer,
            dir_cache: &mut dir_cache,
            skip_duplicates: true,
            duplicate_skips: &mut duplicate_skips,
            hardlink_duplicate_skips: &mut hardlink_duplicate_skips,
            disallowed_extension_skips: &mut disallowed_extension_skips,
            config: &config,
            progress: &mut progress,
        };

        let result = TarArchive::<Cursor<Vec<u8>>>::create_hardlink(&info, &mut ctx);

        assert_matches!(
            result,
            Err(ArchiveError::HardlinkEscape { .. }),
            "expected the pass-1-to-pass-2 target swap to be rejected as a hardlink escape, got: {result:?}"
        );
        assert!(
            !temp.path().join("loot.txt").exists(),
            "sentinel content must not have been copied into the destination, and TempFileGuard \
             must have removed the exclusively-opened link file on this error path"
        );
    }

    /// Regression test for issue #467's `TempFileGuard` cleanup path: when
    /// the quota reservation fails *after* the hardlink's exclusive-open
    /// destination file was already created, no stray zero-byte file must
    /// be left behind at `link_path`.
    #[test]
    #[cfg(unix)]
    fn test_hardlink_quota_failure_leaves_no_stray_link_file() {
        let temp = TempDir::new().unwrap();

        let tar_data = create_hardlink_tar(&[b'A'; 100]);
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        // Enough room for target.txt (100 bytes) but not for the hardlink's
        // own independent 100-byte copy on top of it.
        config.max_total_size = 150;
        let config = config.validate().expect("valid config");

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err(), "expected quota exceeded, got: {result:?}");
        assert!(
            temp.path().join("target.txt").exists(),
            "target.txt should have been extracted before the hardlink's quota failure"
        );
        assert!(
            !temp.path().join("hardlink.txt").exists(),
            "TempFileGuard must remove the empty hardlink destination file left by the failed \
             quota reservation"
        );
    }

    /// Regression test for issue #467's
    /// `open_no_follow`/`ErrorKind::FilesystemLoop` re-resolution path: a
    /// hardlink whose target is itself a symlink pointing *inside* `dest`
    /// (a legitimate, common archive shape — two links sharing an inode,
    /// where the second is stored as a `Symlink` entry rather than a second
    /// `Link` entry) must still extract correctly, not hard-fail with a raw
    /// `ELOOP`.
    ///
    /// Archive order matters here: `real.txt` (regular) then `loot.txt`
    /// (hardlink -> `target.txt`) then `target.txt` (symlink -> `real.txt`)
    /// means `target.txt` does not exist on disk yet when `loot.txt`'s
    /// hardlink entry is validated in pass one, so pass one cannot resolve
    /// the symlink itself — deferring to pass two's `create_hardlink`, which
    /// by then finds `target.txt` on disk as the symlink created earlier in
    /// the same pass-one loop. This is the exact ordering the regression was
    /// reproduced with.
    #[test]
    #[cfg(unix)]
    fn test_hardlink_target_is_legitimate_symlink_created_earlier_in_extraction() {
        let temp = TempDir::new().unwrap();

        let mut builder = tar::Builder::new(Vec::new());

        let mut file_header = tar::Header::new_gnu();
        file_header.set_entry_type(tar::EntryType::Regular);
        file_header.set_size(5);
        file_header.set_mode(0o644);
        file_header.set_cksum();
        builder
            .append_data(&mut file_header, "real.txt", b"hello" as &[u8])
            .unwrap();

        let mut link_header = tar::Header::new_gnu();
        link_header.set_entry_type(tar::EntryType::Link);
        link_header.set_link_name("target.txt").unwrap();
        link_header.set_size(0);
        link_header.set_cksum();
        builder
            .append_data(&mut link_header, "loot.txt", &[] as &[u8])
            .unwrap();

        let mut symlink_header = tar::Header::new_gnu();
        symlink_header.set_entry_type(tar::EntryType::Symlink);
        symlink_header.set_link_name("real.txt").unwrap();
        symlink_header.set_size(0);
        symlink_header.set_cksum();
        builder
            .append_data(&mut symlink_header, "target.txt", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        config.allowed.symlinks = true;
        let config = config.validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .expect("legitimate hardlink-to-in-dest-symlink shape must extract successfully");

        assert_eq!(report.files_extracted, 2, "real.txt and loot.txt");
        assert_eq!(report.symlinks_created, 1, "target.txt");
        assert_eq!(
            std::fs::read(temp.path().join("loot.txt")).unwrap(),
            b"hello",
            "loot.txt must contain real.txt's content, resolved through target.txt's symlink"
        );
    }

    // OPT-H001: Test SmallVec stack allocation for hardlinks
    #[test]
    #[cfg(unix)]
    fn test_hardlink_collection_stack_allocation() {
        // Test with 7 hardlinks - should stay on stack (SmallVec<[T; 8]>)
        let mut builder = tar::Builder::new(Vec::new());

        // Add target file
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "target.txt", &b"data\n"[..])
            .unwrap();

        // Add 7 hardlinks (stays on stack)
        for i in 0..7 {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Link);
            header.set_link_name("target.txt").unwrap();
            header.set_size(0);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("link{i}.txt"), &[] as &[u8])
                .unwrap();
        }

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        let config = config.validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        // 1 target file + 7 hardlinks = 8 files extracted
        assert_eq!(report.files_extracted, 8);
        for i in 0..7 {
            assert!(temp.path().join(format!("link{i}.txt")).exists());
        }
    }

    // OPT-H001: Test SmallVec heap spillover for hardlinks
    #[test]
    #[cfg(unix)]
    fn test_hardlink_collection_heap_spillover() {
        // Test with 20 hardlinks - should spill to heap
        let mut builder = tar::Builder::new(Vec::new());

        // Add target file
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "target.txt", &b"data\n"[..])
            .unwrap();

        // Add 20 hardlinks (spills to heap)
        for i in 0..20 {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Link);
            header.set_link_name("target.txt").unwrap();
            header.set_size(0);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("link{i}.txt"), &[] as &[u8])
                .unwrap();
        }

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        let config = config.validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        // 1 target file + 20 hardlinks = 21 files extracted
        assert_eq!(report.files_extracted, 21);
        for i in 0..20 {
            assert!(temp.path().join(format!("link{i}.txt")).exists());
        }
    }

    // Builds a raw TAR archive with a PAX extended header that advertises
    // `pax_size` for the file, while the ustar header carries size=0.
    // This is exactly the structure that exploits the PAX quota bypass (issue #82).
    fn create_tar_with_pax_size_override(filename: &str, pax_size: u64, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();

        // PAX key-value: "<len> size=<N>\n" where len equals the total record byte
        // count.
        let kv_suffix = format!(" size={pax_size}\n");
        let mut total = 1 + kv_suffix.len(); // start with 1 digit
        loop {
            let digits = total.to_string().len();
            let candidate = digits + kv_suffix.len();
            if candidate == total {
                break;
            }
            total = candidate;
        }
        let pax_data = format!("{total}{kv_suffix}");
        let pax_bytes = pax_data.as_bytes();

        // PAX extended header (type 'x') with the computed size
        let mut pax_header = tar::Header::new_ustar();
        pax_header.set_entry_type(tar::EntryType::XHeader);
        pax_header.set_size(pax_bytes.len() as u64);
        pax_header.set_mode(0o644);
        pax_header.set_path("././@PaxHeader").unwrap();
        pax_header.set_cksum();
        out.extend_from_slice(pax_header.as_bytes());
        out.extend_from_slice(pax_bytes);
        let pax_pad = (512 - pax_bytes.len() % 512) % 512;
        out.extend(std::iter::repeat_n(0u8, pax_pad));

        // Regular file header with ustar size=0 (triggers the bypass pre-fix)
        let mut file_header = tar::Header::new_ustar();
        file_header.set_entry_type(tar::EntryType::Regular);
        file_header.set_size(0);
        file_header.set_mode(0o644);
        file_header.set_path(filename).unwrap();
        file_header.set_cksum();
        out.extend_from_slice(file_header.as_bytes());
        out.extend_from_slice(data);
        let data_pad = if data.is_empty() {
            0
        } else {
            (512 - data.len() % 512) % 512
        };
        out.extend(std::iter::repeat_n(0u8, data_pad));

        // End-of-archive: two 512-byte zero blocks
        out.extend(std::iter::repeat_n(0u8, 1024));
        out
    }

    #[test]
    fn test_pax_size_override_bypasses_max_file_size_quota() {
        // Regression for issue #82: PAX size must be used for quota, not ustar size.
        // File has PAX size=2MB but ustar size=0; limit is 1MB — must be rejected.
        const PAX_SIZE: u64 = 2 * 1024 * 1024;
        let data = vec![0u8; usize::try_from(PAX_SIZE).unwrap()];
        let tar_data = create_tar_with_pax_size_override("big.bin", PAX_SIZE, &data);

        let mut archive = TarArchive::new(Cursor::new(tar_data));
        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default()
            .with_max_file_size(1024 * 1024)
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
            "expected quota error for PAX file size override, got: {result:?}"
        );
    }

    #[test]
    fn test_pax_size_override_bypasses_max_total_size_quota() {
        // Regression for issue #82: PAX size must be used for total-size quota.
        // File has PAX size=600KB but ustar size=0; total limit is 500KB — must be
        // rejected.
        const PAX_SIZE: u64 = 600 * 1024;
        let data = vec![0u8; usize::try_from(PAX_SIZE).unwrap()];
        let tar_data = create_tar_with_pax_size_override("big.bin", PAX_SIZE, &data);

        let mut archive = TarArchive::new(Cursor::new(tar_data));
        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default()
            .with_max_total_size(500 * 1024)
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
            "expected quota error for PAX total size override, got: {result:?}"
        );
    }

    // OPT-H001: Test SmallVec boundary at exactly 8 hardlinks
    #[test]
    #[cfg(unix)]
    fn test_hardlink_collection_boundary() {
        // Test with exactly 8 hardlinks - boundary case
        let mut builder = tar::Builder::new(Vec::new());

        // Add target file
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "target.txt", &b"data\n"[..])
            .unwrap();

        // Add exactly 8 hardlinks (boundary case)
        for i in 0..8 {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Link);
            header.set_link_name("target.txt").unwrap();
            header.set_size(0);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("link{i}.txt"), &[] as &[u8])
                .unwrap();
        }

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        let config = config.validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        // 1 target file + 8 hardlinks = 9 files extracted
        assert_eq!(report.files_extracted, 9);
        for i in 0..8 {
            assert!(temp.path().join(format!("link{i}.txt")).exists());
        }
    }

    /// Build a TAR archive in-memory with two entries sharing the same path.
    fn create_duplicate_entry_tar(path: &str, content1: &[u8], content2: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_size(content1.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, content1).unwrap();

        let mut header = tar::Header::new_gnu();
        header.set_size(content2.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, content2).unwrap();

        builder.into_inner().unwrap()
    }

    #[test]
    fn test_duplicate_entry_skip_default() {
        let tar_data = create_duplicate_entry_tar("legit.txt", b"first", b"second");
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");
        let options = ExtractionOptions::default(); // skip_duplicates = true

        let report = archive
            .extract(temp.path(), &config, &options, &mut crate::NoopProgress)
            .unwrap();

        // First entry extracted, second skipped
        assert_eq!(report.files_extracted, 1);
        assert_eq!(report.files_skipped, 1);
        assert_eq!(report.warnings.len(), 1);
        assert!(report.warnings[0].contains("pre-existing duplicates"));

        // File content is from the first entry
        let content = std::fs::read(temp.path().join("legit.txt")).unwrap();
        assert_eq!(content, b"first");
    }

    #[test]
    fn test_duplicate_entry_overwrites_when_skip_disabled() {
        let tar_data = create_duplicate_entry_tar("legit.txt", b"first", b"second");
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");
        let options = ExtractionOptions {
            atomic: false,
            skip_duplicates: false,
        };

        let report = archive
            .extract(temp.path(), &config, &options, &mut crate::NoopProgress)
            .unwrap();

        // Both entries extracted (second overwrites first)
        assert_eq!(report.files_extracted, 2);
        assert_eq!(report.files_skipped, 0);

        // File content is from the second (overwriting) entry
        let content = std::fs::read(temp.path().join("legit.txt")).unwrap();
        assert_eq!(content, b"second");
    }

    /// Regression test for issue #490: extracting an archive with many
    /// pre-existing duplicate entries must push exactly one aggregated
    /// warning onto `report.warnings`, not one `String` per skipped entry
    /// (mirrors 7z's `test_skip_duplicates_aggregates_single_warning`, #484).
    #[test]
    fn test_skip_duplicates_aggregates_single_warning() {
        const ENTRY_COUNT: usize = 30;
        let names: Vec<String> = (0..ENTRY_COUNT).map(|i| format!("dup-{i}.txt")).collect();
        let entries: Vec<(&str, &[u8])> = names
            .iter()
            .map(|n| (n.as_str(), b"payload".as_slice()))
            .collect();
        let tar_data = create_test_tar(entries);
        let mut archive = TarArchive::new(Cursor::new(tar_data));

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

    /// Companion to [`test_skip_duplicates_aggregates_single_warning`]: TAR's
    /// hardlink duplicate-skip path (`create_hardlink`) is not routed
    /// through `common.rs`, so it needs its own counter and must be verified
    /// to aggregate separately (issue #490).
    #[test]
    #[cfg(unix)]
    fn test_skip_duplicate_hardlinks_aggregates_single_warning() {
        const LINK_COUNT: usize = 10;

        let mut builder = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "target.txt", &b"data\n"[..])
            .unwrap();

        for i in 0..LINK_COUNT {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Link);
            header.set_link_name("target.txt").unwrap();
            header.set_size(0);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("link{i}.txt"), &[] as &[u8])
                .unwrap();
        }

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        for i in 0..LINK_COUNT {
            std::fs::write(temp.path().join(format!("link{i}.txt")), b"already here").unwrap();
        }

        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        let config = config.validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(), // skip_duplicates = true
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_skipped, LINK_COUNT);
        assert_eq!(report.files_extracted, 1, "only target.txt is extracted");
        assert_eq!(
            report.warnings.len(),
            1,
            "hardlink duplicate skips must be aggregated into a single warning, got: {:?}",
            report.warnings
        );
        assert!(
            report.warnings[0].contains(&LINK_COUNT.to_string())
                && report.warnings[0].contains("hardlink"),
            "aggregated warning must report the correct skipped hardlink count, got: {}",
            report.warnings[0]
        );
    }

    #[test]
    fn test_list_returns_manifest_with_entries() {
        let tar_data = create_test_tar(vec![("a.txt", b"hello"), ("b.txt", b"world")]);
        let mut archive = TarArchive::new(Cursor::new(tar_data));
        let config = SecurityConfig::default().validate().expect("valid config");

        let manifest = archive.list(&config).unwrap();

        assert_eq!(manifest.total_entries, 2);
        assert_eq!(manifest.total_size, 10);
    }

    #[test]
    fn test_list_empty_archive_returns_empty_manifest() {
        let tar_data = create_test_tar(vec![]);
        let mut archive = TarArchive::new(Cursor::new(tar_data));
        let config = SecurityConfig::default().validate().expect("valid config");

        let manifest = archive.list(&config).unwrap();

        assert_eq!(manifest.total_entries, 0);
        assert_eq!(manifest.total_size, 0);
    }

    #[test]
    fn test_verify_clean_archive_is_safe() {
        let tar_data = create_test_tar(vec![("safe.txt", b"data")]);
        let mut archive = TarArchive::new(Cursor::new(tar_data));
        let config = SecurityConfig::default().validate().expect("valid config");

        let report = archive.verify(&config).unwrap();

        assert!(report.is_safe());
        assert_eq!(report.total_entries, 1);
    }

    fn create_tar_with_absolute_path(path_bytes: &[u8], content: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        let mut name_field = [0u8; 100];
        let len = path_bytes.len().min(100);
        name_field[..len].copy_from_slice(&path_bytes[..len]);
        header.as_gnu_mut().unwrap().name = name_field;
        header.set_cksum();
        builder.append(&header, content).unwrap();
        builder.into_inner().unwrap()
    }

    #[test]
    fn test_tar_absolute_path_rejected_by_default() {
        let tar_data = create_tar_with_absolute_path(b"/etc/shadow", b"secret");
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut NoopProgress,
        );
        assert!(result.is_err(), "absolute path must be rejected by default");
        assert_matches!(
            result.unwrap_err(),
            ArchiveError::PathTraversal { .. },
            "expected PathTraversal"
        );
    }

    #[test]
    fn test_tar_absolute_path_with_flag_writes_to_dest() {
        let tar_data = create_tar_with_absolute_path(b"/etc/shadow", b"content");
        let mut archive = TarArchive::new(Cursor::new(tar_data));

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
                &mut NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert!(
            temp.path().join("etc/shadow").exists(),
            "file must land inside dest, not at real /etc/shadow"
        );
    }

    #[test]
    fn test_tar_absolute_path_traversal_still_rejected_with_flag() {
        // Even with allow_absolute_paths, `/../etc/passwd` contains `..` and
        // must be rejected regardless.
        let tar_data = create_tar_with_absolute_path(b"/../etc/passwd", b"secret");
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default()
            .with_allow_absolute_paths(true)
            .validate()
            .unwrap();

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut NoopProgress,
        );
        assert!(
            result.is_err(),
            "traversal-after-root must be rejected even with allow_absolute_paths"
        );
    }

    #[test]
    fn test_allowed_extensions_filters_out_disallowed() {
        let tar_data = create_test_tar(vec![("keep.txt", b"keep"), ("skip.exe", b"skip")]);
        let dest = tempfile::tempdir().unwrap();
        let config = SecurityConfig::default()
            .with_allowed_extensions(vec!["txt".to_string()])
            .validate()
            .unwrap();

        let report = TarArchive::new(Cursor::new(tar_data))
            .extract(
                dest.path(),
                &config,
                &ExtractionOptions::default(),
                &mut NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert_eq!(report.files_skipped, 1);
        assert!(dest.path().join("keep.txt").exists());
        assert!(!dest.path().join("skip.exe").exists());
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
        let tar_data = create_test_tar(entries);
        let dest = tempfile::tempdir().unwrap();
        let config = SecurityConfig::default()
            .with_allowed_extensions(vec!["txt".to_string()])
            .validate()
            .expect("valid config");

        let report = TarArchive::new(Cursor::new(tar_data))
            .extract(
                dest.path(),
                &config,
                &ExtractionOptions::default(),
                &mut NoopProgress,
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
        let tar_data = create_test_tar(entries);

        let temp = TempDir::new().unwrap();
        for name in names.iter().take(DUPLICATE_COUNT) {
            std::fs::write(temp.path().join(name), b"already here").unwrap();
        }

        let config = SecurityConfig::default()
            .with_allowed_extensions(vec!["txt".to_string()])
            .validate()
            .expect("valid config");

        let report = TarArchive::new(Cursor::new(tar_data))
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(), // skip_duplicates = true
                &mut NoopProgress,
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
        let tar_data = create_test_tar(vec![("a.txt", b"a"), ("b.exe", b"b")]);
        let dest = tempfile::tempdir().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config"); // empty = allow all

        let report = TarArchive::new(Cursor::new(tar_data))
            .extract(
                dest.path(),
                &config,
                &ExtractionOptions::default(),
                &mut NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 2);
        assert_eq!(report.files_skipped, 0);
    }

    #[test]
    fn test_extension_less_files_blocked_when_allowlist_nonempty() {
        // A file without any extension must be blocked when an allowlist is set.
        let tar_data = create_test_tar(vec![("Makefile", b"all:"), ("keep.txt", b"ok")]);
        let dest = tempfile::tempdir().unwrap();
        let config = SecurityConfig::default()
            .with_allowed_extensions(vec!["txt".to_string()])
            .validate()
            .unwrap();

        let report = TarArchive::new(Cursor::new(tar_data))
            .extract(
                dest.path(),
                &config,
                &ExtractionOptions::default(),
                &mut NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1, "only .txt should be extracted");
        assert_eq!(
            report.files_skipped, 1,
            "extension-less file must be skipped"
        );
        assert!(!dest.path().join("Makefile").exists());
        assert!(dest.path().join("keep.txt").exists());
    }
}
