//! Common extraction utilities shared between archive formats.
//!
//! This module provides shared functionality for TAR and ZIP extractors
//! to avoid code duplication. It is an internal module not exposed in
//! the public API.
//!
//! # Functions
//!
//! - [`extract_file_with_permit`]: Generic file extraction with buffered I/O
//! - [`create_file_with_mode`]: O_NOFOLLOW/O_EXCL-safe file creation, also used
//!   by 7z for its temp file (issues #459, #471)
//! - [`create_directory`]: Directory creation (idempotent)
//! - [`create_symlink`]: Symbolic link creation (Unix only)
//! - [`open_no_follow`]: Read-only open that refuses to follow a symlink
//! - [`is_filesystem_loop_error`]: Detects the `ELOOP` error `open_no_follow`
//!   produces
//! - [`copy_file_content_with_permit`]: Hardlink content copy between
//!   already-open source/destination handles
//! - [`check_extension_allowed`]: Extension allowlist filtering
//! - [`push_disallowed_extension_warning`]: Aggregated disallowed-extension
//!   skip warning

use rustc_hash::FxHashSet;
use std::fs::File;
use std::fs::create_dir_all;
use std::io::BufWriter;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use crate::ArchiveError;
use crate::ExtractionReport;
use crate::ProgressCallback;
use crate::Result;
use crate::SecurityConfig;
use crate::config::Validated;
use crate::copy::CopyBuffer;
use crate::copy::copy_with_buffer;
use crate::error::QuotaResource;
use crate::security::permissions::SanitizedMode;
use crate::security::quota::QuotaPermit;
use crate::types::DestDir;
use crate::types::SafePath;
use crate::types::SafeSymlink;

/// RAII guard that calls `on_entry_complete` when dropped.
///
/// Ensures `on_entry_complete` is always paired with `on_entry_start`, even
/// when extraction fails mid-entry and the caller returns early via `?`.
pub struct EntryCompleteGuard<'a> {
    progress: &'a mut dyn ProgressCallback,
    path: &'a std::path::Path,
    fired: bool,
}

impl<'a> EntryCompleteGuard<'a> {
    /// Creates a new guard. `on_entry_complete` will fire on drop unless
    /// `disarm` is called first.
    pub fn new(progress: &'a mut dyn ProgressCallback, path: &'a std::path::Path) -> Self {
        Self {
            progress,
            path,
            fired: false,
        }
    }

    /// Returns a mutable reference to the underlying progress callback.
    ///
    /// Use this to pass the callback to nested helpers while keeping the guard
    /// in scope for RAII completion.
    pub fn progress_mut(&mut self) -> &mut dyn ProgressCallback {
        self.progress
    }

    /// Fire `on_entry_complete` immediately and prevent the drop from firing
    /// again.
    pub fn complete(mut self) {
        self.progress.on_entry_complete(self.path);
        self.fired = true;
    }
}

impl Drop for EntryCompleteGuard<'_> {
    fn drop(&mut self) {
        if !self.fired {
            self.progress.on_entry_complete(self.path);
        }
    }
}

/// Cache for tracking created directories during extraction.
///
/// Reduces redundant mkdir syscalls for nested archive structures.
/// For example, extracting 1000 files in nested directories without caching
/// can result in ~3000 mkdir syscalls. With caching, this reduces to ~150.
///
/// # Implementation
///
/// Uses an in-memory `FxHashSet<PathBuf>` to track all created directory paths.
/// `FxHashSet` is a faster non-cryptographic hash from rustc, optimized for
/// performance when hash DOS protection is not needed.
///
/// When a directory needs to be created, we first check the cache to avoid
/// redundant syscalls.
///
/// # Performance
///
/// - Reduces syscalls by ~95% for deeply nested archives
/// - Memory overhead: O(d) where d is number of unique directories
/// - Lookup cost: O(1) average with `FxHasher` (faster than `SipHash`)
/// - Default capacity: 128 directories (tunable via `with_capacity`)
///
/// # TOCTOU Safety
///
/// This cache creates a potential Time-Of-Check-Time-Of-Use (TOCTOU) race:
/// another process could delete cached directories between our check and use.
/// However, this is NOT a security concern because:
///
/// 1. **Fail-safe**: If a cached directory is deleted, subsequent file creation
///    will fail with ENOENT, causing extraction to abort cleanly.
/// 2. **No privilege escalation**: Cache only tracks directories we created,
///    not arbitrary filesystem state.
/// 3. **Defense in depth**: Path validation happens before caching (blocks
///    traversal, absolute paths, etc.).
/// 4. **Industry standard**: TAR, ZIP, and other extractors use similar caching
///    without additional synchronization.
///
/// # Future Work
///
/// Potential quota features for future versions:
/// - `max_directory_depth`: Limit nesting depth (`DoS` protection)
/// - `max_unique_directories`: Limit total directory count (memory limit)
///
/// These are deferred because:
/// - Current `max_total_size` quota provides sufficient `DoS` protection
/// - Real-world archives rarely exceed reasonable directory counts
/// - Simpler implementation reduces attack surface
///
/// # Examples
///
/// ```ignore
/// use exarch_core::formats::common::DirCache;
/// use std::path::Path;
///
/// let mut cache = DirCache::new();
///
/// // First call creates directory and caches all ancestors
/// cache.ensure_parent_dir(Path::new("a/b/c/file.txt"))?;
///
/// // Second call skips mkdir - already cached
/// cache.ensure_parent_dir(Path::new("a/b/c/file2.txt"))?;
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug)]
pub struct DirCache {
    created: FxHashSet<PathBuf>,
}

impl DirCache {
    /// Creates a new directory cache with default capacity (128).
    ///
    /// This is sufficient for most archives. Use [`with_capacity`] if you
    /// know the archive has significantly more unique directories.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let cache = DirCache::new();
    /// ```
    ///
    /// [`with_capacity`]: Self::with_capacity
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self::with_capacity(128)
    }

    /// Creates a new directory cache with specified capacity.
    ///
    /// Pre-allocating capacity avoids rehashing during extraction.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // For archives with many unique directories
    /// let cache = DirCache::with_capacity(1000);
    /// ```
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        use rustc_hash::FxBuildHasher;
        Self {
            created: FxHashSet::with_capacity_and_hasher(capacity, FxBuildHasher),
        }
    }

    /// Private helper to cache all ancestor directories of a path.
    ///
    /// This avoids duplicating the ancestor-walking logic in both
    /// `ensure_parent_dir` and `ensure_dir`.
    fn cache_ancestors(&mut self, path: &Path) {
        let mut current = path;
        while !current.as_os_str().is_empty() {
            self.created.insert(current.to_path_buf());
            match current.parent() {
                Some(p) if !p.as_os_str().is_empty() => current = p,
                _ => break,
            }
        }
    }

    /// Checks if a path is in the cache (i.e., was created by us).
    #[inline]
    pub fn contains(&self, path: &Path) -> bool {
        self.created.contains(path)
    }

    /// Ensures parent directory exists, using cache to skip redundant mkdir
    /// calls.
    ///
    /// This function creates the parent directory of the given file path if it
    /// does not exist. All ancestor directories are also created and cached.
    ///
    /// # Performance
    ///
    /// - First call for a directory: Creates directory and caches all ancestors
    /// - Subsequent calls for same directory: O(1) cache lookup, no syscall
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if directory was created
    /// - `Ok(false)` if directory already existed (cached or no parent)
    ///
    /// # Errors
    ///
    /// Returns an I/O error if directory creation fails.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let mut cache = DirCache::new();
    /// let created = cache.ensure_parent_dir(Path::new("a/b/file.txt"))?;
    /// assert!(created); // First call creates directory
    ///
    /// let created = cache.ensure_parent_dir(Path::new("a/b/file2.txt"))?;
    /// assert!(!created); // Second call finds cached directory
    /// ```
    #[inline]
    pub fn ensure_parent_dir(&mut self, file_path: &Path) -> std::io::Result<bool> {
        if let Some(parent) = file_path.parent() {
            if parent.as_os_str().is_empty() {
                return Ok(false);
            }
            if !self.created.contains(parent) {
                create_dir_all(parent)?;
                self.cache_ancestors(parent);
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Ensures a directory exists (for directory entries in archives).
    ///
    /// This function creates the directory if it does not exist. All ancestor
    /// directories are also created and cached.
    ///
    /// # Performance
    ///
    /// - First call for a directory: Creates directory and caches all ancestors
    /// - Subsequent calls for same directory: O(1) cache lookup, no syscall
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if directory was created
    /// - `Ok(false)` if directory already existed (cached or empty path)
    ///
    /// # Errors
    ///
    /// Returns an I/O error if directory creation fails.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let mut cache = DirCache::new();
    /// let created = cache.ensure_dir(Path::new("a/b/c"))?;
    /// assert!(created); // First call creates directory
    ///
    /// let created = cache.ensure_dir(Path::new("a/b/c"))?;
    /// assert!(!created); // Second call finds cached directory
    /// ```
    #[inline]
    pub fn ensure_dir(&mut self, dir_path: &Path) -> std::io::Result<bool> {
        if dir_path.as_os_str().is_empty() {
            return Ok(false);
        }
        if !self.created.contains(dir_path) {
            create_dir_all(dir_path)?;
            self.cache_ancestors(dir_path);
            return Ok(true);
        }
        Ok(false)
    }
}

impl Default for DirCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Normalizes a raw archive entry name by replacing backslashes with forward
/// slashes.
///
/// Windows-created archives (particularly 7z) may embed `\` as a path
/// separator. On Unix, `\` is a valid filename character, so
/// `PathBuf::from("..\\..\\x")` produces a single path component rather than
/// three — bypassing traversal detection. Callers must normalize before
/// constructing a `PathBuf` and passing to `SafePath::validate`.
///
/// This is a no-op for entry names that contain no `\`.
///
/// # Examples
///
/// ```ignore
/// # use exarch_core::formats::common::normalize_entry_name;
/// assert_eq!(normalize_entry_name("foo\\bar\\baz.txt"), "foo/bar/baz.txt");
/// assert_eq!(normalize_entry_name("plain/path.txt"), "plain/path.txt");
/// ```
#[inline]
#[must_use]
pub fn normalize_entry_name(name: &str) -> String {
    if name.contains('\\') {
        name.replace('\\', "/")
    } else {
        name.to_owned()
    }
}

/// Appends a single aggregated warning for `count` skipped duplicate
/// entries, choosing `noun_singular`/`noun_plural` based on `count`.
///
/// Shared by the TAR, ZIP, and 7z extractors (#499) so a single warning is
/// pushed once extraction completes instead of one warning per skipped
/// duplicate. A no-op when `count` is zero.
///
/// # Examples
///
/// ```ignore
/// # use exarch_core::formats::common::push_duplicate_skip_warning;
/// # use exarch_core::ExtractionReport;
/// let mut report = ExtractionReport::new();
/// push_duplicate_skip_warning(&mut report, 3, "entry", "entries");
/// assert_eq!(
///     report.warnings,
///     vec!["skipped 3 entries as pre-existing duplicates".to_string()]
/// );
/// ```
pub fn push_duplicate_skip_warning(
    report: &mut ExtractionReport,
    count: u64,
    noun_singular: &str,
    noun_plural: &str,
) {
    if count > 0 {
        let noun = if count == 1 {
            noun_singular
        } else {
            noun_plural
        };
        report
            .warnings
            .push(format!("skipped {count} {noun} as pre-existing duplicates"));
    }
}

/// Appends a single aggregated warning for `count` entries skipped due to a
/// disallowed extension.
///
/// Mirrors [`push_duplicate_skip_warning`]'s aggregation pattern so
/// `report.warnings` grows once per extraction instead of once per rejected
/// entry (issue #495). A no-op when `count` is zero.
///
/// # Examples
///
/// ```ignore
/// # use exarch_core::formats::common::push_disallowed_extension_warning;
/// # use exarch_core::ExtractionReport;
/// let mut report = ExtractionReport::new();
/// push_disallowed_extension_warning(&mut report, 3);
/// assert_eq!(
///     report.warnings,
///     vec!["skipped 3 entries with disallowed extensions".to_string()]
/// );
/// ```
pub fn push_disallowed_extension_warning(report: &mut ExtractionReport, count: u64) {
    if count > 0 {
        let (noun, ext_noun) = if count == 1 {
            ("entry", "extension")
        } else {
            ("entries", "extensions")
        };
        report
            .warnings
            .push(format!("skipped {count} {noun} with disallowed {ext_noun}"));
    }
}

/// Increments `report.files_skipped`, failing closed with
/// `QuotaExceeded { resource: IntegerOverflow }` instead of wrapping if the
/// counter is already at its maximum.
///
/// Shared by the TAR and ZIP extractors' duplicate-file, duplicate-symlink,
/// and duplicate-hardlink skip paths, which all perform this exact checked
/// increment before recording the skip in their own per-cause counter (issue
/// #518). 7z performs the same guard inline in `sevenz.rs` because it must
/// return a `sevenz_rust2::Error`, not this function's `Result`.
///
/// # Errors
///
/// Returns [`ArchiveError::QuotaExceeded`] with
/// [`QuotaResource::IntegerOverflow`] if `report.files_skipped` is already at
/// its maximum value.
///
/// # Examples
///
/// ```ignore
/// # use exarch_core::formats::common::checked_increment_files_skipped;
/// # use exarch_core::ExtractionReport;
/// let mut report = ExtractionReport::new();
/// checked_increment_files_skipped(&mut report)?;
/// assert_eq!(report.files_skipped, 1);
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
#[inline]
pub fn checked_increment_files_skipped(report: &mut ExtractionReport) -> Result<()> {
    report.files_skipped =
        report
            .files_skipped
            .checked_add(1)
            .ok_or(ArchiveError::QuotaExceeded {
                resource: QuotaResource::IntegerOverflow,
            })?;
    Ok(())
}

/// Returns `true` if `path`'s extension passes `config`'s allowlist.
///
/// If the extension is not allowed, records the skip (increments
/// `report.files_skipped` and `disallowed_extension_skips`) and returns
/// `false`. Shared by the TAR, ZIP, and 7z extractors, which all reject
/// entries with disallowed extensions before further validation.
///
/// This is the single source of truth for the extension-allowlist skip
/// check: do not re-inline this pattern at a new call site (this helper
/// exists because the pattern already drifted once for the FFI boundary
/// path check in #406 — see #413).
///
/// # Aggregated Warning (issue #495)
///
/// `path` is deliberately not recorded anywhere: earlier versions pushed one
/// path-bearing warning string per rejected entry, which grew
/// `report.warnings` without bound for archives with many disallowed
/// entries. The caller instead increments `disallowed_extension_skips` and
/// aggregates it into a single [`push_disallowed_extension_warning`] once
/// extraction completes, mirroring the `duplicate_skips` pattern used by
/// [`push_duplicate_skip_warning`].
///
/// # Examples
///
/// ```ignore
/// # use exarch_core::formats::common::check_extension_allowed;
/// if !check_extension_allowed(&path, config, report, &mut disallowed_extension_skips) {
///     return Ok(None);
/// }
/// ```
#[must_use]
#[inline]
pub fn check_extension_allowed(
    path: &Path,
    config: &SecurityConfig<Validated>,
    report: &mut ExtractionReport,
    disallowed_extension_skips: &mut u64,
) -> bool {
    let ext = path.extension().and_then(|e| e.to_str());
    if config.is_path_extension_allowed(ext) {
        return true;
    }

    report.files_skipped = report.files_skipped.saturating_add(1);
    *disallowed_extension_skips = disallowed_extension_skips.saturating_add(1);
    false
}

/// Creates a file with permissions enforced after creation to bypass umask.
///
/// On Unix platforms, this function uses `OpenOptions::mode()` to hint the
/// desired mode during `open()`, then calls `File::set_permissions()` on the
/// already-open file descriptor (`fchmod`) to enforce the exact sanitized
/// mode. The second call is required because `OpenOptions::mode()` is
/// subject to the process umask and the resulting permissions may be
/// narrower than requested. Operating on the open descriptor rather than
/// `std::fs::set_permissions(path, ..)` avoids re-resolving `path` from the
/// filesystem root a second time, which would otherwise reopen a TOCTOU
/// window between file creation and permission enforcement (issue #460).
///
/// On non-Unix platforms, permissions are not supported and mode is ignored.
///
/// When `create_new` is `true`, the file is opened with `O_EXCL` semantics
/// (`OpenOptions::create_new`): the call atomically fails with
/// `ErrorKind::AlreadyExists` if `path` already exists, instead of truncating
/// it. This folds the caller's duplicate-detection into the `open()` syscall
/// itself rather than requiring a separate `exists()` stat beforehand.
///
/// # Security - Symlink-at-Destination Rejection (issue #459)
///
/// On Unix, every open passes `O_NOFOLLOW`: if `path`'s final component is a
/// symlink (dangling or not — planted by something other than this
/// extraction, since `SafeSymlink::validate` already prevents an in-archive
/// symlink entry from escaping `dest`), the call fails with `ELOOP` instead
/// of following the link. Without this, `path.exists()` (used by the old,
/// now-removed pre-check) returns `false` for a dangling symlink, and a plain
/// `File::create` follows it, writing archive content outside the
/// extraction root. `create_new`'s `O_EXCL` already rejects any existing
/// path including symlinks, so `O_NOFOLLOW` is redundant there; it is the
/// only guard on the `create`+`truncate` (`create_new = false`) branch.
///
/// # Performance
///
/// - Unix, `mode.is_some()`: 2 syscalls (`open` with mode hint + `fchmod` to
///   bypass umask)
/// - Unix, `mode.is_none()`: 1 syscall (`open`, no permission enforcement to
///   perform)
/// - Non-Unix: 1 syscall (`open`)
///
/// # Security - Mode Sanitization Requirement
///
/// **CRITICAL**: This function trusts the caller to provide safe mode values.
/// The `mode` parameter MUST be sanitized before calling this function to:
///
/// - Strip setuid bit (0o4000) if required by security policy
/// - Strip setgid bit (0o2000) if required by security policy
/// - Strip sticky bit (0o1000) if required by security policy
/// - Ensure world-writable permissions are only set if allowed
///
/// The [`SanitizedMode`] parameter type enforces mode sanitization at
/// compile time: only
/// [`sanitize_permissions`](crate::security::sanitize_permissions)
/// can construct one, so a raw, unsanitized mode read from an archive header
/// cannot reach this function by mistake.
///
/// # Arguments
///
/// * `path` - Path where file should be created
/// * `mode` - Optional pre-sanitized Unix file mode
/// * `create_new` - If `true`, fail with `AlreadyExists` instead of truncating
///   an existing file at `path`
///
/// # Errors
///
/// Returns an I/O error if file creation fails, including
/// `ErrorKind::AlreadyExists` when `create_new` is `true` and `path` already
/// exists, or `ELOOP` (via `custom_flags(O_NOFOLLOW)`) when `path`'s final
/// component is a symlink on any branch.
#[inline]
#[cfg(unix)]
pub fn create_file_with_mode(
    path: &Path,
    mode: Option<SanitizedMode>,
    create_new: bool,
) -> std::io::Result<File> {
    use std::fs::OpenOptions;
    use std::fs::Permissions;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;

    let mut opts = OpenOptions::new();
    opts.write(true);
    // O_NOFOLLOW rejects a symlink at `path` on every branch (issue #459);
    // `create_new`'s O_EXCL already implies this, but the create+truncate
    // branch below has no other protection against a planted symlink.
    opts.custom_flags(libc::O_NOFOLLOW);
    if create_new {
        opts.create_new(true);
    } else {
        opts.create(true).truncate(true);
    }

    if let Some(m) = mode {
        // Apply sanitized mode during open (already stripped setuid/setgid)
        opts.mode(m.as_u32());
    }

    let file = opts.open(path)?;

    // OpenOptions::mode() is subject to the process umask, which may reduce
    // the requested permissions. Call set_permissions() explicitly to enforce
    // the exact sanitized mode, bypassing umask. Applied to the already-open
    // file descriptor (fchmod) rather than std::fs::set_permissions(path, ..),
    // which would re-resolve path from the filesystem root and reopen a
    // TOCTOU window between this open() and the permission change (issue
    // #460).
    if let Some(m) = mode {
        file.set_permissions(Permissions::from_mode(m.as_u32()))?;
    }

    Ok(file)
}

/// Creates a file (non-Unix platforms ignore mode parameter).
///
/// This is the fallback implementation for platforms that do not support
/// Unix-style file permissions.
///
/// # Arguments
///
/// * `path` - Path where file should be created
/// * `_mode` - Ignored on non-Unix platforms
/// * `create_new` - If `true`, fail with `AlreadyExists` instead of truncating
///   an existing file at `path`
///
/// # Errors
///
/// Returns an I/O error if file creation fails, including
/// `ErrorKind::AlreadyExists` when `create_new` is `true` and `path` already
/// exists.
#[inline]
#[cfg(not(unix))]
pub fn create_file_with_mode(
    path: &Path,
    _mode: Option<SanitizedMode>,
    create_new: bool,
) -> std::io::Result<File> {
    if create_new {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
    } else {
        File::create(path)
    }
}

/// Generic file extraction implementation used by all format adapters.
///
/// This function consolidates file extraction logic to ensure consistent:
/// - Directory creation with caching
/// - Buffered I/O (64KB buffer)
/// - Exclusive file creation with permission enforcement (Unix only)
/// - Quota tracking with overflow protection
/// - A hard streaming ceiling on `expected_size`, so a forged declared size
///   cannot decouple what was quota-checked from what is actually written
///
/// # Security - Streaming Size Enforcement (GHSA-5j8q-wxg5-hj4r)
///
/// `expected_size` is the same declared size the caller already used for
/// compression-ratio and quota validation — metadata read from the archive,
/// not measured from real bytes. This function does not merely trust it a
/// second time: it is threaded into [`copy_with_buffer`] as a hard ceiling
/// enforced on every buffered read, so a forged small `expected_size` cannot
/// let the real decompressed stream grow unbounded, and a short stream (less
/// than declared) is rejected once it reaches EOF. On either violation, the
/// partially-written file is removed via [`TempFileGuard`] before the error
/// propagates — a rejected entry never leaves oversized or truncated content
/// on disk.
///
/// # Permission Enforcement
///
/// On Unix, file permissions are enforced via `File::set_permissions()` on
/// the already-open file descriptor (`fchmod`), not a path-based
/// `std::fs::set_permissions()` call, to bypass the process umask without
/// reopening a TOCTOU window between file creation and permission
/// enforcement (issue #460). This ensures the exact sanitized mode from
/// `SecurityConfig` is applied, regardless of the caller's umask. See
/// [`create_file_with_mode`] for the full contract.
///
/// # Correctness
///
/// The quota charge for this entry already happened during
/// `EntryValidator::validate_entry`, proven by the [`QuotaPermit`] passed in
/// by value: a `QuotaPermit` is neither `Clone` nor `Copy`, so this function
/// cannot be called at all without the caller having moved a genuine permit
/// out of a `ValidatedEntryType::File` via [`ValidatedEntry::into_parts`]
/// (mirrors 7z's `write_file_with_permit`, issue #445). This guards
/// `report.bytes_written` against overflow before writing.
///
/// [`ValidatedEntry::into_parts`]: crate::security::validator::ValidatedEntry::into_parts
///
/// # Type Parameters
///
/// - `R`: Reader type that implements `Read`
///
/// # Arguments
///
/// * `reader` - Source data stream
/// * `safe_path` - Validated destination-relative path
/// * `mode` - Sanitized Unix file mode, if any
/// * `_permit` - Proof that this file's size was already reserved against the
///   quota tracker; consumed by value and otherwise unused
/// * `dest` - Destination directory
/// * `report` - Extraction statistics (updated)
/// * `expected_size` - Declared uncompressed size (if known); used for the
///   quota pre-check and, per the security note above, enforced as a hard
///   streaming ceiling and exact post-copy match
/// * `copy_buffer` - Reusable buffer for I/O operations
/// * `dir_cache` - Directory cache to reduce redundant mkdir syscalls
/// * `duplicate_skips` - Counter incremented (not pushed as a warning string)
///   when a duplicate entry is skipped; the caller aggregates it into a single
///   warning after extraction completes, mirroring 7z's `duplicate_skips`
///   accumulator (issue #490)
///
/// # Errors
///
/// Returns error if:
/// - Parent directory creation fails
/// - Quota would be exceeded (checked before write)
/// - File creation fails
/// - I/O error during copy
/// - `expected_size` is `Some` and the actual decompressed byte count exceeds
///   or falls short of it (forged size metadata)
#[allow(clippy::too_many_arguments)]
#[inline]
pub fn extract_file_with_permit<R: Read>(
    reader: &mut R,
    safe_path: &SafePath,
    mode: Option<SanitizedMode>,
    _permit: QuotaPermit,
    dest: &DestDir,
    report: &mut ExtractionReport,
    expected_size: Option<u64>,
    copy_buffer: &mut CopyBuffer,
    dir_cache: &mut DirCache,
    skip_duplicates: bool,
    duplicate_skips: &mut u64,
    progress: &mut dyn ProgressCallback,
) -> Result<()> {
    let output_path = dest.join(safe_path);

    // Create parent directories if needed using cache
    dir_cache.ensure_parent_dir(&output_path)?;

    // The size was already reserved against QuotaTracker during
    // validate_entry (proven by the QuotaPermit consumed above); this only
    // guards report.bytes_written, a different quantity, against overflow.
    // Checked before any filesystem mutation so a rejected entry never
    // leaves a zero-byte file on disk (restores the pre-#446 ordering).
    if let Some(size) = expected_size {
        report
            .bytes_written
            .checked_add(size)
            .ok_or(ArchiveError::QuotaExceeded {
                resource: QuotaResource::IntegerOverflow,
            })?;
    }

    // Folds the duplicate-existence check into the open() syscall itself
    // (create_new(true) atomically fails with AlreadyExists) instead of a
    // separate exists() stat followed by a truncating create — one syscall
    // per extracted file instead of two.
    let output_file = match create_file_with_mode(&output_path, mode, skip_duplicates) {
        Ok(file) => file,
        Err(e) if skip_duplicates && e.kind() == std::io::ErrorKind::AlreadyExists => {
            checked_increment_files_skipped(report)?;
            *duplicate_skips = duplicate_skips.saturating_add(1);
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    // SECURITY: guards against leaving a partial file on disk when
    // copy_with_buffer aborts mid-stream because expected_size was forged
    // (GHSA-5j8q-wxg5-hj4r) — the `?` below returns before `persist()` runs,
    // so the guard's Drop removes whatever was written so far.
    //
    // Only armed when `skip_duplicates` is true: that is exactly the branch
    // where `create_file_with_mode` used `create_new(true)` above, so
    // `output_path` is guaranteed to have held nothing before this call and
    // deleting it on abort loses nothing. When `skip_duplicates` is false
    // (`--force`/overwrite), `create_file_with_mode` already truncated a
    // possibly pre-existing file in place before any of this ran — deleting
    // that truncated stub on abort would be new behavior this security fix
    // has no reason to introduce (unlike 7z's temp+rename, TAR/ZIP's
    // in-place overwrite was never atomic; restoring the original on failure
    // would need that same restructuring, tracked separately, not folded
    // into this patch).
    let guard = skip_duplicates.then(|| TempFileGuard::new(output_path));
    let mut buffered_writer = BufWriter::with_capacity(64 * 1024, output_file);
    let bytes_written = copy_with_buffer(reader, &mut buffered_writer, copy_buffer, expected_size)?;
    buffered_writer.flush()?;
    if let Some(guard) = guard {
        guard.persist();
    }

    if bytes_written > 0 {
        progress.on_bytes_written(bytes_written);
    }

    report.files_extracted += 1;
    report.bytes_written =
        report
            .bytes_written
            .checked_add(bytes_written)
            .ok_or(ArchiveError::QuotaExceeded {
                resource: QuotaResource::IntegerOverflow,
            })?;

    Ok(())
}

/// Creates a directory from a validated entry.
///
/// This is a shared helper used by both TAR and ZIP extractors.
///
/// # Idempotent Behavior
///
/// This function is idempotent - calling it multiple times for the same
/// directory has no effect thanks to the directory cache.
///
/// # Quota Tracking
///
/// Directory creation increments the `directories_created` counter but
/// does NOT count toward the byte quota (`bytes_written`). Only regular
/// file data counts toward byte quotas.
///
/// # Arguments
///
/// * `safe_path` - Validated destination-relative path of the directory
/// * `dest` - Destination directory
/// * `report` - Extraction statistics (updated)
/// * `dir_cache` - Directory cache to reduce redundant mkdir syscalls
///
/// # Errors
///
/// Returns an error if directory creation fails due to I/O errors.
pub fn create_directory(
    safe_path: &SafePath,
    dest: &DestDir,
    report: &mut ExtractionReport,
    dir_cache: &mut DirCache,
) -> Result<()> {
    let dir_path = dest.join(safe_path);

    // Use cache to avoid redundant mkdir syscalls
    dir_cache.ensure_dir(&dir_path)?;

    report.directories_created += 1;

    Ok(())
}

/// Creates a symbolic link from a validated symlink entry.
///
/// This is a shared helper used by both TAR and ZIP extractors.
/// Parent directories are created automatically if needed using the directory
/// cache.
///
/// # Platform Support
///
/// - **Unix**: Full symlink support via `std::os::unix::fs::symlink`
/// - **Other platforms**: Returns `SecurityViolation` error
///
/// # Error Behavior
///
/// If the symlink already exists, the function will fail with an I/O error.
/// Unlike `create_directory`, this function is NOT idempotent - it does not
/// overwrite existing symlinks or files at the target path.
///
/// # Arguments
///
/// * `safe_symlink` - Validated symlink entry
/// * `dest` - Destination directory
/// * `report` - Extraction statistics (updated)
/// * `dir_cache` - Directory cache to reduce redundant mkdir syscalls
/// * `duplicate_skips` - Counter incremented (not pushed as a warning string)
///   when a duplicate symlink is skipped; the caller aggregates it into a
///   single warning after extraction completes, mirroring 7z's
///   `duplicate_skips` accumulator (issue #490)
///
/// # Errors
///
/// Returns an error if:
/// - Platform does not support symlinks
/// - Parent directory creation fails
/// - Symlink creation fails (including when target path already exists)
/// - Removing an existing path fails when `skip_duplicates` is false
#[allow(unused_variables)]
pub fn create_symlink(
    safe_symlink: &SafeSymlink,
    dest: &DestDir,
    report: &mut ExtractionReport,
    dir_cache: &mut DirCache,
    skip_duplicates: bool,
    duplicate_skips: &mut u64,
) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let link_path = dest.join_path(safe_symlink.link_path());
        let target_path = safe_symlink.target_path();

        // Create parent directories using cache
        dir_cache.ensure_parent_dir(&link_path)?;

        if link_path.symlink_metadata().is_ok() {
            if skip_duplicates {
                checked_increment_files_skipped(report)?;
                *duplicate_skips = duplicate_skips.saturating_add(1);
                return Ok(());
            }
            std::fs::remove_file(&link_path)?;
        }

        // Create symlink
        symlink(target_path, &link_path)?;

        report.symlinks_created += 1;

        Ok(())
    }

    #[cfg(not(unix))]
    {
        Err(ArchiveError::SecurityViolation {
            reason: "symlinks are not supported on this platform".into(),
        })
    }
}

/// Opens `path` for reading, refusing to follow a symlink at its final path
/// component.
///
/// # Security - Hardlink-Target TOCTOU Rejection (issue #467)
///
/// A hardlink's target is validated for containment in an earlier pass
/// (`HardlinkTracker::validate_hardlink`, resolving on-disk symlinks as of
/// that point in time) but nothing re-validates it by the time a later pass
/// actually reads it — a plain `File::open` at that point would silently
/// follow whatever is at the target path *then*, which given an
/// attacker-writable destination directory may no longer be what the
/// earlier pass validated. On Unix, this is closed with `O_NOFOLLOW`: the
/// open fails instead of following a symlink planted or swapped in at the
/// target path since. Callers should reserve quota and copy from the
/// returned handle rather than re-opening `path`, to avoid a TOCTOU window
/// between a path-based size check and a separate path-based read. A symlink
/// at `path` is not automatically an attack, though — see
/// [`resolve_through_symlinks`](crate::types::safe_symlink::resolve_through_symlinks)
/// for the re-validation callers should perform on `ErrorKind::FilesystemLoop`
/// before treating it as one.
///
/// This mitigation is Unix-only: non-Unix platforms have no `O_NOFOLLOW`
/// equivalent wired up here, so the TOCTOU window this closes on Unix
/// remains open on those platforms.
///
/// # Errors
///
/// Returns an I/O error if `path` does not exist, is a symlink (Unix only,
/// via `ELOOP`), or otherwise cannot be opened for reading.
pub fn open_no_follow(path: &Path) -> std::io::Result<File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }

    opts.open(path)
}

/// Returns `true` if `error` is the "too many levels of symbolic links"
/// error (`ELOOP` on Unix) that [`open_no_follow`] produces when its final
/// path component is a symlink.
///
/// `std::io::ErrorKind::FilesystemLoop` exists for exactly this case but is
/// not yet stable (`io_error_more`, rust-lang/rust#86442 as of this crate's
/// MSRV), so this compares the raw OS error code directly on Unix. Always
/// `false` on non-Unix, since [`open_no_follow`] has no `O_NOFOLLOW`
/// equivalent there and cannot produce this specific error.
#[must_use]
pub fn is_filesystem_loop_error(error: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(libc::ELOOP)
    }
    #[cfg(not(unix))]
    {
        let _ = error;
        false
    }
}

/// Copies a hardlink target's bytes from an already-open source handle into
/// an already-open destination handle, consuming the [`QuotaPermit`] that
/// authorized the copy.
///
/// Taking `permit` by value ensures a reservation can be spent at most once:
/// `QuotaPermit` is neither `Clone` nor `Copy`, so the caller cannot retain
/// it to pass to a second copy.
///
/// # Security - Symlink Rejection and Quota TOCTOU (issue #467)
///
/// Unlike `std::fs::copy(from, to)`, both `from` and `to` are already-open
/// [`File`] handles rather than paths. Callers obtain `to` via
/// `OpenOptions::create_new` (refusing to create through a pre-existing
/// destination path, symlink or not) and `from` via [`open_no_follow`]
/// (refusing to follow a symlink at the source path), and reserve quota from
/// `from`'s already-open `fstat`, not a separate path-based `stat`. Passing
/// paths instead would both re-expose the symlink-follow read this function
/// exists to prevent, and reopen a TOCTOU window where the reserved size and
/// the actually-copied bytes come from two different filesystem objects.
///
/// On Unix, `from`'s permission bits are copied to `to` afterward, matching
/// `std::fs::copy`'s behavior. `from`'s permissions were already sanitized
/// when the target file was extracted as a regular file (setuid/setgid
/// stripped), so re-applying them to the brand-new `to` here does not
/// reintroduce anything unsanitized.
///
/// # Errors
///
/// Returns an I/O error if the copy or (on Unix) applying permissions fails.
pub fn copy_file_content_with_permit(
    mut from: File,
    mut to: File,
    _permit: QuotaPermit,
) -> std::io::Result<u64> {
    let bytes_copied = std::io::copy(&mut from, &mut to)?;

    #[cfg(unix)]
    {
        let permissions = from.metadata()?.permissions();
        to.set_permissions(permissions)?;
    }

    Ok(bytes_copied)
}

/// RAII guard that removes a file at `path` when dropped, unless [`persist`]
/// was called first.
///
/// Shared between TAR's hardlink-content copy and 7z's temp-file-then-rename
/// write path so a fallible step between file creation and the operation's
/// success point (quota reservation, the copy itself) does not leave a
/// partial artifact behind on the error path.
///
/// [`persist`]: TempFileGuard::persist
pub struct TempFileGuard {
    path: PathBuf,
    should_cleanup: bool,
}

impl TempFileGuard {
    /// Creates a new guard that will remove `path` on drop.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            should_cleanup: true,
        }
    }

    /// Marks the file as successfully processed, preventing cleanup on drop.
    pub fn persist(mut self) {
        self.should_cleanup = false;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if self.should_cleanup {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::ArchiveError;
    use crate::ExtractionReport;
    use crate::NoopProgress;
    use crate::SecurityConfig;
    use crate::copy::CopyBuffer;
    use crate::security::permissions::sanitize_permissions;
    use crate::security::quota::QuotaTracker;
    use std::assert_matches;
    use std::io::Cursor;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Builds a [`SanitizedMode`] for tests that don't otherwise need a
    /// `SecurityConfig` in scope. None of the modes used across these tests
    /// carry setuid/setgid/world-writable bits, so sanitizing with the
    /// default config never changes the value.
    fn sanitized(mode: u32) -> SanitizedMode {
        let config = SecurityConfig::default().validate().expect("valid config");
        sanitize_permissions(mode, &config)
    }

    #[test]
    fn test_extract_file_with_permit_integer_overflow_check() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let mut report = ExtractionReport::default();
        let mut copy_buffer = CopyBuffer::new();
        let mut dir_cache = DirCache::new();

        // Set bytes_written to a value close to u64::MAX
        report.bytes_written = u64::MAX - 100;

        // Try to extract a file with size that would overflow
        let expected_size = Some(200u64); // This would overflow when added

        let config = SecurityConfig::default().validate().expect("valid config");
        let permit = QuotaTracker::new()
            .reserve(0, &config)
            .expect("reservation should succeed");
        let safe_path = SafePath::validate(&PathBuf::from("test.txt"), &dest, &config)
            .expect("path should be valid");

        let mut reader = Cursor::new(b"test data");

        let result = extract_file_with_permit(
            &mut reader,
            &safe_path,
            Some(sanitized(0o644)),
            permit,
            &dest,
            &mut report,
            expected_size,
            &mut copy_buffer,
            &mut dir_cache,
            true,
            &mut 0u64,
            &mut NoopProgress,
        );

        // Should return QuotaExceeded with IntegerOverflow
        assert!(result.is_err());
        assert_matches!(
            result.unwrap_err(),
            ArchiveError::QuotaExceeded {
                resource: QuotaResource::IntegerOverflow
            }
        );
        // The overflow check now runs before the file is created (issue
        // #446 review): a rejected entry must not leave a zero-byte file on
        // disk.
        assert!(
            !temp.path().join("test.txt").exists(),
            "overflow-rejected entry must not touch the filesystem"
        );
    }

    /// Regression test for #515: `files_skipped` must fail closed with
    /// `QuotaExceeded { resource: IntegerOverflow }` instead of wrapping (or
    /// panicking, in debug builds) once it reaches `usize::MAX`, mirroring
    /// `test_extract_file_with_permit_integer_overflow_check` for
    /// `bytes_written`.
    #[test]
    fn test_extract_file_with_permit_files_skipped_overflow_check() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let mut report = ExtractionReport::default();
        let mut copy_buffer = CopyBuffer::new();
        let mut dir_cache = DirCache::new();
        let mut duplicate_skips = 0u64;

        // Set files_skipped to usize::MAX so the duplicate-skip path's
        // increment would overflow.
        report.files_skipped = usize::MAX;

        let config = SecurityConfig::default().validate().expect("valid config");
        let permit = QuotaTracker::new()
            .reserve(0, &config)
            .expect("reservation should succeed");
        let safe_path = SafePath::validate(&PathBuf::from("test.txt"), &dest, &config)
            .expect("path should be valid");

        // Pre-create the destination file so create_file_with_mode's
        // create_new(true) hits AlreadyExists, taking the duplicate-skip
        // branch that increments files_skipped.
        std::fs::write(temp.path().join("test.txt"), b"existing").expect("failed to seed file");

        let mut reader = Cursor::new(b"test data");

        let result = extract_file_with_permit(
            &mut reader,
            &safe_path,
            Some(sanitized(0o644)),
            permit,
            &dest,
            &mut report,
            None,
            &mut copy_buffer,
            &mut dir_cache,
            true,
            &mut duplicate_skips,
            &mut NoopProgress,
        );

        assert!(result.is_err());
        assert_matches!(
            result.unwrap_err(),
            ArchiveError::QuotaExceeded {
                resource: QuotaResource::IntegerOverflow
            }
        );
    }

    /// Regression test for GHSA-5j8q-wxg5-hj4r: a reader that produces far
    /// more bytes than the entry's declared `expected_size` (the
    /// proof-of-concept shape — a ZIP local/central-directory header lying
    /// about `uncompressed_size`) must abort extraction with a security
    /// error and must not leave an oversized (or any) file behind on disk.
    #[test]
    fn test_extract_file_with_permit_forged_size_aborts_and_cleans_up() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let mut report = ExtractionReport::default();
        let mut copy_buffer = CopyBuffer::new();
        let mut dir_cache = DirCache::new();

        let config = SecurityConfig::default().validate().expect("valid config");
        // Declares 50 bytes, mirroring the PoC's forged uncompressed_size.
        let permit = QuotaTracker::new()
            .reserve(50, &config)
            .expect("reservation should succeed");
        let safe_path = SafePath::validate(&PathBuf::from("bomb.txt"), &dest, &config)
            .expect("path should be valid");

        // The "decompressed" stream actually produces far more than declared.
        let real_data = vec![0x41u8; 200 * 1024];
        let mut reader = Cursor::new(&real_data);

        let result = extract_file_with_permit(
            &mut reader,
            &safe_path,
            Some(sanitized(0o644)),
            permit,
            &dest,
            &mut report,
            Some(50),
            &mut copy_buffer,
            &mut dir_cache,
            true,
            &mut 0u64,
            &mut NoopProgress,
        );

        assert_matches!(
            result,
            Err(ArchiveError::SecurityViolation { .. }),
            "streaming past the declared size must abort with a security error, got: {result:?}"
        );
        assert!(
            !temp.path().join("bomb.txt").exists(),
            "aborted extraction must not leave a partial or oversized file on disk"
        );
    }

    /// A stream that ends short of its declared `expected_size` is rejected
    /// too, and the partial file it produced is removed rather than left
    /// truncated on disk.
    #[test]
    fn test_extract_file_with_permit_undersized_stream_cleans_up() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let mut report = ExtractionReport::default();
        let mut copy_buffer = CopyBuffer::new();
        let mut dir_cache = DirCache::new();

        let config = SecurityConfig::default().validate().expect("valid config");
        let permit = QuotaTracker::new()
            .reserve(1000, &config)
            .expect("reservation should succeed");
        let safe_path = SafePath::validate(&PathBuf::from("short.txt"), &dest, &config)
            .expect("path should be valid");

        let mut reader = Cursor::new(b"too short");

        let result = extract_file_with_permit(
            &mut reader,
            &safe_path,
            Some(sanitized(0o644)),
            permit,
            &dest,
            &mut report,
            Some(1000),
            &mut copy_buffer,
            &mut dir_cache,
            true,
            &mut 0u64,
            &mut NoopProgress,
        );

        assert_matches!(
            result,
            Err(ArchiveError::SecurityViolation { .. }),
            "actual size short of declared size must be rejected, got: {result:?}"
        );
        assert!(
            !temp.path().join("short.txt").exists(),
            "rejected entry must not leave a truncated file on disk"
        );
    }

    /// Security-review follow-up for GHSA-5j8q-wxg5-hj4r: with
    /// `skip_duplicates = false` (`--force`), a pre-existing destination
    /// file must not be *deleted* by an aborted forged-size entry. The
    /// `TempFileGuard` added for the streaming ceiling is only armed when
    /// this call created the file itself (`skip_duplicates = true`,
    /// `create_new`); the overwrite branch already truncated the
    /// pre-existing file in place before any size check ran (pre-existing,
    /// non-atomic behavior this security fix does not change), so on abort
    /// the truncated file is left as-is rather than additionally deleted.
    #[test]
    fn test_extract_file_with_permit_force_overwrite_forged_size_does_not_delete_destination() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let mut report = ExtractionReport::default();
        let mut copy_buffer = CopyBuffer::new();
        let mut dir_cache = DirCache::new();

        // Pre-existing destination file, as if from a prior extraction.
        std::fs::write(temp.path().join("target.txt"), b"pre-existing content")
            .expect("failed to seed file");

        let config = SecurityConfig::default().validate().expect("valid config");
        let permit = QuotaTracker::new()
            .reserve(50, &config)
            .expect("reservation should succeed");
        let safe_path = SafePath::validate(&PathBuf::from("target.txt"), &dest, &config)
            .expect("path should be valid");

        let real_data = vec![0x41u8; 200 * 1024];
        let mut reader = Cursor::new(&real_data);

        let result = extract_file_with_permit(
            &mut reader,
            &safe_path,
            Some(sanitized(0o644)),
            permit,
            &dest,
            &mut report,
            Some(50),
            &mut copy_buffer,
            &mut dir_cache,
            false, // skip_duplicates = false: --force overwrite
            &mut 0u64,
            &mut NoopProgress,
        );

        assert_matches!(result, Err(ArchiveError::SecurityViolation { .. }));
        assert!(
            temp.path().join("target.txt").exists(),
            "aborted --force overwrite must not delete the destination path entirely"
        );
    }

    /// Test `DirCache` basic functionality
    #[test]
    fn test_dir_cache_basic() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let mut cache = DirCache::new();

        let file_path = temp.path().join("a/b/c/file.txt");

        // First call creates directory
        let created = cache
            .ensure_parent_dir(&file_path)
            .expect("should create dir");
        assert!(created, "first call should create directory");
        assert!(temp.path().join("a/b/c").exists());

        // Second call finds cached directory
        let created = cache
            .ensure_parent_dir(&file_path)
            .expect("should use cache");
        assert!(!created, "second call should use cache");
    }

    /// Test `DirCache` with nested paths
    #[test]
    fn test_dir_cache_nested_paths() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let mut cache = DirCache::new();

        // Create deep nested directory
        let file1 = temp.path().join("a/b/c/d/file1.txt");
        cache.ensure_parent_dir(&file1).expect("should create");
        assert!(temp.path().join("a/b/c/d").exists());

        // All ancestors should be cached
        let file2 = temp.path().join("a/b/other.txt");
        let created = cache.ensure_parent_dir(&file2).expect("should use cache");
        assert!(!created, "ancestor should be cached");
    }

    /// Test `DirCache` `ensure_dir` method
    #[test]
    fn test_dir_cache_ensure_dir() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let mut cache = DirCache::new();

        let dir_path = temp.path().join("a/b/c");

        // First call creates directory
        let created = cache.ensure_dir(&dir_path).expect("should create dir");
        assert!(created, "first call should create directory");
        assert!(dir_path.exists());

        // Second call finds cached directory
        let created = cache.ensure_dir(&dir_path).expect("should use cache");
        assert!(!created, "second call should use cache");
    }

    /// Test `DirCache` with empty parent path
    #[test]
    fn test_dir_cache_empty_parent() {
        use std::path::PathBuf;
        let mut cache = DirCache::new();

        // Relative file path with no parent directory
        let file_path = PathBuf::from("file.txt");
        let created = cache
            .ensure_parent_dir(&file_path)
            .expect("should handle empty parent");
        assert!(!created, "file with no directory should return false");
    }

    /// Test `DirCache` with single component path
    #[test]
    fn test_dir_cache_single_component() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let mut cache = DirCache::new();

        // Path with single component (no parent except current dir)
        let file_path = temp.path().join("file.txt");
        let created = cache
            .ensure_parent_dir(&file_path)
            .expect("should handle single component");

        // Parent is temp.path(), which was not in cache, so it gets
        // created/cached
        assert!(created, "parent directory gets cached on first call");

        // Second call should use cache
        let file_path2 = temp.path().join("file2.txt");
        let created = cache
            .ensure_parent_dir(&file_path2)
            .expect("should use cache");
        assert!(!created, "second call uses cached parent");
    }

    /// Test `DirCache` with pre-existing directory
    #[test]
    fn test_dir_cache_preexisting_directory() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let mut cache = DirCache::new();

        // Create directory manually first
        let dir_path = temp.path().join("existing/dir");
        std::fs::create_dir_all(&dir_path).expect("should create dir");

        // First call should still return true (not in cache)
        let created = cache.ensure_dir(&dir_path).expect("should succeed");
        assert!(created, "first call creates cache entry even if dir exists");

        // Second call should return false (cached)
        let created = cache.ensure_dir(&dir_path).expect("should succeed");
        assert!(!created, "second call uses cache");
    }

    /// Test `DirCache` with deep nesting (stress test)
    #[test]
    fn test_dir_cache_deep_nesting() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let mut cache = DirCache::new();

        // Create path with 100 levels of nesting
        let mut path = temp.path().to_path_buf();
        for i in 0..100 {
            path.push(format!("level{i}"));
        }
        path.push("file.txt");

        // First call creates all 100 levels
        let created = cache
            .ensure_parent_dir(&path)
            .expect("should create deep nesting");
        assert!(created, "deep nesting should be created");

        // Verify all levels exist
        let parent = path.parent().expect("should have parent");
        assert!(parent.exists(), "all levels should exist");

        // Second call should use cache
        let created = cache.ensure_parent_dir(&path).expect("should use cache");
        assert!(!created, "deep nesting should be cached");
    }

    /// Test `DirCache` with multiple files in same directory
    #[test]
    fn test_dir_cache_multiple_files_same_dir() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let mut cache = DirCache::new();

        let dir = temp.path().join("shared/directory");

        // First file creates directory
        let file1 = dir.join("file1.txt");
        let created = cache.ensure_parent_dir(&file1).expect("should create dir");
        assert!(created, "first file creates directory");

        // Subsequent files in same directory use cache
        for i in 2..=10 {
            let file = dir.join(format!("file{i}.txt"));
            let created = cache.ensure_parent_dir(&file).expect("should use cache");
            assert!(!created, "file {i} should use cached directory");
        }
    }

    /// Test `DirCache::with_capacity` constructor
    #[test]
    fn test_dir_cache_with_capacity() {
        let cache = DirCache::with_capacity(1000);
        // Just verify it constructs without panic
        assert_eq!(cache.created.len(), 0, "should start empty");
    }

    /// Test `DirCache::contains` method
    #[test]
    fn test_dir_cache_contains() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let mut cache = DirCache::new();

        let dir_path = temp.path().join("a/b/c");

        // Before creation, should not contain
        assert!(
            !cache.contains(&dir_path),
            "should not contain before creation"
        );

        // Create directory
        cache.ensure_dir(&dir_path).expect("should create dir");

        // After creation, should contain
        assert!(cache.contains(&dir_path), "should contain after creation");

        // Ancestors should also be cached
        assert!(
            cache.contains(&temp.path().join("a/b")),
            "ancestor should be cached"
        );
        assert!(
            cache.contains(&temp.path().join("a")),
            "ancestor should be cached"
        );
    }

    /// H1: Test `create_file_with_mode()` with Unix mode 0o644
    #[cfg(unix)]
    #[test]
    fn test_create_file_with_mode_0o644() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("failed to create temp dir");
        let file_path = temp.path().join("test_0o644.txt");

        // Create file with mode 0o644
        let file = create_file_with_mode(&file_path, Some(sanitized(0o644)), false)
            .expect("should create file");
        drop(file);

        // Verify file exists
        assert!(file_path.exists(), "file should exist");

        // Verify permissions
        let metadata = std::fs::metadata(&file_path).expect("should read metadata");
        let mode = metadata.permissions().mode();

        // Mask to get only permission bits (remove file type bits)
        let permission_bits = mode & 0o777;
        assert_eq!(
            permission_bits, 0o644,
            "file should have permissions 0o644, got 0o{permission_bits:o}"
        );
    }

    /// H1: Test `create_file_with_mode()` with Unix mode 0o755
    #[cfg(unix)]
    #[test]
    fn test_create_file_with_mode_0o755() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("failed to create temp dir");
        let file_path = temp.path().join("test_0o755.txt");

        // Create file with mode 0o755
        let file = create_file_with_mode(&file_path, Some(sanitized(0o755)), false)
            .expect("should create file");
        drop(file);

        // Verify file exists
        assert!(file_path.exists(), "file should exist");

        // Verify permissions
        let metadata = std::fs::metadata(&file_path).expect("should read metadata");
        let mode = metadata.permissions().mode();

        // Mask to get only permission bits
        let permission_bits = mode & 0o777;
        assert_eq!(
            permission_bits, 0o755,
            "file should have permissions 0o755, got 0o{permission_bits:o}"
        );
    }

    /// H1: Test `create_file_with_mode()` with Unix mode 0o600
    #[cfg(unix)]
    #[test]
    fn test_create_file_with_mode_0o600() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("failed to create temp dir");
        let file_path = temp.path().join("test_0o600.txt");

        // Create file with mode 0o600
        let file = create_file_with_mode(&file_path, Some(sanitized(0o600)), false)
            .expect("should create file");
        drop(file);

        // Verify file exists
        assert!(file_path.exists(), "file should exist");

        // Verify permissions
        let metadata = std::fs::metadata(&file_path).expect("should read metadata");
        let mode = metadata.permissions().mode();

        // Mask to get only permission bits
        let permission_bits = mode & 0o777;
        assert_eq!(
            permission_bits, 0o600,
            "file should have permissions 0o600, got 0o{permission_bits:o}"
        );
    }

    /// H2: Test `create_file_with_mode()` with None (system default
    /// permissions)
    #[test]
    fn test_create_file_with_mode_none() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let file_path = temp.path().join("test_none.txt");

        // Create file with mode=None (should use system defaults)
        let file = create_file_with_mode(&file_path, None, false).expect("should create file");
        drop(file);

        // Verify file exists
        assert!(file_path.exists(), "file should exist");

        // File should have been created successfully with default permissions
        // The exact permissions depend on umask and platform, so we just verify
        // creation
    }

    /// H2: Test `create_file_with_mode()` with None on Unix (verify umask-based
    /// default)
    #[cfg(unix)]
    #[test]
    fn test_create_file_with_mode_none_unix() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("failed to create temp dir");
        let file_path = temp.path().join("test_none_unix.txt");

        // Create file with mode=None
        let file = create_file_with_mode(&file_path, None, false).expect("should create file");
        drop(file);

        // Verify file exists
        assert!(file_path.exists(), "file should exist");

        // Verify file has some permission bits set (not zero)
        let metadata = std::fs::metadata(&file_path).expect("should read metadata");
        let mode = metadata.permissions().mode();
        let permission_bits = mode & 0o777;

        // Should have some permissions (not completely locked)
        // Typical defaults are 0o644 or 0o666 & !umask
        assert_ne!(
            permission_bits, 0,
            "file should have non-zero permissions with mode=None"
        );
    }

    /// Verify that extracted file permissions match the sanitized mode even
    /// when the process umask would otherwise reduce them.
    ///
    /// A file with mode 0o777 in the archive is sanitized to 0o775 by default
    /// (world-writable bit stripped). The extracted file must have exactly
    /// 0o775, not 0o755 (which would happen if umask 022 were applied on top).
    #[cfg(unix)]
    #[test]
    fn test_extract_file_permissions_bypass_umask() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let mut report = ExtractionReport::default();
        let mut copy_buffer = CopyBuffer::new();
        let mut dir_cache = DirCache::new();

        let config = SecurityConfig::default().validate().expect("valid config");

        // Mode 0o777 in archive, sanitized to 0o775 (world-writable stripped)
        let sanitized_mode = sanitize_permissions(0o777, &config);
        let permit = QuotaTracker::new()
            .reserve(0, &config)
            .expect("reservation should succeed");
        let safe_path = SafePath::validate(&PathBuf::from("perm_test.txt"), &dest, &config)
            .expect("path should be valid");

        let mut reader = Cursor::new(b"content");

        extract_file_with_permit(
            &mut reader,
            &safe_path,
            Some(sanitized_mode),
            permit,
            &dest,
            &mut report,
            None,
            &mut copy_buffer,
            &mut dir_cache,
            true,
            &mut 0u64,
            &mut NoopProgress,
        )
        .expect("extraction should succeed");

        let extracted = temp.path().join("perm_test.txt");
        assert!(extracted.exists(), "file should exist");

        let metadata = std::fs::metadata(&extracted).expect("should read metadata");
        let permission_bits = metadata.permissions().mode() & 0o777;

        assert_eq!(
            permission_bits, 0o775,
            "extracted file must have exact sanitized mode 0o775, got 0o{permission_bits:o}; \
             umask may have incorrectly reduced permissions"
        );
    }

    /// Verify that `create_file_with_mode` bypasses umask by explicitly setting
    /// a strict umask (0o077) before creating the file. Without the
    /// `set_permissions` call, umask 0o077 would reduce 0o755 to 0o700.
    /// With the fix, the file must retain the full 0o755 mode.
    ///
    /// Uses `libc::umask` to set and restore the process umask around the test.
    /// nextest runs each test in its own process, so umask mutation is safe.
    #[cfg(unix)]
    #[test]
    #[allow(unsafe_code)]
    fn test_create_file_with_mode_bypasses_strict_umask() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("failed to create temp dir");
        let file_path = temp.path().join("strict_umask_test.txt");

        // Set a strict umask that would strip group+other bits entirely.
        // Without set_permissions(), 0o755 & ~0o077 = 0o700.
        // SAFETY: single-threaded test process (nextest isolation), umask is
        // process-global but safe to mutate here. Restored unconditionally.
        let previous_umask = unsafe { libc::umask(0o077) };

        let result = create_file_with_mode(&file_path, Some(sanitized(0o755)), false);

        // Restore previous umask unconditionally before any assert.
        unsafe { libc::umask(previous_umask) };

        let file = result.expect("should create file under strict umask");
        drop(file);

        let metadata = std::fs::metadata(&file_path).expect("should read metadata");
        let permission_bits = metadata.permissions().mode() & 0o777;

        assert_eq!(
            permission_bits, 0o755,
            "file must have exact mode 0o755 despite strict umask 0o077; \
             got 0o{permission_bits:o} — set_permissions bypass not working"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_duplicate_symlink_overwrites_when_skip_disabled() {
        use crate::types::SafeSymlink;

        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default()
            .with_allow_symlinks(true)
            .validate()
            .expect("valid config");

        // Create the target file so the symlink has somewhere to point
        std::fs::write(temp.path().join("target.txt"), b"data").expect("write target");

        let link_safe_path =
            SafePath::validate(&PathBuf::from("link.txt"), &dest, &config).expect("safe path");
        // Validate before the symlink exists on disk
        let safe_symlink =
            SafeSymlink::validate(&link_safe_path, Path::new("target.txt"), &dest, &config)
                .expect("safe symlink");

        let mut report = ExtractionReport::default();
        let mut dir_cache = DirCache::new();

        // First creation
        create_symlink(
            &safe_symlink,
            &dest,
            &mut report,
            &mut dir_cache,
            false,
            &mut 0u64,
        )
        .expect("first create_symlink should succeed");
        assert_eq!(report.symlinks_created, 1);

        // Second creation with skip_duplicates=false must overwrite without
        // error
        create_symlink(
            &safe_symlink,
            &dest,
            &mut report,
            &mut dir_cache,
            false,
            &mut 0u64,
        )
        .expect("second create_symlink should overwrite");
        assert_eq!(report.symlinks_created, 2);
        assert_eq!(report.files_skipped, 0);
        assert!(temp.path().join("link.txt").exists());
    }

    /// Pins the aggregation behavior of `check_extension_allowed`: a rejected
    /// entry increments `disallowed_extension_skips` instead of pushing a
    /// per-entry warning, so `report.warnings`'s growth stays independent of
    /// how many disallowed entries an archive contains (issue #495).
    #[test]
    fn test_check_extension_allowed_increments_counter_not_warnings() {
        let config = SecurityConfig::default()
            .with_allowed_extensions(vec!["txt".to_string()])
            .validate()
            .expect("valid config");
        let mut report = ExtractionReport::default();
        let path = PathBuf::from("skip.exe");
        let mut disallowed_extension_skips = 0u64;

        let allowed =
            check_extension_allowed(&path, &config, &mut report, &mut disallowed_extension_skips);

        assert!(!allowed, "disallowed extension must be rejected");
        assert_eq!(report.files_skipped, 1);
        assert_eq!(disallowed_extension_skips, 1);
        assert!(report.warnings.is_empty());
    }

    /// Verifies the happy path leaves `report` and the counter untouched.
    #[test]
    fn test_check_extension_allowed_allowed_extension() {
        let config = SecurityConfig::default()
            .with_allowed_extensions(vec!["txt".to_string()])
            .validate()
            .expect("valid config");
        let mut report = ExtractionReport::default();
        let path = PathBuf::from("keep.txt");
        let mut disallowed_extension_skips = 0u64;

        let allowed =
            check_extension_allowed(&path, &config, &mut report, &mut disallowed_extension_skips);

        assert!(allowed, "allowed extension must pass");
        assert_eq!(report.files_skipped, 0);
        assert_eq!(disallowed_extension_skips, 0);
        assert!(report.warnings.is_empty());
    }

    /// Pins the exact aggregated warning message text produced by
    /// `push_disallowed_extension_warning` for both singular and plural
    /// counts, and confirms it is a no-op for a zero count.
    #[test]
    fn test_push_disallowed_extension_warning_text() {
        let mut report = ExtractionReport::default();
        push_disallowed_extension_warning(&mut report, 0);
        assert!(report.warnings.is_empty(), "zero count must be a no-op");

        push_disallowed_extension_warning(&mut report, 1);
        assert_eq!(
            report.warnings,
            vec!["skipped 1 entry with disallowed extension".to_string()]
        );

        report.warnings.clear();
        push_disallowed_extension_warning(&mut report, 3);
        assert_eq!(
            report.warnings,
            vec!["skipped 3 entries with disallowed extensions".to_string()]
        );
    }

    /// Pins the exact aggregated warning message text produced by
    /// `push_duplicate_skip_warning` for both singular and plural counts,
    /// and confirms it is a no-op for a zero count.
    #[test]
    fn test_push_duplicate_skip_warning_text() {
        let mut report = ExtractionReport::default();
        push_duplicate_skip_warning(&mut report, 0, "entry", "entries");
        assert!(report.warnings.is_empty(), "zero count must be a no-op");

        push_duplicate_skip_warning(&mut report, 1, "entry", "entries");
        assert_eq!(
            report.warnings,
            vec!["skipped 1 entry as pre-existing duplicates".to_string()]
        );

        report.warnings.clear();
        push_duplicate_skip_warning(&mut report, 3, "entry", "entries");
        assert_eq!(
            report.warnings,
            vec!["skipped 3 entries as pre-existing duplicates".to_string()]
        );
    }
}
