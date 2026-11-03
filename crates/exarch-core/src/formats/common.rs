//! Common extraction utilities shared between archive formats.
//!
//! This module provides shared functionality for TAR and ZIP extractors
//! to avoid code duplication. It is an internal module not exposed in
//! the public API.
//!
//! # Functions
//!
//! - [`extract_file_with_permit`]: Generic file extraction with buffered I/O
//! - [`create_directory`]: Directory creation (idempotent)
//! - [`create_symlink`]: Symbolic link creation (Unix only)
//! - [`is_filesystem_loop_error`]: Detects the `ELOOP` error an `O_NOFOLLOW`
//!   open produces
//! - [`copy_file_content_with_permit`]: Hardlink content copy between
//!   already-open source/destination handles
//! - [`is_extension_allowed`]: Extension allowlist predicate
//! - [`push_disallowed_extension_warning`]: Aggregated disallowed-extension
//!   skip warning
//!
//! Every write below the destination goes through a
//! [`VettedDir`](crate::formats::pinned_dir::VettedDir), so no path is
//! resolved a second time between a check and the act that follows it.

use std::fs::File;
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
use crate::SinkOptions;
use crate::config::Validated;
use crate::copy::CopyBuffer;
use crate::copy::CopyError;
use crate::copy::copy_bounded;
use crate::copy::copy_with_buffer;
use crate::error::QuotaResource;
use crate::formats::dir_walker::DirWalker;
use crate::formats::pinned_dir::Leaf;
use crate::formats::pinned_dir::PinnedRoot;
use crate::formats::pinned_dir::TempFileGuard;
use crate::formats::pinned_dir::TempLeaf;
use crate::formats::pinned_dir::VettedDir;
use crate::security::fs_view::HostFs;
use crate::security::fs_view::Occupant;
use crate::security::fs_view::blocked_parent_error;
use crate::security::permissions::SanitizedMode;
use crate::security::quota::QuotaPermit;
use crate::types::DestDir;
use crate::types::SafePath;
use crate::types::SafeSymlink;
use crate::types::dest_dir::ProbePath;
use crate::types::safe_path::ParentCheck;

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
        self.fired = true;
        self.progress.on_entry_complete(self.path);
    }
}

impl Drop for EntryCompleteGuard<'_> {
    fn drop(&mut self) {
        if !self.fired {
            self.progress.on_entry_complete(self.path);
        }
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

/// Builds the error returned for any password-protected archive, so ZIP and
/// 7z (open, list and extract paths) report encryption identically.
#[must_use]
pub fn encrypted_archive_error() -> ArchiveError {
    ArchiveError::violation(
        "archive is encrypted (password-protected). Encrypted archives are not \
                 supported; decrypt the archive externally and try again."
            .into(),
    )
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

/// Adds `n` to a byte counter.
///
/// # Errors
///
/// Returns `QuotaExceeded` on overflow.
#[inline]
pub fn checked_add_bytes(total: u64, n: u64) -> Result<u64> {
    total.checked_add(n).ok_or(ArchiveError::QuotaExceeded {
        resource: QuotaResource::IntegerOverflow,
    })
}

/// Adds `n` to an entry counter.
///
/// # Errors
///
/// Returns `QuotaExceeded` on overflow.
#[inline]
pub fn checked_add_count(total: usize, n: usize) -> Result<usize> {
    total.checked_add(n).ok_or(ArchiveError::QuotaExceeded {
        resource: QuotaResource::IntegerOverflow,
    })
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
    report.files_skipped = checked_add_count(report.files_skipped, 1)?;
    Ok(())
}

/// Whether the extension allowlist admits `path`.
///
/// The one definition of the rule, applied by the validator's file screen and
/// by the passes that must agree with it on which files are skipped.
#[must_use]
pub fn is_extension_allowed(path: &Path, config: &SecurityConfig<Validated>) -> bool {
    config.is_path_extension_allowed(path.extension().and_then(|e| e.to_str()))
}

/// Generic file extraction implementation used by all format adapters.
///
/// This function consolidates file extraction logic to ensure consistent:
/// - Directory creation through the validated directory walker
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
/// [`VettedDir::create_new`] for the full contract.
///
/// # Security - Pinned Parent Directory (issue #818)
///
/// The parent directory is walked once into a [`VettedDir`] handle, and the
/// create, the optional temp-file rename and the cleanup all happen relative
/// to that handle. A parent component swapped for a symlink after the walk
/// cannot redirect the write.
///
/// # Correctness
///
/// The quota charge for this entry already happened during
/// `EntryValidator::validate_entry`, proven by the [`QuotaPermit`] passed in
/// by value: a `QuotaPermit` is neither `Clone` nor `Copy`, so this function
/// cannot be called at all without the caller having moved a genuine permit
/// out of a validated file (mirrors 7z's `write_file_with_permit`, issue
/// #445). This guards `report.bytes_written` against overflow before writing.
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
/// * `root` - Destination directory, pinned by an open handle
/// * `report` - Extraction statistics (updated)
/// * `expected_size` - Declared uncompressed size (if known); used for the
///   quota pre-check and, per the security note above, enforced as a hard
///   streaming ceiling and exact post-copy match
/// * `copy_buffer` - Reusable buffer for I/O operations
/// * `dirs` - Creates and vets the parent directories
/// * `options` - Duplicate-handling policy for a pre-existing destination path
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
#[expect(
    clippy::too_many_arguments,
    reason = "arguments are threaded through from the caller; a parameter struct adds indirection"
)]
#[inline]
pub fn extract_file_with_permit<R: Read, P: ParentCheck>(
    reader: &mut R,
    safe_path: &SafePath<P>,
    mode: Option<SanitizedMode>,
    _permit: QuotaPermit,
    root: &PinnedRoot,
    report: &mut ExtractionReport,
    expected_size: Option<u64>,
    copy_buffer: &mut CopyBuffer,
    dirs: DirWalker,
    options: SinkOptions,
    duplicate_skips: &mut u64,
    progress: &mut dyn ProgressCallback,
) -> Result<()> {
    let skip_duplicates = options.skip_duplicates;

    let (parent, leaf) = dirs.ensure_parent(root, safe_path)?;

    // The size was already reserved against QuotaTracker during
    // validate_entry (proven by the QuotaPermit consumed above); this only
    // guards report.bytes_written, a different quantity, against overflow.
    // Checked before any filesystem mutation so a rejected entry never
    // leaves a zero-byte file on disk (restores the pre-#446 ordering).
    if let Some(size) = expected_size {
        checked_add_bytes(report.bytes_written, size)?;
    }

    let Some(OutputSlot {
        file: output_file,
        written_at,
    }) = open_output_slot(&parent, leaf, safe_path.as_path(), mode, skip_duplicates)?
    else {
        checked_increment_files_skipped(report)?;
        *duplicate_skips = duplicate_skips.saturating_add(1);
        return Ok(());
    };

    // Removes the partial file when the copy aborts (forged `expected_size`);
    // `written_at` never holds a pre-existing entry, so nothing else is lost.
    let guard = written_at.guard(&parent, leaf);
    let mut buffered_writer = BufWriter::with_capacity(64 * 1024, output_file);
    let bytes_written = copy_with_buffer(reader, &mut buffered_writer, copy_buffer, expected_size)?;
    buffered_writer.flush()?;
    drop(buffered_writer);
    commit_output(&parent, &written_at, leaf, safe_path.as_path())?;
    guard.persist();

    record_file_written(report, progress, bytes_written)
}

/// Counts one written file and its bytes, and reports the bytes to `progress`
/// when there were any.
///
/// The single success bookkeeping for every target that writes a file.
///
/// # Errors
///
/// Returns `QuotaExceeded` when a counter would overflow.
pub fn record_file_written(
    report: &mut ExtractionReport,
    progress: &mut dyn ProgressCallback,
    written: u64,
) -> Result<()> {
    report.files_extracted = checked_add_count(report.files_extracted, 1)?;
    report.bytes_written = checked_add_bytes(report.bytes_written, written)?;
    if written > 0 {
        progress.on_bytes_written(written);
    }
    Ok(())
}

/// Maximum attempts to create a uniquely named sibling temp file before
/// giving up.
///
/// Bounds retry cost when predicted `.exarch-tmp-{pid}-{counter}` names are
/// pre-occupied; a genuine collision from concurrent extraction into the same
/// directory resolves on the first or second attempt.
pub const MAX_TEMP_FILE_CREATE_ATTEMPTS: u32 = 8;

/// Creates a new file in `dir` under the first free name drawn from
/// `next_candidate`, retrying on `AlreadyExists` up to
/// [`MAX_TEMP_FILE_CREATE_ATTEMPTS`] times.
///
/// Each attempt uses [`VettedDir::create_new`] (`O_EXCL`), so a planted entry
/// at a predicted name is never followed or reused. `entry` names the file the
/// temp file stands in for, for the error text only.
///
/// # Errors
///
/// Returns the first non-`AlreadyExists` I/O error, or `AlreadyExists` when
/// every attempt collided.
pub fn create_temp_sibling(
    dir: &VettedDir,
    entry: Leaf<'_>,
    mode: Option<SanitizedMode>,
    mut next_candidate: impl FnMut() -> TempLeaf,
) -> std::io::Result<(TempLeaf, File)> {
    for _ in 0..MAX_TEMP_FILE_CREATE_ATTEMPTS {
        let candidate = next_candidate();
        match dir.create_new(candidate.as_leaf(), mode) {
            Ok(file) => return Ok((candidate, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!(
            "failed to create a unique temp file for {} after {MAX_TEMP_FILE_CREATE_ATTEMPTS} attempts",
            Path::new(entry.as_os_str()).display()
        ),
    ))
}

/// Where an output file was written before it reaches its final name.
enum WrittenAt {
    /// The final name itself.
    Final,
    /// A sibling temp file that is renamed over the existing entry.
    Temp(TempLeaf),
}

impl WrittenAt {
    /// A guard that removes the written file unless persisted.
    fn guard<'d>(&self, dir: &'d VettedDir, final_name: Leaf<'_>) -> TempFileGuard<'d> {
        match self {
            Self::Final => TempFileGuard::new(dir, final_name),
            Self::Temp(temp) => TempFileGuard::for_temp(dir, temp.clone()),
        }
    }
}

/// An open, empty output file and where its content must end up.
struct OutputSlot {
    file: File,
    written_at: WrittenAt,
}

/// Opens the destination for a regular-file entry without ever writing
/// through an existing inode.
///
/// A free name is created in place with `O_EXCL`. When an entry already
/// exists, overwrite mode writes a fresh sibling temp file that the caller
/// renames over the entry, so other hardlinks to the old inode keep their
/// content. Returns `None` when the entry exists and `skip_duplicates` is set.
fn open_output_slot(
    dir: &VettedDir,
    leaf: Leaf<'_>,
    rel: &Path,
    mode: Option<SanitizedMode>,
    skip_duplicates: bool,
) -> Result<Option<OutputSlot>> {
    match dir.create_new(leaf, mode) {
        Ok(file) => Ok(Some(OutputSlot {
            file,
            written_at: WrittenAt::Final,
        })),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && skip_duplicates => Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            refuse_non_file_occupant(dir, leaf, rel)?;
            let (temp, file) = create_temp_sibling(dir, leaf, mode, TempLeaf::next)
                .map_err(|e| replace_error(rel, &e))?;
            Ok(Some(OutputSlot {
                file,
                written_at: WrittenAt::Temp(temp),
            }))
        }
        Err(e) => Err(name_occupant_on_open_error(dir, leaf, rel, e).into()),
    }
}

/// Renames the completed temp file over the entry it replaces, if any.
fn commit_output(
    dir: &VettedDir,
    written_at: &WrittenAt,
    leaf: Leaf<'_>,
    rel: &Path,
) -> Result<()> {
    if let WrittenAt::Temp(temp) = written_at {
        dir.rename_within(temp.as_leaf(), leaf)
            .map_err(|e| replace_error(rel, &e))?;
    }
    Ok(())
}

/// Wraps a failure to replace the existing entry at `rel`, keeping its kind
/// and naming the entry.
fn replace_error(rel: &Path, err: &std::io::Error) -> std::io::Error {
    std::io::Error::new(
        err.kind(),
        format!(
            "cannot replace the existing file at {}: {err}",
            rel.display()
        ),
    )
}

/// Fails with an entry-naming error when `leaf` holds a directory or a
/// symlink, which an overwrite never replaces.
fn refuse_non_file_occupant(dir: &VettedDir, leaf: Leaf<'_>, rel: &Path) -> Result<()> {
    match dir.probe(leaf) {
        Ok(Some(occupant @ (Occupant::Directory | Occupant::Symlink))) => {
            Err(occupant_at_dest_error(rel, occupant).into())
        }
        Ok(Some(Occupant::File) | None) | Err(_) => Ok(()),
    }
}

/// Creates a directory from a validated entry.
///
/// This is a shared helper used by both TAR and ZIP extractors.
///
/// # Idempotent Behavior
///
/// This function is idempotent - calling it multiple times for the same
/// directory has no effect.
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
/// * `root` - Destination directory, pinned by an open handle
/// * `report` - Extraction statistics (updated)
/// * `dirs` - Creates and vets the directory
///
/// # Errors
///
/// Returns an error if directory creation fails due to I/O errors or a
/// component is a symlink the policy refuses.
pub fn create_directory<P: ParentCheck>(
    safe_path: &SafePath<P>,
    root: &PinnedRoot,
    report: &mut ExtractionReport,
    dirs: DirWalker,
) -> Result<()> {
    check_directory_occupant(
        &root.dest().probe(safe_path.as_path()),
        safe_path.as_path(),
        root.dest(),
    )?;
    dirs.ensure_dir(root, safe_path)?;

    report.directories_created += 1;

    Ok(())
}

/// Fails with an entry-naming error when `dir_path` holds something a
/// directory entry cannot become: a file ([`occupant_at_dest_error`]), or a
/// symlink that does not resolve to a directory inside `dest` (a security
/// violation, the category `verify` reports for it).
///
/// The path-based `lstat` here only chooses the error message; the fd-relative
/// walk in [`DirWalker::ensure_dir`] enforces the same refusals again.
fn check_directory_occupant(probe: &ProbePath, rel: &Path, dest: &DestDir) -> Result<()> {
    let file_type = match probe.lstat() {
        Ok(metadata) => metadata.file_type(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(blocked_parent_error(&HostFs, dest, rel).unwrap_or_else(|| e.into()));
        }
    };
    if file_type.is_dir() {
        return Ok(());
    }
    if file_type.is_symlink() {
        return if probe.lands_in_dir(dest) {
            Ok(())
        } else {
            Err(ArchiveError::violation(Occupant::Symlink.refusal(rel)))
        };
    }
    Err(occupant_at_dest_error(rel, Occupant::File).into())
}

/// Creates a symbolic link from a validated symlink entry.
///
/// This is a shared helper used by both TAR and ZIP extractors.
/// Parent directories are created automatically if needed through the
/// directory walker.
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
/// * `root` - Destination directory, pinned by an open handle
/// * `report` - Extraction statistics (updated)
/// * `dirs` - Creates and vets the parent directories
/// * `options` - Duplicate-handling policy for a pre-existing destination path
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
/// - A symlink with a different target occupies the path and `skip_duplicates`
///   is false (one with the same target is skipped as unchanged)
#[allow(unused_variables)]
#[cfg_attr(
    not(unix),
    expect(
        clippy::needless_pass_by_ref_mut,
        reason = "only the Unix path updates the counters; the signature is shared"
    )
)]
pub fn create_symlink<P: ParentCheck>(
    safe_symlink: &SafeSymlink<P>,
    root: &PinnedRoot,
    report: &mut ExtractionReport,
    dirs: DirWalker,
    options: SinkOptions,
    duplicate_skips: &mut u64,
) -> Result<()> {
    let skip_duplicates = options.skip_duplicates;
    #[cfg(unix)]
    {
        let target_path = safe_symlink.target_path();

        let (parent, leaf) = dirs.ensure_parent(root, safe_symlink.link())?;

        if let Some(existing) = parent.probe(leaf)? {
            if skip_duplicates {
                checked_increment_files_skipped(report)?;
                *duplicate_skips = duplicate_skips.saturating_add(1);
                return Ok(());
            }
            if existing == Occupant::Symlink {
                // An unchanged link re-points nothing; a different target could
                // re-point a path that an earlier link's `..` resolved through.
                if parent.read_link(leaf)? == target_path {
                    checked_increment_files_skipped(report)?;
                    return Ok(());
                }
                return Err(symlink_at_dest_error(safe_symlink.link_path()).into());
            }
            parent.remove_file(leaf)?;
        }

        parent.symlink(target_path, leaf)?;

        report.symlinks_created += 1;

        Ok(())
    }

    #[cfg(not(unix))]
    {
        require_symlink_creation()
    }
}

/// The I/O error for an earlier entry that occupies a path extraction would
/// overwrite, so the replacement fails closed and names the entry instead of
/// surfacing a bare errno (issues #477, #735, #765).
///
/// A symlink maps to the loop kind on Unix (what `O_NOFOLLOW` reports) and to
/// `AlreadyExists` elsewhere; the text is identical on every platform.
pub fn occupant_at_dest_error(rel: &Path, occupant: Occupant) -> std::io::Error {
    use std::io::ErrorKind;

    #[cfg(unix)]
    let symlink_kind = std::io::Error::from_raw_os_error(libc::ELOOP).kind();
    #[cfg(not(unix))]
    let symlink_kind = ErrorKind::AlreadyExists;

    let kind = match occupant {
        Occupant::Directory => ErrorKind::IsADirectory,
        Occupant::Symlink => symlink_kind,
        Occupant::File => ErrorKind::AlreadyExists,
    };
    std::io::Error::new(kind, occupant.refusal(rel))
}

/// The error for a symlink that occupies a path extraction would overwrite.
pub fn symlink_at_dest_error(rel: &Path) -> std::io::Error {
    occupant_at_dest_error(rel, Occupant::Symlink)
}

/// Replaces `err`, the failure of an overwrite-mode open at `path`, with the
/// entry-naming [`occupant_at_dest_error`] when the failure is the refusal of
/// the directory or symlink that holds the path; any other failure (including
/// a different errno on such a path) is returned unchanged.
///
/// Runs only on the error path, via a `probe` of the name, so the success path
/// costs nothing.
fn name_occupant_on_open_error(
    dir: &VettedDir,
    leaf: Leaf<'_>,
    rel: &Path,
    err: std::io::Error,
) -> std::io::Error {
    refused_occupant(dir, leaf, &err).map_or(err, |occupant| occupant_at_dest_error(rel, occupant))
}

/// The occupant of `leaf` whose presence explains `err`, if any.
///
/// A symlink refusal is identified by `ELOOP` on Unix and by the
/// `AlreadyExists` that `VettedDir::create_new` returns elsewhere.
fn refused_occupant(dir: &VettedDir, leaf: Leaf<'_>, err: &std::io::Error) -> Option<Occupant> {
    use std::io::ErrorKind;

    let occupant = dir.probe(leaf).ok()??;
    let dir_refusal = err.kind() == ErrorKind::IsADirectory
        || (cfg!(not(unix)) && err.kind() == ErrorKind::PermissionDenied);
    let symlink_refusal = if cfg!(unix) {
        is_filesystem_loop_error(err)
    } else {
        err.kind() == ErrorKind::AlreadyExists
    };
    match occupant {
        Occupant::Directory if dir_refusal => Some(Occupant::Directory),
        Occupant::Symlink if symlink_refusal => Some(Occupant::Symlink),
        Occupant::Directory | Occupant::Symlink | Occupant::File => None,
    }
}

/// Fails on a host that cannot create symlinks, so a format can refuse a link
/// before it writes anything.
///
/// # Errors
///
/// Returns `SecurityViolation` on a non-Unix host.
pub fn require_symlink_creation() -> Result<()> {
    cfg!(unix).ok_or_else(|| {
        ArchiveError::violation("symlinks are not supported on this platform".into())
    })
}

/// The file-type bits of a Unix mode (`S_IFMT`).
const S_IFMT: u32 = 0o17_0000;

/// A Unix file type that exarch never creates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialFile {
    /// A named pipe.
    Fifo,
    /// A character device node.
    CharDevice,
    /// A block device node.
    BlockDevice,
    /// A Unix domain socket.
    Socket,
}

impl SpecialFile {
    /// The noun used in refusal messages.
    pub const fn noun(self) -> &'static str {
        match self {
            Self::Fifo => "FIFO",
            Self::CharDevice => "character device",
            Self::BlockDevice => "block device",
            Self::Socket => "socket",
        }
    }
}

/// The file type recorded in the type bits of a Unix mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnixFileType {
    /// `S_IFREG`.
    Regular,
    /// `S_IFDIR`.
    Directory,
    /// `S_IFLNK`.
    Symlink,
    /// A FIFO, device node or socket.
    Special(SpecialFile),
    /// Type bits that name no defined file type; holds the bits shifted down.
    Undefined(u8),
}

impl UnixFileType {
    /// Reads the type bits of `mode`; `None` when they are all zero, which
    /// records no type.
    pub fn from_mode(mode: u32) -> Option<Self> {
        match mode & S_IFMT {
            0 => None,
            0o10_0000 => Some(Self::Regular),
            0o04_0000 => Some(Self::Directory),
            0o12_0000 => Some(Self::Symlink),
            0o01_0000 => Some(Self::Special(SpecialFile::Fifo)),
            0o02_0000 => Some(Self::Special(SpecialFile::CharDevice)),
            0o06_0000 => Some(Self::Special(SpecialFile::BlockDevice)),
            0o14_0000 => Some(Self::Special(SpecialFile::Socket)),
            bits => Some(Self::Undefined(u8::try_from(bits >> 12).unwrap_or(u8::MAX))),
        }
    }
}

/// Longest symlink target stored as entry data that is read at all.
pub const MAX_STORED_SYMLINK_TARGET: u64 =
    crate::security::fs_view::MAX_SYMLINK_TARGET_BYTES as u64;

/// The refusal for a symlink target stored as entry data above the host's
/// symlink target limit.
///
/// # Errors
///
/// Returns `SecurityViolation` when `size` exceeds
/// [`MAX_STORED_SYMLINK_TARGET`].
pub fn check_symlink_target_size(size: u64) -> Result<()> {
    if size > MAX_STORED_SYMLINK_TARGET {
        return Err(symlink_target_too_large(size));
    }
    Ok(())
}

/// The refusal for a stored symlink target of `size` bytes above the limit.
pub fn symlink_target_too_large(size: u64) -> ArchiveError {
    ArchiveError::violation(format!(
        "symlink target too large: {size} bytes (max {MAX_STORED_SYMLINK_TARGET})"
    ))
}

/// Decodes the bytes of a stored symlink target.
///
/// # Errors
///
/// Returns `InvalidArchive` when the bytes are not UTF-8.
pub fn symlink_target_from_bytes(target_bytes: &[u8]) -> Result<PathBuf> {
    let target_str = std::str::from_utf8(target_bytes)
        .map_err(|_| ArchiveError::InvalidArchive("symlink target is not valid UTF-8".into()))?;

    Ok(PathBuf::from(target_str))
}

/// Returns `true` if `error` is the "too many levels of symbolic links"
/// error (`ELOOP` on Unix) that an `O_NOFOLLOW` open produces when its final
/// path component is a symlink.
///
/// `std::io::ErrorKind::FilesystemLoop` exists for exactly this case but is
/// not yet stable (`io_error_more`, rust-lang/rust#86442 as of this crate's
/// MSRV), so this compares the raw OS error code directly on Unix. Always
/// `false` on non-Unix, which has no `O_NOFOLLOW` equivalent wired up here.
/// Used only to word an error: whether a symlink is to blame is decided by a
/// `probe` of the name, not by this code.
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

/// The error for a hardlink target that changed between the `fstat` that sized
/// its quota reservation and the end of the copy.
fn hardlink_target_changed(error: CopyError) -> ArchiveError {
    match error {
        CopyError::Overrun { .. } | CopyError::Short { .. } => {
            ArchiveError::violation("hardlink target changed while it was being copied".into())
        }
        other => other.into(),
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
/// [`File`] handles rather than paths. Callers obtain `to` from
/// [`VettedDir::create_new`] (refusing to create through a pre-existing
/// destination name, symlink or not) and `from` from [`VettedDir::open_read`]
/// (refusing to follow a symlink), and reserve quota from `from`'s `fstat`
/// size, passed as `expected_len`.
///
/// `expected_len` is a hard ceiling and an exact length: the quota was charged
/// for that many bytes, so a target that grew after the `fstat` fails closed
/// instead of writing past the charged permit, and one that shrank fails too.
///
/// Permissions are not copied here: the caller creates `to` with the
/// sanitized mode of the target before any byte is written (a pre-existing
/// target in the destination can carry setuid, setgid or world-write bits that
/// extraction never sanitized).
///
/// # Errors
///
/// Returns `SecurityViolation` if the target's length differs from
/// `expected_len`, and an I/O error if the copy fails.
pub fn copy_file_content_with_permit(
    mut from: File,
    mut to: File,
    expected_len: u64,
    copy_buffer: &mut CopyBuffer,
    _permit: QuotaPermit,
) -> Result<u64> {
    copy_bounded(&mut from, &mut to, copy_buffer, Some(expected_len))
        .map_err(hardlink_target_changed)
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

    fn test_walker() -> DirWalker {
        DirWalker::new(&SecurityConfig::default().validate().expect("valid config"))
    }

    fn pinned(dest: &DestDir) -> PinnedRoot {
        PinnedRoot::open(dest.clone()).expect("open destination")
    }

    /// Creates `path` the way extraction does: exclusively, relative to a
    /// handle on its parent directory.
    fn create_file_with_mode(path: &Path, mode: Option<SanitizedMode>) -> std::io::Result<File> {
        let parent = pinned(&DestDir::new(path.parent().expect("parent")).expect("dest"));
        let (_, leaf) = Leaf::split(Path::new(path.file_name().expect("name"))).expect("leaf");
        parent.dir().reopen()?.create_new(leaf, mode)
    }

    #[test]
    fn occupant_error_names_the_entry_and_the_occupant() {
        use std::io::ErrorKind;

        #[cfg(unix)]
        let symlink_kind = std::io::Error::from_raw_os_error(libc::ELOOP).kind();
        #[cfg(not(unix))]
        let symlink_kind = ErrorKind::AlreadyExists;

        for (occupant, noun, kind) in [
            (Occupant::Directory, "directory", ErrorKind::IsADirectory),
            (Occupant::Symlink, "symlink", symlink_kind),
            (Occupant::File, "file", ErrorKind::AlreadyExists),
        ] {
            let rel = Path::new("a/b");
            let err = occupant_at_dest_error(rel, occupant);
            assert_eq!(err.kind(), kind, "{occupant:?}");
            assert_eq!(
                err.to_string(),
                format!(
                    "refusing to replace the existing {noun} at {}",
                    rel.components().collect::<PathBuf>().display()
                )
            );
        }
    }

    #[test]
    fn open_error_is_renamed_only_when_it_matches_the_occupant() {
        use std::io::Error;
        use std::io::ErrorKind;

        let temp = TempDir::new().expect("temp dir");
        std::fs::create_dir(temp.path().join("d")).expect("mkdir");
        let root = pinned(&DestDir::new(temp.path()).expect("dest"));
        let dir = root.dir();
        let leaf = |name: &'static str| Leaf::split(Path::new(name)).expect("leaf").1;

        let refused = Error::from(ErrorKind::IsADirectory);
        assert_matches!(
            refused_occupant(dir, leaf("d"), &refused),
            Some(Occupant::Directory)
        );
        let unrelated = Error::from(ErrorKind::Other);
        assert_matches!(refused_occupant(dir, leaf("d"), &unrelated), None);
        assert_matches!(refused_occupant(dir, leaf("gone"), &refused), None);

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("t", temp.path().join("l")).expect("symlink");
            let loop_err = Error::from_raw_os_error(libc::ELOOP);
            assert_matches!(
                refused_occupant(dir, leaf("l"), &loop_err),
                Some(Occupant::Symlink)
            );
            assert_matches!(refused_occupant(dir, leaf("l"), &unrelated), None);
            let too_many_files = Error::from_raw_os_error(libc::EMFILE);
            assert_matches!(refused_occupant(dir, leaf("l"), &too_many_files), None);
        }
    }

    fn make_directory(
        dest: &DestDir,
        name: &str,
        allow_symlinks: bool,
    ) -> crate::Result<ExtractionReport> {
        let config = SecurityConfig::default()
            .with_allow_symlinks(allow_symlinks)
            .validate()
            .expect("valid config");
        let safe_path = SafePath::validate(&PathBuf::from(name), dest, &config).expect("safe path");
        let mut report = ExtractionReport::default();
        create_directory(
            &safe_path,
            &pinned(dest),
            &mut report,
            DirWalker::new(&config),
        )
        .map(|()| report)
    }

    #[test]
    fn test_create_directory_over_a_file_names_the_entry() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        std::fs::write(temp.path().join("x"), b"f").expect("write file");

        let err = make_directory(&dest, "x/", false).expect_err("must be refused");

        assert_matches!(&err, ArchiveError::Io(e) if e.kind() == std::io::ErrorKind::AlreadyExists);
        assert!(
            err.to_string()
                .contains("refusing to replace the existing file at x"),
            "{err}"
        );
        assert!(temp.path().join("x").is_file());
    }

    #[test]
    fn test_create_directory_over_an_existing_directory_is_idempotent() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        std::fs::create_dir(temp.path().join("d")).expect("create dir");

        make_directory(&dest, "d", false).expect("existing directory is accepted");
        make_directory(&dest, "d", false).expect("repeated directory entry is accepted");
    }

    #[cfg(unix)]
    #[test]
    fn test_create_directory_over_a_dangling_symlink_is_refused() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        std::os::unix::fs::symlink("t", temp.path().join("x")).expect("create symlink");

        let err = make_directory(&dest, "x/", false).expect_err("must be refused");

        assert!(
            err.to_string()
                .contains("refusing to replace the existing symlink at x"),
            "{err}"
        );
        assert!(!temp.path().join("t").exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_create_directory_over_a_symlink_to_a_directory_inside_dest_is_accepted() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        std::fs::create_dir(temp.path().join("real")).expect("create dir");
        std::os::unix::fs::symlink("real", temp.path().join("x")).expect("create symlink");

        make_directory(&dest, "x", true).expect("in-dest directory link accepted");
        let err = make_directory(&dest, "x", false).expect_err("refused when symlinks are off");
        assert_matches!(err, ArchiveError::SecurityViolation { .. });
    }

    #[test]
    fn test_extract_file_with_permit_integer_overflow_check() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let mut report = ExtractionReport::default();
        let mut copy_buffer = CopyBuffer::new();
        let dirs = test_walker();

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
            &pinned(&dest),
            &mut report,
            expected_size,
            &mut copy_buffer,
            dirs,
            SinkOptions::default(),
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
        let dirs = test_walker();
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

        // Pre-create the destination file so the exclusive create hits
        // AlreadyExists, taking the duplicate-skip branch that increments
        // files_skipped.
        std::fs::write(temp.path().join("test.txt"), b"existing").expect("failed to seed file");

        let mut reader = Cursor::new(b"test data");

        let result = extract_file_with_permit(
            &mut reader,
            &safe_path,
            Some(sanitized(0o644)),
            permit,
            &pinned(&dest),
            &mut report,
            None,
            &mut copy_buffer,
            dirs,
            SinkOptions::default(),
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
        let dirs = test_walker();

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
            &pinned(&dest),
            &mut report,
            Some(50),
            &mut copy_buffer,
            dirs,
            SinkOptions::default(),
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
        let dirs = test_walker();

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
            &pinned(&dest),
            &mut report,
            Some(1000),
            &mut copy_buffer,
            dirs,
            SinkOptions::default(),
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

    /// With `skip_duplicates = false` (`--force`), an aborted forged-size
    /// entry must leave the pre-existing destination file untouched and no
    /// temp file behind.
    #[test]
    fn test_extract_file_with_permit_force_overwrite_forged_size_keeps_destination() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let mut report = ExtractionReport::default();
        let mut copy_buffer = CopyBuffer::new();
        let dirs = test_walker();

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
            &pinned(&dest),
            &mut report,
            Some(50),
            &mut copy_buffer,
            dirs,
            SinkOptions::default().with_skip_duplicates(false),
            &mut 0u64,
            &mut NoopProgress,
        );

        assert_matches!(result, Err(ArchiveError::SecurityViolation { .. }));
        assert_eq!(
            std::fs::read(temp.path().join("target.txt")).expect("read target"),
            b"pre-existing content"
        );
        let leftovers = std::fs::read_dir(temp.path()).expect("read dir").count();
        assert_eq!(leftovers, 1, "no temp file may remain after an abort");
    }

    #[test]
    fn failed_commit_names_the_entry_and_guard_removes_the_temp_file() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let written = temp.path().join(".exarch-tmp-test");
        std::fs::write(&written, b"data").expect("failed to seed temp file");
        let occupied = temp.path().join("d");
        std::fs::create_dir(&occupied).expect("failed to create dir");
        std::fs::write(occupied.join("child"), b"x").expect("failed to seed child");
        let root = pinned(&DestDir::new(temp.path()).expect("dest"));
        let dir = root.dir();
        let leaf = Leaf::split(Path::new("d")).expect("leaf").1;
        let written_at = WrittenAt::Temp(TempLeaf::named(".exarch-tmp-test"));

        let guard = written_at.guard(dir, leaf);
        let err = commit_output(dir, &written_at, leaf, Path::new("d")).unwrap_err();
        drop(guard);

        assert!(err.to_string().contains("at d"), "{err}");
        assert!(!written.exists(), "temp file must be removed");
        assert!(occupied.join("child").exists());
    }

    /// Issue #818: the hardlink copy is bounded by the size the quota was
    /// charged for, so a target that grew or shrank after the `fstat` fails
    /// closed with its own message instead of the archive's "declared size".
    #[test]
    fn hardlink_copy_fails_closed_when_the_target_changes_size() {
        let temp = TempDir::new().expect("temp dir");
        let config = SecurityConfig::default().validate().expect("valid config");
        let source = temp.path().join("source");
        std::fs::write(&source, vec![b'x'; 100_000]).expect("seed source");

        for (charged, ok) in [(100_000u64, true), (10, false), (200_000, false)] {
            let permit = QuotaTracker::new()
                .reserve(charged, &config)
                .expect("reservation");
            let to = temp.path().join(format!("copy-{charged}"));
            let result = copy_file_content_with_permit(
                File::open(&source).expect("open source"),
                File::create(&to).expect("create copy"),
                charged,
                &mut CopyBuffer::new(),
                permit,
            );
            if ok {
                assert_eq!(result.expect("exact length copies"), 100_000);
            } else {
                let err = result.expect_err("a changed length must fail");
                assert_matches!(&err, ArchiveError::SecurityViolation { .. });
                assert!(err.to_string().contains("hardlink target changed"), "{err}");
            }
        }
    }

    /// H1: Test `create_file_with_mode()` with Unix mode 0o644
    #[cfg(unix)]
    #[test]
    fn test_create_file_with_mode_0o644() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("failed to create temp dir");
        let file_path = temp.path().join("test_0o644.txt");

        // Create file with mode 0o644
        let file =
            create_file_with_mode(&file_path, Some(sanitized(0o644))).expect("should create file");
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
        let file =
            create_file_with_mode(&file_path, Some(sanitized(0o755))).expect("should create file");
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
        let file =
            create_file_with_mode(&file_path, Some(sanitized(0o600))).expect("should create file");
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
        let file = create_file_with_mode(&file_path, None).expect("should create file");
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
        let file = create_file_with_mode(&file_path, None).expect("should create file");
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
        let dirs = test_walker();

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
            &pinned(&dest),
            &mut report,
            None,
            &mut copy_buffer,
            dirs,
            SinkOptions::default(),
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

        let result = create_file_with_mode(&file_path, Some(sanitized(0o755)));

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
    fn test_duplicate_symlink_unchanged_or_refused_when_skip_disabled() {
        use crate::types::SafeSymlink;

        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default()
            .with_allow_symlinks(true)
            .validate()
            .expect("valid config");

        std::fs::write(temp.path().join("target.txt"), b"data").expect("write target");

        let link_safe_path =
            SafePath::validate(&PathBuf::from("link.txt"), &dest, &config).expect("safe path");
        let safe_symlink =
            SafeSymlink::validate(&link_safe_path, Path::new("target.txt"), &dest, &config)
                .expect("safe symlink");

        let mut report = ExtractionReport::default();
        let dirs = test_walker();

        create_symlink(
            &safe_symlink,
            &pinned(&dest),
            &mut report,
            dirs,
            SinkOptions::default().with_skip_duplicates(false),
            &mut 0u64,
        )
        .expect("first create_symlink should succeed");
        assert_eq!(report.symlinks_created, 1);

        let unchanged = report.symlinks_created;
        create_symlink(
            &safe_symlink,
            &pinned(&dest),
            &mut report,
            dirs,
            SinkOptions::default().with_skip_duplicates(false),
            &mut 0u64,
        )
        .expect("an identical link is an unchanged duplicate");
        assert_eq!(report.symlinks_created, unchanged);
        assert_eq!(report.files_skipped, 1);

        std::fs::write(temp.path().join("other.txt"), b"data").expect("write other");
        let other_safe_symlink =
            SafeSymlink::validate(&link_safe_path, Path::new("other.txt"), &dest, &config)
                .expect("safe symlink");
        let err = create_symlink(
            &other_safe_symlink,
            &pinned(&dest),
            &mut report,
            dirs,
            SinkOptions::default().with_skip_duplicates(false),
            &mut 0u64,
        )
        .expect_err("a link with another target must not be replaced");
        assert_matches!(
            &err,
            ArchiveError::Io(e)
                if e.kind() == symlink_at_dest_error(Path::new("link.txt")).kind(),
            "{err:?}"
        );
        assert_eq!(report.symlinks_created, 1);
        assert_eq!(
            std::fs::read_link(temp.path().join("link.txt")).expect("link kept"),
            Path::new("target.txt")
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_replaces_existing_file_when_skip_disabled() {
        use crate::types::SafeSymlink;

        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default()
            .with_allow_symlinks(true)
            .validate()
            .expect("valid config");

        std::fs::write(temp.path().join("target.txt"), b"data").expect("write target");
        std::fs::write(temp.path().join("link.txt"), b"old").expect("write file");

        let link_safe_path =
            SafePath::validate(&PathBuf::from("link.txt"), &dest, &config).expect("safe path");
        let safe_symlink =
            SafeSymlink::validate(&link_safe_path, Path::new("target.txt"), &dest, &config)
                .expect("safe symlink");

        let mut report = ExtractionReport::default();
        create_symlink(
            &safe_symlink,
            &pinned(&dest),
            &mut report,
            test_walker(),
            SinkOptions::default().with_skip_duplicates(false),
            &mut 0u64,
        )
        .expect("a file is replaced");
        assert_eq!(report.symlinks_created, 1);
        assert!(temp.path().join("link.txt").is_symlink());
    }

    #[test]
    fn test_record_file_written_counts_bytes_and_reports_progress_once() {
        struct Bytes(Vec<u64>);
        impl ProgressCallback for Bytes {
            fn on_entry_start(&mut self, _: &Path, _: usize, _: usize) {}

            fn on_bytes_written(&mut self, bytes: u64) {
                self.0.push(bytes);
            }

            fn on_entry_complete(&mut self, _: &Path) {}

            fn on_complete(&mut self) {}
        }
        let mut report = ExtractionReport::default();
        let mut progress = Bytes(Vec::new());

        record_file_written(&mut report, &mut progress, 7).unwrap();
        record_file_written(&mut report, &mut progress, 0).unwrap();

        assert_eq!(report.files_extracted, 2);
        assert_eq!(report.bytes_written, 7);
        assert_eq!(progress.0, vec![7], "an empty file reports no bytes");
    }

    #[test]
    fn test_record_file_written_refuses_a_counter_overflow() {
        let mut report = ExtractionReport {
            bytes_written: u64::MAX,
            ..ExtractionReport::default()
        };

        let result = record_file_written(&mut report, &mut crate::NoopProgress, 1);

        assert_matches!(
            result,
            Err(ArchiveError::QuotaExceeded {
                resource: QuotaResource::IntegerOverflow
            })
        );
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

    #[test]
    fn test_entry_complete_guard_panicking_callback_fires_once() {
        use std::panic::AssertUnwindSafe;
        use std::panic::catch_unwind;

        struct Panicking(u32);
        impl ProgressCallback for Panicking {
            fn on_entry_start(&mut self, _: &Path, _: usize, _: usize) {}

            fn on_bytes_written(&mut self, _: u64) {}

            fn on_entry_complete(&mut self, _: &Path) {
                self.0 += 1;
                panic!("callback panic");
            }

            fn on_complete(&mut self) {}
        }

        let mut progress = Panicking(0);
        let path = PathBuf::from("f");
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            EntryCompleteGuard::new(&mut progress, &path).complete();
        }));
        assert!(outcome.is_err());
        assert_eq!(progress.0, 1, "Drop must not fire the callback again");
    }
}
