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
//! - [`record_skip`]: Counts an entry left out of the extraction
//!
//! Every write below the destination goes through a
//! [`VettedDir`], so no path is
//! resolved a second time between a check and the act that follows it.

use std::fs::File;
use std::io;
use std::io::BufWriter;
use std::io::Read;
use std::io::Write;
use std::mem::DropGuard;
use std::path::Path;
use std::path::PathBuf;

use crate::ArchiveError;
use crate::EntryPosition;
use crate::ExtractionReport;
use crate::Malformation;
use crate::OccupiedBy;
use crate::ProgressCallback;
use crate::Result;
use crate::SecurityConfig;
use crate::SinkOptions;
use crate::Skip;
use crate::SkipKind;
pub(crate) use crate::SpecialFile;
use crate::Violation;
use crate::copy::CopyBuffer;
use crate::copy::CopyError;
use crate::copy::copy_cancellable;
use crate::error::QuotaResource;
use crate::formats::dir_walker::DirWalker;
use crate::formats::occupant::KeptOccupant;
use crate::formats::occupant::OccupantAction;
use crate::formats::occupant::OccupantPolicy;
use crate::formats::occupant::OccupiedSite;
use crate::formats::occupant::ReplacePermit;
use crate::formats::occupant::kept_occupant_refusal;
use crate::formats::occupant::occupied_by;
use crate::formats::occupant::replaces_symlink;
use crate::formats::pinned_dir::Leaf;
use crate::formats::pinned_dir::PendingMode;
use crate::formats::pinned_dir::PinnedRoot;
use crate::formats::pinned_dir::TempFileGuard;
use crate::formats::pinned_dir::TempLeaf;
use crate::formats::pinned_dir::VettedDir;
use crate::formats::source_fault::ReadFaults;
use crate::mark::MarkRun;
#[cfg(unix)]
use crate::security::fs_view::LinkKind;
use crate::security::fs_view::Occupant;
use crate::security::fs_view::PathModel;
use crate::security::permissions::CreateMode;
use crate::security::quota::QuotaPermit;
use crate::selection::EntryShape;
use crate::types::SafePath;
use crate::types::SafeSymlink;
use crate::types::safe_path::ParentCheck;

/// Opens the archive at `path` for reading.
///
/// A missing archive is [`ArchiveError::SourceNotFound`] and any other failure
/// is [`ArchiveError::SourceNotAccessible`], the classification creation
/// already gives its sources, so every front end can point at the archive path.
///
/// A path that is not a regular file (a named pipe, a device, a directory) is
/// refused with [`ArchiveError::SourceNotAccessible`] carrying
/// [`NotARegularFile`]. On Unix the open never blocks, so a pipe with no
/// writer cannot hold the run; the returned handle is back in blocking mode.
///
/// # Errors
///
/// See above.
pub(crate) fn open_archive(path: &Path) -> Result<File> {
    let refuse = |error| crate::creation::source::source_error(path, error);
    let file = open_without_blocking(path).map_err(refuse)?;
    if file.metadata().map_err(refuse)?.is_file() {
        #[cfg(unix)]
        clear_nonblocking(&file).map_err(refuse)?;
        Ok(file)
    } else {
        Err(refuse(io::Error::other(NotARegularFile)))
    }
}

#[cfg(unix)]
#[expect(
    clippy::disallowed_methods,
    reason = "the archive is the caller's own path, not an entry below the destination"
)]
fn open_without_blocking(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
}

#[cfg(unix)]
fn clear_nonblocking(file: &File) -> io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(file)?;
    rustix::fs::fcntl_setfl(file, flags.difference(rustix::fs::OFlags::NONBLOCK))?;
    Ok(())
}

#[cfg(not(unix))]
fn open_without_blocking(path: &Path) -> io::Result<File> {
    File::open(path)
}

/// The cause of an archive path that names something other than a regular
/// file.
#[derive(Debug, thiserror::Error)]
#[error("not a regular file")]
pub(crate) struct NotARegularFile;

impl NotARegularFile {
    /// Whether `error` is the refusal [`open_archive`] gives such a path.
    pub(crate) fn is_cause_of(error: &ArchiveError) -> bool {
        matches!(error, ArchiveError::SourceNotAccessible { error, .. }
            if error.get_ref().is_some_and(<dyn std::error::Error + Send + Sync>::is::<Self>))
    }
}

/// RAII guard that calls `on_entry_complete` when dropped.
///
/// The only way to build one is [`EntryCompleteGuard::try_start`], which fires
/// `on_entry_start`, so `on_entry_complete` is paired with it on every path,
/// including an early `?` return.
///
/// `try_start` is the single per-entry cancellation hook of extraction,
/// listing, verification and creation: it polls
/// [`ProgressCallback::is_cancelled`] before announcing an entry.
pub(crate) struct EntryCompleteGuard<'a>(DropGuard<Announced<'a>, fn(Announced<'a>)>);

/// The callback and the entry whose completion the guard announces.
type Announced<'a> = (&'a mut dyn ProgressCallback, &'a Path);

impl<'a> EntryCompleteGuard<'a> {
    /// Fires `on_entry_start` and returns the guard that will fire
    /// `on_entry_complete` on drop unless [`complete`](Self::complete) ran.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::Cancelled`] without announcing the entry when
    /// the callback asks to stop.
    pub(crate) fn try_start(
        progress: &'a mut dyn ProgressCallback,
        path: &'a std::path::Path,
        position: EntryPosition,
    ) -> Result<Self> {
        if progress.is_cancelled() {
            return Err(ArchiveError::Cancelled);
        }
        progress.on_entry_start(path, position);
        Ok(Self(DropGuard::new(
            (progress, path),
            |(progress, path)| progress.on_entry_complete(path),
        )))
    }

    /// Returns a mutable reference to the underlying progress callback.
    ///
    /// Use this to pass the callback to nested helpers while keeping the guard
    /// in scope for RAII completion.
    pub(crate) fn progress_mut(&mut self) -> &mut dyn ProgressCallback {
        &mut *self.0.0
    }

    /// Fire `on_entry_complete` immediately and prevent the drop from firing
    /// again.
    pub(crate) fn complete(self) {
        drop(self);
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
#[inline]
#[must_use]
pub(crate) fn normalize_entry_name(name: &str) -> String {
    if name.contains('\\') {
        name.replace('\\', "/")
    } else {
        name.to_owned()
    }
}

/// Builds the error returned for any password-protected archive, so ZIP and
/// 7z (open, list and extract paths) report encryption identically.
#[must_use]
pub(crate) fn encrypted_archive_error() -> ArchiveError {
    Violation::Encrypted {
        reason: crate::EncryptionRefusal::PasswordRequired,
        name: None,
    }
    .into()
}

/// Adds `n` to a byte counter.
///
/// # Errors
///
/// Returns `QuotaExceeded` on overflow.
#[inline]
pub(crate) fn checked_add_bytes(total: u64, n: u64) -> Result<u64> {
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
pub(crate) fn checked_add_count(total: usize, n: usize) -> Result<usize> {
    total.checked_add(n).ok_or(ArchiveError::QuotaExceeded {
        resource: QuotaResource::IntegerOverflow,
    })
}

/// Records `path` in `report.skipped` as skipped for `kind`.
///
/// The one place an extraction counts a skip, so the counter fails closed
/// instead of wrapping (#515).
///
/// # Errors
///
/// Returns `QuotaExceeded { resource: IntegerOverflow }` when the counter
/// would overflow.
pub(crate) fn record_skip(
    report: &mut ExtractionReport,
    kind: SkipKind,
    path: &Path,
) -> Result<()> {
    report.skipped.record(Skip::new(kind, path))
}

/// Records `path` as a pre-existing duplicate the skip-duplicates policy kept.
///
/// # Errors
///
/// See [`record_skip`].
pub(crate) fn record_duplicate_skip(report: &mut ExtractionReport, path: &Path) -> Result<()> {
    record_skip(report, SkipKind::Duplicate, path)
}

/// Whether the extension allowlist admits `path`.
///
/// The one definition of the rule, applied by the validator's file screen and
/// by the passes that must agree with it on which files are skipped.
#[must_use]
pub(crate) fn is_extension_allowed(path: &Path, config: &SecurityConfig) -> bool {
    config.is_extension_allowed(path.extension().and_then(|e| e.to_str()))
}

/// Refuses an entry name `model` cannot hold.
///
/// A regular file the extension allowlist skips is never created, so it is
/// exempt. The one definition of that rule, shared by extraction, `list` and
/// `verify` so their verdicts cannot drift.
///
/// # Errors
///
/// Returns the name-too-long error when the path or a component exceeds the
/// model's limits.
pub(crate) fn check_entry_name_limits(
    model: PathModel,
    path: &Path,
    regular_file: bool,
    config: &SecurityConfig,
) -> std::io::Result<()> {
    if regular_file && !is_extension_allowed(path, config) {
        return Ok(());
    }
    model.check_name_lengths(path)
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
/// second time: it is threaded into [`copy_bounded`](crate::copy::copy_bounded)
/// as a hard ceiling enforced on every buffered read, so a forged small
/// `expected_size` cannot let the real decompressed stream grow unbounded, and
/// a short stream (less than declared) is rejected once it reaches EOF. On
/// either violation, the partially-written file is removed via
/// [`TempFileGuard`] before the error propagates — a rejected entry never
/// leaves oversized or truncated content on disk.
///
/// # Permission Enforcement
///
/// On Unix, the mode is given through the create call and the already-open
/// file descriptor (`fchmod`), never a path-based `std::fs::set_permissions()`
/// call, so no TOCTOU window opens between file creation and permission
/// enforcement (issue #460). Under `PermissionPolicy::Preserve` the exact
/// sanitized mode is set, whatever the caller's umask. Under
/// `PermissionPolicy::Normalize` the sanitized mode is passed to the create and
/// the kernel subtracts the umask, which is never read. See
/// [`VettedDir::create_new_deferred`] for the full contract.
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
/// * `root` - Destination directory, pinned by an open handle
/// * `report` - Extraction statistics (updated)
/// * `dirs` - Creates and vets the parent directories
/// * `options` - Duplicate-handling policy for a pre-existing destination path
/// * `write` - The [`FileWrite`]: its permit proves the size was reserved
///   against the quota tracker and, per the security note above, is enforced as
///   a hard streaming ceiling and exact post-copy match
///
/// A skipped duplicate entry is recorded in `report.skipped`.
///
/// # Errors
///
/// Returns error if:
/// - Parent directory creation fails
/// - Quota would be exceeded (checked before write)
/// - File creation fails
/// - I/O error during copy
/// - The actual decompressed byte count exceeds or falls short of the permit's
///   size (forged size metadata)
#[expect(
    clippy::too_many_arguments,
    reason = "the write context is bundled in FileWrite; the rest is the entry's location and run state"
)]
#[inline]
pub(crate) fn extract_file_with_permit<R: Read, P: ParentCheck>(
    reader: &mut R,
    faults: ReadFaults<'_>,
    safe_path: &SafePath<P>,
    root: &PinnedRoot,
    report: &mut ExtractionReport,
    dirs: DirWalker,
    options: SinkOptions,
    write: FileWrite<'_>,
) -> Result<()> {
    let FileWrite {
        copy_buffer,
        permit,
        marking,
        mode,
        progress,
    } = write;
    let duplicates = OccupantPolicy::of(options);

    let (parent, leaf) = dirs.ensure_parent(root, safe_path)?;

    // The size was already reserved against QuotaTracker during
    // validate_entry (proven by the QuotaPermit consumed above); this only
    // guards report.bytes_written, a different quantity, against overflow.
    // Checked before any filesystem mutation so a rejected entry never
    // leaves a zero-byte file on disk (restores the pre-#446 ordering).
    checked_add_bytes(report.bytes_written, permit.admitted().get())?;

    let timing = ModeTiming::of(marking);
    let Some(OutputSlot {
        file: output_file,
        pending,
        written_at,
    }) = open_output_slot(
        &parent,
        leaf,
        safe_path.as_path(),
        mode,
        duplicates,
        root,
        timing,
    )?
    else {
        return record_duplicate_skip(report, safe_path.as_path());
    };

    // Removes the partial file when the copy aborts (forged `expected_size`);
    // `written_at` never holds a pre-existing entry, so nothing else is lost.
    let guard = written_at.guard(&parent, leaf);
    let bytes_written = copy_and_finish_file(
        reader,
        output_file,
        faults,
        FileWrite {
            copy_buffer,
            permit,
            marking,
            mode,
            progress: &mut *progress,
        },
        pending,
    )?;
    let replaced = matches!(written_at, WrittenAt::Temp(..));
    commit_output(&parent, written_at, leaf, safe_path.as_path())?;
    if replaced {
        root.created().note(&parent, leaf, safe_path.as_path());
    }
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
pub(crate) fn record_file_written(
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
pub(crate) const MAX_TEMP_FILE_CREATE_ATTEMPTS: u32 = 8;

/// When a created file is given its mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModeTiming {
    /// Right after the create, before any byte is written.
    AtCreate,
    /// After the caller wrote the download-origin mark, through the returned
    /// [`PendingMode`].
    AfterMark,
}

/// Creates a new file in `dir` under the first free name drawn from
/// `next_candidate`, retrying on `AlreadyExists` up to
/// [`MAX_TEMP_FILE_CREATE_ATTEMPTS`] times.
///
/// Each attempt uses [`create_file`] (`O_EXCL`), so a planted entry at a
/// predicted name is never followed or reused. `entry` names the file the temp
/// file stands in for, for the error text only. The permit proves the policy
/// allows replacing `entry`, which the temp file exists to do.
///
/// With [`ModeTiming::AfterMark`] the returned [`PendingMode`] is still to be
/// applied; with [`ModeTiming::AtCreate`] it is already spent.
///
/// # Errors
///
/// Returns the first non-`AlreadyExists` I/O error, or `AlreadyExists` when
/// every attempt collided.
pub(crate) fn create_temp_sibling_with(
    dir: &VettedDir,
    entry: Leaf<'_>,
    mode: Option<CreateMode>,
    timing: ModeTiming,
    _replace: &ReplacePermit,
    mut next_candidate: impl FnMut() -> TempLeaf,
) -> std::io::Result<(TempLeaf, File, PendingMode)> {
    for _ in 0..MAX_TEMP_FILE_CREATE_ATTEMPTS {
        let candidate = next_candidate();
        match create_file(dir, candidate.as_leaf(), mode, timing) {
            Ok((file, pending)) => return Ok((candidate, file, pending)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        crate::IoContext::new(
            "failed to create a unique temp file",
            format!(
                "{} after {MAX_TEMP_FILE_CREATE_ATTEMPTS} attempts",
                crate::path_text(Path::new(entry.as_os_str()))
            ),
        ),
    ))
}

/// Where an output file was written before it reaches its final name.
enum WrittenAt {
    /// The final name itself.
    Final,
    /// A sibling temp file that is renamed over the existing entry.
    Temp(TempLeaf, ReplacePermit),
}

impl WrittenAt {
    /// A guard that removes the written file unless persisted.
    fn guard<'d>(&self, dir: &'d VettedDir, final_name: Leaf<'_>) -> TempFileGuard<'d> {
        match self {
            Self::Final => TempFileGuard::new(dir, final_name),
            Self::Temp(temp, _) => TempFileGuard::for_temp(dir, temp.clone()),
        }
    }
}

impl ModeTiming {
    /// The timing a run needs: the mode waits for the mark only when one is
    /// written.
    pub(crate) const fn of(marking: Option<&MarkRun>) -> Self {
        if marking.is_some() {
            Self::AfterMark
        } else {
            Self::AtCreate
        }
    }
}

/// Creates `leaf` exclusively and gives it its mode at `timing`.
pub(crate) fn create_file(
    dir: &VettedDir,
    leaf: Leaf<'_>,
    mode: Option<CreateMode>,
    timing: ModeTiming,
) -> std::io::Result<(File, PendingMode)> {
    let (file, pending) = dir.create_new_deferred(leaf, mode)?;
    match timing {
        ModeTiming::AfterMark => Ok((file, pending)),
        ModeTiming::AtCreate => {
            pending.apply(&file)?;
            Ok((file, PendingMode::applied()))
        }
    }
}

/// Writes the download-origin mark through `file`, then gives it the mode it
/// was created without.
///
/// The mode is applied whatever the mark's result: a failed best-effort mark is
/// counted by the run, and the file must not stay owner-only because of it.
///
/// # Errors
///
/// The I/O error of applying the mode.
pub(crate) fn seal_output(
    file: &File,
    pending: PendingMode,
    marking: Option<&MarkRun>,
) -> std::io::Result<()> {
    if let Some(run) = marking {
        run.mark_file(file);
    }
    pending.apply(file)
}

/// Write buffer capacity (64 KiB) used when streaming archive file contents
/// to disk, matching typical filesystem block sizes and cutting per-file
/// write syscalls.
const FILE_WRITE_BUFFER_BYTES: usize = 64 * 1024;

/// Streams `reader` into `file` through a [`FILE_WRITE_BUFFER_BYTES`]-byte
/// buffer, enforces the permit's size, classifies read faults, flushes, seals
/// the file (download-origin mark then pending mode), and closes `file` before
/// returning.
///
/// Taking `file` by value ensures the descriptor closes on both success
/// (explicit `drop`) and any error unwind before the caller's cleanup guard
/// unlinks the file or renames a temp file into place — critical on Windows,
/// where unlinking or renaming an open handle fails.
///
/// # Security - Streaming Size Enforcement (GHSA-5j8q-wxg5-hj4r)
///
/// The [`AdmittedSize`](crate::security::quota::AdmittedSize) of `write.permit`
/// is enforced as a hard streaming ceiling and exact post-copy match by
/// [`copy_cancellable`].
///
/// # Errors
///
/// Returns a classified error when reading, writing, size enforcement,
/// cancellation, flushing, or mode application fails.
pub(crate) fn copy_and_finish_file<R: Read + ?Sized>(
    reader: &mut R,
    file: File,
    faults: ReadFaults<'_>,
    write: FileWrite<'_>,
    pending: PendingMode,
) -> Result<u64> {
    let FileWrite {
        copy_buffer,
        permit,
        marking,
        mode: _,
        progress,
    } = write;
    let mut writer = BufWriter::with_capacity(FILE_WRITE_BUFFER_BYTES, file);
    let bytes_written = copy_cancellable(
        reader,
        &mut writer,
        copy_buffer,
        permit.into_admitted(),
        progress,
    )
    .map_err(|error| faults.classify(error))?;
    writer.flush()?;
    drop(finish_written(writer, pending, marking)?);
    Ok(bytes_written)
}

/// What a file write consumes besides the entry's bytes and location: the
/// scratch buffer, the quota permit, the mark, the creation mode and the
/// progress callback.
///
/// The permit is held by value and the struct is not `Clone`, so one value
/// authorizes exactly one write.
pub(crate) struct FileWrite<'a> {
    pub(crate) copy_buffer: &'a mut CopyBuffer,
    pub(crate) permit: QuotaPermit,
    pub(crate) marking: Option<&'a MarkRun>,
    pub(crate) mode: Option<CreateMode>,
    pub(crate) progress: &'a mut dyn ProgressCallback,
}

/// Flushes out `writer`'s file handle and seals it: the mark, then the mode.
///
/// The caller drops the returned handle before the name is published or
/// replaced.
///
/// # Errors
///
/// The I/O error of recovering the file from the buffer, or of applying the
/// mode.
fn finish_written(
    writer: BufWriter<File>,
    pending: PendingMode,
    marking: Option<&MarkRun>,
) -> std::io::Result<File> {
    let file = writer
        .into_inner()
        .map_err(std::io::IntoInnerError::into_error)?;
    seal_output(&file, pending, marking)?;
    Ok(file)
}

/// An open, empty output file and where its content must end up.
struct OutputSlot {
    file: File,
    pending: PendingMode,
    written_at: WrittenAt,
}

/// Opens the destination for a regular-file entry without ever writing
/// through an existing inode.
///
/// A free name is created in place with `O_EXCL`. When an entry already
/// exists, overwrite mode writes a fresh sibling temp file that the caller
/// renames over the entry, so other hardlinks to the old inode keep their
/// content. Returns `None` when the entry exists and `duplicates` is `Skip`.
/// Under `Refuse` a file or symlink this run created is a duplicate and gives
/// `None` as well; any other occupant fails with `DestinationOccupied`.
fn open_output_slot(
    dir: &VettedDir,
    leaf: Leaf<'_>,
    rel: &Path,
    mode: Option<CreateMode>,
    duplicates: OccupantPolicy,
    root: &PinnedRoot,
    timing: ModeTiming,
) -> Result<Option<OutputSlot>> {
    match create_file(dir, leaf, mode, timing) {
        Ok((file, pending)) => {
            root.created().note_file(&file, dir, leaf, rel);
            Ok(Some(OutputSlot {
                file,
                pending,
                written_at: WrittenAt::Final,
            }))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let action = duplicates.on_occupant(
                EntryShape::File,
                rel,
                || dir.probe(leaf),
                || root.created().maker(dir, leaf, rel),
                OccupiedSite::Host(root),
            )?;
            let OccupantAction::Replace(permit) = action else {
                return Ok(None);
            };
            refuse_non_file_occupant(dir, leaf, rel, root)?;
            let (temp, file, pending) =
                create_temp_sibling_with(dir, leaf, mode, timing, &permit, TempLeaf::next)
                    .map_err(|e| replace_error(rel, &e))?;
            Ok(Some(OutputSlot {
                file,
                pending,
                written_at: WrittenAt::Temp(temp, permit),
            }))
        }
        Err(e) => Err(name_occupant_on_open_error(dir, leaf, rel, root, e)),
    }
}

/// Renames the completed temp file over the entry it replaces, if any.
fn commit_output(dir: &VettedDir, written_at: WrittenAt, leaf: Leaf<'_>, rel: &Path) -> Result<()> {
    if let WrittenAt::Temp(temp, permit) = written_at {
        dir.replace_entry(&temp, leaf, permit)
            .map_err(|e| replace_error(rel, &e))?;
    }
    Ok(())
}

/// Wraps a failure to replace the existing entry at `rel`, keeping its kind
/// and naming the entry.
fn replace_error(rel: &Path, err: &std::io::Error) -> std::io::Error {
    std::io::Error::new(
        err.kind(),
        crate::IoContext::new(
            "cannot replace the existing file",
            format!("{}: {err}", crate::path_text(rel)),
        ),
    )
}

/// Fails with the typed refusal of [`kept_occupant_refusal`] when `leaf`
/// holds a directory or a symlink, which an overwrite never replaces.
fn refuse_non_file_occupant(
    dir: &VettedDir,
    leaf: Leaf<'_>,
    rel: &Path,
    root: &PinnedRoot,
) -> Result<()> {
    let kept = dir.probe(leaf).ok().flatten().and_then(KeptOccupant::of);
    kept.map_or(Ok(()), |kept| {
        Err(kept_refusal_at(kept, dir, leaf, rel, root))
    })
}

/// [`kept_occupant_refusal`] for the occupant at `leaf` of a host run, whose
/// maker is read from the run record.
pub(crate) fn kept_refusal_at(
    kept: KeptOccupant,
    dir: &VettedDir,
    leaf: Leaf<'_>,
    rel: &Path,
    root: &PinnedRoot,
) -> ArchiveError {
    kept_occupant_refusal(
        kept,
        rel,
        || root.created().created_here(dir, leaf, rel),
        OccupiedSite::Host(root),
    )
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
/// * `policy` - What an occupied landing means: a directory entry over a file
///   or symlink the run made is a repeat when repeated paths are refused
///
/// # Errors
///
/// Returns an error if directory creation fails due to I/O errors or a
/// component is a symlink the policy refuses.
pub(crate) fn create_directory<P: ParentCheck>(
    safe_path: &SafePath<P>,
    root: &PinnedRoot,
    report: &mut ExtractionReport,
    dirs: DirWalker,
    policy: OccupantPolicy,
) -> Result<()> {
    let rel = safe_path.as_path();
    check_directory_occupant(root, dirs, rel, policy, |occupant| {
        maker_of(root, dirs, rel, occupant)
    })?;
    dirs.ensure_dir(root, safe_path)?;

    report.directories_created = report.directories_created.saturating_add(1);

    Ok(())
}

/// Fails with an entry-naming error when `rel` holds something a directory
/// entry cannot become: a file (`DestinationOccupied`), or a symlink that does
/// not resolve to a directory inside the destination (a security violation,
/// the category `verify` reports for it). `maker` says who made that occupant.
///
/// A landing that is absent or already a directory, by one path `lstat`, is
/// accepted at once: the lstat only chooses the error and never enforces, the
/// fd-relative walk in [`DirWalker::ensure_dir`] does. Any other occupant, and
/// a name the host cannot look up by path (too long), is read through its
/// pinned parent, so the verdict does not depend on how long its host path
/// is. A parent that cannot be opened is left
/// to the walk in [`DirWalker::ensure_dir`], which refuses a blocking parent
/// again and alone names a file parent, since only it can tell who made that
/// file.
pub(crate) fn check_directory_occupant(
    root: &PinnedRoot,
    dirs: DirWalker,
    rel: &Path,
    policy: OccupantPolicy,
    maker: impl FnOnce(Occupant) -> OccupiedBy,
) -> Result<()> {
    if landing_is_free_or_directory(root, rel) {
        return Ok(());
    }
    let Ok((parent, leaf)) = dirs.open_parent(root, rel) else {
        return Ok(());
    };
    let found = match parent.probe(leaf) {
        Ok(None | Some(Occupant::Directory)) | Err(_) => return Ok(()),
        Ok(Some(found)) => found,
    };
    policy.repeats().refuse_repeat(
        EntryShape::Directory,
        rel,
        found,
        || root.created().maker(&parent, leaf, rel),
        OccupiedSite::Host(root),
    )?;
    match found {
        Occupant::File => {
            Err(OccupiedSite::Host(root).refuse(rel, Some(Occupant::File), maker(Occupant::File)))
        }
        Occupant::Symlink => {
            refuse_unadmitted_symlink_landing(root, dirs, rel, || maker(Occupant::Symlink))
        }
        Occupant::Directory => Ok(()),
    }
}

/// Whether one path `lstat` finds nothing, or a directory, at `rel`: the
/// common landing of a directory entry, which needs no pinned probe.
///
/// The `lstat` follows symlinks in intermediate components, so this is not
/// containment: `ensure_dir`'s fd-relative no-follow walk enforces. A `true`
/// only spares the classification walk and never chooses an error.
pub(crate) fn landing_is_free_or_directory(root: &PinnedRoot, rel: &Path) -> bool {
    match root.dest().probe(rel).lstat() {
        Ok(metadata) => metadata.is_dir(),
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
    }
}

/// Fails with [`replaces_symlink`] when `rel` is a symlink that does not
/// resolve to a directory inside the destination; every other outcome,
/// including a policy refusal of an inside link, is left to the write phase.
///
/// The one rule for a directory entry over a symlink, shared by
/// [`check_directory_occupant`] and the 7z pre-pass.
pub(crate) fn refuse_unadmitted_symlink_landing(
    root: &PinnedRoot,
    dirs: DirWalker,
    rel: &Path,
    maker: impl FnOnce() -> OccupiedBy,
) -> Result<()> {
    match dirs.vet_dir(root, rel, rel) {
        Err(
            ArchiveError::SymlinkEscape { .. }
            | ArchiveError::SecurityViolation {
                kind: Violation::SymlinkParent { .. },
                ..
            },
        ) => Err(replaces_symlink(rel, maker())),
        Ok(()) | Err(_) => Ok(()),
    }
}

/// Who made the `occupant` at `rel`: the run when its record confirms it, read
/// through a strict walk to the parent that only a refusal pays for.
fn maker_of(root: &PinnedRoot, dirs: DirWalker, rel: &Path, occupant: Occupant) -> OccupiedBy {
    occupied_by(Some(occupant), || {
        dirs.open_resolved_parent(root, rel)
            .is_ok_and(|(dir, leaf)| root.created().created_here(&dir, leaf, rel))
    })
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
/// - **Other platforms**: Refuses through [`require_symlink_creation`]
///
/// # Error Behavior
///
/// What an occupied path does follows `options.existing_files`: `Skip` keeps
/// the occupant and records the skip, `Overwrite` replaces a file but never a
/// symlink or directory, and `Refuse` fails with `DestinationOccupied` for an
/// occupant this run did not create. A symlink that already holds the same
/// target is skipped as unchanged under every policy.
///
/// # Arguments
///
/// * `safe_symlink` - Validated symlink entry
/// * `root` - Destination directory, pinned by an open handle
/// * `report` - Extraction statistics (updated)
/// * `dirs` - Creates and vets the parent directories
/// * `options` - Duplicate-handling policy for a pre-existing destination path
///
/// A skipped duplicate symlink is recorded in `report.skipped`.
///
/// # Errors
///
/// Returns an error if:
/// - Platform does not support symlinks
/// - Parent directory creation fails
/// - Symlink creation fails (including when target path already exists)
/// - Removing an existing path fails when the policy is
///   `ExistingFiles::Overwrite`
/// - A symlink with a different target occupies the path
/// - A directory occupies the path under `ExistingFiles::Overwrite`, which
///   never replaces a directory; the error names the entry (`Refuse` fails
///   earlier as a conflict, `Skip` skips the entry)
#[cfg_attr(
    not(unix),
    expect(
        unused_variables,
        reason = "only the Unix path reads the entry, the handles and the options"
    )
)]
#[cfg_attr(
    not(unix),
    expect(
        clippy::needless_pass_by_ref_mut,
        reason = "only the Unix path updates the counters; the signature is shared"
    )
)]
pub(crate) fn create_symlink<P: ParentCheck>(
    safe_symlink: &SafeSymlink<P>,
    root: &PinnedRoot,
    report: &mut ExtractionReport,
    dirs: DirWalker,
    options: SinkOptions,
) -> Result<()> {
    #[cfg(unix)]
    {
        let duplicates = OccupantPolicy::of(options);
        let target_path = safe_symlink.target_path();

        let (parent, leaf) = dirs.ensure_parent(root, safe_symlink.link())?;

        if let Some(existing) = parent.probe(leaf)? {
            let link_path = safe_symlink.link().as_path();
            let action = duplicates.on_occupant(
                EntryShape::Link(LinkKind::Symlink),
                link_path,
                || Ok(Some(existing)),
                || root.created().maker(&parent, leaf, link_path),
                OccupiedSite::Host(root),
            )?;
            let OccupantAction::Replace(permit) = action else {
                return record_duplicate_skip(report, link_path);
            };
            match existing {
                Occupant::Symlink => {
                    // An unchanged link re-points nothing; a different target
                    // could re-point a path that an earlier link's `..`
                    // resolved through.
                    if parent.read_link(leaf)? == target_path {
                        return record_duplicate_skip(report, link_path);
                    }
                    return Err(kept_refusal_at(
                        KeptOccupant::Symlink,
                        &parent,
                        leaf,
                        link_path,
                        root,
                    ));
                }
                Occupant::Directory => {
                    return Err(kept_refusal_at(
                        KeptOccupant::Directory,
                        &parent,
                        leaf,
                        link_path,
                        root,
                    ));
                }
                Occupant::File => parent.remove_occupant(leaf, permit)?,
            }
        }

        parent.symlink(target_path, leaf)?;
        root.created()
            .note(&parent, leaf, safe_symlink.link().as_path());

        report.symlinks_created = report.symlinks_created.saturating_add(1);

        Ok(())
    }

    #[cfg(not(unix))]
    {
        require_symlink_creation()
    }
}

/// Replaces `err`, the failure of an overwrite-mode open at `path`, with the
/// typed [`kept_occupant_refusal`] when the failure is the refusal of the
/// directory or symlink that holds the path; any other failure (including a
/// different errno on such a path) is returned unchanged.
///
/// Runs only on the error path, via a `probe` of the name, so the success path
/// costs nothing.
fn name_occupant_on_open_error(
    dir: &VettedDir,
    leaf: Leaf<'_>,
    rel: &Path,
    root: &PinnedRoot,
    err: std::io::Error,
) -> ArchiveError {
    refused_occupant(dir, leaf, &err).map_or(ArchiveError::Io(err), |kept| {
        kept_refusal_at(kept, dir, leaf, rel, root)
    })
}

/// The occupant of `leaf` whose presence explains `err`, if any.
///
/// A symlink refusal is identified by `ELOOP` on Unix and by the
/// `AlreadyExists` that `VettedDir::create_new_deferred` returns elsewhere.
fn refused_occupant(dir: &VettedDir, leaf: Leaf<'_>, err: &std::io::Error) -> Option<KeptOccupant> {
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
        Occupant::Directory if dir_refusal => Some(KeptOccupant::Directory),
        Occupant::Symlink if symlink_refusal => Some(KeptOccupant::Symlink),
        Occupant::Directory | Occupant::Symlink | Occupant::File => None,
    }
}

/// Fails on a host that cannot create symlinks, so a format can refuse a link
/// before it writes anything.
///
/// # Errors
///
/// Returns `SecurityViolation` on a non-Unix host.
pub(crate) fn require_symlink_creation() -> Result<()> {
    cfg!(unix).ok_or_else(|| Violation::SymlinksUnsupported.into())
}

/// The file-type bits of a Unix mode (`S_IFMT`).
const S_IFMT: u32 = 0o17_0000;

/// The file type recorded in the type bits of a Unix mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnixFileType {
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
    pub(crate) fn from_mode(mode: u32) -> Option<Self> {
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
pub(crate) const MAX_STORED_SYMLINK_TARGET: u64 =
    crate::security::fs_view::MAX_SYMLINK_TARGET_BYTES as u64;

/// The refusal for a symlink target stored as entry data above the host's
/// symlink target limit.
///
/// # Errors
///
/// Returns `SecurityViolation` when `size` exceeds
/// [`MAX_STORED_SYMLINK_TARGET`].
pub(crate) fn check_symlink_target_size(size: u64) -> Result<()> {
    if size > MAX_STORED_SYMLINK_TARGET {
        return Err(symlink_target_too_large(size));
    }
    Ok(())
}

/// The refusal for a stored symlink target of `size` bytes above the limit.
pub(crate) fn symlink_target_too_large(size: u64) -> ArchiveError {
    Violation::LinkTargetTooLarge {
        size,
        max: MAX_STORED_SYMLINK_TARGET,
    }
    .into()
}

/// Decodes the bytes of a stored symlink target.
///
/// # Errors
///
/// Returns `InvalidArchive` when the bytes are not UTF-8.
pub(crate) fn symlink_target_from_bytes(target_bytes: &[u8]) -> Result<PathBuf> {
    let target_str = std::str::from_utf8(target_bytes)
        .map_err(|_| ArchiveError::from(Malformation::SymlinkTargetNotUtf8))?;

    Ok(PathBuf::from(target_str))
}

/// Whether `error` carries one of the OS error codes in `set`.
///
/// The one spelling of an errno comparison, so a failure is classified the same
/// way wherever it is checked.
#[cfg(any(unix, target_os = "wasi"))]
pub(crate) fn errno_is(error: &std::io::Error, set: &[rustix::io::Errno]) -> bool {
    rustix::io::Errno::from_io_error(error).is_some_and(|errno| set.contains(&errno))
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
pub(crate) fn is_filesystem_loop_error(error: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        errno_is(error, &[rustix::io::Errno::LOOP])
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
            Violation::HardlinkTargetChanged.into()
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
/// [`VettedDir::create_new_deferred`] (refusing to create through a
/// pre-existing destination name, symlink or not) and `from` from
/// [`VettedDir::open_read`] (refusing to follow a symlink), and reserve quota
/// from `from`'s `fstat` size, which the `permit` then carries.
///
/// The permit's byte count is a hard ceiling and an exact length: the quota was
/// charged for that many bytes, so a target that grew after the `fstat` fails
/// closed instead of writing past the charged permit, and one that shrank fails
/// too.
///
/// Permissions are not copied here: the caller creates `to` with the
/// sanitized mode of the target before any byte is written (a pre-existing
/// target in the destination can carry setuid, setgid, sticky or world-write
/// bits that extraction never sanitized).
///
/// # Errors
///
/// Returns `SecurityViolation` if the target's length differs from
/// the permit's byte count, and an I/O error if the copy fails.
pub(crate) fn copy_file_content_with_permit(
    mut from: File,
    to: &mut File,
    copy_buffer: &mut CopyBuffer,
    permit: QuotaPermit,
    progress: &mut dyn ProgressCallback,
) -> Result<u64> {
    copy_cancellable(&mut from, to, copy_buffer, permit.into_admitted(), progress)
        .map_err(hardlink_target_changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ArchiveError;
    use crate::ExtractionReport;
    use crate::Malformation;
    use crate::NoopProgress;
    use crate::SecurityConfig;
    use crate::copy::CopyBuffer;
    use crate::formats::source_fault::ReadFamily;
    use crate::formats::source_fault::SourceTap;
    use crate::security::RawMode;
    use crate::security::permissions::sanitize_permissions;
    use crate::security::quota::QuotaTracker;
    use crate::types::DestDir;
    use std::assert_matches;
    use std::io::Cursor;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[cfg(any(unix, target_os = "wasi"))]
    #[test]
    fn errno_is_matches_only_the_listed_codes() {
        use rustix::io::Errno;

        let error = |errno: Errno| std::io::Error::from_raw_os_error(errno.raw_os_error());
        let all = [
            Errno::NOENT,
            Errno::NOTDIR,
            Errno::LOOP,
            Errno::ACCESS,
            Errno::NOTSUP,
            Errno::INVAL,
            Errno::BADF,
            Errno::MFILE,
            Errno::NFILE,
            Errno::NOMEM,
        ];
        for listed in all {
            for observed in all {
                assert_eq!(
                    errno_is(&error(observed), &[listed]),
                    observed == listed,
                    "{observed:?} against {listed:?}"
                );
            }
            assert!(errno_is(&error(listed), &all));
            assert!(!errno_is(&error(listed), &[]));
        }
        assert!(!errno_is(&std::io::Error::other("no code"), &all));
        assert_eq!(
            errno_is(&error(Errno::OPNOTSUPP), &[Errno::NOTSUP]),
            Errno::OPNOTSUPP == Errno::NOTSUP,
            "equal on Linux, distinct on macOS"
        );
    }

    /// Builds an exact [`CreateMode`] for tests that don't otherwise need a
    /// `SecurityConfig` in scope. None of the modes used across these tests
    /// carry setuid/setgid/world-writable bits, so sanitizing with the
    /// default config never changes the value.
    fn sanitized(mode: u32) -> CreateMode {
        let config = SecurityConfig::default();
        CreateMode::Exact(sanitize_permissions(RawMode::new(mode), &config))
    }

    fn test_walker() -> DirWalker {
        DirWalker::new(&SecurityConfig::default())
    }

    fn pinned(dest: &DestDir) -> PinnedRoot {
        PinnedRoot::open(dest.clone()).expect("open destination")
    }

    /// Creates `path` the way extraction does: exclusively, relative to a
    /// handle on its parent directory.
    fn create_file_with_mode(path: &Path, mode: Option<CreateMode>) -> std::io::Result<File> {
        let parent = pinned(&DestDir::new(path.parent().expect("parent")).expect("dest"));
        let (_, leaf) = Leaf::split(Path::new(path.file_name().expect("name"))).expect("leaf");
        parent.dir().reopen()?.create_new(leaf, mode)
    }

    #[test]
    fn normalize_entry_name_turns_backslashes_into_slashes_only() {
        assert_eq!(normalize_entry_name("foo\\bar\\baz.txt"), "foo/bar/baz.txt");
        assert_eq!(normalize_entry_name("plain/path.txt"), "plain/path.txt");
    }

    #[cfg(unix)]
    #[test]
    fn replace_refusals_of_names_differing_in_invalid_bytes_differ() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let io = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let message =
            |bytes: &[u8]| replace_error(Path::new(OsStr::from_bytes(bytes)), &io).to_string();
        let (a, b) = (message(b"caf\xe9"), message(b"caf\xe8"));
        assert_ne!(a, b);
        assert!(!a.contains('\u{FFFD}'), "{a}");

        let occupant = |bytes: &[u8]| {
            OccupiedSite::Detached
                .refuse(
                    Path::new(OsStr::from_bytes(bytes)),
                    Some(Occupant::File),
                    crate::OccupiedBy::Existing,
                )
                .to_string()
        };
        assert_ne!(occupant(b"caf\xe9"), occupant(b"caf\xe8"));
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
            Some(KeptOccupant::Directory)
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
                Some(KeptOccupant::Symlink)
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
        let config = SecurityConfig::default().with_allow_symlinks(allow_symlinks);
        let safe_path = SafePath::validate(&PathBuf::from(name), dest, &config).expect("safe path");
        let mut report = ExtractionReport::default();
        create_directory(
            &safe_path,
            &pinned(dest),
            &mut report,
            DirWalker::new(&config),
            OccupantPolicy::PRE_EXISTING,
        )
        .map(|()| report)
    }

    #[test]
    fn test_create_directory_over_a_file_names_the_entry() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        std::fs::write(temp.path().join("x"), b"f").expect("write file");

        let err = make_directory(&dest, "x/", false).expect_err("must be refused");

        assert_matches!(
            &err,
            ArchiveError::DestinationOccupied { conflicts, by: OccupiedBy::Existing, .. }
                if conflicts.iter().map(|c| (c.path.as_path(), c.occupant))
                    .eq([(Path::new("x"), Some(Occupant::File))])
        );
        assert!(
            err.to_string()
                .ends_with("refusing to replace the existing file at x"),
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

        let config = SecurityConfig::default();
        // A 200-byte reservation would overflow when added to bytes_written
        let permit = QuotaTracker::new()
            .reserve(200, &config)
            .expect("reservation should succeed");
        let safe_path = SafePath::validate(&PathBuf::from("test.txt"), &dest, &config)
            .expect("path should be valid");

        let mut reader = Cursor::new(b"test data");

        let root = pinned(&dest);
        let result = extract_file_with_permit(
            &mut reader,
            ReadFaults::new(ReadFamily::Tar, None),
            &safe_path,
            &root,
            &mut report,
            dirs,
            SinkOptions::default(),
            FileWrite {
                copy_buffer: &mut copy_buffer,
                permit,
                marking: root.marking(),
                mode: Some(sanitized(0o644)),
                progress: &mut NoopProgress,
            },
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
        // Saturate the duplicate counter so the duplicate-skip path's
        // increment would overflow.
        report.skipped = crate::Skips::with_saturated_count(crate::SkipKind::Duplicate);

        let config = SecurityConfig::default();
        // A 200-byte reservation would overflow when added to bytes_written
        let permit = QuotaTracker::new()
            .reserve(200, &config)
            .expect("reservation should succeed");
        let safe_path = SafePath::validate(&PathBuf::from("test.txt"), &dest, &config)
            .expect("path should be valid");

        // Pre-create the destination file so the exclusive create hits
        // AlreadyExists, taking the duplicate-skip branch that increments
        // files_skipped.
        std::fs::write(temp.path().join("test.txt"), b"existing").expect("failed to seed file");

        let mut reader = Cursor::new(b"test data");

        let root = pinned(&dest);
        let result = extract_file_with_permit(
            &mut reader,
            ReadFaults::new(ReadFamily::Tar, None),
            &safe_path,
            &root,
            &mut report,
            dirs,
            SinkOptions::default(),
            FileWrite {
                copy_buffer: &mut copy_buffer,
                permit,
                marking: root.marking(),
                mode: Some(sanitized(0o644)),
                progress: &mut NoopProgress,
            },
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

        let config = SecurityConfig::default();
        // Declares 50 bytes, mirroring the PoC's forged uncompressed_size.
        let permit = QuotaTracker::new()
            .reserve(50, &config)
            .expect("reservation should succeed");
        let safe_path = SafePath::validate(&PathBuf::from("bomb.txt"), &dest, &config)
            .expect("path should be valid");

        // The "decompressed" stream actually produces far more than declared.
        let real_data = vec![0x41u8; 200 * 1024];
        let mut reader = Cursor::new(&real_data);

        let root = pinned(&dest);
        let result = extract_file_with_permit(
            &mut reader,
            ReadFaults::new(ReadFamily::Tar, None),
            &safe_path,
            &root,
            &mut report,
            dirs,
            SinkOptions::default(),
            FileWrite {
                copy_buffer: &mut copy_buffer,
                permit,
                marking: root.marking(),
                mode: Some(sanitized(0o644)),
                progress: &mut NoopProgress,
            },
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
        for family in [ReadFamily::Zip, ReadFamily::SevenZ, ReadFamily::Tar] {
            let temp = TempDir::new().expect("failed to create temp dir");
            let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
            let mut report = ExtractionReport::default();
            let mut copy_buffer = CopyBuffer::new();
            let dirs = test_walker();

            let config = SecurityConfig::default();
            let permit = QuotaTracker::new()
                .reserve(1000, &config)
                .expect("reservation should succeed");
            let safe_path = SafePath::validate(&PathBuf::from("short.txt"), &dest, &config)
                .expect("path should be valid");

            let mut reader = Cursor::new(b"too short");

            let tap = SourceTap::default();
            let root = pinned(&dest);
            let result = extract_file_with_permit(
                &mut reader,
                ReadFaults::new(family, Some(&tap)),
                &safe_path,
                &root,
                &mut report,
                dirs,
                SinkOptions::default(),
                FileWrite {
                    copy_buffer: &mut copy_buffer,
                    permit,
                    marking: root.marking(),
                    mode: Some(sanitized(0o644)),
                    progress: &mut NoopProgress,
                },
            );

            match family {
                ReadFamily::Tar => assert_matches!(
                    result,
                    Err(ArchiveError::InvalidArchive(
                        Malformation::TarEntryTruncated {
                            declared: 1000,
                            actual: 9
                        }
                    )),
                    "a TAR entry short of its header size is a truncated archive: {result:?}"
                ),
                _ => assert_matches!(
                    result,
                    Err(ArchiveError::SecurityViolation { .. }),
                    "{family:?}: actual size short of declared size must be rejected, got: \
                     {result:?}"
                ),
            }
            assert!(
                !temp.path().join("short.txt").exists(),
                "{family:?}: rejected entry must not leave a truncated file on disk"
            );
        }
    }

    /// With `ExistingFiles::Overwrite` (`--force`), an aborted forged-size
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

        let config = SecurityConfig::default();
        let permit = QuotaTracker::new()
            .reserve(50, &config)
            .expect("reservation should succeed");
        let safe_path = SafePath::validate(&PathBuf::from("target.txt"), &dest, &config)
            .expect("path should be valid");

        let real_data = vec![0x41u8; 200 * 1024];
        let mut reader = Cursor::new(&real_data);

        let root = pinned(&dest);
        let result = extract_file_with_permit(
            &mut reader,
            ReadFaults::new(ReadFamily::Tar, None),
            &safe_path,
            &root,
            &mut report,
            dirs,
            SinkOptions::default().with_existing_files(crate::ExistingFiles::Overwrite),
            FileWrite {
                copy_buffer: &mut copy_buffer,
                permit,
                marking: root.marking(),
                mode: Some(sanitized(0o644)),
                progress: &mut NoopProgress,
            },
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
        let written_at = WrittenAt::Temp(
            TempLeaf::named(".exarch-tmp-test"),
            ReplacePermit::for_test(),
        );

        let guard = written_at.guard(dir, leaf);
        let err = commit_output(dir, written_at, leaf, Path::new("d")).unwrap_err();
        drop(guard);

        assert!(
            err.to_string()
                .contains("cannot replace the existing file: d"),
            "{err}"
        );
        assert!(!written.exists(), "temp file must be removed");
        assert!(occupied.join("child").exists());
    }

    /// Issue #818: the hardlink copy is bounded by the size the quota was
    /// charged for, so a target that grew or shrank after the `fstat` fails
    /// closed with its own message instead of the archive's "declared size".
    #[test]
    fn hardlink_copy_fails_closed_when_the_target_changes_size() {
        let temp = TempDir::new().expect("temp dir");
        let config = SecurityConfig::default();
        let source = temp.path().join("source");
        std::fs::write(&source, vec![b'x'; 100_000]).expect("seed source");

        for (charged, ok) in [(100_000u64, true), (10, false), (200_000, false)] {
            let permit = QuotaTracker::new()
                .reserve(charged, &config)
                .expect("reservation");
            let to = temp.path().join(format!("copy-{charged}"));
            let result = copy_file_content_with_permit(
                File::open(&source).expect("open source"),
                &mut File::create(&to).expect("create copy"),
                &mut CopyBuffer::new(),
                permit,
                &mut NoopProgress,
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

        let config = SecurityConfig::default();

        // Mode 0o777 in archive, sanitized to 0o775 (world-writable stripped)
        let sanitized_mode = sanitize_permissions(RawMode::new(0o777), &config);
        let permit = QuotaTracker::new()
            .reserve(7, &config)
            .expect("reservation should succeed");
        let safe_path = SafePath::validate(&PathBuf::from("perm_test.txt"), &dest, &config)
            .expect("path should be valid");

        let mut reader = Cursor::new(b"content");

        let root = pinned(&dest);
        extract_file_with_permit(
            &mut reader,
            ReadFaults::new(ReadFamily::Tar, None),
            &safe_path,
            &root,
            &mut report,
            dirs,
            SinkOptions::default(),
            FileWrite {
                copy_buffer: &mut copy_buffer,
                permit,
                marking: root.marking(),
                mode: Some(CreateMode::Exact(sanitized_mode)),
                progress: &mut NoopProgress,
            },
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
    #[allow(unsafe_code, reason = "the test swaps the process umask through libc")]
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
        let config = SecurityConfig::default().with_allow_symlinks(true);

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
            SinkOptions::default().with_existing_files(crate::ExistingFiles::Overwrite),
        )
        .expect("first create_symlink should succeed");
        assert_eq!(report.symlinks_created, 1);

        let unchanged = report.symlinks_created;
        create_symlink(
            &safe_symlink,
            &pinned(&dest),
            &mut report,
            dirs,
            SinkOptions::default().with_existing_files(crate::ExistingFiles::Overwrite),
        )
        .expect("an identical link is an unchanged duplicate");
        assert_eq!(report.symlinks_created, unchanged);
        assert_eq!(report.files_skipped(), 1);

        std::fs::write(temp.path().join("other.txt"), b"data").expect("write other");
        let other_safe_symlink =
            SafeSymlink::validate(&link_safe_path, Path::new("other.txt"), &dest, &config)
                .expect("safe symlink");
        let err = create_symlink(
            &other_safe_symlink,
            &pinned(&dest),
            &mut report,
            dirs,
            SinkOptions::default().with_existing_files(crate::ExistingFiles::Overwrite),
        )
        .expect_err("a link with another target must not be replaced");
        assert_matches!(
            &err,
            ArchiveError::SecurityViolation {
                kind: Violation::ReplacesSymlink { rel, by },
            } if &**rel == "link.txt" && *by == OccupiedBy::Existing,
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
        let config = SecurityConfig::default().with_allow_symlinks(true);

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
            SinkOptions::default().with_existing_files(crate::ExistingFiles::Overwrite),
        )
        .expect("a file is replaced");
        assert_eq!(report.symlinks_created, 1);
        assert!(temp.path().join("link.txt").is_symlink());
    }

    #[test]
    fn test_record_file_written_counts_bytes_and_reports_progress_once() {
        struct Bytes(Vec<u64>);
        impl ProgressCallback for Bytes {
            fn on_entry_start(&mut self, _: &Path, _position: crate::EntryPosition) {}

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

    #[test]
    fn test_record_skip_counts_by_kind_and_keeps_the_path() {
        let mut report = ExtractionReport::default();
        record_duplicate_skip(&mut report, Path::new("a/b")).expect("count duplicate");
        record_skip(
            &mut report,
            SkipKind::ExtensionNotAllowed,
            Path::new("c.exe"),
        )
        .expect("count extension skip");
        record_duplicate_skip(&mut report, Path::new("d")).expect("count duplicate");

        assert_eq!(report.files_skipped(), 3);
        assert_eq!(report.skipped.count(SkipKind::Duplicate), 2);
        assert_eq!(report.skipped.count(SkipKind::ExtensionNotAllowed), 1);
        let paths: Vec<_> = report.skipped.sample().iter().map(|s| &s.path).collect();
        assert_eq!(
            paths,
            [Path::new("a/b"), Path::new("c.exe"), Path::new("d")]
        );
    }

    #[test]
    fn test_entry_complete_guard_panicking_callback_fires_once() {
        use std::panic::AssertUnwindSafe;
        use std::panic::catch_unwind;

        struct Panicking(u32);
        impl ProgressCallback for Panicking {
            fn on_entry_start(&mut self, _: &Path, _position: crate::EntryPosition) {}

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
            EntryCompleteGuard::try_start(
                &mut progress,
                &path,
                crate::EntryPosition::at_index(0, crate::EntryTotal::Known(1)),
            )
            .unwrap()
            .complete();
        }));
        assert!(outcome.is_err());
        assert_eq!(progress.0, 1, "Drop must not fire the callback again");
    }

    #[cfg(unix)]
    #[test]
    fn open_archive_refuses_a_named_pipe_without_blocking() {
        let temp = tempfile::TempDir::new().unwrap();
        let fifo = temp.path().join("pipe");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );

        let (done, outcome) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(open_archive(&fifo).map(drop));
        });
        let refusal = outcome
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("opening a named pipe blocked")
            .unwrap_err();

        assert!(NotARegularFile::is_cause_of(&refusal), "{refusal}");
    }

    #[cfg(unix)]
    #[test]
    fn open_archive_leaves_a_regular_file_in_blocking_mode() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = temp.path().join("f");
        std::fs::write(&file, b"x").unwrap();

        let opened = open_archive(&file).unwrap();

        assert!(
            !rustix::fs::fcntl_getfl(&opened)
                .unwrap()
                .contains(rustix::fs::OFlags::NONBLOCK)
        );
    }

    #[test]
    fn open_archive_reports_a_missing_path_as_not_found() {
        let temp = tempfile::TempDir::new().unwrap();

        let refusal = open_archive(&temp.path().join("absent")).unwrap_err();

        assert_matches!(refusal, ArchiveError::SourceNotFound { .. });
        assert!(!NotARegularFile::is_cause_of(&refusal));
    }

    #[test]
    fn copy_and_finish_file_writes_flushes_and_enforces_admitted_size() {
        let temp = TempDir::new().expect("temp dir");
        let root = pinned(&DestDir::new(temp.path()).expect("dest"));
        let config = SecurityConfig::default();
        let mut copy_buffer = CopyBuffer::new();

        let (_, leaf) = Leaf::split(Path::new("ok.txt")).expect("leaf");
        let (file, pending) = create_file(
            root.dir(),
            leaf,
            Some(sanitized(0o644)),
            ModeTiming::AfterMark,
        )
        .expect("create file");
        let permit = QuotaTracker::new().reserve(11, &config).expect("reserve");
        let mut reader = Cursor::new(b"hello world");
        let written = copy_and_finish_file(
            &mut reader,
            file,
            ReadFaults::new(ReadFamily::SevenZ, None),
            FileWrite {
                copy_buffer: &mut copy_buffer,
                permit,
                marking: None,
                mode: None,
                progress: &mut NoopProgress,
            },
            pending,
        )
        .expect("exact copy should succeed");
        assert_eq!(written, 11);
        assert_eq!(
            std::fs::read(temp.path().join("ok.txt")).expect("read file"),
            b"hello world"
        );

        let (_, over_leaf) = Leaf::split(Path::new("over.txt")).expect("leaf");
        let (over_file, over_pending) =
            create_file(root.dir(), over_leaf, None, ModeTiming::AtCreate).expect("create file");
        let over_permit = QuotaTracker::new().reserve(4, &config).expect("reserve");
        let mut over_reader = Cursor::new(b"longer than four bytes");
        let err = copy_and_finish_file(
            &mut over_reader,
            over_file,
            ReadFaults::new(ReadFamily::SevenZ, None),
            FileWrite {
                copy_buffer: &mut copy_buffer,
                permit: over_permit,
                marking: None,
                mode: None,
                progress: &mut NoopProgress,
            },
            over_pending,
        )
        .expect_err("overrun must fail");
        assert_matches!(err, ArchiveError::SecurityViolation { .. });
    }
}

/// `Refuse` when the occupant probe and the run record disagree, in both
/// directions: whichever is wrong, the outcome is a refusal or a skip, never a
/// write or a rename.
#[cfg(all(test, unix))]
#[expect(clippy::unwrap_used, reason = "tests assert by panicking")]
mod refuse_probe_tests {

    use super::*;
    use crate::formats::pinned_dir::support::leaf;
    use std::assert_matches;
    use tempfile::TempDir;

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn open(root: &PinnedRoot, name: &str) -> Result<Option<()>> {
        open_output_slot(
            root.dir(),
            leaf(name),
            Path::new(name),
            None,
            OccupantPolicy::new(
                crate::ExistingFiles::Refuse,
                crate::RepeatedPaths::KeepFirst,
            ),
            root,
            ModeTiming::AtCreate,
        )
        .map(|slot| slot.map(drop))
    }

    fn assert_untouched(dir: &Path, expected: &[(&str, &str)]) {
        let listed: Vec<_> = expected
            .iter()
            .map(|(name, _)| (*name).to_string())
            .collect();
        assert_eq!(names(dir), listed, "no temp file, no rename");
        for (name, content) in expected {
            assert_eq!(std::fs::read_to_string(dir.join(name)).unwrap(), *content);
        }
    }

    #[test]
    fn a_file_the_run_made_but_the_record_lacks_is_refused() {
        let temp = TempDir::new().unwrap();
        let root = PinnedRoot::open_for_test(temp.path()).unwrap();
        std::fs::write(temp.path().join("f"), "ours").unwrap();

        let outcome = open(&root, "f");

        assert_matches!(outcome, Err(ArchiveError::DestinationOccupied { .. }));
        assert_untouched(temp.path(), &[("f", "ours")]);
    }

    #[test]
    fn a_file_the_run_made_is_refused_once_the_record_is_saturated() {
        let temp = TempDir::new().unwrap();
        let root = PinnedRoot::open_for_test(temp.path()).unwrap();
        std::fs::write(temp.path().join("f"), "ours").unwrap();
        root.created().note(root.dir(), leaf("f"), Path::new("f"));
        root.created().saturate();

        let outcome = open(&root, "f");

        assert_matches!(outcome, Err(ArchiveError::DestinationOccupied { .. }));
        assert_untouched(temp.path(), &[("f", "ours")]);
    }

    #[test]
    fn a_foreign_occupant_the_record_vouches_for_is_skipped() {
        let temp = TempDir::new().unwrap();
        let root = PinnedRoot::open_for_test(temp.path()).unwrap();
        std::fs::write(temp.path().join("f"), "ours").unwrap();
        root.created().note(root.dir(), leaf("f"), Path::new("f"));
        std::fs::hard_link(temp.path().join("f"), temp.path().join("g")).unwrap();

        let outcome = open(&root, "g");

        assert_matches!(outcome, Ok(None));
        assert_untouched(temp.path(), &[("f", "ours"), ("g", "ours")]);
    }

    #[test]
    fn a_foreign_occupant_the_record_does_not_know_is_refused() {
        let temp = TempDir::new().unwrap();
        let root = PinnedRoot::open_for_test(temp.path()).unwrap();
        std::fs::write(temp.path().join("f"), "ours").unwrap();
        root.created().note(root.dir(), leaf("f"), Path::new("f"));
        std::fs::rename(temp.path().join("f"), temp.path().join("kept")).unwrap();
        std::fs::write(temp.path().join("f"), "foreign").unwrap();

        let outcome = open(&root, "f");

        assert_matches!(outcome, Err(ArchiveError::DestinationOccupied { .. }));
        assert_untouched(temp.path(), &[("f", "foreign"), ("kept", "ours")]);
    }

    #[test]
    fn a_foreign_occupant_with_a_recorded_identity_is_skipped_never_written() {
        let temp = TempDir::new().unwrap();
        let root = PinnedRoot::open_for_test(temp.path()).unwrap();
        std::fs::write(temp.path().join("f"), "foreign").unwrap();
        let reused = root.dir().identity(leaf("f")).unwrap().unwrap();
        root.created().insert_identity_for_test(reused);

        let outcome = open(&root, "f");

        assert_matches!(outcome, Ok(None));
        assert_untouched(temp.path(), &[("f", "foreign")]);
    }
}
