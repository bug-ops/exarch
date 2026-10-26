//! Writing 7z file entries to disk: direct writes and the temp-file-and-rename
//! path for destinations that already hold something.

use super::links::LinkStorage;
use super::links::link_storage;
use crate::Result;
use crate::SecurityConfig;
use crate::config::Validated;
use crate::copy::CopyBuffer;
use crate::copy::copy_with_buffer;
use crate::formats::common;
use crate::security::quota::QuotaPermit;
use crate::types::DestDir;
use crate::types::SafePath;
use crate::types::SafeSymlink;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::id;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

// Atomic counter for generating unique temporary file names
pub(super) static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Maximum number of attempts to create a uniquely-named temp file before
/// giving up.
///
/// Bounds retry cost if an attacker has pre-planted symlinks at several
/// predicted `.{name}.exarch-tmp-{pid}-{counter}` paths (issue #471); a
/// genuine collision from concurrent extraction into the same directory
/// resolves on the first or second attempt since `TEMP_COUNTER` is
/// monotonically increasing per process.
pub(super) const MAX_TEMP_FILE_CREATE_ATTEMPTS: u32 = 8;

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
pub(super) fn write_file_direct(
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
pub(super) fn write_file_with_permit(
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
pub(super) fn write_file_with_permit_using(
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
pub(super) fn lstat_dest(dest_path: &Path) -> std::io::Result<Option<std::fs::Metadata>> {
    match std::fs::symlink_metadata(dest_path) {
        Ok(meta) => Ok(Some(meta)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Refuses, from the file table alone, a link whose target is empty or larger
/// than a target may be, with the error reading it in Step 3 would give.
///
/// Any other target is read and validated once, in Step 3, so extraction
/// decodes each block a single time.
pub(super) fn refuse_undecoded_target(
    link: &SafePath,
    file: &sevenz_rust2::ArchiveEntry,
    dest: &DestDir,
    config: &SecurityConfig<Validated>,
) -> Result<()> {
    match link_storage(file) {
        LinkStorage::Empty => SafeSymlink::validate(link, Path::new(""), dest, config).map(drop),
        LinkStorage::Oversized(bytes) => Err(common::symlink_target_too_large(bytes)),
        LinkStorage::Stream => Ok(()),
    }
}
