//! Writing 7z file entries to disk: direct writes and the temp-file-and-rename
//! path for destinations that already hold something.

use super::links::LinkStorage;
use super::links::link_storage;
use crate::ProgressCallback;
use crate::Result;
use crate::SecurityConfig;
use crate::copy::CopyBuffer;
use crate::copy::copy_cancellable;
use crate::formats::common;
use crate::formats::occupant::ReplacePermit;
use crate::formats::pinned_dir::Leaf;
use crate::formats::pinned_dir::TempFileGuard;
use crate::formats::pinned_dir::TempLeaf;
use crate::formats::pinned_dir::VettedDir;
use crate::formats::source_fault::ReadFaults;
use crate::security::fs_view::FsView;
use crate::security::quota::QuotaPermit;
use crate::types::SafePath;
use crate::types::SafeSymlink;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::path::Path;

/// Writes `reader`'s bytes directly to `leaf` in `parent` (no temp file, no
/// rename), consuming the [`QuotaPermit`] that authorized the write.
///
/// Used for the common case where nothing currently occupies `leaf`
/// (issue #492): creates `leaf` itself via [`VettedDir::create_new`], giving
/// the same `O_EXCL`+`O_NOFOLLOW` guarantee against a symlink race as
/// [`write_file_with_permit`]'s temp file and as TAR/ZIP's
/// [`common::extract_file_with_permit`] — just without the two extra syscalls
/// (create+rename of a temp file) that only matter when something needs to be
/// atomically replaced. Callers must have already confirmed `leaf` has no
/// pre-existing occupant (see [`DestOccupancy`](super::host)); when it does,
/// use [`write_file_with_permit`] instead so a decode failure mid-stream
/// cannot leave a truncated file where the original stood.
///
/// `parent` is the pinned directory handle the caller obtained from the
/// directory walker; the create, the cleanup on failure and every later step
/// are relative to it, so a parent component swapped after the walk cannot
/// redirect the write (issue #818).
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
/// the permit's byte count is `entry.size` — the declared uncompressed size
/// read from 7z's own (attacker-controlled) archive metadata, the same value
/// already used to authorize `permit`. The copy goes through
/// [`copy_bounded`], which enforces it as a hard streaming ceiling and
/// an exact post-copy match rather than trusting it a second time, closing
/// the same gap TAR/ZIP close via [`common::extract_file_with_permit`].
///
/// # Errors
///
/// Returns an error if file creation, the copy, or the underlying I/O fails,
/// or if the actual decompressed byte count exceeds or falls short of
/// the permit's byte count.
pub(super) fn write_file_direct(
    reader: &mut dyn Read,
    faults: ReadFaults<'_>,
    parent: &VettedDir,
    leaf: Leaf<'_>,
    copy_buffer: &mut CopyBuffer,
    permit: QuotaPermit,
    progress: &mut dyn ProgressCallback,
) -> Result<u64> {
    let file = parent.create_new(leaf, None)?;
    // A decode failure partway through the copy would otherwise leave a
    // truncated file at `leaf` (issue #492 adversarial review, finding M1):
    // since this branch only runs when nothing occupied `leaf` beforehand, it
    // is always safe to remove whatever we just started writing there.
    //
    // Declared before `writer` takes ownership of `file` below: Rust drops
    // locals in reverse declaration order, so on an error unwind `writer`
    // (and the `file` it owns) drops — and closes the fd — before `guard`
    // attempts to remove the name. Reversing this order would let the guard
    // try to unlink a still-open file, a silent no-op on Windows.
    let guard = TempFileGuard::new(parent, leaf);
    // 64KiB write buffering to cut per-file syscall count (finding M2),
    // matching TAR/ZIP's common::extract_file_with_permit.
    let mut writer = std::io::BufWriter::with_capacity(64 * 1024, file);
    let bytes_written = copy_cancellable(
        reader,
        &mut writer,
        copy_buffer,
        Some(permit.into_bytes()),
        progress,
    )
    .map_err(|error| faults.classify(error))?;
    writer.flush()?;
    guard.persist();
    Ok(bytes_written)
}

/// Writes `reader`'s bytes to `leaf` in `parent` via an atomic
/// temp-file-then-rename, consuming the [`QuotaPermit`] that authorized the
/// write.
///
/// Used only when `leaf` has a pre-existing occupant being overwritten
/// (issue #492): atomicity matters here because a decode failure mid-stream
/// must not leave a truncated file where the original stood. When `leaf` is
/// known to have no pre-existing occupant, [`write_file_direct`] skips the
/// temp file and rename entirely.
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
/// predicted temp name used to be silently followed by `File::create`,
/// writing archive content outside the extraction root. The temp file is
/// now created via [`VettedDir::create_new`] (`O_EXCL | O_NOFOLLOW`), which
/// refuses any pre-existing name instead of following it. On collision
/// (`ErrorKind::AlreadyExists`), a fresh counter value is drawn and creation
/// is retried up to [`common::MAX_TEMP_FILE_CREATE_ATTEMPTS`] times. The temp
/// file, the rename and the cleanup are all relative to `parent` (issue #818).
///
/// # Security - Streaming Size Enforcement (GHSA-5j8q-wxg5-hj4r)
///
/// Same enforcement as [`write_file_direct`]: the copy runs through
/// [`copy_bounded`] with the permit's byte count (`entry.size`) as a hard
/// streaming ceiling and exact post-copy match, not trusted metadata.
///
/// # Errors
///
/// Returns an error if a unique temp file cannot be created within
/// [`common::MAX_TEMP_FILE_CREATE_ATTEMPTS`] attempts, if the copy or rename
/// fails, or if the actual decompressed byte count exceeds or falls short of
/// the permit's byte count.
#[expect(
    clippy::too_many_arguments,
    reason = "the permits and the progress callback are threaded through from the caller; a parameter struct adds indirection"
)]
pub(super) fn write_file_with_permit(
    reader: &mut dyn Read,
    faults: ReadFaults<'_>,
    parent: &VettedDir,
    leaf: Leaf<'_>,
    copy_buffer: &mut CopyBuffer,
    permit: QuotaPermit,
    replace: ReplacePermit,
    progress: &mut dyn ProgressCallback,
) -> Result<u64> {
    write_file_with_permit_using(
        reader,
        faults,
        parent,
        leaf,
        copy_buffer,
        permit,
        replace,
        progress,
        TempLeaf::next,
    )
}

/// Implementation behind [`write_file_with_permit`], parameterized over the
/// candidate temp-name generator.
///
/// Tests inject a private, non-shared generator here instead of calling
/// [`write_file_with_permit`] directly, so that predicting which names a test
/// run will attempt never depends on the process-global temp counter — a
/// global shared with every other test in the same binary that also happens to
/// write a 7z file, and therefore not something a single test can safely
/// predict under `cargo test`'s default multi-threaded execution (only
/// nextest's one-test-per-process model would make that safe).
///
/// # Security - Streaming Size Enforcement (GHSA-5j8q-wxg5-hj4r)
///
/// Same enforcement as [`write_file_direct`]: the copy runs through
/// [`copy_bounded`] with the permit's byte count as a hard streaming
/// ceiling and exact post-copy match, not trusted metadata.
///
/// # Errors
///
/// Returns an error if a unique temp file cannot be created within
/// [`common::MAX_TEMP_FILE_CREATE_ATTEMPTS`] attempts, if the copy or rename
/// fails, or if the actual decompressed byte count exceeds or falls short of
/// the permit's byte count.
#[expect(
    clippy::too_many_arguments,
    reason = "the permits and the temp-name generator are threaded through from the caller; a parameter struct adds indirection"
)]
pub(super) fn write_file_with_permit_using(
    reader: &mut dyn Read,
    faults: ReadFaults<'_>,
    parent: &VettedDir,
    leaf: Leaf<'_>,
    copy_buffer: &mut CopyBuffer,
    permit: QuotaPermit,
    replace: ReplacePermit,
    progress: &mut dyn ProgressCallback,
    next_candidate: impl FnMut() -> TempLeaf,
) -> Result<u64> {
    let (temp, temp_file) =
        common::create_temp_sibling(parent, leaf, None, &replace, next_candidate)?;

    // Declared before `writer` takes ownership of `temp_file` below, for the
    // same reason as write_file_direct's `guard`: reverse-declaration-order
    // drop means `writer` (owning `temp_file`) closes the fd before
    // `temp_guard` attempts to remove the temp name on an error unwind,
    // instead of racing a still-open handle (a silent no-op on Windows).
    let temp_guard = TempFileGuard::for_temp(parent, temp.clone());
    // 64KiB write buffering to cut per-file syscall count (issue #492
    // adversarial review, finding M2), matching TAR/ZIP's
    // common::extract_file_with_permit.
    let mut writer = std::io::BufWriter::with_capacity(64 * 1024, temp_file);
    let bytes_written = copy_cancellable(
        reader,
        &mut writer,
        copy_buffer,
        Some(permit.into_bytes()),
        progress,
    )
    .map_err(|error| faults.classify(error))?;
    writer.flush()?;
    // Explicit close before rename: renaming a still-open file is fine on
    // Unix but the handle should not outlive its purpose regardless.
    drop(writer);
    parent.replace_entry(&temp, leaf, replace)?;
    temp_guard.persist();

    Ok(bytes_written)
}

/// lstat's `dest_path`, returning `Ok(None)` if nothing occupies it.
///
/// Uses `symlink_metadata` rather than `exists()`/`is_dir()`: those follow
/// symlinks and report a dangling symlink as absent, which would let a
/// dangling symlink slip past both duplicate detection and the
/// pre-existing-symlink rejection below (issues #468, #477, #478). Used by the
/// host pre-pass, which only decides whether to skip or refuse an entry before
/// anything is written.
///
/// # TOCTOU
///
/// This check is advisory, not atomic: the write itself re-probes the name
/// relative to its pinned parent directory ([`VettedDir::probe`]) and both of
/// 7z's write paths enforce the outcome again (issues #492, #818):
///
/// - When nothing occupied the name ([`write_file_direct`]): the fast path
///   creates it with `O_EXCL | O_NOFOLLOW`, so anything planted in the race
///   window makes that create fail with `AlreadyExists` instead of being
///   followed.
/// - When something did occupy it ([`write_file_with_permit`]): this branch
///   never opens the name itself, and `renameat` replaces whatever occupies it
///   without following a symlink planted there in the interim, so a race cannot
///   redirect the write through a symlink target.
pub(super) fn lstat_dest(dest_path: &Path) -> std::io::Result<Option<std::fs::Metadata>> {
    match std::fs::symlink_metadata(dest_path) {
        Ok(meta) => Ok(Some(meta)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Refuses, from the file table alone, a link whose target is empty or larger
/// than a target may be, with the error reading it during extraction would
/// give.
///
/// Any other target is read and validated once, during extraction, so
/// extraction decodes each block a single time.
pub(super) fn refuse_undecoded_target_in<V: FsView>(
    link: &SafePath,
    file: &sevenz_rust2::ArchiveEntry,
    root: &V::Root,
    config: &SecurityConfig,
    view: &V,
) -> Result<()> {
    match link_storage(file) {
        LinkStorage::Empty => {
            SafeSymlink::validate_in(link, Path::new(""), root, config, view).map(drop)
        }
        LinkStorage::Oversized(bytes) => Err(common::symlink_target_too_large(bytes)),
        LinkStorage::Stream => Ok(()),
    }
}
