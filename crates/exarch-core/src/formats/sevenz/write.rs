//! Writing 7z file entries to disk: direct writes and the temp-file-and-rename
//! path for destinations that already hold something.

use super::links::LinkStorage;
use super::links::link_storage;
use crate::Result;
use crate::SecurityConfig;
use crate::formats::common;
use crate::formats::common::FileWrite;
use crate::formats::common::ModeTiming;
use crate::formats::occupant::ReplacePermit;
use crate::formats::pinned_dir::Leaf;
use crate::formats::pinned_dir::TempFileGuard;
use crate::formats::pinned_dir::TempLeaf;
use crate::formats::pinned_dir::VettedDir;
use crate::formats::source_fault::ReadFaults;
use crate::security::fs_view::FsView;
use crate::types::SafePath;
use crate::types::SafeSymlink;
use std::io::ErrorKind;
use std::io::Read;
use std::path::Path;

/// Writes `reader`'s bytes directly to `leaf` in `parent` (no temp file, no
/// rename), consuming the [`QuotaPermit`](crate::security::quota::QuotaPermit)
/// that authorized the write.
///
/// Used for the common case where nothing currently occupies `leaf`
/// (issue #492): creates `leaf` itself through [`common::create_file`]
/// (`O_EXCL`+`O_NOFOLLOW` via [`VettedDir::create_new_deferred`]), giving the
/// same guarantee against a symlink race as
/// [`write_file_with_permit`]'s temp file and as TAR/ZIP's
/// [`common::extract_file_with_permit`] — just without the two extra syscalls
/// (create+rename of a temp file) that only matter when something needs to be
/// atomically replaced. Callers must have already confirmed `leaf` has no
/// pre-existing occupant (see [`DestOccupancy`](super::host)); when it does,
/// use [`write_file_with_permit`] instead so a decode failure mid-stream
/// cannot leave a truncated file where the original stood.
///
/// The entry's sanitized mode, when it has one, is applied through the open
/// descriptor (`fchmod`) by [`common::copy_and_finish_file`], after the
/// download-origin mark when the run writes one.
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
/// [`copy_bounded`](crate::copy::copy_bounded), which enforces it as a hard
/// streaming ceiling and an exact post-copy match rather than trusting it a
/// second time, closing the same gap TAR/ZIP close via
/// [`common::extract_file_with_permit`].
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
    write: FileWrite<'_>,
) -> Result<u64> {
    let (file, pending) =
        common::create_file(parent, leaf, write.mode, ModeTiming::of(write.marking))?;
    // A decode failure partway through the copy would otherwise leave a
    // truncated file at `leaf` (issue #492 adversarial review, finding M1):
    // since this branch only runs when nothing occupied `leaf` beforehand, it
    // is always safe to remove whatever we just started writing there.
    // `copy_and_finish_file` takes `file` by value and closes it before
    // returning on both success and error, so `guard` never unlinks a
    // still-open handle (critical on Windows).
    let guard = TempFileGuard::new(parent, leaf);
    let bytes_written = common::copy_and_finish_file(reader, file, faults, write, pending)?;
    guard.persist();
    Ok(bytes_written)
}

/// Writes `reader`'s bytes to `leaf` in `parent` via an atomic
/// temp-file-then-rename, consuming the
/// [`QuotaPermit`](crate::security::quota::QuotaPermit) that authorized the
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
/// now created through [`common::create_temp_sibling_with`]
/// (`O_EXCL | O_NOFOLLOW` via [`VettedDir::create_new_deferred`]), which
/// refuses any pre-existing name instead of following it; the entry's
/// sanitized mode is applied to the temp file through its descriptor before the
/// rename. On collision
/// (`ErrorKind::AlreadyExists`), a fresh counter value is drawn and creation
/// is retried up to [`common::MAX_TEMP_FILE_CREATE_ATTEMPTS`] times. The temp
/// file, the rename and the cleanup are all relative to `parent` (issue #818).
///
/// # Security - Streaming Size Enforcement (GHSA-5j8q-wxg5-hj4r)
///
/// Same enforcement as [`write_file_direct`]: the copy runs through
/// [`copy_bounded`](crate::copy::copy_bounded) with the permit's byte count
/// (`entry.size`) as a hard streaming ceiling and exact post-copy match, not
/// trusted metadata.
///
/// # Errors
///
/// Returns an error if a unique temp file cannot be created within
/// [`common::MAX_TEMP_FILE_CREATE_ATTEMPTS`] attempts, if the copy or rename
/// fails, or if the actual decompressed byte count exceeds or falls short of
/// the permit's byte count.
pub(super) fn write_file_with_permit(
    reader: &mut dyn Read,
    faults: ReadFaults<'_>,
    parent: &VettedDir,
    leaf: Leaf<'_>,
    replace: ReplacePermit,
    write: FileWrite<'_>,
) -> Result<u64> {
    write_file_with_permit_using(reader, faults, parent, leaf, replace, write, TempLeaf::next)
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
/// [`copy_bounded`](crate::copy::copy_bounded) with the permit's byte count as
/// a hard streaming ceiling and exact post-copy match, not trusted metadata.
///
/// # Errors
///
/// Returns an error if a unique temp file cannot be created within
/// [`common::MAX_TEMP_FILE_CREATE_ATTEMPTS`] attempts, if the copy or rename
/// fails, or if the actual decompressed byte count exceeds or falls short of
/// the permit's byte count.
pub(super) fn write_file_with_permit_using(
    reader: &mut dyn Read,
    faults: ReadFaults<'_>,
    parent: &VettedDir,
    leaf: Leaf<'_>,
    replace: ReplacePermit,
    write: FileWrite<'_>,
    next_candidate: impl FnMut() -> TempLeaf,
) -> Result<u64> {
    let (temp, temp_file, pending) = common::create_temp_sibling_with(
        parent,
        leaf,
        write.mode,
        ModeTiming::of(write.marking),
        &replace,
        next_candidate,
    )?;

    // `copy_and_finish_file` takes `temp_file` by value and closes it before
    // returning on both success and error, so neither the rename nor
    // `temp_guard`'s unwind cleanup ever races a still-open handle (Windows).
    let temp_guard = TempFileGuard::for_temp(parent, temp.clone());
    let bytes_written = common::copy_and_finish_file(reader, temp_file, faults, write, pending)?;
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
