//! The destination pre-check of a listed archive.
//!
//! [`check`] walks the landings a listing says extraction creates, in the
//! order it creates them, through the same [`DirWalker`] that the write phase
//! uses. Every parent is opened handle-relatively with the walker's symlink
//! policy, so a symlink among the parents is refused with the very error
//! extraction gives, and a failure to inspect a path is reported as the I/O
//! error it is, never as a symlink refusal.

use std::path::Path;
use std::path::PathBuf;

use crate::ArchiveError;
use crate::DestinationCheck;
use crate::Result;
use crate::SecurityConfig;
use crate::Violation;
use crate::formats::common::check_directory_occupant;
use crate::formats::dir_walker::DirWalker;
use crate::formats::pinned_dir::PinnedRoot;
use crate::inspection::ArchiveManifest;
use crate::inspection::Landing;
use crate::inspection::LandingKind;
use crate::inspection::ManifestEntryKind;
use crate::path_text;
use crate::security::fs_view::Occupant;
use crate::types::DestDir;

/// What a landing finds at its path.
enum Occupancy {
    /// Nothing is there, or what is there is acceptable.
    Free,
    /// Something is there that the write phase refuses to replace.
    Conflict,
}

/// Opens `dest` for probing, or `None` when it does not exist: nothing can
/// conflict with an archive that has no destination yet.
fn open_destination(dest: &Path) -> Result<Option<PinnedRoot>> {
    match DestDir::new(dest) {
        Ok(dest_dir) => PinnedRoot::open(dest_dir).map(Some),
        Err(ArchiveError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Whether the landing must end up a directory: an implied parent, or an entry
/// that is one.
fn needs_directory(landing: &Landing<'_>) -> bool {
    match landing.kind() {
        LandingKind::ImplicitParent => true,
        LandingKind::Entry(entry) => matches!(entry.kind, ManifestEntryKind::Directory),
    }
}

/// Refuses, before anything is written, a destination the write phase would
/// refuse.
///
/// # Errors
///
/// `DestinationOccupied` naming every occupied landing; the typed symlink
/// refusal the write phase gives for a link among the parents or at a
/// landing; or the I/O error of a path that could not be inspected.
pub(super) fn check(
    manifest: &ArchiveManifest,
    config: &SecurityConfig,
    dest: &Path,
    check: DestinationCheck,
) -> Result<()> {
    let Some(root) = open_destination(dest)? else {
        return Ok(());
    };
    let walker = DirWalker::new(config);
    let mut conflicts: Vec<PathBuf> = Vec::new();
    for landing in manifest.landings(config) {
        let rel = landing.path().as_path();
        let directory = needs_directory(&landing);
        let checked = match check {
            DestinationCheck::Vacant => true,
            DestinationCheck::Replaceable => directory,
        };
        if rel.is_empty() || !checked {
            continue;
        }
        match inspect(walker, &root, &landing, directory) {
            Ok(Occupancy::Free) => {}
            Ok(Occupancy::Conflict) => conflicts.push(rel.to_path_buf()),
            Err(ArchiveError::Io(error)) if is_below_a_conflict(&error, &conflicts) => {}
            Err(error) => return Err(error),
        }
    }
    conflicts
        .is_empty()
        .ok_or_else(|| ArchiveError::DestinationOccupied {
            destination: dest.to_path_buf(),
            conflicts: conflicts.into_boxed_slice(),
        })
}

/// Whether an I/O failure only says that the path is absent or sits below a
/// conflict already reported at one of its ancestors.
fn is_below_a_conflict(error: &std::io::Error, conflicts: &[PathBuf]) -> bool {
    match error.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidFilename => true,
        std::io::ErrorKind::NotADirectory => !conflicts.is_empty(),
        _ => false,
    }
}

/// Looks at the landing's path through its pinned parent.
fn inspect(
    walker: DirWalker,
    root: &PinnedRoot,
    landing: &Landing<'_>,
    directory: bool,
) -> Result<Occupancy> {
    let rel = landing.path().as_path();
    let (parent, leaf) = walker.open_parent(root, rel)?;
    let Some(occupant) = parent.probe(leaf)? else {
        return Ok(Occupancy::Free);
    };
    match (occupant, directory) {
        (Occupant::Directory, true) => Ok(Occupancy::Free),
        (Occupant::Symlink, true) => vet_symlinked_directory(walker, root, landing),
        (Occupant::Symlink, false) => Err(Violation::ReplacesSymlink {
            rel: path_text(rel).into(),
        }
        .into()),
        (Occupant::Directory | Occupant::File, _) => Ok(Occupancy::Conflict),
    }
}

/// The write phase's verdict on a symlink at a directory landing: an entry
/// goes through the occupant check, an implied parent through the walk.
fn vet_symlinked_directory(
    walker: DirWalker,
    root: &PinnedRoot,
    landing: &Landing<'_>,
) -> Result<Occupancy> {
    let rel = landing.path().as_path();
    if matches!(landing.kind(), LandingKind::Entry(_)) {
        check_directory_occupant(&root.dest().probe(rel), rel, root.dest())?;
    }
    walker.vet_dir(root, rel)?;
    Ok(Occupancy::Free)
}
