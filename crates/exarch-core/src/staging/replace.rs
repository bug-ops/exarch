//! [`Staging::AtomicReplace`]: swapping a staged tree over an existing
//! destination directory.
//!
//! The extraction runs into a fresh staging directory next to the destination.
//! Only after it succeeded is the original destination renamed aside to a
//! backup name, the staging directory renamed into its place and the backup
//! removed. If moving the staged tree into place fails, the backup is moved
//! back, so the original is restored.
//!
//! Every rename and removal is relative to a descriptor of the destination's
//! parent (see [`PinnedParent`]), which closes the window in which an
//! intermediate component is replaced with a symlink mid-swap (issue #526). A
//! `(dev, ino)` recheck right before the destructive rename additionally
//! narrows, without closing, the window around the destination itself: the
//! recheck is a check followed by a use, shrunk from the length of the
//! extraction to two system calls.
//!
//! A destination that is a symlink or not a directory is refused, as is one
//! that is a filesystem root or contains the archive or the working directory,
//! because replacing it would destroy more than the caller asked to replace.

use std::io;
use std::path::Path;
use std::path::PathBuf;

use super::StagedRun;
use super::cancelled_after;
use super::io_context;
use super::parent::DestEntryKind;
use super::parent::EntryName;
use super::parent::FileIdentity;
use super::parent::IdentityCheck;
use super::parent::PinnedParent;
use super::parent::is_absent;
use super::parent::surviving_path;
use super::staged_options;
use crate::ArchiveError;
use crate::BackupIdentity;
use crate::ConfigProblem;
use crate::ConfigSetting;
use crate::ExtractionOptions;
use crate::ExtractionReport;
use crate::ExtractionWarning;
use crate::IoKind;
use crate::ProgressCallback;
use crate::ProtectedPath;
use crate::ReplaceFailure;
use crate::Restore;
use crate::Result;
use crate::StagingLeftover;
use crate::Violation;
use crate::sanitize_io_error_for_error;

/// An existing destination directory, resolved and pinned before extraction
/// starts.
pub(super) struct ReplaceTarget {
    pin: PinnedParent,
    name: EntryName,
    id: FileIdentity,
    parent: PathBuf,
    path: PathBuf,
}

fn refuse(problem: ConfigProblem) -> ArchiveError {
    ArchiveError::InvalidConfiguration {
        setting: ConfigSetting::OutputPath,
        problem,
    }
}

fn protected(path: ProtectedPath) -> ArchiveError {
    refuse(ConfigProblem::ReplacesProtectedPath { path })
}

/// Splits `output_dir` into the directory to pin and the destination's name.
///
/// The name stays `file_name()`-derived: `file_name()` strips a trailing
/// separator, and a trailing separator makes even `SYMLINK_NOFOLLOW` resolve
/// through a symlink (`"link/"` names its target). A path that ends in `.`,
/// `..` or a root has no such name and goes through `canonicalize`.
///
/// `Ok(None)` means nothing can exist at the destination.
fn locate(output_dir: &Path) -> Result<Option<(PathBuf, EntryName)>> {
    if let Some(name) = EntryName::of(output_dir) {
        let parent = match output_dir.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => PathBuf::from("."),
        };
        return Ok(Some((parent, name)));
    }
    match output_dir.canonicalize() {
        Ok(canonical) => {
            let Some(parent) = canonical.parent() else {
                return Err(protected(ProtectedPath::FilesystemRoot));
            };
            let name = EntryName::of(&canonical).ok_or_else(|| refuse(ConfigProblem::NoParent))?;
            Ok(Some((parent.to_path_buf(), name)))
        }
        Err(e) if is_absent(&e) => Ok(None),
        Err(e) => Err(ArchiveError::Io(io_context(
            &e,
            "failed to resolve the destination",
            output_dir,
        ))),
    }
}

/// Resolves and pins what a replace of `output_dir` needs.
///
/// Returns `Ok(None)` when nothing can exist at the destination, so there is
/// nothing to replace and the caller stages and publishes as
/// [`Staging::Atomic`](crate::Staging::Atomic) does. A destination that
/// exists but is not a real directory is refused instead of replaced: that
/// would destroy data the caller never named. A parent that is absent or not a
/// directory only means there is nothing to replace.
///
/// Pinning the parent needs read permission on it, even when the destination
/// does not exist yet.
///
/// # Errors
///
/// `InvalidConfiguration` on `OutputPath` for a symlink or a non-directory
/// destination, or for a protected destination ([`ProtectedPath`]); an I/O
/// error when the parent cannot be resolved or pinned.
pub(super) fn resolve(output_dir: &Path, archive: Option<&Path>) -> Result<Option<ReplaceTarget>> {
    let Some((parent_path, name)) = locate(output_dir)? else {
        return Ok(None);
    };
    let parent = match parent_path.canonicalize() {
        Ok(canonical) => canonical,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(None);
        }
        Err(e) => {
            return Err(ArchiveError::Io(io_context(
                &e,
                "failed to resolve the destination parent",
                &parent_path,
            )));
        }
    };
    let pin = PinnedParent::open(&parent).map_err(|e| {
        ArchiveError::Io(io_context(
            &e,
            "failed to pin the destination parent",
            &parent,
        ))
    })?;
    let path = parent.join(&name);
    let (kind, id) = match pin.entry_status(&name) {
        Ok(status) => status,
        Err(e) if is_absent(&e) => return Ok(None),
        Err(e) => {
            return Err(ArchiveError::Io(io_context(
                &e,
                "failed to inspect the destination",
                &path,
            )));
        }
    };
    match kind {
        DestEntryKind::Directory => {}
        DestEntryKind::Symlink => return Err(refuse(ConfigProblem::IsSymlink)),
        DestEntryKind::Other => return Err(refuse(ConfigProblem::NotADirectory)),
    }
    if let Some(guard) = protected_path(&path, archive) {
        return Err(protected(guard));
    }
    Ok(Some(ReplaceTarget {
        pin,
        name,
        id,
        parent,
        path,
    }))
}

/// Why replacing the canonical directory `dest` would destroy more than the
/// destination, if it would.
///
/// An archive or working directory that cannot be resolved is not a reason to
/// refuse: an archive that is missing fails the extraction, and a deleted
/// working directory sits inside nothing.
pub(super) fn protected_path(dest: &Path, archive: Option<&Path>) -> Option<ProtectedPath> {
    if dest.parent().is_none() {
        return Some(ProtectedPath::FilesystemRoot);
    }
    let holds = |inner: Option<PathBuf>| inner.is_some_and(|inner| inner.starts_with(dest));
    if holds(archive.and_then(|archive| archive.canonicalize().ok())) {
        return Some(ProtectedPath::ArchiveAncestor);
    }
    if holds(
        std::env::current_dir()
            .and_then(|cwd| cwd.canonicalize())
            .ok(),
    ) {
        return Some(ProtectedPath::WorkingDirectory);
    }
    None
}

/// The staging directory, identified by the inode `entry_status` reported when
/// it was created, so a later check asks whether this directory is still
/// there and not just whether something has its name.
struct Staged<'a> {
    pin: &'a PinnedParent,
    name: EntryName,
    id: FileIdentity,
    parent: &'a Path,
}

impl Staged<'_> {
    /// Removes the staging directory and says what survived the removal.
    ///
    /// The removal goes by the logical path, which a redirect of the parent
    /// could point at a decoy; the survival check is relative to the pinned
    /// parent and so still sees the real directory, and names it from a
    /// descriptor on the entry itself.
    #[expect(
        clippy::disallowed_methods,
        reason = "removes the private staging directory; std's removal does not follow symlinks"
    )]
    fn discard(&self) -> Option<StagingLeftover> {
        let _ = std::fs::remove_dir_all(self.parent.join(&self.name));
        match self.pin.entry_status(&self.name) {
            Err(e) if is_absent(&e) => None,
            Ok((_, observed)) if observed.check(self.id) == IdentityCheck::Different => None,
            Ok(_) | Err(_) => Some(StagingLeftover {
                path: surviving_path(self.pin, &self.name, self.parent),
            }),
        }
    }

    /// The failure of a step that left the original destination in place.
    fn failed(&self, error: &io::Error, context: &'static str, path: &Path) -> ArchiveError {
        ArchiveError::ReplaceFailed(ReplaceFailure::new(
            io_context(error, context, path),
            Restore::NotNeeded,
            self.discard(),
        ))
    }
}

/// Extracts into a staging directory and swaps it over `target`.
///
/// # Errors
///
/// The extraction's own error, rolled back; `Cancelled` if the callback asked
/// to stop once extraction finished; `SecurityViolation(DestinationChanged)`
/// when the destination is no longer the directory that was pinned;
/// `ReplaceFailed` when a rename failed, saying whether the original
/// destination was restored.
pub(super) fn run(
    target: ReplaceTarget,
    options: &ExtractionOptions,
    progress: &mut dyn ProgressCallback,
    extract: impl StagedRun,
) -> Result<ExtractionReport> {
    let ReplaceTarget {
        pin,
        name,
        id,
        parent,
        path,
    } = target;
    let staging = tempfile::Builder::new()
        .prefix(".exarch-")
        .tempdir_in(&parent)
        .map_err(|e| {
            ArchiveError::Io(io_context(&e, "failed to create temp directory", &parent))
        })?;
    let staging_path = staging.keep();
    let staged_name = EntryName::of(&staging_path).ok_or_else(|| {
        ArchiveError::Io(io::Error::other(
            "the staging directory has no usable file name",
        ))
    });
    let staged_name = match staged_name {
        Ok(name) => name,
        Err(e) => {
            discard_unnamed(&staging_path);
            return Err(e);
        }
    };
    let staged_id = match pin.entry_status(&staged_name) {
        Ok((_, identity)) => identity,
        Err(e) => {
            discard_unnamed(&staging_path);
            return Err(ArchiveError::Io(io_context(
                &e,
                "failed to inspect the staging directory",
                &staging_path,
            )));
        }
    };
    let staged = Staged {
        pin: &pin,
        name: staged_name,
        id: staged_id,
        parent: &parent,
    };

    let report = match extract(&staging_path, &staged_options(options), progress) {
        Ok(report) => report,
        Err(e) => {
            // TODO(review): a staging directory that survives its removal after
            // a failed extraction cannot be reported through the extraction's
            // error.
            let _ = staged.discard();
            return Err(e.rolled_back());
        }
    };
    if progress.is_cancelled() {
        let _ = staged.discard();
        return Err(cancelled_after(report));
    }
    swap(&staged, &name, id, &path, report)
}

/// Removes a staging directory that has no name to identify it by.
#[expect(
    clippy::disallowed_methods,
    reason = "removes the private staging directory; std's removal does not follow symlinks"
)]
fn discard_unnamed(staging: &Path) {
    let _ = std::fs::remove_dir_all(staging);
}

/// The original destination, moved aside to a backup name until the swap
/// completes. Dropping it armed (a panic) moves the backup back, best effort.
#[must_use = "dropping a displaced destination restores it"]
struct Displaced<'a> {
    pin: &'a PinnedParent,
    dest_name: &'a EntryName,
    backup_name: EntryName,
    backup_path: PathBuf,
    backup_id: Option<FileIdentity>,
    armed: bool,
}

impl<'a> Displaced<'a> {
    /// Reserves a unique vacant sibling name, then renames the destination
    /// onto it.
    ///
    /// The reservation is a directory made by `tempfile` and freed again right
    /// away, as renaming onto an existing directory is unsupported on Windows.
    /// Every failure before the rename removes the staging directory.
    fn displace(
        staged: &Staged<'a>,
        dest_name: &'a EntryName,
        dest_id: FileIdentity,
        dest_path: &Path,
    ) -> Result<Self> {
        let backup_dir = tempfile::Builder::new()
            .prefix(".exarch-backup-")
            .tempdir_in(staged.parent)
            .map_err(|e| staged.failed(&e, "failed to reserve a backup path", staged.parent))?;
        let backup_path = backup_dir.keep();
        let Some(backup_name) = EntryName::of(&backup_path) else {
            return Err(staged.failed(
                &io::Error::other("the backup path has no usable file name"),
                "failed to reserve a backup path",
                &backup_path,
            ));
        };
        staged
            .pin
            .remove_dir(&backup_name)
            .map_err(|e| staged.failed(&e, "failed to free the backup path", &backup_path))?;

        verify_unchanged(staged.pin, dest_name, dest_id).inspect_err(|_| {
            let _ = staged.discard();
        })?;

        staged.pin.rename(dest_name, &backup_name).map_err(|e| {
            staged.failed(
                &e,
                "failed to move the existing destination aside",
                dest_path,
            )
        })?;
        // Best effort: the destination is already moved, so a failure to
        // inspect the backup must not abort the swap. Without an identity the
        // cleanup warning is skipped rather than claimed.
        let backup_id = staged
            .pin
            .entry_status(&backup_name)
            .ok()
            .map(|(_, identity)| identity);
        Ok(Self {
            pin: staged.pin,
            dest_name,
            backup_name,
            backup_path,
            backup_id,
            armed: true,
        })
    }

    /// Moves the backup back and disarms the guard.
    fn restore(mut self) -> io::Result<()> {
        self.armed = false;
        self.pin.rename(&self.backup_name, self.dest_name)
    }

    /// Removes the backup after a successful swap and disarms the guard. A
    /// removal that fails while the backup name still identifies the backup
    /// is reported as a warning on `report`.
    #[expect(
        clippy::disallowed_methods,
        reason = "removes the backup directory; std's removal does not follow symlinks"
    )]
    fn discard(mut self, report: &mut ExtractionReport) {
        self.armed = false;
        let Err(cleanup_error) = std::fs::remove_dir_all(&self.backup_path) else {
            return;
        };
        let Some(backup_id) = self.backup_id else {
            return;
        };
        let Ok((_, observed)) = self.pin.entry_status(&self.backup_name) else {
            return;
        };
        let identity = match observed.check(backup_id) {
            IdentityCheck::Same => BackupIdentity::Verified,
            IdentityCheck::Unknown => BackupIdentity::Unverified,
            IdentityCheck::Different => return,
        };
        report.add_warning(ExtractionWarning::BackupCleanupFailed {
            path: self.backup_path.clone(),
            identity,
            io_kind: IoKind::from(cleanup_error.kind()),
            message: sanitize_io_error_for_error(&cleanup_error).into(),
        });
    }
}

impl Drop for Displaced<'_> {
    fn drop(&mut self) {
        if self.armed {
            // Reached only when unwinding: every normal path consumes the guard
            // through `restore` or `discard`, which report their own outcome.
            let _unreportable = self.pin.rename(&self.backup_name, self.dest_name);
        }
    }
}

/// Refuses the swap when the destination is no longer the directory that was
/// pinned, or is no longer a directory. An identity the platform cannot
/// provide is not a mismatch: there is nothing to compare, and refusing would
/// make the replace unusable there.
fn verify_unchanged(pin: &PinnedParent, name: &EntryName, expected: FileIdentity) -> Result<()> {
    let (kind, current) = pin.entry_status(name).map_err(ArchiveError::Io)?;
    if kind != DestEntryKind::Directory || current.check(expected) == IdentityCheck::Different {
        return Err(Violation::DestinationChanged.into());
    }
    Ok(())
}

/// Swaps the staged tree over the destination and removes the backup.
fn swap(
    staged: &Staged<'_>,
    dest_name: &EntryName,
    dest_id: FileIdentity,
    dest_path: &Path,
    mut report: ExtractionReport,
) -> Result<ExtractionReport> {
    let displaced = Displaced::displace(staged, dest_name, dest_id, dest_path)?;
    if let Err(error) = staged.pin.rename(&staged.name, dest_name) {
        let backup = displaced.backup_path.clone();
        let restore = match displaced.restore() {
            Ok(()) => Restore::Restored,
            Err(restore_error) => Restore::Failed {
                backup,
                error: restore_error,
            },
        };
        return Err(ArchiveError::ReplaceFailed(ReplaceFailure::new(
            io_context(
                &error,
                "failed to move the extracted content into place",
                dest_path,
            ),
            restore,
            staged.discard(),
        )));
    }
    displaced.discard(&mut report);
    Ok(report)
}
