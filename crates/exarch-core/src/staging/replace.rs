//! [`Staging::AtomicReplace`](crate::Staging::AtomicReplace): swapping a staged
//! tree over an existing destination directory.
//!
//! The extraction runs into a fresh private staging directory next to the
//! destination. Only after it succeeded is the original destination renamed
//! aside to a backup name, the staging directory (given the original's
//! permissions) renamed into its place and the backup removed. If moving the
//! staged tree into place fails, the backup is moved back, so the original is
//! restored.
//!
//! Every rename and removal is relative to a pinned descriptor of the
//! destination's parent (a [`VettedDir`], a directory handle on Windows), which
//! closes the window in which an intermediate component is replaced with a
//! symlink mid-swap (issue #526). A file-identity recheck right before the
//! destructive rename additionally narrows, without closing, the window around
//! the destination itself: the recheck is a check followed by a use, shrunk
//! from the length of the extraction to two system calls.
//!
//! A destination that is a symlink or reparse point or not a directory is
//! refused, as is one that is a filesystem root or contains the archive or the
//! working directory, because replacing it would destroy more than the caller
//! asked to replace.

use std::io;
use std::path::Path;
use std::path::PathBuf;

use super::StagedRun;
use super::acl;
use super::adopt::Adoption;
use super::adopt::make_removable;
use super::cancelled_after;
use super::dir::Seed;
use super::dir::StagingDir;
use super::io_context;
use super::parent_or_cwd;
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
use crate::formats::file_identity::FileIdentity;
use crate::formats::file_identity::IdentityCheck;
use crate::formats::file_identity::identity_of;
use crate::formats::pinned_dir::EntryStatus;
use crate::formats::pinned_dir::LeafBuf;
use crate::formats::pinned_dir::VettedDir;
use crate::sanitize_io_error_for_error;
use crate::security::fs_view::Occupant;

const BACKUP_ATTEMPTS: usize = 16;

/// An existing destination directory, resolved and pinned before extraction
/// starts.
pub(super) struct ReplaceTarget {
    pin: VettedDir,
    name: LeafBuf,
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

fn is_absent(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound
}

/// Splits `output_dir` into the directory to pin and the destination's name.
///
/// The name stays `file_name()`-derived: `file_name()` strips a trailing
/// separator, and a trailing separator makes even `SYMLINK_NOFOLLOW` resolve
/// through a symlink (`"link/"` names its target). A path that ends in `.`,
/// `..` or a root has no such name and goes through `canonicalize`.
///
/// `Ok(None)` means nothing can exist at the destination.
fn locate(output_dir: &Path) -> Result<Option<(PathBuf, LeafBuf)>> {
    if let Some(name) = LeafBuf::of(output_dir) {
        return Ok(Some((parent_or_cwd(output_dir).to_path_buf(), name)));
    }
    match output_dir.canonicalize() {
        Ok(canonical) => {
            let Some(parent) = canonical.parent() else {
                return Err(protected(ProtectedPath::FilesystemRoot));
            };
            let name = LeafBuf::of(&canonical).ok_or_else(|| refuse(ConfigProblem::NoParent))?;
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
/// Pinning the parent needs search permission on it, even when the destination
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
    let pin = VettedDir::open_path(&parent).map_err(|e| {
        ArchiveError::Io(io_context(
            &e,
            "failed to pin the destination parent",
            &parent,
        ))
    })?;
    let path = parent.join(&name);
    let status = match pin.status(name.as_leaf()) {
        Ok(Some(status)) => status,
        Ok(None) => return Ok(None),
        Err(e) => {
            return Err(ArchiveError::Io(io_context(
                &e,
                "failed to inspect the destination",
                &path,
            )));
        }
    };
    refuse_unreplaceable(&status)?;
    if let Some(guard) = protected_path(&path, status.identity, archive) {
        return Err(protected(guard));
    }
    Ok(Some(ReplaceTarget {
        pin,
        name,
        id: status.identity,
        parent,
        path,
    }))
}

/// Refuses a destination that is not a plain directory: a symlink, any reparse
/// point (a mount point, or a tag `std` does not call a link) or a file.
fn refuse_unreplaceable(status: &EntryStatus) -> Result<()> {
    if status.reparse {
        return Err(refuse(ConfigProblem::IsSymlink));
    }
    match status.occupant {
        Occupant::Directory => Ok(()),
        Occupant::Symlink => Err(refuse(ConfigProblem::IsSymlink)),
        Occupant::File => Err(refuse(ConfigProblem::NotADirectory)),
    }
}

/// Why replacing the directory `dest`, identified by `dest_id`, would destroy
/// more than the destination, if it would.
///
/// The archive and the working directory are compared by identity, not by
/// path text: on a case- or normalization-insensitive volume (APFS by default,
/// NTFS) the caller can spell the destination differently from the canonical
/// path of what it holds, and a text comparison would let the replace delete
/// the archive or the working directory. Only where a volume reports no
/// identity is the canonical path compared.
///
/// An archive or working directory that cannot be resolved is not a reason to
/// refuse: an archive that is missing fails the extraction, and a deleted
/// working directory sits inside nothing.
pub(super) fn protected_path(
    dest: &Path,
    dest_id: FileIdentity,
    archive: Option<&Path>,
) -> Option<ProtectedPath> {
    if dest.parent().is_none() {
        return Some(ProtectedPath::FilesystemRoot);
    }
    let holds = |inner: Option<PathBuf>| {
        inner.is_some_and(|inner| is_within(dest, dest_id, &inner, identity_of))
    };
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

/// Whether `inner`, or one of its ancestors, is the directory `dest_id`
/// identifies. `identify` looks an ancestor up; one that cannot be looked up
/// counts as a match, so an uncertain answer refuses.
///
/// Where either identity is unknown the canonical form of `dest` is compared
/// with the (canonical) ancestor, and a `dest` that cannot be canonicalized
/// refuses too: comparing the destination as the caller spelled it would let
/// another spelling of the same directory (an 8.3 short name on Windows) pass.
pub(super) fn is_within(
    dest: &Path,
    dest_id: FileIdentity,
    inner: &Path,
    identify: impl Fn(&Path) -> io::Result<FileIdentity>,
) -> bool {
    inner
        .ancestors()
        .filter(|ancestor| !ancestor.is_empty())
        .any(|ancestor| {
            identify(ancestor).map_or(true, |id| match id.check(dest_id) {
                IdentityCheck::Same => true,
                IdentityCheck::Different => false,
                IdentityCheck::Unknown => dest
                    .canonicalize()
                    .map_or(true, |dest| same_text(ancestor, &dest)),
            })
        })
}

/// Path text equality, case-insensitive on Windows.
#[cfg(windows)]
fn same_text(a: &Path, b: &Path) -> bool {
    use crate::security::fs_view::paths_start_with;
    paths_start_with(a, b) && paths_start_with(b, a)
}

#[cfg(not(windows))]
fn same_text(a: &Path, b: &Path) -> bool {
    a == b
}

/// A failure before the destination was touched.
enum Refusal {
    Failed {
        error: io::Error,
        context: &'static str,
        path: PathBuf,
        restore: Restore,
    },
    Error(ArchiveError),
}

impl Refusal {
    fn failed(error: io::Error, context: &'static str, path: &Path) -> Self {
        Self::Failed {
            error,
            context,
            path: path.to_path_buf(),
            restore: Restore::NotNeeded,
        }
    }

    /// The error, saying which staging directory survived its removal.
    fn into_error(self, leftover: Option<StagingLeftover>) -> ArchiveError {
        match self {
            Self::Failed {
                error,
                context,
                path,
                restore,
            } => ArchiveError::ReplaceFailed(ReplaceFailure::new(
                io_context(&error, context, &path),
                restore,
                leftover,
            )),
            Self::Error(error) => error.rolled_back_with(leftover),
        }
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
/// destination was restored. An error names the staging directory that could
/// not be removed.
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
    let inheritance = acl::read_inheritance(&pin, name.as_leaf(), &parent, id).map_err(|e| {
        ArchiveError::Io(io_context(
            &e,
            "failed to read the destination's access control list",
            &path,
        ))
    })?;
    let staging = StagingDir::create(&pin, &parent, Seed::Replace(id, inheritance))?;

    let report = match extract(staging.path(), &staged_options(options), progress) {
        Ok(report) => report,
        Err(e) => return Err(e.rolled_back_with(staging.discard())),
    };
    if progress.is_cancelled() {
        return Err(cancelled_after(report, staging.discard()));
    }
    let dest = Dest {
        name: &name,
        id,
        path: &path,
        parent: &parent,
    };
    swap(staging, &dest, report)
}

/// The destination being replaced.
struct Dest<'a> {
    name: &'a LeafBuf,
    id: FileIdentity,
    path: &'a Path,
    parent: &'a Path,
}

/// The original destination, moved aside to a backup name until the swap
/// completes. Dropping it armed (a panic) moves the backup back, best effort.
#[must_use = "dropping a displaced destination restores it"]
struct Displaced<'a> {
    pin: &'a VettedDir,
    dest_name: &'a LeafBuf,
    backup_name: LeafBuf,
    backup_path: PathBuf,
    backup: EntryStatus,
    armed: bool,
}

impl<'a> Displaced<'a> {
    /// Reserves a vacant sibling name, then renames the destination onto it.
    ///
    /// The name must be vacant: renaming onto an existing directory is
    /// refused on Windows.
    ///
    /// The directory that was actually moved is inspected afterwards and must
    /// still be the one pinned (`dest.id`): the check before the rename leaves
    /// a window in which a writer of the parent could swap in a substitute,
    /// whose permissions would then be adopted and whose tree would be
    /// deleted. A mismatch moves the entry back and refuses. A volume that
    /// reports no identity cannot be compared and is accepted, as in
    /// [`verify_unchanged`].
    fn displace(pin: &'a VettedDir, dest: &Dest<'a>) -> std::result::Result<Self, Refusal> {
        Self::displace_with(pin, dest, || {})
    }

    fn displace_with(
        pin: &'a VettedDir,
        dest: &Dest<'a>,
        between_check_and_rename: impl FnOnce(),
    ) -> std::result::Result<Self, Refusal> {
        let backup_name = Self::vacant_name(pin)
            .map_err(|e| Refusal::failed(e, "failed to reserve a backup path", dest.parent))?;
        let backup_path = dest.parent.join(&backup_name);

        verify_unchanged(pin, dest.name, dest.id).map_err(Refusal::Error)?;
        between_check_and_rename();

        pin.rename_dir_within(dest.name.as_leaf(), backup_name.as_leaf())
            .map_err(|e| {
                Refusal::failed(
                    e,
                    "failed to move the existing destination aside",
                    dest.path,
                )
            })?;
        let moved = match pin.status(backup_name.as_leaf()) {
            Ok(Some(status)) if Self::is_pinned_directory(&status, dest.id) => status,
            other => {
                let (error, context, changed) = match other {
                    Err(e) => (e, "failed to inspect the destination moved aside", false),
                    _ => (
                        io::Error::other("the destination changed while it was moved aside"),
                        "failed to move the existing destination aside",
                        true,
                    ),
                };
                let restored = pin.rename_dir_within(backup_name.as_leaf(), dest.name.as_leaf());
                return Err(match (restored, changed) {
                    (Ok(()), true) => Refusal::Error(Violation::DestinationChanged.into()),
                    (Ok(()), false) => Refusal::Failed {
                        error,
                        context,
                        path: dest.path.to_path_buf(),
                        restore: Restore::Restored,
                    },
                    (Err(restore_error), _) => Refusal::Failed {
                        error,
                        context,
                        path: dest.path.to_path_buf(),
                        restore: Restore::Failed {
                            backup: backup_path,
                            error: restore_error,
                        },
                    },
                });
            }
        };
        Ok(Self {
            pin,
            dest_name: dest.name,
            backup_name,
            backup_path,
            backup: moved,
            armed: true,
        })
    }

    fn is_pinned_directory(status: &EntryStatus, expected: FileIdentity) -> bool {
        status.occupant == Occupant::Directory
            && !status.reparse
            && (matches!(expected, FileIdentity::Unknown)
                || status.identity.check(expected) == IdentityCheck::Same)
    }

    fn vacant_name(pin: &VettedDir) -> io::Result<LeafBuf> {
        for _ in 0..BACKUP_ATTEMPTS {
            let name = LeafBuf::random(".exarch-backup-");
            if pin.status(name.as_leaf())?.is_none() {
                return Ok(name);
            }
        }
        Err(io::Error::from(io::ErrorKind::AlreadyExists))
    }

    /// The permissions and ACL of the destination that was displaced, read
    /// from the verified directory itself, which now sits in `parent`.
    fn original_permissions(&self, parent: &Path) -> io::Result<Adoption> {
        let acl = acl::read_destination(
            self.pin,
            self.backup_name.as_leaf(),
            parent,
            self.backup.identity,
        )?;
        Ok(Adoption::of(&self.backup, acl))
    }

    /// Moves the backup back and disarms the guard.
    fn restore(mut self) -> io::Result<()> {
        self.armed = false;
        self.pin
            .rename_dir_within(self.backup_name.as_leaf(), self.dest_name.as_leaf())
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
        make_removable(self.pin, self.backup_name.as_leaf(), self.backup.identity);
        let Err(cleanup_error) = std::fs::remove_dir_all(&self.backup_path) else {
            return;
        };
        let backup = self.backup;
        let Ok(Some(observed)) = self.pin.status(self.backup_name.as_leaf()) else {
            return;
        };
        let identity = match observed.identity.check(backup.identity) {
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
            let _unreportable = self
                .pin
                .rename_dir_within(self.backup_name.as_leaf(), self.dest_name.as_leaf());
        }
    }
}

/// Refuses the swap when the destination is no longer the directory that was
/// pinned, or is no longer a plain directory. An identity the volume cannot
/// provide is not a mismatch: there is nothing to compare, and refusing would
/// make the replace unusable there.
fn verify_unchanged(pin: &VettedDir, name: &LeafBuf, expected: FileIdentity) -> Result<()> {
    let current = pin
        .status(name.as_leaf())
        .map_err(ArchiveError::Io)?
        .filter(|status| status.occupant == Occupant::Directory && !status.reparse)
        .ok_or(Violation::DestinationChanged)?;
    if current.identity.check(expected) == IdentityCheck::Different {
        return Err(Violation::DestinationChanged.into());
    }
    Ok(())
}

/// Swaps the staged tree over the destination and removes the backup.
///
/// The staged root takes the original's permissions only now, right before it
/// is published, so a failure anywhere earlier leaves it private. A failure to
/// do that or to rename puts the original back.
fn swap(
    staging: StagingDir<'_>,
    dest: &Dest<'_>,
    report: ExtractionReport,
) -> Result<ExtractionReport> {
    let displaced = match Displaced::displace(staging.parent, dest) {
        Ok(displaced) => displaced,
        Err(refusal) => return Err(refusal.into_error(staging.discard())),
    };
    let adoption = displaced.original_permissions(dest.parent);
    swap_adopted(staging, dest, displaced, adoption, report)
}

/// Adopts `adoption` on the staged root, publishes it over the displaced
/// destination and removes the backup, recording on `report` every way the
/// root ended up with less access than the destination had.
fn swap_adopted(
    mut staging: StagingDir<'_>,
    dest: &Dest<'_>,
    displaced: Displaced<'_>,
    adoption: io::Result<Adoption>,
    mut report: ExtractionReport,
) -> Result<ExtractionReport> {
    match adoption.and_then(|adoption| staging.adopt(adoption)) {
        Ok(narrowed) => report.record_narrowing(narrowed),
        Err(error) => {
            let context = "failed to give the extracted content the destination's permissions";
            return Err(roll_back(displaced, staging, &error, context, dest.path));
        }
    }
    if let Err(error) = staging.publish(dest.name) {
        let context = "failed to move the extracted content into place";
        return Err(roll_back(displaced, staging, &error, context, dest.path));
    }
    displaced.discard(&mut report);
    Ok(report)
}

/// Puts the original destination back after a failed publish and discards the
/// staging directory.
fn roll_back(
    displaced: Displaced<'_>,
    staging: StagingDir<'_>,
    error: &io::Error,
    context: &'static str,
    dest_path: &Path,
) -> ArchiveError {
    let backup = displaced.backup_path.clone();
    let restore = match displaced.restore() {
        Ok(()) => Restore::Restored,
        Err(restore_error) => Restore::Failed {
            backup,
            error: restore_error,
        },
    };
    ArchiveError::ReplaceFailed(ReplaceFailure::new(
        io_context(error, context, dest_path),
        restore,
        staging.discard(),
    ))
}

/// Runs [`swap_adopted`] over a real destination with `adoption`, on a staging
/// directory made as `seed` says of the destination's identity, and returns
/// the report it produced.
#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
pub(super) fn swap_adopted_for_test(
    adoption: Adoption,
    seed: impl FnOnce(FileIdentity) -> Seed,
) -> ExtractionReport {
    use crate::formats::file_identity::identity_of;

    let temp = tempfile::TempDir::new().unwrap();
    let parent = temp.path().canonicalize().unwrap();
    let dest_path = parent.join("dest");
    std::fs::create_dir(&dest_path).unwrap();
    let name = LeafBuf::of(&dest_path).unwrap();
    let dest = Dest {
        name: &name,
        id: identity_of(&dest_path).unwrap(),
        path: &dest_path,
        parent: &parent,
    };
    let pin = crate::formats::pinned_dir::support::pinned_at(&parent);
    let staging = StagingDir::create(&pin, &parent, seed(dest.id)).unwrap();
    let Ok(displaced) = Displaced::displace(&pin, &dest) else {
        panic!("the destination should be displaced");
    };
    swap_adopted(
        staging,
        &dest,
        displaced,
        Ok(adoption),
        ExtractionReport::new(),
    )
    .unwrap()
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod displace_tests {
    use tempfile::TempDir;

    use super::Dest;
    use super::Displaced;
    use super::Refusal;
    use crate::ArchiveError;
    use crate::Violation;
    use crate::formats::file_identity::identity_of;
    use crate::formats::pinned_dir::LeafBuf;
    use crate::formats::pinned_dir::support::pinned_at;

    #[test]
    fn a_destination_swapped_after_the_check_is_moved_back_and_refused() {
        let temp = TempDir::new().unwrap();
        let parent = temp.path().canonicalize().unwrap();
        let dest_path = parent.join("dest");
        std::fs::create_dir(&dest_path).unwrap();
        std::fs::write(dest_path.join("old"), b"original").unwrap();
        let name = LeafBuf::of(&dest_path).unwrap();
        let dest = Dest {
            name: &name,
            id: identity_of(&dest_path).unwrap(),
            path: &dest_path,
            parent: &parent,
        };
        let pin = pinned_at(&parent);
        let aside = parent.join("aside");

        let outcome = Displaced::displace_with(&pin, &dest, || {
            std::fs::rename(&dest_path, &aside).unwrap();
            std::fs::create_dir(&dest_path).unwrap();
            std::fs::write(dest_path.join("substitute"), b"planted").unwrap();
        });

        let Err(Refusal::Error(ArchiveError::SecurityViolation {
            kind: Violation::DestinationChanged,
        })) = outcome
        else {
            panic!("expected a DestinationChanged refusal");
        };
        assert_eq!(std::fs::read(aside.join("old")).unwrap(), b"original");
        assert!(dest_path.join("substitute").exists());
        let names: Vec<_> = std::fs::read_dir(&parent)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().all(|n| !n.starts_with(".exarch-")),
            "{names:?}"
        );
    }
}

#[cfg(all(test, windows))]
#[allow(clippy::unwrap_used)]
mod windows_tests {
    use std::os::windows::process::CommandExt;
    use std::path::Path;
    use std::path::PathBuf;
    use std::process::Command;

    use tempfile::TempDir;

    use super::protected_path;
    use crate::ProtectedPath;
    use crate::formats::file_identity::FileIdentity;
    use crate::formats::file_identity::IdentityCheck;
    use crate::formats::file_identity::identity_of;

    /// The 8.3 spelling of `path`, or `None` when the volume has no short
    /// names (they can be disabled per volume).
    fn short_spelling(path: &Path) -> Option<PathBuf> {
        let output = Command::new("cmd")
            .raw_arg(format!(
                "/C for %I in (\"{}\") do @echo %~sI",
                path.display()
            ))
            .output()
            .ok()?;
        let short = PathBuf::from(String::from_utf8(output.stdout).ok()?.trim());
        (short.exists() && short != path).then_some(short)
    }

    fn long_named_dir(temp: &TempDir) -> PathBuf {
        let dir = temp.path().join("exarchlongdirectoryname");
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn a_short_name_is_the_same_directory_by_identity() {
        let temp = TempDir::new().unwrap();
        let long = long_named_dir(&temp);
        let Some(short) = short_spelling(&long) else {
            eprintln!("skipping: the volume has no 8.3 names");
            return;
        };
        let (long_id, short_id) = (identity_of(&long).unwrap(), identity_of(&short).unwrap());
        if matches!(long_id, FileIdentity::Unknown) {
            eprintln!("skipping: the volume reports no file id");
            return;
        }

        assert_eq!(short_id.check(long_id), IdentityCheck::Same);
        let other = temp.path().join("other");
        std::fs::create_dir(&other).unwrap();
        assert_eq!(
            identity_of(&other).unwrap().check(long_id),
            IdentityCheck::Different
        );
    }

    #[test]
    fn a_destination_spelled_with_its_short_name_still_protects_the_archive() {
        let temp = TempDir::new().unwrap();
        let long = long_named_dir(&temp);
        let archive = long.join("a.tar");
        std::fs::write(&archive, b"x").unwrap();
        let Some(short) = short_spelling(&long) else {
            eprintln!("skipping: the volume has no 8.3 names");
            return;
        };
        let dest_id = identity_of(&short).unwrap();

        assert_eq!(
            protected_path(&short, dest_id, Some(&archive)),
            Some(ProtectedPath::ArchiveAncestor)
        );
        assert_eq!(
            protected_path(&short, FileIdentity::Unknown, Some(&archive)),
            Some(ProtectedPath::ArchiveAncestor),
            "an unknown identity falls back to the canonical paths"
        );
    }
}
