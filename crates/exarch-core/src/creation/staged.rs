//! Staged archive output: written beside the target, published on success.
//!
//! An archive is written to a temporary file in the target's directory and
//! renamed into place only after it is complete. A failed creation therefore
//! leaves the target path exactly as it was: absent, or holding the previous
//! archive.

use std::ffi::OsString;
use std::fs;
use std::fs::File;
use std::fs::Permissions;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use tempfile::Builder;
use tempfile::NamedTempFile;

use crate::ArchiveError;
use crate::ConfigProblem;
use crate::ConfigSetting;
use crate::CreationWarning;
use crate::Result;
use crate::STAGING_PREFIX;
use crate::request::Durability;
use crate::request::OutputPolicy;

/// What currently occupies the target path.
enum Occupant {
    Absent,
    /// A regular file, or a symlink that resolves to one, with its mode.
    Regular(Permissions),
    /// A symlink whose destination does not exist.
    DanglingLink,
}

impl Occupant {
    /// Classifies `target`; anything that is not a regular file, a symlink to
    /// one or a dangling symlink cannot be replaced by a regular archive file.
    fn inspect(target: &Path) -> Result<Self> {
        let link = match fs::symlink_metadata(target) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Self::Absent),
            Err(e) => return Err(e.into()),
        };
        if link.is_file() {
            return Ok(Self::Regular(link.permissions()));
        }
        if !link.is_symlink() {
            return Err(unsupported_target());
        }
        match fs::metadata(target) {
            Ok(resolved) if resolved.is_file() => Ok(Self::Regular(resolved.permissions())),
            Ok(_) => Err(unsupported_target()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::DanglingLink),
            Err(e) => Err(e.into()),
        }
    }
}

const fn unsupported_target() -> ArchiveError {
    ArchiveError::InvalidConfiguration {
        setting: ConfigSetting::OutputPath,
        problem: ConfigProblem::NotSupported,
    }
}

/// The mode the staged file ends with: the replaced file's, never wider than
/// it was and never setuid, setgid or sticky.
#[cfg(unix)]
fn carried_over(permissions: &Permissions) -> Permissions {
    use std::os::unix::fs::PermissionsExt;
    Permissions::from_mode(permissions.mode() & 0o777)
}

#[cfg(not(unix))]
fn carried_over(permissions: &Permissions) -> Permissions {
    permissions.clone()
}

/// Mode of a file that is being written and must not be readable by others
/// before its final mode is applied.
#[cfg(unix)]
fn private_while_writing(builder: &mut Builder<'_, '_>) {
    use std::os::unix::fs::PermissionsExt;
    builder.permissions(Permissions::from_mode(0o600));
}

/// Mode of a new file, subject to the umask, like `File::create`.
#[cfg(unix)]
fn default_creation_mode(builder: &mut Builder<'_, '_>) {
    use std::os::unix::fs::PermissionsExt;
    builder.permissions(Permissions::from_mode(0o666));
}

#[cfg(not(unix))]
fn private_while_writing(_: &mut Builder<'_, '_>) {}

#[cfg(not(unix))]
fn default_creation_mode(_: &mut Builder<'_, '_>) {}

/// Archive paths that creation must not add to the archive: the staged file
/// and the target it will replace.
///
/// Matched by path, not by identity (a file identity is not stable on every
/// platform): the entry's file name first, then its canonical parent. The name
/// comparison is case-sensitive, so on a case-insensitive filesystem a target
/// spelled in another case than its on-disk name is not recognized.
#[derive(Debug)]
pub(crate) struct ExcludedOutput {
    parent: PathBuf,
    names: Vec<OsString>,
}

impl ExcludedOutput {
    /// Excludes nothing: for a destination that is not a file in a directory.
    pub(crate) const fn none() -> Self {
        Self {
            parent: PathBuf::new(),
            names: Vec::new(),
        }
    }

    /// Whether `path` is the staged file or the target.
    pub(crate) fn excludes(&self, path: &Path) -> bool {
        let Some(name) = path.file_name() else {
            return false;
        };
        if !self.names.iter().any(|excluded| excluded == name) {
            return false;
        }
        let parent = path
            .parent()
            .filter(|parent| !parent.is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::canonicalize(parent).is_ok_and(|parent| parent == self.parent)
    }
}

/// An archive being written to a temporary file next to its target.
///
/// Dropping it without [`commit`](Self::commit) deletes the temporary file.
pub(crate) struct StagedOutput {
    temp: NamedTempFile,
    target: PathBuf,
    policy: OutputPolicy,
    permissions: Option<Permissions>,
    excluded: ExcludedOutput,
}

impl StagedOutput {
    /// Stages an archive for `target` under `policy`.
    ///
    /// Everything that can refuse the target is decided here, before any
    /// source is read: an existing file under
    /// [`OutputPolicy::CreateNew`] is [`ArchiveError::OutputExists`], and a
    /// target that is neither a regular file, nor a symlink to one, nor absent
    /// (a FIFO, a device, a directory) is refused for both policies.
    ///
    /// # Errors
    ///
    /// Returns an error if the target is refused as described, its parent
    /// directory cannot be resolved or written, or the temporary file cannot
    /// be created.
    pub(crate) fn begin(target: &Path, policy: OutputPolicy) -> Result<Self> {
        let name = target.file_name().ok_or_else(unsupported_target)?;
        let parent = target.parent().ok_or(ArchiveError::InvalidConfiguration {
            setting: ConfigSetting::OutputPath,
            problem: ConfigProblem::NoParent,
        })?;
        let parent = fs::canonicalize(if parent.is_empty() {
            Path::new(".")
        } else {
            parent
        })?;
        let target = parent.join(name);

        let occupant = Occupant::inspect(&target)?;
        if policy == OutputPolicy::CreateNew && !matches!(occupant, Occupant::Absent) {
            return Err(ArchiveError::OutputExists { path: target });
        }

        let mut builder = Builder::new();
        builder.prefix(STAGING_PREFIX);
        let permissions = match &occupant {
            Occupant::Regular(permissions) => {
                private_while_writing(&mut builder);
                Some(carried_over(permissions))
            }
            Occupant::Absent | Occupant::DanglingLink => {
                default_creation_mode(&mut builder);
                None
            }
        };
        let temp = builder.tempfile_in(&parent)?;

        let mut names = vec![name.to_os_string()];
        names.extend(temp.path().file_name().map(OsString::from));
        Ok(Self {
            temp,
            target,
            policy,
            permissions,
            excluded: ExcludedOutput { parent, names },
        })
    }

    /// The temporary file the archive is written to, and the staged and target
    /// paths, which a source directory that contains them must not archive.
    pub(crate) fn parts(&mut self) -> (&mut File, &ExcludedOutput) {
        (self.temp.as_file_mut(), &self.excluded)
    }

    /// Publishes the archive at the target. Under [`Durability::Synced`] the
    /// file is flushed first and the parent directory is synced afterwards
    /// (Unix only); [`Durability::Unsynced`] skips both.
    ///
    /// The directory sync happens after the archive is published, so its
    /// failure does not fail the creation: it is returned as
    /// [`CreationWarning::DirectoryNotSynced`].
    ///
    /// The mode of a replaced file is applied after the write, right before the
    /// rename. [`OutputPolicy::CreateNew`] never overwrites: a file that
    /// appeared since [`begin`](Self::begin) is [`ArchiveError::OutputExists`].
    ///
    /// # Errors
    ///
    /// Returns an error if syncing, setting the mode or renaming fails; the
    /// temporary file is deleted and the target is untouched.
    pub(crate) fn commit(self, durability: Durability) -> Result<Option<CreationWarning>> {
        self.commit_with(durability, &HostFlush)
    }

    fn commit_with(
        self,
        durability: Durability,
        flush: &impl Flush,
    ) -> Result<Option<CreationWarning>> {
        let Self {
            temp,
            target,
            policy,
            permissions,
            ..
        } = self;
        if durability == Durability::Synced {
            flush.file(temp.as_file())?;
        }
        if let Some(permissions) = permissions {
            temp.as_file().set_permissions(permissions)?;
        }
        match policy {
            OutputPolicy::Replace => temp
                .persist(&target)
                .map(drop)
                .map_err(|failed| ArchiveError::Io(failed.error))?,
            OutputPolicy::CreateNew => publish_new(temp, &target)?,
        }
        if durability == Durability::Synced
            && let Err(error) = flush.parent(&target)
        {
            return Ok(Some(CreationWarning::DirectoryNotSynced {
                io_kind: error.kind().into(),
            }));
        }
        Ok(None)
    }
}

/// The two flushes of a synced commit, behind a seam so a test can observe
/// that an unsynced commit performs neither.
trait Flush {
    /// Flushes the staged archive file to stable storage.
    fn file(&self, file: &File) -> io::Result<()>;

    /// Flushes the directory entry of the published `target`.
    fn parent(&self, target: &Path) -> io::Result<()>;
}

/// Flushes through the operating system.
struct HostFlush;

impl Flush for HostFlush {
    fn file(&self, file: &File) -> io::Result<()> {
        file.sync_all()
    }

    fn parent(&self, target: &Path) -> io::Result<()> {
        sync_parent(target)
    }
}

/// Flushes the directory entry of a published archive, so the rename survives
/// a crash and not only the file contents.
///
/// Unix only: elsewhere this does nothing and reports success.
#[cfg(unix)]
fn sync_parent(target: &Path) -> io::Result<()> {
    match target.parent() {
        Some(parent) => File::open(parent)?.sync_all(),
        None => Ok(()),
    }
}

#[cfg(not(unix))]
#[expect(clippy::unnecessary_wraps, reason = "same signature as the Unix flush")]
fn sync_parent(_: &Path) -> io::Result<()> {
    Ok(())
}

/// Renames `temp` to `target` unless something is there.
fn publish_new(temp: NamedTempFile, target: &Path) -> Result<()> {
    match temp.persist_noclobber(target) {
        Ok(_) => Ok(()),
        Err(failed) if failed.error.kind() == io::ErrorKind::AlreadyExists => {
            Err(ArchiveError::OutputExists {
                path: target.to_path_buf(),
            })
        }
        Err(failed) => publish_through_reservation(failed.file, target, failed.error),
    }
}

/// The fallback for a filesystem that cannot publish without replacing (the
/// link primitive of `persist_noclobber` is missing on FAT and exFAT): the name
/// is reserved with an exclusive create, then the staged file is renamed over
/// the reservation.
///
/// A crash between the two steps leaves an empty file at the target, on such
/// filesystems only. A failed rename removes the reservation, after checking
/// that the file at the target is still the one reserved; where that cannot be
/// checked, the reservation is left and named in the error.
#[expect(
    clippy::disallowed_methods,
    reason = "reserves the caller-named output path exclusively, not an extraction destination"
)]
fn publish_through_reservation(
    temp: NamedTempFile,
    target: &Path,
    unsupported: io::Error,
) -> Result<()> {
    let reservation = match File::create_new(target) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return Err(ArchiveError::OutputExists {
                path: target.to_path_buf(),
            });
        }
        Err(_) => return Err(ArchiveError::Io(unsupported)),
    };
    match temp.persist(target) {
        Ok(_) => Ok(()),
        Err(failed) => Err(if release_reservation(&reservation, target) {
            ArchiveError::Io(failed.error)
        } else {
            ArchiveError::OutputReservationLeft {
                path: target.to_path_buf(),
                error: failed.error,
            }
        }),
    }
}

/// Removes the reservation at `target` if it is still the reserved file;
/// returns whether it is gone.
#[cfg(unix)]
#[expect(
    clippy::disallowed_methods,
    reason = "removes the reservation this call created at the caller-named output path"
)]
fn release_reservation(reservation: &File, target: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let (Ok(reserved), Ok(present)) = (reservation.metadata(), fs::symlink_metadata(target)) else {
        return false;
    };
    reserved.dev() == present.dev()
        && reserved.ino() == present.ino()
        && fs::remove_file(target).is_ok()
}

#[cfg(not(unix))]
fn release_reservation(_: &File, _: &Path) -> bool {
    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::assert_matches;

    use super::*;

    fn staged(dir: &Path, name: &str, policy: OutputPolicy) -> Result<StagedOutput> {
        StagedOutput::begin(&dir.join(name), policy)
    }

    fn write_and_commit(staged: StagedOutput, bytes: &[u8]) -> Result<()> {
        write_and_commit_with(staged, bytes, Durability::Synced)
    }

    fn write_and_commit_with(
        mut staged: StagedOutput,
        bytes: &[u8],
        durability: Durability,
    ) -> Result<()> {
        io::Write::write_all(staged.parts().0, bytes).unwrap();
        staged.commit(durability).map(drop)
    }

    #[test]
    fn dropping_the_staged_output_leaves_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let out = staged(dir.path(), "a.tar", OutputPolicy::CreateNew).unwrap();
        drop(out);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn commit_publishes_a_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let out = staged(dir.path(), "a.tar", OutputPolicy::CreateNew).unwrap();
        write_and_commit(out, b"new").unwrap();
        assert_eq!(fs::read(dir.path().join("a.tar")).unwrap(), b"new");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[derive(Default)]
    struct Recorder(std::cell::RefCell<Vec<&'static str>>);

    impl Flush for Recorder {
        fn file(&self, _: &File) -> io::Result<()> {
            self.0.borrow_mut().push("file");
            Ok(())
        }

        fn parent(&self, _: &Path) -> io::Result<()> {
            self.0.borrow_mut().push("parent");
            Ok(())
        }
    }

    fn flushes(durability: Durability) -> Vec<&'static str> {
        let dir = tempfile::tempdir().unwrap();
        let recorder = Recorder::default();
        let mut out = staged(dir.path(), "a.tar", OutputPolicy::CreateNew).unwrap();
        io::Write::write_all(out.parts().0, b"new").unwrap();
        out.commit_with(durability, &recorder).unwrap();
        assert_eq!(fs::read(dir.path().join("a.tar")).unwrap(), b"new");
        recorder.0.into_inner()
    }

    #[test]
    fn synced_flushes_the_file_then_the_parent() {
        assert_eq!(flushes(Durability::Synced), ["file", "parent"]);
    }

    struct ParentSyncFails(io::ErrorKind);

    impl Flush for ParentSyncFails {
        fn file(&self, _: &File) -> io::Result<()> {
            Ok(())
        }

        fn parent(&self, _: &Path) -> io::Result<()> {
            Err(self.0.into())
        }
    }

    fn commit_with_failing_parent(durability: Durability) -> Option<CreationWarning> {
        let dir = tempfile::tempdir().unwrap();
        let mut out = staged(dir.path(), "a.tar", OutputPolicy::CreateNew).unwrap();
        io::Write::write_all(out.parts().0, b"new").unwrap();
        let warning = out
            .commit_with(
                durability,
                &ParentSyncFails(io::ErrorKind::PermissionDenied),
            )
            .unwrap();
        assert_eq!(fs::read(dir.path().join("a.tar")).unwrap(), b"new");
        warning
    }

    #[test]
    fn a_parent_sync_failure_publishes_the_archive_and_warns() {
        assert_matches!(
            commit_with_failing_parent(Durability::Synced),
            Some(CreationWarning::DirectoryNotSynced {
                io_kind: crate::IoKind::PermissionDenied
            })
        );
    }

    #[test]
    fn unsynced_never_warns_about_the_parent() {
        assert_matches!(commit_with_failing_parent(Durability::Unsynced), None);
    }

    #[test]
    fn unsynced_flushes_neither_the_file_nor_the_parent() {
        assert!(flushes(Durability::Unsynced).is_empty());
    }

    #[test]
    fn the_default_durability_is_synced() {
        assert_eq!(Durability::default(), Durability::Synced);
    }

    #[test]
    fn every_durability_publishes_under_both_policies() {
        for durability in Durability::ALL {
            for policy in [OutputPolicy::CreateNew, OutputPolicy::Replace] {
                let dir = tempfile::tempdir().unwrap();
                fs::write(dir.path().join("old.tar"), b"old").unwrap();
                let name = "old.tar";
                let name = if policy == OutputPolicy::CreateNew {
                    "a.tar"
                } else {
                    name
                };
                let out = staged(dir.path(), name, policy).unwrap();
                write_and_commit_with(out, b"new", *durability).unwrap();
                assert_eq!(fs::read(dir.path().join(name)).unwrap(), b"new");
            }
        }
    }

    #[test]
    fn create_new_refuses_an_existing_file_before_any_work() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.tar"), b"old").unwrap();
        let err = staged(dir.path(), "a.tar", OutputPolicy::CreateNew)
            .err()
            .unwrap();
        assert_matches!(err, ArchiveError::OutputExists { .. });
        assert_eq!(fs::read(dir.path().join("a.tar")).unwrap(), b"old");
    }

    #[test]
    fn create_new_refuses_a_file_that_appeared_after_staging() {
        let dir = tempfile::tempdir().unwrap();
        let out = staged(dir.path(), "a.tar", OutputPolicy::CreateNew).unwrap();
        fs::write(dir.path().join("a.tar"), b"raced").unwrap();
        let err = write_and_commit(out, b"new").unwrap_err();
        assert_matches!(err, ArchiveError::OutputExists { .. });
        assert_eq!(fs::read(dir.path().join("a.tar")).unwrap(), b"raced");
    }

    #[test]
    fn a_missing_parent_directory_is_an_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = StagedOutput::begin(&dir.path().join("nope/a.tar"), OutputPolicy::Replace)
            .err()
            .unwrap();
        assert_matches!(err, ArchiveError::Io(e) if e.kind() == io::ErrorKind::NotFound);
    }

    #[test]
    fn excludes_the_staged_file_and_the_target_by_name_and_parent() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();
        let out = staged(dir.path(), "a.tar", OutputPolicy::Replace).unwrap();
        let temp_path = out.temp.path().to_path_buf();

        assert!(out.excluded.excludes(&dir.path().join("a.tar")));
        assert!(out.excluded.excludes(&temp_path));
        assert!(!out.excluded.excludes(&sub.join("a.tar")));
        assert!(!out.excluded.excludes(&dir.path().join("b.tar")));
        assert!(!ExcludedOutput::none().excludes(&dir.path().join("a.tar")));
    }

    #[cfg(unix)]
    mod unix {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::fs::symlink;

        use super::*;

        fn mode(path: &Path) -> u32 {
            fs::metadata(path).unwrap().permissions().mode() & 0o7777
        }

        #[test]
        fn replace_keeps_a_narrower_mode_and_never_widens_while_writing() {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("a.tar");
            fs::write(&target, b"old").unwrap();
            fs::set_permissions(&target, Permissions::from_mode(0o600)).unwrap();

            let out = staged(dir.path(), "a.tar", OutputPolicy::Replace).unwrap();
            assert_eq!(mode(out.temp.path()), 0o600);
            write_and_commit(out, b"new").unwrap();

            assert_eq!(mode(&target), 0o600);
            assert_eq!(fs::read(&target).unwrap(), b"new");
        }

        #[test]
        fn replace_drops_setuid_setgid_and_sticky_bits() {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("a.tar");
            fs::write(&target, b"old").unwrap();
            fs::set_permissions(&target, Permissions::from_mode(0o4755)).unwrap();

            write_and_commit(
                staged(dir.path(), "a.tar", OutputPolicy::Replace).unwrap(),
                b"new",
            )
            .unwrap();

            assert_eq!(mode(&target), 0o755);
        }

        #[test]
        fn a_new_file_gets_the_umask_filtered_default_mode() {
            let dir = tempfile::tempdir().unwrap();
            let reference = dir.path().join("reference");
            fs::File::create(&reference).unwrap();

            write_and_commit(
                staged(dir.path(), "a.tar", OutputPolicy::CreateNew).unwrap(),
                b"new",
            )
            .unwrap();

            assert_eq!(mode(&dir.path().join("a.tar")), mode(&reference));
        }

        #[test]
        fn a_dangling_symlink_is_replaced_under_replace_and_refused_under_create_new() {
            let dir = tempfile::tempdir().unwrap();
            let link = dir.path().join("link.tar");
            symlink(dir.path().join("missing"), &link).unwrap();

            let err = staged(dir.path(), "link.tar", OutputPolicy::CreateNew)
                .err()
                .unwrap();
            assert_matches!(err, ArchiveError::OutputExists { .. });

            write_and_commit(
                staged(dir.path(), "link.tar", OutputPolicy::Replace).unwrap(),
                b"new",
            )
            .unwrap();
            assert!(!fs::symlink_metadata(&link).unwrap().is_symlink());
        }

        #[test]
        fn a_symlink_to_a_directory_is_refused() {
            let dir = tempfile::tempdir().unwrap();
            fs::create_dir(dir.path().join("d")).unwrap();
            symlink(dir.path().join("d"), dir.path().join("link.tar")).unwrap();
            for policy in [OutputPolicy::CreateNew, OutputPolicy::Replace] {
                let err = staged(dir.path(), "link.tar", policy).err().unwrap();
                assert_matches!(
                    err,
                    ArchiveError::InvalidConfiguration {
                        problem: ConfigProblem::NotSupported,
                        ..
                    }
                );
            }
        }

        #[test]
        fn the_reservation_fallback_publishes_and_refuses_an_existing_file() {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("a.tar");
            let temp = Builder::new().tempfile_in(dir.path()).unwrap();
            publish_through_reservation(temp, &target, io::Error::other("no links")).unwrap();
            assert!(target.exists());

            let temp = Builder::new().tempfile_in(dir.path()).unwrap();
            let err = publish_through_reservation(temp, &target, io::Error::other("no links"))
                .unwrap_err();
            assert_matches!(err, ArchiveError::OutputExists { .. });
        }

        #[test]
        fn a_reservation_is_released_only_while_it_is_still_the_reserved_file() {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("a.tar");

            let reservation = File::create_new(&target).unwrap();
            assert!(release_reservation(&reservation, &target));
            assert!(!target.exists());

            let reservation = File::create_new(&target).unwrap();
            fs::remove_file(&target).unwrap();
            fs::write(&target, b"someone else's").unwrap();
            assert!(!release_reservation(&reservation, &target));
            assert_eq!(fs::read(&target).unwrap(), b"someone else's");
        }
    }
}
