//! The destination directory of an atomic run, held open from the first read
//! of its identity until the run returns.
//!
//! Filesystems that reuse an inode number at once (ext4, tmpfs) can give a
//! directory recreated after an `rmdir` the number of the one it replaced, so
//! an identity read twice cannot tell the two apart. An inode that is held
//! open cannot be freed, so its number cannot be reissued: while a
//! [`DestinationHold`] lives, a different directory at the destination's name
//! always compares as a different identity.
//!
//! The handle stays open across the publishing rename, and under
//! `AtomicReplace` across the move of the destination to its backup and the
//! removal of that backup. Local filesystems allow all three; a network volume
//! (smbfs, nfs) may refuse one with `EBUSY` or `EACCES`, which has not been
//! measured.

use std::io;

#[cfg(unix)]
use crate::formats::common::errno_is;
use crate::formats::pinned_dir::EntryStatus;
use crate::formats::pinned_dir::Leaf;
use crate::formats::pinned_dir::VettedDir;
use crate::security::fs_view::Occupant;

/// A search-only handle on the destination directory that is kept open for
/// the run, and never read.
#[cfg(unix)]
#[derive(Debug)]
pub(super) struct DestinationHold(
    #[allow(dead_code, reason = "held open for its lifetime and never read")] VettedDir,
);

/// Only Unix reuses an inode number that quickly, and only Unix holds the
/// destination.
#[cfg(not(unix))]
#[derive(Debug)]
#[allow(
    clippy::empty_enums,
    reason = "uninhabited on purpose, stable has no `!`"
)]
pub(super) enum DestinationHold {}

/// What is at a destination's name.
#[derive(Debug)]
pub(super) enum Destination {
    /// Nothing.
    Absent,
    /// A symlink or a file, which is never the directory of an atomic run.
    Other(EntryStatus),
    /// A directory. `hold` is there when it could be opened without read
    /// access; without one the status was read by name.
    Directory {
        status: EntryStatus,
        hold: Option<DestinationHold>,
    },
}

impl Destination {
    /// Looks at the entry `name` of `pin`, holding it when it is a directory.
    ///
    /// The status of a held directory is read from the handle, so it is the
    /// status of the directory that stays held. An entry that is absent, is
    /// not a directory, or cannot be opened for lack of search permission
    /// (macOS) is classified by name and held by nothing.
    ///
    /// # Errors
    ///
    /// The I/O error of a lookup that is neither of those.
    pub(super) fn open(pin: &VettedDir, name: Leaf<'_>) -> io::Result<Self> {
        #[cfg(unix)]
        if let Some((hold, status)) = DestinationHold::open(pin, name)? {
            return Ok(Self::Directory {
                status,
                hold: Some(hold),
            });
        }
        Self::by_name(pin, name)
    }

    fn by_name(pin: &VettedDir, name: Leaf<'_>) -> io::Result<Self> {
        Ok(match pin.status(name)? {
            None => Self::Absent,
            Some(status) if status.occupant == Occupant::Directory => {
                Self::Directory { status, hold: None }
            }
            Some(status) => Self::Other(status),
        })
    }
}

#[cfg(unix)]
impl DestinationHold {
    /// Opens the directory `name` of `pin` and reads its status from the
    /// handle. `None` when it cannot be held: it is absent, a symlink or a
    /// file, the caller may not search it, or the handle cannot be inspected.
    fn open(pin: &VettedDir, name: Leaf<'_>) -> io::Result<Option<(Self, EntryStatus)>> {
        let dir = match pin.open_dir(name) {
            Ok(dir) => dir,
            Err(e) if is_not_held(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        Ok(dir.own_status().ok().map(|status| (Self(dir), status)))
    }
}

/// The failures of opening a destination that only mean it is not a directory
/// that can be held.
#[cfg(unix)]
fn is_not_held(error: &io::Error) -> bool {
    use rustix::io::Errno;

    errno_is(
        error,
        &[Errno::NOENT, Errno::NOTDIR, Errno::LOOP, Errno::ACCESS],
    )
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::assert_matches;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;

    use super::*;
    use crate::formats::file_identity::IdentityCheck;
    use crate::formats::pinned_dir::support::leaf;
    use crate::formats::pinned_dir::support::pinned_at;

    /// Whether the owner of `path`, a directory this process just made, is
    /// root.
    fn is_root(path: &std::path::Path) -> bool {
        std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(path).unwrap()) == 0
    }

    fn held_directory(pin: &VettedDir, name: &str) -> (EntryStatus, DestinationHold) {
        match Destination::open(pin, leaf(name)).unwrap() {
            Destination::Directory {
                status,
                hold: Some(hold),
            } => (status, hold),
            other => panic!("expected a held directory, got {other:?}"),
        }
    }

    #[test]
    fn a_directory_recreated_under_the_held_name_is_a_different_directory() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("d")).unwrap();
        let pin = pinned_at(temp.path());
        let (status, _hold) = held_directory(&pin, "d");

        std::fs::remove_dir(temp.path().join("d")).unwrap();
        std::fs::create_dir(temp.path().join("d")).unwrap();

        let recreated = pin.status(leaf("d")).unwrap().unwrap();
        assert_eq!(
            recreated.identity.check(status.identity),
            IdentityCheck::Different
        );
    }

    #[test]
    fn the_status_of_a_held_directory_is_the_one_read_by_name() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("d");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o751)).unwrap();
        let pin = pinned_at(temp.path());

        let (status, _hold) = held_directory(&pin, "d");

        let by_name = pin.status(leaf("d")).unwrap().unwrap();
        assert_eq!(status.identity.check(by_name.identity), IdentityCheck::Same);
        assert_eq!(status.mode.bits(), 0o751);
    }

    #[test]
    fn a_directory_without_any_access_is_still_a_directory_and_held_where_the_handle_needs_none() {
        let temp = tempfile::tempdir().unwrap();
        let locked = temp.path().join("d");
        std::fs::create_dir(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let pin = pinned_at(temp.path());

        let found = Destination::open(&pin, leaf("d")).unwrap();

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        let Destination::Directory { hold, .. } = found else {
            panic!("expected a directory, got {found:?}");
        };
        if cfg!(any(target_os = "linux", target_os = "android")) {
            assert!(hold.is_some());
        } else if cfg!(target_os = "macos") && !is_root(temp.path()) {
            assert!(hold.is_none(), "no search permission, so no handle");
        }
    }

    #[test]
    fn what_is_not_a_directory_is_classified_and_never_held() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("f"), b"x").unwrap();
        symlink("f", temp.path().join("l")).unwrap();
        let pin = pinned_at(temp.path());

        assert_matches!(
            Destination::open(&pin, leaf("absent")).unwrap(),
            Destination::Absent
        );
        for name in ["f", "l"] {
            let Destination::Other(status) = Destination::open(&pin, leaf(name)).unwrap() else {
                panic!("{name} is not a directory");
            };
            assert_ne!(status.occupant, Occupant::Directory, "{name}");
        }
    }
}
