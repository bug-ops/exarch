//! A destination's parent directory, pinned for the destination swap.
//!
//! Replacing a destination renames it aside, renames the staged tree into its
//! place and removes the backup: three renames and a reservation-clearing
//! `remove_dir`, all in one parent directory. Resolving them by path walks the
//! parent's components again on every call, so replacing an intermediate
//! component with a symlink between two calls would redirect the swap. A
//! [`PinnedParent`] opens the parent once and performs every operation relative
//! to that descriptor, which names an inode and not a path.
//!
//! [`PinnedParent::entry_status`] classifies the destination itself without
//! following it, which closes the final-component vector (a destination that is
//! a symlink or junction is refused instead of followed).
//!
//! On Windows, and on any target without descriptor-relative calls, the
//! operations are path-based and [`FileIdentity::Unknown`] is the only
//! identity: the intermediate-component window stays open there, and the
//! final-component check stays real (a reparse point is classified as a
//! symlink).

use std::ffi::OsString;
use std::io;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

/// One normal path component: no separator, never `.`, `..` or empty.
///
/// Every [`PinnedParent`] operation resolves its names relative to the pinned
/// directory, which is only sound for a single component: a name with a
/// separator or equal to `..` would make `renameat` leave the pinned directory.
/// The only constructor refuses anything else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryName(OsString);

impl EntryName {
    /// The final component of `path`, or `None` when `path` ends in `.`, `..`
    /// or a root, which have no usable final name.
    pub fn of(path: &Path) -> Option<Self> {
        let name = path.file_name()?;
        let mut components = Path::new(name).components();
        match (components.next(), components.next()) {
            (Some(Component::Normal(only)), None) if only == name => {
                Some(Self(name.to_os_string()))
            }
            _ => None,
        }
    }
}

impl AsRef<Path> for EntryName {
    fn as_ref(&self) -> &Path {
        Path::new(&self.0)
    }
}

/// What a directory entry is, without following it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestEntryKind {
    /// A directory, the only kind a replace may swap.
    Directory,
    /// A symlink (on Windows also a junction or any other reparse point),
    /// refused whatever it points at.
    Symlink,
    /// Neither a directory nor a symlink.
    Other,
}

#[cfg(any(unix, target_os = "wasi"))]
mod imp {
    use std::fs::File;
    use std::io;
    use std::path::Path;

    use rustix::fs::AtFlags;
    use rustix::fs::FileType;
    use rustix::fs::Mode;
    use rustix::fs::OFlags;

    use super::DestEntryKind;
    use super::EntryName;
    use super::FileIdentity;
    use crate::formats::file_identity::IdentityKey;

    /// A directory pinned by an open descriptor.
    ///
    /// Opening it needs read permission on the directory, a stricter
    /// requirement than the path-based calls it replaces, which needed search
    /// and write permission only. Linux's permission-free `O_PATH` has no
    /// portable equivalent.
    #[derive(Debug)]
    pub struct PinnedParent(File);

    impl PinnedParent {
        /// Opens `parent` and pins it. Fails closed if `parent` is a symlink at
        /// the moment of the call (Unix): the one path-based resolution left in
        /// a replace, microseconds wide after the caller's `canonicalize`.
        #[cfg(unix)]
        pub fn open(parent: &Path) -> io::Result<Self> {
            let fd = rustix::fs::open(
                parent,
                OFlags::RDONLY
                    | OFlags::DIRECTORY
                    | OFlags::CLOEXEC
                    | OFlags::NOFOLLOW
                    // A FIFO planted at `parent` can stall an `open` that
                    // waits for a writer before `O_DIRECTORY` rejects it.
                    | OFlags::NONBLOCK,
                Mode::empty(),
            )?;
            Ok(Self(File::from(fd)))
        }

        /// Opens `parent` through std, as WASI has no `AT_FDCWD`.
        #[cfg(target_os = "wasi")]
        pub fn open(parent: &Path) -> io::Result<Self> {
            File::open(parent).map(Self)
        }

        /// What the entry `name` is and which inode it is, in one `fstatat`.
        ///
        /// `statat` needs only search permission on the pinned directory,
        /// where opening the entry would also need read permission on it.
        pub fn entry_status(&self, name: &EntryName) -> io::Result<(DestEntryKind, FileIdentity)> {
            let stat = rustix::fs::statat(&self.0, &name.0, AtFlags::SYMLINK_NOFOLLOW)?;
            let kind = match FileType::from_raw_mode(stat.st_mode) {
                FileType::Directory => DestEntryKind::Directory,
                FileType::Symlink => DestEntryKind::Symlink,
                _ => DestEntryKind::Other,
            };
            Ok((kind, FileIdentity::Known(IdentityKey::of_stat(&stat)?)))
        }

        /// Renames `from` to `to`, both relative to the pinned directory.
        pub fn rename(&self, from: &EntryName, to: &EntryName) -> io::Result<()> {
            Ok(rustix::fs::renameat(&self.0, &from.0, &self.0, &to.0)?)
        }

        /// Removes the empty directory `name`.
        pub fn remove_dir(&self, name: &EntryName) -> io::Result<()> {
            Ok(rustix::fs::unlinkat(&self.0, &name.0, AtFlags::REMOVEDIR)?)
        }

        /// Opens the directory `name`, refusing a symlink, for
        /// [`current_path`].
        pub fn open_entry(&self, name: &EntryName) -> io::Result<File> {
            let fd = rustix::fs::openat(
                &self.0,
                &name.0,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )?;
            Ok(File::from(fd))
        }
    }

    /// Best effort: where the open directory `fd` is now, resolved from the
    /// descriptor and so unaffected by a redirect of any ancestor since it was
    /// opened. `None` where the platform has no fd-to-path facility here.
    #[cfg(target_os = "linux")]
    pub fn current_path(fd: &File) -> Option<std::path::PathBuf> {
        use std::os::fd::AsRawFd;
        std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).ok()
    }

    /// macOS: `fcntl(fd, F_GETPATH)`.
    #[cfg(target_os = "macos")]
    pub fn current_path(fd: &File) -> Option<std::path::PathBuf> {
        use std::os::unix::ffi::OsStrExt;
        rustix::fs::getpath(fd)
            .ok()
            .map(|c_path| std::path::PathBuf::from(std::ffi::OsStr::from_bytes(c_path.as_bytes())))
    }

    /// Other targets have no descriptor-to-path facility implemented here.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub fn current_path(_fd: &File) -> Option<std::path::PathBuf> {
        None
    }
}

#[cfg(not(any(unix, target_os = "wasi")))]
mod imp {
    use std::fs::File;
    use std::io;
    use std::path::Path;
    use std::path::PathBuf;

    use super::DestEntryKind;
    use super::EntryName;
    use super::FileIdentity;

    /// A directory named by path: nothing here is pinned.
    #[derive(Debug)]
    pub struct PinnedParent {
        parent: PathBuf,
    }

    impl PinnedParent {
        #[allow(clippy::unnecessary_wraps)] // the descriptor-based arm can fail
        pub fn open(parent: &Path) -> io::Result<Self> {
            Ok(Self {
                parent: parent.to_path_buf(),
            })
        }

        /// Classifies the entry `name`; its identity is always unknown.
        pub fn entry_status(&self, name: &EntryName) -> io::Result<(DestEntryKind, FileIdentity)> {
            let metadata = std::fs::symlink_metadata(self.parent.join(name))?;
            let kind = if is_reparse_point(&metadata) {
                DestEntryKind::Symlink
            } else if metadata.is_dir() {
                DestEntryKind::Directory
            } else {
                DestEntryKind::Other
            };
            Ok((kind, FileIdentity::Unknown))
        }

        #[expect(
            clippy::disallowed_methods,
            reason = "the descriptor-relative rename does not exist on this target"
        )]
        pub fn rename(&self, from: &EntryName, to: &EntryName) -> io::Result<()> {
            std::fs::rename(self.parent.join(from), self.parent.join(to))
        }

        #[expect(
            clippy::disallowed_methods,
            reason = "the descriptor-relative unlink does not exist on this target"
        )]
        pub fn remove_dir(&self, name: &EntryName) -> io::Result<()> {
            std::fs::remove_dir(self.parent.join(name))
        }

        pub fn open_entry(&self, name: &EntryName) -> io::Result<File> {
            File::open(self.parent.join(name))
        }
    }

    /// No descriptor-to-path facility: callers name the logical path instead.
    #[allow(clippy::missing_const_for_fn)]
    pub fn current_path(_fd: &File) -> Option<PathBuf> {
        None
    }

    /// Whether `metadata` carries `FILE_ATTRIBUTE_REPARSE_POINT`, whatever the
    /// tag: a junction needs no elevation to create and is a practical
    /// redirect.
    #[cfg(windows)]
    fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    #[cfg(not(windows))]
    fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
        metadata.file_type().is_symlink()
    }
}

pub use imp::PinnedParent;
pub use imp::current_path;

pub use crate::formats::file_identity::FileIdentity;
pub use crate::formats::file_identity::IdentityCheck;
pub use crate::formats::file_identity::identity_of;

/// The path of a surviving staging or backup entry, resolved from the entry
/// itself where the platform can and named logically otherwise.
pub fn surviving_path(pin: &PinnedParent, name: &EntryName, parent_display: &Path) -> PathBuf {
    pin.open_entry(name)
        .ok()
        .and_then(|fd| current_path(&fd))
        .unwrap_or_else(|| parent_display.join(name))
}

/// Why an I/O failure while inspecting an entry means "nothing there".
pub fn is_absent(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::assert_matches;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    use super::DestEntryKind;
    use super::EntryName;
    use super::FileIdentity;
    use super::IdentityCheck;
    use super::PinnedParent;
    use super::current_path;
    use crate::formats::file_identity::IdentityKey;

    fn entry(name: &str) -> EntryName {
        EntryName::of(Path::new(name)).expect("single component")
    }

    #[test]
    fn entry_name_accepts_only_one_normal_component() {
        assert_eq!(entry("dest").0, "dest");
        assert_eq!(EntryName::of(Path::new("a/dest")).unwrap().0, "dest");
        assert_eq!(EntryName::of(Path::new("a/dest/")).unwrap().0, "dest");
        for refused in ["..", ".", "/", "a/..", ""] {
            assert!(EntryName::of(Path::new(refused)).is_none(), "{refused:?}");
        }
    }

    #[test]
    fn rename_follows_the_pinned_inode_not_a_planted_symlink() {
        let root = tempfile::tempdir().unwrap();
        let real_parent = root.path().join("real_parent");
        std::fs::create_dir(&real_parent).unwrap();
        std::fs::write(real_parent.join("payload"), b"original").unwrap();

        let pin = PinnedParent::open(&real_parent).unwrap();

        let decoy = root.path().join("decoy");
        std::fs::create_dir(&decoy).unwrap();
        let moved_real = root.path().join("real_parent_moved");
        std::fs::rename(&real_parent, &moved_real).unwrap();
        symlink(&decoy, &real_parent).unwrap();

        pin.rename(&entry("payload"), &entry("payload_renamed"))
            .unwrap();

        assert!(moved_real.join("payload_renamed").exists());
        assert!(!decoy.join("payload_renamed").exists());
    }

    #[test]
    fn identity_changes_when_the_destination_is_swapped_for_a_new_directory() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        let dest = parent.join("dest");
        std::fs::create_dir(&dest).unwrap();

        let pin = PinnedParent::open(&parent).unwrap();
        let (kind, snapshot) = pin.entry_status(&entry("dest")).unwrap();
        assert_eq!(kind, DestEntryKind::Directory);

        std::fs::rename(&dest, parent.join("dest.old")).unwrap();
        std::fs::create_dir(&dest).unwrap();

        let (_, recheck) = pin.entry_status(&entry("dest")).unwrap();
        assert_eq!(recheck.check(snapshot), IdentityCheck::Different);
    }

    #[test]
    fn identity_of_an_untouched_entry_matches_itself() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("dest")).unwrap();
        let pin = PinnedParent::open(root.path()).unwrap();
        let (_, first) = pin.entry_status(&entry("dest")).unwrap();
        let (_, second) = pin.entry_status(&entry("dest")).unwrap();
        assert_matches!(first, FileIdentity::Known(_));
        assert_eq!(second.check(first), IdentityCheck::Same);
    }

    #[test]
    fn an_unknown_identity_never_compares_as_same_or_different() {
        let known = FileIdentity::Known(IdentityKey { dev: 1, ino: 2 });
        let other = FileIdentity::Known(IdentityKey { dev: 1, ino: 3 });
        assert_eq!(known.check(known), IdentityCheck::Same);
        assert_eq!(known.check(other), IdentityCheck::Different);
        for (a, b) in [
            (FileIdentity::Unknown, FileIdentity::Unknown),
            (FileIdentity::Unknown, known),
            (known, FileIdentity::Unknown),
        ] {
            assert_eq!(a.check(b), IdentityCheck::Unknown);
        }
    }

    #[test]
    fn entry_status_classifies_symlink_file_and_missing_entries() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        let real_dir = root.path().join("real_dir");
        std::fs::create_dir(&real_dir).unwrap();
        symlink(&real_dir, parent.join("link")).unwrap();
        std::fs::write(parent.join("file"), b"x").unwrap();

        let pin = PinnedParent::open(&parent).unwrap();
        assert_eq!(
            pin.entry_status(&entry("link")).unwrap().0,
            DestEntryKind::Symlink
        );
        assert_eq!(
            pin.entry_status(&entry("file")).unwrap().0,
            DestEntryKind::Other
        );
        assert_eq!(
            pin.entry_status(&entry("missing")).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[test]
    fn entry_status_needs_no_read_permission_on_the_entry() {
        let root = tempfile::tempdir().unwrap();
        let dest = root.path().join("dest");
        std::fs::create_dir(&dest).unwrap();
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o311)).unwrap();

        let pin = PinnedParent::open(root.path()).unwrap();
        let result = pin.entry_status(&entry("dest"));

        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755)).unwrap();
        result.expect("statat needs search permission on the parent only");
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn current_path_resolves_through_a_redirected_parent() {
        let root = tempfile::tempdir().unwrap();
        let real_parent = root.path().join("real_parent");
        std::fs::create_dir(&real_parent).unwrap();
        std::fs::create_dir(real_parent.join("entry")).unwrap();

        let pin = PinnedParent::open(&real_parent).unwrap();
        let fd = pin.open_entry(&entry("entry")).unwrap();

        let decoy = root.path().join("decoy");
        std::fs::create_dir(&decoy).unwrap();
        let moved = root.path().join("real_parent_moved");
        std::fs::rename(&real_parent, &moved).unwrap();
        symlink(&decoy, &real_parent).unwrap();

        let expected = moved.join("entry").canonicalize().unwrap();
        assert_eq!(current_path(&fd).unwrap(), expected);
    }

    #[test]
    fn open_entry_refuses_a_planted_symlink() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        let real_dir = root.path().join("real_dir");
        std::fs::create_dir(&real_dir).unwrap();
        symlink(&real_dir, parent.join("link")).unwrap();

        let pin = PinnedParent::open(&parent).unwrap();
        let err = pin.open_entry(&entry("link")).unwrap_err();
        let raw = err.raw_os_error();
        assert!(
            raw == Some(rustix::io::Errno::LOOP.raw_os_error())
                || raw == Some(rustix::io::Errno::NOTDIR.raw_os_error()),
            "NOFOLLOW must reject the symlink, got {err}"
        );
    }
}
