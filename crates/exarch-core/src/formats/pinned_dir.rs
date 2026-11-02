//! Directory handles that pin every write below the destination.
//!
//! Extraction used to check a path with `lstat` and then act on the same path,
//! so a local attacker who could write inside the destination could swap a
//! vetted component for a symlink between the check and the act. A
//! [`VettedDir`] closes that window: it is an open directory descriptor, and
//! every open, create, rename, unlink, symlink and readlink below the
//! destination is relative to such a descriptor. Moving a vetted directory
//! aside or replacing its name with a symlink cannot redirect an operation that
//! already holds the descriptor.
//!
//! A [`VettedDir`] has no public constructor. It comes from [`PinnedRoot`]
//! (the destination, opened once per extraction) or from the
//! [`DirWalker`](super::dir_walker::DirWalker), which descends one component at
//! a time with `NOFOLLOW` and never keeps more than two descriptors open. A
//! [`Leaf`] is exactly one normal path component, so no separator reaches an
//! `*at` call.
//!
//! # Directory handles
//!
//! Directories are opened with `O_PATH` on Linux and Android and `O_SEARCH` on
//! Apple platforms (falling back to `O_RDONLY` if the kernel rejects it), so a
//! directory with mode `0o311` or a destination with mode `0o733` stays usable:
//! the path-based calls this replaces needed only search and write permission.
//! Other Unix targets and WASI have no such mode and open directories
//! read-only, so there a directory without read permission fails with
//! `EACCES` where path-based code worked. None of them is a shipped target for
//! the bindings or the CLI release builds.
//!
//! # Residual risks
//!
//! - A vetted directory renamed out of the destination still receives writes
//!   made through its descriptor. Only `O_EXCL` creates and renames within that
//!   directory happen there, and moving it needs write access to a directory
//!   the attacker already controls.
//! - The destination itself is opened by path once. Swapping it between the
//!   caller's `canonicalize` and the open needs write access to the
//!   destination's parent, which is outside the threat model of an attacker
//!   confined to the destination. Closing the gap would compare the opened
//!   descriptor's device and inode with a stat taken at canonicalize time (the
//!   CLI's `verify_destination_unchanged` does this) or verify the descriptor's
//!   path; both are left to the follow-up that covers the CLI as well.
//! - Windows has no descriptor backend here: [`VettedDir`] stores the path and
//!   joins names onto it, which is the previous behaviour.

use std::ffi::OsStr;
use std::ffi::OsString;
use std::path::Component;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use crate::ArchiveError;
use crate::Result;
use crate::security::fs_view::Occupant;
use crate::types::DestDir;

pub use imp::VettedDir;

/// Exactly one normal path component: a name inside a [`VettedDir`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Leaf<'a>(&'a OsStr);

impl<'a> Leaf<'a> {
    /// Splits a relative path into its parent and its final name.
    ///
    /// # Errors
    ///
    /// Returns `PathTraversal` when the final component is not a normal name
    /// (`..`, a root, a prefix, or an empty path).
    pub(crate) fn split(rel: &'a Path) -> Result<(&'a Path, Self)> {
        match (rel.parent(), rel.components().next_back()) {
            (Some(parent), Some(Component::Normal(name))) => Ok((parent, Self(name))),
            _ => Err(ArchiveError::PathTraversal {
                path: rel.to_path_buf(),
            }),
        }
    }

    /// The leaf of a path component, or `None` unless it is a normal name.
    pub(super) const fn from_component(component: Component<'a>) -> Option<Self> {
        match component {
            Component::Normal(name) => Some(Self(name)),
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => None,
        }
    }

    pub(crate) const fn as_os_str(self) -> &'a OsStr {
        self.0
    }
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A generated temp-file name that is a single component by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TempLeaf(OsString);

impl TempLeaf {
    /// The next candidate name, independent of the entry's own name so it stays
    /// within the filesystem's name-length limit however long that name is.
    pub(crate) fn next() -> Self {
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        Self(OsString::from(format!(
            ".exarch-tmp-{}-{counter}",
            std::process::id()
        )))
    }

    /// A test-chosen name; `name` must not contain a separator.
    #[cfg(test)]
    pub(crate) fn named(name: &str) -> Self {
        assert!(
            !name.contains(['/', '\\']),
            "not a single component: {name}"
        );
        Self(OsString::from(name))
    }

    /// Borrows the name as a [`Leaf`].
    pub(crate) fn as_leaf(&self) -> Leaf<'_> {
        Leaf(&self.0)
    }
}

/// What a path-based `lstat` found, as an [`Occupant`].
pub fn occupant_of(file_type: std::fs::FileType) -> Occupant {
    if file_type.is_dir() {
        Occupant::Directory
    } else if file_type.is_symlink() {
        Occupant::Symlink
    } else {
        Occupant::File
    }
}

/// The extraction destination, with its directory opened once.
#[derive(Debug)]
pub struct PinnedRoot {
    dest: DestDir,
    dir: VettedDir,
}

impl PinnedRoot {
    /// Opens the (already canonical) destination.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the directory cannot be opened.
    pub(crate) fn open(dest: DestDir) -> Result<Self> {
        let dir = VettedDir::open_path(dest.as_path())?;
        Ok(Self { dest, dir })
    }

    pub(crate) const fn dest(&self) -> &DestDir {
        &self.dest
    }

    pub(super) const fn dir(&self) -> &VettedDir {
        &self.dir
    }

    /// Wraps the directory at `path` for tests that exercise a write primitive
    /// without an extraction.
    #[cfg(all(test, unix))]
    pub(crate) fn open_for_test(path: &Path) -> Result<Self> {
        Self::open(DestDir::new(path.to_path_buf())?)
    }
}

/// Proof that every path validated with it is written through [`DirWalker`]
/// from a [`PinnedRoot`]'s descriptor, so the walker's per-component vetting
/// at write time stands in for the validator's path-based parent probe.
///
/// Only [`PinnedRoot::backs_parent_probe`] mints it.
///
/// [`DirWalker`]: crate::formats::dir_walker::DirWalker
#[cfg(any(unix, target_os = "wasi"))]
#[derive(Debug, Clone, Copy)]
pub struct WalkerBacked(());

#[cfg(any(unix, target_os = "wasi"))]
impl PinnedRoot {
    /// The proof that this root's writes are vetted by the walker.
    ///
    /// The holder must write every path it validates with the proof through
    /// `DirWalker::ensure_parent` or `ensure_dir` on this root.
    #[expect(clippy::unused_self, reason = "binds the proof to a root by signature")]
    pub(crate) const fn backs_parent_probe(&self) -> WalkerBacked {
        WalkerBacked(())
    }
}

#[cfg(any(unix, target_os = "wasi"))]
mod imp {
    use std::fs::File;
    use std::io;
    use std::os::fd::OwnedFd;
    use std::path::Path;

    use rustix::fs::AtFlags;
    use rustix::fs::FileType;
    use rustix::fs::Mode;
    use rustix::fs::OFlags;
    use rustix::io::Errno;

    use super::Leaf;
    use crate::security::fs_view::Occupant;
    use crate::security::permissions::SanitizedMode;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    const DIR_ACCESS: OFlags = OFlags::PATH;
    #[cfg(target_vendor = "apple")]
    const DIR_ACCESS: OFlags = OFlags::from_bits_retain(libc::O_SEARCH.cast_unsigned());
    #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
    const DIR_ACCESS: OFlags = OFlags::RDONLY;

    /// Opens a directory without following a symlink, with the platform's
    /// permission-light access mode.
    fn open_directory(open: impl Fn(OFlags) -> rustix::io::Result<OwnedFd>) -> io::Result<OwnedFd> {
        let base = OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let opened = open(base | DIR_ACCESS);
        // Older macOS kernels may reject `O_SEARCH` with `EINVAL`.
        #[cfg(target_vendor = "apple")]
        let opened = match opened {
            Err(e) if e == Errno::INVAL => open(base | OFlags::RDONLY),
            other => other,
        };
        Ok(opened?)
    }

    /// An open directory below the destination.
    #[derive(Debug)]
    pub struct VettedDir(OwnedFd);

    impl VettedDir {
        /// Opens `path`, which the caller has canonicalized.
        #[cfg(unix)]
        pub(super) fn open_path(path: &Path) -> io::Result<Self> {
            open_directory(|flags| rustix::fs::open(path, flags, Mode::empty())).map(Self)
        }

        /// Opens `path` through std, so nothing relies on `AT_FDCWD`, which
        /// WASI has no equivalent of.
        #[cfg(target_os = "wasi")]
        pub(super) fn open_path(path: &Path) -> io::Result<Self> {
            File::open(path).map(|dir| Self(OwnedFd::from(dir)))
        }

        /// Another handle to the same directory, opened through `.` because
        /// `dup` is unsupported on WASI.
        pub(crate) fn reopen(&self) -> io::Result<Self> {
            open_directory(|flags| rustix::fs::openat(&self.0, ".", flags, Mode::empty())).map(Self)
        }

        /// Opens the subdirectory `name`; a symlink or a file there is an
        /// error.
        pub(crate) fn open_dir(&self, name: Leaf<'_>) -> io::Result<Self> {
            open_directory(|flags| {
                rustix::fs::openat(&self.0, name.as_os_str(), flags, Mode::empty())
            })
            .map(Self)
        }

        /// Creates the subdirectory `name`, honouring the umask like
        /// `fs::create_dir`.
        pub(crate) fn make_dir(&self, name: Leaf<'_>) -> io::Result<()> {
            Ok(rustix::fs::mkdirat(
                &self.0,
                name.as_os_str(),
                Mode::from_bits_truncate(0o777),
            )?)
        }

        /// What `name` is, without following a symlink; `None` if it is absent.
        pub(crate) fn probe(&self, name: Leaf<'_>) -> io::Result<Option<Occupant>> {
            match rustix::fs::statat(&self.0, name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => Ok(Some(match FileType::from_raw_mode(stat.st_mode) {
                    FileType::Directory => Occupant::Directory,
                    FileType::Symlink => Occupant::Symlink,
                    _ => Occupant::File,
                })),
                Err(e) if e == Errno::NOENT => Ok(None),
                Err(e) => Err(e.into()),
            }
        }

        /// Creates `name` exclusively, never following a symlink at it.
        ///
        /// With `mode`, the file is created owner-only and then set to exactly
        /// `mode` through the open descriptor (`fchmod`), so the umask cannot
        /// reduce it and no path is resolved again.
        pub(crate) fn create_new(
            &self,
            name: Leaf<'_>,
            mode: Option<SanitizedMode>,
        ) -> io::Result<File> {
            let creation =
                mode.map_or(Mode::from_bits_truncate(0o666), |_| Mode::RUSR | Mode::WUSR);
            let fd = rustix::fs::openat(
                &self.0,
                name.as_os_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                creation,
            )?;
            let file = File::from(fd);
            #[cfg(unix)]
            if let Some(m) = mode {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(m.as_u32()))?;
            }
            Ok(file)
        }

        /// Opens `name` for reading without following a symlink and without
        /// blocking on a FIFO that was swapped in; the caller checks the file
        /// type through the returned handle.
        pub(crate) fn open_read(&self, name: Leaf<'_>) -> io::Result<File> {
            let fd = rustix::fs::openat(
                &self.0,
                name.as_os_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            Ok(File::from(fd))
        }

        /// Renames `from` over `to`, both in this directory.
        pub(crate) fn rename_within(&self, from: Leaf<'_>, to: Leaf<'_>) -> io::Result<()> {
            Ok(rustix::fs::renameat(
                &self.0,
                from.as_os_str(),
                &self.0,
                to.as_os_str(),
            )?)
        }

        /// Unlinks the non-directory `name`.
        pub(crate) fn remove_file(&self, name: Leaf<'_>) -> io::Result<()> {
            Ok(rustix::fs::unlinkat(
                &self.0,
                name.as_os_str(),
                AtFlags::empty(),
            )?)
        }

        /// Reads the target of the symlink `name`.
        #[cfg(unix)]
        pub(crate) fn read_link(&self, name: Leaf<'_>) -> io::Result<std::path::PathBuf> {
            use std::os::unix::ffi::OsStringExt;

            let target = rustix::fs::readlinkat(&self.0, name.as_os_str(), Vec::new())?;
            Ok(std::path::PathBuf::from(std::ffi::OsString::from_vec(
                target.into_bytes(),
            )))
        }

        /// Creates the symlink `name` pointing at `target`.
        #[cfg(unix)]
        pub(crate) fn symlink(&self, target: &Path, name: Leaf<'_>) -> io::Result<()> {
            Ok(rustix::fs::symlinkat(target, &self.0, name.as_os_str())?)
        }
    }
}

#[cfg(not(any(unix, target_os = "wasi")))]
mod imp {
    use std::fs;
    use std::fs::File;
    use std::io;
    use std::path::Path;
    use std::path::PathBuf;

    use super::Leaf;
    use super::occupant_of;
    use crate::security::fs_view::Occupant;
    use crate::security::permissions::SanitizedMode;

    /// A directory below the destination, by path.
    // TODO(#839): path-based on Windows; residual component-swap TOCTOU.
    #[derive(Debug)]
    pub struct VettedDir(PathBuf);

    impl VettedDir {
        pub(super) fn open_path(path: &Path) -> io::Result<Self> {
            Ok(Self(path.to_path_buf()))
        }

        pub(crate) fn reopen(&self) -> io::Result<Self> {
            Ok(Self(self.0.clone()))
        }

        pub(crate) fn open_dir(&self, name: Leaf<'_>) -> io::Result<Self> {
            let path = self.0.join(name.as_os_str());
            if fs::symlink_metadata(&path)?.is_dir() {
                Ok(Self(path))
            } else {
                Err(io::Error::from(io::ErrorKind::NotADirectory))
            }
        }

        pub(crate) fn make_dir(&self, name: Leaf<'_>) -> io::Result<()> {
            fs::create_dir(self.0.join(name.as_os_str()))
        }

        pub(crate) fn probe(&self, name: Leaf<'_>) -> io::Result<Option<Occupant>> {
            match fs::symlink_metadata(self.0.join(name.as_os_str())) {
                Ok(meta) => Ok(Some(occupant_of(meta.file_type()))),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }

        pub(crate) fn create_new(
            &self,
            name: Leaf<'_>,
            _mode: Option<SanitizedMode>,
        ) -> io::Result<File> {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.0.join(name.as_os_str()))
        }

        pub(crate) fn open_read(&self, name: Leaf<'_>) -> io::Result<File> {
            File::open(self.0.join(name.as_os_str()))
        }

        pub(crate) fn rename_within(&self, from: Leaf<'_>, to: Leaf<'_>) -> io::Result<()> {
            fs::rename(self.0.join(from.as_os_str()), self.0.join(to.as_os_str()))
        }

        pub(crate) fn remove_file(&self, name: Leaf<'_>) -> io::Result<()> {
            fs::remove_file(self.0.join(name.as_os_str()))
        }
    }
}

/// RAII guard that removes a file from its directory when dropped, unless
/// [`persist`](Self::persist) was called first.
///
/// Shared between TAR's hardlink-content copy, the TAR/ZIP output path and 7z's
/// temp-file-then-rename write path so a fallible step between file creation
/// and the operation's success point does not leave a partial artifact behind.
/// The removal is relative to the directory the file was created in.
pub struct TempFileGuard<'d> {
    dir: &'d VettedDir,
    name: OsString,
    should_cleanup: bool,
}

impl<'d> TempFileGuard<'d> {
    /// Removes `name` from `dir` on drop.
    pub(crate) fn new(dir: &'d VettedDir, name: Leaf<'_>) -> Self {
        Self {
            dir,
            name: name.as_os_str().to_os_string(),
            should_cleanup: true,
        }
    }

    /// Removes the generated temp file `name` from `dir` on drop.
    pub(crate) fn for_temp(dir: &'d VettedDir, name: TempLeaf) -> Self {
        Self {
            dir,
            name: name.0,
            should_cleanup: true,
        }
    }

    /// Marks the file as successfully processed, preventing cleanup on drop.
    pub(crate) fn persist(mut self) {
        self.should_cleanup = false;
    }
}

impl Drop for TempFileGuard<'_> {
    fn drop(&mut self) {
        if self.should_cleanup {
            let _ = self.dir.remove_file(Leaf(&self.name));
        }
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::assert_matches;
    use std::fs;
    use std::io;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    fn leaf(name: &str) -> Leaf<'_> {
        Leaf::from_component(Path::new(name).components().next().unwrap()).unwrap()
    }

    fn pinned(temp: &TempDir) -> VettedDir {
        PinnedRoot::open_for_test(temp.path())
            .unwrap()
            .dir()
            .reopen()
            .unwrap()
    }

    /// Returns a handle on `base/a` after `a` was moved to `a_moved` and a
    /// symlink `a -> outside` was planted in its place.
    fn swapped(temp: &TempDir) -> (VettedDir, std::path::PathBuf) {
        let base = temp.path().join("base");
        let outside = temp.path().join("outside");
        fs::create_dir_all(base.join("a")).unwrap();
        fs::create_dir(&outside).unwrap();
        let root = pinned_at(&base);
        let a = root.open_dir(leaf("a")).unwrap();
        fs::rename(base.join("a"), base.join("a_moved")).unwrap();
        symlink(&outside, base.join("a")).unwrap();
        (a, outside)
    }

    fn pinned_at(path: &Path) -> VettedDir {
        PinnedRoot::open_for_test(path)
            .unwrap()
            .dir()
            .reopen()
            .unwrap()
    }

    #[test]
    fn create_new_after_a_swap_lands_in_the_moved_directory() {
        let temp = TempDir::new().unwrap();
        let (a, outside) = swapped(&temp);

        let mut file = a.create_new(leaf("f"), None).unwrap();
        file.write_all(b"x").unwrap();

        assert!(temp.path().join("base/a_moved/f").is_file());
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    }

    #[test]
    fn guard_after_a_swap_removes_from_the_moved_directory() {
        let temp = TempDir::new().unwrap();
        let (a, outside) = swapped(&temp);
        fs::write(outside.join("f"), b"keep").unwrap();
        a.create_new(leaf("f"), None).unwrap();

        drop(TempFileGuard::new(&a, leaf("f")));

        assert!(!temp.path().join("base/a_moved/f").exists());
        assert_eq!(fs::read(outside.join("f")).unwrap(), b"keep");
    }

    #[test]
    fn symlink_and_rename_after_a_swap_stay_in_the_moved_directory() {
        let temp = TempDir::new().unwrap();
        let (a, outside) = swapped(&temp);

        a.create_new(leaf("tmp"), None).unwrap();
        a.rename_within(leaf("tmp"), leaf("final")).unwrap();
        a.symlink(Path::new("final"), leaf("alias")).unwrap();

        assert!(temp.path().join("base/a_moved/final").is_file());
        assert!(
            fs::symlink_metadata(temp.path().join("base/a_moved/alias"))
                .unwrap()
                .is_symlink()
        );
        assert_eq!(a.read_link(leaf("alias")).unwrap(), Path::new("final"));
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    }

    #[test]
    fn open_dir_refuses_a_symlink_and_probe_names_it() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("real")).unwrap();
        symlink("real", temp.path().join("alias")).unwrap();
        let dir = pinned(&temp);

        assert!(dir.open_dir(leaf("alias")).is_err());
        assert_eq!(dir.probe(leaf("alias")).unwrap(), Some(Occupant::Symlink));
        assert_eq!(dir.probe(leaf("real")).unwrap(), Some(Occupant::Directory));
        assert_eq!(dir.probe(leaf("absent")).unwrap(), None);
    }

    #[test]
    fn create_new_applies_the_exact_mode_and_refuses_an_existing_name() {
        let temp = TempDir::new().unwrap();
        let dir = pinned(&temp);
        let config = crate::SecurityConfig::default().validate().unwrap();
        let mode = crate::security::permissions::sanitize_permissions(0o640, &config);

        dir.create_new(leaf("f"), Some(mode)).unwrap();

        let actual = fs::metadata(temp.path().join("f"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(actual & 0o7777, 0o640);
        let err = dir.create_new(leaf("f"), None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn leaf_split_accepts_only_a_normal_final_component() {
        let (parent, name) = Leaf::split(Path::new("a/b/c.txt")).unwrap();
        assert_eq!(parent, Path::new("a/b"));
        assert_eq!(name.as_os_str(), "c.txt");
        let (parent, name) = Leaf::split(Path::new("top")).unwrap();
        assert_eq!(parent, Path::new(""));
        assert_eq!(name.as_os_str(), "top");

        for bad in ["", "/", "..", "a/..", "../x/.."] {
            assert_matches!(
                Leaf::split(Path::new(bad)),
                Err(ArchiveError::PathTraversal { .. }),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn works_in_a_directory_without_read_permission() {
        let temp = TempDir::new().unwrap();
        let locked = temp.path().join("locked");
        fs::create_dir(&locked).unwrap();
        fs::create_dir(locked.join("sub")).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o311)).unwrap();
        if fs::read_dir(&locked).is_ok() {
            // Root ignores the mode, so the check below would prove nothing.
            return;
        }

        let result = (|| -> io::Result<()> {
            let dir = VettedDir::open_path(&locked)?;
            dir.make_dir(leaf("made"))?;
            dir.open_dir(leaf("sub"))?;
            dir.create_new(leaf("f"), None)?;
            assert_eq!(dir.probe(leaf("f"))?, Some(Occupant::File));
            Ok(())
        })();

        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        result.unwrap();
        assert!(locked.join("made").is_dir());
        assert!(locked.join("f").is_file());
    }

    #[test]
    fn destination_without_read_permission_is_usable() {
        for mode in [0o733, 0o333] {
            let temp = TempDir::new().unwrap();
            let dest = temp.path().join("dest");
            fs::create_dir(&dest).unwrap();
            fs::set_permissions(&dest, fs::Permissions::from_mode(mode)).unwrap();

            let result = PinnedRoot::open_for_test(&dest).and_then(|root| {
                let dir = root.dir().reopen()?;
                dir.make_dir(leaf("d"))?;
                dir.create_new(leaf("f"), None)?;
                Ok(())
            });

            fs::set_permissions(&dest, fs::Permissions::from_mode(0o755)).unwrap();
            result.unwrap();
            assert!(dest.join("d").is_dir() && dest.join("f").is_file());
        }
    }
}
