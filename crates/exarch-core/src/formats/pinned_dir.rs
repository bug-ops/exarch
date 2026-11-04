//! Directory handles that pin every write below the destination.
//!
//! Extraction used to check a path with `lstat` and then act on the same path,
//! so a local attacker who could write inside the destination could swap a
//! vetted component for a symlink between the check and the act. A
//! [`VettedDir`] closes that window: it is an open directory descriptor, and
//! every open, create, rename, unlink, symlink and readlink below the
//! destination is relative to such a descriptor (a directory handle on
//! Windows). Moving a vetted directory aside or replacing its name with a
//! symlink or junction cannot redirect an operation that already holds the
//! descriptor.
//!
//! A [`VettedDir`] has no public constructor. It comes from [`PinnedRoot`]
//! (the destination, opened once per extraction) or from the
//! [`DirWalker`](super::dir_walker::DirWalker), which descends one component at
//! a time without following links and never keeps more than two descriptors
//! open. A [`Leaf`] is exactly one normal path component, so no separator
//! reaches an `*at` call.
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
//! On Windows a [`VettedDir`] is a directory handle. Below the root, a junction
//! or symlink is opened as itself and refused. The root is opened the same
//! way, so a destination that is itself a reparse point (for example a volume
//! mounted at a folder) is refused rather than followed.
//! Names below it are opened with `NtCreateFile` and a `RootDirectory` handle,
//! and renames and deletes go through `NtSetInformationFile`, so no
//! operation resolves the directory's path again. The `nt` module holds the
//! only `unsafe` code. Every share mode is granted, so, as on Unix, a held
//! directory can be renamed and writes follow the handle.
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
//! - Over SMB the redirector rebuilds a relative open as a full path, so the
//!   server resolves the names. Third-party filesystem drivers are unverified.
//! - Only NTFS is exercised in CI; `ReFS` and Dev Drive are untested.
//! - Following a pre-existing symlink under `ContainedOnly` stays path-based
//!   through `classify_link` on Windows. On Unix it is resolved with
//!   `readlinkat` and `openat` on the held handles instead.

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

/// The one rule that maps a file type onto an [`Occupant`].
const fn occupant(is_dir: bool, is_symlink: bool) -> Occupant {
    if is_dir {
        Occupant::Directory
    } else if is_symlink {
        Occupant::Symlink
    } else {
        Occupant::File
    }
}

/// What a path-based `lstat` found.
impl From<std::fs::FileType> for Occupant {
    fn from(file_type: std::fs::FileType) -> Self {
        occupant(file_type.is_dir(), file_type.is_symlink())
    }
}

/// What a descriptor-relative `fstatat` found.
#[cfg(any(unix, target_os = "wasi"))]
impl From<rustix::fs::FileType> for Occupant {
    fn from(file_type: rustix::fs::FileType) -> Self {
        occupant(
            file_type == rustix::fs::FileType::Directory,
            file_type == rustix::fs::FileType::Symlink,
        )
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
    #[cfg(test)]
    pub(crate) fn open_for_test(path: &Path) -> Result<Self> {
        Self::open(DestDir::new(path.to_path_buf())?)
    }
}

/// Proof that every path validated with it is written through [`DirWalker`]
/// from a [`PinnedRoot`]'s descriptor, so the walker's per-component vetting
/// at write time stands in for the validator's path-based parent probe.
///
/// Only [`PinnedRoot::backs_parent_probe`] mints it. It borrows the root, so a
/// proof cannot outlive or be reused for another root, and it is not `Copy`.
///
/// [`DirWalker`]: crate::formats::dir_walker::DirWalker
#[cfg(any(unix, target_os = "wasi"))]
#[derive(Debug)]
pub struct WalkerBacked<'r>(
    #[expect(dead_code, reason = "ties the proof to its root")] &'r PinnedRoot,
);

#[cfg(any(unix, target_os = "wasi"))]
impl PinnedRoot {
    /// The proof that this root's writes are vetted by the walker.
    ///
    /// The holder must write every path it validates with the proof through
    /// `DirWalker::ensure_parent` or `ensure_dir` on this root.
    pub(crate) const fn backs_parent_probe(&self) -> WalkerBacked<'_> {
        WalkerBacked(self)
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
                Ok(stat) => Ok(Some(FileType::from_raw_mode(stat.st_mode).into())),
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

#[cfg(windows)]
#[allow(unsafe_code)] // the only unsafe code on Windows: NT directory-relative calls
mod nt;

#[cfg(windows)]
mod imp {
    use std::fs::File;
    use std::io;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsHandle;
    use std::path::Path;

    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;
    use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_WRITE;
    use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE;
    use windows_sys::Win32::Storage::FileSystem::FILE_TRAVERSE;
    use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;

    use super::Leaf;
    use super::nt;
    use super::nt::Disposition;
    use super::nt::Kind;
    use super::nt::Request;
    use crate::security::fs_view::Occupant;
    use crate::security::permissions::SanitizedMode;

    const DIR_ACCESS: u32 = FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;

    /// An open directory below the destination.
    ///
    /// Every operation is relative to this handle, so replacing or converting
    /// the directory's path cannot redirect it.
    #[derive(Debug)]
    pub struct VettedDir(File);

    impl VettedDir {
        fn into_dir(file: File) -> io::Result<Self> {
            if file.metadata()?.is_dir() {
                Ok(Self(file))
            } else {
                Err(io::Error::from(io::ErrorKind::NotADirectory))
            }
        }

        /// Opens `path`, which the caller has canonicalized. A reparse point at
        /// `path` is not followed and is refused.
        #[expect(
            clippy::disallowed_methods,
            reason = "opens the destination root itself; no directory handle exists yet"
        )]
        pub(super) fn open_path(path: &Path) -> io::Result<Self> {
            let file = std::fs::OpenOptions::new()
                .access_mode(DIR_ACCESS)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)?;
            Self::into_dir(file)
        }

        /// Another handle to the same directory.
        pub(crate) fn reopen(&self) -> io::Result<Self> {
            self.0.try_clone().map(Self)
        }

        /// Opens the subdirectory `name`; a link or a file there is an error.
        pub(crate) fn open_dir(&self, name: Leaf<'_>) -> io::Result<Self> {
            let request = Request {
                kind: Kind::Directory,
                ..Request::open(DIR_ACCESS)
            };
            let handle = nt::create_at(self.0.as_handle(), name, request)?;
            Self::into_dir(File::from(handle))
        }

        /// Reports an occupied `name` as `AlreadyExists`.
        ///
        /// NT answers a create that meets an existing directory or junction
        /// with `STATUS_ACCESS_DENIED`, which callers cannot tell from a real
        /// permission failure. The probe opens the name as itself and never
        /// follows a link.
        fn occupied_as_exists(&self, name: Leaf<'_>, err: io::Error) -> io::Error {
            if err.kind() == io::ErrorKind::PermissionDenied
                && matches!(self.probe(name), Ok(Some(_)))
            {
                io::Error::from(io::ErrorKind::AlreadyExists)
            } else {
                err
            }
        }

        /// Creates the subdirectory `name`, inheriting the parent's ACL.
        pub(crate) fn make_dir(&self, name: Leaf<'_>) -> io::Result<()> {
            let request = Request {
                access: SYNCHRONIZE | FILE_READ_ATTRIBUTES,
                disposition: Disposition::Create,
                kind: Kind::Directory,
                attributes: 0,
            };
            nt::create_at(self.0.as_handle(), name, request)
                .map(drop)
                .map_err(|err| self.occupied_as_exists(name, err))
        }

        /// What `name` is, without following a link; `None` if it is absent.
        pub(crate) fn probe(&self, name: Leaf<'_>) -> io::Result<Option<Occupant>> {
            let request = Request::open(FILE_READ_ATTRIBUTES);
            match nt::create_at(self.0.as_handle(), name, request) {
                Ok(handle) => {
                    let meta = File::from(handle).metadata()?;
                    Ok(Some(meta.file_type().into()))
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// Creates the file `name` exclusively, never following a link at it.
        pub(crate) fn create_new(
            &self,
            name: Leaf<'_>,
            _mode: Option<SanitizedMode>,
        ) -> io::Result<File> {
            let request = Request {
                access: FILE_GENERIC_WRITE,
                disposition: Disposition::Create,
                kind: Kind::NonDirectory,
                attributes: FILE_ATTRIBUTE_NORMAL,
            };
            nt::create_at(self.0.as_handle(), name, request)
                .map(File::from)
                .map_err(|err| self.occupied_as_exists(name, err))
        }

        /// Opens `name` for reading without following a link; the caller
        /// checks the file type through the returned handle.
        pub(crate) fn open_read(&self, name: Leaf<'_>) -> io::Result<File> {
            nt::create_at(self.0.as_handle(), name, Request::open(FILE_GENERIC_READ))
                .map(File::from)
        }

        /// Renames `from` over `to`, both in this directory.
        pub(crate) fn rename_within(&self, from: Leaf<'_>, to: Leaf<'_>) -> io::Result<()> {
            nt::rename_within(self.0.as_handle(), from, to)
        }

        /// Deletes the non-directory `name`.
        pub(crate) fn remove_file(&self, name: Leaf<'_>) -> io::Result<()> {
            nt::remove_file(self.0.as_handle(), name)
        }
    }
}

#[cfg(not(any(unix, target_os = "wasi", windows)))]
compile_error!("exarch-core has no directory-handle backend for this target");

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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod support {
    use std::path::Path;

    use super::Leaf;
    use super::PinnedRoot;
    use super::VettedDir;

    pub fn leaf(name: &str) -> Leaf<'_> {
        Leaf::from_component(Path::new(name).components().next().unwrap()).unwrap()
    }

    pub fn pinned_at(path: &Path) -> VettedDir {
        PinnedRoot::open_for_test(path)
            .unwrap()
            .dir()
            .reopen()
            .unwrap()
    }

    pub(super) fn pinned(temp: &tempfile::TempDir) -> VettedDir {
        pinned_at(temp.path())
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::support::leaf;
    use super::support::pinned;
    use super::support::pinned_at;
    use super::*;
    use crate::security::RawMode;
    use std::assert_matches;
    use std::fs;
    use std::io;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    #[test]
    fn both_file_type_mappings_agree_on_the_occupant() {
        use rustix::fs::FileType;
        assert_eq!(Occupant::from(FileType::Directory), Occupant::Directory);
        assert_eq!(Occupant::from(FileType::Symlink), Occupant::Symlink);
        assert_eq!(Occupant::from(FileType::RegularFile), Occupant::File);
        assert_eq!(Occupant::from(FileType::Fifo), Occupant::File);

        let temp = TempDir::new().unwrap();
        let std_type = |name: &str| {
            fs::symlink_metadata(temp.path().join(name))
                .unwrap()
                .file_type()
        };
        fs::create_dir(temp.path().join("d")).unwrap();
        fs::write(temp.path().join("f"), b"x").unwrap();
        symlink("f", temp.path().join("l")).unwrap();
        assert_eq!(Occupant::from(std_type("d")), Occupant::Directory);
        assert_eq!(Occupant::from(std_type("l")), Occupant::Symlink);
        assert_eq!(Occupant::from(std_type("f")), Occupant::File);
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
        let config = crate::SecurityConfig::default();
        let mode = crate::security::permissions::sanitize_permissions(RawMode::new(0o640), &config);

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

#[cfg(all(test, windows))]
#[allow(clippy::unwrap_used)]
mod windows_tests {
    use super::support::leaf;
    use super::support::pinned;
    use super::support::pinned_at;
    use super::*;
    use std::fs;
    use std::io;
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::Command;
    use tempfile::TempDir;

    fn run(program: &str, args: &[&std::ffi::OsStr]) -> bool {
        Command::new(program)
            .args(args)
            .output()
            .is_ok_and(|out| out.status.success())
    }

    fn junction(link: &Path, target: &Path) -> bool {
        run(
            "cmd",
            &[
                "/C".as_ref(),
                "mklink".as_ref(),
                "/J".as_ref(),
                link.as_ref(),
                target.as_ref(),
            ],
        )
    }

    fn entries(dir: &Path) -> usize {
        fs::read_dir(dir).unwrap().count()
    }

    #[test]
    fn basic_operations_stay_relative_to_the_handle() {
        let temp = TempDir::new().unwrap();
        let dir = pinned(&temp);

        dir.make_dir(leaf("sub")).unwrap();
        assert_eq!(dir.probe(leaf("sub")).unwrap(), Some(Occupant::Directory));
        assert_eq!(dir.probe(leaf("absent")).unwrap(), None);

        let mut file = dir.create_new(leaf("a"), None).unwrap();
        file.write_all(b"one").unwrap();
        drop(file);
        let err = dir.create_new(leaf("a"), None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(dir.probe(leaf("a")).unwrap(), Some(Occupant::File));
        assert!(
            dir.open_read(leaf("a"))
                .unwrap()
                .metadata()
                .unwrap()
                .is_file()
        );

        fs::write(temp.path().join("b"), b"old").unwrap();
        dir.rename_within(leaf("a"), leaf("b")).unwrap();
        assert_eq!(fs::read(temp.path().join("b")).unwrap(), b"one");
        assert!(!temp.path().join("a").exists());

        assert!(dir.remove_file(leaf("sub")).is_err());
        assert!(temp.path().join("sub").is_dir());
        dir.remove_file(leaf("b")).unwrap();
        assert_eq!(dir.probe(leaf("b")).unwrap(), None);

        dir.reopen().unwrap().create_new(leaf("c"), None).unwrap();
        assert!(temp.path().join("c").is_file());
        assert!(dir.open_dir(leaf("c")).is_err());
        assert!(dir.open_dir(leaf("sub")).is_ok());
    }

    #[test]
    fn an_occupied_name_of_any_kind_is_already_exists() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("d")).unwrap();
        fs::write(temp.path().join("f"), b"x").unwrap();
        let dir = pinned(&temp);

        let err = dir.create_new(leaf("d"), None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        let err = dir.create_new(leaf("f"), None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        let err = dir.make_dir(leaf("d")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn a_preexisting_junction_is_never_followed() {
        let temp = TempDir::new().unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), b"k").unwrap();
        let link = temp.path().join("j");
        assert!(junction(&link, &outside), "mklink /J failed");
        let dir = pinned(&temp);

        let err = dir.open_dir(leaf("j")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotADirectory);
        assert_eq!(dir.probe(leaf("j")).unwrap(), Some(Occupant::Symlink));
        let err = dir.create_new(leaf("j"), None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(
            !dir.open_read(leaf("j"))
                .unwrap()
                .metadata()
                .unwrap()
                .is_file()
        );

        dir.remove_file(leaf("j")).unwrap();
        assert!(fs::symlink_metadata(&link).is_err());
        assert_eq!(fs::read(outside.join("keep")).unwrap(), b"k");
    }

    #[test]
    fn a_grandparent_of_held_handles_cannot_be_renamed_away() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("base");
        fs::create_dir_all(base.join("a/b/c")).unwrap();
        let root = pinned_at(&base);
        let b = {
            let a = root.open_dir(leaf("a")).unwrap();
            a.open_dir(leaf("b")).unwrap()
        };
        let c = b.open_dir(leaf("c")).unwrap();

        let renamed = fs::rename(base.join("a"), base.join("a_moved"));
        assert!(
            renamed.is_err(),
            "NTFS is expected to refuse renaming an ancestor of an open handle"
        );

        c.create_new(leaf("tmp"), None).unwrap();
        c.rename_within(leaf("tmp"), leaf("final")).unwrap();
        assert!(base.join("a/b/c/final").is_file());
    }

    #[test]
    fn a_deleted_and_replaced_directory_receives_nothing() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("base");
        let outside = temp.path().join("outside");
        fs::create_dir_all(base.join("c")).unwrap();
        fs::create_dir(&outside).unwrap();
        let c = pinned_at(&base).open_dir(leaf("c")).unwrap();

        fs::remove_dir(base.join("c")).unwrap();
        assert!(junction(&base.join("c"), &outside), "mklink /J failed");

        assert!(c.create_new(leaf("f"), None).is_err());
        assert!(c.make_dir(leaf("d")).is_err());
        assert_eq!(entries(&outside), 0);
    }

    struct MountGuard {
        mount_dir: PathBuf,
        escaped: Vec<PathBuf>,
    }

    impl Drop for MountGuard {
        fn drop(&mut self) {
            run("mountvol", &[self.mount_dir.as_ref(), "/D".as_ref()]);
            for path in &self.escaped {
                let _ = fs::remove_file(path);
                let _ = fs::remove_dir(path);
            }
        }
    }

    fn volume_guid(drive_root: &Path) -> Option<String> {
        let out = Command::new("mountvol")
            .arg(drive_root)
            .arg("/L")
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }

    #[test]
    fn a_directory_converted_in_place_into_a_mount_point_receives_nothing() {
        let temp = TempDir::new().unwrap();
        let drive_root = temp
            .path()
            .ancestors()
            .last()
            .map(Path::to_path_buf)
            .unwrap();
        let c_path = temp.path().join("c");
        fs::create_dir(&c_path).unwrap();
        let held = pinned(&temp).open_dir(leaf("c")).unwrap();

        let mount_dir = c_path.join("");
        let mounted = volume_guid(&drive_root)
            .is_some_and(|guid| run("mountvol", &[mount_dir.as_ref(), guid.as_ref()]));
        if !mounted {
            assert!(
                std::env::var_os("EXARCH_REQUIRE_PRIVILEGED_TESTS").is_none(),
                "mountvol failed but EXARCH_REQUIRE_PRIVILEGED_TESTS is set"
            );
            eprintln!("skipped: mountvol needs administrator rights");
            return;
        }
        let pid = std::process::id();
        let names = [
            format!(".exarch-escape-tmp-{pid}"),
            format!(".exarch-escape-final-{pid}"),
            format!(".exarch-escape-dir-{pid}"),
        ];
        let _guard = MountGuard {
            mount_dir,
            escaped: names.iter().map(|name| drive_root.join(name)).collect(),
        };
        let [first, second, third] = &names;

        let created = held.create_new(leaf(first), None);
        let renamed = created
            .is_ok()
            .then(|| held.rename_within(leaf(first), leaf(second)));
        let made = held.make_dir(leaf(third));
        let opened = made.is_ok().then(|| held.open_dir(leaf(third)).map(drop));

        for name in &names {
            assert!(
                !drive_root.join(name).exists(),
                "{name} escaped: create={created:?} rename={renamed:?} make={made:?} open={opened:?}"
            );
        }
    }
}
