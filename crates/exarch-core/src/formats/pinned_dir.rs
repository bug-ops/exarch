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
//!   confined to the destination. The destination swap narrows the same gap by
//!   comparing the file identity read at pin time with one read right before
//!   the destructive rename (`staging/replace.rs::verify_unchanged`).
//! - Over SMB the redirector rebuilds a relative open as a full path, so the
//!   server resolves the names. Third-party filesystem drivers are unverified.
//! - Only NTFS is exercised in CI; `ReFS` and Dev Drive are untested.
//! - Following a pre-existing symlink or junction under `ContainedOnly` reads
//!   the link with `FSCTL_GET_REPARSE_POINT` on the held handle and opens the
//!   target relative to the destination root. An absolute target is matched
//!   against the canonical destination only, case-insensitively by component; a
//!   destination reached through `SUBST`, a mapped drive or a symlinked
//!   ancestor, or a target spelled with a short name or volume GUID, is refused
//!   as an escape.

use std::ffi::OsStr;
use std::ffi::OsString;
use std::path::Component;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use super::file_identity::FileIdentity;
use super::run_record::RunRecord;
use crate::ArchiveError;
use crate::Result;
use crate::security::fs_view::Occupant;
use crate::types::DestDir;

pub(crate) use imp::VettedDir;

/// Exactly one normal path component: a name inside a [`VettedDir`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Leaf<'a>(&'a OsStr);

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
pub(crate) struct TempLeaf(OsString);

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

/// An owned, generated name that is exactly one normal component, for the
/// staging and backup entries the destination swap creates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LeafBuf(OsString);

impl LeafBuf {
    /// The final component of `path`, or `None` when `path` ends in `.`, `..`
    /// or a root, which have no usable final name.
    pub(crate) fn of(path: &Path) -> Option<Self> {
        let name = path.file_name()?;
        let mut components = Path::new(name).components();
        match (components.next(), components.next()) {
            (Some(Component::Normal(only)), None) if only == name => {
                Some(Self(name.to_os_string()))
            }
            _ => None,
        }
    }

    /// `prefix` followed by 64 random bits in hex.
    ///
    /// The randomness comes from the standard library's per-process hasher
    /// keys, so a local user cannot predict the next name.
    pub(crate) fn random(prefix: &str) -> Self {
        use std::hash::BuildHasher;
        use std::hash::RandomState;

        let bits = RandomState::new().hash_one(TEMP_COUNTER.fetch_add(1, Ordering::Relaxed));
        Self(OsString::from(format!("{prefix}{bits:016x}")))
    }

    /// Borrows the name as a [`Leaf`].
    pub(crate) fn as_leaf(&self) -> Leaf<'_> {
        Leaf(&self.0)
    }
}

impl AsRef<Path> for LeafBuf {
    fn as_ref(&self) -> &Path {
        Path::new(&self.0)
    }
}

/// Permission bits and owner of a directory entry, as `stat` reports them.
#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct EntryMode {
    pub(crate) bits: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

#[cfg(unix)]
impl EntryMode {
    #[allow(
        clippy::useless_conversion,
        reason = "`st_mode` is `u16` on macOS and `u32` on Linux"
    )]
    fn of_stat(stat: &rustix::fs::Stat) -> Self {
        Self {
            bits: u32::from(stat.st_mode) & 0o7777,
            uid: stat.st_uid,
            gid: stat.st_gid,
        }
    }
}

/// What a directory entry is, which inode it is and, on Unix, its mode and
/// owner, read without following the entry.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EntryStatus {
    pub(crate) occupant: Occupant,
    /// Whether the entry is a reparse point of any kind (Windows only; a
    /// non-name-surrogate reparse point is classified as a directory or file
    /// by `occupant`).
    pub(crate) reparse: bool,
    pub(crate) identity: FileIdentity,
    #[cfg(unix)]
    pub(crate) mode: EntryMode,
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
pub(crate) struct PinnedRoot {
    dest: DestDir,
    dir: VettedDir,
    created: RunRecord,
}

impl PinnedRoot {
    /// Opens the (already canonical) destination.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the directory cannot be opened.
    pub(crate) fn open(dest: DestDir) -> Result<Self> {
        let dir = VettedDir::open_path(dest.as_path())?;
        Ok(Self {
            dest,
            dir,
            created: RunRecord::default(),
        })
    }

    /// What this run created in the destination, for `ExistingFiles::Refuse`.
    pub(crate) const fn created(&self) -> &RunRecord {
        &self.created
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
#[cfg_attr(not(feature = "testing"), allow(unreachable_pub))]
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

    use super::EntryStatus;
    use super::Leaf;
    use super::TempLeaf;
    use crate::formats::file_identity::FileIdentity;
    use crate::formats::file_identity::IdentityKey;
    use crate::formats::occupant::ReplacePermit;
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
    pub(crate) struct VettedDir(OwnedFd);

    impl VettedDir {
        /// Opens `path`, which the caller has canonicalized.
        #[cfg(unix)]
        pub(crate) fn open_path(path: &Path) -> io::Result<Self> {
            open_directory(|flags| rustix::fs::open(path, flags, Mode::empty())).map(Self)
        }

        /// Opens `path` through std, so nothing relies on `AT_FDCWD`, which
        /// WASI has no equivalent of.
        #[cfg(target_os = "wasi")]
        pub(crate) fn open_path(path: &Path) -> io::Result<Self> {
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

        /// What `name` is, which inode it is and its mode, without following a
        /// symlink; `None` if it is absent. An identity that does not fit the
        /// key is [`FileIdentity::Unknown`]; what the entry is never depends on
        /// it.
        pub(crate) fn status(&self, name: Leaf<'_>) -> io::Result<Option<EntryStatus>> {
            match rustix::fs::statat(&self.0, name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => Ok(Some(EntryStatus {
                    occupant: FileType::from_raw_mode(stat.st_mode).into(),
                    reparse: false,
                    identity: IdentityKey::of_stat(&stat)
                        .map_or(FileIdentity::Unknown, FileIdentity::Known),
                    #[cfg(unix)]
                    mode: super::EntryMode::of_stat(&stat),
                })),
                Err(e) if e == Errno::NOENT => Ok(None),
                Err(e) => Err(e.into()),
            }
        }

        /// What `name` is, without following a symlink; `None` if it is absent.
        pub(crate) fn probe(&self, name: Leaf<'_>) -> io::Result<Option<Occupant>> {
            Ok(self.status(name)?.map(|status| status.occupant))
        }

        /// The identity of the entry `name` itself, never of a symlink's
        /// target; `None` if it is absent.
        pub(crate) fn identity(&self, name: Leaf<'_>) -> io::Result<Option<FileIdentity>> {
            Ok(self.status(name)?.map(|status| status.identity))
        }

        /// Opens the directory `name` for reading, refusing a symlink: the
        /// handle `fchmod` and `fchown` need, which an `O_PATH` handle is not.
        pub(crate) fn open_dir_file(&self, name: Leaf<'_>) -> io::Result<File> {
            let fd = rustix::fs::openat(
                &self.0,
                name.as_os_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            Ok(File::from(fd))
        }

        /// Best effort: where the directory `name` is now, resolved from a
        /// descriptor on the entry itself and so unaffected by a redirect of
        /// any ancestor. `None` where the platform cannot say.
        pub(crate) fn entry_path(&self, name: Leaf<'_>) -> Option<std::path::PathBuf> {
            self.open_dir_file(name)
                .ok()
                .and_then(|dir| current_path(&dir))
        }

        /// Creates the subdirectory `name` readable and writable by the owner
        /// only.
        pub(crate) fn make_private_dir(&self, name: Leaf<'_>) -> io::Result<()> {
            Ok(rustix::fs::mkdirat(&self.0, name.as_os_str(), Mode::RWXU)?)
        }

        /// Removes the empty directory `name`.
        #[cfg(unix)]
        pub(crate) fn remove_dir(&self, name: Leaf<'_>) -> io::Result<()> {
            Ok(rustix::fs::unlinkat(
                &self.0,
                name.as_os_str(),
                AtFlags::REMOVEDIR,
            )?)
        }

        /// Renames the directory `from` to `to`, both in this directory. An
        /// existing `to` is replaced only where the platform replaces an empty
        /// directory on rename.
        pub(crate) fn rename_dir_within(&self, from: Leaf<'_>, to: Leaf<'_>) -> io::Result<()> {
            Ok(rustix::fs::renameat(
                &self.0,
                from.as_os_str(),
                &self.0,
                to.as_os_str(),
            )?)
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

        /// Renames the temp file `from` over the occupant `to`, both in this
        /// directory; the permit proves the policy allows replacing it.
        pub(crate) fn replace_entry(
            &self,
            from: &TempLeaf,
            to: Leaf<'_>,
            _permit: ReplacePermit,
        ) -> io::Result<()> {
            Ok(rustix::fs::renameat(
                &self.0,
                from.as_leaf().as_os_str(),
                &self.0,
                to.as_os_str(),
            )?)
        }

        /// Unlinks the occupant `name`; the permit proves the policy allows
        /// destroying it.
        #[cfg(unix)]
        pub(crate) fn remove_occupant(
            &self,
            name: Leaf<'_>,
            _permit: ReplacePermit,
        ) -> io::Result<()> {
            self.unlink_own(name)
        }

        /// Unlinks a file this run created.
        pub(super) fn unlink_own(&self, name: Leaf<'_>) -> io::Result<()> {
            Ok(rustix::fs::unlinkat(
                &self.0,
                name.as_os_str(),
                AtFlags::empty(),
            )?)
        }

        /// Reads the target of the symlink `name`.
        pub(crate) fn read_link(&self, name: Leaf<'_>) -> io::Result<std::path::PathBuf> {
            #[cfg(unix)]
            use std::os::unix::ffi::OsStringExt;
            #[cfg(target_os = "wasi")]
            use std::os::wasi::ffi::OsStringExt;

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

    /// Linux: the target of `/proc/self/fd/<fd>`.
    #[cfg(target_os = "linux")]
    fn current_path(fd: &File) -> Option<std::path::PathBuf> {
        use std::os::fd::AsRawFd;
        std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).ok()
    }

    /// macOS: `fcntl(fd, F_GETPATH)`.
    #[cfg(target_os = "macos")]
    fn current_path(fd: &File) -> Option<std::path::PathBuf> {
        use std::os::unix::ffi::OsStrExt;
        rustix::fs::getpath(fd)
            .ok()
            .map(|c_path| std::path::PathBuf::from(std::ffi::OsStr::from_bytes(c_path.as_bytes())))
    }

    /// Other targets have no descriptor-to-path facility implemented here.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn current_path(_fd: &File) -> Option<std::path::PathBuf> {
        None
    }
}

#[cfg(windows)]
#[allow(unsafe_code)] // the only unsafe code on Windows: NT directory-relative calls
pub(in crate::formats) mod nt;

#[cfg(windows)]
mod imp {
    use std::ffi::OsString;
    use std::fs::File;
    use std::io;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsHandle;
    use std::path::Path;
    use std::path::PathBuf;

    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
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

    use super::EntryStatus;
    use super::Leaf;
    use super::TempLeaf;
    use super::nt;
    use super::nt::Disposition;
    use super::nt::Kind;
    use super::nt::Request;
    use crate::formats::file_identity::FileIdentity;
    use crate::formats::occupant::ReplacePermit;
    use crate::formats::reparse;
    use crate::formats::reparse::ReparseTarget;
    use crate::security::fs_view::Occupant;
    use crate::security::permissions::SanitizedMode;

    const DIR_ACCESS: u32 = FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;

    /// An open directory below the destination.
    ///
    /// Every operation is relative to this handle, so replacing or converting
    /// the directory's path cannot redirect it.
    #[derive(Debug)]
    pub(crate) struct VettedDir(File);

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
        pub(crate) fn open_path(path: &Path) -> io::Result<Self> {
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

        /// Reads the target of the symlink or junction `name` from its reparse
        /// data. An absolute target comes back in the verbatim `\\?\` form.
        ///
        /// A reparse point of another kind, or data that does not parse, is an
        /// `InvalidData` error.
        pub(crate) fn read_link(&self, name: Leaf<'_>) -> io::Result<PathBuf> {
            let buffer = nt::reparse_data_at(self.0.as_handle(), name)?;
            let (ReparseTarget::Relative(units) | ReparseTarget::Absolute(units)) =
                reparse::parse(&buffer)?;
            Ok(PathBuf::from(OsString::from_wide(&units)))
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

        /// What `name` is, which entry it is and whether it is a reparse
        /// point, without following a link; `None` if it is absent.
        pub(crate) fn status(&self, name: Leaf<'_>) -> io::Result<Option<EntryStatus>> {
            let request = Request::open(FILE_READ_ATTRIBUTES);
            let handle = match nt::create_at(self.0.as_handle(), name, request) {
                Ok(handle) => handle,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e),
            };
            let file = File::from(handle);
            let meta = file.metadata()?;
            Ok(Some(EntryStatus {
                occupant: meta.file_type().into(),
                reparse: meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0,
                identity: FileIdentity::of_file(&file),
            }))
        }

        /// What `name` is, without following a link; `None` if it is absent.
        pub(crate) fn probe(&self, name: Leaf<'_>) -> io::Result<Option<Occupant>> {
            Ok(self.status(name)?.map(|status| status.occupant))
        }

        /// The identity of the entry `name` itself; `None` if it is absent.
        ///
        /// [`FileIdentity::Unknown`] when the volume reports no file id.
        pub(crate) fn identity(&self, name: Leaf<'_>) -> io::Result<Option<FileIdentity>> {
            Ok(self.status(name)?.map(|status| status.identity))
        }

        /// There is no handle-to-path resolution here, so a surviving entry is
        /// named logically by the caller.
        #[allow(
            clippy::unused_self,
            reason = "keeps the signature of the platforms that name the entry by path"
        )]
        pub(crate) fn entry_path(&self, _name: Leaf<'_>) -> Option<std::path::PathBuf> {
            None
        }

        /// Creates the subdirectory `name`.
        ///
        /// It inherits the parent's ACL, so it is not owner-only here.
        // TODO(critic): an explicit owner-only DACL for staging directories.
        pub(crate) fn make_private_dir(&self, name: Leaf<'_>) -> io::Result<()> {
            self.make_dir(name)
        }

        /// Renames the directory `from` to `to`, both in this directory, and
        /// fails if `to` exists.
        pub(crate) fn rename_dir_within(&self, from: Leaf<'_>, to: Leaf<'_>) -> io::Result<()> {
            nt::rename_with(self.0.as_handle(), from, to, nt::Replace::Never)
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

        /// Renames the temp file `from` over the occupant `to`, both in this
        /// directory; the permit proves the policy allows replacing it.
        pub(crate) fn replace_entry(
            &self,
            from: &TempLeaf,
            to: Leaf<'_>,
            _permit: ReplacePermit,
        ) -> io::Result<()> {
            nt::rename_within(self.0.as_handle(), from.as_leaf(), to)
        }

        /// Deletes the occupant `name`; the permit proves the policy allows
        /// destroying it. Only Unix replaces a symlink, so only tests call it.
        #[cfg(test)]
        pub(crate) fn remove_occupant(
            &self,
            name: Leaf<'_>,
            _permit: ReplacePermit,
        ) -> io::Result<()> {
            self.unlink_own(name)
        }

        /// Deletes a file this run created.
        pub(super) fn unlink_own(&self, name: Leaf<'_>) -> io::Result<()> {
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
pub(crate) struct TempFileGuard<'d> {
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
            let _ = self.dir.unlink_own(Leaf(&self.name));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod support {
    use std::path::Path;

    use super::Leaf;
    use super::PinnedRoot;
    use super::VettedDir;

    pub(crate) fn leaf(name: &str) -> Leaf<'_> {
        Leaf::from_component(Path::new(name).components().next().unwrap()).unwrap()
    }

    pub(crate) fn pinned_at(path: &Path) -> VettedDir {
        PinnedRoot::open_for_test(path)
            .unwrap()
            .dir()
            .reopen()
            .unwrap()
    }

    pub(super) fn pinned(temp: &tempfile::TempDir) -> VettedDir {
        pinned_at(temp.path())
    }

    /// `path` without the verbatim `\\?\` prefix a canonical Windows path
    /// carries, which `mklink` does not accept.
    #[cfg(windows)]
    pub(crate) fn plain(path: &Path) -> std::path::PathBuf {
        path.to_str()
            .and_then(|text| text.strip_prefix(r"\\?\"))
            .map_or_else(|| path.to_path_buf(), std::path::PathBuf::from)
    }

    /// Creates the junction `link` to `target`; `false` when `mklink` fails.
    #[cfg(windows)]
    pub(crate) fn junction(link: &Path, target: &Path) -> bool {
        std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(plain(target))
            .output()
            .is_ok_and(|out| out.status.success())
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::support::leaf;
    use super::support::pinned;
    use super::support::pinned_at;
    use super::*;
    use crate::formats::occupant::ReplacePermit;
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
        a.replace_entry(
            &TempLeaf::named("tmp"),
            leaf("final"),
            ReplacePermit::for_test(),
        )
        .unwrap();
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
    use super::support::junction;
    use super::support::leaf;
    use super::support::pinned;
    use super::support::pinned_at;
    use super::*;
    use crate::formats::file_identity::IdentityCheck;
    use crate::formats::occupant::ReplacePermit;
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

    fn entries(dir: &Path) -> usize {
        fs::read_dir(dir).unwrap().count()
    }

    #[test]
    fn a_handle_relative_status_carries_the_file_identity_of_the_path() {
        let temp = TempDir::new().unwrap();
        let dir = pinned(&temp);
        dir.make_dir(leaf("sub")).unwrap();
        fs::write(temp.path().join("other"), b"x").unwrap();

        let sub = dir.status(leaf("sub")).unwrap().unwrap();
        let other = dir.status(leaf("other")).unwrap().unwrap();
        let by_path = crate::formats::file_identity::identity_of(&temp.path().join("sub")).unwrap();
        if matches!(
            sub.identity,
            crate::formats::file_identity::FileIdentity::Unknown
        ) {
            eprintln!("skipping: the volume reports no file id");
            return;
        }

        assert_eq!(sub.identity.check(by_path), IdentityCheck::Same);
        assert_eq!(sub.identity.check(other.identity), IdentityCheck::Different);
        assert!(!sub.reparse);
    }

    #[test]
    fn a_junction_is_reported_as_a_reparse_point() {
        let temp = TempDir::new().unwrap();
        let dir = pinned(&temp);
        fs::create_dir(temp.path().join("target")).unwrap();
        if !junction(&temp.path().join("link"), &temp.path().join("target")) {
            eprintln!("skipping: cannot create a junction");
            return;
        }

        let status = dir.status(leaf("link")).unwrap().unwrap();

        assert!(status.reparse);
    }

    #[test]
    fn a_junction_reads_back_as_its_verbatim_target() {
        let temp = TempDir::new().unwrap();
        let dir = pinned(&temp);
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        let target = target.canonicalize().unwrap();
        if !junction(&temp.path().join("link"), &target) {
            eprintln!("skipping: cannot create a junction");
            return;
        }

        let read = dir.read_link(leaf("link")).unwrap();

        assert_eq!(read, target);
    }

    #[test]
    fn reading_a_link_that_is_not_one_fails() {
        let temp = TempDir::new().unwrap();
        let dir = pinned(&temp);
        dir.make_dir(leaf("plain")).unwrap();
        fs::write(temp.path().join("file"), b"x").unwrap();

        assert!(dir.read_link(leaf("plain")).is_err());
        assert!(dir.read_link(leaf("file")).is_err());
        assert!(dir.read_link(leaf("missing")).is_err());
    }

    #[test]
    fn renaming_a_directory_onto_an_existing_name_is_refused() {
        let temp = TempDir::new().unwrap();
        let dir = pinned(&temp);
        dir.make_dir(leaf("from")).unwrap();
        dir.make_dir(leaf("taken")).unwrap();

        assert!(dir.rename_dir_within(leaf("from"), leaf("taken")).is_err());
        assert_eq!(entries(temp.path()), 2);
        dir.rename_dir_within(leaf("from"), leaf("free")).unwrap();
        assert_eq!(dir.probe(leaf("free")).unwrap(), Some(Occupant::Directory));
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
        dir.replace_entry(&TempLeaf::named("a"), leaf("b"), ReplacePermit::for_test())
            .unwrap();
        assert_eq!(fs::read(temp.path().join("b")).unwrap(), b"one");
        assert!(!temp.path().join("a").exists());

        assert!(
            dir.remove_occupant(leaf("sub"), ReplacePermit::for_test())
                .is_err()
        );
        assert!(temp.path().join("sub").is_dir());
        dir.remove_occupant(leaf("b"), ReplacePermit::for_test())
            .unwrap();
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

        dir.remove_occupant(leaf("j"), ReplacePermit::for_test())
            .unwrap();
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
        c.replace_entry(
            &TempLeaf::named("tmp"),
            leaf("final"),
            ReplacePermit::for_test(),
        )
        .unwrap();
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
            .then(|| String::from_utf8_lossy_owned(out.stdout).trim().to_owned())
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
        let renamed = created.is_ok().then(|| {
            held.replace_entry(
                &TempLeaf::named(first),
                leaf(second),
                ReplacePermit::for_test(),
            )
        });
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
