//! File identity: which inode a directory entry is, independent of its name.
//!
//! Path text is a poor identity on a case-insensitive or 8.3-aliasing volume,
//! so the staging guards and the run record compare the device and file index
//! of the entry itself. Where the platform offers none the identity is
//! [`FileIdentity::Unknown`], which no caller may treat as equal to anything.

use std::fs::File;
use std::io;
use std::path::Path;

/// The file index of an entry: 64 bits on Unix and WASI, the 128-bit
/// `FILE_ID_128` on Windows.
#[cfg(windows)]
pub(crate) type FileIndex = u128;
/// The file index of an entry: 64 bits on Unix and WASI, the 128-bit
/// `FILE_ID_128` on Windows.
#[cfg(not(windows))]
pub(crate) type FileIndex = u64;

/// A device and file index that together name one directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct IdentityKey {
    pub(crate) dev: u64,
    pub(crate) ino: FileIndex,
}

#[cfg(any(unix, target_os = "wasi"))]
impl IdentityKey {
    /// The key of a `stat` result.
    ///
    /// The one conversion from the platform-native `st_dev` and `st_ino`; an
    /// unrepresentable value fails instead of collapsing to a shared sentinel
    /// that would make two inodes compare equal.
    pub(crate) fn of_stat(stat: &rustix::fs::Stat) -> io::Result<Self> {
        Self::from_parts(stat.st_dev, stat.st_ino)
    }

    /// The key of a device and inode in the platform's native widths, which
    /// differ between targets (`st_dev` is `i32` on macOS, negative for a major
    /// number of 128 or more).
    fn from_parts<D, I>(dev: D, ino: I) -> io::Result<Self>
    where
        D: TryInto<u64>,
        I: TryInto<u64>,
    {
        let dev = dev
            .try_into()
            .map_err(|_| io::Error::other("unrepresentable st_dev"))?;
        let ino = ino
            .try_into()
            .map_err(|_| io::Error::other("unrepresentable st_ino"))?;
        Ok(Self { dev, ino })
    }
}

/// The identity of a directory entry.
///
/// Does not implement `PartialEq`: where the platform offers no stable
/// identity ([`Unknown`](Self::Unknown)) a derived `==` would make every
/// comparison succeed. [`check`](Self::check) makes each caller decide what an
/// unverifiable identity means.
#[derive(Debug, Clone, Copy)]
pub(crate) enum FileIdentity {
    /// A device and file index from the filesystem.
    Known(IdentityKey),
    /// The platform or volume provides no stable identity.
    Unknown,
}

/// The outcome of comparing two [`FileIdentity`] values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityCheck {
    /// Both identities are known and equal.
    Same,
    /// Both identities are known and differ.
    Different,
    /// At least one identity is unknown, so nothing can be concluded.
    Unknown,
}

impl FileIdentity {
    /// Compares `self` (observed now) with `expected` (taken earlier).
    pub(crate) fn check(self, expected: Self) -> IdentityCheck {
        match (self, expected) {
            (Self::Known(now), Self::Known(then)) => {
                if now == then {
                    IdentityCheck::Same
                } else {
                    IdentityCheck::Different
                }
            }
            _ => IdentityCheck::Unknown,
        }
    }

    /// The key to record, or `None` where the identity is unknown.
    pub(in crate::formats) const fn key(self) -> Option<IdentityKey> {
        match self {
            Self::Known(key) => Some(key),
            Self::Unknown => None,
        }
    }

    /// The identity of an open file, read from its descriptor.
    ///
    /// Any failure to read it is [`Unknown`](Self::Unknown), which every
    /// consumer treats as unverified.
    #[cfg(any(unix, target_os = "wasi"))]
    pub(crate) fn of_file(file: &File) -> Self {
        rustix::fs::fstat(file)
            .ok()
            .and_then(|stat| IdentityKey::of_stat(&stat).ok())
            .map_or(Self::Unknown, Self::Known)
    }

    /// The identity of an open file, from the volume serial number and file
    /// id of its handle ([`Unknown`](Self::Unknown) when the volume reports
    /// none, as FAT and some redirectors do).
    #[cfg(windows)]
    pub(crate) fn of_file(file: &File) -> Self {
        use std::os::windows::io::AsHandle;

        super::pinned_dir::nt::file_id(file.as_handle()).map_or(Self::Unknown, |(dev, ino)| {
            Self::Known(IdentityKey { dev, ino })
        })
    }
}

/// The identity of the entry at `path`, following symlinks: the device and
/// file index where the platform has them, [`FileIdentity::Unknown`]
/// elsewhere.
///
/// # Errors
///
/// The I/O error of the lookup.
#[cfg(unix)]
pub(crate) fn identity_of(path: &Path) -> io::Result<FileIdentity> {
    let stat = rustix::fs::stat(path)?;
    IdentityKey::of_stat(&stat).map(FileIdentity::Known)
}

/// WASI has no path-only `stat` here, so the entry is opened and its
/// descriptor is stat'ed.
///
/// # Errors
///
/// The I/O error of the lookup.
#[cfg(target_os = "wasi")]
pub(crate) fn identity_of(path: &Path) -> io::Result<FileIdentity> {
    let stat = rustix::fs::fstat(File::open(path)?)?;
    IdentityKey::of_stat(&stat).map(FileIdentity::Known)
}

/// The entry is opened for its attributes only and its handle is asked for the
/// file id, so an 8.3 short name and the long name give one identity.
///
/// # Errors
///
/// The I/O error of the lookup.
#[cfg(windows)]
#[expect(
    clippy::disallowed_methods,
    reason = "opens an entry for its attributes only; nothing is written or created"
)]
pub(crate) fn identity_of(path: &Path) -> io::Result<FileIdentity> {
    use std::os::windows::fs::OpenOptionsExt;

    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
    use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE;

    let file = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    Ok(FileIdentity::of_file(&file))
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::assert_matches;

    use super::FileIdentity;
    use super::IdentityCheck;
    use super::IdentityKey;
    use super::identity_of;

    #[test]
    fn a_device_or_inode_outside_u64_has_no_key() {
        assert!(IdentityKey::from_parts(-1_i32, 5_u64).is_err());
        assert!(IdentityKey::from_parts(7_i32, -2_i64).is_err());
        let key = IdentityKey::from_parts(7_i32, 9_u64).unwrap();
        assert_eq!((key.dev, key.ino), (7, 9));
    }

    #[test]
    fn an_untouched_entry_matches_itself_and_a_sibling_differs() {
        let temp = tempfile::tempdir().unwrap();
        let a = temp.path().join("a");
        let b = temp.path().join("b");
        std::fs::write(&a, b"x").unwrap();
        std::fs::write(&b, b"x").unwrap();

        let first = identity_of(&a).unwrap();
        assert_matches!(first, FileIdentity::Known(_));
        assert_eq!(identity_of(&a).unwrap().check(first), IdentityCheck::Same);
        assert_eq!(
            identity_of(&b).unwrap().check(first),
            IdentityCheck::Different
        );
    }

    #[test]
    fn a_file_descriptor_reports_the_identity_of_its_path() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        let file = std::fs::File::open(&path).unwrap();

        let by_fd = FileIdentity::of_file(&file);

        assert_eq!(
            by_fd.check(identity_of(&path).unwrap()),
            IdentityCheck::Same
        );
        assert_eq!(by_fd.key(), identity_of(&path).unwrap().key());
    }

    #[test]
    fn an_unknown_identity_has_no_key() {
        let key = IdentityKey { dev: 1, ino: 2 };

        assert_eq!(FileIdentity::Unknown.key(), None);
        assert_eq!(FileIdentity::Known(key).key(), Some(key));
    }
}
