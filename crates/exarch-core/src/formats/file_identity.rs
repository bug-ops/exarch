//! File identity: which inode a directory entry is, independent of its name.
//!
//! Path text is a poor identity on a case-insensitive or 8.3-aliasing volume,
//! so the staging guards and the run record compare the device and file index
//! of the entry itself. Where the platform offers none the identity is
//! [`FileIdentity::Unknown`], which no caller may treat as equal to anything.
#![cfg_attr(
    not(all(test, unix)),
    expect(
        dead_code,
        reason = "`of_file` is adopted by the occupant track and the Windows bodies by the staging \
                  track; the unix unit tests keep them live"
    )
)]

use std::fs::File;
use std::io;
use std::path::Path;

/// The file index of an entry: 64 bits on Unix and WASI, the 128-bit
/// `FILE_ID_128` on Windows.
#[cfg(windows)]
pub type FileIndex = u128;
/// The file index of an entry: 64 bits on Unix and WASI, the 128-bit
/// `FILE_ID_128` on Windows.
#[cfg(not(windows))]
pub type FileIndex = u64;

/// A device and file index that together name one directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdentityKey {
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
    // `st_dev` and `st_ino` are `i32` and `u64` on macOS and `u64` on 64-bit
    // Linux, so the conversion is a no-op on some targets.
    #[allow(clippy::useless_conversion)]
    pub(crate) fn of_stat(stat: &rustix::fs::Stat) -> io::Result<Self> {
        let dev =
            u64::try_from(stat.st_dev).map_err(|_| io::Error::other("unrepresentable st_dev"))?;
        let ino =
            u64::try_from(stat.st_ino).map_err(|_| io::Error::other("unrepresentable st_ino"))?;
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
pub enum FileIdentity {
    /// A device and file index from the filesystem.
    Known(IdentityKey),
    /// The platform or volume provides no stable identity.
    Unknown,
}

/// The outcome of comparing two [`FileIdentity`] values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityCheck {
    /// Both identities are known and equal.
    Same,
    /// Both identities are known and differ.
    Different,
    /// At least one identity is unknown, so nothing can be concluded.
    Unknown,
}

impl FileIdentity {
    /// Compares `self` (observed now) with `expected` (taken earlier).
    pub fn check(self, expected: Self) -> IdentityCheck {
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
    pub fn of_file(file: &File) -> Self {
        rustix::fs::fstat(file)
            .ok()
            .and_then(|stat| IdentityKey::of_stat(&stat).ok())
            .map_or(Self::Unknown, Self::Known)
    }

    /// The identity of an open file.
    ///
    /// Always [`Unknown`](Self::Unknown) for now: no Windows identity source is
    /// wired up.
    #[cfg(not(any(unix, target_os = "wasi")))]
    pub const fn of_file(_file: &File) -> Self {
        Self::Unknown
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
pub fn identity_of(path: &Path) -> io::Result<FileIdentity> {
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
pub fn identity_of(path: &Path) -> io::Result<FileIdentity> {
    let stat = rustix::fs::fstat(File::open(path)?)?;
    IdentityKey::of_stat(&stat).map(FileIdentity::Known)
}

/// No identity is available on this target.
///
/// # Errors
///
/// The I/O error of the lookup.
#[cfg(not(any(unix, target_os = "wasi")))]
pub fn identity_of(path: &Path) -> io::Result<FileIdentity> {
    std::fs::metadata(path).map(|_| FileIdentity::Unknown)
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
