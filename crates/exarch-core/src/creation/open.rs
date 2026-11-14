//! Opening a creation source so that what is read is what the walk saw.
//!
//! The walk records the identity of every entry it reports. A source is then
//! opened without following a link, and the opened handle is only accepted when
//! it is a regular file with that same identity. The copy takes exactly the
//! size the handle reported, so a file that changes while it is read cannot
//! leave an archive entry whose data disagrees with its header.

use crate::ArchiveError;
use crate::Result;
use crate::creation::config::CreationConfig;
use crate::creation::source::source_error;
use crate::creation::walker::FilteredEntry;
use crate::formats::file_identity::FileIdentity;
use crate::formats::file_identity::IdentityCheck;
#[cfg(not(unix))]
use crate::formats::file_identity::identity_of;
use crate::formats::io_marker::IoMarker;
use std::fs::File;
use std::fs::Metadata;
use std::io;
use std::io::Read;
use std::path::Path;

/// Whether a creation source may be reached through a symbolic link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkPolicy {
    /// The source itself must not be a link.
    Refuse,

    /// The source may be a link; its target is archived.
    Follow,
}

impl LinkPolicy {
    /// The policy a creation configuration asks for.
    pub(crate) const fn of(follow_symlinks: bool) -> Self {
        if follow_symlinks {
            Self::Follow
        } else {
            Self::Refuse
        }
    }
}

/// What the walk saw of a source: the file and, on Unix, the directory it was
/// found in.
///
/// The directory is part of it because a later open goes through that
/// directory; a directory replaced after the walk must be noticed before
/// anything below it is opened. Identities are [`FileIdentity`] values.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WalkedSource {
    file: FileIdentity,
    #[cfg(unix)]
    parent: FileIdentity,
}

impl WalkedSource {
    /// Records the entry at `path` that the walk described with `metadata`,
    /// and the directory that holds it. On Unix the entry's identity is the
    /// one in `metadata`, so it is never read a second time.
    ///
    /// # Errors
    ///
    /// A source error when an identity cannot be read; a source that cannot
    /// be inspected is never recorded as unknown.
    pub(crate) fn of(path: &Path, metadata: &Metadata) -> Result<Self> {
        #[cfg(unix)]
        {
            let parent = parent_of(path);
            let parent_metadata = std::fs::metadata(parent).map_err(|e| source_error(parent, e))?;
            Ok(Self {
                file: FileIdentity::of_metadata(metadata),
                parent: FileIdentity::of_metadata(&parent_metadata),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Ok(Self {
                file: identity_of(path).map_err(|e| source_error(path, e))?,
            })
        }
    }

    /// An identity for a hand-built entry in a test; it matches no object
    /// where the platform has identities.
    #[cfg(all(test, unix))]
    pub(crate) const fn unknown() -> Self {
        Self {
            file: FileIdentity::Unknown,
            parent: FileIdentity::Unknown,
        }
    }
}

/// Whether `now` is a different object than the walked `then`.
///
/// Identities of different objects, and a known one against an unknown one,
/// differ. Only two unknown identities pass: the volume itself offers none
/// (the opened file and the walked one live on it), and the regular-file
/// check is all that is left. This is deliberately stricter than the backup
/// check in `staging::replace`, which accepts an unknown identity: there the
/// alternative is leaving a backup behind, here it is reading another object.
fn differs(now: FileIdentity, then: FileIdentity) -> bool {
    match now.check(then) {
        IdentityCheck::Same => false,
        IdentityCheck::Different => true,
        IdentityCheck::Unknown => {
            now.check(now) != IdentityCheck::Unknown || then.check(then) != IdentityCheck::Unknown
        }
    }
}

/// The directory `path` is found in; the current directory for a bare name.
#[cfg(unix)]
fn parent_of(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// A source file opened without following a link and checked against the
/// walk: a regular file with the walked identity.
///
/// Only [`open_source`] builds one.
#[derive(Debug)]
pub(crate) struct VerifiedSource {
    file: File,
    metadata: Metadata,
}

impl VerifiedSource {
    /// The size of the opened handle in bytes.
    pub(crate) fn size(&self) -> u64 {
        self.metadata.len()
    }

    /// Splits into the handle and a reader bound to the handle's size, so the
    /// bytes copied can never differ from the size the header states.
    pub(crate) fn into_exact(self) -> (Metadata, ExactReader<File>) {
        let size = self.metadata.len();
        (self.metadata, ExactReader::new(self.file, size))
    }
}

/// Opens `path` and verifies it is the regular file the walk reported as
/// `walked`.
///
/// The final component is opened relative to its parent directory, never
/// through a link under [`LinkPolicy::Refuse`], and without blocking on a
/// FIFO.
///
/// # Errors
///
/// [`ArchiveError::SourceChanged`] when the object is a link (under
/// [`LinkPolicy::Refuse`]), is not a regular file, or is not the walked
/// object; a source error when it cannot be opened.
pub(crate) fn open_source(
    path: &Path,
    walked: WalkedSource,
    links: LinkPolicy,
) -> Result<VerifiedSource> {
    let file = open_nonblocking(path, walked, links)?;
    let metadata = file.metadata().map_err(|e| source_error(path, e))?;
    if !metadata.is_file() || differs(FileIdentity::of_file(&file), walked.file) {
        return Err(changed(path));
    }
    Ok(VerifiedSource { file, metadata })
}

/// Opens the content of a walked entry, as [`open_source`] does for the
/// identity the walk recorded for it.
///
/// # Errors
///
/// As [`open_source`]; an entry the walk recorded no identity for is
/// [`ArchiveError::SourceChanged`], since nothing can vouch for it.
pub(crate) fn open_entry(entry: &FilteredEntry, config: &CreationConfig) -> Result<VerifiedSource> {
    let walked = entry.identity.ok_or_else(|| changed(&entry.path))?;
    open_source(&entry.path, walked, LinkPolicy::of(config.follow_symlinks))
}

fn changed(path: &Path) -> ArchiveError {
    ArchiveError::SourceChanged {
        path: path.to_path_buf(),
    }
}

/// Platform access that needs no read permission on a directory.
#[cfg(any(target_os = "linux", target_os = "android"))]
const SEARCH_ACCESS: rustix::fs::OFlags = rustix::fs::OFlags::PATH;
#[cfg(target_vendor = "apple")]
const SEARCH_ACCESS: rustix::fs::OFlags =
    rustix::fs::OFlags::from_bits_retain(libc::O_SEARCH.cast_unsigned());
#[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "illumos"))]
const SEARCH_ACCESS: rustix::fs::OFlags =
    rustix::fs::OFlags::from_bits_retain(libc::O_SEARCH.cast_unsigned());
// OpenBSD and DragonFly have no search-only open: a directory without read
// permission is refused there, as it is by `PinnedRoot`.
#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "illumos"
    ))
))]
const SEARCH_ACCESS: rustix::fs::OFlags = rustix::fs::OFlags::RDONLY;

/// Opens the directory holding the source without blocking, with search
/// access only, and requires it to be the directory the walk saw.
#[cfg(unix)]
fn open_parent(path: &Path, walked: WalkedSource) -> Result<File> {
    use rustix::fs::Mode;
    use rustix::fs::OFlags;
    use rustix::io::Errno;

    let parent = parent_of(path);
    let base = OFlags::DIRECTORY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    let open = |access: OFlags| rustix::fs::open(parent, base | access, Mode::empty());
    let opened = match open(SEARCH_ACCESS) {
        // Older Apple kernels reject `O_SEARCH` with `EINVAL`, and NetBSD
        // with `EACCES` for a directory it cannot read.
        Err(Errno::INVAL | Errno::ACCESS) => open(OFlags::RDONLY),
        other => other,
    };
    let directory = match opened {
        Ok(fd) => File::from(fd),
        Err(Errno::NOTDIR) => return Err(changed(path)),
        Err(error) => return Err(source_error(parent, error.into())),
    };
    if differs(FileIdentity::of_file(&directory), walked.parent) {
        Err(changed(path))
    } else {
        Ok(directory)
    }
}

#[cfg(unix)]
fn open_nonblocking(path: &Path, walked: WalkedSource, links: LinkPolicy) -> Result<File> {
    use rustix::fs::Mode;
    use rustix::fs::OFlags;
    use rustix::io::Errno;

    let name = path
        .file_name()
        .ok_or_else(|| source_error(path, io::Error::from(io::ErrorKind::InvalidInput)))?;
    let directory = open_parent(path, walked)?;
    let mut flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    if links == LinkPolicy::Refuse {
        flags |= OFlags::NOFOLLOW;
    }
    match rustix::fs::openat(&directory, name, flags, Mode::empty()) {
        Ok(fd) => Ok(File::from(fd)),
        // ELOOP on Linux and macOS, EMLINK on the BSDs, when O_NOFOLLOW meets a
        // link.
        Err(Errno::LOOP | Errno::MLINK) if links == LinkPolicy::Refuse => Err(changed(path)),
        Err(error) => Err(source_error(path, error.into())),
    }
}

#[cfg(windows)]
#[expect(
    clippy::disallowed_methods,
    reason = "opens a creation source the caller named, not an extraction destination"
)]
fn open_nonblocking(path: &Path, _walked: WalkedSource, links: LinkPolicy) -> Result<File> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    let mut options = OpenOptions::new();
    options.read(true);
    if links == LinkPolicy::Refuse {
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path).map_err(|e| source_error(path, e))
}

#[cfg(not(any(unix, windows)))]
fn open_nonblocking(path: &Path, _walked: WalkedSource, _links: LinkPolicy) -> Result<File> {
    File::open(path).map_err(|e| source_error(path, e))
}

/// Marks a source that did not have exactly the bytes its header stated.
#[derive(Debug, thiserror::Error)]
#[error("source changed while it was read")]
pub(crate) struct SourceChangedMidRead;

impl IoMarker for SourceChangedMidRead {}

/// Yields exactly `size` bytes of `inner`, or fails with
/// [`SourceChangedMidRead`] when `inner` ends early or has more.
#[derive(Debug)]
pub(crate) struct ExactReader<R> {
    inner: R,
    remaining: u64,
}

impl<R> ExactReader<R> {
    pub(crate) const fn new(inner: R, size: u64) -> Self {
        Self {
            inner,
            remaining: size,
        }
    }
}

impl<R: Read> Read for ExactReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(SourceChangedMidRead.into_io()),
            };
        }
        let cap = usize::try_from(self.remaining).map_or(buf.len(), |left| left.min(buf.len()));
        let Some(window) = buf.get_mut(..cap) else {
            return Ok(0);
        };
        match self.inner.read(window)? {
            0 => Err(SourceChangedMidRead.into_io()),
            read => {
                self.remaining = self.remaining.saturating_sub(read as u64);
                Ok(read)
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::assert_matches;
    use std::io::Cursor;

    fn drain(reader: &mut impl Read) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        reader.read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn exact_reader_passes_exactly_the_stated_size() {
        let mut reader = ExactReader::new(Cursor::new(b"abcdef".to_vec()), 6);
        assert_eq!(drain(&mut reader).unwrap(), b"abcdef");
    }

    #[test]
    fn exact_reader_refuses_a_source_that_ended_early() {
        let mut reader = ExactReader::new(Cursor::new(b"abc".to_vec()), 6);
        let error = drain(&mut reader).unwrap_err();
        assert!(SourceChangedMidRead::find(&error).is_some());
    }

    #[test]
    fn exact_reader_refuses_a_source_that_grew() {
        let mut reader = ExactReader::new(Cursor::new(b"abcdef".to_vec()), 4);
        let error = drain(&mut reader).unwrap_err();
        assert!(SourceChangedMidRead::find(&error).is_some());
    }

    #[test]
    fn open_source_accepts_the_walked_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.txt");
        std::fs::write(&path, "hello").unwrap();
        let walked = WalkedSource::of(&path, &std::fs::symlink_metadata(&path).unwrap()).unwrap();
        let source = open_source(&path, walked, LinkPolicy::Refuse).unwrap();
        assert_eq!(source.size(), 5);
    }

    #[test]
    fn open_source_refuses_another_object_than_the_walked_one() {
        let dir = tempfile::tempdir().unwrap();
        let walked_path = dir.path().join("a.txt");
        let opened_path = dir.path().join("b.txt");
        std::fs::write(&walked_path, "hello").unwrap();
        std::fs::write(&opened_path, "other").unwrap();
        let walked = WalkedSource::of(
            &walked_path,
            &std::fs::symlink_metadata(&walked_path).unwrap(),
        )
        .unwrap();
        assert_matches!(
            open_source(&opened_path, walked, LinkPolicy::Refuse),
            Err(ArchiveError::SourceChanged { .. })
        );
    }

    #[cfg(unix)]
    #[test]
    fn open_source_refuses_a_link() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.txt");
        let secret = dir.path().join("secret.txt");
        std::fs::write(&path, "hello").unwrap();
        std::fs::write(&secret, "secret").unwrap();
        let walked = WalkedSource::of(&path, &std::fs::symlink_metadata(&path).unwrap()).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&secret, &path).unwrap();
        assert_matches!(
            open_source(&path, walked, LinkPolicy::Refuse),
            Err(ArchiveError::SourceChanged { .. })
        );
    }

    #[cfg(unix)]
    #[test]
    fn open_source_refuses_a_fifo_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pipe");
        crate::test_utils::make_fifo(&path);
        let walked = WalkedSource::of(&path, &std::fs::symlink_metadata(&path).unwrap()).unwrap();
        assert_matches!(
            open_source(&path, walked, LinkPolicy::Refuse),
            Err(ArchiveError::SourceChanged { .. })
        );
    }

    #[cfg(unix)]
    #[test]
    fn open_source_refuses_a_source_with_no_recorded_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.txt");
        std::fs::write(&path, "hello").unwrap();
        assert_matches!(
            open_source(&path, WalkedSource::unknown(), LinkPolicy::Refuse),
            Err(ArchiveError::SourceChanged { .. })
        );
    }

    #[cfg(unix)]
    #[test]
    fn recording_a_source_whose_directory_is_gone_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("a.txt");
        std::fs::write(&real, "hello").unwrap();
        let metadata = std::fs::symlink_metadata(&real).unwrap();
        let missing = dir.path().join("gone").join("a.txt");
        assert_matches!(
            WalkedSource::of(&missing, &metadata),
            Err(ArchiveError::SourceNotFound { .. })
        );
    }
}
