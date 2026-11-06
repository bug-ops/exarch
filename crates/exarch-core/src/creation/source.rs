//! Classification of failures to read a creation source.

use crate::ArchiveError;
use crate::IoContext;
use crate::Result;
use std::io;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;

/// Classifies an I/O failure on the creation source `path`.
///
/// A source that is gone (`NotFound`, or a parent that is not a directory) is
/// [`ArchiveError::SourceNotFound`]; every other failure keeps its cause in
/// [`ArchiveError::SourceNotAccessible`].
pub(crate) fn source_error(path: &Path, error: io::Error) -> ArchiveError {
    if matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    ) {
        ArchiveError::SourceNotFound {
            path: path.to_path_buf(),
        }
    } else {
        ArchiveError::SourceNotAccessible {
            path: path.to_path_buf(),
            error,
        }
    }
}

/// Classifies a failure of the directory walk below `fallback`.
///
/// An I/O cause is a source failure at the path walkdir names; a walk error
/// without one (a symlink loop) stays a context-carrying `Io` error.
pub(crate) fn walk_error(error: walkdir::Error, fallback: &Path) -> ArchiveError {
    let path: PathBuf = error.path().unwrap_or(fallback).to_path_buf();
    let text = error.to_string();
    error.into_io_error().map_or_else(
        || {
            ArchiveError::Io(io::Error::other(IoContext::new(
                "directory walk failed",
                text,
            )))
        },
        |cause| source_error(&path, cause),
    )
}

fn duplicate(error: &io::Error) -> io::Error {
    error.raw_os_error().map_or_else(
        || io::Error::new(error.kind(), error.to_string()),
        io::Error::from_raw_os_error,
    )
}

/// Wraps a source reader and keeps the first read error that is not
/// `Interrupted` in `fault`.
///
/// A copy into the archive fails with one `io::Error` whether the read or the
/// write side broke; the slot tells the two apart so only a read fault is
/// reported as an unreadable source.
pub(crate) struct FaultSlotReader<'a, R> {
    inner: R,
    fault: &'a mut Option<io::Error>,
}

impl<'a, R> FaultSlotReader<'a, R> {
    pub(crate) const fn new(inner: R, fault: &'a mut Option<io::Error>) -> Self {
        Self { inner, fault }
    }
}

impl<R: Read> Read for FaultSlotReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let result = self.inner.read(buf);
        if let Err(error) = &result
            && error.kind() != io::ErrorKind::Interrupted
            && self.fault.is_none()
        {
            *self.fault = Some(duplicate(error));
        }
        result
    }
}

/// Resolves the outcome of a copy out of the source `path`: a recorded read
/// fault is a source error, any other failure is the writer's.
pub(crate) fn copy_outcome<T>(
    result: io::Result<T>,
    fault: Option<io::Error>,
    path: &Path,
) -> Result<T> {
    result.map_err(|error| fault.map_or_else(|| error.into(), |fault| source_error(path, fault)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::assert_matches;

    struct Failing(io::ErrorKind);

    impl Read for Failing {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(self.0))
        }
    }

    #[test]
    fn a_missing_source_is_not_found_and_any_other_failure_is_not_accessible() {
        let path = Path::new("src");
        assert_matches!(
            source_error(path, io::Error::from(io::ErrorKind::NotFound)),
            ArchiveError::SourceNotFound { .. }
        );
        assert_matches!(
            source_error(path, io::Error::from(io::ErrorKind::PermissionDenied)),
            ArchiveError::SourceNotAccessible { .. }
        );
    }

    #[test]
    fn a_read_fault_is_recorded_and_wins_over_the_copy_error() {
        let mut fault = None;
        let mut reader = FaultSlotReader::new(Failing(io::ErrorKind::PermissionDenied), &mut fault);
        let result = io::copy(&mut reader, &mut io::sink());
        let err = copy_outcome(result, fault, Path::new("src")).unwrap_err();
        assert_matches!(
            err,
            ArchiveError::SourceNotAccessible { error, .. }
                if error.kind() == io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn an_interrupted_read_is_not_a_fault() {
        let mut fault = None;
        let mut reader = FaultSlotReader::new(Failing(io::ErrorKind::Interrupted), &mut fault);
        let _ = reader.read(&mut [0u8; 1]);
        assert!(fault.is_none());
    }

    #[test]
    fn a_write_failure_without_a_read_fault_stays_an_io_error() {
        let result: io::Result<()> = Err(io::Error::from(io::ErrorKind::WriteZero));
        assert_matches!(
            copy_outcome(result, None, Path::new("src")).unwrap_err(),
            ArchiveError::Io(_)
        );
    }

    #[cfg(unix)]
    mod unreadable {
        use super::*;
        use crate::CreationConfig;
        use crate::create_archive;
        use crate::creation::staged::ExcludedOutput;
        use crate::creation::walker::collect_entries;
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use tempfile::TempDir;

        fn unreadable_tree() -> Option<(TempDir, PathBuf)> {
            let dir = TempDir::new().unwrap();
            let tree = dir.path().join("tree");
            fs::create_dir(&tree).unwrap();
            fs::write(tree.join("ok.txt"), "x").unwrap();
            let file = tree.join("unread.txt");
            fs::write(&file, "y").unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
            fs::File::open(&file).is_err().then_some((dir, tree))
        }

        #[test]
        fn an_unreadable_file_is_reported_with_its_path_in_every_format() {
            let Some((dir, tree)) = unreadable_tree() else {
                return;
            };
            for name in ["o.tar", "o.tar.gz", "o.zip"] {
                let out = dir.path().join(name);
                let err = create_archive(&out, &[&tree], &CreationConfig::default()).unwrap_err();
                assert_matches!(
                    &err,
                    ArchiveError::SourceNotAccessible { path, error }
                        if path.ends_with("unread.txt")
                            && error.kind() == io::ErrorKind::PermissionDenied
                );
                assert!(!out.exists(), "{name}");
            }
        }

        #[test]
        fn an_unreadable_top_level_source_is_not_accessible_not_missing() {
            let Some((dir, tree)) = unreadable_tree() else {
                return;
            };
            let file = tree.join("unread.txt");
            let out = dir.path().join("o.tar");
            let err = create_archive(&out, &[&file], &CreationConfig::default()).unwrap_err();
            assert_matches!(err, ArchiveError::SourceNotAccessible { .. });
        }

        #[test]
        fn an_unreadable_directory_is_not_accessible() {
            let dir = TempDir::new().unwrap();
            let locked = dir.path().join("locked");
            fs::create_dir(&locked).unwrap();
            fs::write(locked.join("f"), "x").unwrap();
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
            if fs::read_dir(&locked).is_ok() {
                return;
            }
            let result = create_archive(
                dir.path().join("o.tar"),
                &[&locked],
                &CreationConfig::default(),
            );
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
            assert_matches!(
                result.unwrap_err(),
                ArchiveError::SourceNotAccessible { path, .. } if path.ends_with("locked")
            );
        }
        #[test]
        fn a_symlink_loop_keeps_the_walk_context_instead_of_naming_a_source() {
            let dir = TempDir::new().unwrap();
            let tree = dir.path().join("tree");
            fs::create_dir(&tree).unwrap();
            std::os::unix::fs::symlink("../tree", tree.join("loop")).unwrap();
            let config = CreationConfig::default().with_follow_symlinks(true);
            let err = create_archive(dir.path().join("o.tar"), &[&tree], &config).unwrap_err();
            assert_matches!(
                &err,
                ArchiveError::Io(error)
                    if error
                        .get_ref()
                        .and_then(|inner| inner.downcast_ref::<IoContext>())
                        .is_some_and(|context| context.context == "directory walk failed")
            );
        }

        #[test]
        fn the_top_level_lstat_tells_a_missing_source_from_an_unreadable_parent() {
            let dir = TempDir::new().unwrap();
            let locked = dir.path().join("locked");
            fs::create_dir(&locked).unwrap();
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
            let probe = locked.join("child");
            let denied = probe
                .symlink_metadata()
                .is_err_and(|e| e.kind() == io::ErrorKind::PermissionDenied);
            let behind_lock = collect_entries(
                &[&probe],
                &CreationConfig::default(),
                &ExcludedOutput::none(),
            );
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
            let missing = collect_entries(
                &[locked.join("missing")],
                &CreationConfig::default(),
                &ExcludedOutput::none(),
            );
            assert_matches!(missing.unwrap_err(), ArchiveError::SourceNotFound { .. });
            if denied {
                assert_matches!(
                    behind_lock.unwrap_err(),
                    ArchiveError::SourceNotAccessible { path, .. } if path == probe
                );
            }
        }
    }
}
