//! Progress events of archive creation: pairing on failure and entry counts.

#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

use std::assert_matches;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::CreateRequest;
use exarch_core::CreationConfig;
use exarch_core::OutputFile;
use exarch_core::ProgressCallback;
use tempfile::TempDir;

#[derive(Debug, Default)]
struct Recorder {
    starts: Vec<(PathBuf, usize)>,
    completes: Vec<PathBuf>,
    #[cfg(unix)]
    change_to_link: Option<(PathBuf, PathBuf)>,
}

impl ProgressCallback for Recorder {
    fn on_entry_start(&mut self, path: &Path, position: exarch_core::EntryPosition) {
        let total = position.total.known().unwrap_or(0);
        self.starts.push((path.to_path_buf(), total));
        #[cfg(unix)]
        if let Some((file, target)) = &self.change_to_link {
            std::fs::remove_file(file).unwrap();
            std::os::unix::fs::symlink(target, file).unwrap();
        }
    }

    fn on_bytes_written(&mut self, _bytes: u64) {}

    fn on_entry_complete(&mut self, path: &Path) {
        self.completes.push(path.to_path_buf());
    }

    fn on_complete(&mut self) {}
}

fn one_file_source() -> TempDir {
    let src = TempDir::new().unwrap();
    std::fs::write(src.path().join("a.txt"), b"payload").unwrap();
    src
}

#[test]
fn root_directory_is_not_reported_as_an_entry() {
    for name in ["out.tar.gz", "out.zip"] {
        let src = one_file_source();
        let out = TempDir::new().unwrap();
        let mut progress = Recorder::default();

        CreateRequest::new(&CreationConfig::default())
            .with_progress(&mut progress)
            .create(&OutputFile::replace(out.path().join(name)), &[src.path()])
            .unwrap();

        assert_eq!(progress.starts.len(), 1, "{name}");
        assert_eq!(progress.starts[0].1, 1, "{name}: total");
        assert_eq!(progress.starts[0].0, Path::new("a.txt"), "{name}");
        assert_eq!(progress.completes, [PathBuf::from("a.txt")], "{name}");
    }
}

#[test]
fn directory_emptied_by_strip_prefix_is_dropped() {
    for name in ["out.tar.gz", "out.zip"] {
        let src = TempDir::new().unwrap();
        std::fs::create_dir(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("sub/a.txt"), b"payload").unwrap();
        let out = TempDir::new().unwrap();
        let mut progress = Recorder::default();
        let config = CreationConfig::default().with_strip_prefix(Some(PathBuf::from("sub")));

        CreateRequest::new(&config)
            .with_progress(&mut progress)
            .create(&OutputFile::replace(out.path().join(name)), &[src.path()])
            .unwrap();

        let started: Vec<_> = progress
            .starts
            .iter()
            .map(|(path, _)| path.clone())
            .collect();
        assert_eq!(started, [PathBuf::from("a.txt")], "{name}");
        assert_eq!(progress.completes, started, "{name}");
    }
}

#[test]
fn file_emptied_by_strip_prefix_is_refused() {
    let src = TempDir::new().unwrap();
    let file = src.path().join("a.txt");
    std::fs::write(&file, b"payload").unwrap();
    let out = TempDir::new().unwrap();
    let mut progress = Recorder::default();
    let config = CreationConfig::default().with_strip_prefix(Some(PathBuf::from("a.txt")));

    let err = CreateRequest::new(&config)
        .with_progress(&mut progress)
        .create(
            &OutputFile::replace(out.path().join("out.tar.gz")),
            &[file.as_path()],
        )
        .unwrap_err();

    assert_matches!(err, ArchiveError::InvalidConfiguration { .. }, "{err:?}");
    assert!(progress.starts.is_empty());
}

#[cfg(unix)]
#[test]
fn symlink_emptied_by_strip_prefix_is_refused() {
    let src = TempDir::new().unwrap();
    let link = src.path().join("link");
    std::os::unix::fs::symlink("target", &link).unwrap();
    let out = TempDir::new().unwrap();
    let mut progress = Recorder::default();
    let config = CreationConfig::default().with_strip_prefix(Some(PathBuf::from("link")));

    let err = CreateRequest::new(&config)
        .with_progress(&mut progress)
        .create(
            &OutputFile::replace(out.path().join("out.zip")),
            &[link.as_path()],
        )
        .unwrap_err();

    assert_matches!(err, ArchiveError::InvalidConfiguration { .. }, "{err:?}");
}

/// A source that changed since the walk is refused, for any user including
/// root.
#[cfg(unix)]
#[test]
fn failing_entry_is_still_completed() {
    for name in ["out.tar.gz", "out.zip"] {
        let src = one_file_source();
        let outside = TempDir::new().unwrap();
        let target = outside.path().join("elsewhere.txt");
        std::fs::write(&target, b"elsewhere").unwrap();
        let out = TempDir::new().unwrap();
        let mut progress = Recorder {
            change_to_link: Some((src.path().join("a.txt"), target)),
            ..Recorder::default()
        };

        let result = CreateRequest::new(&CreationConfig::default())
            .with_progress(&mut progress)
            .create(&OutputFile::replace(out.path().join(name)), &[src.path()]);

        assert_matches!(result, Err(ArchiveError::SourceChanged { .. }), "{name}");
        assert!(!progress.starts.is_empty(), "{name}");
        assert_eq!(
            progress.starts.len(),
            progress.completes.len(),
            "{name}: {progress:?}"
        );
    }
}
