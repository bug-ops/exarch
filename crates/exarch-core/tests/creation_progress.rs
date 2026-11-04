//! Progress events of archive creation: pairing on failure and entry counts.

#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::ProgressCallback;
use exarch_core::create_archive_with_progress;
use exarch_core::creation::CreationConfig;
use tempfile::TempDir;

#[derive(Debug, Default)]
struct Recorder {
    starts: Vec<(PathBuf, usize)>,
    completes: Vec<PathBuf>,
}

impl ProgressCallback for Recorder {
    fn on_entry_start(&mut self, path: &Path, total: usize, _current: usize) {
        self.starts.push((path.to_path_buf(), total));
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

        create_archive_with_progress(
            out.path().join(name),
            &[src.path()],
            &CreationConfig::default(),
            &mut progress,
        )
        .unwrap();

        assert_eq!(progress.starts.len(), 1, "{name}");
        assert_eq!(progress.starts[0].1, 1, "{name}: total");
        assert_eq!(progress.starts[0].0, Path::new("a.txt"), "{name}");
        assert_eq!(progress.completes, [PathBuf::from("a.txt")], "{name}");
    }
}

#[test]
fn directory_emptied_by_strip_prefix_is_dropped() {
    let src = TempDir::new().unwrap();
    std::fs::create_dir(src.path().join("sub")).unwrap();
    std::fs::write(src.path().join("sub/a.txt"), b"payload").unwrap();
    let out = TempDir::new().unwrap();
    let mut progress = Recorder::default();
    let config = CreationConfig::default().with_strip_prefix(Some(PathBuf::from("sub")));

    create_archive_with_progress(
        out.path().join("out.tar.gz"),
        &[src.path()],
        &config,
        &mut progress,
    )
    .unwrap();

    assert!(
        progress
            .starts
            .iter()
            .all(|(path, _)| !path.as_os_str().is_empty()),
        "{:?}",
        progress.starts
    );
    assert_eq!(progress.starts.len(), progress.completes.len());
}

#[test]
fn file_emptied_by_strip_prefix_is_refused() {
    let src = TempDir::new().unwrap();
    let file = src.path().join("a.txt");
    std::fs::write(&file, b"payload").unwrap();
    let out = TempDir::new().unwrap();
    let mut progress = Recorder::default();
    let config = CreationConfig::default().with_strip_prefix(Some(PathBuf::from("a.txt")));

    let err = create_archive_with_progress(
        out.path().join("out.tar.gz"),
        &[file.as_path()],
        &config,
        &mut progress,
    )
    .unwrap_err();

    assert!(
        matches!(err, ArchiveError::InvalidConfiguration { .. }),
        "{err:?}"
    );
    assert!(progress.starts.is_empty());
}

#[cfg(unix)]
#[test]
fn failing_entry_is_still_completed() {
    use std::os::unix::fs::PermissionsExt;

    for name in ["out.tar.gz", "out.zip"] {
        let src = one_file_source();
        let secret = src.path().join("secret.txt");
        std::fs::write(&secret, b"hidden").unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::File::open(&secret).is_ok() {
            continue;
        }
        let out = TempDir::new().unwrap();
        let mut progress = Recorder::default();

        let result = create_archive_with_progress(
            out.path().join(name),
            &[src.path()],
            &CreationConfig::default(),
            &mut progress,
        );

        assert!(result.is_err(), "{name}");
        assert_eq!(
            progress.starts.len(),
            progress.completes.len(),
            "{name}: {progress:?}"
        );
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}
