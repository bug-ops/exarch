//! Progress events of TAR extraction: every start is closed, even for a
//! skipped or refused entry.

#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

mod sink_support;

use std::path::Path;

use exarch_core::Extension;
use exarch_core::ExtractRequest;
use exarch_core::ProgressCallback;
use exarch_core::SecurityConfig;
use sink_support::tar_archive;
use sink_support::tar_file;
use sink_support::tar_symlink;
use tempfile::TempDir;

#[derive(Debug, Default)]
struct Counter {
    starts: usize,
    completes: usize,
}

impl ProgressCallback for Counter {
    fn on_entry_start(&mut self, _path: &Path, _position: exarch_core::EntryPosition) {
        self.starts += 1;
    }

    fn on_bytes_written(&mut self, _bytes: u64) {}

    fn on_entry_complete(&mut self, _path: &Path) {
        self.completes += 1;
    }

    fn on_complete(&mut self) {}
}

fn extract(entries: &[Vec<u8>], config: &SecurityConfig) -> (Counter, bool) {
    let work = TempDir::new().unwrap();
    let archive = work.path().join("a.tar");
    std::fs::write(&archive, tar_archive(entries)).unwrap();
    let mut progress = Counter::default();
    let result = ExtractRequest::new(config)
        .with_progress(&mut progress)
        .extract(&archive, work.path().join("out"));
    (progress, result.is_ok())
}

#[test]
fn a_refused_entry_is_completed() {
    let entries = [tar_file("a.txt", b"x"), tar_symlink("l", "a.txt")];

    let (progress, ok) = extract(&entries, &SecurityConfig::default());

    assert!(!ok);
    assert_eq!(progress.starts, 2);
    assert_eq!(progress.completes, progress.starts);
}

#[test]
fn a_skipped_entry_is_completed() {
    let entries = [tar_file("a.txt", b"x"), tar_file("b.bin", b"y")];
    let config = SecurityConfig::default()
        .with_allowed_extensions(vec![Extension::try_from("txt").unwrap()]);

    let (progress, ok) = extract(&entries, &config);

    assert!(ok);
    assert_eq!(progress.starts, 2);
    assert_eq!(progress.completes, progress.starts);
}
