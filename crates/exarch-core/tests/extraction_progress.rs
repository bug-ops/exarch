//! Progress events of TAR extraction: every start is closed, even for a
//! skipped or refused entry.

#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

mod sink_support;

use std::path::Path;

use exarch_core::Extension;
use exarch_core::ExtensionFilter;
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
    let config = SecurityConfig::default().with_allowed_extensions(
        ExtensionFilter::only(vec![Extension::try_from("txt").unwrap()]).unwrap(),
    );

    let (progress, ok) = extract(&entries, &config);

    assert!(ok);
    assert_eq!(progress.starts, 2);
    assert_eq!(progress.completes, progress.starts);
}

/// Cancels once `limit` entries were announced.
#[derive(Debug, Default)]
struct CancelAfter {
    limit: usize,
    starts: usize,
}

impl ProgressCallback for CancelAfter {
    fn on_entry_start(&mut self, _path: &Path, _position: exarch_core::EntryPosition) {
        self.starts += 1;
    }

    fn on_bytes_written(&mut self, _bytes: u64) {}

    fn on_entry_complete(&mut self, _path: &Path) {}

    fn on_complete(&mut self) {}

    fn is_cancelled(&mut self) -> bool {
        self.starts >= self.limit
    }
}

fn three_files() -> (TempDir, std::path::PathBuf) {
    let work = TempDir::new().unwrap();
    let archive = work.path().join("a.tar");
    let entries = [
        tar_file("a.txt", b"a"),
        tar_file("b.txt", b"b"),
        tar_file("c.txt", b"c"),
    ];
    std::fs::write(&archive, tar_archive(&entries)).unwrap();
    (work, archive)
}

fn cancelled(error: &exarch_core::ArchiveError) -> bool {
    match error {
        exarch_core::ArchiveError::Cancelled => true,
        exarch_core::ArchiveError::PartialExtraction(partial) => cancelled(partial.cause()),
        _ => false,
    }
}

#[test]
fn an_in_place_extraction_stops_at_the_first_entry_after_cancel() {
    let (work, archive) = three_files();
    let out = work.path().join("out");
    let mut progress = CancelAfter {
        limit: 1,
        starts: 0,
    };

    let error = ExtractRequest::new(&SecurityConfig::default())
        .with_progress(&mut progress)
        .extract(&archive, &out)
        .unwrap_err();

    assert!(cancelled(&error), "{error:?}");
    assert_eq!(progress.starts, 1, "no entry is announced after the cancel");
    assert!(
        out.join("a.txt").is_file(),
        "an in-place extraction keeps its writes"
    );
    assert!(!out.join("b.txt").exists());
    assert!(!out.join("c.txt").exists());
}

#[test]
fn list_stops_at_the_first_entry_after_cancel() {
    let (_work, archive) = three_files();
    let mut progress = CancelAfter {
        limit: 1,
        starts: 0,
    };

    let error = exarch_core::ListRequest::new(&SecurityConfig::default())
        .with_progress(&mut progress)
        .list(&archive)
        .unwrap_err();

    assert!(cancelled(&error), "{error:?}");
    assert_eq!(progress.starts, 1);
}

#[test]
fn verify_stops_at_the_first_entry_after_cancel() {
    let (_work, archive) = three_files();
    let mut progress = CancelAfter {
        limit: 1,
        starts: 0,
    };

    let error = exarch_core::VerifyRequest::new(&SecurityConfig::default())
        .with_progress(&mut progress)
        .verify(&archive)
        .unwrap_err();

    assert!(cancelled(&error), "{error:?}");
    assert_eq!(progress.starts, 1);
}
