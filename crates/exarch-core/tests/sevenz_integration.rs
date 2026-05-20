//! Integration tests for 7z format extraction

#![allow(clippy::unwrap_used, clippy::expect_used)]

use exarch_core::ExtractionError;
use exarch_core::ExtractionOptions;
use exarch_core::ProgressCallback;
use exarch_core::SecurityConfig;
use exarch_core::formats::SevenZArchive;
use exarch_core::formats::traits::ArchiveFormat;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use tempfile::TempDir;

fn load_fixture(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&path).expect("fixture should exist")
}

#[test]
fn test_7z_extraction_via_trait() {
    let data = load_fixture("simple.7z");
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();

    let temp = TempDir::new().unwrap();
    let report = archive
        .extract(
            temp.path(),
            &SecurityConfig::default(),
            &ExtractionOptions::default(),
            &mut exarch_core::NoopProgress,
        )
        .unwrap();

    assert_eq!(report.files_extracted, 2);
    assert!(temp.path().join("simple/file1.txt").exists());
    assert!(temp.path().join("simple/file2.txt").exists());

    // Verify file contents
    let content1 = std::fs::read_to_string(temp.path().join("simple/file1.txt")).unwrap();
    assert_eq!(content1, "hello world\n");
}

#[test]
fn test_7z_security_config_integration() {
    let data = load_fixture("large-file.7z");
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();

    let temp = TempDir::new().unwrap();
    let config = SecurityConfig {
        max_file_size: 1024, // 1 KB limit
        ..SecurityConfig::default()
    };

    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut exarch_core::NoopProgress,
    );
    assert!(matches!(result, Err(ExtractionError::QuotaExceeded { .. })));
}

#[test]
fn test_7z_format_name() {
    let data = load_fixture("simple.7z");
    let cursor = Cursor::new(data);
    let archive = SevenZArchive::new(cursor).unwrap();

    assert_eq!(archive.format_name(), "7z");
}

#[test]
fn test_7z_nested_directories() {
    let data = load_fixture("nested-dirs.7z");
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();

    let temp = TempDir::new().unwrap();
    let report = archive
        .extract(
            temp.path(),
            &SecurityConfig::default(),
            &ExtractionOptions::default(),
            &mut exarch_core::NoopProgress,
        )
        .unwrap();

    assert!(report.files_extracted >= 1);
    assert!(report.directories_created >= 1);
    assert!(temp.path().join("nested/subdir1/subdir2/deep.txt").exists());
}

#[test]
fn test_7z_solid_archive_rejected_at_new() {
    let data = load_fixture("solid.7z");
    let cursor = Cursor::new(data);

    // new() now succeeds (just caches is_solid flag)
    let mut archive = SevenZArchive::new(cursor).unwrap();

    // Rejection happens in extract() with default config
    let temp = TempDir::new().unwrap();
    let result = archive.extract(
        temp.path(),
        &SecurityConfig::default(),
        &ExtractionOptions::default(),
        &mut exarch_core::NoopProgress,
    );

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ExtractionError::SecurityViolation { .. }
    ));
}

#[test]
fn test_7z_encrypted_archive_rejected_at_new() {
    let data = load_fixture("encrypted.7z");
    let cursor = Cursor::new(data);

    let result = SevenZArchive::new(cursor);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, ExtractionError::SecurityViolation { .. }));

    // Verify error message is helpful
    let msg = err.to_string();
    assert!(msg.contains("encrypted"), "error should mention encryption");
    assert!(
        msg.contains("not supported"),
        "error should say not supported"
    );
    assert!(
        msg.contains("Decrypt") || msg.contains("decrypt"),
        "error should suggest decrypting externally"
    );
}

#[test]
fn test_7z_quota_file_count() {
    let data = load_fixture("simple.7z"); // 2 files
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();

    let temp = TempDir::new().unwrap();
    let config = SecurityConfig {
        max_file_count: 1, // Only 1 file allowed
        ..SecurityConfig::default()
    };

    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut exarch_core::NoopProgress,
    );
    assert!(matches!(result, Err(ExtractionError::QuotaExceeded { .. })));
}

#[test]
fn test_7z_quota_total_size() {
    let data = load_fixture("simple.7z");
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();

    let temp = TempDir::new().unwrap();
    let config = SecurityConfig {
        max_total_size: 10, // Very small limit
        ..SecurityConfig::default()
    };

    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut exarch_core::NoopProgress,
    );
    assert!(matches!(result, Err(ExtractionError::QuotaExceeded { .. })));
}

// ============================================================================
// Phase 10.4: Solid Archive Integration Tests
// ============================================================================

/// M-4: Integration test for solid extraction success
#[test]
fn test_7z_solid_archive_extraction_success() {
    let data = load_fixture("solid.7z");
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();

    let temp = TempDir::new().unwrap();
    let config = SecurityConfig {
        allow_solid_archives: true,
        max_solid_block_memory: 100 * 1024 * 1024, // 100 MB
        ..SecurityConfig::default()
    };

    let report = archive
        .extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut exarch_core::NoopProgress,
        )
        .unwrap();

    assert!(
        report.files_extracted > 0,
        "should extract files from solid archive"
    );
    assert_eq!(archive.format_name(), "7z");
}

/// M-4: Integration test for solid + file count quota interaction
#[test]
fn test_7z_solid_archive_with_file_count_quota() {
    let data = load_fixture("solid.7z");
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();

    let temp = TempDir::new().unwrap();
    let config = SecurityConfig {
        allow_solid_archives: true,
        max_solid_block_memory: 100 * 1024 * 1024,
        max_file_count: 1, // Solid has more than 1 file
        ..SecurityConfig::default()
    };

    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut exarch_core::NoopProgress,
    );
    assert!(matches!(result, Err(ExtractionError::QuotaExceeded { .. })));
}

// ============================================================================
// Phase 10.5: Symlink/Hardlink Detection Integration Tests
// ============================================================================

/// Test: Unix symlink extraction (documented limitation - extracted as file)
#[test]
#[cfg(unix)]
fn test_7z_unix_symlink_extracted_as_file() {
    let data = load_fixture("symlink-unix.7z");
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();

    let temp = TempDir::new().unwrap();
    let config = SecurityConfig::default();

    // Current behavior: succeeds, extracts symlink as file
    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut exarch_core::NoopProgress,
    );
    assert!(
        result.is_ok(),
        "Unix symlink should extract as file (documented limitation): {result:?}"
    );

    let report = result.unwrap();
    assert_eq!(
        report.files_extracted, 2,
        "should extract exactly 2 files (target.txt and link.txt)"
    );

    // Verify link.txt exists as regular file (not symlink)
    let link_path = temp.path().join("symlink-test/link.txt");
    assert!(link_path.exists(), "link.txt should exist");
    assert!(link_path.is_file(), "link.txt should be a regular file");

    // Verify it's not a symlink (symlink_metadata doesn't follow symlinks)
    let metadata = std::fs::symlink_metadata(&link_path).unwrap();
    assert!(
        !metadata.file_type().is_symlink(),
        "should NOT create actual symlink"
    );

    // Content should be the target path (symlink metadata stored as file data)
    let content = std::fs::read_to_string(&link_path).unwrap();
    assert_eq!(
        content.trim(),
        "target.txt",
        "file should contain symlink target path"
    );
}

/// Test: Hardlink extraction (documented limitation - extracted as separate
/// files)
#[test]
fn test_7z_hardlink_extracted_as_duplicate_files() {
    let data = load_fixture("hardlink.7z");
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();

    let temp = TempDir::new().unwrap();
    let config = SecurityConfig::default();

    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut exarch_core::NoopProgress,
    );
    assert!(
        result.is_ok(),
        "hardlink should extract as separate files: {result:?}"
    );

    let report = result.unwrap();
    assert_eq!(report.files_extracted, 2, "should extract both files");

    // Both files should exist as separate regular files
    let original = temp.path().join("hardlink-test/original.txt");
    let link = temp.path().join("hardlink-test/link.txt");

    assert!(original.exists(), "original.txt should exist");
    assert!(link.exists(), "link.txt should exist");
    assert!(original.is_file(), "original.txt should be a file");
    assert!(link.is_file(), "link.txt should be a file");

    // Content should be identical (both files have same data)
    let original_content = std::fs::read_to_string(&original).unwrap();
    let link_content = std::fs::read_to_string(&link).unwrap();
    assert_eq!(
        original_content, link_content,
        "both files should have identical content"
    );

    // Verify they are NOT hardlinked (different inodes on Unix)
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let original_meta = std::fs::metadata(&original).unwrap();
        let link_meta = std::fs::metadata(&link).unwrap();
        assert_ne!(
            original_meta.ino(),
            link_meta.ino(),
            "files should NOT be hardlinked (different inodes)"
        );
    }
}

// ============================================================================
// Regression test: progress callbacks fire per-entry (not bulk)
// ============================================================================

#[derive(Debug, PartialEq)]
enum ProgressEvent {
    Start(String),
    Complete(String),
}

struct RecordingProgress {
    events: Arc<Mutex<Vec<ProgressEvent>>>,
}

impl ProgressCallback for RecordingProgress {
    fn on_entry_start(&mut self, path: &Path, _total: usize, _index: usize) {
        self.events
            .lock()
            .unwrap()
            .push(ProgressEvent::Start(path.to_string_lossy().into_owned()));
    }

    fn on_entry_complete(&mut self, path: &Path) {
        self.events
            .lock()
            .unwrap()
            .push(ProgressEvent::Complete(path.to_string_lossy().into_owned()));
    }

    fn on_bytes_written(&mut self, _bytes: u64) {}

    fn on_complete(&mut self) {}
}

/// Regression test for #191: `on_entry_start` and `on_entry_complete` must
/// interleave per-entry (start(A), complete(A), start(B), complete(B)),
/// not be batched (all starts then all completes).
#[test]
fn test_7z_progress_interleaves_per_entry() {
    let data = load_fixture("simple.7z"); // 2-file archive
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();

    let events = Arc::new(Mutex::new(Vec::new()));
    let mut progress = RecordingProgress {
        events: Arc::clone(&events),
    };

    let temp = TempDir::new().unwrap();
    archive
        .extract(
            temp.path(),
            &SecurityConfig::default(),
            &ExtractionOptions::default(),
            &mut progress,
        )
        .unwrap();

    let events = events.lock().unwrap();
    // Must have at least 4 events for 2 files
    assert!(
        events.len() >= 4,
        "expected at least 4 events (start+complete per file), got {}: {events:?}",
        events.len()
    );

    // Verify interleaving: every Start must be immediately followed by Complete
    // for the same path, i.e. no two consecutive Starts.
    for pair in events.chunks(2) {
        match pair {
            [ProgressEvent::Start(s), ProgressEvent::Complete(c)] => {
                assert_eq!(
                    s, c,
                    "start and complete paths must match: start={s}, complete={c}"
                );
            }
            _ => panic!("expected (Start, Complete) pairs but got: {pair:?}"),
        }
    }
}

/// Regression test for #201: `bytes_written` must accumulate correctly across
/// multiple files via `checked_add` (no silent integer overflow).
#[test]
fn test_7z_bytes_written_accumulates_correctly() {
    let data = load_fixture("simple.7z"); // 2-file archive: "hello world\n" each
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();

    let temp = TempDir::new().unwrap();
    let report = archive
        .extract(
            temp.path(),
            &SecurityConfig::default(),
            &ExtractionOptions::default(),
            &mut exarch_core::NoopProgress,
        )
        .unwrap();

    // The fixture contains 2 files totalling 25 bytes (verified via `7z l`).
    // The exact value matters: checked_add accumulates per-file sizes correctly.
    assert_eq!(
        report.bytes_written, 25,
        "bytes_written must equal the total bytes extracted, got {}",
        report.bytes_written
    );
}

// ============================================================================
// Regression tests for issues #207 and #210: PartialExtraction report
// ============================================================================

/// Regression test for #207: the `ExtractionReport` accumulated before a quota
/// error must survive and be returned inside `PartialExtraction`.
///
/// Previously, `SevenZArchive::extract` used a local `accumulated` variable
/// inside the closure that was dropped when `decompress_with_extract_fn`
/// returned `Err`, so `PartialExtraction` always carried an empty report.
#[test]
fn test_7z_partial_extraction_accurate_report() {
    // Build an in-memory 7z archive with two entries sharing the same path.
    // The extraction callback writes the first entry successfully, then fails
    // with a "duplicate entry" error on the second — triggering PartialExtraction.
    // Pre-validation cannot detect this because it only validates paths, not
    // on-disk state.
    let mut buf = std::io::Cursor::new(Vec::<u8>::new());
    {
        let mut writer = ArchiveWriter::new(&mut buf).unwrap();
        writer
            .push_archive_entry(
                ArchiveEntry::new_file("file.txt"),
                Some(b"first content".as_ref()),
            )
            .unwrap();
        writer
            .push_archive_entry(
                ArchiveEntry::new_file("file.txt"),
                Some(b"second content".as_ref()),
            )
            .unwrap();
        writer.finish().unwrap();
    }
    buf.set_position(0);
    let data = buf.into_inner();

    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();
    let out_temp = TempDir::new().unwrap();

    // skip_duplicates=false so the second "file.txt" triggers an error after
    // the first has already been written to disk.
    let options = ExtractionOptions {
        skip_duplicates: false,
        ..ExtractionOptions::default()
    };
    let result = archive.extract(
        out_temp.path(),
        &SecurityConfig::default(),
        &options,
        &mut exarch_core::NoopProgress,
    );

    let Err(ExtractionError::PartialExtraction { report, .. }) = result else {
        panic!("expected PartialExtraction, got: {result:?}");
    };
    assert!(
        report.files_extracted > 0,
        "report must record at least one extracted file, got files_extracted={}",
        report.files_extracted
    );
    assert!(
        report.bytes_written > 0,
        "report must record bytes written, got bytes_written={}",
        report.bytes_written
    );
}

/// Regression test for #207: when the very first entry triggers a security
/// error (zero items extracted), the result must NOT be wrapped in
/// `PartialExtraction` — the raw error is returned directly.
///
/// This matches the TAR/ZIP behavior added in the same fix.
#[test]
fn test_7z_no_partial_extraction_when_zero_items() {
    // Build an in-memory 7z archive whose first (and only) entry has a
    // path-traversal name so validation fails immediately.
    let mut buf = std::io::Cursor::new(Vec::<u8>::new());
    {
        let mut writer = ArchiveWriter::new(&mut buf).unwrap();
        let entry = ArchiveEntry::new_file("../evil.txt");
        writer
            .push_archive_entry(entry, Some(b"pwned".as_ref()))
            .unwrap();
        writer.finish().unwrap();
    }
    buf.set_position(0);
    let data = buf.into_inner();

    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();
    let out_temp = TempDir::new().unwrap();

    let result = archive.extract(
        out_temp.path(),
        &SecurityConfig::default(),
        &ExtractionOptions::default(),
        &mut exarch_core::NoopProgress,
    );

    assert!(result.is_err(), "expected an error, got Ok");
    assert!(
        !matches!(result, Err(ExtractionError::PartialExtraction { .. })),
        "must NOT be PartialExtraction when zero items were written; got: {result:?}"
    );
}
