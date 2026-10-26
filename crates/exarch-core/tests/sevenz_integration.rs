//! Integration tests for 7z format extraction

#![allow(clippy::unwrap_used, clippy::expect_used)]

use exarch_core::ArchiveError;
use exarch_core::ExtractionOptions;
use exarch_core::ProgressCallback;
use exarch_core::SecurityConfig;
use exarch_core::formats::SevenZArchive;
use exarch_core::formats::traits::ArchiveFormat;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use std::assert_matches;
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
            &SecurityConfig::default().validate().unwrap(),
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
    let config = SecurityConfig::default()
        .with_max_file_size(1024)
        .with_max_compression_ratio(10_000.0)
        .validate()
        .unwrap();

    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut exarch_core::NoopProgress,
    );
    assert_matches!(result, Err(ArchiveError::QuotaExceeded { .. }));
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
            &SecurityConfig::default().validate().unwrap(),
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
        &SecurityConfig::default().validate().unwrap(),
        &ExtractionOptions::default(),
        &mut exarch_core::NoopProgress,
    );

    assert!(result.is_err());
    assert_matches!(result.unwrap_err(), ArchiveError::SecurityViolation { .. });
}

#[test]
fn test_7z_encrypted_archive_rejected_at_new() {
    let data = load_fixture("encrypted.7z");
    let cursor = Cursor::new(data);

    let result = SevenZArchive::new(cursor);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_matches!(err, ArchiveError::SecurityViolation { .. });

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

/// Regression test for #397 / upstream sevenz-rust2 issue #127: a malformed
/// block header could overflow while summing attacker-controlled coder
/// stream counts, panicking in debug builds and bypassing the stream-count
/// bound in release builds. Fixed upstream in sevenz-rust2 0.21.4 (via
/// `checked_add`). The fixture is ported verbatim from upstream's own
/// regression test (`tests/resources/issue_127_coder_stream_overflow.bin`,
/// `tests/decompression_tests.rs::malformed_coder_stream_counts_are_rejected`,
/// Apache-2.0, from the sevenz-rust2 0.21.4 source distribution).
/// `SevenZArchive::new` parses the header eagerly, so the malformed archive
/// must be rejected gracefully here rather than panicking.
#[test]
fn test_7z_malformed_coder_stream_overflow_rejected_gracefully() {
    let data = load_fixture("malformed-coder-stream-overflow.7z");
    let cursor = Cursor::new(data);

    let result = SevenZArchive::new(cursor);

    assert!(
        result.is_err(),
        "malformed archive with overflowing coder stream count must be rejected, got: {result:?}"
    );
}

#[test]
fn test_7z_quota_file_count() {
    let data = load_fixture("simple.7z"); // 2 files
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();

    let temp = TempDir::new().unwrap();
    let config = SecurityConfig::default()
        .with_max_file_count(1)
        .validate()
        .unwrap();

    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut exarch_core::NoopProgress,
    );
    assert_matches!(result, Err(ArchiveError::QuotaExceeded { .. }));
}

#[test]
fn test_7z_quota_total_size() {
    let data = load_fixture("simple.7z");
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();

    let temp = TempDir::new().unwrap();
    let config = SecurityConfig::default()
        .with_max_total_size(10)
        .validate()
        .unwrap();

    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut exarch_core::NoopProgress,
    );
    assert_matches!(result, Err(ArchiveError::QuotaExceeded { .. }));
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
    let config = SecurityConfig::default()
        .with_allow_solid_archives(true)
        .with_max_solid_block_memory(100 * 1024 * 1024)
        .validate()
        .unwrap();

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
    let config = SecurityConfig::default()
        .with_allow_solid_archives(true)
        .with_max_solid_block_memory(100 * 1024 * 1024)
        .with_max_file_count(1)
        .validate()
        .unwrap();

    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut exarch_core::NoopProgress,
    );
    assert_matches!(result, Err(ArchiveError::QuotaExceeded { .. }));
}

// ============================================================================
// Phase 10.5: Symlink/Hardlink Detection Integration Tests
// ============================================================================

/// Test: the fixture's `link.txt` carries a regular-file Unix mode (0o100644)
/// whose data is a target path, so it extracts as a file. A real `S_IFLNK`
/// entry is refused (see `sevenz_reparse_point.rs`).
#[test]
#[cfg(unix)]
fn test_7z_regular_mode_entry_with_target_text_extracts_as_file() {
    let data = load_fixture("symlink-unix.7z");
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();

    let temp = TempDir::new().unwrap();
    let config = SecurityConfig::default().validate().unwrap();

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
    let config = SecurityConfig::default().validate().unwrap();

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
            &SecurityConfig::default().validate().unwrap(),
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
            &SecurityConfig::default().validate().unwrap(),
            &ExtractionOptions::default(),
            &mut exarch_core::NoopProgress,
        )
        .unwrap();

    // The fixture contains 2 files totalling 25 bytes (verified via `7z l`).
    // The exact value matters: checked_add accumulates per-file sizes
    // correctly.
    assert_eq!(
        report.bytes_written, 25,
        "bytes_written must equal the total bytes extracted, got {}",
        report.bytes_written
    );
}

// ============================================================================
// Regression tests for issues #207 and #210: PartialExtraction report
// ============================================================================

/// Regression test for #207: quota errors caught in the pre-validation pass
/// return `QuotaExceeded` directly (no partial state on disk), not wrapped in
/// `PartialExtraction`. This verifies the fix for the accumulated-report bug
/// is moot for 7z because pre-validation prevents any extraction from starting.
#[test]
fn test_7z_partial_extraction_accurate_report() {
    // simple.7z contains 2 files totalling 25 bytes.  A quota smaller than
    // the total triggers QuotaExceeded during pre-validation, before any file
    // is written.  The result is a direct error, not PartialExtraction.
    let data = load_fixture("simple.7z");
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();
    let out_temp = TempDir::new().unwrap();

    let config = SecurityConfig::default()
        .with_max_total_size(20)
        .validate()
        .unwrap();
    let result = archive.extract(
        out_temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut exarch_core::NoopProgress,
    );

    assert_matches!(
        result,
        Err(ArchiveError::QuotaExceeded { .. }),
        "pre-validation quota check must return QuotaExceeded directly, got: {result:?}"
    );
    // No files should have been written — the output directory is empty.
    let entries: Vec<_> = std::fs::read_dir(out_temp.path()).unwrap().collect();
    assert!(
        entries.is_empty(),
        "no files should be on disk after a pre-validation quota failure"
    );
}

/// Regression test for #323: `skip_duplicates=false` must overwrite an existing
/// file rather than returning an error, matching TAR/ZIP handler behaviour.
#[test]
fn test_7z_force_overwrite_duplicate_entry() {
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

    let options = ExtractionOptions::default().with_skip_duplicates(false);
    let report = archive
        .extract(
            out_temp.path(),
            &SecurityConfig::default().validate().unwrap(),
            &options,
            &mut exarch_core::NoopProgress,
        )
        .expect("force-overwrite must succeed, not return an error");

    assert_eq!(
        report.files_extracted, 2,
        "both entries must be counted as extracted"
    );
    let content = std::fs::read_to_string(out_temp.path().join("file.txt")).unwrap();
    assert_eq!(
        content, "second content",
        "second entry must overwrite the first"
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
        &SecurityConfig::default().validate().unwrap(),
        &ExtractionOptions::default(),
        &mut exarch_core::NoopProgress,
    );

    assert!(result.is_err(), "expected an error, got Ok");
    assert!(
        !matches!(result, Err(ArchiveError::PartialExtraction { .. })),
        "must NOT be PartialExtraction when zero items were written; got: {result:?}"
    );
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn push_number(out: &mut Vec<u8>, value: u64) {
    out.push(0xFF);
    out.extend_from_slice(&value.to_le_bytes());
}

/// Builds a minimal one-file 7z with an unencoded header and a Copy coder.
/// `content` is stored as the packed stream; `unpack_size` and
/// `declared_pack_size` are written to the header as given.
fn build_plain_sevenz(
    name: &str,
    content: &[u8],
    unpack_size: u64,
    declared_pack_size: u64,
) -> Vec<u8> {
    build_plain_sevenz_packs(name, content, unpack_size, &[declared_pack_size])
}

/// Like [`build_plain_sevenz`], but the header declares one pack stream per
/// entry of `declared_pack_sizes` while the single Copy coder consumes only the
/// first; `content` holds the bytes of all of them.
fn build_plain_sevenz_packs(
    name: &str,
    content: &[u8],
    unpack_size: u64,
    declared_pack_sizes: &[u64],
) -> Vec<u8> {
    let mut header = vec![0x01, 0x04];
    header.extend_from_slice(&[0x06, 0x00]);
    push_number(&mut header, declared_pack_sizes.len() as u64);
    header.push(0x09);
    for &size in declared_pack_sizes {
        push_number(&mut header, size);
    }
    header.push(0x00);
    header.extend_from_slice(&[0x07, 0x0B, 0x01, 0x00, 0x01, 0x01, 0x00, 0x0C]);
    push_number(&mut header, unpack_size);
    header.extend_from_slice(&[0x00, 0x08, 0x00, 0x00]);

    let mut names: Vec<u8> = vec![0x00];
    for unit in name.encode_utf16().chain(std::iter::once(0)) {
        names.extend_from_slice(&unit.to_le_bytes());
    }
    header.extend_from_slice(&[0x05, 0x01, 0x11]);
    push_number(&mut header, names.len() as u64);
    header.extend_from_slice(&names);
    header.extend_from_slice(&[0x00, 0x00]);

    let mut start = Vec::new();
    start.extend_from_slice(&(content.len() as u64).to_le_bytes());
    start.extend_from_slice(&(header.len() as u64).to_le_bytes());
    start.extend_from_slice(&crc32(&header).to_le_bytes());

    let mut out = vec![b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    out.extend_from_slice(&crc32(&start).to_le_bytes());
    out.extend_from_slice(&start);
    out.extend_from_slice(content);
    out.extend_from_slice(&header);
    out
}

#[test]
fn sevenz_plain_builder_round_trips_well_formed_archive() {
    let data = build_plain_sevenz("a.txt", b"hello", 5, 5);
    let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();
    let out = TempDir::new().unwrap();
    archive
        .extract(
            out.path(),
            &SecurityConfig::default().validate().unwrap(),
            &ExtractionOptions::default(),
            &mut exarch_core::NoopProgress,
        )
        .unwrap();
    assert_eq!(std::fs::read(out.path().join("a.txt")).unwrap(), b"hello");
}

#[test]
fn sevenz_rejects_pack_sizes_beyond_archive_length() {
    let data = build_plain_sevenz("a.txt", b"hello", 5, 1_000_000);

    assert_matches!(
        SevenZArchive::new(Cursor::new(data.clone())),
        Err(ArchiveError::InvalidArchive(_))
    );

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("a.7z");
    std::fs::write(&path, &data).unwrap();
    let config = SecurityConfig::default();
    assert_matches!(
        exarch_core::list_archive(&path, &config),
        Err(ArchiveError::InvalidArchive(_))
    );
    assert_matches!(
        exarch_core::verify_archive(&path, &config),
        Err(ArchiveError::InvalidArchive(_))
    );
}

#[test]
fn sevenz_extract_enforces_compression_ratio() {
    let data = build_plain_sevenz("a.txt", &[0u8; 100], 1_000_000, 100);
    let mut archive = SevenZArchive::new(Cursor::new(data.clone())).unwrap();
    let out = TempDir::new().unwrap();

    let result = archive.extract(
        out.path(),
        &SecurityConfig::default().validate().unwrap(),
        &ExtractionOptions::default(),
        &mut exarch_core::NoopProgress,
    );

    assert_matches!(result, Err(ArchiveError::ZipBomb(_)));
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("a.7z");
    std::fs::write(&path, &data).unwrap();
    let report = exarch_core::verify_archive(&path, &SecurityConfig::default()).unwrap();
    assert_eq!(report.status(), exarch_core::VerificationStatus::Fail);
}

#[test]
fn sevenz_unreferenced_trailing_pack_stream_does_not_dilute_the_ratio() {
    let mut content = vec![0u8; 100];
    content.extend(vec![0u8; 1_000_000]);
    let data = build_plain_sevenz_packs("a.txt", &content, 1_000_000, &[100, 1_000_000]);
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("a.7z");
    std::fs::write(&path, &data).unwrap();

    let report = exarch_core::verify_archive(&path, &SecurityConfig::default()).unwrap();

    assert!(
        report
            .issues()
            .iter()
            .any(|i| i.category == exarch_core::IssueCategory::ZipBomb),
        "unreferenced pack stream hid the ratio: {:?}",
        report.issues()
    );
}

#[test]
fn sevenz_solid_archive_is_not_flagged_by_ratio_check() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("solid.7z");
    std::fs::write(&path, load_fixture("solid.7z")).unwrap();

    let report = exarch_core::verify_archive(&path, &SecurityConfig::default()).unwrap();
    assert!(
        report
            .issues()
            .iter()
            .all(|i| i.category != exarch_core::IssueCategory::ZipBomb),
        "unexpected ratio issue: {:?}",
        report.issues()
    );
}

#[test]
fn sevenz_ratio_check_runs_before_duplicate_skip() {
    let data = build_plain_sevenz("a.txt", &[0u8; 100], 1_000_000, 100);
    let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();
    let out = TempDir::new().unwrap();
    std::fs::write(out.path().join("a.txt"), b"existing").unwrap();

    let result = archive.extract(
        out.path(),
        &SecurityConfig::default().validate().unwrap(),
        &ExtractionOptions::default().with_skip_duplicates(true),
        &mut exarch_core::NoopProgress,
    );

    assert_matches!(result, Err(ArchiveError::ZipBomb(_)));
    assert_eq!(
        std::fs::read(out.path().join("a.txt")).unwrap(),
        b"existing"
    );
}

/// Swaps an already-created directory for a symlink to `outside` when the
/// entry named `trigger` starts.
#[cfg(unix)]
struct SwapDirForSymlink<'a> {
    trigger: &'a str,
    dir: std::path::PathBuf,
    outside: std::path::PathBuf,
}

#[cfg(unix)]
impl ProgressCallback for SwapDirForSymlink<'_> {
    fn on_entry_start(&mut self, path: &Path, _total: usize, _index: usize) {
        if path.ends_with(self.trigger) {
            std::fs::remove_dir_all(&self.dir).unwrap();
            std::os::unix::fs::symlink(&self.outside, &self.dir).unwrap();
        }
    }

    fn on_entry_complete(&mut self, _path: &Path) {}

    fn on_bytes_written(&mut self, _bytes: u64) {}

    fn on_complete(&mut self) {}
}

/// Regression test for #740: a path check that fails inside the entry callback
/// reaches the caller as the typed security error, not as
/// `InvalidArchive("7z error: ...")`.
#[cfg(unix)]
#[test]
fn directory_swapped_for_symlink_mid_extraction_reports_a_typed_security_error() {
    let bytes = load_fixture("nested-dirs.7z");
    let dest = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let mut progress = SwapDirForSymlink {
        trigger: "file.txt",
        dir: dest.path().join("nested/subdir1/subdir2"),
        outside: outside.path().to_path_buf(),
    };
    let config = SecurityConfig::default().validate().unwrap();
    let mut archive = SevenZArchive::new(Cursor::new(bytes)).unwrap();

    let err = archive
        .extract(
            dest.path(),
            &config,
            &ExtractionOptions::default(),
            &mut progress,
        )
        .unwrap_err();

    let ArchiveError::PartialExtraction { source, .. } = err else {
        panic!("expected PartialExtraction, got {err:?}");
    };
    assert_matches!(
        *source,
        ArchiveError::PathTraversal { .. } | ArchiveError::SymlinkEscape { .. }
    );
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
}
