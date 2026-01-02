//! Integration tests for 7z format extraction

#![allow(clippy::unwrap_used, clippy::expect_used)]

use exarch_core::ExtractionError;
use exarch_core::SecurityConfig;
use exarch_core::formats::SevenZArchive;
use exarch_core::formats::traits::ArchiveFormat;
use std::io::Cursor;
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
        .extract(temp.path(), &SecurityConfig::default())
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

    let result = archive.extract(temp.path(), &config);
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
        .extract(temp.path(), &SecurityConfig::default())
        .unwrap();

    assert!(report.files_extracted >= 1);
    assert!(report.directories_created >= 1);
    assert!(temp.path().join("nested/subdir1/subdir2/deep.txt").exists());
}

#[test]
fn test_7z_solid_archive_rejected_at_new() {
    let data = load_fixture("solid.7z");
    let cursor = Cursor::new(data);

    let result = SevenZArchive::new(cursor);
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
    assert!(matches!(
        result.unwrap_err(),
        ExtractionError::SecurityViolation { .. }
    ));
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

    let result = archive.extract(temp.path(), &config);
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

    let result = archive.extract(temp.path(), &config);
    assert!(matches!(result, Err(ExtractionError::QuotaExceeded { .. })));
}
