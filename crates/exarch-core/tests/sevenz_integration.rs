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

    // new() now succeeds (just caches is_solid flag)
    let mut archive = SevenZArchive::new(cursor).unwrap();

    // Rejection happens in extract() with default config
    let temp = TempDir::new().unwrap();
    let result = archive.extract(temp.path(), &SecurityConfig::default());

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

    let report = archive.extract(temp.path(), &config).unwrap();

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

    let result = archive.extract(temp.path(), &config);
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
    let result = archive.extract(temp.path(), &config);
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

    let result = archive.extract(temp.path(), &config);
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
