//! `EntryValidator` zip bomb / compression ratio detection regression tests.
//!
//! Exercises `EntryValidator::validate_entry` directly against declared
//! compressed/uncompressed size pairs: the classic 42.zip shape, ratio
//! boundary values, the HIGH-001 zero-compressed-size bypass fix, and the
//! permissive-config override.

#![allow(clippy::unwrap_used)]

use exarch_core::ArchiveError;
use exarch_core::QuotaResource;
use exarch_core::SecurityConfig;
use exarch_core::security::EntryValidator;
use exarch_core::types::DestDir;
use exarch_core::types::EntryType;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn test_42_zip_bomb_rejected_by_default_file_size_quota() {
    // Under the default config (50 MB max_file_size), the File branch's
    // quota reservation runs before the ratio check (validator.rs), so a
    // 42.zip-shaped entry is rejected as a file-size QuotaExceeded, not a
    // ZipBomb. This pins that ordering: swapping the two checks would leave
    // this test green with a different error variant, but the assertion
    // that a 42.zip shape is rejected under the default config would then
    // silently rely on the ratio check alone.
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default().validate().unwrap();

    let mut validator = EntryValidator::new(&config, &dest);

    let result = validator.validate_entry(
        Path::new("42.zip"),
        &EntryType::File,
        4_500_000_000_000_000, // 4.5 PB
        Some(42_000),          // 42 KB
        Some(0o644),
        None,
    );

    assert!(matches!(
        result,
        Err(ArchiveError::QuotaExceeded {
            resource: QuotaResource::FileSize { .. }
        })
    ));
}

#[test]
fn test_42_zip_bomb_simulation() {
    // 42.zip: 42 KB compressed -> 4.5 PB uncompressed. Quota limits are
    // raised so the declared size is charged against the ratio check, not
    // rejected earlier by `max_file_size`/`max_total_size` — this isolates
    // the ratio-detection path under test.
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default()
        .with_max_file_size(u64::MAX)
        .with_max_total_size(u64::MAX)
        .validate()
        .unwrap();

    let mut validator = EntryValidator::new(&config, &dest);

    let result = validator.validate_entry(
        Path::new("42.zip"),
        &EntryType::File,
        4_500_000_000_000_000, // 4.5 PB
        Some(42_000),          // 42 KB
        Some(0o644),
        None,
    );

    assert!(matches!(result, Err(ArchiveError::ZipBomb { .. })));
}

#[test]
fn test_high_compression_ratio_individual() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default().validate().unwrap(); // max_compression_ratio = 100.0

    let mut validator = EntryValidator::new(&config, &dest);

    // Ratio = 1,000,000 / 1,000 = 1000 (exceeds 100).
    let result = validator.validate_entry(
        Path::new("highly_compressed.txt"),
        &EntryType::File,
        1_000_000,
        Some(1_000),
        Some(0o644),
        None,
    );

    assert!(matches!(result, Err(ArchiveError::ZipBomb { .. })));
}

#[test]
fn test_normal_compression_allowed() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default().validate().unwrap();

    let mut validator = EntryValidator::new(&config, &dest);

    // Ratio = 10,000 / 1,000 = 10 (within limits).
    let result = validator.validate_entry(
        Path::new("normal.txt"),
        &EntryType::File,
        10_000,
        Some(1_000),
        Some(0o644),
        None,
    );

    assert!(result.is_ok());
}

#[test]
fn test_boundary_compression_ratio() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default().validate().unwrap(); // max = 100.0

    let mut validator = EntryValidator::new(&config, &dest);

    // Ratio exactly at limit: 100,000 / 1,000 = 100.
    let result = validator.validate_entry(
        Path::new("boundary.txt"),
        &EntryType::File,
        100_000,
        Some(1_000),
        Some(0o644),
        None,
    );

    assert!(
        result.is_ok(),
        "Compression ratio at limit should be allowed"
    );
}

#[test]
fn test_just_over_compression_ratio() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default().validate().unwrap(); // max = 100.0

    let mut validator = EntryValidator::new(&config, &dest);

    // Ratio just over limit: 100,001 / 1,000 = 100.001.
    let result = validator.validate_entry(
        Path::new("over_limit.txt"),
        &EntryType::File,
        100_001,
        Some(1_000),
        Some(0o644),
        None,
    );

    assert!(matches!(result, Err(ArchiveError::ZipBomb { .. })));
}

#[test]
fn test_zero_compressed_nonzero_uncompressed_rejected() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default().validate().unwrap();

    let mut validator = EntryValidator::new(&config, &dest);

    // HIGH-001: a stored (compressed_size == 0) entry claiming nonzero
    // uncompressed content is invalid archive metadata, not a "free" ratio
    // that divides cleanly to zero — this closes what used to be a
    // zip-bomb-detection bypass via a fabricated zero compressed size.
    let result = validator.validate_entry(
        Path::new("empty.txt"),
        &EntryType::File,
        1000,
        Some(0),
        Some(0o644),
        None,
    );

    assert!(matches!(result, Err(ArchiveError::InvalidArchive(_))));
}

#[test]
fn test_both_sizes_zero_allowed() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default().validate().unwrap();

    let mut validator = EntryValidator::new(&config, &dest);

    // Both declared sizes zero (a genuinely empty file) remains valid.
    let result = validator.validate_entry(
        Path::new("empty.txt"),
        &EntryType::File,
        0,
        Some(0),
        Some(0o644),
        None,
    );

    assert!(result.is_ok());
}

#[test]
fn test_uncompressed_archive() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default().validate().unwrap();

    let mut validator = EntryValidator::new(&config, &dest);

    // No compressed size (e.g., tar without compression).
    let result = validator.validate_entry(
        Path::new("file.txt"),
        &EntryType::File,
        1_000_000,
        None,
        Some(0o644),
        None,
    );

    assert!(
        result.is_ok(),
        "Uncompressed files should not trigger zip bomb detection"
    );
}

#[test]
fn test_permissive_compression_ratio() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::permissive()
        .with_max_compression_ratio(1000.0)
        .validate()
        .unwrap();

    let mut validator = EntryValidator::new(&config, &dest);

    // High ratio but within permissive limit.
    let result = validator.validate_entry(
        Path::new("high_compression.txt"),
        &EntryType::File,
        500_000,
        Some(1_000),
        Some(0o644),
        None,
    );

    assert!(
        result.is_ok(),
        "High ratio should be allowed with permissive config"
    );
}
