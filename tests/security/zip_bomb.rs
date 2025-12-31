//! Zip bomb detection integration tests.

use exarch_core::security::EntryValidator;
use exarch_core::types::{DestDir, EntryType};
use exarch_core::{ExtractionError, SecurityConfig};
use std::path::Path;
use tempfile::TempDir;

#[test]
fn test_42_zip_bomb_simulation() {
    // 42.zip: 42 KB compressed → 4.5 PB uncompressed
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();

    let mut validator = EntryValidator::new(config, dest);

    let result = validator.validate_entry(
        Path::new("42.zip"),
        &EntryType::File,
        4_500_000_000_000_000, // 4.5 PB
        Some(42_000),          // 42 KB
        Some(0o644),
    );

    assert!(matches!(result, Err(ExtractionError::ZipBomb { .. })));
}

#[test]
fn test_high_compression_ratio_individual() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default(); // max_compression_ratio = 100.0

    let mut validator = EntryValidator::new(config, dest);

    // Ratio = 1,000,000 / 1,000 = 1000 (exceeds 100)
    let result = validator.validate_entry(
        Path::new("highly_compressed.txt"),
        &EntryType::File,
        1_000_000,
        Some(1_000),
        Some(0o644),
    );

    assert!(matches!(result, Err(ExtractionError::ZipBomb { .. })));
}

#[test]
fn test_normal_compression_allowed() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();

    let mut validator = EntryValidator::new(config, dest);

    // Ratio = 10,000 / 1,000 = 10 (within limits)
    let result = validator.validate_entry(
        Path::new("normal.txt"),
        &EntryType::File,
        10_000,
        Some(1_000),
        Some(0o644),
    );

    assert!(result.is_ok());
}

#[test]
fn test_boundary_compression_ratio() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default(); // max = 100.0

    let mut validator = EntryValidator::new(config, dest);

    // Ratio exactly at limit: 100,000 / 1,000 = 100
    let result = validator.validate_entry(
        Path::new("boundary.txt"),
        &EntryType::File,
        100_000,
        Some(1_000),
        Some(0o644),
    );

    assert!(result.is_ok(), "Compression ratio at limit should be allowed");
}

#[test]
fn test_just_over_compression_ratio() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default(); // max = 100.0

    let mut validator = EntryValidator::new(config, dest);

    // Ratio just over limit: 100,001 / 1,000 = 100.001
    let result = validator.validate_entry(
        Path::new("over_limit.txt"),
        &EntryType::File,
        100_001,
        Some(1_000),
        Some(0o644),
    );

    assert!(matches!(result, Err(ExtractionError::ZipBomb { .. })));
}

#[test]
fn test_zero_compressed_size() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();

    let mut validator = EntryValidator::new(config, dest);

    // Zero compressed size should be handled gracefully
    let result = validator.validate_entry(
        Path::new("empty.txt"),
        &EntryType::File,
        1000,
        Some(0),
        Some(0o644),
    );

    // Should not error on division by zero
    assert!(result.is_ok());
}

#[test]
fn test_uncompressed_archive() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();

    let mut validator = EntryValidator::new(config, dest);

    // No compressed size (e.g., tar without compression)
    let result = validator.validate_entry(
        Path::new("file.txt"),
        &EntryType::File,
        1_000_000,
        None,
        Some(0o644),
    );

    assert!(result.is_ok(), "Uncompressed files should not trigger zip bomb detection");
}

#[test]
fn test_permissive_compression_ratio() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let mut config = SecurityConfig::permissive();
    config.max_compression_ratio = 1000.0;

    let mut validator = EntryValidator::new(config, dest);

    // High ratio but within permissive limit
    let result = validator.validate_entry(
        Path::new("high_compression.txt"),
        &EntryType::File,
        500_000,
        Some(1_000),
        Some(0o644),
    );

    assert!(result.is_ok(), "High ratio should be allowed with permissive config");
}
