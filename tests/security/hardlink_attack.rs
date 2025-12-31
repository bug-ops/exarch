//! Hardlink attack integration tests.

use exarch_core::security::EntryValidator;
use exarch_core::types::{DestDir, EntryType};
use exarch_core::{ExtractionError, SecurityConfig};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

#[test]
fn test_hardlink_absolute_target() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let mut config = SecurityConfig::default();
    config.allow_hardlinks = true;

    let mut validator = EntryValidator::new(config, dest);

    let result = validator.validate_entry(
        Path::new("malicious_hardlink"),
        &EntryType::Hardlink {
            target: PathBuf::from("/etc/passwd"),
        },
        0,
        None,
        None,
    );

    assert!(matches!(
        result,
        Err(ExtractionError::HardlinkEscape { .. })
    ));
}

#[test]
fn test_hardlink_parent_traversal() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let mut config = SecurityConfig::default();
    config.allow_hardlinks = true;

    let mut validator = EntryValidator::new(config, dest);

    let result = validator.validate_entry(
        Path::new("link"),
        &EntryType::Hardlink {
            target: PathBuf::from("../../etc/passwd"),
        },
        0,
        None,
        None,
    );

    assert!(matches!(
        result,
        Err(ExtractionError::HardlinkEscape { .. })
    ));
}

#[test]
fn test_hardlink_disabled_by_default() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();

    let mut validator = EntryValidator::new(config, dest);

    let result = validator.validate_entry(
        Path::new("link"),
        &EntryType::Hardlink {
            target: PathBuf::from("target.txt"),
        },
        0,
        None,
        None,
    );

    assert!(matches!(
        result,
        Err(ExtractionError::SecurityViolation { .. })
    ));
}

#[test]
fn test_hardlink_relative_safe() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let mut config = SecurityConfig::default();
    config.allow_hardlinks = true;

    let mut validator = EntryValidator::new(config, dest);

    let result = validator.validate_entry(
        Path::new("foo/link"),
        &EntryType::Hardlink {
            target: PathBuf::from("foo/target.txt"),
        },
        0,
        None,
        None,
    );

    assert!(result.is_ok(), "Safe relative hardlink should be allowed");
}

#[test]
fn test_hardlink_same_directory() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let mut config = SecurityConfig::default();
    config.allow_hardlinks = true;

    let mut validator = EntryValidator::new(config, dest);

    let result = validator.validate_entry(
        Path::new("link"),
        &EntryType::Hardlink {
            target: PathBuf::from("target.txt"),
        },
        0,
        None,
        None,
    );

    assert!(result.is_ok(), "Same directory hardlink should be allowed");
}

#[test]
fn test_multiple_hardlinks_tracked() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let mut config = SecurityConfig::default();
    config.allow_hardlinks = true;

    let mut validator = EntryValidator::new(config, dest);

    validator
        .validate_entry(
            Path::new("link1"),
            &EntryType::Hardlink {
                target: PathBuf::from("target1.txt"),
            },
            0,
            None,
            None,
        )
        .unwrap();

    validator
        .validate_entry(
            Path::new("link2"),
            &EntryType::Hardlink {
                target: PathBuf::from("target2.txt"),
            },
            0,
            None,
            None,
        )
        .unwrap();

    let report = validator.finish();
    assert_eq!(report.hardlinks_tracked, 2);
}

#[test]
fn test_hardlink_chain_escape() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let mut config = SecurityConfig::default();
    config.allow_hardlinks = true;

    let mut validator = EntryValidator::new(config, dest);

    // Try to escape via multiple parent traversals
    let result = validator.validate_entry(
        Path::new("a/b/c/link"),
        &EntryType::Hardlink {
            target: PathBuf::from("../../../../etc/passwd"),
        },
        0,
        None,
        None,
    );

    assert!(matches!(
        result,
        Err(ExtractionError::HardlinkEscape { .. })
    ));
}
