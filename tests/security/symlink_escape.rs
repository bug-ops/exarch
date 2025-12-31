//! Symlink escape attack integration tests.

use exarch_core::security::EntryValidator;
use exarch_core::types::{DestDir, EntryType};
use exarch_core::{ExtractionError, SecurityConfig};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

#[test]
fn test_symlink_absolute_target() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let mut config = SecurityConfig::default();
    config.allow_symlinks = true;

    let mut validator = EntryValidator::new(config, dest);

    let result = validator.validate_entry(
        Path::new("malicious_link"),
        &EntryType::Symlink {
            target: PathBuf::from("/etc/passwd"),
        },
        0,
        None,
        None,
    );

    assert!(matches!(
        result,
        Err(ExtractionError::SymlinkEscape { .. })
    ));
}

#[test]
fn test_symlink_parent_traversal() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let mut config = SecurityConfig::default();
    config.allow_symlinks = true;

    let mut validator = EntryValidator::new(config, dest);

    let result = validator.validate_entry(
        Path::new("safe/link"),
        &EntryType::Symlink {
            target: PathBuf::from("../../etc/passwd"),
        },
        0,
        None,
        None,
    );

    assert!(matches!(
        result,
        Err(ExtractionError::SymlinkEscape { .. })
    ));
}

#[test]
fn test_symlink_disabled_by_default() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();

    let mut validator = EntryValidator::new(config, dest);

    let result = validator.validate_entry(
        Path::new("link"),
        &EntryType::Symlink {
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
fn test_symlink_relative_safe() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let mut config = SecurityConfig::default();
    config.allow_symlinks = true;

    let mut validator = EntryValidator::new(config, dest);

    let result = validator.validate_entry(
        Path::new("foo/link"),
        &EntryType::Symlink {
            target: PathBuf::from("../bar/target.txt"),
        },
        0,
        None,
        None,
    );

    assert!(result.is_ok(), "Safe relative symlink should be allowed");
}

#[test]
fn test_symlink_same_directory() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let mut config = SecurityConfig::default();
    config.allow_symlinks = true;

    let mut validator = EntryValidator::new(config, dest);

    let result = validator.validate_entry(
        Path::new("link"),
        &EntryType::Symlink {
            target: PathBuf::from("target.txt"),
        },
        0,
        None,
        None,
    );

    assert!(result.is_ok(), "Same directory symlink should be allowed");
}

#[test]
fn test_symlink_chain_escape() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let mut config = SecurityConfig::default();
    config.allow_symlinks = true;

    let mut validator = EntryValidator::new(config, dest);

    // Try to escape via multiple parent traversals
    let result = validator.validate_entry(
        Path::new("a/b/c/link"),
        &EntryType::Symlink {
            target: PathBuf::from("../../../../etc/passwd"),
        },
        0,
        None,
        None,
    );

    assert!(matches!(
        result,
        Err(ExtractionError::SymlinkEscape { .. })
    ));
}
