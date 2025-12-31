//! Path traversal attack integration tests.
//!
//! Tests real-world CVE scenarios for path traversal vulnerabilities.

use exarch_core::security::EntryValidator;
use exarch_core::types::{DestDir, EntryType};
use exarch_core::{ExtractionError, SecurityConfig};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

#[test]
fn test_cve_2025_4517_python_tarfile_traversal() {
    // CVE-2025-4517: Python tarfile path traversal
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();
    let mut validator = EntryValidator::new(config, dest);

    let malicious_paths = vec![
        "../etc/passwd",
        "../../etc/passwd",
        "foo/../../etc/passwd",
        "foo/../../../etc/passwd",
    ];

    for path in malicious_paths {
        let result = validator.validate_entry(
            Path::new(path),
            &EntryType::File,
            1024,
            None,
            Some(0o644),
        );

        assert!(
            matches!(result, Err(ExtractionError::PathTraversal { .. })),
            "Path should be rejected: {}",
            path
        );
    }
}

#[test]
fn test_absolute_path_attack() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();
    let mut validator = EntryValidator::new(config, dest);

    #[cfg(unix)]
    let paths = vec!["/etc/passwd", "/tmp/malicious"];

    #[cfg(windows)]
    let paths = vec!["C:\\Windows\\System32", "\\\\server\\share"];

    for path in paths {
        let result = validator.validate_entry(
            Path::new(path),
            &EntryType::File,
            1024,
            None,
            Some(0o644),
        );

        assert!(result.is_err(), "Absolute path should be rejected: {}", path);
    }
}

#[test]
fn test_null_byte_injection() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();
    let mut validator = EntryValidator::new(config, dest);

    #[cfg(unix)]
    {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let bytes = b"file\0.txt";
        let os_str = OsStr::from_bytes(bytes);
        let path = PathBuf::from(os_str);

        let result = validator.validate_entry(&path, &EntryType::File, 1024, None, Some(0o644));

        assert!(matches!(
            result,
            Err(ExtractionError::SecurityViolation { .. })
        ));
    }
}

#[test]
fn test_deep_path_nesting() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();
    let mut validator = EntryValidator::new(config, dest);

    // Create a path with depth exceeding max_path_depth (32 by default)
    let deep_path = (0..40).map(|i| format!("dir{}", i)).collect::<Vec<_>>().join("/");

    let result = validator.validate_entry(
        Path::new(&deep_path),
        &EntryType::File,
        1024,
        None,
        Some(0o644),
    );

    assert!(result.is_err(), "Deep path should be rejected");
}

#[test]
fn test_banned_path_components() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();
    let mut validator = EntryValidator::new(config, dest);

    let banned_paths = vec![
        ".git/config",
        ".ssh/id_rsa",
        ".gnupg/private-keys-v1.d/key.key",
        ".aws/credentials",
        ".kube/config",
        ".docker/config.json",
        ".env",
    ];

    for path in banned_paths {
        let result = validator.validate_entry(
            Path::new(path),
            &EntryType::File,
            1024,
            None,
            Some(0o644),
        );

        assert!(
            result.is_err(),
            "Banned path component should be rejected: {}",
            path
        );
    }
}

#[test]
fn test_case_insensitive_banned_components() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();
    let mut validator = EntryValidator::new(config, dest);

    // Try to bypass ban with case variations
    let paths = vec![".Git/config", ".SSH/id_rsa", ".GNUPG/key", ".Aws/credentials"];

    for path in paths {
        let result = validator.validate_entry(
            Path::new(path),
            &EntryType::File,
            1024,
            None,
            Some(0o644),
        );

        assert!(
            result.is_err(),
            "Case variation should be rejected: {}",
            path
        );
    }
}

#[test]
fn test_safe_paths_allowed() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();
    let mut validator = EntryValidator::new(config, dest);

    let safe_paths = vec![
        "README.md",
        "src/main.rs",
        "foo/bar/baz.txt",
        "data/config.json",
        "docs/guide.md",
    ];

    for path in safe_paths {
        let result = validator.validate_entry(
            Path::new(path),
            &EntryType::File,
            1024,
            None,
            Some(0o644),
        );

        assert!(result.is_ok(), "Safe path should be allowed: {}", path);
    }
}
