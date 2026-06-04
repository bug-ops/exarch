//! Integration tests for exarch-core.
//!
//! These tests verify end-to-end workflows with real filesystem operations.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]

mod security;

use exarch_core::ArchiveError;
use exarch_core::SecurityConfig;
use exarch_core::types::DestDir;
use exarch_core::types::SafePath;
use exarch_core::types::SafeSymlink;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use tempfile::NamedTempFile;
use tempfile::TempDir;

#[test]
fn test_full_safe_path_workflow() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();

    // Create actual file
    let file_path = temp.path().join("test_file.txt");
    fs::write(&file_path, "content").unwrap();

    // Validate existing file
    let safe = SafePath::validate(&PathBuf::from("test_file.txt"), &dest, &config).unwrap();
    let final_path = dest.join(&safe);
    assert!(final_path.exists());
    assert_eq!(fs::read_to_string(&final_path).unwrap(), "content");
}

#[test]
fn test_dest_dir_join_safe_path() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();

    let safe = SafePath::validate(&PathBuf::from("foo/bar.txt"), &dest, &config).unwrap();
    let joined = dest.join(&safe);

    assert!(joined.starts_with(dest.as_path()));
    assert!(joined.ends_with("foo/bar.txt"));
}

#[test]
fn test_nested_directory_creation() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();

    // Validate nested path
    let safe = SafePath::validate(&PathBuf::from("a/b/c/d/file.txt"), &dest, &config).unwrap();
    let final_path = dest.join(&safe);

    // Create parent directories
    if let Some(parent) = final_path.parent() {
        fs::create_dir_all(parent).unwrap();
    }

    // Create file
    fs::write(&final_path, "nested content").unwrap();
    assert!(final_path.exists());
}

#[test]
fn test_symlink_workflow() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let mut config = SecurityConfig::default();
    config.allowed.symlinks = true;

    // Create target file
    let target_path = temp.path().join("target.txt");
    fs::write(&target_path, "target content").unwrap();

    // Validate symlink
    let link = SafePath::validate(&PathBuf::from("link.txt"), &dest, &config).unwrap();
    let target = PathBuf::from("target.txt");
    let symlink = SafeSymlink::validate(&link, &target, &dest, &config).unwrap();

    assert_eq!(symlink.link_path(), PathBuf::from("link.txt").as_path());
    assert_eq!(symlink.target_path(), PathBuf::from("target.txt").as_path());

    // Create actual symlink on filesystem
    #[cfg(unix)]
    {
        let link_path = dest.join(&link);
        std::os::unix::fs::symlink(&target, &link_path).unwrap();
        assert!(link_path.exists());
    }
}

#[test]
fn test_path_traversal_blocked() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();

    let paths = vec![
        "../etc/passwd",
        "foo/../../etc/passwd",
        "a/b/../../../etc/passwd",
    ];

    for path in paths {
        let result = SafePath::validate(&PathBuf::from(path), &dest, &config);
        assert!(
            matches!(result, Err(ArchiveError::PathTraversal { .. })),
            "Path {path} should be rejected"
        );
    }
}

#[test]
fn test_banned_components_blocked() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();

    let paths = vec![".git/config", "user/.ssh/id_rsa", "home/.gnupg/key"];

    for path in paths {
        let result = SafePath::validate(&PathBuf::from(path), &dest, &config);
        assert!(
            matches!(result, Err(ArchiveError::SecurityViolation { .. })),
            "Path {path} should be rejected"
        );
    }
}

#[test]
fn test_multiple_files_same_directory() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();

    // Create directory
    let dir_path = temp.path().join("subdir");
    fs::create_dir(&dir_path).unwrap();

    // Validate and create multiple files
    let files = vec!["subdir/file1.txt", "subdir/file2.txt", "subdir/file3.txt"];

    for file in &files {
        let safe = SafePath::validate(&PathBuf::from(file), &dest, &config).unwrap();
        let final_path = dest.join(&safe);
        fs::write(&final_path, format!("content of {file}")).unwrap();
        assert!(final_path.exists());
    }

    // Verify all files exist
    assert_eq!(fs::read_dir(&dir_path).unwrap().count(), 3);
}

#[test]
fn test_relative_symlink_resolution() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let mut config = SecurityConfig::default();
    config.allowed.symlinks = true;

    // Create directory structure: a/b/target.txt and a/link.txt -> b/target.txt
    let a_dir = temp.path().join("a");
    let b_dir = a_dir.join("b");
    fs::create_dir_all(&b_dir).unwrap();

    let target_path = b_dir.join("target.txt");
    fs::write(&target_path, "target").unwrap();

    // Validate symlink in a/ pointing to b/target.txt
    let link = SafePath::validate(&PathBuf::from("a/link.txt"), &dest, &config).unwrap();
    let target = PathBuf::from("b/target.txt");
    let symlink = SafeSymlink::validate(&link, &target, &dest, &config).unwrap();

    assert!(symlink.link_path().starts_with("a"));
    assert!(symlink.target_path().starts_with("b"));
}

#[test]
fn test_depth_limit_enforced() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let mut config = SecurityConfig::default();
    config.max_path_depth = 5;

    // Path with 5 components should be allowed
    let ok_path = "a/b/c/d/e";
    let result = SafePath::validate(&PathBuf::from(ok_path), &dest, &config);
    assert!(result.is_ok());

    // Path with 6 components should be rejected
    let bad_path = "a/b/c/d/e/f";
    let result = SafePath::validate(&PathBuf::from(bad_path), &dest, &config);
    assert!(matches!(
        result,
        Err(ArchiveError::SecurityViolation { .. })
    ));
}

/// Regression test for #200: `verify_archive` must not share a temp dir across
/// concurrent calls (TOCTOU race). Each call must create an isolated temp dir.
#[test]
fn verify_archive_concurrent_calls_do_not_collide() {
    // Build a minimal valid tar archive to use as fixture.
    fn make_tar() -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let data = b"regression test content";
        let mut header = tar::Header::new_gnu();
        header.set_path("hello.txt").unwrap();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, &data[..]).unwrap();
        builder.into_inner().unwrap()
    }

    // Write the fixture to a temp file that all threads will share (read-only).
    let mut fixture = NamedTempFile::with_suffix(".tar").unwrap();
    fixture.write_all(&make_tar()).unwrap();
    fixture.flush().unwrap();
    let fixture_path = Arc::new(fixture.path().to_path_buf());

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let path = Arc::clone(&fixture_path);
            thread::spawn(move || {
                let config = SecurityConfig::default();
                exarch_core::verify_archive(path.as_ref(), &config)
            })
        })
        .collect();

    for handle in handles {
        let result = handle.join().expect("thread panicked");
        assert!(
            result.is_ok(),
            "concurrent verify_archive failed: {result:?}"
        );
    }
}
