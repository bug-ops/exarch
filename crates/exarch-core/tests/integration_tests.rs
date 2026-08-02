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
use exarch_core::create_archive;
use exarch_core::creation::CreationConfig;
use exarch_core::extract_archive;
use exarch_core::formats::detect::ArchiveType;
use exarch_core::types::DestDir;
use exarch_core::types::SafePath;
use exarch_core::types::SafeSymlink;
use std::assert_matches;
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
        assert_matches!(
            result,
            Err(ArchiveError::PathTraversal { .. }),
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
        assert_matches!(
            result,
            Err(ArchiveError::SecurityViolation { .. }),
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
    assert_matches!(result, Err(ArchiveError::SecurityViolation { .. }));
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

// ============================================================================
// Roundtrip tests: create → extract → verify content
// ============================================================================

/// Source layout written by all roundtrip tests.
///
/// Returns `(src_dir, files)` where `files` is a list of `(relative_path,
/// content)` pairs that can be used to assert the extracted output.
fn make_roundtrip_source() -> (TempDir, Vec<(&'static str, &'static [u8])>) {
    let src = TempDir::new().unwrap();
    let files: Vec<(&str, &[u8])> = vec![
        ("hello.txt", b"hello world"),
        ("data.bin", b"\x00\x01\x02\x03\xfe\xff"),
        ("nested/deep.txt", b"deep content"),
        ("nested/sub/leaf.txt", b"leaf content"),
    ];
    for (rel, content) in &files {
        let dest = src.path().join(rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&dest, content).unwrap();
    }
    (src, files)
}

fn assert_roundtrip_content(extract_dir: &TempDir, files: &[(&str, &[u8])]) {
    for (rel, expected) in files {
        let path = extract_dir.path().join(rel);
        let actual =
            fs::read(&path).unwrap_or_else(|e| panic!("cannot read extracted file {rel}: {e}"));
        assert_eq!(
            actual.as_slice(),
            *expected,
            "content mismatch for {rel}: got {} bytes, expected {} bytes",
            actual.len(),
            expected.len()
        );
    }
}

macro_rules! roundtrip_test {
    ($name:ident, $ext:literal, $format:expr) => {
        #[test]
        fn $name() {
            let (src, files) = make_roundtrip_source();
            let archive_dir = TempDir::new().unwrap();
            let archive = archive_dir.path().join(concat!("out.", $ext));

            let config = CreationConfig::default()
                .with_include_hidden(true)
                .with_format(Some($format));
            create_archive(&archive, &[src.path()], &config).unwrap();
            assert!(archive.exists(), "archive file must exist after creation");

            let extract_dir = TempDir::new().unwrap();
            extract_archive(&archive, extract_dir.path(), &SecurityConfig::default()).unwrap();

            assert_roundtrip_content(&extract_dir, &files);
        }
    };
}

roundtrip_test!(roundtrip_tar_gz, "tar.gz", ArchiveType::TarGz);
roundtrip_test!(roundtrip_tar_bz2, "tar.bz2", ArchiveType::TarBz2);
roundtrip_test!(roundtrip_tar_xz, "tar.xz", ArchiveType::TarXz);
roundtrip_test!(roundtrip_tar_zst, "tar.zst", ArchiveType::TarZst);
roundtrip_test!(roundtrip_zip, "zip", ArchiveType::Zip);

// ============================================================================
// Empty directory preservation tests (issue #400)
// ============================================================================

/// Source layout with a top-level empty directory and a nested empty
/// directory, alongside a regular file so the tree isn't degenerate.
fn make_empty_dir_source() -> TempDir {
    let src = TempDir::new().unwrap();
    fs::write(src.path().join("file.txt"), b"content").unwrap();
    fs::create_dir(src.path().join("empty1")).unwrap();
    fs::create_dir_all(src.path().join("empty2/empty3")).unwrap();
    src
}

fn assert_empty_dirs_preserved(extract_dir: &TempDir) {
    for rel in ["empty1", "empty2", "empty2/empty3"] {
        let path = extract_dir.path().join(rel);
        assert!(
            path.is_dir(),
            "expected directory {rel} to exist after extraction"
        );
    }
    let leaf_entries: Vec<_> = fs::read_dir(extract_dir.path().join("empty2/empty3"))
        .unwrap()
        .collect();
    assert!(
        leaf_entries.is_empty(),
        "expected empty2/empty3 to be empty, found {} entries",
        leaf_entries.len()
    );
}

macro_rules! empty_dir_roundtrip_test {
    ($name:ident, $ext:literal, $format:expr) => {
        #[test]
        fn $name() {
            let src = make_empty_dir_source();
            let archive_dir = TempDir::new().unwrap();
            let archive = archive_dir.path().join(concat!("out.", $ext));

            let config = CreationConfig::default()
                .with_include_hidden(true)
                .with_format(Some($format));
            let report = create_archive(&archive, &[src.path()], &config).unwrap();
            // empty1, empty2, empty2/empty3 = 3 directory entries.
            assert_eq!(report.directories_added, 3);

            let extract_dir = TempDir::new().unwrap();
            let extract_report =
                extract_archive(&archive, extract_dir.path(), &SecurityConfig::default()).unwrap();
            assert!(extract_report.directories_created >= 3);

            assert_empty_dirs_preserved(&extract_dir);
        }
    };
}

empty_dir_roundtrip_test!(empty_dirs_tar, "tar", ArchiveType::Tar);
empty_dir_roundtrip_test!(empty_dirs_tar_gz, "tar.gz", ArchiveType::TarGz);
empty_dir_roundtrip_test!(empty_dirs_tar_bz2, "tar.bz2", ArchiveType::TarBz2);
empty_dir_roundtrip_test!(empty_dirs_tar_xz, "tar.xz", ArchiveType::TarXz);
empty_dir_roundtrip_test!(empty_dirs_tar_zst, "tar.zst", ArchiveType::TarZst);

/// Parity check (SC-003): the same source tree with nested empty
/// directories produces the same directory-entry count for TAR and ZIP.
#[test]
fn empty_dirs_parity_between_tar_gz_and_zip() {
    let src = make_empty_dir_source();

    let archive_dir = TempDir::new().unwrap();
    let tar_gz = archive_dir.path().join("out.tar.gz");
    let zip = archive_dir.path().join("out.zip");

    let tar_config = CreationConfig::default()
        .with_include_hidden(true)
        .with_format(Some(ArchiveType::TarGz));
    let zip_config = CreationConfig::default()
        .with_include_hidden(true)
        .with_format(Some(ArchiveType::Zip));

    let tar_report = create_archive(&tar_gz, &[src.path()], &tar_config).unwrap();
    let zip_report = create_archive(&zip, &[src.path()], &zip_config).unwrap();

    assert_eq!(tar_report.directories_added, zip_report.directories_added);
}

// ============================================================================
// Compression report accuracy tests (issue #402)
// ============================================================================

/// Highly compressible fixture so real compression is nontrivial and easy
/// to distinguish from the previous (broken) always-0/always-100% reports.
fn make_compressible_source() -> TempDir {
    let src = TempDir::new().unwrap();
    fs::write(src.path().join("big.txt"), "a".repeat(200_000)).unwrap();
    src
}

macro_rules! bytes_compressed_matches_disk_test {
    ($name:ident, $ext:literal, $format:expr) => {
        #[test]
        fn $name() {
            let src = make_compressible_source();
            let archive_dir = TempDir::new().unwrap();
            let archive = archive_dir.path().join(concat!("out.", $ext));

            let config = CreationConfig::default().with_format(Some($format));
            let report = create_archive(&archive, &[src.path()], &config).unwrap();

            let on_disk = fs::metadata(&archive).unwrap().len();
            assert_eq!(
                report.bytes_compressed, on_disk,
                "bytes_compressed must equal the actual on-disk archive size"
            );
            assert!(report.bytes_compressed > 0);
            // Real compression on a highly-compressible fixture must beat the
            // uncompressed size, never hit the old 0/100% fallback.
            assert!(report.bytes_compressed < report.bytes_written);
            assert!(report.compression_percentage() < 100.0);
        }
    };
}

bytes_compressed_matches_disk_test!(bytes_compressed_matches_disk_zip, "zip", ArchiveType::Zip);
bytes_compressed_matches_disk_test!(
    bytes_compressed_matches_disk_tar_gz,
    "tar.gz",
    ArchiveType::TarGz
);
bytes_compressed_matches_disk_test!(
    bytes_compressed_matches_disk_tar_bz2,
    "tar.bz2",
    ArchiveType::TarBz2
);
bytes_compressed_matches_disk_test!(
    bytes_compressed_matches_disk_tar_xz,
    "tar.xz",
    ArchiveType::TarXz
);
bytes_compressed_matches_disk_test!(
    bytes_compressed_matches_disk_tar_zst,
    "tar.zst",
    ArchiveType::TarZst
);

/// Plain (uncompressed) TAR: `bytes_compressed` still reflects the actual
/// on-disk TAR stream size (headers + padding), not a reused
/// `bytes_written` value.
#[test]
fn bytes_compressed_matches_disk_plain_tar() {
    let src = make_compressible_source();
    let archive_dir = TempDir::new().unwrap();
    let archive = archive_dir.path().join("out.tar");

    let config = CreationConfig::default().with_format(Some(ArchiveType::Tar));
    let report = create_archive(&archive, &[src.path()], &config).unwrap();

    let on_disk = fs::metadata(&archive).unwrap().len();
    assert_eq!(report.bytes_compressed, on_disk);
    assert!(report.bytes_compressed > 0);
}

/// `bytes_compressed` must track the real on-disk size at both ends of the
/// compression-level range, not just the (untested) default level — a
/// metadata-based measurement should be correct regardless of how much the
/// encoder actually shrinks the stream.
#[test]
fn bytes_compressed_matches_disk_across_compression_levels() {
    let src = make_compressible_source();

    for level in [1, 9] {
        let archive_dir = TempDir::new().unwrap();
        let archive = archive_dir.path().join("out.tar.gz");

        let config = CreationConfig::default()
            .with_format(Some(ArchiveType::TarGz))
            .with_compression_level(level)
            .unwrap();
        let report = create_archive(&archive, &[src.path()], &config).unwrap();

        let on_disk = fs::metadata(&archive).unwrap().len();
        assert_eq!(
            report.bytes_compressed, on_disk,
            "level {level}: bytes_compressed must equal on-disk size"
        );
    }
}

/// Incompressible (pseudo-random) input: `bytes_compressed` must still
/// track the real on-disk size, even though compression buys little or
/// nothing here (guards against a fix that only measures correctly for
/// highly-compressible fixtures).
#[test]
fn bytes_compressed_matches_disk_incompressible_data() {
    let src = TempDir::new().unwrap();
    let mut data = vec![0u8; 200_000];
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    for byte in &mut data {
        // xorshift64* — deterministic, no external RNG dependency needed.
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        *byte = (state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8;
    }
    fs::write(src.path().join("random.bin"), &data).unwrap();

    let archive_dir = TempDir::new().unwrap();
    let archive = archive_dir.path().join("out.tar.gz");

    let config = CreationConfig::default().with_format(Some(ArchiveType::TarGz));
    let report = create_archive(&archive, &[src.path()], &config).unwrap();

    let on_disk = fs::metadata(&archive).unwrap().len();
    assert_eq!(report.bytes_compressed, on_disk);
}

// ============================================================================
// Additional edge cases for #400 (directory preservation)
// ============================================================================

/// A source tree that is *only* empty directories (no files at all) must
/// still round-trip: `directories_added` counts every directory, and none
/// are silently dropped for lack of file siblings.
#[test]
fn only_empty_directories_no_files_roundtrip() {
    let src = TempDir::new().unwrap();
    fs::create_dir_all(src.path().join("a/b/c")).unwrap();

    let archive_dir = TempDir::new().unwrap();
    let archive = archive_dir.path().join("out.tar.gz");

    let config = CreationConfig::default()
        .with_include_hidden(true)
        .with_format(Some(ArchiveType::TarGz));
    let report = create_archive(&archive, &[src.path()], &config).unwrap();

    // a, a/b, a/b/c = 3 directory entries; zero files.
    assert_eq!(report.directories_added, 3);
    assert_eq!(report.files_added, 0);

    let extract_dir = TempDir::new().unwrap();
    let extract_report =
        extract_archive(&archive, extract_dir.path(), &SecurityConfig::default()).unwrap();
    assert!(extract_report.directories_created >= 3);

    for rel in ["a", "a/b", "a/b/c"] {
        assert!(extract_dir.path().join(rel).is_dir());
    }
}

/// Directory names with unicode and spaces must survive TAR creation and
/// extraction unchanged, exercising the same `add_directory_to_tar` path
/// as the ASCII-only tests above with non-trivial `archive_path` encoding.
#[test]
fn empty_dir_unicode_and_space_names_roundtrip_tar() {
    let src = TempDir::new().unwrap();
    fs::create_dir_all(src.path().join("café \u{1F980}/nested dir")).unwrap();
    fs::write(src.path().join("file.txt"), b"content").unwrap();

    let archive_dir = TempDir::new().unwrap();
    let archive = archive_dir.path().join("out.tar.gz");

    let config = CreationConfig::default()
        .with_include_hidden(true)
        .with_format(Some(ArchiveType::TarGz));
    let report = create_archive(&archive, &[src.path()], &config).unwrap();
    assert_eq!(report.directories_added, 2);

    let extract_dir = TempDir::new().unwrap();
    extract_archive(&archive, extract_dir.path(), &SecurityConfig::default()).unwrap();

    assert!(
        extract_dir
            .path()
            .join("café \u{1F980}/nested dir")
            .is_dir()
    );
}
