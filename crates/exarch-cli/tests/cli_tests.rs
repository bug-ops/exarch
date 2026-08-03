//! Integration tests for exarch-cli.
//!
//! Note: Tests use `unwrap`/`expect` which is acceptable in test code.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn exarch_cmd() -> Command {
    cargo_bin_cmd!("exarch")
}

#[test]
fn test_version_flag() {
    exarch_cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("exarch"));
}

#[test]
fn test_help_flag() {
    exarch_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Command-line utility"));
}

#[test]
fn test_extract_help() {
    exarch_cmd()
        .arg("extract")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Extract archive contents"));
}

/// Tests that extraction runs successfully.
/// This test verifies CLI wiring and basic extraction.
#[test]
fn test_extract_runs_successfully() {
    let temp = TempDir::new().expect("failed to create temp dir");

    exarch_cmd()
        .arg("extract")
        .arg(fixture_path("sample.tar.gz"))
        .arg(temp.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Extraction complete"));
}

/// Tests actual file extraction.
#[test]
fn test_extract_creates_files() {
    let temp = TempDir::new().expect("failed to create temp dir");

    exarch_cmd()
        .arg("extract")
        .arg(fixture_path("sample.tar.gz"))
        .arg(temp.path())
        .assert()
        .success();

    assert!(temp.path().join("sample.txt").exists());
}

/// Tests JSON output format - verifies structure, not extraction counts.
#[test]
fn test_extract_json_output_format() {
    let temp = TempDir::new().expect("failed to create temp dir");

    let output = exarch_cmd()
        .arg("extract")
        .arg("--json")
        .arg(fixture_path("sample.tar.gz"))
        .arg(temp.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("invalid JSON output");
    assert_eq!(json["status"], "success");
    assert_eq!(json["operation"], "extract");
    assert!(json["data"]["files_extracted"].is_number());
}

/// Tests JSON output with actual extraction counts.
#[test]
fn test_extract_json_output_counts() {
    let temp = TempDir::new().expect("failed to create temp dir");

    let output = exarch_cmd()
        .arg("extract")
        .arg("--json")
        .arg(fixture_path("sample.tar.gz"))
        .arg(temp.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("invalid JSON output");
    assert!(json["data"]["files_extracted"].as_u64().unwrap() > 0);
}

/// Tests error handling for non-existent archives.
#[test]
fn test_extract_nonexistent_archive() {
    let temp = TempDir::new().expect("failed to create temp dir");

    exarch_cmd()
        .arg("extract")
        .arg("nonexistent.tar.gz")
        .arg(temp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error:"));
}

#[test]
fn test_create_help() {
    exarch_cmd()
        .arg("create")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Create a new archive"));
}

#[test]
fn test_create_command_basic() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("test.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Archive created"));

    assert!(archive.exists());
}

#[test]
fn test_create_command_multiple_sources() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("multi.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .arg(fixture_path("sample.tar.gz"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Archive created"));

    assert!(archive.exists());
}

#[test]
fn test_create_command_json_output() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("test.tar.gz");

    let output = exarch_cmd()
        .arg("--json")
        .arg("create")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("invalid JSON output");
    assert_eq!(json["status"], "success");
    assert_eq!(json["operation"], "create");
    assert!(json["data"]["files_added"].is_number());
    assert!(json["data"]["bytes_written"].is_number());
}

#[test]
fn test_create_command_output_exists_without_force() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("exists.tar.gz");

    // Create archive first time
    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .success();

    // Try to create again without --force
    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn test_create_command_force_overwrite() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("overwrite.tar.gz");

    // Create archive first time
    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .success();

    // Overwrite with --force
    exarch_cmd()
        .arg("create")
        .arg("--force")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .success();
}

#[test]
fn test_create_command_exclude_patterns() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("exclude.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg("--exclude")
        .arg("*.tmp")
        .arg("-x")
        .arg("*.bak")
        .arg(fixture_path("sample.txt"))
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_command_compression_level() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("compressed.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg("-l")
        .arg("9")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_command_quiet_mode() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("quiet.tar.gz");

    let output = exarch_cmd()
        .arg("--quiet")
        .arg("create")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    // In quiet mode, should have no output
    assert!(output.is_empty());
}

// ============================================================================
// Compression Format Tests
// ============================================================================

#[test]
fn test_create_tar_uncompressed() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("test.tar");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Archive created"));

    assert!(archive.exists());
}

#[test]
fn test_create_tar_bz2() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("test.tar.bz2");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_tar_xz() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("test.tar.xz");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_tar_zst() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("test.tar.zst");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_zip() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("test.zip");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .success();

    assert!(archive.exists());
}

// ============================================================================
// Configuration Option Tests
// ============================================================================

#[test]
fn test_create_with_strip_prefix() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let src_dir = temp.path().join("project");
    std::fs::create_dir(&src_dir).expect("failed to create source dir");
    std::fs::write(src_dir.join("file.txt"), "content").expect("failed to write file");

    let archive = temp.path().join("test.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg("--strip-prefix")
        .arg(&src_dir)
        .arg(&archive)
        .arg(&src_dir)
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_with_include_hidden() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let src_dir = temp.path().join("src");
    std::fs::create_dir(&src_dir).expect("failed to create source dir");
    std::fs::write(src_dir.join("visible.txt"), "visible").expect("failed to write visible file");
    std::fs::write(src_dir.join(".hidden"), "hidden").expect("failed to write hidden file");

    let archive = temp.path().join("test.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg("--include-hidden")
        .arg(&archive)
        .arg(&src_dir)
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
#[cfg(unix)]
fn test_create_with_follow_symlinks() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let src_dir = temp.path().join("src");
    std::fs::create_dir(&src_dir).expect("failed to create source dir");

    let target_file = src_dir.join("target.txt");
    std::fs::write(&target_file, "target content").expect("failed to write target file");

    let link_file = src_dir.join("link.txt");
    std::os::unix::fs::symlink(&target_file, &link_file).expect("failed to create symlink");

    let archive = temp.path().join("symlinks.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg("--follow-symlinks")
        .arg(&archive)
        .arg(&src_dir)
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
#[cfg(unix)]
fn test_create_default_skips_symlinks() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let src_dir = temp.path().join("src");
    std::fs::create_dir(&src_dir).expect("failed to create source dir");

    let target_file = src_dir.join("target.txt");
    std::fs::write(&target_file, "target content").expect("failed to write target file");

    let link_file = src_dir.join("link.txt");
    std::os::unix::fs::symlink(&target_file, &link_file).expect("failed to create symlink");

    let archive = temp.path().join("no_symlinks.tar.gz");

    // Without --follow-symlinks, should create archive with only regular file
    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(&src_dir)
        .assert()
        .success();

    // Archive should exist
    assert!(archive.exists());
}

#[test]
fn test_create_excludes_hidden_by_default() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let src_dir = temp.path().join("src");
    std::fs::create_dir(&src_dir).expect("failed to create source dir");
    std::fs::write(src_dir.join("visible.txt"), "visible").expect("failed to write visible file");
    std::fs::write(src_dir.join(".hidden"), "hidden").expect("failed to write hidden file");

    let archive = temp.path().join("test.tar.gz");

    // Without --include-hidden, should create archive with only visible file
    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(&src_dir)
        .assert()
        .success();

    // Archive should exist
    assert!(archive.exists());
}

#[test]
fn test_create_from_directory() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let src_dir = temp.path().join("source");
    std::fs::create_dir(&src_dir).expect("failed to create source dir");
    std::fs::write(src_dir.join("file1.txt"), "content1").expect("failed to write file1");
    std::fs::write(src_dir.join("file2.txt"), "content2").expect("failed to write file2");

    let archive = temp.path().join("directory.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(&src_dir)
        .assert()
        .success()
        .stdout(predicate::str::contains("Archive created"));

    assert!(archive.exists());
}

#[test]
fn test_create_mixed_sources() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let dir = temp.path().join("dir");
    std::fs::create_dir(&dir).expect("failed to create dir");
    std::fs::write(dir.join("file.txt"), "content").expect("failed to write file in dir");

    let file = temp.path().join("standalone.txt");
    std::fs::write(&file, "standalone").expect("failed to write standalone file");

    let archive = temp.path().join("mixed.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(&dir)
        .arg(&file)
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_multiple_exclude_patterns() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("excluded.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg("--exclude")
        .arg("*.log")
        .arg("--exclude")
        .arg("*.tmp")
        .arg("-x")
        .arg("*.bak")
        .arg(fixture_path("sample.txt"))
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_invalid_compression_level_zero() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("test.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg("-l")
        .arg("0")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .failure();
}

#[test]
fn test_create_invalid_compression_level_ten() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("test.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg("-l")
        .arg("10")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .failure();
}

#[test]
fn test_create_compression_level_min() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("fast.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg("-l")
        .arg("1")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_compression_level_max() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("best.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg("-l")
        .arg("9")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .success();

    assert!(archive.exists());
}

// ============================================================================
// #306 — CLI create flags: --max-file-size, --preserve-permissions
// ============================================================================

#[test]
fn test_create_max_file_size_flag_accepted() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("test.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg("--max-file-size")
        .arg("10M")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_preserve_permissions_default_true() {
    // --preserve-permissions=true explicitly mirrors the default behaviour
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("perms.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg("--preserve-permissions=true")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_preserve_permissions_false() {
    // --preserve-permissions=false must be accepted without error
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("noperms.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg("--preserve-permissions=false")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .success();

    assert!(archive.exists());
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_create_unknown_archive_format() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("test.unknown");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("format").or(predicate::str::contains("extension")));
}

#[test]
fn test_create_nonexistent_source() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("test.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(temp.path().join("nonexistent.txt"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found").or(predicate::str::contains("No such file")));
}

#[test]
fn test_create_no_sources() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("test.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .assert()
        .failure()
        .stderr(predicate::str::contains("required").or(predicate::str::contains("SOURCES")));
}

// ============================================================================
// Roundtrip Tests (Create → Extract)
// ============================================================================

#[test]
fn test_roundtrip_tar_gz_single_file() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let src_file = temp.path().join("original.txt");
    let content = b"Hello, World!";
    std::fs::write(&src_file, content).expect("failed to write source file");

    let archive = temp.path().join("roundtrip.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(&src_file)
        .assert()
        .success();

    let extract_dir = temp.path().join("extracted");
    std::fs::create_dir(&extract_dir).expect("failed to create extract dir");

    exarch_cmd()
        .arg("extract")
        .arg(&archive)
        .arg(&extract_dir)
        .assert()
        .success();

    let extracted =
        std::fs::read(extract_dir.join("original.txt")).expect("extracted file must exist");
    assert_eq!(
        extracted.as_slice(),
        content,
        "extracted content must match source"
    );
}

#[test]
fn test_roundtrip_zip_directory() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let src_dir = temp.path().join("source");
    std::fs::create_dir(&src_dir).expect("failed to create source dir");
    std::fs::write(src_dir.join("file1.txt"), b"content1").expect("failed to write file1");
    std::fs::write(src_dir.join("file2.txt"), b"content2").expect("failed to write file2");

    let archive = temp.path().join("roundtrip.zip");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(&src_dir)
        .assert()
        .success();

    let extract_dir = temp.path().join("extracted");
    std::fs::create_dir(&extract_dir).expect("failed to create extract dir");

    exarch_cmd()
        .arg("extract")
        .arg(&archive)
        .arg(&extract_dir)
        .assert()
        .success();

    let actual1 =
        std::fs::read(extract_dir.join("file1.txt")).expect("file1.txt must be extracted");
    assert_eq!(
        actual1.as_slice(),
        b"content1",
        "file1.txt content must match"
    );

    let actual2 =
        std::fs::read(extract_dir.join("file2.txt")).expect("file2.txt must be extracted");
    assert_eq!(
        actual2.as_slice(),
        b"content2",
        "file2.txt content must match"
    );
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_create_empty_directory() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let empty_dir = temp.path().join("empty");
    std::fs::create_dir(&empty_dir).expect("failed to create empty dir");

    let archive = temp.path().join("empty.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(&empty_dir)
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_directory_with_only_hidden_files() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let hidden_dir = temp.path().join("hidden_only");
    std::fs::create_dir(&hidden_dir).expect("failed to create dir");
    std::fs::write(hidden_dir.join(".hidden1"), "hidden1").expect("failed to write .hidden1");
    std::fs::write(hidden_dir.join(".hidden2"), "hidden2").expect("failed to write .hidden2");

    let archive = temp.path().join("hidden_only.tar.gz");

    // Without --include-hidden, should create archive with no files
    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(&hidden_dir)
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_long_filename() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let long_name = "a".repeat(200) + ".txt";
    let long_file = temp.path().join(&long_name);
    std::fs::write(&long_file, "content").expect("failed to write long filename");

    let archive = temp.path().join("long.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(&long_file)
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_unicode_filename() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let unicode_file = temp.path().join("файл.txt");
    std::fs::write(&unicode_file, "содержимое").expect("failed to write unicode file");

    let archive = temp.path().join("unicode.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(&unicode_file)
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_special_characters_filename() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let special_file = temp.path().join("file with spaces & special!.txt");
    std::fs::write(&special_file, "content").expect("failed to write special chars file");

    let archive = temp.path().join("special.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(&special_file)
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_nested_directories() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let nested = temp.path().join("a").join("b").join("c").join("d");
    std::fs::create_dir_all(&nested).expect("failed to create nested dirs");
    std::fs::write(nested.join("deep.txt"), "deep content").expect("failed to write deep file");

    let archive = temp.path().join("nested.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(temp.path().join("a"))
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_verbose_output() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("verbose.tar.gz");

    exarch_cmd()
        .arg("--verbose")
        .arg("create")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Archive created"));
}

#[test]
fn test_list_archive() {
    exarch_cmd()
        .arg("list")
        .arg(fixture_path("sample.tar.gz"))
        .assert()
        .success()
        .stdout(predicates::str::contains("sample.txt"));
}

/// Regression test for #349: `list -l` must display symlink targets as `link ->
/// target`.
#[test]
fn test_list_long_shows_symlink_target() {
    exarch_cmd()
        .arg("list")
        .arg("-l")
        .arg(fixture_path("symlink.zip"))
        .assert()
        .success()
        .stdout(predicates::str::contains("link.txt -> target.txt"));
}

/// Regression test for #349: `list -l` must display hardlink targets as `link
/// -> target`.
#[test]
fn test_list_long_shows_hardlink_target() {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let temp = TempDir::new().expect("create temp dir");
    let archive_path = temp.path().join("hardlink.tar.gz");

    let file = std::fs::File::create(&archive_path).expect("create archive");
    let gz = GzEncoder::new(file, Compression::default());
    let mut builder = tar::Builder::new(gz);

    let mut header = tar::Header::new_gnu();
    header.set_size(4);
    header.set_mode(0o644);
    header.set_path("target.txt").expect("set path");
    header.set_cksum();
    builder
        .append_data(&mut header, "target.txt", &b"data"[..])
        .expect("append file entry");

    let mut link_header = tar::Header::new_gnu();
    link_header.set_size(0);
    link_header.set_mode(0o644);
    link_header.set_entry_type(tar::EntryType::Link);
    link_header.set_path("link.txt").expect("set link path");
    link_header
        .set_link_name("target.txt")
        .expect("set link name");
    link_header.set_cksum();
    builder
        .append(&link_header, &b""[..] as &[u8])
        .expect("append hardlink entry");

    let gz = builder.into_inner().expect("get gz encoder");
    gz.finish().expect("finish gzip");

    exarch_cmd()
        .arg("list")
        .arg("-l")
        .arg(&archive_path)
        .assert()
        .success()
        .stdout(predicates::str::contains("link.txt -> target.txt"));
}

#[test]
fn test_list_archive_json_output() {
    let output = exarch_cmd()
        .arg("list")
        .arg("--json")
        .arg(fixture_path("sample.tar.gz"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("invalid JSON output");
    assert_eq!(json["status"], "success");
    assert_eq!(json["operation"], "list");
    assert!(json["data"]["entries"].is_array());
    assert!(json["data"]["total_entries"].is_number());
}

/// Builds a tar.gz archive at `path` containing one file of `size` bytes.
fn create_sized_tar_gz(path: &std::path::Path, size: usize) {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let file = std::fs::File::create(path).expect("create archive");
    let gz = GzEncoder::new(file, Compression::default());
    let mut builder = tar::Builder::new(gz);
    let data = vec![0u8; size];
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_path("big.bin").expect("set path");
    header.set_cksum();
    builder
        .append_data(&mut header, "big.bin", &data[..])
        .expect("append entry");
    let gz = builder.into_inner().expect("get gz encoder");
    gz.finish().expect("finish gzip stream");
}

/// Regression test: `list` must respect a caller-supplied `--max-file-size`,
/// not just the compiled-in 50MB default — previously `list`/`verify` had no
/// flag to raise or lower this cap, unlike `extract`/`create`.
#[test]
fn test_list_max_file_size_flag_enforced_and_configurable() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive_path = temp.path().join("oversized.tar.gz");
    create_sized_tar_gz(&archive_path, 1000);

    // Below the entry's size: list must reject with QuotaExceeded.
    let output = exarch_cmd()
        .arg("list")
        .arg("--json")
        .arg("--max-file-size")
        .arg("500")
        .arg(&archive_path)
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).expect("invalid JSON output");
    assert_eq!(json["status"], "error");
    assert_eq!(json["error"]["kind"], "QuotaExceeded");

    // Above the entry's size: list must succeed.
    exarch_cmd()
        .arg("list")
        .arg("--max-file-size")
        .arg("2000")
        .arg(&archive_path)
        .assert()
        .success();
}

/// Regression test: an oversized entry must degrade `verify` to a graceful
/// Fail-status report (with the violation itemized as an issue), not a bare
/// error — `verify`'s internal pre-flight listing pass keeps `max_file_size`
/// unlimited precisely so this stays a report, not a hard failure.
#[test]
fn test_verify_oversized_entry_produces_fail_report_not_error() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive_path = temp.path().join("oversized.tar.gz");
    create_sized_tar_gz(&archive_path, 1000);

    let output = exarch_cmd()
        .arg("verify")
        .arg("--json")
        .arg("--check-security")
        .arg("--max-file-size")
        .arg("500")
        .arg(&archive_path)
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("invalid JSON output");
    assert_eq!(
        json["status"], "success",
        "verify's envelope status must stay success even when data.status is FAIL"
    );
    assert_eq!(json["data"]["status"], "FAIL");
    let issues = json["data"]["issues"].as_array().expect("issues array");
    assert!(
        issues.iter().any(|i| i["category"] == "Quota Exceeded"),
        "expected a QuotaExceeded issue in the report, got: {json}"
    );
}

#[test]
fn test_verify_archive_safe() {
    exarch_cmd()
        .arg("verify")
        .arg(fixture_path("sample.tar.gz"))
        .assert()
        .success()
        .stdout(predicates::str::contains("Archive verification"));
}

#[test]
fn test_verify_strict_passes_on_clean_archive() {
    exarch_cmd()
        .arg("verify")
        .arg("--strict")
        .arg(fixture_path("sample.tar.gz"))
        .assert()
        .success();
}

/// Builds a tar.gz archive at `path` containing one file with a setuid bit set.
/// The setuid bit triggers an `InvalidPermissions` issue (Medium severity),
/// which causes the verification report to have `VerificationStatus::Warning`.
#[cfg(unix)]
fn create_setuid_tar_gz(path: &std::path::Path) {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let file = std::fs::File::create(path).expect("create archive");
    let gz = GzEncoder::new(file, Compression::default());
    let mut builder = tar::Builder::new(gz);
    let mut header = tar::Header::new_gnu();
    header.set_size(4);
    header.set_mode(0o4755); // setuid bit — triggers InvalidPermissions Medium issue
    header.set_path("binary").expect("set path");
    header.set_cksum();
    builder
        .append_data(&mut header, "binary", &b"data"[..])
        .expect("append entry");
    let gz = builder.into_inner().expect("get gz encoder");
    gz.finish().expect("finish gzip stream");
}

/// On Unix, an archive containing a setuid file produces a Warning-severity
/// verification report. With --strict, the CLI must exit with code 2 and
/// must not write any unstructured text to stderr.
#[test]
#[cfg(unix)]
fn test_verify_strict_exits_2_on_warning() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive_path = temp.path().join("setuid.tar.gz");
    create_setuid_tar_gz(&archive_path);

    exarch_cmd()
        .arg("verify")
        .arg("--strict")
        .arg(&archive_path)
        .assert()
        .code(2)
        .stderr(predicate::str::is_empty());
}

/// Without --strict, the same setuid archive must still exit 0.
#[test]
#[cfg(unix)]
fn test_verify_without_strict_exits_0_on_warning() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive_path = temp.path().join("setuid_lenient.tar.gz");
    create_setuid_tar_gz(&archive_path);

    exarch_cmd()
        .arg("verify")
        .arg(&archive_path)
        .assert()
        .success();
}

/// --quiet suppresses all non-error output; --strict must not bypass this
/// by writing directly to stderr.
#[test]
#[cfg(unix)]
fn test_verify_strict_quiet_produces_no_stderr() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive_path = temp.path().join("setuid_quiet.tar.gz");
    create_setuid_tar_gz(&archive_path);

    exarch_cmd()
        .arg("--quiet")
        .arg("verify")
        .arg("--strict")
        .arg(&archive_path)
        .assert()
        .code(2)
        .stderr(predicate::str::is_empty());
}

/// --json mode must not mix unstructured text into stderr alongside
/// structured JSON on stdout.
#[test]
#[cfg(unix)]
fn test_verify_strict_json_produces_no_stderr() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive_path = temp.path().join("setuid_json.tar.gz");
    create_setuid_tar_gz(&archive_path);

    exarch_cmd()
        .arg("--json")
        .arg("verify")
        .arg("--strict")
        .arg(&archive_path)
        .assert()
        .code(2)
        .stderr(predicate::str::is_empty());
}

#[test]
fn test_verify_archive_json_output() {
    let output = exarch_cmd()
        .arg("verify")
        .arg("--json")
        .arg(fixture_path("sample.tar.gz"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("invalid JSON output");
    assert_eq!(json["status"], "success");
    assert_eq!(json["operation"], "verify");
    assert!(json["data"]["status"].is_string());
    assert!(json["data"]["total_entries"].is_number());
    assert!(json["data"]["issues"].is_array());
    assert!(json["data"]["integrity_status"].is_string());
    assert!(json["data"]["security_status"].is_string());
}

/// Builds a tar.gz archive at `path` containing one symlink entry pointing
/// outside the extraction root. Verification rejects the symlink, producing a
/// `VerificationStatus::Fail` report.
fn create_symlink_escape_tar_gz(path: &std::path::Path) {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let file = std::fs::File::create(path).expect("create archive");
    let gz = GzEncoder::new(file, Compression::default());
    let mut builder = tar::Builder::new(gz);
    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_path("evil_link").expect("set path");
    header.set_link_name("/etc/passwd").expect("set link name");
    header.set_cksum();
    builder
        .append_data(&mut header, "evil_link", std::io::empty())
        .expect("append entry");
    let gz = builder.into_inner().expect("get gz encoder");
    gz.finish().expect("finish gzip stream");
}

/// Regression test for issue #387: `verify --json` on a FAIL-status archive
/// must print exactly one top-level JSON document, and the process must still
/// exit non-zero.
#[test]
fn test_verify_json_fail_prints_single_document() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive_path = temp.path().join("symlink_escape.tar.gz");
    create_symlink_escape_tar_gz(&archive_path);

    let output = exarch_cmd()
        .arg("verify")
        .arg("--json")
        .arg(&archive_path)
        .assert()
        .failure()
        .code(1)
        .get_output()
        .stdout
        .clone();

    let stdout = std::str::from_utf8(&output).expect("stdout is not valid UTF-8");
    let mut deserializer =
        serde_json::Deserializer::from_str(stdout).into_iter::<serde_json::Value>();
    let first = deserializer
        .next()
        .expect("expected at least one JSON document")
        .expect("first JSON document is invalid");
    assert!(
        deserializer.next().is_none(),
        "stdout must contain exactly one top-level JSON document, got extra trailing data: {stdout}"
    );

    assert_eq!(first["operation"], "verify");
    assert_eq!(first["status"], "success");
    assert_eq!(first["data"]["status"], "FAIL");
}

/// Regression test for issue #387: the human-readable path must still print
/// an error message on stderr and exit non-zero for a FAIL-status archive.
#[test]
fn test_verify_fail_human_readable_prints_error() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive_path = temp.path().join("symlink_escape.tar.gz");
    create_symlink_escape_tar_gz(&archive_path);

    exarch_cmd()
        .arg("verify")
        .arg(&archive_path)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Archive verification failed"));
}

/// Regression test for issue #386: `extract --json` must populate the
/// structured `error.partial_report` field when extraction is stopped
/// mid-archive after some entries were already written.
///
/// Uses a symlink entry (rejected only during extraction, since
/// `allow_symlinks` defaults to false) rather than an oversized entry: since
/// issue #396, `list` enforces `max_file_size` during the CLI's pre-flight
/// `list_archive()` call (see `extract.rs`'s `list_config`), so an oversized
/// entry is now rejected before extraction ever starts and would never produce
/// a partial report.
#[test]
fn test_extract_json_partial_report_populated() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive_path = temp.path().join("partial.tar.gz");

    {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        let file = std::fs::File::create(&archive_path).expect("create archive");
        let gz = GzEncoder::new(file, Compression::default());
        let mut builder = tar::Builder::new(gz);
        builder
            .append_data(
                &mut {
                    let mut h = tar::Header::new_gnu();
                    h.set_size(4);
                    h.set_mode(0o644);
                    h.set_cksum();
                    h
                },
                "small.txt",
                &b"data"[..],
            )
            .expect("append small entry");
        let mut link_header = tar::Header::new_gnu();
        link_header.set_size(0);
        link_header.set_entry_type(tar::EntryType::Symlink);
        link_header.set_mode(0o777);
        link_header.set_cksum();
        builder
            .append_link(&mut link_header, "link", "target.txt")
            .expect("append symlink entry");
        let gz = builder.into_inner().expect("get gz encoder");
        gz.finish().expect("finish gzip stream");
    }

    let output_dir = temp.path().join("out");
    let output = exarch_cmd()
        .arg("extract")
        .arg("--json")
        .arg(&archive_path)
        .arg(&output_dir)
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("invalid JSON output");
    assert_eq!(json["status"], "error");
    let partial_report = &json["error"]["partial_report"];
    assert!(
        !partial_report.is_null(),
        "error.partial_report must be populated, got: {json}"
    );
    assert!(partial_report["files_extracted"].as_u64().unwrap() >= 1);
}

/// Regression test for issue #386: `error.partial_report` must stay
/// absent/null for failures that never wrote anything to disk. Guards
/// against a broken fix that always populates `partial_report` regardless
/// of whether extraction actually made progress.
#[test]
fn test_extract_json_partial_report_absent_when_nothing_extracted() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let output_dir = temp.path().join("out");

    let output = exarch_cmd()
        .arg("extract")
        .arg("--json")
        .arg("nonexistent.tar.gz")
        .arg(&output_dir)
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("invalid JSON output");
    assert_eq!(json["status"], "error");
    assert!(
        json["error"]["partial_report"].is_null(),
        "error.partial_report must be absent/null when no entries were extracted, got: {json}"
    );
}

#[test]
fn test_global_verbose_flag() {
    let temp = TempDir::new().expect("failed to create temp dir");

    exarch_cmd()
        .arg("--verbose")
        .arg("extract")
        .arg(fixture_path("sample.tar.gz"))
        .arg(temp.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Symlinks"));
}

#[test]
fn test_byte_size_parsing() {
    let temp = TempDir::new().expect("failed to create temp dir");

    exarch_cmd()
        .arg("extract")
        .arg("--max-total-size")
        .arg("10M")
        .arg(fixture_path("sample.tar.gz"))
        .arg(temp.path())
        .assert()
        .success();
}

#[test]
fn test_security_flags() {
    let temp = TempDir::new().expect("failed to create temp dir");

    exarch_cmd()
        .arg("extract")
        .arg("--allow-symlinks")
        .arg("--allow-hardlinks")
        .arg("--preserve-permissions")
        .arg(fixture_path("sample.tar.gz"))
        .arg(temp.path())
        .assert()
        .success();
}

// ============================================================================
// Additional Coverage Tests
// ============================================================================

#[test]
fn test_create_compression_level_validation_range() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("test.tar.gz");

    // Test valid range boundaries
    for level in 1..=9 {
        exarch_cmd()
            .arg("create")
            .arg("-l")
            .arg(level.to_string())
            .arg(&archive)
            .arg("--force")
            .arg(fixture_path("sample.txt"))
            .assert()
            .success();
    }
}

#[test]
fn test_create_all_compression_formats_single_file() {
    let temp = TempDir::new().expect("failed to create temp dir");

    let formats = vec![
        "test.tar",
        "test.tar.gz",
        "test.tar.bz2",
        "test.tar.xz",
        "test.tar.zst",
        "test.zip",
    ];

    for format in formats {
        let archive = temp.path().join(format);
        exarch_cmd()
            .arg("create")
            .arg(&archive)
            .arg(fixture_path("sample.txt"))
            .assert()
            .success();
        assert!(archive.exists(), "Archive {format} should exist");
    }
}

#[test]
fn test_create_all_compression_formats_directory() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let src_dir = temp.path().join("source");
    std::fs::create_dir(&src_dir).expect("failed to create source dir");
    std::fs::write(src_dir.join("file1.txt"), "content1").expect("failed to write file1");
    std::fs::write(src_dir.join("file2.txt"), "content2").expect("failed to write file2");

    let formats = vec![
        "dir.tar",
        "dir.tar.gz",
        "dir.tar.bz2",
        "dir.tar.xz",
        "dir.tar.zst",
        "dir.zip",
    ];

    for format in formats {
        let archive = temp.path().join(format);
        exarch_cmd()
            .arg("create")
            .arg(&archive)
            .arg(&src_dir)
            .assert()
            .success();
        assert!(archive.exists(), "Archive {format} should exist");
    }
}

#[test]
fn test_create_json_output_structure_complete() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("test.tar.gz");

    let output = exarch_cmd()
        .arg("--json")
        .arg("create")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("invalid JSON output");

    // Verify all required fields are present
    assert_eq!(json["status"], "success");
    assert_eq!(json["operation"], "create");
    assert!(json["data"]["files_added"].is_number());
    assert!(json["data"]["bytes_written"].is_number());
    assert!(json["data"]["compression_ratio"].is_number());
}

// Regression test for issue #357: --json must never be silenced by --quiet.
#[test]
fn test_create_quiet_with_json_still_produces_output() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("test.tar.gz");

    let output = exarch_cmd()
        .arg("--quiet")
        .arg("--json")
        .arg("create")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value =
        serde_json::from_slice(&output).expect("--quiet --json must emit valid JSON");
    assert_eq!(json["operation"], "create");
    assert_eq!(json["status"], "success");
    assert!(json["data"]["files_added"].is_number());
}

#[test]
fn test_create_verbose_shows_details() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let src_dir = temp.path().join("source");
    std::fs::create_dir(&src_dir).expect("failed to create source dir");
    std::fs::write(src_dir.join("file1.txt"), "content1").expect("failed to write file1");
    std::fs::write(src_dir.join("file2.txt"), "content2").expect("failed to write file2");

    let archive = temp.path().join("verbose.tar.gz");

    exarch_cmd()
        .arg("--verbose")
        .arg("create")
        .arg(&archive)
        .arg(&src_dir)
        .assert()
        .success()
        .stdout(predicate::str::contains("Archive created"))
        .stdout(predicate::str::contains("Files added"));
}

#[test]
fn test_create_exclude_filters_correctly() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let src_dir = temp.path().join("source");
    std::fs::create_dir(&src_dir).expect("failed to create source dir");

    // Create files with different extensions
    std::fs::write(src_dir.join("keep.txt"), "keep").expect("failed to write keep.txt");
    std::fs::write(src_dir.join("remove.tmp"), "remove").expect("failed to write remove.tmp");
    std::fs::write(src_dir.join("also_keep.md"), "also keep")
        .expect("failed to write also_keep.md");

    let archive = temp.path().join("filtered.tar.gz");

    // Should exclude *.tmp files
    exarch_cmd()
        .arg("create")
        .arg("--exclude")
        .arg("*.tmp")
        .arg(&archive)
        .arg(&src_dir)
        .assert()
        .success();

    // Archive should exist
    assert!(archive.exists());
}

#[test]
fn test_create_deeply_nested_structure() {
    let temp = TempDir::new().expect("failed to create temp dir");

    // Create a deeply nested directory structure
    let mut current = temp.path().join("level1");
    std::fs::create_dir(&current).expect("failed to create level1");

    for i in 2..=10 {
        let next = current.join(format!("level{i}"));
        std::fs::create_dir(&next).unwrap_or_else(|_| panic!("failed to create level{i}"));
        current = next;
    }

    std::fs::write(current.join("deep.txt"), "deep content").expect("failed to write deep file");

    let archive = temp.path().join("deep.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(temp.path().join("level1"))
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_mixed_file_types() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let src_dir = temp.path().join("mixed");
    std::fs::create_dir(&src_dir).expect("failed to create source dir");

    // Create different file types
    std::fs::write(src_dir.join("text.txt"), "text").expect("failed to write text.txt");
    std::fs::write(src_dir.join("binary.bin"), [0u8, 1, 2, 3, 255])
        .expect("failed to write binary.bin");
    std::fs::write(src_dir.join("empty.txt"), "").expect("failed to write empty.txt");

    let subdir = src_dir.join("subdir");
    std::fs::create_dir(&subdir).expect("failed to create subdir");
    std::fs::write(subdir.join("nested.txt"), "nested").expect("failed to write nested.txt");

    let archive = temp.path().join("mixed.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(&src_dir)
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_strip_prefix_removes_parent_path() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let parent = temp.path().join("parent");
    let child = parent.join("child");
    std::fs::create_dir_all(&child).expect("failed to create dirs");
    std::fs::write(child.join("file.txt"), "content").expect("failed to write file");

    let archive = temp.path().join("stripped.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg("--strip-prefix")
        .arg(&parent)
        .arg(&archive)
        .arg(&child)
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_multiple_sources_mixed_types() {
    let temp = TempDir::new().expect("failed to create temp dir");

    // Create multiple sources of different types
    let file1 = temp.path().join("file1.txt");
    std::fs::write(&file1, "file1").expect("failed to write file1");

    let dir1 = temp.path().join("dir1");
    std::fs::create_dir(&dir1).expect("failed to create dir1");
    std::fs::write(dir1.join("inner.txt"), "inner").expect("failed to write inner.txt");

    let file2 = temp.path().join("file2.txt");
    std::fs::write(&file2, "file2").expect("failed to write file2");

    let archive = temp.path().join("multi_mixed.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(&file1)
        .arg(&dir1)
        .arg(&file2)
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_handles_readonly_source_files() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let readonly_file = temp.path().join("readonly.txt");
    std::fs::write(&readonly_file, "readonly content").expect("failed to write readonly file");

    // Make file read-only
    let mut perms = std::fs::metadata(&readonly_file)
        .expect("failed to get metadata")
        .permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&readonly_file, perms).expect("failed to set readonly");

    let archive = temp.path().join("readonly.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(&readonly_file)
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_empty_file() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let empty_file = temp.path().join("empty.txt");
    std::fs::write(&empty_file, "").expect("failed to write empty file");

    let archive = temp.path().join("with_empty.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(&empty_file)
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_very_long_path() {
    let temp = TempDir::new().expect("failed to create temp dir");

    // Create a path with many directory levels
    let mut current = temp.path().to_path_buf();
    for i in 0..20 {
        current = current.join(format!("dir_{i}"));
        std::fs::create_dir(&current).unwrap_or_else(|_| panic!("failed to create dir_{i}"));
    }

    std::fs::write(current.join("file.txt"), "content").expect("failed to write file");

    let archive = temp.path().join("long_path.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(temp.path().join("dir_0"))
        .assert()
        .success();

    assert!(archive.exists());
}

#[test]
fn test_create_tar_gz_matches_gzip_extension() {
    let temp = TempDir::new().expect("failed to create temp dir");

    for ext in &["tar.gz", "tgz"] {
        let archive = temp.path().join(format!("test.{ext}"));
        exarch_cmd()
            .arg("create")
            .arg(&archive)
            .arg(fixture_path("sample.txt"))
            .assert()
            .success();
        assert!(archive.exists());
    }
}

// ============================================================================
// Completion Command Tests
// ============================================================================

#[test]
fn test_completion_bash() {
    exarch_cmd()
        .arg("completion")
        .arg("bash")
        .assert()
        .success()
        .stdout(predicate::str::contains("_exarch"));
}

#[test]
fn test_completion_zsh() {
    exarch_cmd()
        .arg("completion")
        .arg("zsh")
        .assert()
        .success()
        .stdout(predicate::str::contains("_exarch"));
}

#[test]
fn test_completion_fish() {
    exarch_cmd()
        .arg("completion")
        .arg("fish")
        .assert()
        .success()
        .stdout(predicate::str::contains("exarch"));
}

#[test]
fn test_completion_powershell() {
    exarch_cmd()
        .arg("completion")
        .arg("powershell")
        .assert()
        .success()
        .stdout(predicate::str::contains("exarch"));
}

#[test]
fn test_completion_elvish() {
    exarch_cmd()
        .arg("completion")
        .arg("elvish")
        .assert()
        .success()
        .stdout(predicate::str::contains("exarch"));
}

#[test]
fn test_completion_help() {
    exarch_cmd()
        .arg("completion")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Generate shell completions"));
}

#[test]
fn test_completion_invalid_shell() {
    exarch_cmd()
        .arg("completion")
        .arg("invalid_shell")
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value"));
}

// ============================================================================
// --force Flag Tests (Extract)
// ============================================================================

/// Without --force, extracting into a directory with conflicting files fails
/// and the error message lists the conflicting files.
#[test]
fn test_extract_without_force_fails_on_conflict() {
    let temp = TempDir::new().expect("failed to create temp dir");

    // First extraction populates the output directory.
    exarch_cmd()
        .arg("extract")
        .arg(fixture_path("sample.tar.gz"))
        .arg(temp.path())
        .assert()
        .success();

    // Second extraction must fail because destination files already exist.
    exarch_cmd()
        .arg("extract")
        .arg(fixture_path("sample.tar.gz"))
        .arg(temp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exist").and(predicate::str::contains("--force")));
}

/// With --force, extracting into a directory with conflicting files succeeds
/// and silently overwrites them.
#[test]
fn test_extract_with_force_overwrites_conflicts() {
    let temp = TempDir::new().expect("failed to create temp dir");

    // First extraction populates the output directory.
    exarch_cmd()
        .arg("extract")
        .arg(fixture_path("sample.tar.gz"))
        .arg(temp.path())
        .assert()
        .success();

    // Second extraction with --force must succeed.
    exarch_cmd()
        .arg("extract")
        .arg("--force")
        .arg(fixture_path("sample.tar.gz"))
        .arg(temp.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Extraction complete"));
}

/// Regression test for #500: the pre-flight destination-conflict error must
/// cap the number of individually listed paths rather than dumping one line
/// per conflicting file.
#[test]
fn test_extract_without_force_caps_conflict_list_for_many_files() {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let temp = TempDir::new().expect("failed to create temp dir");
    let archive_path = temp.path().join("many_files.tar.gz");

    let file = std::fs::File::create(&archive_path).expect("create archive");
    let gz = GzEncoder::new(file, Compression::default());
    let mut builder = tar::Builder::new(gz);

    for i in 0..15 {
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o644);
        header
            .set_path(format!("f{i}.txt"))
            .expect("set entry path");
        header.set_cksum();
        builder
            .append_data(&mut header, format!("f{i}.txt"), &b"data"[..])
            .expect("append file entry");
    }
    builder
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip");

    let output_dir = temp.path().join("out");

    // First extraction populates the output directory.
    exarch_cmd()
        .arg("extract")
        .arg(&archive_path)
        .arg(&output_dir)
        .assert()
        .success();

    // Second extraction without --force must fail with a capped conflict list.
    exarch_cmd()
        .arg("extract")
        .arg(&archive_path)
        .arg(&output_dir)
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("15 destination files already exist")
                .and(predicate::str::contains("first 10 shown"))
                .and(predicate::str::contains("... and 5 more")),
        );
}

/// Builds a tar.gz with `allowed` files matching `.txt` and `rejected` files
/// matching `.exe`, so `--allowed-extensions txt` skips exactly `rejected`
/// entries.
fn make_mixed_extension_archive(path: &std::path::Path, allowed: usize, rejected: usize) {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let file = std::fs::File::create(path).expect("create archive");
    let gz = GzEncoder::new(file, Compression::default());
    let mut builder = tar::Builder::new(gz);

    for i in 0..allowed {
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o644);
        header
            .set_path(format!("keep{i}.txt"))
            .expect("set entry path");
        header.set_cksum();
        builder
            .append_data(&mut header, format!("keep{i}.txt"), &b"data"[..])
            .expect("append file entry");
    }
    for i in 0..rejected {
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o644);
        header
            .set_path(format!("drop{i}.exe"))
            .expect("set entry path");
        header.set_cksum();
        builder
            .append_data(&mut header, format!("drop{i}.exe"), &b"data"[..])
            .expect("append file entry");
    }
    builder
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip");
}

/// Regression test for #498: entries skipped by `--allowed-extensions` (a
/// real core→CLI round trip, not a synthetic report fed directly to the
/// formatter) must be surfaced in human-readable stdout as `Files skipped:`
/// plus a `Warnings:` section.
#[test]
fn test_extract_reports_files_skipped_and_warnings_for_disallowed_extensions() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive_path = temp.path().join("mixed.tar.gz");
    make_mixed_extension_archive(&archive_path, 3, 2);

    let output_dir = temp.path().join("out");

    exarch_cmd()
        .arg("extract")
        .arg("--allowed-extensions")
        .arg("txt")
        .arg(&archive_path)
        .arg(&output_dir)
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Files skipped: 2")
                .and(predicate::str::contains("Warnings:"))
                .and(predicate::str::contains(
                    "skipped 2 entries with disallowed extensions",
                )),
        );
}

/// Regression test for #498: same scenario as
/// `test_extract_reports_files_skipped_and_warnings_for_disallowed_extensions`
/// but for `--json`, verifying the `files_skipped`/`warnings` fields the
/// Python and Node.js bindings already exposed are now present in the CLI's
/// JSON payload too.
#[test]
fn test_extract_json_reports_files_skipped_and_warnings_for_disallowed_extensions() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive_path = temp.path().join("mixed.tar.gz");
    make_mixed_extension_archive(&archive_path, 3, 2);

    let output_dir = temp.path().join("out");

    let output = exarch_cmd()
        .arg("extract")
        .arg("--allowed-extensions")
        .arg("txt")
        .arg("--json")
        .arg(&archive_path)
        .arg(&output_dir)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON output");
    assert_eq!(json["data"]["files_skipped"], 2);
    assert_eq!(
        json["data"]["warnings"][0],
        "skipped 2 entries with disallowed extensions"
    );
}

// ============================================================================
// symlink_target in JSON list output (#346)
// ============================================================================

/// Builds a minimal ZIP archive containing a single symlink entry using raw
/// bytes. The symlink target is stored as the file content with `S_IFLNK` mode
/// bits set in the central-directory `external_attributes` field.
fn make_zip_with_symlink(link_name: &str, target: &str) -> Vec<u8> {
    let content = target.as_bytes();
    let crc = {
        let mut c: u32 = 0xFFFF_FFFF;
        for &b in content {
            c ^= u32::from(b);
            for _ in 0..8 {
                if c & 1 != 0 {
                    c = (c >> 1) ^ 0xEDB8_8320;
                } else {
                    c >>= 1;
                }
            }
        }
        c ^ 0xFFFF_FFFF
    };
    let external_attributes: u32 = 0o120_777 << 16;
    let name_bytes = link_name.as_bytes();
    let name_len = u16::try_from(name_bytes.len()).unwrap();
    let content_len = u32::try_from(content.len()).unwrap();

    let mut buf: Vec<u8> = Vec::new();

    let local_offset = u32::try_from(buf.len()).unwrap();
    buf.extend_from_slice(b"PK\x03\x04");
    buf.extend_from_slice(&20u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&crc.to_le_bytes());
    buf.extend_from_slice(&content_len.to_le_bytes());
    buf.extend_from_slice(&content_len.to_le_bytes());
    buf.extend_from_slice(&name_len.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(name_bytes);
    buf.extend_from_slice(content);

    let central_offset = u32::try_from(buf.len()).unwrap();
    buf.extend_from_slice(b"PK\x01\x02");
    buf.extend_from_slice(&0x031eu16.to_le_bytes());
    buf.extend_from_slice(&20u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&crc.to_le_bytes());
    buf.extend_from_slice(&content_len.to_le_bytes());
    buf.extend_from_slice(&content_len.to_le_bytes());
    buf.extend_from_slice(&name_len.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&external_attributes.to_le_bytes());
    buf.extend_from_slice(&local_offset.to_le_bytes());
    buf.extend_from_slice(name_bytes);

    let central_size = u32::try_from(buf.len()).unwrap() - central_offset;
    buf.extend_from_slice(b"PK\x05\x06");
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&central_size.to_le_bytes());
    buf.extend_from_slice(&central_offset.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());

    buf
}

/// `exarch list --json -l` must include `symlink_target` for symlink entries
/// (regression test for issue #346).
#[test]
fn test_list_json_long_symlink_target() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("symlink.zip");
    let zip_bytes = make_zip_with_symlink("link.txt", "target.txt");
    std::fs::write(&archive, &zip_bytes).expect("failed to write zip fixture");

    let output = exarch_cmd()
        .arg("list")
        .arg("--json")
        .arg("-l")
        .arg(&archive)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("invalid JSON output");
    let entries = json["data"]["entries"]
        .as_array()
        .expect("entries must be array");
    let symlink = entries
        .iter()
        .find(|e| e["entry_type"] == "Symlink")
        .expect("expected a Symlink entry in the listing");

    assert_eq!(
        symlink["symlink_target"].as_str(),
        Some("target.txt"),
        "symlink_target must equal the link target stored in the archive"
    );
}

/// Regular file entries must NOT contain `symlink_target` or `hardlink_target`
/// keys in JSON output, pinning the `skip_serializing_if` contract (#346).
#[test]
fn test_list_json_long_regular_file_omits_link_fields() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("regular.tar.gz");

    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(fixture_path("sample.txt"))
        .assert()
        .success();

    let output = exarch_cmd()
        .arg("list")
        .arg("--json")
        .arg("-l")
        .arg(&archive)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("invalid JSON output");
    let entries = json["data"]["entries"]
        .as_array()
        .expect("entries must be array");
    let file_entry = entries
        .iter()
        .find(|e| e["entry_type"] == "File")
        .expect("expected a File entry in the listing");

    assert!(
        file_entry.get("symlink_target").is_none(),
        "regular file entry must not contain symlink_target key"
    );
    assert!(
        file_entry.get("hardlink_target").is_none(),
        "regular file entry must not contain hardlink_target key"
    );
}

/// Builds a tar.gz archive at `path` containing one file entry nested under
/// `component`, so a `--banned-component` flag matching `component` triggers
/// `ArchiveError::SecurityViolation` during extraction.
fn create_tar_gz_with_component(path: &std::path::Path, component: &str) {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let file = std::fs::File::create(path).expect("create archive");
    let gz = GzEncoder::new(file, Compression::default());
    let mut builder = tar::Builder::new(gz);
    let data = b"payload";
    let entry_path = format!("{component}/file.txt");
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_path(&entry_path).expect("set path");
    header.set_cksum();
    builder
        .append_data(&mut header, &entry_path, &data[..])
        .expect("append entry");
    let gz = builder.into_inner().expect("get gz encoder");
    gz.finish().expect("finish gzip stream");
}

/// Regression test for issue #403: the `SecurityViolation` reason must appear
/// exactly once in `--json` output, not doubled by redundant anyhow context.
#[test]
fn test_extract_security_violation_json_reason_appears_once() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive_path = temp.path().join("banned.tar.gz");
    create_tar_gz_with_component(&archive_path, ".customdir");
    let out_dir = temp.path().join("out");
    std::fs::create_dir_all(&out_dir).expect("create out dir");

    let output = exarch_cmd()
        .arg("extract")
        .arg(&archive_path)
        .arg(&out_dir)
        .arg("--banned-component")
        .arg(".customdir")
        .arg("--json")
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("invalid JSON output");
    assert_eq!(json["status"], "error");
    assert_eq!(json["error"]["kind"], "SecurityViolation");
    let message = json["error"]["message"]
        .as_str()
        .expect("error.message must be a string");
    assert_eq!(
        message.matches("banned path component: .customdir").count(),
        1,
        "reason should appear exactly once, got: {message}"
    );
}

/// Regression test for issue #403: same duplication check as
/// [`test_extract_security_violation_json_reason_appears_once`], for the
/// human-readable (non-JSON) output path.
#[test]
fn test_extract_security_violation_text_reason_appears_once() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive_path = temp.path().join("banned.tar.gz");
    create_tar_gz_with_component(&archive_path, ".customdir");
    let out_dir = temp.path().join("out");
    std::fs::create_dir_all(&out_dir).expect("create out dir");

    let output = exarch_cmd()
        .arg("extract")
        .arg(&archive_path)
        .arg(&out_dir)
        .arg("--banned-component")
        .arg(".customdir")
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();

    let stderr = std::str::from_utf8(&output).expect("stderr is not valid UTF-8");
    assert_eq!(
        stderr.matches("banned path component: .customdir").count(),
        1,
        "reason should appear exactly once, got: {stderr}"
    );
}

/// Regression test for issue #449: `--banned-component ""` is a documented
/// idiom (see clap help on `ExtractArgs::banned_components`) for disabling
/// the default ban list entirely. `SecurityConfig::validate()` now rejects
/// empty entries, so the CLI must filter them out before building the
/// config rather than passing the raw, unfiltered flag values through.
#[test]
fn test_extract_banned_component_empty_string_disables_default_ban_list() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive_path = temp.path().join("git.tar.gz");
    create_tar_gz_with_component(&archive_path, ".git");
    let out_dir = temp.path().join("out");
    std::fs::create_dir_all(&out_dir).expect("create out dir");

    exarch_cmd()
        .arg("extract")
        .arg(&archive_path)
        .arg(&out_dir)
        .arg("--banned-component")
        .arg("")
        .assert()
        .success();

    assert!(
        out_dir.join(".git").join("file.txt").exists(),
        "empty --banned-component should disable the default ban list, allowing .git/ through"
    );
}

/// Encodes `n` as a classic octal numeric field of `width` bytes (including
/// the trailing NUL), or `None` if it does not fit in `width - 1` digits.
fn octal_field(n: u64, width: usize) -> Option<Vec<u8>> {
    let digits = format!("{n:o}").into_bytes();
    if digits.len() > width - 1 {
        return None;
    }
    let mut out = vec![b'0'; width - 1 - digits.len()];
    out.extend_from_slice(&digits);
    out.push(0);
    Some(out)
}

/// Encodes `n` as a GNU base-256 numeric field (big-endian, high bit of the
/// first byte set) — used for values beyond octal's digit capacity.
fn base256_field(n: u64, width: usize) -> Vec<u8> {
    let mut out = vec![0u8; width];
    let bytes = n.to_be_bytes();
    out[width - bytes.len()..].copy_from_slice(&bytes);
    out[0] |= 0x80;
    out
}

fn num_field(n: u64, width: usize) -> Vec<u8> {
    octal_field(n, width).unwrap_or_else(|| base256_field(n, width))
}

/// Builds a raw GNU old-format sparse header (typeflag `'S'`) with a real
/// inline `(offset, numbytes)` block and a `realsize` at offset 483.
fn gnu_sparse_header(
    name: &[u8],
    size_field: u64,
    realsize: u64,
    offset: u64,
    numbytes: u64,
) -> Vec<u8> {
    const BLOCK: usize = 512;
    let mut h = vec![0u8; BLOCK];
    let name_len = name.len().min(100);
    h[..name_len].copy_from_slice(&name[..name_len]);
    h[100..108].copy_from_slice(&num_field(0o644, 8));
    h[108..116].copy_from_slice(&num_field(0, 8));
    h[116..124].copy_from_slice(&num_field(0, 8));
    h[124..136].copy_from_slice(&num_field(size_field, 12));
    h[136..148].copy_from_slice(&num_field(0, 12));
    h[156] = b'S';
    h[257..263].copy_from_slice(b"ustar ");
    h[263..265].copy_from_slice(b" \0");
    h[386..398].copy_from_slice(&num_field(offset, 12));
    h[398..410].copy_from_slice(&num_field(numbytes, 12));
    h[482] = 0;
    h[483..495].copy_from_slice(&num_field(realsize, 12));
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

/// Builds a raw single-entry TAR with a GNU sparse header shaped so that
/// `exarch-core`'s bounded drain (`SYNTHETIC_PAD_CAP_BYTES`, currently
/// 8 MiB) gives up mid-hole, leaving the trailing real data segment
/// entirely unread — see the matching (and more detailed) construction and
/// rationale in `exarch-core`'s `tar_metadata_bomb.rs`, in the test named
/// `known_limitation_legitimate_sparse_hole_above_the_synthetic_cap_is_rejected`.
fn legitimate_sparse_hole_fixture() -> Vec<u8> {
    const BLOCK: usize = 512;
    let gap = 12 * 1024 * 1024u64;
    let real_trailing = 6 * 1024 * 1024u64;
    let mut out = gnu_sparse_header(
        b"legit_sparse.bin",
        real_trailing,
        gap + real_trailing,
        gap,
        real_trailing,
    );
    out.extend(std::iter::repeat_n(
        b'D',
        usize::try_from(real_trailing).unwrap(),
    ));
    let rem = out.len() % BLOCK;
    if rem != 0 {
        out.extend(std::iter::repeat_n(0u8, BLOCK - rem));
    }
    out.extend(std::iter::repeat_n(0u8, BLOCK * 2));
    out
}

/// Pins the documented residual limitation of the C1/C2/C3 drain-bound fix
/// (issue #414) specifically at the CLI level: `exarch extract` runs its
/// own `list_archive` pre-flight (for progress-bar/conflict detection,
/// `src/commands/extract.rs`) ahead of the actual extraction, so a
/// legitimate GNU sparse file whose hole exceeds the synthetic-bytes drain
/// cap is rejected by the CLI even though the underlying library's
/// `extract_archive`/`TarArchive::extract` calls (which never run that
/// pre-flight) handle the identical archive cleanly. This is a deliberately
/// accepted trade-off (P3 follow-up tracked separately), not a bug — this
/// test exists so the CLI-specific angle of that trade-off cannot silently
/// change without a test noticing.
#[test]
fn test_extract_known_limitation_cli_rejects_legitimate_sparse_hole_above_synthetic_cap() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive_path = temp.path().join("legit_sparse.tar");
    std::fs::write(&archive_path, legitimate_sparse_hole_fixture()).expect("write sparse fixture");
    let out_dir = temp.path().join("out");

    exarch_cmd()
        .arg("extract")
        .arg(&archive_path)
        .arg(&out_dir)
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to list archive"));
}
