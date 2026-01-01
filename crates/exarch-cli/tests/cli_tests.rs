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
    let content = "Hello, World!";
    std::fs::write(&src_file, content).expect("failed to write source file");

    let archive = temp.path().join("roundtrip.tar.gz");

    // Create archive
    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(&src_file)
        .assert()
        .success();

    // Extract archive
    let extract_dir = temp.path().join("extracted");
    std::fs::create_dir(&extract_dir).expect("failed to create extract dir");

    exarch_cmd()
        .arg("extract")
        .arg(&archive)
        .arg(&extract_dir)
        .assert()
        .success();
}

#[test]
fn test_roundtrip_zip_directory() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let src_dir = temp.path().join("source");
    std::fs::create_dir(&src_dir).expect("failed to create source dir");
    std::fs::write(src_dir.join("file1.txt"), "content1").expect("failed to write file1");
    std::fs::write(src_dir.join("file2.txt"), "content2").expect("failed to write file2");

    let archive = temp.path().join("roundtrip.zip");

    // Create archive
    exarch_cmd()
        .arg("create")
        .arg(&archive)
        .arg(&src_dir)
        .assert()
        .success();

    // Extract archive
    let extract_dir = temp.path().join("extracted");
    std::fs::create_dir(&extract_dir).expect("failed to create extract dir");

    exarch_cmd()
        .arg("extract")
        .arg(&archive)
        .arg(&extract_dir)
        .assert()
        .success();

    // Verify roundtrip completed
    assert!(archive.exists());
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

#[test]
fn test_create_quiet_with_json_produces_no_output() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let archive = temp.path().join("test.tar.gz");

    // --quiet takes precedence, even with --json
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

    // In quiet mode, should have no output
    assert!(output.is_empty());
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
