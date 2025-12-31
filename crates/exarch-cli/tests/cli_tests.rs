//! Integration tests for exarch-cli.
//!
//! Note: Tests use `unwrap`/`expect` which is acceptable in test code.
//!
//! Tests marked with `#[ignore]` require the exarch-core extraction engine
//! to be fully implemented (currently a placeholder).

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

/// Tests that extraction runs successfully (placeholder returns empty report).
/// This test verifies CLI wiring, not actual extraction.
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

/// Tests actual file extraction - requires core implementation.
#[test]
#[ignore = "requires exarch-core extraction engine implementation"]
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
    // Verify structure exists, not specific values (placeholder returns 0)
    assert!(json["data"]["files_extracted"].is_number());
}

/// Tests JSON output with actual extraction counts - requires core
/// implementation.
#[test]
#[ignore = "requires exarch-core extraction engine implementation"]
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

/// Tests error handling for non-existent archives - requires core
/// implementation.
#[test]
#[ignore = "requires exarch-core extraction engine implementation"]
fn test_extract_nonexistent_archive() {
    let temp = TempDir::new().expect("failed to create temp dir");

    exarch_cmd()
        .arg("extract")
        .arg("nonexistent.tar.gz")
        .arg(temp.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("ERROR"));
}

#[test]
fn test_create_not_implemented() {
    exarch_cmd()
        .arg("create")
        .arg("output.tar.gz")
        .arg("source/")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not implemented"));
}

#[test]
fn test_list_not_implemented() {
    exarch_cmd()
        .arg("list")
        .arg(fixture_path("sample.tar.gz"))
        .assert()
        .failure();
}

#[test]
fn test_verify_not_implemented() {
    exarch_cmd()
        .arg("verify")
        .arg(fixture_path("sample.tar.gz"))
        .assert()
        .failure();
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
