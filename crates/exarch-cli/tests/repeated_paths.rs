//! Acceptance contract of #1201 for the CLI: `--repeated-paths
//! <keep-first|refuse>` on `extract`, `list` and `verify`; the default keeps
//! the first copy.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use assert_cmd::cargo::cargo_bin_cmd;
use common::Member;
use common::write_tar;
use tempfile::TempDir;

fn repeated_tar(dir: &TempDir) -> std::path::PathBuf {
    let archive = dir.path().join("s07.tar");
    write_tar(&archive, &[Member::File("a"), Member::File("a")]);
    archive
}

#[test]
fn test_extract_default_keeps_the_first_copy_and_succeeds() {
    let dir = TempDir::new().unwrap();
    let archive = repeated_tar(&dir);
    let out = dir.path().join("out");

    cargo_bin_cmd!("exarch")
        .arg("extract")
        .arg(&archive)
        .arg(&out)
        .assert()
        .success();

    assert!(out.join("a").is_file());
}

#[test]
fn test_extract_repeated_paths_keep_first_equals_the_default() {
    let dir = TempDir::new().unwrap();
    let archive = repeated_tar(&dir);

    cargo_bin_cmd!("exarch")
        .args(["extract", "--repeated-paths", "keep-first"])
        .arg(&archive)
        .arg(dir.path().join("out"))
        .assert()
        .success();
}

#[test]
fn test_extract_repeated_paths_refuse_fails_with_a_typed_json_error_and_a_hint() {
    let dir = TempDir::new().unwrap();
    let archive = repeated_tar(&dir);

    let output = cargo_bin_cmd!("exarch")
        .args(["extract", "--json", "--repeated-paths", "refuse"])
        .arg(&archive)
        .arg(dir.path().join("out"))
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "error", "{json}");
    let error = json["error"].to_string().to_lowercase().replace('_', "");
    assert!(error.contains("repeatedpath"), "{json}");
    let hint = json["error"]["hint"].as_str().unwrap_or_default();
    assert!(hint.contains("--repeated-paths keep-first"), "{json}");
}

#[test]
fn test_list_repeated_paths_refuse_marks_the_repeat_as_refused() {
    let dir = TempDir::new().unwrap();
    let archive = repeated_tar(&dir);

    let output = cargo_bin_cmd!("exarch")
        .args(["list", "--json", "--repeated-paths", "refuse"])
        .arg(&archive)
        .output()
        .unwrap();

    let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
    assert!(text.contains("\"refuse\""), "{text}");
}

#[test]
fn test_verify_repeated_paths_refuse_reports_the_repeat() {
    let dir = TempDir::new().unwrap();
    let archive = repeated_tar(&dir);

    let plain = cargo_bin_cmd!("exarch")
        .args(["verify", "--json"])
        .arg(&archive)
        .output()
        .unwrap();
    let strict = cargo_bin_cmd!("exarch")
        .args(["verify", "--json", "--repeated-paths", "refuse"])
        .arg(&archive)
        .output()
        .unwrap();

    assert_ne!(plain.stdout, strict.stdout);
}

#[test]
fn test_repeated_paths_rejects_an_unknown_value() {
    let dir = TempDir::new().unwrap();
    let archive = repeated_tar(&dir);

    cargo_bin_cmd!("exarch")
        .args(["extract", "--repeated-paths", "last-wins"])
        .arg(&archive)
        .arg(dir.path().join("out"))
        .assert()
        .failure();
}

#[test]
fn test_repeated_paths_is_refused_on_create() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("f"), b"x").unwrap();

    cargo_bin_cmd!("exarch")
        .args(["create", "--repeated-paths", "refuse"])
        .arg(dir.path().join("o.tar.gz"))
        .arg(dir.path().join("f"))
        .assert()
        .failure();
}
