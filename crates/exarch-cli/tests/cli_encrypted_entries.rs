//! Acceptance contract of #1242 and #1243 on the CLI: `list -l` marks encrypted
//! entries (`"encrypted": bool` in JSON, `(encrypted)` in the human line), and
//! `verify` treats a 7z with AES content under a plain header like an AES ZIP.
//! The fixtures are the core's encrypted archives.

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "integration test helpers"
)]

mod common;

use std::path::Path;
use std::path::PathBuf;

use assert_cmd::cargo::cargo_bin_cmd;
use common::Member;
use common::write_tar;
use tempfile::TempDir;

fn core_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../exarch-core/tests/data/encryption")
        .join(name)
}

fn json_run(args: &[&str], archive: &Path) -> (i32, serde_json::Value) {
    let output = cargo_bin_cmd!("exarch")
        .args(args)
        .arg(archive)
        .output()
        .unwrap();
    let json = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {output:?}"));
    (output.status.code().unwrap_or(-1), json)
}

fn entries(json: &serde_json::Value) -> &Vec<serde_json::Value> {
    json["data"]["entries"].as_array().expect("entries array")
}

#[test]
fn list_long_json_marks_every_entry_of_an_aes_zip_with_a_boolean() {
    let (code, json) = json_run(&["list", "--json", "-l"], &core_fixture("aes256.zip"));

    assert_eq!(code, 0, "{json}");
    for entry in entries(&json) {
        assert!(entry["encrypted"].is_boolean(), "{entry}");
        if entry["entry_type"] == "File" {
            assert_eq!(entry["encrypted"], true, "{entry}");
        }
    }
}

#[test]
fn list_long_json_marks_the_files_of_a_7z_with_encrypted_content() {
    let (code, json) = json_run(&["list", "--json", "-l"], &core_fixture("content.7z"));

    assert_eq!(code, 0, "{json}");
    let files: Vec<_> = entries(&json)
        .iter()
        .filter(|entry| entry["entry_type"] == "File")
        .collect();
    assert!(!files.is_empty());
    assert!(files.iter().all(|entry| entry["encrypted"] == true));
}

#[test]
fn list_long_json_marks_a_plain_zip_a_plain_7z_and_a_tar_false_everywhere() {
    let dir = TempDir::new().unwrap();
    let tar = dir.path().join("m.tar");
    write_tar(&tar, &[Member::File("a"), Member::Dir("d")]);

    for archive in [core_fixture("plain.zip"), core_fixture("plain.7z"), tar] {
        let (code, json) = json_run(&["list", "--json", "-l"], &archive);

        assert_eq!(code, 0, "{json}");
        for entry in entries(&json) {
            assert_eq!(entry["encrypted"], false, "{archive:?}: {entry}");
        }
    }
}

#[test]
fn list_long_human_marks_encrypted_entries_and_only_those() {
    let encrypted = cargo_bin_cmd!("exarch")
        .args(["list", "-l"])
        .arg(core_fixture("aes256.zip"))
        .output()
        .unwrap();
    let plain = cargo_bin_cmd!("exarch")
        .args(["list", "-l"])
        .arg(core_fixture("plain.zip"))
        .output()
        .unwrap();

    let encrypted = String::from_utf8_lossy(&encrypted.stdout);
    let plain = String::from_utf8_lossy(&plain.stdout);

    let marked: Vec<_> = encrypted
        .lines()
        .filter(|line| line.contains("(encrypted)"))
        .collect();
    assert_eq!(marked.len(), 2, "{encrypted}");
    assert!(marked.iter().any(|line| line.contains("hello.txt")));
    assert!(!plain.contains("(encrypted)"), "{plain}");
}

#[test]
fn verify_check_integrity_of_aes_content_7z_matches_the_aes_zip_exit_and_status() {
    let (zip_code, zip) = json_run(
        &["verify", "--json", "--check-integrity"],
        &core_fixture("aes256.zip"),
    );
    let (sevenz_code, sevenz) = json_run(
        &["verify", "--json", "--check-integrity"],
        &core_fixture("content.7z"),
    );

    assert_eq!((zip_code, sevenz_code), (0, 0), "{sevenz}");
    assert_eq!(sevenz["data"]["status"], zip["data"]["status"], "{sevenz}");
    assert_eq!(sevenz["data"]["status"], "WARNING", "{sevenz}");
    assert_eq!(
        sevenz["data"]["integrity_status"],
        zip["data"]["integrity_status"]
    );
    assert_eq!(sevenz["data"]["integrity_gaps"]["counts"]["encrypted"], 2);
}

#[test]
fn verify_of_aes_content_7z_reports_no_encrypted_security_issue_and_no_high_issue() {
    for flags in [
        &["verify", "--json"][..],
        &["verify", "--json", "--check-integrity"],
    ] {
        let (_code, json) = json_run(flags, &core_fixture("content.7z"));

        for issue in json["data"]["issues"].as_array().expect("issues array") {
            assert_ne!(issue["severity"], "HIGH", "{issue}");
            assert_ne!(issue["sub_code"], "ENCRYPTED", "{issue}");
        }
    }
}

#[test]
fn extract_of_aes_content_7z_without_a_password_still_fails_before_writing() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out");

    let output = cargo_bin_cmd!("exarch")
        .args(["extract", "--json"])
        .arg(core_fixture("content.7z"))
        .arg(&out)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "error", "{json}");
    assert!(
        !out.exists() || std::fs::read_dir(&out).unwrap().next().is_none(),
        "nothing is written"
    );
}
