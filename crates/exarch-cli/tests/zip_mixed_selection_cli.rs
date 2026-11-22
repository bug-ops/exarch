//! `extract` of a ZIP that mixes plain and AES-encrypted entries needs a
//! password only for an encrypted entry the selection extracts (#1261): the
//! listing pass the CLI runs first must not check the password of an entry the
//! selection leaves out.

#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]
#![expect(clippy::disallowed_methods, reason = "integration test fixture setup")]

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::path::PathBuf;

use assert_cmd::cargo::cargo_bin_cmd;
use tempfile::TempDir;
use zip::AesMode;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

const PASSWORD: &str = "correct-horse";

fn mixed_zip(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("mix.zip");
    let mut writer = ZipWriter::new(std::fs::File::create(&path).unwrap());
    writer
        .start_file("p.txt", SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"plain\n").unwrap();
    writer
        .start_file(
            "sub/e.txt",
            SimpleFileOptions::default().with_aes_encryption(AesMode::Aes256, PASSWORD),
        )
        .unwrap();
    writer.write_all(b"secret\n").unwrap();
    writer.finish().unwrap();
    path
}

fn password_file(dir: &TempDir, password: &str) -> PathBuf {
    let path = dir.path().join(format!("{password}.pw"));
    std::fs::write(&path, format!("{password}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn extract(archive: &Path, out: &Path, args: &[&str]) -> (i32, serde_json::Value) {
    let output = cargo_bin_cmd!("exarch")
        .args(["extract", "--json"])
        .args(args)
        .arg(archive)
        .arg(out)
        .output()
        .unwrap();
    let json = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {output:?}"));
    (output.status.code().unwrap_or(-1), json)
}

#[test]
fn an_include_of_plain_entries_needs_no_password() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out");

    let (code, json) = extract(&mixed_zip(&dir), &out, &["--include", "p.txt"]);

    assert_eq!(code, 0, "{json}");
    assert_eq!(std::fs::read(out.join("p.txt")).unwrap(), b"plain\n");
    assert!(!out.join("sub").exists());
    assert_eq!(json["data"]["skipped_by_kind"]["not_selected"], 1, "{json}");
}

#[test]
fn a_wrong_password_is_ignored_when_no_encrypted_entry_is_selected() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out");
    let wrong = password_file(&dir, "wrong-horse");

    let (code, json) = extract(
        &mixed_zip(&dir),
        &out,
        &[
            "--include",
            "p.txt",
            "--password-file",
            wrong.to_str().unwrap(),
        ],
    );

    assert_eq!(code, 0, "{json}");
    assert!(out.join("p.txt").exists());
    assert!(!out.join("sub").exists());
}

#[test]
fn standalone_list_still_checks_the_password_of_every_encrypted_entry() {
    let dir = TempDir::new().unwrap();
    let wrong = password_file(&dir, "wrong-horse");

    let output = cargo_bin_cmd!("exarch")
        .args(["list", "--json", "--include", "p.txt", "--password-file"])
        .arg(&wrong)
        .arg(mixed_zip(&dir))
        .output()
        .unwrap();

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!output.status.success(), "{json}");
    assert_eq!(json["error"]["reason"], "wrong_password", "{json}");
}

#[test]
fn a_selected_encrypted_entry_without_a_password_is_password_required() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out");

    let (code, json) = extract(&mixed_zip(&dir), &out, &[]);

    assert_ne!(code, 0, "{json}");
    assert_eq!(json["error"]["reason"], "password_required", "{json}");
    assert!(!out.join("p.txt").exists());
}

#[test]
fn a_selected_encrypted_entry_with_a_wrong_password_is_wrong_password() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out");
    let wrong = password_file(&dir, "wrong-horse");

    let (code, json) = extract(
        &mixed_zip(&dir),
        &out,
        &["--password-file", wrong.to_str().unwrap()],
    );

    assert_ne!(code, 0, "{json}");
    assert_eq!(json["error"]["reason"], "wrong_password", "{json}");
}

fn verify(archive: &Path, args: &[&str]) -> (i32, serde_json::Value) {
    let output = cargo_bin_cmd!("exarch")
        .args(["verify", "--json", "--check-integrity"])
        .args(args)
        .arg(archive)
        .output()
        .unwrap();
    let json = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {output:?}"));
    (output.status.code().unwrap_or(-1), json)
}

#[test]
fn verify_with_an_include_and_the_right_password_still_checks_encrypted_entries() {
    let dir = TempDir::new().unwrap();
    let right = password_file(&dir, PASSWORD);

    let (code, json) = verify(
        &mixed_zip(&dir),
        &[
            "--include",
            "p.txt",
            "--password-file",
            right.to_str().unwrap(),
        ],
    );

    assert_eq!(code, 0, "{json}");
    assert_eq!(json["data"]["status"], "PASS", "{json}");
}

#[test]
fn verify_with_an_include_and_a_wrong_password_reports_it() {
    let dir = TempDir::new().unwrap();
    let wrong = password_file(&dir, "wrong-horse");

    let (code, json) = verify(
        &mixed_zip(&dir),
        &[
            "--include",
            "p.txt",
            "--password-file",
            wrong.to_str().unwrap(),
        ],
    );

    assert_ne!(code, 0, "{json}");
    assert_eq!(json["error"]["reason"], "wrong_password", "{json}");
}

#[test]
fn verify_with_an_include_still_fails_on_a_corrupt_unselected_plain_entry() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("corrupt.zip");
    let mut writer = ZipWriter::new(std::fs::File::create(&path).unwrap());
    let stored = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    writer.start_file("p.txt", stored).unwrap();
    writer.write_all(b"plain\n").unwrap();
    writer.start_file("q.txt", stored).unwrap();
    writer.write_all(b"corruptible-payload").unwrap();
    writer.finish().unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    let at = bytes
        .windows(b"corruptible".len())
        .position(|window| window == b"corruptible")
        .unwrap();
    bytes[at] ^= 0xff;
    std::fs::write(&path, bytes).unwrap();

    let (code, json) = verify(&path, &["--include", "p.txt"]);

    assert_ne!(code, 0, "{json}");
    assert_eq!(json["data"]["status"], "FAIL", "{json}");
}

#[test]
fn a_selected_encrypted_entry_with_the_right_password_extracts() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out");
    let right = password_file(&dir, PASSWORD);

    let (code, json) = extract(
        &mixed_zip(&dir),
        &out,
        &["--password-file", right.to_str().unwrap()],
    );

    assert_eq!(code, 0, "{json}");
    assert_eq!(std::fs::read(out.join("sub/e.txt")).unwrap(), b"secret\n");
}
