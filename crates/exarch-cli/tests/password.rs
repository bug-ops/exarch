//! Acceptance contract of #1023 on the CLI: the password comes only from a
//! file, a descriptor or a prompt, never from argv or the environment, is never
//! echoed, and a needless or missing password behaves as the library says.
//!
//! The fixtures are the core's AES archives (password `correct-horse`): a
//! `WinZip` AES-256 ZIP and a non-solid 7z with an encrypted header.

#![expect(clippy::unwrap_used, reason = "integration test helpers")]

mod common;

use std::path::Path;
use std::path::PathBuf;

use assert_cmd::cargo::cargo_bin_cmd;
use common::Member;
use common::write_tar;
use tempfile::TempDir;

const PASSWORD: &str = "correct-horse";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn password_file(dir: &TempDir, content: &str) -> PathBuf {
    let path = dir.path().join("password.txt");
    std::fs::write(&path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

fn run(args: &[&str], archive: &Path, out: Option<&Path>) -> std::process::Output {
    let mut command = cargo_bin_cmd!("exarch");
    command.args(args).arg(archive);
    if let Some(out) = out {
        command.arg(out);
    }
    command.output().unwrap()
}

fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = if root.exists() {
        vec![root.to_path_buf()]
    } else {
        Vec::new()
    };
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                found.push(path.strip_prefix(root).unwrap().to_path_buf());
            }
        }
    }
    found.sort();
    found
}

#[test]
fn extract_with_a_password_file_decrypts_a_zip_and_a_header_encrypted_7z() {
    for archive in ["encrypted-aes256.zip", "encrypted-header.7z"] {
        let dir = TempDir::new().unwrap();
        let file = password_file(&dir, &format!("{PASSWORD}\n"));
        let out = dir.path().join("out");

        let output = run(
            &["extract", "--password-file", file.to_str().unwrap()],
            &fixture(archive),
            Some(&out),
        );

        assert!(output.status.success(), "{archive}: {output:?}");
        assert_eq!(
            std::fs::read_to_string(out.join("hello.txt")).unwrap(),
            "hello encrypted\n",
            "{archive}"
        );
        assert_eq!(files_under(&out).len(), 2, "{archive}");
    }
}

#[cfg(unix)]
#[test]
fn extract_with_a_password_fd_reads_the_descriptor() {
    let dir = TempDir::new().unwrap();
    let file = password_file(&dir, &format!("{PASSWORD}\n"));
    let out = dir.path().join("out");

    // The shell opens descriptor 3 on the password file for the child.
    let output = std::process::Command::new("sh")
        .args([
            "-c",
            r#"exec "$0" extract --password-fd 3 "$1" "$2" 3< "$3""#,
        ])
        .arg(assert_cmd::cargo::cargo_bin!("exarch"))
        .arg(fixture("encrypted-aes256.zip"))
        .arg(&out)
        .arg(&file)
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert!(out.join("hello.txt").exists());
}

#[test]
fn extract_without_a_password_reports_password_required_in_json() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out");

    let output = run(
        &["extract", "--json"],
        &fixture("encrypted-aes256.zip"),
        Some(&out),
    );

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["error"]["kind"], "SecurityViolation", "{json}");
    assert_eq!(json["error"]["sub_code"], "ENCRYPTED", "{json}");
    assert_eq!(json["error"]["reason"], "password_required", "{json}");
    assert!(
        json["error"]["hint"]
            .as_str()
            .is_some_and(|hint| hint.contains("--password-file")),
        "{json}"
    );
    assert!(files_under(&out).is_empty());
}

#[test]
fn a_wrong_password_is_refused_and_never_echoed() {
    let dir = TempDir::new().unwrap();
    let file = password_file(&dir, "s3cr3t-wrong-value\n");
    let out = dir.path().join("out");

    let output = run(
        &[
            "extract",
            "--json",
            "--password-file",
            file.to_str().unwrap(),
        ],
        &fixture("encrypted-aes256.zip"),
        Some(&out),
    );

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let everything = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!everything.contains("s3cr3t"), "{everything}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["error"]["sub_code"], "ENCRYPTED", "{json}");
    assert_eq!(json["error"]["reason"], "wrong_password", "{json}");
    assert!(files_under(&out).is_empty());
}

#[test]
fn a_needless_password_is_ignored() {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("plain.tar");
    write_tar(&archive, &[Member::File("a.txt")]);
    let file = password_file(&dir, "unused\n");
    let out = dir.path().join("out");

    let output = run(
        &["extract", "--password-file", file.to_str().unwrap()],
        &archive,
        Some(&out),
    );

    assert!(output.status.success(), "{output:?}");
    assert!(out.join("a.txt").exists());
}

#[test]
fn list_and_verify_take_the_password_too() {
    let dir = TempDir::new().unwrap();
    let file = password_file(&dir, &format!("{PASSWORD}\n"));
    for command in ["list", "verify"] {
        let output = run(
            &[command, "--password-file", file.to_str().unwrap()],
            &fixture("encrypted-header.7z"),
            None,
        );

        assert!(output.status.success(), "{command}: {output:?}");
    }
    let without = run(&["list"], &fixture("encrypted-header.7z"), None);
    assert!(!without.status.success(), "{without:?}");
}

#[cfg(unix)]
#[test]
fn a_group_readable_password_file_is_refused_before_the_archive_is_touched() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TempDir::new().unwrap();
    let file = password_file(&dir, &format!("{PASSWORD}\n"));
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
    let out = dir.path().join("out");

    let output = run(
        &["extract", "--password-file", file.to_str().unwrap()],
        &dir.path().join("missing.zip"),
        Some(&out),
    );

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("chmod 600"), "{stderr}");
    assert!(!out.exists());
}

#[test]
fn the_password_flags_exclude_each_other_and_there_is_no_argv_value() {
    let dir = TempDir::new().unwrap();
    let file = password_file(&dir, "x\n");
    let archive = fixture("encrypted-aes256.zip");

    let both = run(
        &[
            "extract",
            "--password-file",
            file.to_str().unwrap(),
            "--password-prompt",
        ],
        &archive,
        Some(&dir.path().join("out")),
    );
    let value = run(
        &["extract", "--password", PASSWORD],
        &archive,
        Some(&dir.path().join("out2")),
    );
    let max_kdf = run(
        &["extract", "--max-kdf-work", "1"],
        &archive,
        Some(&dir.path().join("out3")),
    );

    assert!(!both.status.success());
    assert!(!value.status.success());
    assert!(!max_kdf.status.success());
}

#[test]
fn the_environment_never_supplies_a_password() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out");

    let output = cargo_bin_cmd!("exarch")
        .env("EXARCH_PASSWORD", PASSWORD)
        .env("PASSWORD", PASSWORD)
        .args(["extract"])
        .arg(fixture("encrypted-aes256.zip"))
        .arg(&out)
        .output()
        .unwrap();

    assert!(!output.status.success(), "{output:?}");
    assert!(files_under(&out).is_empty());
}

#[test]
fn a_prompt_without_a_terminal_fails_before_the_destination_is_made() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out");

    let output = cargo_bin_cmd!("exarch")
        .args(["extract", "--password-prompt"])
        .arg(fixture("encrypted-aes256.zip"))
        .arg(&out)
        .write_stdin("typed-password\n")
        .output()
        .unwrap();

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("interactive terminal"), "{stderr}");
    assert!(!stderr.contains("typed-password"), "{stderr}");
    assert!(!out.exists());
}

#[cfg(target_os = "linux")]
mod sandbox_interplay {
    use super::*;

    fn kernel_enforces() -> bool {
        let dir = TempDir::new().unwrap();
        let archive = dir.path().join("probe.tar");
        write_tar(&archive, &[Member::File("probe")]);
        let output = run(
            &["extract", "--sandbox", "require"],
            &archive,
            Some(&dir.path().join("out")),
        );
        if output.status.success() {
            return true;
        }
        assert!(
            std::env::var_os("EXARCH_REQUIRE_LANDLOCK").is_none(),
            "EXARCH_REQUIRE_LANDLOCK is set but --sandbox require failed"
        );
        false
    }

    #[test]
    fn a_password_file_outside_the_destination_works_under_sandbox_require() {
        if !kernel_enforces() {
            return;
        }
        let secret_dir = TempDir::new().unwrap();
        let file = password_file(&secret_dir, &format!("{PASSWORD}\n"));
        let archive = fixture("encrypted-aes256.zip");
        let plain_out = TempDir::new().unwrap();
        let boxed_out = TempDir::new().unwrap();

        let plain = run(
            &["extract", "--password-file", file.to_str().unwrap()],
            &archive,
            Some(plain_out.path()),
        );
        let boxed = run(
            &[
                "extract",
                "--sandbox",
                "require",
                "--password-file",
                file.to_str().unwrap(),
            ],
            &archive,
            Some(boxed_out.path()),
        );

        assert!(plain.status.success(), "{plain:?}");
        assert!(boxed.status.success(), "{boxed:?}");
        assert_eq!(files_under(plain_out.path()), files_under(boxed_out.path()));
    }

    #[test]
    fn a_prompt_without_a_terminal_fails_with_the_prompt_error_not_eacces() {
        if !kernel_enforces() {
            return;
        }
        let dir = TempDir::new().unwrap();

        let output = cargo_bin_cmd!("exarch")
            .args(["extract", "--sandbox", "require", "--password-prompt"])
            .arg(fixture("encrypted-aes256.zip"))
            .arg(dir.path().join("out"))
            .write_stdin("x\n")
            .output()
            .unwrap();

        assert!(!output.status.success(), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("interactive terminal"), "{stderr}");
        assert!(
            !stderr.to_lowercase().contains("permission denied"),
            "{stderr}"
        );
    }
}
