//! Acceptance contract of #1025: `--sandbox <off|best-effort|require>` confines
//! the CLI with Landlock on Linux and never claims more than the kernel
//! enforced.
//!
//! Linux tests that need an enforcing kernel return early when Landlock is
//! missing, unless `EXARCH_REQUIRE_LANDLOCK=1` makes that a failure (the CI
//! runner probe). The EACCES probe needs the `test-hooks` feature.

#![expect(clippy::unwrap_used, reason = "integration test helpers")]

mod common;

use std::path::Path;
use std::path::PathBuf;

use assert_cmd::cargo::cargo_bin_cmd;
use common::Member;
use common::write_tar;
use tempfile::TempDir;

fn archive_in(dir: &TempDir, members: &[Member<'_>]) -> PathBuf {
    let archive = dir.path().join("m.tar");
    write_tar(&archive, members);
    archive
}

fn extract_json(archive: &Path, out: &Path, flags: &[&str]) -> (i32, serde_json::Value) {
    let output = cargo_bin_cmd!("exarch")
        .args(["extract", "--json"])
        .args(flags)
        .arg(archive)
        .arg(out)
        .output()
        .unwrap();
    let json = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {output:?}"));
    (output.status.code().unwrap_or(-1), json)
}

fn tree(root: &Path) -> Vec<(PathBuf, Option<PathBuf>)> {
    fn visit(root: &Path, dir: &Path, out: &mut Vec<(PathBuf, Option<PathBuf>)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let rel = path.strip_prefix(root).unwrap().to_path_buf();
            if path.is_symlink() {
                out.push((rel, Some(std::fs::read_link(&path).unwrap())));
            } else if path.is_dir() {
                out.push((rel, None));
                visit(root, &path, out);
            } else {
                out.push((rel, None));
            }
        }
    }
    let mut out = Vec::new();
    visit(root, root, &mut out);
    out.sort();
    out
}

#[cfg(target_os = "linux")]
fn landlock_required() -> bool {
    std::env::var_os("EXARCH_REQUIRE_LANDLOCK").is_some()
}

/// `true` when this kernel enforces; panics instead of skipping when the
/// runner promised Landlock.
#[cfg(target_os = "linux")]
fn kernel_enforces() -> bool {
    let dir = TempDir::new().unwrap();
    let archive = archive_in(&dir, &[Member::File("probe")]);
    let (code, _) = extract_json(&archive, &dir.path().join("out"), &["--sandbox", "require"]);
    if code == 0 {
        return true;
    }
    assert!(
        !landlock_required(),
        "EXARCH_REQUIRE_LANDLOCK is set but --sandbox require failed"
    );
    false
}

#[test]
fn test_sandbox_off_is_the_default_and_adds_no_json_key() {
    let dir = TempDir::new().unwrap();
    let archive = archive_in(&dir, &[Member::File("a")]);

    let (code, json) = extract_json(&archive, &dir.path().join("out"), &[]);
    let (code_off, json_off) =
        extract_json(&archive, &dir.path().join("out2"), &["--sandbox", "off"]);

    assert_eq!((code, code_off), (0, 0));
    assert!(json.get("sandbox").is_none(), "{json}");
    assert!(json_off.get("sandbox").is_none(), "{json_off}");
}

#[test]
fn test_sandbox_best_effort_reports_a_status_and_never_fails_the_run() {
    let dir = TempDir::new().unwrap();
    let archive = archive_in(
        &dir,
        &[Member::File("a"), Member::Dir("d"), Member::File("d/b")],
    );
    let plain_out = dir.path().join("plain");
    let boxed_out = dir.path().join("boxed");

    let (code_plain, _) = extract_json(&archive, &plain_out, &[]);
    let (code_boxed, json) = extract_json(&archive, &boxed_out, &["--sandbox", "best-effort"]);

    assert_eq!((code_plain, code_boxed), (0, 0), "{json}");
    assert!(
        json["sandbox"].is_object() || json["sandbox"].is_string(),
        "{json}"
    );
    assert_eq!(tree(&plain_out), tree(&boxed_out));
}

#[cfg(target_os = "linux")]
#[test]
fn test_sandbox_require_enforces_and_reports_enforced() {
    if !kernel_enforces() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let archive = archive_in(&dir, &[Member::File("a")]);

    let (code, json) = extract_json(&archive, &dir.path().join("out"), &["--sandbox", "require"]);

    assert_eq!(code, 0, "{json}");
    assert!(
        json["sandbox"]
            .to_string()
            .to_lowercase()
            .contains("enforced"),
        "{json}"
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn test_sandbox_require_off_linux_fails_before_any_archive_access() {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("missing.tar");
    let out = dir.path().join("out");

    let output = cargo_bin_cmd!("exarch")
        .args(["extract", "--sandbox", "require"])
        .arg(&archive)
        .arg(&out)
        .output()
        .unwrap();

    assert!(!output.status.success(), "{output:?}");
    assert!(!out.exists());
    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    assert!(stderr.contains("sandbox"), "{stderr}");
}

#[test]
fn test_sandbox_require_with_atomic_staging_fails_before_extracting() {
    let dir = TempDir::new().unwrap();
    let archive = archive_in(&dir, &[Member::File("a")]);
    let out = dir.path().join("out");

    let (code, json) = extract_json(&archive, &out, &["--sandbox", "require", "--atomic"]);

    assert_ne!(code, 0, "{json}");
    assert!(!out.join("a").exists());
}

#[test]
fn test_sandbox_is_refused_on_create() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("f"), b"x").unwrap();

    cargo_bin_cmd!("exarch")
        .args(["create", "--sandbox", "best-effort"])
        .arg(dir.path().join("o.tar.gz"))
        .arg(dir.path().join("f"))
        .assert()
        .failure();
}

#[test]
fn test_sandbox_rejects_an_unknown_mode() {
    let dir = TempDir::new().unwrap();
    let archive = archive_in(&dir, &[Member::File("a")]);

    cargo_bin_cmd!("exarch")
        .args(["extract", "--sandbox", "strict"])
        .arg(&archive)
        .arg(dir.path().join("out"))
        .assert()
        .failure();
}

#[test]
fn test_sandbox_list_and_verify_succeed_with_the_archive_read_only() {
    for command in ["list", "verify"] {
        let dir = TempDir::new().unwrap();
        let archive = archive_in(
            &dir,
            &[Member::File("a"), Member::Dir("d"), Member::File("d/b")],
        );

        let output = cargo_bin_cmd!("exarch")
            .args([command, "--json", "--sandbox", "best-effort"])
            .arg(&archive)
            .output()
            .unwrap();

        assert!(output.status.success(), "{command}: {output:?}");
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(json.get("sandbox").is_some(), "{command}: {json}");
    }
}

#[cfg(unix)]
#[test]
fn test_sandbox_extract_of_links_and_nested_dirs_matches_the_unsandboxed_tree() {
    let dir = TempDir::new().unwrap();
    let archive = archive_in(
        &dir,
        &[
            Member::Dir("d"),
            Member::File("d/real"),
            Member::Symlink {
                name: "d/ln",
                target: "real",
            },
            Member::Dir("e"),
            Member::File("e/x"),
        ],
    );
    let plain_out = dir.path().join("plain");
    let boxed_out = dir.path().join("boxed");

    let flags = ["--allow-symlinks"];
    let (code_plain, _) = extract_json(&archive, &plain_out, &flags);
    let (code_boxed, json) = extract_json(
        &archive,
        &boxed_out,
        &["--allow-symlinks", "--sandbox", "best-effort"],
    );

    assert_eq!((code_plain, code_boxed), (0, 0), "{json}");
    assert_eq!(tree(&plain_out), tree(&boxed_out));
}

#[test]
fn test_sandbox_creates_a_missing_destination_like_the_unsandboxed_run() {
    let dir = TempDir::new().unwrap();
    let archive = archive_in(&dir, &[Member::File("a")]);
    let plain_out = dir.path().join("nested/plain");
    let boxed_out = dir.path().join("nested/boxed");

    let (code_plain, plain) = extract_json(&archive, &plain_out, &[]);
    let (code_boxed, boxed) = extract_json(&archive, &boxed_out, &["--sandbox", "best-effort"]);

    assert_eq!((code_plain, code_boxed), (0, 0), "{boxed}");
    assert_eq!(tree(&plain_out), tree(&boxed_out));
    assert_eq!(plain["files_extracted"], boxed["files_extracted"]);
}

#[cfg(all(target_os = "linux", feature = "test-hooks"))]
#[test]
fn test_sandbox_blocks_a_create_outside_the_destination_with_eacces() {
    if !kernel_enforces() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let archive = archive_in(&dir, &[Member::File("a")]);
    let outside = dir.path().join("outside-probe");

    let output = cargo_bin_cmd!("exarch")
        .args(["extract", "--sandbox", "require"])
        .arg(&archive)
        .arg(dir.path().join("out"))
        .env("EXARCH_TEST_SANDBOX_PROBE", &outside)
        .output()
        .unwrap();

    assert!(!outside.exists(), "the sandbox let a create through");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("EACCES") || stderr.to_lowercase().contains("permission denied"),
        "{stderr}"
    );
}

#[cfg(all(target_os = "linux", feature = "test-hooks"))]
#[test]
fn test_sandbox_best_effort_probe_is_denied_when_enforced() {
    if !kernel_enforces() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let archive = archive_in(&dir, &[Member::File("a")]);
    let outside = dir.path().join("outside-probe");

    cargo_bin_cmd!("exarch")
        .args(["extract", "--sandbox", "best-effort"])
        .arg(&archive)
        .arg(dir.path().join("out"))
        .env("EXARCH_TEST_SANDBOX_PROBE", &outside)
        .output()
        .unwrap();

    assert!(!outside.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn test_sandbox_require_with_a_password_file_outside_the_destination_matches_the_plain_run() {
    use std::os::unix::fs::PermissionsExt as _;

    if !kernel_enforces() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let archive = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../exarch-core/tests/data/encryption/aes256.zip");
    let password_file = dir.path().join("pw");
    std::fs::write(&password_file, b"correct-horse\n").unwrap();
    std::fs::set_permissions(&password_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let plain_out = dir.path().join("plain");
    let boxed_out = dir.path().join("boxed");

    let plain = cargo_bin_cmd!("exarch")
        .args(["extract", "--password-file"])
        .arg(&password_file)
        .arg(&archive)
        .arg(&plain_out)
        .output()
        .unwrap();
    let boxed = cargo_bin_cmd!("exarch")
        .args(["extract", "--sandbox", "require", "--password-file"])
        .arg(&password_file)
        .arg(&archive)
        .arg(&boxed_out)
        .output()
        .unwrap();

    assert!(plain.status.success(), "{plain:?}");
    assert!(boxed.status.success(), "{boxed:?}");
    assert_eq!(tree(&plain_out), tree(&boxed_out));
}
