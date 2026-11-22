//! The `--sandbox` outcome rides on the `--json` error envelope too, and a
//! failed `require` has its own error kind.

mod common;

use assert_cmd::cargo::cargo_bin_cmd;
use common::Member;
use common::write_tar;
use tempfile::TempDir;

fn json_of(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| panic!("{error}: {output:?}"))
}

#[test]
fn test_sandbox_require_with_atomic_is_a_typed_error_that_carries_the_status() {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("m.tar");
    write_tar(&archive, &[Member::File("a")]);

    let output = cargo_bin_cmd!("exarch")
        .args(["extract", "--json", "--sandbox", "require", "--atomic"])
        .arg(&archive)
        .arg(dir.path().join("out"))
        .output()
        .unwrap();

    assert!(!output.status.success(), "{output:?}");
    let json = json_of(&output);
    assert_eq!(json["status"], "error", "{json}");
    assert_eq!(json["error"]["kind"], "SandboxNotEnforced", "{json}");
    assert_eq!(json["sandbox"]["status"], "unavailable", "{json}");
}

#[test]
fn test_sandbox_best_effort_error_envelope_keeps_the_sandbox_key() {
    let dir = TempDir::new().unwrap();

    let output = cargo_bin_cmd!("exarch")
        .args(["list", "--json", "--sandbox", "best-effort"])
        .arg(dir.path().join("missing.tar"))
        .output()
        .unwrap();

    assert!(!output.status.success(), "{output:?}");
    let json = json_of(&output);
    assert_eq!(json["status"], "error", "{json}");
    assert!(json["sandbox"].is_object(), "{json}");
}

#[test]
fn test_error_without_the_flag_has_no_sandbox_key() {
    let dir = TempDir::new().unwrap();

    let output = cargo_bin_cmd!("exarch")
        .args(["list", "--json"])
        .arg(dir.path().join("missing.tar"))
        .output()
        .unwrap();

    assert!(json_of(&output).get("sandbox").is_none());
}
