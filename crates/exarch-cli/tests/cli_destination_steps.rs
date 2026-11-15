//! Acceptance contract of #1197 (`error.step` in the JSON error), #1206 (typed
//! destination failures in every staging mode), #1204 (one error kind for a
//! file over an existing symlink) and #1205 (`verify` reports a directory
//! over an earlier file as the typed Medium refusal).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::Member;
use common::extract_error;
use common::write_tar;
use tempfile::TempDir;

const STEPS: [&str; 6] = ["resolve", "create", "open", "list", "write_access", "stage"];

fn archive_in(temp: &TempDir) -> std::path::PathBuf {
    let archive = temp.path().join("a.tar");
    write_tar(&archive, &[Member::File("f")]);
    archive
}

fn step(json: &serde_json::Value) -> &str {
    json["error"]["step"].as_str().expect("error.step")
}

#[test]
fn test_extract_destination_below_a_file_reports_the_create_step_in_every_mode() {
    let temp = TempDir::new().expect("temp dir");
    let archive = archive_in(&temp);
    let blocker = temp.path().join("afile");
    std::fs::write(&blocker, "f").expect("file");
    let dest = blocker.join("sub");

    for flags in [&[][..], &["--atomic"][..], &["--atomic", "--force"][..]] {
        let json = extract_error(&archive, &dest, flags);

        assert_eq!(json["error"]["kind"], "IoError", "{flags:?}: {json}");
        let io_kind = if cfg!(windows) {
            "AlreadyExists"
        } else {
            "NotADirectory"
        };
        assert_eq!(json["error"]["io_kind"], io_kind, "{flags:?}: {json}");
        assert_eq!(step(&json), "create", "{flags:?}: {json}");
        assert!(STEPS.contains(&step(&json)));
    }
}

#[test]
fn test_extract_error_step_is_present_only_for_destination_failures() {
    let temp = TempDir::new().expect("temp dir");
    let archive = archive_in(&temp);
    let out = temp.path().join("out");
    std::fs::create_dir_all(out.join("f")).expect("occupant");

    let json = extract_error(&archive, &out, &[]);

    assert_eq!(json["error"]["kind"], "OutputExists", "{json}");
    assert!(json["error"].get("step").is_none(), "{json}");
}

#[cfg(unix)]
#[test]
fn test_extract_atomic_too_long_leaf_is_the_typed_destination_error_with_the_plain_step() {
    let temp = TempDir::new().expect("temp dir");
    let archive = archive_in(&temp);
    let dest = temp.path().join("d").join("n".repeat(300));

    let plain = extract_error(&archive, &dest, &[]);
    let atomic = extract_error(&archive, &dest, &["--atomic"]);

    let text = atomic["error"]["message"].as_str().expect("message");
    assert!(text.contains("Destination is not accessible"), "{atomic}");
    assert!(!text.contains("Failed to process"), "{atomic}");
    assert_eq!(step(&atomic), step(&plain), "{plain} vs {atomic}");
    assert_eq!(atomic["error"]["io_kind"], plain["error"]["io_kind"]);
}

#[cfg(unix)]
#[test]
fn test_extract_into_a_destination_without_search_permission_is_a_typed_write_access_failure() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("temp dir");
    let archive = archive_in(&temp);
    let dest = temp.path().join("ns");
    std::fs::create_dir(&dest).expect("destination");
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    let probe = std::fs::metadata(dest.join("f")).unwrap_err();
    if probe.kind() != std::io::ErrorKind::PermissionDenied {
        return;
    }

    let json = extract_error(&archive, &dest, &[]);

    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o700)).expect("restore");
    let text = json["error"]["message"].as_str().expect("message");
    assert_eq!(json["error"]["io_kind"], "PermissionDenied", "{json}");
    assert_eq!(step(&json), "write_access", "{json}");
    assert!(text.contains("Destination is not accessible"), "{json}");
    assert!(!text.contains("Failed to process"), "{json}");
}

#[cfg(unix)]
#[test]
fn test_extract_file_over_an_existing_symlink_is_an_occupied_refusal_without_force() {
    let temp = TempDir::new().expect("temp dir");
    let archive = temp.path().join("f.tar");
    write_tar(&archive, &[Member::File("x")]);
    let out = temp.path().join("out");
    std::fs::create_dir(&out).expect("destination");
    std::fs::write(out.join("t"), "old").expect("target");
    std::os::unix::fs::symlink("t", out.join("x")).expect("symlink");

    let json = extract_error(&archive, &out, &[]);

    assert_eq!(json["error"]["kind"], "OutputExists", "{json}");
    assert_eq!(
        json["error"]["conflicts"],
        serde_json::json!([{"path": "x", "occupant": "symlink"}]),
        "{json}"
    );
    assert_eq!(json["error"]["by"], "existing", "{json}");
}

#[test]
fn test_verify_directory_over_an_earlier_file_is_the_typed_medium_refusal() {
    let temp = TempDir::new().expect("temp dir");
    let archive = temp.path().join("a.tar");
    write_tar(&archive, &[Member::File("x"), Member::Dir("x/")]);

    let stdout = assert_cmd::cargo::cargo_bin_cmd!("exarch")
        .args(["verify", "--json"])
        .arg(&archive)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&stdout).expect("valid JSON");

    assert_eq!(json["data"]["status"], "WARNING", "{json}");
    let issues = json["data"]["issues"].as_array().expect("issues");
    let issue = issues
        .iter()
        .find(|i| {
            i["entry_path"]
                .as_str()
                .is_some_and(|p| p.trim_end_matches('/') == "x")
        })
        .unwrap_or_else(|| panic!("no issue for x: {json}"));
    assert_eq!(issue["severity"], "MEDIUM", "{issue}");
    assert_eq!(issue["category"], "Invalid Archive", "{issue}");
    let text = issue["message"].as_str().expect("message");
    assert!(
        text.contains("refusing to replace the existing file at x"),
        "{issue}"
    );
    assert!(!text.contains("I/O error"), "{issue}");

    assert_cmd::cargo::cargo_bin_cmd!("exarch")
        .args(["verify", "--json", "--strict"])
        .arg(&archive)
        .assert()
        .code(3);
}
