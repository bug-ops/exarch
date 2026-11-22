//! The `mark_incomplete` JSON warning has a live trigger on macOS: an ACL that
//! denies extended-attribute writes on the destination (write arm) or reads on
//! the archive (read arm) (#1212).
#![cfg(target_os = "macos")]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]
#![expect(clippy::disallowed_methods, reason = "integration test fixture setup")]

use std::path::Path;
use std::process::Command;

use assert_cmd::cargo::cargo_bin_cmd;
use tempfile::TempDir;

fn run(program: &str, args: &[&str]) -> Option<std::process::Output> {
    let output = Command::new(program).args(args).output().ok()?;
    output.status.success().then_some(output)
}

/// Removes the ACLs of `path` on drop so the temp directory can be deleted.
struct AclGuard<'a>(&'a Path);

impl Drop for AclGuard<'_> {
    fn drop(&mut self) {
        let _ = run("chmod", &["-N", &self.0.to_string_lossy()]);
    }
}

fn user_name() -> Option<String> {
    let output = run("id", &["-un"])?;
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Denies `permissions` to the current user on `path`; `None` when the ACL
/// cannot be applied here, so the caller skips.
fn deny<'a>(path: &'a Path, permissions: &str) -> Option<AclGuard<'a>> {
    let rule = format!("{} deny {permissions}", user_name()?);
    run("chmod", &["+a", &rule, &path.to_string_lossy()])?;
    Some(AclGuard(path))
}

fn build_archive(dir: &Path, symlink: Option<&str>) -> Option<std::path::PathBuf> {
    let path = dir.join("a.tar");
    let mut builder = tar::Builder::new(std::fs::File::create(&path).unwrap());
    let mut header = tar::Header::new_gnu();
    header.set_size(4);
    header.set_mode(0o644);
    builder
        .append_data(&mut header, "f.txt", &b"data"[..])
        .unwrap();
    if let Some(name) = symlink {
        let mut link = tar::Header::new_gnu();
        link.set_size(0);
        link.set_entry_type(tar::EntryType::Symlink);
        link.set_mode(0o777);
        builder.append_link(&mut link, name, "target.txt").unwrap();
    }
    builder.finish().unwrap();
    drop(builder);
    let mark = "0083;5f3c8d11;Safari;3F2D5A10-1111-4222-8333-444455556666";
    run(
        "xattr",
        &["-w", "com.apple.quarantine", mark, &path.to_string_lossy()],
    )?;
    Some(path)
}

fn marked_archive(dir: &Path) -> Option<std::path::PathBuf> {
    build_archive(dir, None)
}

/// A marked archive whose symlink entry is refused after `f.txt` is written,
/// so the extraction fails with a partial report.
fn failing_marked_archive(dir: &Path) -> Option<std::path::PathBuf> {
    build_archive(dir, Some("link"))
}

fn extract_json(archive: &Path, dest: &Path) -> serde_json::Value {
    let output = cargo_bin_cmd!("exarch")
        .args(["extract", "--json", "--mark-propagation", "when-marked"])
        .arg(archive)
        .arg(dest)
        .output()
        .unwrap();
    serde_json::from_slice(&output.stdout).unwrap()
}

fn warning_kinds(json: &serde_json::Value) -> Vec<&str> {
    json["data"]["warnings"]
        .as_array()
        .map_or_default(|warnings| warnings.iter().filter_map(|w| w["kind"].as_str()).collect())
}

#[test]
fn control_without_acl_has_no_warning() {
    let dir = TempDir::new().unwrap();
    let Some(archive) = marked_archive(dir.path()) else {
        eprintln!("skipped: xattr is unavailable");
        return;
    };
    let dest = dir.path().join("dest");
    std::fs::create_dir(&dest).unwrap();

    let json = extract_json(&archive, &dest);

    assert_eq!(json["data"]["mark_propagation"]["state"], "propagated");
    assert_eq!(json["data"]["mark_propagation"]["failed"], 0);
    assert!(warning_kinds(&json).is_empty(), "{json}");
}

#[test]
fn write_arm_acl_on_the_destination_warns_mark_incomplete() {
    let dir = TempDir::new().unwrap();
    let Some(archive) = marked_archive(dir.path()) else {
        eprintln!("skipped: xattr is unavailable");
        return;
    };
    let dest = dir.path().join("dest");
    std::fs::create_dir(&dest).unwrap();
    let Some(_guard) = deny(&dest, "writeextattr,file_inherit,directory_inherit") else {
        eprintln!("skipped: chmod +a is unavailable");
        return;
    };

    let json = extract_json(&archive, &dest);

    assert_eq!(json["data"]["mark_propagation"]["state"], "propagated");
    assert_eq!(json["data"]["mark_propagation"]["marked"], 0);
    assert_eq!(json["data"]["mark_propagation"]["failed"], 1);
    assert_eq!(warning_kinds(&json), ["mark_incomplete"], "{json}");
}

#[test]
fn read_arm_acl_on_the_archive_warns_mark_incomplete() {
    let dir = TempDir::new().unwrap();
    let Some(archive) = marked_archive(dir.path()) else {
        eprintln!("skipped: xattr is unavailable");
        return;
    };
    let dest = dir.path().join("dest");
    std::fs::create_dir(&dest).unwrap();
    let Some(_guard) = deny(&archive, "readextattr") else {
        eprintln!("skipped: chmod +a is unavailable");
        return;
    };

    let json = extract_json(&archive, &dest);

    assert_eq!(json["data"]["mark_propagation"]["state"], "unreadable");
    assert_eq!(warning_kinds(&json), ["mark_incomplete"], "{json}");
}

fn partial_warning_kinds(json: &serde_json::Value) -> Vec<&str> {
    json["error"]["partial_report"]["warnings"]
        .as_array()
        .map_or_default(|warnings| warnings.iter().filter_map(|w| w["kind"].as_str()).collect())
}

#[test]
fn failing_run_without_acl_has_no_mark_warning() {
    let dir = TempDir::new().unwrap();
    let Some(archive) = failing_marked_archive(dir.path()) else {
        eprintln!("skipped: xattr is unavailable");
        return;
    };
    let dest = dir.path().join("dest");
    std::fs::create_dir(&dest).unwrap();

    let json = extract_json(&archive, &dest);

    assert!(json["error"]["partial_report"]["files_extracted"].as_u64() >= Some(1));
    assert!(
        !partial_warning_kinds(&json).contains(&"mark_incomplete"),
        "{json}"
    );
}

#[test]
fn failing_run_with_read_arm_acl_warns_mark_incomplete_in_the_partial_report() {
    let dir = TempDir::new().unwrap();
    let Some(archive) = failing_marked_archive(dir.path()) else {
        eprintln!("skipped: xattr is unavailable");
        return;
    };
    let dest = dir.path().join("dest");
    std::fs::create_dir(&dest).unwrap();
    let Some(_guard) = deny(&archive, "readextattr") else {
        eprintln!("skipped: chmod +a is unavailable");
        return;
    };

    let json = extract_json(&archive, &dest);

    assert_eq!(json["status"], "error");
    assert!(json["error"]["partial_report"]["files_extracted"].as_u64() >= Some(1));
    assert_eq!(partial_warning_kinds(&json), ["mark_incomplete"], "{json}");
}

#[test]
fn failing_run_with_write_arm_acl_warns_mark_incomplete_in_the_partial_report() {
    let dir = TempDir::new().unwrap();
    let Some(archive) = failing_marked_archive(dir.path()) else {
        eprintln!("skipped: xattr is unavailable");
        return;
    };
    let dest = dir.path().join("dest");
    std::fs::create_dir(&dest).unwrap();
    let Some(_guard) = deny(&dest, "writeextattr,file_inherit,directory_inherit") else {
        eprintln!("skipped: chmod +a is unavailable");
        return;
    };

    let json = extract_json(&archive, &dest);

    assert_eq!(json["status"], "error");
    assert_eq!(partial_warning_kinds(&json), ["mark_incomplete"], "{json}");
}
