//! Acceptance contract of #1244: `extract --sandbox best-effort|require` into a
//! missing destination keeps the all-or-nothing outcome of the unsandboxed
//! run. A failure, an interrupt or a forced exit leaves the destination absent,
//! the error is the unsandboxed one, and success leaves no `.exarch-*` behind.
//!
//! Linux only. Tests that need an enforcing kernel return early when Landlock
//! is missing, unless `EXARCH_REQUIRE_LANDLOCK` makes that a failure. The
//! stalled-run tests also need the `test-hooks` feature.

#![cfg(target_os = "linux")]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]
#![expect(clippy::disallowed_methods, reason = "integration test fixture setup")]

mod common;
#[cfg(feature = "test-hooks")]
mod stall_support;

use std::path::Path;
use std::path::PathBuf;

use assert_cmd::cargo::cargo_bin_cmd;
use common::Member;
use common::write_tar;
use tempfile::TempDir;

const MODES: [&str; 2] = ["best-effort", "require"];

fn kernel_enforces() -> bool {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("p.tar");
    write_tar(&archive, &[Member::File("probe")]);
    let ok = cargo_bin_cmd!("exarch")
        .args(["extract", "--sandbox", "require"])
        .arg(&archive)
        .arg(dir.path().join("out"))
        .output()
        .unwrap()
        .status
        .success();
    assert!(
        ok || std::env::var_os("EXARCH_REQUIRE_LANDLOCK").is_none(),
        "EXARCH_REQUIRE_LANDLOCK is set but --sandbox require failed"
    );
    ok
}

fn leftovers(parent: &Path) -> Vec<String> {
    std::fs::read_dir(parent)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".exarch-"))
        .collect()
}

struct Outcome {
    code: i32,
    kind: Option<String>,
    destination_exists: bool,
    leftovers: usize,
}

fn extract(archive: &Path, work: &Path, name: &str, flags: &[&str]) -> Outcome {
    let out = work.join(name);
    let output = cargo_bin_cmd!("exarch")
        .args(["extract", "--json"])
        .args(flags)
        .arg(archive)
        .arg(&out)
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {output:?}"));
    Outcome {
        code: output.status.code().unwrap_or(-1),
        kind: json["error"]["kind"].as_str().map(str::to_owned),
        destination_exists: out.exists(),
        leftovers: leftovers(work).len(),
    }
}

fn tree(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn visit(root: &Path, dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(root, &path, out);
            } else {
                out.push((
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    std::fs::read(&path).unwrap(),
                ));
            }
        }
    }
    let mut out = Vec::new();
    visit(root, root, &mut out);
    out.sort();
    out
}

#[test]
fn a_mid_run_failure_into_a_missing_destination_discards_like_the_unsandboxed_run() {
    if !kernel_enforces() {
        return;
    }
    let work = TempDir::new().unwrap();
    let archive = work.path().join("m.tar");
    write_tar(
        &archive,
        &[
            Member::File("a"),
            Member::Symlink {
                name: "l",
                target: "a",
            },
            Member::File("b"),
        ],
    );
    let plain = extract(&archive, work.path(), "plain", &[]);
    assert!(!plain.destination_exists, "the unsandboxed run discards");

    for mode in MODES {
        let boxed = extract(&archive, work.path(), mode, &["--sandbox", mode]);

        assert_eq!(boxed.code, plain.code, "{mode}");
        assert_eq!(boxed.kind, plain.kind, "{mode}");
        assert_ne!(boxed.kind.as_deref(), Some("PartialExtraction"), "{mode}");
        assert!(
            !boxed.destination_exists,
            "{mode}: partial output stayed behind"
        );
        assert_eq!(boxed.leftovers, plain.leftovers, "{mode}");
    }
}

#[test]
fn a_successful_run_into_a_missing_destination_leaves_no_staging_directory() {
    if !kernel_enforces() {
        return;
    }
    let work = TempDir::new().unwrap();
    let archive = work.path().join("m.tar");
    write_tar(
        &archive,
        &[Member::File("a"), Member::Dir("d"), Member::File("d/b")],
    );
    let plain_out = work.path().join("plain");
    cargo_bin_cmd!("exarch")
        .args(["extract"])
        .arg(&archive)
        .arg(&plain_out)
        .assert()
        .success();

    for mode in MODES {
        let out = work.path().join(mode);
        cargo_bin_cmd!("exarch")
            .args(["extract", "--sandbox", mode])
            .arg(&archive)
            .arg(&out)
            .assert()
            .success();

        assert_eq!(tree(&out), tree(&plain_out), "{mode}");
    }
    assert!(
        leftovers(work.path()).is_empty(),
        "{:?}",
        leftovers(work.path())
    );
}

#[test]
fn a_destination_below_a_file_reports_the_create_step_like_the_unsandboxed_run() {
    if !kernel_enforces() {
        return;
    }
    let work = TempDir::new().unwrap();
    let archive = work.path().join("m.tar");
    write_tar(&archive, &[Member::File("a")]);
    let blocker = work.path().join("afile");
    std::fs::write(&blocker, "f").unwrap();
    let dest = blocker.join("sub");

    let run = |flags: &[&str]| -> serde_json::Value {
        let output = cargo_bin_cmd!("exarch")
            .args(["extract", "--json"])
            .args(flags)
            .arg(&archive)
            .arg(&dest)
            .output()
            .unwrap();
        serde_json::from_slice(&output.stdout).unwrap()
    };
    let plain = run(&[]);

    for mode in MODES {
        let boxed = run(&["--sandbox", mode]);

        assert_eq!(
            boxed["error"]["kind"], plain["error"]["kind"],
            "{mode}: {boxed}"
        );
        assert_eq!(boxed["error"]["step"], "create", "{mode}: {boxed}");
        assert_eq!(
            boxed["error"]["io_kind"], plain["error"]["io_kind"],
            "{mode}"
        );
    }
}

#[cfg(feature = "test-hooks")]
#[test]
fn a_forced_exit_while_stalled_leaves_what_the_unsandboxed_forced_exit_leaves() {
    if !kernel_enforces() {
        return;
    }
    let work = TempDir::new().unwrap();
    let archive = work.path().join("m.tar");
    write_tar(
        &archive,
        &[Member::File("a"), Member::File("b"), Member::File("c")],
    );

    let forced = |name: &str, flags: &[&str]| -> (Option<i32>, bool, usize) {
        use std::os::unix::process::ExitStatusExt as _;

        let before = leftovers(work.path()).len();
        let out = work.path().join(name);
        let mut args = vec!["extract"];
        args.extend_from_slice(flags);
        let mut stalled = stall_support::spawn(&args, &archive, &out, 2);
        stalled.wait_ready(2);
        let (status, _stdout) = stalled.interrupt_until_exit();
        (
            status.signal(),
            out.exists(),
            leftovers(work.path()).len() - before,
        )
    };
    let (plain_signal, plain_exists, plain_leftovers) = forced("plain", &[]);
    assert!(!plain_exists);

    for mode in MODES {
        let (signal, exists, left) = forced(mode, &["--sandbox", mode]);

        assert_eq!(signal, plain_signal, "{mode}");
        assert!(!exists, "{mode}: the destination must stay absent");
        assert_eq!(left, plain_leftovers, "{mode}");
    }
}
