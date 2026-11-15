//! Acceptance contract of #1231: a repeated SIGINT while the run is blocked in
//! a read takes the forced exit. The block comes from the `test-hooks` seam
//! `EXARCH_TEST_STALL_AT_ENTRY=<n>`, which reads stdin (held open, never
//! written) when entry `n` starts; no FIFO is used as the archive path. The
//! hook announces the stall with a line on stderr, which the tests wait for
//! instead of polling the filesystem.

#![cfg(all(unix, feature = "test-hooks", debug_assertions))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;

use assert_cmd::cargo::cargo_bin_cmd;
use tempfile::TempDir;

mod stall_support;

const STALL_ENTRY: usize = 1;
const SIGINT: i32 = 2;

fn write_tar(path: &Path, entries: usize) {
    let mut builder = tar::Builder::new(std::fs::File::create(path).unwrap());
    for i in 0..entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(1);
        header.set_mode(0o644);
        builder
            .append_data(&mut header, format!("d/f{i}"), &b"x"[..])
            .unwrap();
    }
    builder.finish().unwrap();
}

fn run_stalled_until_repeated_sigint(json: bool) -> (std::process::ExitStatus, String, TempDir) {
    let temp = TempDir::new().unwrap();
    let archive = temp.path().join("m.tar");
    write_tar(&archive, 8);
    let out = temp.path().join("out");

    let args: &[&str] = if json {
        &["--json", "extract"]
    } else {
        &["extract"]
    };
    let mut stalled = stall_support::spawn(args, &archive, &out, STALL_ENTRY);
    stalled.wait_ready(STALL_ENTRY);
    let (status, stdout) = stalled.interrupt_until_exit();
    (status, stdout, temp)
}

#[test]
fn repeated_sigint_under_json_forces_the_exit_by_the_signal() {
    let (status, stdout, temp) = run_stalled_until_repeated_sigint(true);

    assert_eq!(status.signal(), Some(SIGINT), "{status:?}");
    assert_eq!(status.code(), None, "{status:?}");
    let documents: Vec<serde_json::Value> = serde_json::Deserializer::from_str(&stdout)
        .into_iter()
        .collect::<Result<_, _>>()
        .unwrap_or_else(|error| panic!("{error}; stdout: {stdout:?}"));
    assert_eq!(documents.len(), 1, "{stdout:?}");
    let json = &documents[0];
    assert_eq!(json["status"], "error", "{json}");
    assert_eq!(json["error"]["kind"], "Cancelled", "{json}");
    let canonical = temp.path().canonicalize().unwrap();
    let hint = json["error"]["hint"].as_str().expect("hint text");
    assert!(
        hint.contains(&format!("in {}:", canonical.display())),
        "{hint}"
    );
}

#[test]
fn repeated_sigint_without_json_dies_by_the_signal() {
    let (status, _stdout, _temp) = run_stalled_until_repeated_sigint(false);

    assert_eq!(status.signal(), Some(SIGINT), "{status:?}");
    assert_eq!(status.code(), None, "{status:?}");
}

#[test]
fn stall_hook_is_inert_without_the_environment_variable() {
    let temp = TempDir::new().unwrap();
    let archive = temp.path().join("m.tar");
    write_tar(&archive, 3);

    let output = Command::new(cargo_bin_cmd!("exarch").get_program())
        .arg("extract")
        .arg(&archive)
        .arg(temp.path().join("out"))
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
}
