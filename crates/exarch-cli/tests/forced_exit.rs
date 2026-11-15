//! Acceptance contract of #1231: a repeated SIGINT while the run is blocked in
//! a read takes the forced exit. The block comes from the `test-hooks` seam
//! `EXARCH_TEST_STALL_AT_ENTRY=<n>`, which reads stdin (held open, never
//! written) when entry `n` starts; no FIFO is used as the archive path.

#![cfg(all(unix, feature = "test-hooks", debug_assertions))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::io::Read as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use assert_cmd::cargo::cargo_bin_cmd;
use tempfile::TempDir;

const DEADLINE: Duration = Duration::from_secs(60);

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

fn staging_exists(parent: &Path) -> bool {
    std::fs::read_dir(parent).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".exarch-")
    })
}

struct Reaped(std::process::Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

const SIGINT: i32 = 2;

fn sigint(child: &std::process::Child) {
    let status = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run kill");
    assert!(status.success(), "{status:?}");
}

fn run_stalled_until_repeated_sigint(json: bool) -> (std::process::ExitStatus, String, TempDir) {
    let temp = TempDir::new().unwrap();
    let archive = temp.path().join("m.tar");
    write_tar(&archive, 8);
    let out = temp.path().join("out");

    let mut command = Command::new(cargo_bin_cmd!("exarch").get_program());
    if json {
        command.arg("--json");
    }
    let mut child = Reaped(
        command
            .arg("extract")
            .arg(&archive)
            .arg(&out)
            .env("EXARCH_TEST_STALL_AT_ENTRY", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn exarch"),
    );
    let held_stdin = child.0.stdin.take();

    let ready_by = Instant::now() + DEADLINE;
    while !staging_exists(temp.path()) {
        assert!(Instant::now() < ready_by, "the run never started staging");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(300));

    let ended_by = Instant::now() + DEADLINE;
    let status = loop {
        sigint(&child.0);
        std::thread::sleep(Duration::from_millis(50));
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < ended_by,
            "the run outlived repeated SIGINTs"
        );
    };
    let mut stdout = Vec::new();
    child
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    drop(held_stdin);
    (status, String::from_utf8_lossy(&stdout).into_owned(), temp)
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
