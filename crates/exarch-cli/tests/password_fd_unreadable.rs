//! `--password-fd` naming a descriptor that is open but write-only reports
//! that it is not readable, without the "is it inherited and open?" hint
//! (#1264). The live check is macOS only: Linux reopens `/dev/fd/N` through
//! `/proc` by the file's own mode, so a write-only descriptor on a readable
//! file opens there.

#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::fs::File;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

use tempfile::TempDir;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Runs `extract --password-fd <fd>` with `fd` (1 or 2) redirected to a
/// write-only file; returns everything the process printed on stderr.
fn extract_with_write_only_fd(fd: u8) -> (bool, String) {
    let dir = TempDir::new().unwrap();
    let sink = dir.path().join("sink.txt");
    let writable = Stdio::from(File::create(&sink).unwrap());
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("exarch"));
    command
        .args(["extract", "--password-fd", &fd.to_string()])
        .arg(fixture("encrypted-aes256.zip"))
        .arg(dir.path().join("out"));
    if fd == 1 {
        command.stdout(writable).stderr(Stdio::piped());
    } else {
        command.stderr(writable).stdout(Stdio::piped());
    }

    let output = command.output().unwrap();

    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stderr),
        std::fs::read_to_string(&sink).unwrap()
    );
    (output.status.success(), printed)
}

#[test]
fn extract_with_a_write_only_password_fd_reports_it_is_not_readable() {
    for fd in [1u8, 2] {
        let (success, printed) = extract_with_write_only_fd(fd);

        assert!(!success, "fd {fd}: {printed}");
        assert!(
            printed.contains(&format!("file descriptor {fd}")),
            "fd {fd}: {printed}"
        );
        assert!(
            printed.contains("not readable"),
            "fd {fd}: the message names the problem: {printed}"
        );
    }
}

#[test]
fn extract_with_a_write_only_password_fd_does_not_suggest_an_inheritance_problem() {
    for fd in [1u8, 2] {
        let (_, printed) = extract_with_write_only_fd(fd);

        assert!(
            !printed.contains("inherited"),
            "fd {fd}: the descriptor is open, so no inheritance hint: {printed}"
        );
    }
}
