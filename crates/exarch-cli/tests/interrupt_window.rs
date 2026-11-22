//! Acceptance contract of #1249: a SIGINT delivered after the interrupt
//! `prepare` and before `start` is buffered, not acted on by default. The stall
//! comes from the `test-hooks` seam `EXARCH_TEST_STALL_AFTER_PREPARE=1`, which
//! blocks on stdin at the end of `prepare` and announces it on stderr.

#![cfg(all(unix, feature = "test-hooks", debug_assertions))]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]

mod common;
mod stall_support;

use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::path::PathBuf;

use common::Member;
use common::write_tar;
use tempfile::TempDir;

const SIGINT: i32 = 2;

fn archive_in(dir: &Path) -> PathBuf {
    let archive = dir.join("m.tar");
    write_tar(&archive, &[Member::File("a"), Member::File("b")]);
    archive
}

fn staging_leftovers(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".exarch-"))
        .collect()
}

fn json(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout).unwrap_or_else(|error| panic!("{error}; stdout: {stdout:?}"))
}

#[test]
fn a_sigint_before_start_is_buffered_and_cancels_the_run_when_it_starts() {
    let work = TempDir::new().unwrap();
    let archive = archive_in(work.path());
    let out = work.path().join("out");
    let mut stalled = stall_support::spawn_after_prepare(&["--json", "extract"], &archive, &out);
    stalled.wait_ready_after_prepare();

    stalled.interrupt_once();
    stalled.release();
    let (status, stdout) = stalled.finish();

    assert_eq!(status.signal(), Some(SIGINT), "{status:?}");
    assert_eq!(json(&stdout)["error"]["kind"], "Cancelled", "{stdout}");
    assert!(
        !out.exists(),
        "a cancelled run leaves the destination absent"
    );
    assert_eq!(staging_leftovers(work.path()), Vec::<String>::new());
}

#[cfg(target_os = "linux")]
#[test]
fn a_prepared_interrupt_dropped_unstarted_discards_the_buffered_signal() {
    let work = TempDir::new().unwrap();
    let archive = archive_in(work.path());
    let blocker = work.path().join("afile");
    std::fs::write(&blocker, "f").unwrap();
    let out = blocker.join("sub");
    let mut stalled = stall_support::spawn_after_prepare(
        &["--json", "extract", "--sandbox", "best-effort"],
        &archive,
        &out,
    );
    stalled.wait_ready_after_prepare();

    stalled.interrupt_once();
    stalled.release();
    let (status, stdout) = stalled.finish();

    assert_eq!(status.signal(), None, "{status:?}");
    assert_eq!(status.code(), Some(1), "{status:?}");
    let document = json(&stdout);
    assert_eq!(document["status"], "error", "{document}");
    assert_ne!(document["error"]["kind"], "Cancelled", "{document}");
    assert_eq!(document["error"]["step"], "create", "{document}");
}
