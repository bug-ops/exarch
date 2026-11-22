//! Acceptance contract of #1245: the `test-hooks` stall hook announces that it
//! is blocked with one stderr line, `exarch-test: stalled at entry <n>`, so a
//! test synchronizes on the line instead of polling and sleeping.

#![cfg(all(unix, feature = "test-hooks", debug_assertions))]

mod common;
mod stall_support;

use common::Member;
use common::write_tar;
use tempfile::TempDir;

fn archive_with_entries(dir: &TempDir, count: usize) -> std::path::PathBuf {
    let names: Vec<String> = (0..count).map(|i| format!("f{i}")).collect();
    let members: Vec<Member<'_>> = names.iter().map(|name| Member::File(name)).collect();
    let archive = dir.path().join("m.tar");
    write_tar(&archive, &members);
    archive
}

#[test]
fn the_hook_writes_the_ready_line_for_the_configured_entry_before_blocking() {
    let dir = TempDir::new().unwrap();
    let archive = archive_with_entries(&dir, 4);
    let stalled = stall_support::spawn(&["extract"], &archive, &dir.path().join("out"), 2);

    let seen = stalled.wait_ready(2);

    assert_eq!(
        seen.iter()
            .filter(|line| **line == stall_support::ready_line(2))
            .count(),
        1,
        "{seen:?}"
    );
}

#[test]
fn the_run_is_still_blocked_after_the_ready_line_until_stdin_is_released() {
    let dir = TempDir::new().unwrap();
    let archive = archive_with_entries(&dir, 4);
    let out = dir.path().join("out");
    let stalled = stall_support::spawn(&["extract"], &archive, &out, 2);
    stalled.wait_ready(2);

    assert!(
        !out.exists(),
        "nothing is published while the run is blocked"
    );
    let (status, _stdout) = stalled.finish();

    assert!(status.success(), "{status:?}");
    assert!(out.join("f3").exists());
}
