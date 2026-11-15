//! `--decode-reuse temp-file` under `--sandbox require`: the unnamed spool
//! lives in the temporary directory, outside the grant, so the kernel refuses
//! it and the run falls back to decoding again. The extraction still succeeds
//! and yields the same bytes.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::io::Write as _;

use assert_cmd::cargo::cargo_bin_cmd;
use common::Member;
use common::write_tar;
use tempfile::TempDir;

fn kernel_enforces() -> bool {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("m.tar");
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

/// 64 KiB of xorshift output: deflate cannot shrink it, so the ratio check of
/// the default `SecurityConfig` stays quiet.
fn payload() -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    (0..64 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

#[test]
fn test_sandbox_require_with_temp_file_reuse_falls_back_and_extracts() {
    if !kernel_enforces() {
        return;
    }
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("m.zip");
    let mut writer = zip::ZipWriter::new(std::fs::File::create(&archive).unwrap());
    writer
        .start_file("a.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    writer.write_all(&payload()).unwrap();
    writer.finish().unwrap();
    let scratch = TempDir::new().unwrap();
    let out = dir.path().join("out");

    let output = cargo_bin_cmd!("exarch")
        .args([
            "extract",
            "--sandbox",
            "require",
            "--decode-reuse",
            "temp-file",
        ])
        .arg(&archive)
        .arg(&out)
        .env("TMPDIR", scratch.path())
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(std::fs::read(out.join("a.txt")).unwrap(), payload());
    assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);
}
