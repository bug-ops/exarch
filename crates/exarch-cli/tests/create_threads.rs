//! Acceptance contract of #1027 for the CLI: `create --threads <N>` (a non-zero
//! count, `create` only) yields the same ZIP bytes as the default sequential
//! run.

#![expect(clippy::unwrap_used, reason = "integration test helpers")]
#![expect(clippy::disallowed_methods, reason = "integration test fixture setup")]

use std::path::Path;

use assert_cmd::cargo::cargo_bin_cmd;
use tempfile::TempDir;

fn source() -> TempDir {
    let src = TempDir::new().unwrap();
    std::fs::create_dir_all(src.path().join("sub")).unwrap();
    for i in 0..30 {
        std::fs::write(
            src.path().join(format!("sub/f{i:02}.txt")),
            format!("file {i}\n").repeat(100 + i),
        )
        .unwrap();
    }
    std::fs::write(src.path().join("zero"), b"").unwrap();
    src
}

fn create(src: &Path, out: &Path, threads: Option<&str>) -> assert_cmd::assert::Assert {
    let mut command = cargo_bin_cmd!("exarch");
    command.arg("create").arg(out).arg(src);
    if let Some(threads) = threads {
        command.args(["--threads", threads]);
    }
    command.assert()
}

#[test]
fn test_create_zip_threads_bytes_equal_the_default_run() {
    let src = source();
    let dir = TempDir::new().unwrap();
    let baseline = dir.path().join("baseline.zip");
    create(src.path(), &baseline, None).success();

    for threads in ["1", "2", "4", "8"] {
        let out = dir.path().join(format!("t{threads}.zip"));

        create(src.path(), &out, Some(threads)).success();

        assert!(
            std::fs::read(&out).unwrap() == std::fs::read(&baseline).unwrap(),
            "--threads {threads} changed the ZIP bytes"
        );
    }
}

#[test]
fn test_create_threads_zero_is_a_usage_error() {
    let src = source();
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("zero.zip");

    create(src.path(), &out, Some("0")).failure();

    assert!(!out.exists());
}

#[test]
fn test_create_threads_non_numeric_is_a_usage_error() {
    let src = source();
    let dir = TempDir::new().unwrap();

    create(src.path(), &dir.path().join("x.zip"), Some("many")).failure();
}

#[test]
fn test_create_threads_for_a_tar_output_still_succeeds() {
    let src = source();
    let dir = TempDir::new().unwrap();

    create(src.path(), &dir.path().join("o.tar.gz"), Some("4")).success();
}

#[test]
fn test_extract_refuses_the_threads_flag() {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.tar");
    tar::Builder::new(std::fs::File::create(&archive).unwrap())
        .finish()
        .unwrap();

    cargo_bin_cmd!("exarch")
        .arg("extract")
        .arg(&archive)
        .arg(dir.path().join("out"))
        .args(["--threads", "2"])
        .assert()
        .failure();
}
