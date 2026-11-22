//! Helpers shared by the CLI integration tests that build tar archives and
//! read `--json` output.

#![allow(dead_code, reason = "helpers are used by only some test binaries")]
#![expect(clippy::expect_used, reason = "integration test helpers")]

use std::path::Path;

use assert_cmd::cargo::cargo_bin_cmd;

/// One tar member of [`write_tar`].
pub enum Member<'a> {
    File(&'a str),
    Dir(&'a str),
    #[cfg(unix)]
    Symlink {
        name: &'a str,
        target: &'a str,
    },
}

#[expect(clippy::disallowed_methods, reason = "integration test fixture setup")]
pub fn write_tar(path: &Path, members: &[Member<'_>]) {
    let mut builder = tar::Builder::new(std::fs::File::create(path).expect("create archive"));
    for member in members {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        match *member {
            Member::File(name) => {
                header.set_size(4);
                builder
                    .append_data(&mut header, name, &b"data"[..])
                    .expect("append file");
            }
            Member::Dir(name) => {
                header.set_size(0);
                header.set_entry_type(tar::EntryType::Directory);
                header.set_mode(0o755);
                builder
                    .append_data(&mut header, name, std::io::empty())
                    .expect("append directory");
            }
            #[cfg(unix)]
            Member::Symlink { name, target } => {
                header.set_size(0);
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_mode(0o777);
                header.set_cksum();
                builder
                    .append_link(&mut header, name, target)
                    .expect("append symlink");
            }
        }
    }
    builder.finish().expect("finish archive");
}

/// Runs `exarch <command> --json <flags> <archive> <out>` and returns the
/// parsed stdout, asserting the exit code.
pub fn run_json(
    command: &str,
    archive: &Path,
    out: &Path,
    flags: &[&str],
    code: i32,
) -> serde_json::Value {
    let stdout = cargo_bin_cmd!("exarch")
        .args([command, "--json"])
        .args(flags)
        .arg(archive)
        .arg(out)
        .assert()
        .code(code)
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&stdout).expect("valid JSON")
}

pub fn extract_error(archive: &Path, out: &Path, flags: &[&str]) -> serde_json::Value {
    run_json("extract", archive, out, flags, 1)
}
