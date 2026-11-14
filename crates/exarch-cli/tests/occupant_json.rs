//! `extract --json` reports an occupied-path refusal with the kind of each
//! occupant and the maker of the refusing path: `error.conflicts` is a list of
//! `{path, occupant}` objects and `error.by` names who made the occupant
//! (#1180, #1183).

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::path::Path;

use assert_cmd::cargo::cargo_bin_cmd;
use tempfile::TempDir;

enum Member<'a> {
    File(&'a str),
    Dir(&'a str),
    #[cfg(unix)]
    Symlink {
        name: &'a str,
        target: &'a str,
    },
}

fn write_tar(path: &Path, members: &[Member<'_>]) {
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

fn extract_error(archive: &Path, out: &Path, flags: &[&str]) -> serde_json::Value {
    let stdout = cargo_bin_cmd!("exarch")
        .args(["extract", "--json"])
        .args(flags)
        .arg(archive)
        .arg(out)
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&stdout).expect("valid JSON")
}

#[test]
fn test_extract_conflicts_are_objects_with_the_occupant_kind_and_the_maker() {
    let temp = TempDir::new().expect("temp dir");
    let archive = temp.path().join("m.tar");
    write_tar(&archive, &[Member::File("blocked"), Member::File("plain")]);
    let out = temp.path().join("out");
    std::fs::create_dir_all(out.join("blocked")).expect("blocking directory");
    std::fs::write(out.join("plain"), "old").expect("occupying file");

    let json = extract_error(&archive, &out, &[]);

    assert_eq!(json["error"]["kind"], "OutputExists", "{json}");
    assert_eq!(
        json["error"]["conflicts"],
        serde_json::json!([
            {"path": "blocked", "occupant": "directory"},
            {"path": "plain", "occupant": "file"},
        ]),
        "{json}"
    );
    assert_eq!(json["error"]["by"], "existing", "{json}");
}

#[test]
fn test_extract_directory_over_a_file_is_an_occupied_refusal_naming_the_file() {
    for flags in [&[][..], &["--force"][..]] {
        let temp = TempDir::new().expect("temp dir");
        let archive = temp.path().join("d.tar");
        write_tar(&archive, &[Member::Dir("d/")]);
        let out = temp.path().join("out");
        std::fs::create_dir(&out).expect("destination");
        std::fs::write(out.join("d"), "keep").expect("occupying file");

        let json = extract_error(&archive, &out, flags);

        assert_eq!(json["error"]["kind"], "OutputExists", "{flags:?}: {json}");
        assert_eq!(
            json["error"]["conflicts"],
            serde_json::json!([{"path": "d", "occupant": "file"}]),
            "{flags:?}: {json}"
        );
        assert_eq!(json["error"]["by"], "existing", "{flags:?}: {json}");
        assert_eq!(std::fs::read(out.join("d")).expect("kept"), b"keep");
    }
}

#[test]
fn test_extract_directory_over_a_file_of_the_run_names_the_archive_as_the_maker() {
    let temp = TempDir::new().expect("temp dir");
    let archive = temp.path().join("f.tar");
    write_tar(&archive, &[Member::File("f"), Member::Dir("f/")]);
    let out = temp.path().join("out");

    let json = extract_error(&archive, &out, &[]);

    assert_eq!(json["error"]["kind"], "OutputExists", "{json}");
    assert_eq!(
        json["error"]["conflicts"],
        serde_json::json!([{"path": "f", "occupant": "file"}]),
        "{json}"
    );
    assert_eq!(json["error"]["by"], "archive", "{json}");
}

#[cfg(unix)]
#[test]
fn test_extract_existing_symlink_refusal_names_a_preexisting_symlink_as_existing() {
    let temp = TempDir::new().expect("temp dir");
    let archive = temp.path().join("s.tar");
    write_tar(&archive, &[Member::File("x")]);
    let out = temp.path().join("out");
    std::fs::create_dir(&out).expect("destination");
    std::os::unix::fs::symlink("elsewhere", out.join("x")).expect("symlink");

    let json = extract_error(&archive, &out, &["--force"]);

    assert_eq!(json["error"]["kind"], "SecurityViolation", "{json}");
    assert_eq!(json["error"]["by"], "existing", "{json}");
}

#[cfg(unix)]
#[test]
fn test_extract_existing_symlink_refusal_names_a_symlink_of_the_run_as_the_archive() {
    let temp = TempDir::new().expect("temp dir");
    let archive = temp.path().join("s.tar");
    write_tar(
        &archive,
        &[
            Member::File("t"),
            Member::Symlink {
                name: "l",
                target: "t",
            },
            Member::File("l"),
        ],
    );
    let out = temp.path().join("out");

    let json = extract_error(&archive, &out, &["--force", "--allow-symlinks"]);

    assert_eq!(json["error"]["kind"], "SecurityViolation", "{json}");
    assert_eq!(json["error"]["by"], "archive", "{json}");
}
