//! Acceptance contract of #1196 (the occupied-destination text names the
//! occupant kind and the maker, as `error.conflicts` does) and #1203 (a
//! symlink parent names the refused entry and carries `by`).

#![expect(clippy::expect_used, reason = "integration test helpers")]
#![expect(clippy::disallowed_methods, reason = "integration test fixture setup")]

mod common;

use assert_cmd::cargo::cargo_bin_cmd;
use common::Member;
use common::extract_error;
use common::write_tar;
use tempfile::TempDir;

fn message(json: &serde_json::Value) -> String {
    json["error"]["message"]
        .as_str()
        .expect("message")
        .to_owned()
}

#[test]
fn test_extract_occupied_message_names_the_kind_of_each_occupant() {
    let temp = TempDir::new().expect("temp dir");
    let out = temp.path().join("out");
    std::fs::create_dir_all(out.join("d")).expect("dir occupant");
    std::fs::write(out.join("f"), "old").expect("file occupant");

    for (member, noun, forbidden) in [("d", "directory", "file"), ("f", "file", "directory")] {
        let archive = temp.path().join(format!("{member}.tar"));
        write_tar(&archive, &[Member::File(member)]);

        let json = extract_error(&archive, &out, &[]);

        let text = message(&json);
        assert_eq!(json["error"]["kind"], "OutputExists", "{json}");
        assert_eq!(json["error"]["conflicts"][0]["occupant"], noun, "{json}");
        assert!(text.contains(noun), "{text}");
        assert!(
            !text.contains(&format!("destination {forbidden}")),
            "the text must not name the wrong kind: {text}"
        );
    }
}

#[cfg(unix)]
#[test]
fn test_extract_occupied_message_names_a_symlink_occupant() {
    let temp = TempDir::new().expect("temp dir");
    let archive = temp.path().join("x.tar");
    write_tar(&archive, &[Member::File("x")]);
    let out = temp.path().join("out");
    std::fs::create_dir(&out).expect("destination");
    std::os::unix::fs::symlink("t", out.join("x")).expect("symlink");

    let json = extract_error(&archive, &out, &[]);

    assert_eq!(json["error"]["kind"], "OutputExists", "{json}");
    assert_eq!(
        json["error"]["conflicts"][0]["occupant"], "symlink",
        "{json}"
    );
    assert!(message(&json).contains("symlink"), "{json}");
    assert!(!message(&json).contains("destination file"), "{json}");
}

#[test]
fn test_extract_occupied_message_of_mixed_kinds_does_not_call_them_all_files() {
    let temp = TempDir::new().expect("temp dir");
    let archive = temp.path().join("m.tar");
    write_tar(&archive, &[Member::File("a"), Member::File("b")]);
    let out = temp.path().join("out");
    std::fs::create_dir_all(out.join("a")).expect("dir occupant");
    std::fs::write(out.join("b"), "old").expect("file occupant");

    let json = extract_error(&archive, &out, &[]);

    assert!(!message(&json).contains("destination files"), "{json}");
}

#[test]
fn test_extract_occupant_made_by_the_archive_is_not_reported_as_already_existing() {
    let temp = TempDir::new().expect("temp dir");
    let archive = temp.path().join("f.tar");
    write_tar(&archive, &[Member::File("f"), Member::Dir("f/")]);
    let out = temp.path().join("out");

    let json = extract_error(&archive, &out, &[]);

    assert_eq!(json["error"]["by"], "archive", "{json}");
    assert!(!message(&json).contains("already exist"), "{json}");
}

#[test]
fn test_extract_force_file_over_directory_says_refusing_to_replace_the_directory() {
    let temp = TempDir::new().expect("temp dir");
    let archive = temp.path().join("d.tar");
    write_tar(&archive, &[Member::Dir("d/"), Member::File("d")]);
    let out = temp.path().join("out");

    let output = cargo_bin_cmd!("exarch")
        .args(["extract", "--force"])
        .arg(&archive)
        .arg(&out)
        .assert()
        .code(1)
        .get_output()
        .stderr
        .clone();

    let text = String::from_utf8(output).expect("utf8");
    assert!(
        text.contains("refusing to replace the existing directory at d")
            || text.contains("(directory)"),
        "{text}"
    );
    assert!(!text.contains("destination file already exists"), "{text}");
}

#[test]
fn test_extract_force_cannot_replace_hint_agrees_with_the_number_of_paths() {
    let temp = TempDir::new().expect("temp dir");
    let many_archive = temp.path().join("m.tar");
    write_tar(&many_archive, &[Member::File("a"), Member::File("b")]);
    let one_archive = temp.path().join("one.tar");
    write_tar(&one_archive, &[Member::File("a")]);
    let out = temp.path().join("out");
    std::fs::create_dir_all(out.join("a")).expect("dir a");
    std::fs::create_dir_all(out.join("b")).expect("dir b");

    let many = extract_error(&many_archive, &out, &["--force"]);
    let one = extract_error(&one_archive, &out, &["--force"]);

    let hint = |json: &serde_json::Value| {
        json["error"]["hint"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    };
    assert!(hint(&one).contains("remove it"), "{one}");
    assert!(!hint(&one).contains("remove them"), "{one}");
    assert!(hint(&many).contains("remove them"), "{many}");
}

#[cfg(unix)]
#[test]
fn test_extract_symlink_parent_names_the_entry_and_the_maker() {
    for flags in [&[][..], &["--force"][..]] {
        let temp = TempDir::new().expect("temp dir");
        let archive = temp.path().join("a.tar");
        write_tar(&archive, &[Member::File("d/e/f")]);
        let out = temp.path().join("out");
        std::fs::create_dir(&out).expect("destination");
        std::fs::write(out.join("t"), "old").expect("target");
        std::os::unix::fs::symlink("t", out.join("d")).expect("symlink");

        let json = extract_error(&archive, &out, flags);

        assert_eq!(
            json["error"]["kind"], "SecurityViolation",
            "{flags:?}: {json}"
        );
        assert_eq!(
            json["error"]["sub_code"], "EXISTING_SYMLINK",
            "{flags:?}: {json}"
        );
        assert_eq!(json["error"]["by"], "existing", "{flags:?}: {json}");
        assert!(
            message(&json).contains("refusing to create d/e/f under the existing symlink at d"),
            "{flags:?}: {json}"
        );
    }
}
