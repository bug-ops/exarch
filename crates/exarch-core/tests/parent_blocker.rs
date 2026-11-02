//! An entry whose parent chain an earlier entry (or the destination) turned
//! into a file, a dangling or looping symlink, or a link to a file fails with
//! one entry-naming message and category in extraction and in `verify` (#804).

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use exarch_core::ErrorCode;
use exarch_core::IssueCategory;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive;
use exarch_core::verify_archive;
use tempfile::TempDir;

fn tar_entry(name: &str, kind: tar::EntryType, data: &[u8], link: Option<&str>) -> Vec<u8> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(kind);
    header.set_mode(0o644);
    header.set_size(data.len() as u64);
    header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
    if let Some(link) = link {
        header.set_link_name(link).unwrap();
    }
    header.set_cksum();
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(data);
    bytes.resize(bytes.len().next_multiple_of(512), 0);
    bytes
}

fn file(name: &str) -> Vec<u8> {
    tar_entry(name, tar::EntryType::Regular, b"x", None)
}

fn dir(name: &str) -> Vec<u8> {
    tar_entry(name, tar::EntryType::Directory, b"", None)
}

#[cfg(unix)]
fn symlink(name: &str, target: &str) -> Vec<u8> {
    tar_entry(name, tar::EntryType::Symlink, b"", Some(target))
}

fn write_tar(dir: &TempDir, entries: &[Vec<u8>]) -> PathBuf {
    let mut bytes = entries.concat();
    bytes.resize(bytes.len() + 1024, 0);
    let path = dir.path().join("blocked.tar");
    std::fs::write(&path, bytes).unwrap();
    path
}

fn config() -> SecurityConfig {
    SecurityConfig::default().with_allow_symlinks(true)
}

struct Outcome {
    extract_code: ErrorCode,
    extract_message: String,
    verify_category: IssueCategory,
    verify_message: String,
}

fn run(entries: &[Vec<u8>]) -> Outcome {
    let dir = TempDir::new().unwrap();
    let archive = write_tar(&dir, entries);
    let out = TempDir::new().unwrap();
    let error = extract_archive(&archive, out.path(), &config()).unwrap_err();

    let report = verify_archive(&archive, &config()).unwrap();
    let issue = report
        .issues()
        .iter()
        .find(|issue| issue.message.contains("refusing to create"))
        .unwrap_or_else(|| panic!("no blocked-parent issue: {:?}", report.issues()));
    Outcome {
        extract_code: error.error_code(),
        extract_message: error.to_string(),
        verify_category: issue.category,
        verify_message: issue.message.clone(),
    }
}

fn assert_refusal(outcome: &Outcome, text: &str) {
    assert!(
        outcome.extract_message.contains(text),
        "{}",
        outcome.extract_message
    );
    assert!(
        outcome.verify_message.contains(text),
        "{}",
        outcome.verify_message
    );
}

#[test]
fn file_parent_of_a_directory_entry() {
    let outcome = run(&[file("x"), dir("x/y/")]);

    assert_refusal(
        &outcome,
        "refusing to create x/y under the existing file at x",
    );
    assert_eq!(outcome.extract_code, ErrorCode::IoError);
    assert_eq!(outcome.verify_category, IssueCategory::InvalidArchive);
}

#[test]
fn file_parent_of_a_file_entry_below_a_missing_directory() {
    let outcome = run(&[file("x"), file("x/a/b.txt")]);

    assert_refusal(
        &outcome,
        "refusing to create x/a/b.txt under the existing file at x",
    );
    assert_eq!(outcome.extract_code, ErrorCode::IoError);
    assert_eq!(outcome.verify_category, IssueCategory::InvalidArchive);
}

#[cfg(unix)]
#[test]
fn dangling_symlink_parent() {
    for entry in [dir("x/sub/"), file("x/f.txt"), file("x/a/f.txt")] {
        let outcome = run(&[symlink("x", "t"), entry]);

        assert_refusal(&outcome, "under the existing symlink at x");
        assert_eq!(outcome.extract_code, ErrorCode::SecurityViolation);
        assert_eq!(outcome.verify_category, IssueCategory::SecurityPolicy);
    }
}

#[cfg(unix)]
#[test]
fn symlink_to_a_file_parent() {
    for entry in [dir("x/sub/"), file("x/f.txt"), file("x/a/f.txt")] {
        let outcome = run(&[file("t"), symlink("x", "t"), entry]);

        assert_refusal(&outcome, "under the existing symlink at x");
        assert_eq!(outcome.extract_code, ErrorCode::SecurityViolation);
        assert_eq!(outcome.verify_category, IssueCategory::SecurityPolicy);
    }
}

#[cfg(unix)]
#[test]
fn looping_symlink_parent() {
    let outcome = run(&[symlink("x", "x"), file("x/f.txt")]);

    assert_refusal(&outcome, "under the existing symlink at x");
    assert_eq!(outcome.extract_code, ErrorCode::SecurityViolation);
    assert_eq!(outcome.verify_category, IssueCategory::SecurityPolicy);
}

#[cfg(unix)]
#[test]
fn blocked_extraction_writes_nothing_below_the_blocker() {
    let archive_dir = TempDir::new().unwrap();
    let archive = write_tar(&archive_dir, &[symlink("x", "t"), file("x/f.txt")]);
    let out = TempDir::new().unwrap();

    extract_archive(&archive, out.path(), &config()).unwrap_err();

    assert!(!out.path().join("t").exists());
}

#[cfg(unix)]
#[test]
fn destination_symlink_to_a_file_is_refused_with_a_category() {
    use std::os::unix::fs::symlink;

    let work = TempDir::new().unwrap();
    let outside = work.path().join("outside.txt");
    std::fs::write(&outside, b"keep").unwrap();
    let out = TempDir::new().unwrap();
    symlink(&outside, out.path().join("l")).unwrap();

    for allow_symlinks in [true, false] {
        for (name, code) in [
            ("l/a/b.txt", ErrorCode::SymlinkEscape),
            ("l/b.txt", ErrorCode::PathTraversal),
        ] {
            let archive = write_tar(&work, &[file(name)]);
            let config = SecurityConfig::default().with_allow_symlinks(allow_symlinks);

            let error = extract_archive(&archive, out.path(), &config).unwrap_err();

            let case = format!("{name} allow_symlinks={allow_symlinks}: {error}");
            assert!(!error.to_string().contains("os error"), "{case}");
            assert_eq!(error.error_code(), code, "{case}");
            assert_eq!(std::fs::read(&outside).unwrap(), b"keep", "{case}");
        }
    }
}

#[test]
fn destination_file_parent_names_the_entry() {
    let work = TempDir::new().unwrap();
    let archive = write_tar(&work, &[file("x/f")]);
    let out = TempDir::new().unwrap();
    std::fs::write(out.path().join("x"), b"keep").unwrap();

    let error = extract_archive(&archive, out.path(), &config()).unwrap_err();

    assert_eq!(error.error_code(), ErrorCode::IoError);
    assert!(
        error
            .to_string()
            .contains("refusing to create x/f under the existing file at x"),
        "{error}"
    );
    assert_eq!(std::fs::read(out.path().join("x")).unwrap(), b"keep");
}

#[cfg(unix)]
#[test]
fn destination_self_loop_parent_names_the_entry() {
    let work = TempDir::new().unwrap();
    let archive = write_tar(&work, &[file("x/f")]);
    let out = TempDir::new().unwrap();
    std::os::unix::fs::symlink("x", out.path().join("x")).unwrap();

    let error = extract_archive(&archive, out.path(), &config()).unwrap_err();

    assert_eq!(error.error_code(), ErrorCode::SecurityViolation);
    assert!(
        error
            .to_string()
            .contains("refusing to create x/f under the existing symlink at x"),
        "{error}"
    );
}
