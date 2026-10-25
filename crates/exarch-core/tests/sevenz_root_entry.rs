//! A 7z root entry (`.`) names the destination itself: a directory is a
//! no-op, a file is rejected by `extract`, `list` and `verify` alike.

#![allow(clippy::unwrap_used)]

use std::io::Cursor;
use std::path::PathBuf;

use exarch_core::ManifestEntryKind;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use tempfile::TempDir;

const ROOT_NAMES: [&str; 2] = [".", "./"];

fn file(name: &str, data: &[u8]) -> (ArchiveEntry, Option<Cursor<Vec<u8>>>) {
    let mut entry = ArchiveEntry::new_file(name);
    if data.is_empty() {
        return (entry, None);
    }
    entry.has_stream = true;
    entry.size = data.len() as u64;
    (entry, Some(Cursor::new(data.to_vec())))
}

fn sevenz_of(entries: Vec<(ArchiveEntry, Option<Cursor<Vec<u8>>>)>) -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    for (entry, data) in entries {
        writer.push_archive_entry(entry, data).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn directory(name: &str) -> (ArchiveEntry, Option<Cursor<Vec<u8>>>) {
    (ArchiveEntry::new_directory(name), None)
}

fn write_archive(dir: &TempDir, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join("root.7z");
    std::fs::write(&path, bytes).unwrap();
    path
}

fn assert_root_must_be_directory(err: &exarch_core::ArchiveError) {
    assert_eq!(err.error_code(), "SECURITY_VIOLATION");
    assert!(err.to_string().contains("must be a directory"), "{err}");
}

#[test]
fn root_file_entry_is_rejected_by_extract_before_any_write() {
    for root in ROOT_NAMES {
        for payload in [&b""[..], &b"payload"[..]] {
            let bytes = sevenz_of(vec![file("a.txt", b"hi"), file(root, payload)]);
            let dir = TempDir::new().unwrap();
            let archive = write_archive(&dir, &bytes);
            let out = TempDir::new().unwrap();

            let err =
                extract_archive(&archive, out.path(), &SecurityConfig::default()).unwrap_err();

            assert_root_must_be_directory(&err);
            assert!(!out.path().join("a.txt").exists(), "{root:?} {payload:?}");
        }
    }
}

#[test]
fn root_file_entry_is_rejected_by_list() {
    for root in ROOT_NAMES {
        let bytes = sevenz_of(vec![file("a.txt", b"hi"), file(root, b"")]);
        let dir = TempDir::new().unwrap();
        let archive = write_archive(&dir, &bytes);

        let err = list_archive(&archive, &SecurityConfig::default()).unwrap_err();

        assert_root_must_be_directory(&err);
    }
}

#[test]
fn root_file_entry_is_rejected_by_verify() {
    for root in ROOT_NAMES {
        let bytes = sevenz_of(vec![file("a.txt", b"hi"), file(root, b"payload")]);
        let dir = TempDir::new().unwrap();
        let archive = write_archive(&dir, &bytes);

        let err = verify_archive(&archive, &SecurityConfig::default()).unwrap_err();

        assert_root_must_be_directory(&err);
    }
}

#[test]
fn root_directory_entry_is_a_no_op() {
    for root in ROOT_NAMES {
        let bytes = sevenz_of(vec![directory(root), file("a.txt", b"hi")]);
        let dir = TempDir::new().unwrap();
        let archive = write_archive(&dir, &bytes);
        let config = SecurityConfig::default();

        assert!(verify_archive(&archive, &config).unwrap().is_safe());
        let manifest = list_archive(&archive, &config).unwrap();
        assert_eq!(manifest.entries()[0].kind, ManifestEntryKind::Directory);

        let out = TempDir::new().unwrap();
        extract_archive(&archive, out.path(), &config).unwrap();
        assert_eq!(std::fs::read(out.path().join("a.txt")).unwrap(), b"hi");
    }
}

#[test]
fn traversal_next_to_root_directory_entry_is_still_rejected() {
    let bytes = sevenz_of(vec![
        directory("."),
        file("a.txt", b"hi"),
        file("../evil", b"x"),
    ]);
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, &bytes);
    let config = SecurityConfig::default();
    let out = TempDir::new().unwrap();

    assert!(extract_archive(&archive, out.path(), &config).is_err());
    assert!(!out.path().join("a.txt").exists());
    assert!(list_archive(&archive, &config).is_err());
    assert!(verify_archive(&archive, &config).is_err());
}
