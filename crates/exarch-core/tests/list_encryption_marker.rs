//! Acceptance contract of #1242: every listed entry says whether its data is
//! encrypted. ZIP entries take the flag from their header, 7z entries from the
//! AES coder of their block, TAR entries are always plain; empty files and
//! directories of a 7z are plain.

#![cfg(feature = "encryption")]
#![expect(clippy::disallowed_methods, reason = "test fixture setup")]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]

mod sevenz_patch;

use std::sync::Arc;

use exarch_core::ArchiveEntry;
use exarch_core::EntryEncryption;
use exarch_core::ListRequest;
use exarch_core::ManifestEntryKind;
use exarch_core::Password;
use exarch_core::SecurityConfig;
use sevenz_patch::fixture_path;
use tempfile::TempDir;

fn password() -> Arc<Password> {
    Arc::new(Password::new(b"correct-horse".to_vec()).unwrap())
}

fn list(archive: &std::path::Path, with_password: bool) -> Vec<ArchiveEntry> {
    let config = SecurityConfig::default();
    let request = ListRequest::new(&config);
    let request = request.with_password(with_password.then(password));
    request.list(archive).unwrap().entries().to_vec()
}

fn files(entries: &[ArchiveEntry]) -> Vec<&ArchiveEntry> {
    entries
        .iter()
        .filter(|e| matches!(e.kind, ManifestEntryKind::File { .. }))
        .collect()
}

#[test]
fn list_of_an_aes_zip_marks_every_file_encrypted_with_or_without_a_password() {
    for with_password in [false, true] {
        let entries = list(&fixture_path("aes256.zip"), with_password);

        let files = files(&entries);

        assert!(!files.is_empty());
        for entry in files {
            assert_eq!(entry.encryption, EntryEncryption::Encrypted, "{entry:?}");
            assert!(entry.is_encrypted(), "{entry:?}");
        }
    }
}

#[test]
fn list_of_a_7z_with_encrypted_content_marks_its_files_encrypted() {
    for (name, with_password) in [
        ("content.7z", false),
        ("content.7z", true),
        ("header.7z", true),
    ] {
        let entries = list(&fixture_path(name), with_password);

        let files = files(&entries);

        assert!(!files.is_empty(), "{name}");
        assert!(files.iter().all(|e| e.is_encrypted()), "{name}");
    }
}

#[test]
fn list_of_a_7z_marks_directories_plain_even_in_an_encrypted_archive() {
    let entries = list(&fixture_path("content.7z"), false);

    let directories: Vec<_> = entries
        .iter()
        .filter(|e| matches!(e.kind, ManifestEntryKind::Directory))
        .collect();

    assert!(!directories.is_empty());
    assert!(directories.iter().all(|e| !e.is_encrypted()));
}

#[test]
fn list_of_an_unencrypted_zip_or_7z_marks_nothing_encrypted() {
    for name in ["plain.zip", "plain.7z"] {
        let entries = list(&fixture_path(name), false);

        assert!(!entries.is_empty(), "{name}");
        assert!(
            entries
                .iter()
                .all(|e| e.encryption == EntryEncryption::Plain),
            "{name}"
        );
    }
}

#[test]
fn list_of_a_mixed_7z_marks_only_the_aes_block_encrypted() {
    let entries = list(&fixture_path("mixed-blocks.7z"), false);

    let marked: Vec<_> = entries
        .iter()
        .map(|e| (e.path.to_string_lossy().into_owned(), e.is_encrypted()))
        .collect();

    assert!(
        marked.contains(&("plain.txt".to_owned(), false)),
        "{marked:?}"
    );
    assert!(
        marked.contains(&("sealed.txt".to_owned(), true)),
        "{marked:?}"
    );
}

#[test]
fn list_of_a_tar_marks_nothing_encrypted() {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.tar");
    let mut builder = tar::Builder::new(std::fs::File::create(&archive).unwrap());
    let mut header = tar::Header::new_gnu();
    header.set_size(1);
    header.set_mode(0o644);
    builder
        .append_data(&mut header, "a.txt", &b"x"[..])
        .unwrap();
    builder.finish().unwrap();
    drop(builder);

    let entries = list(&archive, false);

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].encryption, EntryEncryption::Plain);
}

#[test]
fn entry_encryption_strings_are_plain_and_encrypted() {
    assert_eq!(EntryEncryption::Plain.as_str(), "plain");
    assert_eq!(EntryEncryption::Encrypted.as_str(), "encrypted");
}

#[test]
fn a_new_archive_entry_is_plain() {
    let entry = ArchiveEntry::new("a".into(), ManifestEntryKind::Directory);

    assert_eq!(entry.encryption, EntryEncryption::Plain);
    assert!(!entry.is_encrypted());
}
