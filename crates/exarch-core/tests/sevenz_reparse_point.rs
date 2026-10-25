//! A 7z entry that is a link is classified as a symlink: a Windows
//! reparse-point directory or a Unix-mode (`S_IFLNK`) entry. `list` reports it
//! as a symlink, `verify` fails under every link policy and `extract` rejects
//! it before writing anything, so the three entry points agree.

#![allow(clippy::unwrap_used)]

use std::assert_matches;
use std::io::Cursor;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::IssueCategory;
use exarch_core::ManifestEntryKind;
use exarch_core::SecurityConfig;
use exarch_core::VerificationStatus;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use tempfile::TempDir;

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

fn reparse_directory_archive(dir: &TempDir) -> PathBuf {
    let mut buf = Cursor::new(Vec::<u8>::new());
    {
        let mut writer = ArchiveWriter::new(&mut buf).unwrap();
        let mut file = ArchiveEntry::new_file("a.txt");
        file.has_stream = true;
        file.size = 2;
        writer
            .push_archive_entry(file, Some(Cursor::new(b"hi".to_vec())))
            .unwrap();
        let mut entry = ArchiveEntry::new_directory("junction");
        entry.has_windows_attributes = true;
        entry.windows_attributes = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT;
        writer
            .push_archive_entry(entry, None::<Cursor<Vec<u8>>>)
            .unwrap();
        writer.finish().unwrap();
    }
    let path = dir.path().join("junction.7z");
    std::fs::write(&path, buf.into_inner()).unwrap();
    path
}

#[test]
fn list_reports_reparse_directory_as_symlink() {
    let dir = TempDir::new().unwrap();
    let path = reparse_directory_archive(&dir);

    let manifest = list_archive(&path, &SecurityConfig::default()).unwrap();
    let kinds: Vec<_> = manifest.entries().iter().map(|e| &e.kind).collect();
    assert_matches!(
        kinds.as_slice(),
        [ManifestEntryKind::File, ManifestEntryKind::Symlink { .. }]
    );
}

#[test]
fn verify_fails_reparse_directory_under_every_link_policy() {
    let dir = TempDir::new().unwrap();
    let path = reparse_directory_archive(&dir);

    for config in [
        SecurityConfig::default(),
        SecurityConfig::default().with_allow_symlinks(true),
    ] {
        let report = verify_archive(&path, &config).unwrap();
        assert_eq!(report.status(), VerificationStatus::Fail);
    }
}

#[test]
fn extract_rejects_reparse_directory() {
    let dir = TempDir::new().unwrap();
    let path = reparse_directory_archive(&dir);
    let out = TempDir::new().unwrap();

    assert_matches!(
        extract_archive(&path, out.path(), &SecurityConfig::default()),
        Err(ArchiveError::SecurityViolation { reason }) if reason.contains("reparse point")
    );
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

const UNIX_EXTENSION: u32 = 0x8000;
const S_IFLNK: u32 = 0o12_0000;
const S_IFREG: u32 = 0o10_0000;

fn unix_attributes(mode: u32) -> u32 {
    UNIX_EXTENSION | (mode << 16)
}

fn file_with_attributes(name: &str, data: &[u8], attributes: u32) -> ArchiveEntry {
    let mut entry = ArchiveEntry::new_file(name);
    entry.has_stream = true;
    entry.size = data.len() as u64;
    entry.has_windows_attributes = true;
    entry.windows_attributes = attributes;
    entry
}

fn write_entries(dir: &TempDir, entries: Vec<(ArchiveEntry, &[u8])>) -> PathBuf {
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::<u8>::new())).unwrap();
    for (entry, data) in entries {
        let reader = entry.has_stream.then(|| Cursor::new(data.to_vec()));
        writer.push_archive_entry(entry, reader).unwrap();
    }
    let path = dir.path().join("unix-mode.7z");
    std::fs::write(&path, writer.finish().unwrap().into_inner()).unwrap();
    path
}

fn unix_symlink_archive(dir: &TempDir) -> PathBuf {
    let link = file_with_attributes("link", b"/etc/x", unix_attributes(S_IFLNK | 0o777));
    write_entries(dir, vec![(link, b"/etc/x")])
}

fn dest_is_empty(out: &TempDir) -> bool {
    std::fs::read_dir(out.path()).unwrap().count() == 0
}

#[test]
fn list_reports_unix_mode_symlink_as_symlink() {
    let dir = TempDir::new().unwrap();
    let path = unix_symlink_archive(&dir);

    let manifest = list_archive(&path, &SecurityConfig::default()).unwrap();
    let kinds: Vec<_> = manifest.entries().iter().map(|e| &e.kind).collect();
    assert_matches!(kinds.as_slice(), [ManifestEntryKind::Symlink { .. }]);
}

#[test]
fn verify_fails_unix_mode_symlink_under_every_link_policy() {
    let dir = TempDir::new().unwrap();
    let path = unix_symlink_archive(&dir);

    for config in [
        SecurityConfig::default(),
        SecurityConfig::default().with_allow_symlinks(true),
    ] {
        let report = verify_archive(&path, &config).unwrap();
        assert_eq!(report.status(), VerificationStatus::Fail);
        assert!(
            report.issues().iter().any(|i| {
                i.category == IssueCategory::SecurityPolicy
                    && i.entry_path.as_deref() == Some(Path::new("link"))
                    && i.message.contains("not read from this archive format")
            }),
            "{:?}",
            report.issues()
        );
    }
}

#[test]
fn extract_rejects_unix_mode_symlink_under_every_link_policy() {
    for config in [
        SecurityConfig::default(),
        SecurityConfig::default().with_allow_symlinks(true),
    ] {
        let dir = TempDir::new().unwrap();
        let path = unix_symlink_archive(&dir);
        let out = TempDir::new().unwrap();

        assert_matches!(
            extract_archive(&path, out.path(), &config),
            Err(ArchiveError::SecurityViolation { reason }) if reason.contains("S_IFLNK")
        );
        assert!(dest_is_empty(&out));
    }
}

#[test]
fn unix_symlink_among_regular_files_is_rejected_before_writing() {
    let dir = TempDir::new().unwrap();
    let path = write_entries(
        &dir,
        vec![
            (
                file_with_attributes("a.txt", b"hi", unix_attributes(S_IFREG | 0o644)),
                b"hi",
            ),
            (
                file_with_attributes("b.txt", b"yo", unix_attributes(S_IFREG | 0o644)),
                b"yo",
            ),
            (
                file_with_attributes("link", b"a.txt", unix_attributes(S_IFLNK | 0o777)),
                b"a.txt",
            ),
        ],
    );
    let out = TempDir::new().unwrap();

    assert_matches!(
        extract_archive(&path, out.path(), &SecurityConfig::default()),
        Err(ArchiveError::SecurityViolation { .. })
    );
    assert!(dest_is_empty(&out));
}

#[test]
fn unix_symlink_directory_entry_is_rejected() {
    let dir = TempDir::new().unwrap();
    let mut entry = ArchiveEntry::new_directory("dirlink");
    entry.has_windows_attributes = true;
    entry.windows_attributes = FILE_ATTRIBUTE_DIRECTORY | unix_attributes(S_IFLNK | 0o777);
    let path = write_entries(&dir, vec![(entry, b"")]);
    let out = TempDir::new().unwrap();

    assert_matches!(
        extract_archive(&path, out.path(), &SecurityConfig::default()),
        Err(ArchiveError::SecurityViolation { .. })
    );
    assert!(dest_is_empty(&out));
}

#[test]
fn regular_mode_and_missing_extension_flag_extract_as_files() {
    let cases = [
        (
            "regular mode with extension flag",
            unix_attributes(S_IFREG | 0o644),
        ),
        ("link mode without extension flag", (S_IFLNK | 0o777) << 16),
    ];
    for (label, attributes) in cases {
        let dir = TempDir::new().unwrap();
        let path = write_entries(
            &dir,
            vec![(file_with_attributes("f.txt", b"hi", attributes), b"hi")],
        );
        let out = TempDir::new().unwrap();

        extract_archive(&path, out.path(), &SecurityConfig::default())
            .unwrap_or_else(|e| panic!("{label}: {e}"));

        assert_eq!(std::fs::read(out.path().join("f.txt")).unwrap(), b"hi");
    }
}
