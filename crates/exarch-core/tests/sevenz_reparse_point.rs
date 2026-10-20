//! A 7z directory carrying the Windows reparse-point attribute is a link:
//! `list` reports it as a symlink, `verify` fails under every link policy and
//! `extract` rejects it, so the three entry points agree.

#![allow(clippy::unwrap_used)]

use std::assert_matches;
use std::io::Cursor;
use std::path::PathBuf;

use exarch_core::ArchiveError;
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
    assert_matches!(kinds.as_slice(), [ManifestEntryKind::Symlink { .. }]);
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
        Err(ArchiveError::InvalidArchive(msg)) if msg.contains("reparse point")
    );
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}
