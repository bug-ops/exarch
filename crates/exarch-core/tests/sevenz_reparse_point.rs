//! A 7z entry that is a Windows reparse-point directory is classified as a
//! symlink: `list` reports it as one, `verify` fails under every link policy
//! and `extract` rejects it before writing anything, so the three entry points
//! agree. Unix-mode symlinks are read and validated instead, see
//! `sevenz_unix_symlink`.
//!
//! The same is checked on every host against a committed archive made by real
//! 7-Zip with `-snl` over a file symlink and a directory symlink, and on
//! Windows against one generated at test time.
//! Set `EXARCH_REQUIRE_PRODUCERS` to fail instead of skip when 7-Zip is
//! missing.

#![allow(clippy::unwrap_used)]

use std::assert_matches;
use std::io::Cursor;
use std::path::Path;
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
        Err(ArchiveError::SecurityViolation { reason, .. }) if reason.contains("reparse point")
    );
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[test]
fn regular_mode_and_missing_extension_flag_extract_as_files() {
    const UNIX_EXTENSION: u32 = 0x8000;
    const S_IFLNK: u32 = 0o12_0000;
    const S_IFREG: u32 = 0o10_0000;

    let cases = [
        (
            "regular mode with extension flag",
            UNIX_EXTENSION | ((S_IFREG | 0o644) << 16),
        ),
        ("link mode without extension flag", (S_IFLNK | 0o777) << 16),
    ];
    for (label, attributes) in cases {
        let dir = TempDir::new().unwrap();
        let mut entry = ArchiveEntry::new_file("f.txt");
        entry.has_stream = true;
        entry.size = 2;
        entry.has_windows_attributes = true;
        entry.windows_attributes = attributes;
        let mut writer = ArchiveWriter::new(Cursor::new(Vec::<u8>::new())).unwrap();
        writer
            .push_archive_entry(entry, Some(Cursor::new(b"hi".to_vec())))
            .unwrap();
        let path = dir.path().join("unix-mode.7z");
        std::fs::write(&path, writer.finish().unwrap().into_inner()).unwrap();
        let out = TempDir::new().unwrap();

        extract_archive(&path, out.path(), &SecurityConfig::default())
            .unwrap_or_else(|e| panic!("{label}: {e}"));

        assert_eq!(std::fs::read(out.path().join("f.txt")).unwrap(), b"hi");
    }
}

fn assert_listed_as_symlinks_and_refused(archive: &Path) {
    let config = SecurityConfig::default().with_allow_solid_archives(true);
    let manifest = list_archive(archive, &config).unwrap();
    let symlinks = manifest
        .entries()
        .iter()
        .filter(|e| matches!(e.kind, ManifestEntryKind::Symlink { .. }))
        .count();
    assert_eq!(symlinks, 2);
    let report = verify_archive(archive, &config).unwrap();
    assert_eq!(report.status(), VerificationStatus::Fail);
    let out = TempDir::new().unwrap();
    assert_matches!(
        extract_archive(archive, out.path(), &config),
        Err(ArchiveError::SecurityViolation { reason, .. }) if reason.contains("reparse point")
    );
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

/// Made by 7-Zip `a -snl` on a Windows runner over a file symlink and a
/// directory symlink; see `tests/fixtures/PROVENANCE.md`.
#[test]
fn windows_7zip_snl_fixture_is_listed_as_symlinks_and_refused() {
    let archive = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/symlink-7zip-windows-snl.7z");
    assert_listed_as_symlinks_and_refused(&archive);
}

#[cfg(windows)]
fn seven_zip() -> Option<PathBuf> {
    let program_files = std::env::var_os("ProgramFiles").map(PathBuf::from);
    let candidates = [PathBuf::from("7z"), PathBuf::from("7za")]
        .into_iter()
        .chain(program_files.map(|dir| dir.join("7-Zip").join("7z.exe")));
    let found = candidates.into_iter().find(|tool: &PathBuf| {
        std::process::Command::new(tool)
            .output()
            .is_ok_and(|o| o.status.success())
    });
    assert!(
        found.is_some() || std::env::var_os("EXARCH_REQUIRE_PRODUCERS").is_none(),
        "EXARCH_REQUIRE_PRODUCERS is set but 7-Zip is not usable"
    );
    found
}

#[test]
#[cfg(windows)]
fn real_7zip_symlink_archive_is_listed_as_symlinks_and_refused() {
    let Some(tool) = seven_zip() else {
        eprintln!("skipping: 7-Zip not available");
        return;
    };
    let work = TempDir::new().unwrap();
    let src = work.path().join("src");
    std::fs::create_dir_all(src.join("dir")).unwrap();
    std::fs::write(src.join("a.txt"), b"hi").unwrap();
    std::os::windows::fs::symlink_file("a.txt", src.join("file-link")).unwrap();
    std::os::windows::fs::symlink_dir("dir", src.join("dir-link")).unwrap();
    let archive = work.path().join("links.7z");
    let status = std::process::Command::new(&tool)
        .args(["a", "-snl"])
        .arg(&archive)
        .arg(src.join("*"))
        .status()
        .unwrap();
    assert!(status.success());

    assert_listed_as_symlinks_and_refused(&archive);
}
