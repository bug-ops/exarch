//! Acceptance contract of #1230: an entry below an existing symlink whose
//! target escapes the destination is `SYMLINK_ESCAPE` in tar, zip and 7z, under
//! every `ExistingFiles` mode, and nothing is written outside.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

mod sink_support;

use std::os::unix::fs::symlink;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::DestDir;
use exarch_core::ErrorCode;
use exarch_core::ExistingFiles;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::SafePath;
use exarch_core::SecurityConfig;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use sink_support::tar_archive;
use sink_support::tar_file;
use sink_support::zip_archive;
use sink_support::zip_file;
use tempfile::TempDir;

const POLICIES: [ExistingFiles; 3] = [
    ExistingFiles::Skip,
    ExistingFiles::Refuse,
    ExistingFiles::Overwrite,
];

fn config() -> SecurityConfig {
    SecurityConfig::default().with_allow_symlinks(true)
}

fn write(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn sevenz(dir: &TempDir, name: &str) -> PathBuf {
    let path = dir.path().join("a.7z");
    let mut writer = ArchiveWriter::new(std::fs::File::create(&path).unwrap()).unwrap();
    writer
        .push_archive_entry(ArchiveEntry::new_file(name), Some(&b"ok"[..]))
        .unwrap();
    writer.finish().unwrap();
    path
}

fn archives(dir: &TempDir, name: &str) -> [PathBuf; 3] {
    [
        write(dir, "n.tar", &tar_archive(&[tar_file(name, b"n\n")])),
        write(dir, "n.zip", &zip_archive(vec![zip_file(name, b"n\n")])),
        sevenz(dir, name),
    ]
}

fn extract(archive: &Path, dest: &Path, policy: ExistingFiles) -> Result<(), ArchiveError> {
    ExtractRequest::new(&config())
        .with_options(ExtractionOptions::default().with_existing_files(policy))
        .extract(archive, dest)
        .map(drop)
}

fn cause(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    }
}

#[test]
fn extract_entry_under_an_escaping_parent_symlink_is_symlink_escape_in_every_format() {
    for (name, planted) in [("d/l", "d"), ("d/e/f", "d")] {
        for policy in POLICIES {
            let dir = TempDir::new().unwrap();
            for archive in archives(&dir, name) {
                let root = TempDir::new().unwrap();
                let dest = root.path().join("out");
                let outside = root.path().join("outside");
                std::fs::create_dir(&dest).unwrap();
                std::fs::create_dir(&outside).unwrap();
                symlink("../outside", dest.join(planted)).unwrap();

                let error = extract(&archive, &dest, policy).unwrap_err();

                assert_eq!(
                    error.error_code(),
                    ErrorCode::SymlinkEscape,
                    "{name} {policy:?} {}: {error}",
                    archive.display()
                );
                assert_eq!(
                    std::fs::read_dir(&outside).unwrap().count(),
                    0,
                    "{name} {policy:?} {}",
                    archive.display()
                );
            }
        }
    }
}

#[test]
fn extract_entry_under_an_escaping_parent_symlink_keeps_an_existing_outside_entry_untouched() {
    for policy in POLICIES {
        let dir = TempDir::new().unwrap();
        for archive in archives(&dir, "d/l") {
            let root = TempDir::new().unwrap();
            let dest = root.path().join("out");
            let outside = root.path().join("outside");
            std::fs::create_dir(&dest).unwrap();
            std::fs::create_dir(&outside).unwrap();
            std::fs::write(outside.join("l"), b"keep").unwrap();
            symlink("../outside", dest.join("d")).unwrap();

            let error = extract(&archive, &dest, policy).unwrap_err();

            assert_eq!(error.error_code(), ErrorCode::SymlinkEscape, "{error}");
            assert_eq!(std::fs::read(outside.join("l")).unwrap(), b"keep");
        }
    }
}

#[test]
fn extract_escaping_parent_symlink_error_is_a_critical_symlink_escape_not_a_partial_traversal() {
    let dir = TempDir::new().unwrap();
    let seven = sevenz(&dir, "d/l");
    let root = TempDir::new().unwrap();
    let dest = root.path().join("out");
    let outside = root.path().join("outside");
    std::fs::create_dir(&dest).unwrap();
    std::fs::create_dir(&outside).unwrap();
    symlink("../outside", dest.join("d")).unwrap();

    let error = extract(&seven, &dest, ExistingFiles::Refuse).unwrap_err();

    assert!(
        matches!(cause(&error), ArchiveError::SymlinkEscape { .. }),
        "{error}"
    );
}

#[test]
fn safe_path_validate_escaping_parent_symlink_is_symlink_escape() {
    let root = TempDir::new().unwrap();
    let dest = root.path().join("out");
    let outside = root.path().join("outside");
    std::fs::create_dir(&dest).unwrap();
    std::fs::create_dir(&outside).unwrap();
    symlink("../outside", dest.join("d")).unwrap();

    let error =
        SafePath::validate(Path::new("d/l"), &DestDir::new(dest).unwrap(), &config()).unwrap_err();

    assert_eq!(error.error_code(), ErrorCode::SymlinkEscape, "{error}");
}

#[test]
fn safe_path_validate_file_parent_keeps_its_old_kind() {
    let root = TempDir::new().unwrap();
    let dest = root.path().join("out");
    std::fs::create_dir(&dest).unwrap();
    std::fs::write(dest.join("d"), b"file").unwrap();

    let error =
        SafePath::validate(Path::new("d/l"), &DestDir::new(dest).unwrap(), &config()).unwrap_err();

    assert_ne!(error.error_code(), ErrorCode::SymlinkEscape, "{error}");
}
