//! A directory entry over a symlink that existed before the run and leads out
//! of the destination is the existing-symlink refusal, never a path traversal
//! (#1204 case B). With symlinks allowed the validator canonicalizes the
//! landing itself and used to answer `PathTraversal`; the answer is now an
//! error of another kind only, and every other input keeps its error.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

mod sink_support;

use std::assert_matches;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::ExistingFiles;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::OccupiedBy;
use exarch_core::SecurityConfig;
use exarch_core::Violation;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use sink_support::tar_archive;
use sink_support::tar_dir;
use sink_support::tar_entry;
use sink_support::tar_file;
use sink_support::zip_archive;
use sink_support::zip_dir;
use sink_support::zip_file;
use tempfile::TempDir;

const POLICIES: [ExistingFiles; 2] = [ExistingFiles::Refuse, ExistingFiles::Overwrite];

fn write(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn sevenz(dir: &TempDir, entries: &[(&str, bool)]) -> PathBuf {
    let path = dir.path().join("a.7z");
    let mut writer = ArchiveWriter::new(std::fs::File::create(&path).unwrap()).unwrap();
    for (name, is_dir) in entries {
        if *is_dir {
            writer
                .push_archive_entry::<&[u8]>(ArchiveEntry::new_directory(name), None)
                .unwrap();
        } else {
            writer
                .push_archive_entry(ArchiveEntry::new_file(name), Some(&b"ok"[..]))
                .unwrap();
        }
    }
    writer.finish().unwrap();
    path
}

/// A destination whose `x` is a symlink out of it, and the directory it leads
/// to.
fn destination_with_escaping_link(link: &str) -> (TempDir, PathBuf, PathBuf) {
    let root = TempDir::new().unwrap();
    let dest = root.path().join("out");
    let outside = root.path().join("outside");
    std::fs::create_dir(&dest).unwrap();
    std::fs::create_dir(&outside).unwrap();
    symlink("../outside", dest.join(link)).unwrap();
    (root, dest, outside)
}

fn extract(archive: &Path, dest: &Path, policy: ExistingFiles) -> Result<(), ArchiveError> {
    ExtractRequest::new(&SecurityConfig::default().with_allow_symlinks(true))
        .with_options(ExtractionOptions::default().with_existing_files(policy))
        .extract(archive, dest)
        .map(drop)
}

fn is_existing_symlink_refusal(error: &ArchiveError) -> bool {
    matches!(
        error,
        ArchiveError::SecurityViolation {
            kind: Violation::ReplacesSymlink {
                by: OccupiedBy::Existing,
                ..
            },
            ..
        }
    )
}

#[test]
fn a_directory_entry_over_an_escaping_symlink_is_replaces_symlink_with_symlinks_allowed() {
    let dir = TempDir::new().unwrap();
    let archives = [
        write(
            &dir,
            "d.tar",
            &tar_archive(&[tar_dir("x/"), tar_file("x/a", b"ok")]),
        ),
        write(
            &dir,
            "bare.tar",
            &tar_archive(&[tar_entry("x", tar::EntryType::Directory, b"", None)]),
        ),
        write(
            &dir,
            "d.zip",
            &zip_archive(vec![zip_dir("x/"), zip_file("x/a", b"ok")]),
        ),
        sevenz(&dir, &[("x", true)]),
    ];
    for archive in &archives {
        for policy in POLICIES {
            let (_root, dest, outside) = destination_with_escaping_link("x");

            let error = extract(archive, &dest, policy).unwrap_err();

            assert!(
                is_existing_symlink_refusal(&error),
                "{policy:?} {}: {error}",
                archive.display()
            );
            assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
        }
    }
}

#[test]
fn an_entry_below_an_escaping_symlink_is_not_reclassified() {
    let dir = TempDir::new().unwrap();
    let archive = write(&dir, "f.tar", &tar_archive(&[tar_file("x/a", b"ok")]));
    let (_root, dest, outside) = destination_with_escaping_link("x");

    let error = extract(&archive, &dest, ExistingFiles::Refuse).unwrap_err();

    assert!(!is_existing_symlink_refusal(&error), "{error}");
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
}

#[test]
fn a_directory_below_an_escaping_symlink_is_not_reclassified() {
    let dir = TempDir::new().unwrap();
    let archive = write(&dir, "d.tar", &tar_archive(&[tar_dir("x/sub/")]));
    let (_root, dest, outside) = destination_with_escaping_link("x");
    std::fs::create_dir(outside.join("sub")).unwrap();
    symlink("../outside", outside.join("sub").join("l")).unwrap();

    let error = extract(&archive, &dest, ExistingFiles::Refuse).unwrap_err();

    assert!(!is_existing_symlink_refusal(&error), "{error}");
}

#[test]
fn a_directory_entry_over_a_symlink_inside_the_destination_stays_accepted() {
    let dir = TempDir::new().unwrap();
    let archive = write(
        &dir,
        "d.tar",
        &tar_archive(&[tar_dir("x/"), tar_file("x/a", b"ok")]),
    );
    let root = TempDir::new().unwrap();
    let dest = root.path().join("out");
    std::fs::create_dir_all(dest.join("real")).unwrap();
    symlink("real", dest.join("x")).unwrap();

    extract(&archive, &dest, ExistingFiles::Refuse).unwrap();

    assert!(dest.join("real/a").is_file());
}

#[test]
fn sevenz_directory_then_file_over_an_escaping_symlink_is_replaces_symlink_in_every_mode() {
    let dir = TempDir::new().unwrap();
    let archive = sevenz(&dir, &[("x", true), ("x/a", false)]);
    for allow in [false, true] {
        for policy in [
            ExistingFiles::Skip,
            ExistingFiles::Refuse,
            ExistingFiles::Overwrite,
        ] {
            let (_root, dest, outside) = destination_with_escaping_link("x");

            let error = ExtractRequest::new(&SecurityConfig::default().with_allow_symlinks(allow))
                .with_options(ExtractionOptions::default().with_existing_files(policy))
                .extract(&archive, &dest)
                .unwrap_err();

            assert!(
                is_existing_symlink_refusal(&error),
                "{allow} {policy:?}: {error}"
            );
            assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
        }
    }
}

#[test]
fn sevenz_file_below_an_escaping_symlink_without_a_directory_entry_stays_path_traversal() {
    let dir = TempDir::new().unwrap();
    let archive = sevenz(&dir, &[("x/a", false)]);
    let (_root, dest, outside) = destination_with_escaping_link("x");

    let error = extract(&archive, &dest, ExistingFiles::Refuse).unwrap_err();

    assert_matches!(error, ArchiveError::PathTraversal { .. }, "{error}");
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
}

#[test]
fn sevenz_directory_over_a_symlink_inside_the_destination_stays_accepted() {
    let dir = TempDir::new().unwrap();
    let archive = sevenz(&dir, &[("x", true), ("x/a", false)]);
    let root = TempDir::new().unwrap();
    let dest = root.path().join("out");
    std::fs::create_dir_all(dest.join("real")).unwrap();
    symlink("real", dest.join("x")).unwrap();

    extract(&archive, &dest, ExistingFiles::Refuse).unwrap();

    assert!(dest.join("real/a").is_file());
}
