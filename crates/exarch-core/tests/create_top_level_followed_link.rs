//! A link named directly as a creation source under `follow_symlinks` is
//! archived as its target's content (#1255); without it, ZIP skips it and TAR
//! keeps it as a link.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

use std::io::Read;
use std::path::Path;

use exarch_core::CreationConfig;
use exarch_core::create_archive;
use tempfile::TempDir;

fn linked_source(dir: &Path) -> std::path::PathBuf {
    let target = dir.join("target.txt");
    std::fs::write(&target, b"payload").unwrap();
    let link = dir.join("link.txt");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    link
}

fn followed() -> CreationConfig {
    CreationConfig::default().with_follow_symlinks(true)
}

#[test]
fn zip_archives_a_followed_top_level_link_as_content() {
    let src = TempDir::new().unwrap();
    let link = linked_source(src.path());
    let out = TempDir::new().unwrap();
    let archive = out.path().join("out.zip");

    let report = create_archive(&archive, &[&link], &followed()).unwrap();

    assert_eq!(report.files_added, 1);
    assert_eq!(report.symlinks_added, 0);
    let mut zip = zip::ZipArchive::new(std::fs::File::open(&archive).unwrap()).unwrap();
    let mut content = String::new();
    zip.by_name("link.txt")
        .unwrap()
        .read_to_string(&mut content)
        .unwrap();
    assert_eq!(content, "payload");
}

#[test]
fn tar_archives_a_followed_top_level_link_as_content() {
    let src = TempDir::new().unwrap();
    let link = linked_source(src.path());
    let out = TempDir::new().unwrap();
    let archive = out.path().join("out.tar");

    let report = create_archive(&archive, &[&link], &followed()).unwrap();

    assert_eq!(report.files_added, 1);
    assert_eq!(report.symlinks_added, 0);
    let mut tar = tar::Archive::new(std::fs::File::open(&archive).unwrap());
    let mut entry = tar.entries().unwrap().next().unwrap().unwrap();
    assert!(entry.header().entry_type().is_file());
    let mut content = String::new();
    entry.read_to_string(&mut content).unwrap();
    assert_eq!(content, "payload");
}

#[test]
fn a_kept_top_level_link_stays_a_link_in_tar_and_is_skipped_in_zip() {
    let src = TempDir::new().unwrap();
    let link = linked_source(src.path());
    let out = TempDir::new().unwrap();

    let tar_report = create_archive(
        out.path().join("out.tar"),
        &[&link],
        &CreationConfig::default(),
    )
    .unwrap();
    let zip_report = create_archive(
        out.path().join("out.zip"),
        &[&link],
        &CreationConfig::default(),
    )
    .unwrap();

    assert_eq!(tar_report.symlinks_added, 1);
    assert_eq!(zip_report.files_added, 0);
    assert_eq!(zip_report.files_skipped(), 1);
}
