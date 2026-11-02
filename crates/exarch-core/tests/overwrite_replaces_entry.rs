//! `--force` extraction replaces the destination entry instead of writing
//! through its existing inode.

#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use std::io::Cursor;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ExtractionOptions;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive_with_options;
use tempfile::TempDir;

const NEW_CONTENT: &[u8] = b"new content";
const OUTSIDE_CONTENT: &[u8] = b"outside secret";

fn tar_archive(dir: &TempDir) -> PathBuf {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o640);
    header.set_size(NEW_CONTENT.len() as u64);
    header.set_path("f").unwrap();
    header.set_cksum();
    let mut builder = tar::Builder::new(Vec::new());
    builder.append(&header, NEW_CONTENT).unwrap();
    let path = dir.path().join("a.tar");
    std::fs::write(&path, builder.into_inner().unwrap()).unwrap();
    path
}

fn zip_archive(dir: &TempDir) -> PathBuf {
    let options = zip::write::SimpleFileOptions::default().unix_permissions(0o640);
    let mut writer = zip::write::ZipWriter::new(Cursor::new(Vec::new()));
    writer.start_file("f", options).unwrap();
    writer.write_all(NEW_CONTENT).unwrap();
    let path = dir.path().join("a.zip");
    std::fs::write(&path, writer.finish().unwrap().into_inner()).unwrap();
    path
}

fn force(archive: &Path, out: &Path) {
    extract_archive_with_options(
        archive,
        out,
        &SecurityConfig::default(),
        &ExtractionOptions::default().with_skip_duplicates(false),
    )
    .unwrap();
}

fn assert_hardlink_overwrite_leaves_outside_untouched(make: fn(&TempDir) -> PathBuf) {
    let work = TempDir::new().unwrap();
    let archive = make(&work);
    let outside = work.path().join("outside");
    std::fs::write(&outside, OUTSIDE_CONTENT).unwrap();
    let out = TempDir::new().unwrap();
    std::fs::hard_link(&outside, out.path().join("f")).unwrap();

    force(&archive, out.path());

    assert_eq!(std::fs::read(&outside).unwrap(), OUTSIDE_CONTENT);
    assert_eq!(std::fs::metadata(&outside).unwrap().nlink(), 1);
    assert_eq!(std::fs::read(out.path().join("f")).unwrap(), NEW_CONTENT);
}

fn assert_plain_overwrite_replaces_content_and_mode(make: fn(&TempDir) -> PathBuf) {
    let work = TempDir::new().unwrap();
    let archive = make(&work);
    let out = TempDir::new().unwrap();
    let target = out.path().join("f");
    std::fs::write(&target, b"old").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();

    force(&archive, out.path());

    assert_eq!(std::fs::read(&target).unwrap(), NEW_CONTENT);
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
        0o640
    );
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 1);
}

#[test]
fn tar_force_does_not_write_through_hardlink() {
    assert_hardlink_overwrite_leaves_outside_untouched(tar_archive);
}

#[test]
fn zip_force_does_not_write_through_hardlink() {
    assert_hardlink_overwrite_leaves_outside_untouched(zip_archive);
}

#[test]
fn tar_force_replaces_content_and_mode() {
    assert_plain_overwrite_replaces_content_and_mode(tar_archive);
}

#[test]
fn zip_force_replaces_content_and_mode() {
    assert_plain_overwrite_replaces_content_and_mode(zip_archive);
}
