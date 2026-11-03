//! `--force` extraction replaces the destination entry instead of writing
//! through its existing inode.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

use std::io::Cursor;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ExtractionOptions;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive_with_options;
use tempfile::TempDir;

const NEW_CONTENT: &[u8] = b"new content";
const OUTSIDE_CONTENT: &[u8] = b"outside secret";

type MakeArchive = fn(&TempDir, &str) -> PathBuf;

fn tar_archive(dir: &TempDir, name: &str) -> PathBuf {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o640);
    header.set_size(NEW_CONTENT.len() as u64);
    let mut builder = tar::Builder::new(Vec::new());
    builder.append_data(&mut header, name, NEW_CONTENT).unwrap();
    let path = dir.path().join("a.tar");
    std::fs::write(&path, builder.into_inner().unwrap()).unwrap();
    path
}

fn zip_archive(dir: &TempDir, name: &str) -> PathBuf {
    let options = zip::write::SimpleFileOptions::default().unix_permissions(0o640);
    let mut writer = zip::write::ZipWriter::new(Cursor::new(Vec::new()));
    writer.start_file(name, options).unwrap();
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

fn assert_hardlink_overwrite_leaves_outside_untouched(make: MakeArchive) {
    let work = TempDir::new().unwrap();
    let archive = make(&work, "f");
    let outside = work.path().join("outside");
    std::fs::write(&outside, OUTSIDE_CONTENT).unwrap();
    let out = TempDir::new().unwrap();
    std::fs::hard_link(&outside, out.path().join("f")).unwrap();

    force(&archive, out.path());

    assert_eq!(std::fs::read(&outside).unwrap(), OUTSIDE_CONTENT);
    assert_eq!(std::fs::read(out.path().join("f")).unwrap(), NEW_CONTENT);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(std::fs::metadata(&outside).unwrap().nlink(), 1);
    }
}

fn assert_plain_overwrite_replaces_content_and_mode(make: MakeArchive) {
    let work = TempDir::new().unwrap();
    let archive = make(&work, "f");
    let out = TempDir::new().unwrap();
    let target = out.path().join("f");
    std::fs::write(&target, b"old").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    force(&archive, out.path());

    assert_eq!(std::fs::read(&target).unwrap(), NEW_CONTENT);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            0o640
        );
    }
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 1);
}

fn assert_long_name_overwrite_succeeds(make: MakeArchive) {
    let name = "n".repeat(240);
    let work = TempDir::new().unwrap();
    let archive = make(&work, &name);
    let out = TempDir::new().unwrap();
    std::fs::write(out.path().join(&name), b"old").unwrap();

    force(&archive, out.path());

    assert_eq!(std::fs::read(out.path().join(&name)).unwrap(), NEW_CONTENT);
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 1);
}

#[cfg(unix)]
fn assert_fifo_target_is_replaced(make: MakeArchive) {
    let work = TempDir::new().unwrap();
    let archive = make(&work, "f");
    let out = TempDir::new().unwrap();
    let fifo = out.path().join("f");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );

    let out_path = out.path().to_path_buf();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        force(&archive, &out_path);
        let _ = tx.send(());
    });
    // A timeout here means extraction blocked on the FIFO.
    rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();

    assert!(std::fs::symlink_metadata(&fifo).unwrap().is_file());
    assert_eq!(std::fs::read(&fifo).unwrap(), NEW_CONTENT);
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

#[test]
fn tar_force_over_long_name_succeeds() {
    assert_long_name_overwrite_succeeds(tar_archive);
}

#[test]
fn zip_force_over_long_name_succeeds() {
    assert_long_name_overwrite_succeeds(zip_archive);
}

#[cfg(unix)]
#[test]
fn tar_force_replaces_fifo() {
    assert_fifo_target_is_replaced(tar_archive);
}

#[cfg(unix)]
#[test]
fn zip_force_replaces_fifo() {
    assert_fifo_target_is_replaced(zip_archive);
}
