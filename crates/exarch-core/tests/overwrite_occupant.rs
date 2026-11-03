//! `--force` extraction over a path an earlier entry occupies fails with an
//! error that names the entry and the occupant, not a bare errno (#765).

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

use std::io::Cursor;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ErrorCode;
use exarch_core::ExtractionOptions;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive_with_options;
use tempfile::TempDir;

fn tar_entry(name: &str, kind: tar::EntryType, data: &[u8], link: Option<&str>) -> Vec<u8> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(kind);
    header.set_mode(0o644);
    header.set_size(data.len() as u64);
    header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
    if let Some(link) = link {
        header.set_link_name(link).unwrap();
    }
    header.set_cksum();
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(data);
    bytes.resize(bytes.len().next_multiple_of(512), 0);
    bytes
}

fn write_tar(dir: &TempDir, entries: &[Vec<u8>]) -> PathBuf {
    let mut bytes = entries.concat();
    bytes.resize(bytes.len() + 1024, 0);
    let path = dir.path().join("occupied.tar");
    std::fs::write(&path, bytes).unwrap();
    path
}

fn force_options() -> ExtractionOptions {
    ExtractionOptions::default().with_skip_duplicates(false)
}

fn extract_forced(archive: &Path, out: &TempDir, config: &SecurityConfig) -> String {
    let error =
        extract_archive_with_options(archive, out.path(), config, &force_options()).unwrap_err();
    assert_eq!(error.error_code(), ErrorCode::IoError, "{error}");
    error.to_string()
}

#[test]
fn tar_file_over_directory_names_the_entry() {
    let dir = TempDir::new().unwrap();
    let archive = write_tar(
        &dir,
        &[
            tar_entry("d/", tar::EntryType::Directory, b"", None),
            tar_entry("d", tar::EntryType::Regular, b"x", None),
        ],
    );
    let out = TempDir::new().unwrap();

    let message = extract_forced(&archive, &out, &SecurityConfig::default());

    assert!(
        message.contains("refusing to replace the existing directory at d"),
        "{message}"
    );
    assert!(out.path().join("d").is_dir());
}

#[cfg(unix)]
#[test]
fn tar_file_over_symlink_names_the_entry() {
    let dir = TempDir::new().unwrap();
    let archive = write_tar(
        &dir,
        &[
            tar_entry("t", tar::EntryType::Regular, b"t", None),
            tar_entry("l", tar::EntryType::Symlink, b"", Some("t")),
            tar_entry("l", tar::EntryType::Regular, b"x", None),
        ],
    );
    let out = TempDir::new().unwrap();
    let config = SecurityConfig::default().with_allow_symlinks(true);

    let message = extract_forced(&archive, &out, &config);

    assert!(
        message.contains("refusing to replace the existing symlink at l"),
        "{message}"
    );
    assert!(out.path().join("l").is_symlink());
}

#[cfg(unix)]
struct Unlock(PathBuf);

#[cfg(unix)]
impl Drop for Unlock {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
    }
}

#[cfg(unix)]
#[test]
fn tar_open_failure_without_dir_or_symlink_keeps_the_original_error() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let archive = write_tar(
        &dir,
        &[tar_entry("d/f", tar::EntryType::Regular, b"x", None)],
    );
    let out = TempDir::new().unwrap();
    let locked = out.path().join("d");
    std::fs::create_dir(&locked).unwrap();
    std::fs::write(locked.join("f"), b"keep").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();

    let _unlock = Unlock(locked.clone());
    if std::fs::File::create(locked.join("probe")).is_ok() {
        return;
    }

    let error = extract_archive_with_options(
        &archive,
        out.path(),
        &SecurityConfig::default(),
        &force_options(),
    )
    .unwrap_err();

    let message = error.to_string();
    assert!(!message.contains("refusing to replace"), "{message}");
    assert!(message.contains("Permission denied"), "{message}");
}

#[test]
fn sevenz_file_over_directory_names_the_entry() {
    use sevenz_rust2::ArchiveEntry;
    use sevenz_rust2::ArchiveWriter;

    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    let mut entry = ArchiveEntry::new_file("target");
    entry.has_stream = true;
    entry.size = 1;
    writer
        .push_archive_entry(entry, Some(Cursor::new(b"x".to_vec())))
        .unwrap();
    let bytes = writer.finish().unwrap().into_inner();
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("occupied.7z");
    std::fs::write(&archive, bytes).unwrap();
    let out = TempDir::new().unwrap();
    std::fs::create_dir(out.path().join("target")).unwrap();

    let message = extract_forced(&archive, &out, &SecurityConfig::default());

    assert!(
        message.contains("refusing to replace the existing directory at target"),
        "{message}"
    );
    assert!(out.path().join("target").is_dir());
}

fn zip_bytes(build: impl FnOnce(&mut zip::write::ZipWriter<Cursor<Vec<u8>>>)) -> Vec<u8> {
    let mut writer = zip::write::ZipWriter::new(Cursor::new(Vec::new()));
    build(&mut writer);
    writer.finish().unwrap().into_inner()
}

fn write_archive(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn zip_file_over_directory_names_the_entry() {
    use zip::write::SimpleFileOptions;

    let bytes = zip_bytes(|zip| {
        zip.add_directory("d/", SimpleFileOptions::default())
            .unwrap();
        zip.start_file("d", SimpleFileOptions::default()).unwrap();
        std::io::Write::write_all(zip, b"x").unwrap();
    });
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, "occupied.zip", &bytes);
    let out = TempDir::new().unwrap();

    let message = extract_forced(&archive, &out, &SecurityConfig::default());

    assert!(
        message.contains("refusing to replace the existing directory at d"),
        "{message}"
    );
    assert!(out.path().join("d").is_dir());
}

#[cfg(unix)]
#[test]
fn zip_file_over_existing_symlink_names_the_entry() {
    use zip::write::SimpleFileOptions;

    let bytes = zip_bytes(|zip| {
        zip.start_file("l", SimpleFileOptions::default()).unwrap();
        std::io::Write::write_all(zip, b"x").unwrap();
    });
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, "occupied.zip", &bytes);
    let out = TempDir::new().unwrap();
    std::os::unix::fs::symlink("t", out.path().join("l")).unwrap();

    let message = extract_forced(&archive, &out, &SecurityConfig::default());

    assert!(
        message.contains("refusing to replace the existing symlink at l"),
        "{message}"
    );
    assert!(out.path().join("l").is_symlink());
}

#[cfg(unix)]
#[test]
fn sevenz_file_over_existing_symlink_names_the_entry() {
    use sevenz_rust2::ArchiveEntry;
    use sevenz_rust2::ArchiveWriter;

    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    let mut entry = ArchiveEntry::new_file("l");
    entry.has_stream = true;
    entry.size = 1;
    writer
        .push_archive_entry(entry, Some(Cursor::new(b"x".to_vec())))
        .unwrap();
    let bytes = writer.finish().unwrap().into_inner();
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, "occupied.7z", &bytes);
    let out = TempDir::new().unwrap();
    std::os::unix::fs::symlink("t", out.path().join("l")).unwrap();

    let message = extract_forced(&archive, &out, &SecurityConfig::default());

    assert!(
        message.contains("refusing to replace the existing symlink at l"),
        "{message}"
    );
    assert!(out.path().join("l").is_symlink());
}
