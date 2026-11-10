//! `--force` extraction over a path an earlier entry occupies fails with a
//! typed refusal that names the entry, not a bare errno (#765, #1176): a
//! directory occupant is `OUTPUT_EXISTS` with the entry in `conflicts`, a
//! symlink occupant is `EXISTING_SYMLINK`.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

#[cfg(unix)]
use std::assert_matches;
use std::io::Cursor;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::ErrorCode;
use exarch_core::ExistingFiles;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::FfiDetail;
#[cfg(unix)]
use exarch_core::FfiKind;
use exarch_core::SecurityConfig;
#[cfg(unix)]
use exarch_core::SecurityViolationSubCode;
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
    ExtractionOptions::default().with_existing_files(ExistingFiles::Overwrite)
}

fn extract_forced(archive: &Path, out: &TempDir, config: &SecurityConfig) -> ArchiveError {
    ExtractRequest::new(config)
        .with_options(force_options())
        .extract(archive, out.path())
        .unwrap_err()
}

/// A directory occupant is refused as `OUTPUT_EXISTS` naming `entry`, and the
/// release message a binding gets carries the entry in `conflicts`.
fn assert_directory_refused(error: ArchiveError, entry: &str) {
    assert_eq!(error.error_code(), ErrorCode::OutputExists, "{error}");
    let message = error.into_ffi_message();
    let FfiDetail::Occupied { conflicts, .. } = message.detail else {
        panic!("expected the occupied paths: {message:?}");
    };
    assert_eq!(&*conflicts, [entry.to_owned()]);
}

/// A symlink occupant is refused as `EXISTING_SYMLINK` naming `entry`.
#[cfg(unix)]
fn assert_symlink_refused(error: ArchiveError, entry: &str) {
    assert_matches!(
        error.ffi_kind(),
        FfiKind::SecurityViolation {
            sub_code: SecurityViolationSubCode::ExistingSymlink,
            ..
        }
    );
    let message = error.into_ffi_message().description;
    assert!(
        message.contains(&format!(
            "refusing to replace the existing symlink at {entry}"
        )),
        "{message}"
    );
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

    let error = extract_forced(&archive, &out, &SecurityConfig::default());

    assert_directory_refused(error, "d");
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

    let error = extract_forced(&archive, &out, &config);

    assert_symlink_refused(error, "l");
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

    let error = ExtractRequest::new(&SecurityConfig::default())
        .with_options(force_options())
        .extract(&archive, out.path())
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

    let error = extract_forced(&archive, &out, &SecurityConfig::default());

    assert_directory_refused(error, "target");
    assert!(out.path().join("target").is_dir());
}

#[cfg(unix)]
#[test]
fn tar_symlink_over_directory_names_the_entry() {
    let dir = TempDir::new().unwrap();
    let archive = write_tar(
        &dir,
        &[
            tar_entry("t", tar::EntryType::Regular, b"t", None),
            tar_entry("d/", tar::EntryType::Directory, b"", None),
            tar_entry("d", tar::EntryType::Symlink, b"", Some("t")),
        ],
    );
    let out = TempDir::new().unwrap();
    let config = SecurityConfig::default().with_allow_symlinks(true);

    let error = extract_forced(&archive, &out, &config);

    assert_directory_refused(error, "d");
    assert!(out.path().join("d").is_dir());
}

#[cfg(unix)]
#[test]
fn tar_symlink_over_nested_directory_names_the_normalized_path() {
    let dir = TempDir::new().unwrap();
    let archive = write_tar(
        &dir,
        &[
            tar_entry("t", tar::EntryType::Regular, b"t", None),
            tar_entry("a/b/", tar::EntryType::Directory, b"", None),
            tar_entry("./a/b", tar::EntryType::Symlink, b"", Some("../t")),
        ],
    );
    let out = TempDir::new().unwrap();
    let config = SecurityConfig::default().with_allow_symlinks(true);

    let error = extract_forced(&archive, &out, &config);

    assert_directory_refused(error, "a/b");
    assert!(out.path().join("a/b").is_dir());
}

#[cfg(unix)]
#[test]
fn zip_symlink_over_directory_names_the_entry() {
    use zip::write::SimpleFileOptions;

    let bytes = zip_bytes(|zip| {
        zip.add_directory("d/", SimpleFileOptions::default())
            .unwrap();
        zip.add_symlink("d", "t", SimpleFileOptions::default())
            .unwrap();
    });
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, "occupied.zip", &bytes);
    let out = TempDir::new().unwrap();
    let config = SecurityConfig::default().with_allow_symlinks(true);

    let error = extract_forced(&archive, &out, &config);

    assert_directory_refused(error, "d");
    assert!(out.path().join("d").is_dir());
}

#[cfg(unix)]
#[test]
fn sevenz_symlink_over_directory_names_the_entry() {
    use sevenz_rust2::ArchiveEntry;
    use sevenz_rust2::ArchiveWriter;

    const UNIX_EXTENSION: u32 = 0x8000;
    const S_IFLNK: u32 = 0o12_0000;

    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    writer
        .push_archive_entry::<&[u8]>(ArchiveEntry::new_directory("d"), None)
        .unwrap();
    let mut link = ArchiveEntry::new_file("d");
    link.has_stream = true;
    link.size = 1;
    link.has_windows_attributes = true;
    link.windows_attributes = UNIX_EXTENSION | ((S_IFLNK | 0o777) << 16);
    writer
        .push_archive_entry(link, Some(Cursor::new(b"t".to_vec())))
        .unwrap();
    let bytes = writer.finish().unwrap().into_inner();
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, "occupied.7z", &bytes);
    let out = TempDir::new().unwrap();
    let config = SecurityConfig::default().with_allow_symlinks(true);

    let error = extract_forced(&archive, &out, &config);

    assert_directory_refused(error, "d");
    assert!(out.path().join("d").is_dir());
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

    let error = extract_forced(&archive, &out, &SecurityConfig::default());

    assert_directory_refused(error, "d");
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

    let error = extract_forced(&archive, &out, &SecurityConfig::default());

    assert_symlink_refused(error, "l");
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

    let error = extract_forced(&archive, &out, &SecurityConfig::default());

    assert_symlink_refused(error, "l");
    assert!(out.path().join("l").is_symlink());
}
