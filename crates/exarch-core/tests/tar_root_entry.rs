//! A TAR root entry (`.` or `./`) names the destination itself: a directory is
//! a no-op, anything else (file, symlink, hardlink, special file) is rejected
//! by `extract`, `list` and `verify` alike.

#![allow(clippy::unwrap_used)]

use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ExtractionOptions;
use exarch_core::ManifestEntryKind;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive;
use exarch_core::extract_archive_with_options;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use flate2::Compression;
use flate2::write::GzEncoder;
use tempfile::TempDir;

const ROOT_NAMES: [&str; 4] = [".", "./", "./.", ".//"];
// A regular-file header named with a trailing slash is a directory (V7).
const FILE_ROOT_NAMES: [&str; 2] = [".", "./."];

fn entry(name: &str, kind: tar::EntryType, data: &[u8], link: Option<&str>) -> Vec<u8> {
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

fn tar_of(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = entries.concat();
    bytes.resize(bytes.len() + 1024, 0);
    bytes
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn write_archive(dir: &TempDir, file_name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join(file_name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn link_config() -> SecurityConfig {
    SecurityConfig::default()
        .with_allow_symlinks(true)
        .with_allow_hardlinks(true)
}

/// Asserts `extract`, `list` and `verify` all reject the archive with a
/// security error and that `extract` writes at most `max_written` entries (the
/// ones that precede the root entry).
fn assert_rejected_everywhere(archive: &Path, config: &SecurityConfig, max_written: usize) {
    let out = TempDir::new().unwrap();

    let extract = extract_archive(archive, out.path(), config).unwrap_err();
    assert_eq!(extract.error_code(), "SECURITY_VIOLATION", "{extract}");
    let list = list_archive(archive, config).unwrap_err();
    assert_eq!(list.error_code(), "SECURITY_VIOLATION", "{list}");
    let verify = verify_archive(archive, config).unwrap_err();
    assert_eq!(verify.error_code(), "SECURITY_VIOLATION", "{verify}");
    assert!(std::fs::read_dir(out.path()).unwrap().count() <= max_written);
}

fn assert_all_rejected(entries: &[Vec<u8>], config: &SecurityConfig, max_written: usize) {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, "root.tar", &tar_of(entries));
    assert_rejected_everywhere(&archive, config, max_written);
}

#[test]
fn root_regular_file_is_rejected_everywhere() {
    for name in FILE_ROOT_NAMES {
        for data in [&b"hello"[..], b""] {
            assert_all_rejected(
                &[entry(name, tar::EntryType::Regular, data, None)],
                &SecurityConfig::default(),
                0,
            );
        }
    }
}

#[test]
fn root_regular_file_in_tar_gz_is_rejected_everywhere() {
    let bytes = gzip(&tar_of(&[entry(
        ".",
        tar::EntryType::Regular,
        b"hello",
        None,
    )]));
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, "root.tar.gz", &bytes);

    assert_rejected_everywhere(&archive, &SecurityConfig::default(), 0);
}

#[test]
fn root_symlink_is_rejected_whether_or_not_symlinks_are_allowed() {
    for name in ROOT_NAMES {
        let entries = [entry(name, tar::EntryType::Symlink, b"", Some("sub"))];
        assert_all_rejected(&entries, &SecurityConfig::default(), 0);
        assert_all_rejected(&entries, &link_config(), 0);
    }
}

#[test]
fn root_hardlink_is_rejected_everywhere() {
    for name in ROOT_NAMES {
        assert_all_rejected(
            &[
                entry("a.txt", tar::EntryType::Regular, b"x", None),
                entry(name, tar::EntryType::Link, b"", Some("a.txt")),
            ],
            &link_config(),
            1,
        );
    }
}

#[test]
fn root_special_file_is_a_security_violation_everywhere() {
    for kind in [
        tar::EntryType::Fifo,
        tar::EntryType::Char,
        tar::EntryType::Block,
    ] {
        assert_all_rejected(
            &[entry(".", kind, b"", None)],
            &SecurityConfig::default(),
            0,
        );
    }
}

#[test]
fn root_file_is_rejected_when_an_extension_filter_would_skip_it() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(
        &dir,
        "root.tar",
        &tar_of(&[entry(".", tar::EntryType::Regular, b"hello", None)]),
    );
    let out = TempDir::new().unwrap();
    let config = SecurityConfig::default().with_allowed_extensions(vec!["txt".into()]);

    let error = extract_archive(&archive, out.path(), &config).unwrap_err();

    assert_eq!(error.error_code(), "SECURITY_VIOLATION", "{error}");
}

#[test]
fn root_symlink_with_overwrite_is_rejected_and_leaves_the_destination_alone() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(
        &dir,
        "root.tar",
        &tar_of(&[entry(".", tar::EntryType::Symlink, b"", Some("sub"))]),
    );
    let out = TempDir::new().unwrap();
    let options = ExtractionOptions::default().with_skip_duplicates(false);
    std::fs::write(out.path().join("keep"), b"k").unwrap();

    let error =
        extract_archive_with_options(&archive, out.path(), &link_config(), &options).unwrap_err();

    assert_eq!(error.error_code(), "SECURITY_VIOLATION", "{error}");
    assert_eq!(std::fs::read(out.path().join("keep")).unwrap(), b"k");
}

#[test]
fn root_directory_entry_stays_a_no_op() {
    for name in ROOT_NAMES {
        let bytes = tar_of(&[
            entry(name, tar::EntryType::Directory, b"", None),
            entry("./a.txt", tar::EntryType::Regular, b"hi", None),
        ]);
        let dir = TempDir::new().unwrap();
        let archive = write_archive(&dir, "root.tar", &bytes);
        let config = SecurityConfig::default();
        let out = TempDir::new().unwrap();

        let report = extract_archive(&archive, out.path(), &config).unwrap();

        assert_eq!(report.files_skipped, 0, "{name:?}");
        assert_eq!(std::fs::read(out.path().join("a.txt")).unwrap(), b"hi");
        assert!(verify_archive(&archive, &config).unwrap().is_safe());
        let manifest = list_archive(&archive, &config).unwrap();
        assert_eq!(manifest.entries()[0].path, Path::new("."));
        assert_eq!(manifest.entries()[0].kind, ManifestEntryKind::Directory);
    }
}

#[test]
fn trailing_slash_regular_entry_with_payload_is_a_file_not_a_directory() {
    let bytes = tar_of(&[
        entry("sub/", tar::EntryType::Regular, b"12345", None),
        entry("sub/a.txt", tar::EntryType::Regular, b"hi", None),
    ]);
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, "payload.tar", &bytes);
    let config = SecurityConfig::default();
    let out = TempDir::new().unwrap();

    let extracted = extract_archive(&archive, out.path(), &config);
    let listed = list_archive(&archive, &config);
    let verified = verify_archive(&archive, &config);

    assert!(extracted.is_err());
    assert!(!verified.unwrap().is_safe());
    let manifest = listed.unwrap();
    assert_eq!(manifest.total_entries(), 2);
    assert_eq!(manifest.entries()[0].kind, ManifestEntryKind::File);
    assert!(!out.path().join("sub/a.txt").exists());
}

/// `bsdtar --format v7 -cf x.tar .` stores the root as a regular-file header
/// with a trailing slash, which GNU tar and libarchive read as a directory.
#[test]
fn v7_style_root_directory_is_accepted_everywhere() {
    let bytes = tar_of(&[
        entry("./", tar::EntryType::Regular, b"", None),
        entry("./sub/", tar::EntryType::Regular, b"", None),
        entry("./sub/a.txt", tar::EntryType::Regular, b"hi", None),
    ]);
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, "v7.tar", &bytes);
    let config = SecurityConfig::default();
    let out = TempDir::new().unwrap();

    extract_archive(&archive, out.path(), &config).unwrap();

    assert_eq!(std::fs::read(out.path().join("sub/a.txt")).unwrap(), b"hi");
    assert!(verify_archive(&archive, &config).unwrap().is_safe());
    let manifest = list_archive(&archive, &config).unwrap();
    assert_eq!(manifest.entries()[0].kind, ManifestEntryKind::Directory);
    assert_eq!(manifest.entries()[1].kind, ManifestEntryKind::Directory);
}
