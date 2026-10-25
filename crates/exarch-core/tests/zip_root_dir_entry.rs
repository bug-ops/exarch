//! A ZIP whose entry is the root directory (`./` or `.`), as written by
//! `bsdtar --format zip -cf out.zip .`, is the destination itself and a no-op,
//! as in TAR. A root entry that is a symlink or carries data is rejected.

#![allow(clippy::unwrap_used)]

use std::io::Cursor;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ManifestEntryKind;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use tempfile::TempDir;
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;
use zip::write::ZipWriter;

fn options() -> SimpleFileOptions {
    SimpleFileOptions::default().compression_method(CompressionMethod::Stored)
}

fn zip_of(build: impl FnOnce(&mut ZipWriter<Cursor<Vec<u8>>>)) -> Vec<u8> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    build(&mut zip);
    zip.finish().unwrap().into_inner()
}

fn zip_with_root_entry(root: &str) -> Vec<u8> {
    zip_of(|zip| {
        zip.start_file(root, options()).unwrap();
        zip.start_file("./sub/", options()).unwrap();
        zip.start_file("./a.txt", options()).unwrap();
        zip.write_all(b"hi").unwrap();
        zip.start_file("./sub/b", options()).unwrap();
        zip.write_all(b"y").unwrap();
    })
}

fn write_zip(dir: &TempDir, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join("root.zip");
    std::fs::write(&path, bytes).unwrap();
    path
}

fn extract_error_code(bytes: &[u8], config: &SecurityConfig) -> &'static str {
    let dir = TempDir::new().unwrap();
    let archive = write_zip(&dir, bytes);
    let out = TempDir::new().unwrap();
    extract_archive(&archive, out.path(), config)
        .unwrap_err()
        .error_code()
}

#[test]
fn root_dir_entry_is_skipped_on_extract() {
    for root in ["./", "."] {
        let dir = TempDir::new().unwrap();
        let archive = write_zip(&dir, &zip_with_root_entry(root));
        let out = TempDir::new().unwrap();

        let report = extract_archive(&archive, out.path(), &SecurityConfig::default()).unwrap();

        assert_eq!(report.files_skipped, 0, "{root:?}");
        assert_eq!(std::fs::read(out.path().join("a.txt")).unwrap(), b"hi");
        assert_eq!(std::fs::read(out.path().join("sub/b")).unwrap(), b"y");
    }
}

#[test]
fn root_dir_entry_passes_verify_and_is_listed() {
    let dir = TempDir::new().unwrap();
    let archive = write_zip(&dir, &zip_with_root_entry("./"));
    let config = SecurityConfig::default();

    assert!(verify_archive(&archive, &config).unwrap().is_safe());

    let manifest = list_archive(&archive, &config).unwrap();
    assert_eq!(manifest.total_entries(), 4);
    assert_eq!(manifest.entries()[0].path, Path::new("."));
}

#[test]
fn root_entry_is_listed_as_a_directory_in_both_spellings() {
    for root in ["./", "."] {
        let dir = TempDir::new().unwrap();
        let archive = write_zip(&dir, &zip_with_root_entry(root));

        let manifest = list_archive(&archive, &SecurityConfig::default()).unwrap();

        assert_eq!(
            manifest.entries()[0].kind,
            ManifestEntryKind::Directory,
            "{root:?}"
        );
    }
}

#[test]
fn duplicate_and_nested_root_spellings_extract() {
    let bytes = zip_of(|zip| {
        zip.start_file("./", options()).unwrap();
        zip.start_file(".", options()).unwrap();
        zip.start_file("a/./", options()).unwrap();
        zip.start_file("a/./f", options()).unwrap();
        zip.write_all(b"x").unwrap();
    });
    let dir = TempDir::new().unwrap();
    let archive = write_zip(&dir, &bytes);
    let out = TempDir::new().unwrap();

    extract_archive(&archive, out.path(), &SecurityConfig::default()).unwrap();

    assert_eq!(std::fs::read(out.path().join("a/f")).unwrap(), b"x");
}

#[test]
fn root_entry_with_payload_is_rejected_in_extract_list_and_verify() {
    let bytes = zip_of(|zip| {
        zip.start_file(".", options()).unwrap();
        zip.write_all(b"payload").unwrap();
    });
    let config = SecurityConfig::default();
    assert_eq!(extract_error_code(&bytes, &config), "SECURITY_VIOLATION");

    let dir = TempDir::new().unwrap();
    let archive = write_zip(&dir, &bytes);
    assert!(list_archive(&archive, &config).is_err());
    assert!(verify_archive(&archive, &config).is_err());
}

#[test]
fn root_symlink_entry_is_rejected_whether_or_not_symlinks_are_allowed() {
    let bytes = zip_of(|zip| zip.add_symlink(".", "sub", options()).unwrap());
    for allow in [false, true] {
        let config = SecurityConfig::default().with_allow_symlinks(allow);
        let dir = TempDir::new().unwrap();
        let archive = write_zip(&dir, &bytes);

        assert_eq!(
            extract_error_code(&bytes, &config),
            "SECURITY_VIOLATION",
            "allow_symlinks={allow}"
        );
        assert!(list_archive(&archive, &config).is_err(), "allow={allow}");
        assert!(verify_archive(&archive, &config).is_err(), "allow={allow}");
    }
}

#[test]
fn empty_root_file_entry_is_a_no_op_not_a_skipped_duplicate() {
    let bytes = zip_of(|zip| {
        zip.start_file(".", options()).unwrap();
        zip.start_file("a.txt", options()).unwrap();
        zip.write_all(b"hi").unwrap();
    });
    let dir = TempDir::new().unwrap();
    let archive = write_zip(&dir, &bytes);
    let out = TempDir::new().unwrap();

    let report = extract_archive(&archive, out.path(), &SecurityConfig::default()).unwrap();

    assert_eq!(report.files_skipped, 0);
    assert_eq!(report.files_extracted, 1);
    assert!(
        verify_archive(&archive, &SecurityConfig::default())
            .unwrap()
            .is_safe()
    );
}

#[test]
fn traversal_and_absolute_names_next_to_root_dir_entry_are_still_rejected() {
    for name in ["./../evil", "../", "/", "/./x"] {
        let bytes = zip_of(|zip| {
            zip.start_file("./", options()).unwrap();
            zip.start_file(name, options()).unwrap();
        });

        assert_eq!(
            extract_error_code(&bytes, &SecurityConfig::default()),
            "PATH_TRAVERSAL",
            "{name:?}"
        );
    }
}
