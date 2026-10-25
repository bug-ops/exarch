//! A TAR or ZIP entry with an empty name is rejected by `extract`, `list` and
//! `verify` alike, with the same error as 7z. It is not the root entry (`.`).

#![allow(clippy::unwrap_used)]

use std::io::Cursor;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::SecurityConfig;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use flate2::Compression;
use flate2::write::GzEncoder;
use tempfile::TempDir;
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;
use zip::write::ZipWriter;

fn tar_entry(name: &str, kind: tar::EntryType, data: &[u8]) -> Vec<u8> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(kind);
    header.set_mode(0o644);
    header.set_size(data.len() as u64);
    header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
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

fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in entries {
        zip.start_file(*name, options).unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

fn write_archive(dir: &TempDir, file_name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join(file_name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn dir_is_empty(path: &Path) -> bool {
    std::fs::read_dir(path).unwrap().next().is_none()
}

/// Asserts all three commands fail with the empty-path security violation and
/// `extract` writes nothing.
fn assert_empty_name_rejected(archive: &Path) {
    let out = TempDir::new().unwrap();
    let config = SecurityConfig::default();

    let errors = [
        list_archive(archive, &config).unwrap_err(),
        verify_archive(archive, &config).unwrap_err(),
        extract_archive(archive, out.path(), &config).unwrap_err(),
    ];
    for err in errors {
        assert_eq!(err.error_code(), "SECURITY_VIOLATION", "{err}");
        assert!(err.to_string().contains("empty path not allowed"), "{err}");
    }
    assert!(dir_is_empty(out.path()));
}

#[test]
fn tar_empty_name_is_rejected_by_list_verify_and_extract() {
    for kind in [tar::EntryType::Regular, tar::EntryType::Directory] {
        for data in [&b""[..], b"payload"] {
            let dir = TempDir::new().unwrap();
            let bytes = tar_of(&[
                tar_entry("", kind, data),
                tar_entry("a.txt", tar::EntryType::Regular, b"hi"),
            ]);
            let archive = write_archive(&dir, "empty-name.tar", &bytes);

            assert_empty_name_rejected(&archive);
        }
    }
}

#[test]
fn tar_pax_and_gnu_long_empty_names_are_rejected_by_list_verify_and_extract() {
    let pax = tar_entry("pax", tar::EntryType::XHeader, b"8 path=\n");
    let gnu_long = tar_entry("long", tar::EntryType::GNULongName, b"\0");
    for prefix in [pax, gnu_long] {
        let dir = TempDir::new().unwrap();
        let bytes = tar_of(&[prefix, tar_entry("a.txt", tar::EntryType::Regular, b"hi")]);
        let archive = write_archive(&dir, "empty-long-name.tar", &bytes);

        assert_empty_name_rejected(&archive);
    }
}

#[test]
fn tar_gz_empty_name_is_rejected_by_list_verify_and_extract() {
    let dir = TempDir::new().unwrap();
    let bytes = gzip(&tar_of(&[tar_entry("", tar::EntryType::Regular, b"x")]));
    let archive = write_archive(&dir, "empty-name.tar.gz", &bytes);

    assert_empty_name_rejected(&archive);
}

#[test]
fn zip_empty_name_is_rejected_by_list_verify_and_extract() {
    for data in [&b""[..], b"payload"] {
        let dir = TempDir::new().unwrap();
        let bytes = zip_of(&[("", data), ("a.txt", b"hi")]);
        let archive = write_archive(&dir, "empty-name.zip", &bytes);

        assert_empty_name_rejected(&archive);
    }
}
