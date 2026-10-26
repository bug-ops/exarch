//! A TAR regular-file entry named with a trailing slash and carrying a payload
//! is refused by `list`, `verify` and `extract` with a typed `InvalidArchive`;
//! the same entry without a payload stays a directory.

#![allow(clippy::unwrap_used)]

use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::ManifestEntryKind;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use flate2::Compression;
use flate2::write::GzEncoder;
use tempfile::TempDir;

const REGULAR: u8 = b'0';
const CONTINUOUS: u8 = b'7';
const GNU_SPARSE: u8 = b'S';

fn octal_field(dest: &mut [u8], value: usize) {
    let text = format!("{value:011o}\0");
    dest.copy_from_slice(text.as_bytes());
}

fn entry(name: &str, typeflag: u8, data: &[u8]) -> Vec<u8> {
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o644);
    header.set_size(data.len() as u64);
    header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
    header.set_cksum();
    let mut block = header.as_bytes().to_vec();
    block[156] = typeflag;
    if typeflag == GNU_SPARSE {
        // One sparse segment covering the whole payload, real size = payload.
        octal_field(&mut block[386..398], 0);
        octal_field(&mut block[398..410], data.len());
        block[482] = 0;
        octal_field(&mut block[483..495], data.len());
    }
    block[148..156].fill(b' ');
    let checksum: u32 = block.iter().map(|&b| u32::from(b)).sum();
    block[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    block.extend_from_slice(data);
    block.resize(block.len().next_multiple_of(512), 0);
    block
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

fn smuggling_tar(typeflag: u8) -> Vec<u8> {
    tar_of(&[
        entry("ok.txt", REGULAR, b"ok"),
        entry("a/b/", typeflag, b"payload"),
        entry("z.txt", REGULAR, b"z"),
    ])
}

fn assert_invalid_archive(error: &ArchiveError) {
    assert_eq!(error.error_code(), "INVALID_ARCHIVE", "{error}");
    assert!(error.to_string().contains("a/b/"), "{error}");
}

fn assert_refused_everywhere(archive: &Path) {
    let config = SecurityConfig::default();
    assert_invalid_archive(&list_archive(archive, &config).unwrap_err());
    assert_invalid_archive(&verify_archive(archive, &config).unwrap_err());

    let out = TempDir::new().unwrap();
    let error = extract_archive(archive, out.path(), &config).unwrap_err();
    let ArchiveError::PartialExtraction { source, .. } = &error else {
        panic!("expected PartialExtraction, got {error:?}");
    };
    assert_invalid_archive(source);
    assert!(out.path().join("ok.txt").is_file());
    assert!(!out.path().join("a").join("b").exists());
    assert!(!out.path().join("z.txt").exists());
}

#[test]
fn directory_named_file_with_payload_is_refused_in_tar() {
    for typeflag in [REGULAR, CONTINUOUS, GNU_SPARSE] {
        let dir = TempDir::new().unwrap();
        let archive = write_archive(&dir, "smuggle.tar", &smuggling_tar(typeflag));
        assert_refused_everywhere(&archive);
    }
}

#[test]
fn directory_named_file_with_payload_is_refused_in_tar_gz() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, "smuggle.tar.gz", &gzip(&smuggling_tar(REGULAR)));
    assert_refused_everywhere(&archive);
}

#[test]
fn directory_named_file_without_payload_is_still_a_directory() {
    for typeflag in [REGULAR, CONTINUOUS] {
        assert_empty_file_typed_entry_is_a_directory(typeflag);
    }
}

fn assert_empty_file_typed_entry_is_a_directory(typeflag: u8) {
    let dir = TempDir::new().unwrap();
    let bytes = tar_of(&[
        entry("a/b/", typeflag, b""),
        entry("a/b/f.txt", REGULAR, b"f"),
    ]);
    let archive = write_archive(&dir, "dirs.tar", &bytes);
    let config = SecurityConfig::default();

    let manifest = list_archive(&archive, &config).unwrap();
    assert!(
        manifest
            .entries()
            .iter()
            .any(|e| e.kind == ManifestEntryKind::Directory)
    );
    assert!(verify_archive(&archive, &config).is_ok());

    let out = TempDir::new().unwrap();
    extract_archive(&archive, out.path(), &config).unwrap();
    assert!(out.path().join("a").join("b").is_dir());
    assert!(out.path().join("a").join("b").join("f.txt").is_file());
}
