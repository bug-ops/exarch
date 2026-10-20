//! Unsupported ZIP compression methods are rejected at open, identically by
//! extract, list and verify, before anything is written.

#![allow(clippy::unwrap_used)]

use std::assert_matches;
use std::io::Cursor;
use std::io::Write;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use tempfile::TempDir;
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;
use zip::write::ZipWriter;

const LOCAL_SIGNATURE: &[u8] = b"PK\x03\x04";
const CENTRAL_SIGNATURE: &[u8] = b"PK\x01\x02";
const LOCAL_METHOD_OFFSET: usize = 8;
const CENTRAL_METHOD_OFFSET: usize = 10;
const DEFLATE64_METHOD: u16 = 9;

fn patch_last_method(data: &mut [u8], signature: &[u8], offset: usize) {
    let last = data
        .windows(signature.len())
        .rposition(|w| w == signature)
        .unwrap();
    data[last + offset..last + offset + 2].copy_from_slice(&DEFLATE64_METHOD.to_le_bytes());
}

/// Two stored entries; the second one is relabelled as `deflate64`.
fn zip_with_deflate64_entry() -> Vec<u8> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    zip.start_file("ok.txt", options).unwrap();
    zip.write_all(b"fine").unwrap();
    zip.start_file("odd.bin", options).unwrap();
    zip.write_all(b"data").unwrap();
    let mut data = zip.finish().unwrap().into_inner();
    patch_last_method(&mut data, LOCAL_SIGNATURE, LOCAL_METHOD_OFFSET);
    patch_last_method(&mut data, CENTRAL_SIGNATURE, CENTRAL_METHOD_OFFSET);
    data
}

fn write_fixture(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("deflate64.zip");
    std::fs::write(&path, zip_with_deflate64_entry()).unwrap();
    path
}

#[test]
fn extract_rejects_unsupported_method_with_empty_destination() {
    let dir = TempDir::new().unwrap();
    let path = write_fixture(&dir);
    let out = TempDir::new().unwrap();

    assert_matches!(
        extract_archive(&path, out.path(), &SecurityConfig::default()),
        Err(ArchiveError::SecurityViolation { reason })
            if reason.contains("unsupported compression method")
    );
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[test]
fn list_rejects_unsupported_method() {
    let dir = TempDir::new().unwrap();
    let path = write_fixture(&dir);

    assert_matches!(
        list_archive(&path, &SecurityConfig::default()),
        Err(ArchiveError::SecurityViolation { reason })
            if reason.contains("unsupported compression method")
    );
}

#[test]
fn verify_rejects_unsupported_method() {
    let dir = TempDir::new().unwrap();
    let path = write_fixture(&dir);

    assert_matches!(
        verify_archive(&path, &SecurityConfig::default()),
        Err(ArchiveError::SecurityViolation { reason })
            if reason.contains("unsupported compression method")
    );
}
