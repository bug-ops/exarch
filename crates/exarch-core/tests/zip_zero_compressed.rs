//! A ZIP entry claiming data from zero compressed bytes is a zip bomb with an
//! unbounded ratio.

#![allow(clippy::unwrap_used)]

use std::assert_matches;
use std::io::Cursor;
use std::io::Write;

use exarch_core::ArchiveError;
use exarch_core::CompressionRatio;
use exarch_core::IssueCategory;
use exarch_core::SecurityConfig;
use exarch_core::ZipBombScope;
use exarch_core::extract_archive;
use exarch_core::verify_archive;
use tempfile::TempDir;
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;
use zip::write::ZipWriter;

const LOCAL_SIGNATURE: &[u8] = b"PK\x03\x04";
const CENTRAL_SIGNATURE: &[u8] = b"PK\x01\x02";
const LOCAL_COMPRESSED_SIZE_OFFSET: usize = 18;
const CENTRAL_COMPRESSED_SIZE_OFFSET: usize = 20;

fn zero_compressed_zip() -> Vec<u8> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    zip.start_file("a.txt", options).unwrap();
    zip.write_all(&[7u8; 64]).unwrap();
    let mut data = zip.finish().unwrap().into_inner();
    for (signature, offset) in [
        (LOCAL_SIGNATURE, LOCAL_COMPRESSED_SIZE_OFFSET),
        (CENTRAL_SIGNATURE, CENTRAL_COMPRESSED_SIZE_OFFSET),
    ] {
        let at = data
            .windows(signature.len())
            .position(|w| w == signature)
            .unwrap();
        data[at + offset..at + offset + 4].copy_from_slice(&0u32.to_le_bytes());
    }
    data
}

#[test]
fn zero_compressed_entry_is_unbounded_zip_bomb_in_extract_and_verify() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("zero.zip");
    std::fs::write(&path, zero_compressed_zip()).unwrap();
    let config = SecurityConfig::default();

    let out = TempDir::new().unwrap();
    assert_matches!(
        extract_archive(&path, out.path(), &config),
        Err(ArchiveError::ZipBomb(details))
            if details.scope() == ZipBombScope::Entry
                && details.ratio() == CompressionRatio::Unbounded
    );
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);

    let report = verify_archive(&path, &config).unwrap();
    assert!(
        report
            .issues()
            .iter()
            .any(|i| i.category == IssueCategory::ZipBomb && i.message.contains("unbounded")),
        "issues: {:?}",
        report.issues()
    );
}
