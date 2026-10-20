//! Declared ZIP compressed sizes are validated against the archive length.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::assert_matches;
use std::io::Cursor;
use std::io::Write;

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
const LOCAL_COMPRESSED_SIZE_OFFSET: usize = 18;
const CENTRAL_COMPRESSED_SIZE_OFFSET: usize = 20;

fn stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, data) in entries {
        zip.start_file(*name, options).unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

fn set_declared_compressed_size(data: &mut [u8], signature: &[u8], offset: usize, size: u32) {
    let at = data
        .windows(signature.len())
        .position(|w| w == signature)
        .expect("header present");
    data[at + offset..at + offset + 4].copy_from_slice(&size.to_le_bytes());
}

fn with_declared_compressed_size(mut data: Vec<u8>, size: u32) -> Vec<u8> {
    set_declared_compressed_size(
        &mut data,
        LOCAL_SIGNATURE,
        LOCAL_COMPRESSED_SIZE_OFFSET,
        size,
    );
    set_declared_compressed_size(
        &mut data,
        CENTRAL_SIGNATURE,
        CENTRAL_COMPRESSED_SIZE_OFFSET,
        size,
    );
    data
}

#[test]
fn zip_rejects_declared_compressed_size_beyond_archive_length() {
    let data = with_declared_compressed_size(stored_zip(&[("a.txt", &[7u8; 64])]), 400_000);
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("a.zip");
    std::fs::write(&path, &data).unwrap();
    let config = SecurityConfig::default();

    let out = TempDir::new().unwrap();
    assert_matches!(
        extract_archive(&path, out.path(), &config),
        Err(ArchiveError::InvalidArchive(_))
    );
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);

    assert_matches!(
        list_archive(&path, &config),
        Err(ArchiveError::InvalidArchive(_))
    );
    assert_matches!(
        verify_archive(&path, &config),
        Err(ArchiveError::InvalidArchive(_))
    );
}

#[test]
fn zip_rejects_cumulative_declared_sizes_beyond_archive_length() {
    let mut data = stored_zip(&[("a.txt", &[1u8; 64]), ("b.txt", &[2u8; 64])]);
    let archive_len = u32::try_from(data.len()).unwrap();
    // Each entry alone fits within the archive; together they do not.
    let per_entry = archive_len * 3 / 4;
    for signature_offset in [
        (LOCAL_SIGNATURE, LOCAL_COMPRESSED_SIZE_OFFSET),
        (CENTRAL_SIGNATURE, CENTRAL_COMPRESSED_SIZE_OFFSET),
    ] {
        let (signature, offset) = signature_offset;
        let positions: Vec<usize> = data
            .windows(signature.len())
            .enumerate()
            .filter(|(_, w)| *w == signature)
            .map(|(i, _)| i)
            .collect();
        for at in positions {
            data[at + offset..at + offset + 4].copy_from_slice(&per_entry.to_le_bytes());
        }
    }
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("a.zip");
    std::fs::write(&path, &data).unwrap();

    assert_matches!(
        list_archive(&path, &SecurityConfig::default()),
        Err(ArchiveError::InvalidArchive(_))
    );
}

#[test]
fn zip_with_prepended_data_within_declared_length_extracts() {
    let mut data = vec![0xAB; 1000];
    data.extend_from_slice(&stored_zip(&[("a.txt", b"hello")]));
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("a.zip");
    std::fs::write(&path, &data).unwrap();

    let out = TempDir::new().unwrap();
    extract_archive(&path, out.path(), &SecurityConfig::default()).unwrap();
    assert_eq!(std::fs::read(out.path().join("a.txt")).unwrap(), b"hello");
}

#[test]
fn zip_well_formed_archive_lists_and_verifies() {
    let data = stored_zip(&[("a.txt", b"hello"), ("b.txt", b"world")]);
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("a.zip");
    std::fs::write(&path, &data).unwrap();
    let config = SecurityConfig::default();

    assert_eq!(list_archive(&path, &config).unwrap().total_entries(), 2);
    assert!(verify_archive(&path, &config).unwrap().is_safe());
}

/// Appends a second central-directory record (under another name) that
/// refers to the same local header.
fn with_repeated_central_record(data: &[u8]) -> Vec<u8> {
    const EOCD: &[u8] = b"PK\x05\x06";
    let eocd_at = data.windows(4).rposition(|w| w == EOCD).unwrap();
    let dir_start = u32::from_le_bytes(*data[eocd_at + 16..].first_chunk::<4>().unwrap()) as usize;
    let record = &data[dir_start..eocd_at];

    let mut second = record.to_vec();
    let name_at = second.windows(5).position(|w| w == b"a.txt").unwrap();
    second[name_at] = b'b';

    let mut out = data[..eocd_at].to_vec();
    out.extend_from_slice(&second);
    let mut eocd = data[eocd_at..].to_vec();
    eocd[8..10].copy_from_slice(&2u16.to_le_bytes());
    eocd[10..12].copy_from_slice(&2u16.to_le_bytes());
    let dir_size = u32::try_from(record.len() * 2).unwrap();
    eocd[12..16].copy_from_slice(&dir_size.to_le_bytes());
    out.extend_from_slice(&eocd);
    out
}

#[test]
fn zip_rejects_repeated_central_records_for_one_local_header() {
    let data = with_repeated_central_record(&stored_zip(&[("a.txt", &[9u8; 64])]));
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("a.zip");
    std::fs::write(&path, &data).unwrap();
    let config = SecurityConfig::default();

    assert_matches!(
        list_archive(&path, &config),
        Err(ArchiveError::InvalidArchive(_))
    );
    assert_matches!(
        verify_archive(&path, &config),
        Err(ArchiveError::InvalidArchive(_))
    );
    let out = TempDir::new().unwrap();
    assert!(extract_archive(&path, out.path(), &config).is_err());
}
