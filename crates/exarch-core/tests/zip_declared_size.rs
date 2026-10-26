//! Declared ZIP compressed sizes are validated against the archive length.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::assert_matches;
use std::io::Cursor;
use std::io::Write;

use exarch_core::ArchiveError;
use exarch_core::SecurityConfig;
use exarch_core::ZipHeaderField;
use exarch_core::ZipInconsistency;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use exarch_testkit::raw_zip::RawEntry;
use exarch_testkit::raw_zip::RawZip;
use tempfile::TempDir;
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;
use zip::write::ZipWriter;

const EXCEEDS_ARCHIVE: &str = "declared compressed size exceeds archive length";

fn stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, data) in entries {
        zip.start_file(*name, options).unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

/// A stored entry whose local header and central record both declare a
/// compressed size of `declared` bytes.
fn forged_entry(name: &str, data: &[u8], declared: u32) -> RawEntry {
    RawEntry {
        declared_compressed: Some(u64::from(declared)),
        local_sizes: Some((declared, u32::try_from(data.len()).unwrap())),
        ..RawEntry::stored(name, data)
    }
}

fn write_archive(dir: &TempDir, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.path().join("a.zip");
    std::fs::write(&path, bytes).unwrap();
    path
}

fn assert_exceeds_archive(error: Option<ArchiveError>) {
    assert_matches!(
        error,
        Some(ArchiveError::InvalidArchive(reason)) if reason == EXCEEDS_ARCHIVE
    );
}

#[test]
fn zip_rejects_declared_compressed_size_beyond_archive_length() {
    let built = RawZip::new(vec![forged_entry("a.txt", &[7u8; 64], 400_000)]).build();
    let dir = TempDir::new().unwrap();
    let path = write_archive(&dir, &built.bytes);
    let config = SecurityConfig::default();

    let out = TempDir::new().unwrap();
    assert_exceeds_archive(extract_archive(&path, out.path(), &config).err());
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);

    assert_exceeds_archive(list_archive(&path, &config).err());
    assert_exceeds_archive(verify_archive(&path, &config).err());
}

#[test]
fn zip_rejects_cumulative_declared_sizes_beyond_archive_length() {
    let baseline = RawZip::new(vec![
        RawEntry::stored("a.txt", &[1u8; 64]),
        RawEntry::stored("b.txt", &[2u8; 64]),
    ])
    .build();
    let archive_len = u32::try_from(baseline.bytes.len()).unwrap();
    // Each entry alone fits within the archive; together they do not.
    let per_entry = archive_len * 3 / 4;
    let built = RawZip::new(vec![
        forged_entry("a.txt", &[1u8; 64], per_entry),
        forged_entry("b.txt", &[2u8; 64], per_entry),
    ])
    .build();
    let dir = TempDir::new().unwrap();
    let path = write_archive(&dir, &built.bytes);

    assert_exceeds_archive(list_archive(&path, &SecurityConfig::default()).err());
}

#[test]
fn zip_with_prepended_data_within_declared_length_extracts() {
    let mut data = vec![0xAB; 1000];
    data.extend_from_slice(&stored_zip(&[("a.txt", b"hello")]));
    let dir = TempDir::new().unwrap();
    let path = write_archive(&dir, &data);

    let out = TempDir::new().unwrap();
    extract_archive(&path, out.path(), &SecurityConfig::default()).unwrap();
    assert_eq!(std::fs::read(out.path().join("a.txt")).unwrap(), b"hello");
}

#[test]
fn zip_well_formed_archive_lists_and_verifies() {
    let data = stored_zip(&[("a.txt", b"hello"), ("b.txt", b"world")]);
    let dir = TempDir::new().unwrap();
    let path = write_archive(&dir, &data);
    let config = SecurityConfig::default();

    assert_eq!(list_archive(&path, &config).unwrap().total_entries(), 2);
    assert!(verify_archive(&path, &config).unwrap().is_safe());
}

/// A second central record under another name that refers to the same local
/// header as the entry's own.
fn with_repeated_central_record(entry: RawEntry) -> RawZip {
    let repeated = RawEntry {
        name: b"b.txt".to_vec(),
        ..entry.clone()
    };
    let mut zip = RawZip::new(vec![entry]);
    zip.extra_central_records = vec![(repeated, 0)];
    zip
}

#[test]
fn zip_rejects_repeated_central_records_for_one_local_header() {
    // Both records declare 64 compressed bytes for data that exists once, so
    // the cumulative declared size is what rejects the archive.
    let zip = with_repeated_central_record(RawEntry::stored("a.txt", &[9u8; 64]));
    let dir = TempDir::new().unwrap();
    let path = write_archive(&dir, &zip.build().bytes);
    let config = SecurityConfig::default();

    assert_exceeds_archive(list_archive(&path, &config).err());
    assert_exceeds_archive(verify_archive(&path, &config).err());
    let out = TempDir::new().unwrap();
    assert_exceeds_archive(extract_archive(&path, out.path(), &config).err());
}

#[test]
fn zip_repeated_central_record_with_room_for_both_is_a_name_mismatch() {
    // Padding keeps the cumulative declared size within the archive, so the
    // repeated record is judged on its own: its name differs from the local
    // header's.
    let entry = RawEntry::stored("a.txt", &[9u8; 64]).with_padding_after(300);
    let zip = with_repeated_central_record(entry);
    let dir = TempDir::new().unwrap();
    let path = write_archive(&dir, &zip.build().bytes);
    let config = SecurityConfig::default();

    let mismatch = |error: Option<ArchiveError>| {
        assert_matches!(
            error,
            Some(ArchiveError::ZipInconsistency(
                ZipInconsistency::HeaderMismatch {
                    field: ZipHeaderField::FileName,
                    ..
                }
            ))
        );
    };
    mismatch(list_archive(&path, &config).err());
    let out = TempDir::new().unwrap();
    mismatch(extract_archive(&path, out.path(), &config).err());
}
