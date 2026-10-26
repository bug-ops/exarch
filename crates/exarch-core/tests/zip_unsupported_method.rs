//! Unsupported ZIP compression methods are rejected at open, identically by
//! extract, list and verify, before anything is written.

#![allow(clippy::unwrap_used)]

use std::assert_matches;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use exarch_testkit::raw_zip::RawEntry;
use exarch_testkit::raw_zip::RawZip;
use tempfile::TempDir;

const DEFLATE64_METHOD: u16 = 9;

/// Two stored entries; the second one is labelled `deflate64`.
fn zip_with_deflate64_entry() -> Vec<u8> {
    let odd = RawEntry {
        method: DEFLATE64_METHOD,
        ..RawEntry::stored("odd.bin", b"data")
    };
    RawZip::new(vec![RawEntry::stored("ok.txt", b"fine"), odd])
        .build()
        .bytes
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
        Err(ArchiveError::SecurityViolation { reason, .. })
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
        Err(ArchiveError::SecurityViolation { reason, .. })
            if reason.contains("unsupported compression method")
    );
}

#[test]
fn verify_rejects_unsupported_method() {
    let dir = TempDir::new().unwrap();
    let path = write_fixture(&dir);

    assert_matches!(
        verify_archive(&path, &SecurityConfig::default()),
        Err(ArchiveError::SecurityViolation { reason, .. })
            if reason.contains("unsupported compression method")
    );
}
