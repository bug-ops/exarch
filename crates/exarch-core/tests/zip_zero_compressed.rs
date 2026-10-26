//! A ZIP entry claiming data from zero compressed bytes is a zip bomb with an
//! unbounded ratio.

#![allow(clippy::unwrap_used)]

use std::assert_matches;

use exarch_core::ArchiveError;
use exarch_core::CompressionRatio;
use exarch_core::IssueCategory;
use exarch_core::SecurityConfig;
use exarch_core::ZipBombScope;
use exarch_core::extract_archive;
use exarch_core::verify_archive;
use exarch_testkit::raw_zip::RawEntry;
use exarch_testkit::raw_zip::RawZip;
use tempfile::TempDir;

/// A stored entry of 64 bytes whose headers both declare zero compressed bytes.
fn zero_compressed_zip() -> Vec<u8> {
    let entry = RawEntry {
        declared_compressed: Some(0),
        local_sizes: Some((0, 64)),
        ..RawEntry::stored("a.txt", &[7u8; 64])
    };
    RawZip::new(vec![entry]).build().bytes
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
