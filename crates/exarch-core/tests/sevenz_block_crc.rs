//! `verify` reports every corrupt entry of a solid 7z block, including one
//! with no checksum of its own that only the block checksum covers, whether or
//! not another entry of the block already failed its own checksum.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

mod common;

use std::path::Path;
use std::path::PathBuf;

use common::RawEntry;
use common::crc32;
use common::flip_first;
use common::solid_copy_7z_with_crcs;
use exarch_core::DecompressionBudget;
use exarch_core::IntegrityCheck;
use exarch_core::IssueCategory;
use exarch_core::SecurityConfig;
use exarch_core::SolidArchives;
use exarch_core::SolidLimits;
use exarch_core::VerificationOptions;
use exarch_core::VerificationReport;
use exarch_core::VerifyRequest;
use tempfile::TempDir;

const A: &[u8] = b"AAAAAAAAAAAA";
const B: &[u8] = b"BBBBBBBBBBBB";
const C: &[u8] = b"CCCCCCCCCCCC";

fn verify(path: &Path) -> VerificationReport {
    let config =
        SecurityConfig::default().with_solid_archives(SolidArchives::Allow(SolidLimits::DEFAULT));
    let options = VerificationOptions::default()
        .with_integrity(IntegrityCheck::DecodeToEof(DecompressionBudget::DEFAULT));
    VerifyRequest::new(&config)
        .with_options(options)
        .verify(path)
        .unwrap()
}

fn corrupt_paths(report: &VerificationReport) -> Vec<String> {
    let mut paths: Vec<_> = report
        .issues()
        .iter()
        .filter(|i| i.category() == IssueCategory::CorruptData)
        .filter_map(|i| i.entry_path())
        .map(|p| p.display().to_string())
        .collect();
    paths.sort();
    paths
}

fn write(dir: &TempDir, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join("block.7z");
    std::fs::write(&path, bytes).unwrap();
    path
}

fn archive(file_crcs: &[Option<u32>], block: &[u8], corrupt: &[&[u8]]) -> Vec<u8> {
    let entries = [
        RawEntry::File("a", A),
        RawEntry::File("b", B),
        RawEntry::File("c", C),
    ];
    let mut bytes = solid_copy_7z_with_crcs(&entries, file_crcs, Some(crc32(block)));
    for marker in corrupt {
        flip_first(&mut bytes, marker);
    }
    bytes
}

fn whole_block() -> Vec<u8> {
    [A, B, C].concat()
}

#[test]
fn an_entry_without_a_checksum_is_blamed_when_the_block_checksum_fails_after_another_entry() {
    let dir = TempDir::new().unwrap();
    let bytes = archive(&[Some(crc32(A)), None, None], &whole_block(), &[A, C]);

    let report = verify(&write(&dir, &bytes));

    assert_eq!(corrupt_paths(&report), ["a", "c"]);
}

#[test]
fn every_entry_with_its_own_checksum_is_reported_once() {
    let dir = TempDir::new().unwrap();
    let crcs = [Some(crc32(A)), Some(crc32(B)), Some(crc32(C))];
    let bytes = archive(&crcs, &whole_block(), &[A, C]);

    let report = verify(&write(&dir, &bytes));

    assert_eq!(corrupt_paths(&report), ["a", "c"]);
}

#[test]
fn a_block_checksum_alone_blames_the_last_entry() {
    let dir = TempDir::new().unwrap();
    let bytes = archive(&[], &whole_block(), &[B]);

    let report = verify(&write(&dir, &bytes));

    assert_eq!(corrupt_paths(&report), ["c"]);
}

#[test]
fn an_intact_block_with_mixed_checksums_passes() {
    let dir = TempDir::new().unwrap();
    let bytes = archive(&[Some(crc32(A)), None, Some(crc32(C))], &whole_block(), &[]);

    let report = verify(&write(&dir, &bytes));

    assert!(corrupt_paths(&report).is_empty());
    assert!(
        report
            .issues()
            .iter()
            .all(|i| i.category() != IssueCategory::CorruptData),
        "{:?}",
        report.issues()
    );
}
