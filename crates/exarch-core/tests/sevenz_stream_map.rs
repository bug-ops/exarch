//! A 7z header with streams info and no files info is an invalid archive for
//! `list`, `verify` and `extract` alike, never a panic (#746).
//!
//! The fixture is the 66-byte fuzzer vector from `sevenz-rust2`; see the
//! provenance note in `tests/fixtures/generate_7z_fixtures.sh`.

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::DecompressionBudget;
use exarch_core::IntegrityCheck;
use exarch_core::SecurityConfig;
use exarch_core::VerificationOptions;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use exarch_core::verify_archive_with_options;
use tempfile::TempDir;

fn vector() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/streams-without-files-info.7z")
}

fn assert_invalid_archive(result: &Result<impl std::fmt::Debug, ArchiveError>) {
    assert!(
        matches!(result, Err(ArchiveError::InvalidArchive(m)) if m.starts_with("failed to open 7z archive: ")),
        "expected InvalidArchive, got {result:?}"
    );
}

#[test]
fn list_rejects_streams_without_files_info() {
    assert_invalid_archive(&list_archive(vector(), &SecurityConfig::default()));
}

#[test]
fn verify_rejects_streams_without_files_info() {
    assert_invalid_archive(&verify_archive(vector(), &SecurityConfig::default()));
}

#[test]
fn verify_with_integrity_rejects_streams_without_files_info() {
    let options = VerificationOptions::default()
        .with_integrity(IntegrityCheck::DecodeToEof(DecompressionBudget::DEFAULT));
    assert_invalid_archive(&verify_archive_with_options(
        vector(),
        &SecurityConfig::default(),
        &options,
    ));
}

#[test]
fn extract_rejects_streams_without_files_info_and_writes_nothing() {
    let out = TempDir::new().unwrap();
    let result = extract_archive(vector(), out.path(), &SecurityConfig::default());
    assert_invalid_archive(&result);
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}
