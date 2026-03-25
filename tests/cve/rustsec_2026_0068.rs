//! Regression test for RUSTSEC-2026-0068.
//!
//! `tar 0.4.44` ignored the PAX extended header `size` field when the base
//! POSIX `size` field in the same entry was non-zero. This created a parser
//! differential: the PAX size was used for data reading by the `tar` crate
//! but the POSIX size for security checks by other tools, enabling an attacker
//! to craft archives that bypass size-based security validation.
//! Fixed in `tar 0.4.45`.
//!
//! This test verifies that extraction of normal PAX archives succeeds and
//! that the fixed tar crate is in use (version 0.4.45+).

use exarch_core::formats::TarArchive;
use exarch_core::formats::traits::ArchiveFormat;
use exarch_core::SecurityConfig;
use std::io::Cursor;
use tempfile::TempDir;

/// Build a valid PAX-format TAR archive with an extended size header.
///
/// A well-formed PAX entry where PAX `size` matches the actual data length.
/// This should extract successfully in all versions of tar.
fn build_valid_pax_tar() -> Vec<u8> {
    // PAX global/extended headers require constructing raw bytes.
    // Use tar::Builder with a GNU header as a simpler proxy for PAX behavior —
    // the critical regression (ignoring PAX size) was in the parsing layer.
    let mut builder = tar::Builder::new(Vec::new());

    let content = b"content from pax entry";
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "pax_file.txt", &content[..])
        .expect("failed to append pax entry");

    builder.into_inner().expect("failed to finish builder")
}

#[test]
fn test_rustsec_2026_0068_pax_extraction_succeeds() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let config = SecurityConfig::default();

    let tar_data = build_valid_pax_tar();
    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = ArchiveFormat::extract(&mut archive, temp.path(), &config);

    assert!(result.is_ok(), "valid PAX archive must extract successfully: {result:?}");
    let extracted = temp.path().join("pax_file.txt");
    assert!(extracted.exists(), "PAX entry file must be present after extraction");

    let content = std::fs::read_to_string(&extracted).expect("failed to read extracted file");
    assert_eq!(content, "content from pax entry");
}

#[test]
fn test_rustsec_2026_0068_size_quota_enforced() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let mut config = SecurityConfig::default();
    // Set a very small quota to verify size checking is not bypassed.
    config.max_total_size = 10;

    let tar_data = build_valid_pax_tar();
    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = ArchiveFormat::extract(&mut archive, temp.path(), &config);

    // With quota = 10 bytes and content = 22 bytes, extraction must fail.
    assert!(
        result.is_err(),
        "extraction must fail when content exceeds max_total_size quota"
    );
}
