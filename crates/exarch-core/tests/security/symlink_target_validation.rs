//! Regression tests for issue #415: symlink/hardlink targets were not
//! validated for embedded NUL bytes or emptiness, unlike the link path
//! itself.
//!
//! A short (<=100 byte) linkname written through the `tar` crate's own
//! `Header::set_link_name`/`set_link_name_literal` cannot carry an embedded
//! NUL byte or reach an empty value while non-`None` (the crate either
//! rejects NUL bytes outright or treats an all-zero field as "no link name").
//! A GNU `LongLink` (`K`) record's raw payload has no such restriction, so
//! these tests use one to smuggle both an embedded NUL byte and a truly
//! empty target past the header-field-level shortcuts, exercising the same
//! path a real crafted archive would take.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use exarch_core::ArchiveError;
use exarch_core::ExtractionOptions;
use exarch_core::SecurityConfig;
use exarch_core::formats::ArchiveFormat;
use exarch_core::formats::TarArchive;
use std::assert_matches;
use std::io::Cursor;
use tempfile::TempDir;

/// Builds a TAR archive with a GNU `LongLink` (`K`) record carrying
/// `raw_target` verbatim as its payload, followed by an entry of type
/// `entry_type` at `path` whose own (short) linkname field is overridden by
/// the preceding `LongLink` record.
fn build_tar_with_raw_link_target(
    entry_type: tar::EntryType,
    path: &str,
    raw_target: &[u8],
) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    let mut long_link_header = tar::Header::new_gnu();
    long_link_header.set_entry_type(tar::EntryType::GNULongLink);
    long_link_header.set_size(raw_target.len() as u64);
    long_link_header.set_cksum();
    builder.append(&long_link_header, raw_target).unwrap();

    let mut header = tar::Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_size(0);
    header.set_mode(0o644);
    // Placeholder short name; overridden by the preceding LongLink record.
    header.set_link_name_literal(b"placeholder").unwrap();
    header.set_cksum();
    builder
        .append_data(&mut header, path, std::io::empty())
        .unwrap();

    builder.into_inner().unwrap()
}

fn extract_with_symlinks_allowed(
    tar_data: Vec<u8>,
) -> exarch_core::Result<exarch_core::ExtractionReport> {
    let temp = TempDir::new().unwrap();
    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let config = SecurityConfig::default()
        .with_allow_symlinks(true)
        .validate()
        .unwrap();
    archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut exarch_core::NoopProgress,
    )
}

fn extract_with_hardlinks_allowed(
    tar_data: Vec<u8>,
) -> exarch_core::Result<exarch_core::ExtractionReport> {
    let temp = TempDir::new().unwrap();
    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let config = SecurityConfig::default()
        .with_allow_hardlinks(true)
        .validate()
        .unwrap();
    archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut exarch_core::NoopProgress,
    )
}

#[test]
fn extract_rejects_symlink_target_with_null_byte() {
    let tar_data =
        build_tar_with_raw_link_target(tar::EntryType::Symlink, "link", b"benign\0target");

    let result = extract_with_symlinks_allowed(tar_data);

    assert_matches!(
        result,
        Err(ArchiveError::SecurityViolation { .. }),
        "symlink target containing a null byte must be rejected as a SecurityViolation, got: {result:?}"
    );
}

#[test]
fn extract_rejects_empty_symlink_target() {
    let tar_data = build_tar_with_raw_link_target(tar::EntryType::Symlink, "link", b"");

    let result = extract_with_symlinks_allowed(tar_data);

    assert_matches!(
        result,
        Err(ArchiveError::SecurityViolation { .. }),
        "empty symlink target must be rejected, not silently create a dangling symlink, got: {result:?}"
    );
}

#[test]
fn extract_hardlink_null_byte_error_does_not_embed_raw_null() {
    let tar_data = build_tar_with_raw_link_target(tar::EntryType::Link, "link", b"benign\0target");

    let result = extract_with_hardlinks_allowed(tar_data);

    let err = result.expect_err("hardlink target containing a null byte must be rejected");
    assert_matches!(
        err,
        ArchiveError::SecurityViolation { .. },
        "expected SecurityViolation, got: {err:?}"
    );
    let message = err.to_string();
    assert!(
        !message.contains('\0'),
        "error message must not embed the raw null byte: {message:?}"
    );
}

#[test]
fn extract_rejects_empty_hardlink_target() {
    let tar_data = build_tar_with_raw_link_target(tar::EntryType::Link, "link", b"");

    let result = extract_with_hardlinks_allowed(tar_data);

    assert_matches!(
        result,
        Err(ArchiveError::SecurityViolation { .. }),
        "empty hardlink target must be rejected, got: {result:?}"
    );
}
