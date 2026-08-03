//! Regression test for issue #505: a skip-only `ExtractionReport` (zero
//! `total_items()`, but nonzero `files_skipped`/warnings) was discarded by
//! `ArchiveError::partial_or` on a later mid-archive failure, instead of
//! surfacing as `PartialExtraction`. This exercises the exact repro shape
//! through the public `extract_archive` API: a first entry skipped by the
//! extension allowlist, followed by a second entry that fails validation.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use exarch_core::ArchiveError;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive;
use std::assert_matches;
use tempfile::TempDir;

/// Builds a TAR with a disallowed-extension entry (skipped by the extension
/// allowlist before validation runs) followed by a symlink whose absolute
/// target escapes the extraction directory (a hard validation failure).
fn build_tar_skip_then_symlink_escape() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    let mut h1 = tar::Header::new_gnu();
    h1.set_size(3);
    h1.set_mode(0o644);
    h1.set_cksum();
    builder
        .append_data(&mut h1, "payload.bin", &b"abc"[..])
        .unwrap();

    let mut h2 = tar::Header::new_gnu();
    h2.set_entry_type(tar::EntryType::Symlink);
    h2.set_size(0);
    h2.set_mode(0o644);
    h2.set_link_name("/etc/evil").unwrap();
    h2.set_cksum();
    builder
        .append_data(&mut h2, "escape_link", std::io::empty())
        .unwrap();

    builder.into_inner().unwrap()
}

#[test]
fn skip_only_report_still_wraps_as_partial_extraction_on_later_failure() {
    let data = build_tar_skip_then_symlink_escape();
    let archive_dir = TempDir::new().expect("temp dir for archive");
    let archive_path = archive_dir.path().join("skip_then_fail.tar");
    std::fs::write(&archive_path, &data).expect("write tar to disk");

    let dest = TempDir::new().expect("temp dir for extraction");
    let config = SecurityConfig::default()
        .with_allowed_extensions(vec!["txt".to_string()])
        .with_allow_symlinks(true);

    let result = extract_archive(&archive_path, dest.path(), &config);

    match result {
        Err(ArchiveError::PartialExtraction { source, report }) => {
            assert_matches!(
                *source,
                ArchiveError::SymlinkEscape { .. },
                "expected SymlinkEscape source, got: {source:?}"
            );
            assert_eq!(
                report.files_skipped, 1,
                "payload.bin must be counted as skipped for its disallowed extension"
            );
            assert_eq!(
                report.total_items(),
                0,
                "no entry was ever written before the failure"
            );
            assert!(
                report.has_warnings(),
                "the extension-skip warning must survive on the wrapped report"
            );
        }
        other => panic!("expected PartialExtraction wrapping the skip-only report, got: {other:?}"),
    }
}
