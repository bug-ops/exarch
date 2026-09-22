//! Regression test for GHSA-83g3-92jg-28cx (exarch variant — issue #116).
//!
//! When `--allow-symlinks` is enabled, a two-hop symlink chain could bypass
//! `SafeSymlink::validate`. String-based path normalization treated the second
//! symlink's target as safe because normalizing the string representation kept
//! it within the extraction root. On disk, the first symlink redirects the
//! traversal outside the root.
//!
//! Attack chain:
//!
//! - Entry 1: dir `a/b/c/`
//! - Entry 2: link `a/b/c/up` -> `../..` (resolves to `a/` — written to disk)
//! - Entry 3: link `a/b/escape` -> `c/up/../..` (string: `a/b/` — PASS; disk:
//!   escapes dest)
//! - Entry 4: hard `exfil` -> `a/b/escape/../../etc/passwd`
//!
//! This is the only end-to-end (`TarArchive::extract`) coverage of the
//! two-hop chain:
//! `src/types/safe_symlink.rs::test_safe_symlink_two_hop_chain_rejected`
//! and `src/security/hardlink.rs::test_hardlink_two_hop_chain_rejected` call
//! `SafeSymlink::validate`/hardlink validation directly against a
//! hand-constructed on-disk symlink, which does not exercise
//! `validate_entry_path`'s canonicalize-skipping optimizations
//! (`mark_symlink_seen`, `with_dir_cache`) the way a real archive extraction
//! does.

use exarch_core::ExtractionOptions;
use exarch_core::NoopProgress;
use exarch_core::SecurityConfig;
use exarch_core::formats::ArchiveFormat;
use exarch_core::formats::TarArchive;
use std::io::Cursor;
use tempfile::TempDir;

// Only used by `two_hop_symlink_chain_is_rejected`, which is `#[cfg(unix)]`.
#[cfg(unix)]
use exarch_core::ArchiveError;
#[cfg(unix)]
use std::assert_matches;

/// Build the two-hop symlink escape TAR in memory.
fn build_two_hop_chain_tar() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    // Entry 1: directory a/b/c/
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_size(0);
    header.set_mode(0o755);
    header.set_cksum();
    builder
        .append_data(&mut header, "a/b/c/", &[] as &[u8])
        .expect("append dir");

    // Entry 2: symlink a/b/c/up -> ../..
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    header.set_mode(0o777);
    header.set_cksum();
    builder
        .append_link(&mut header, "a/b/c/up", "../..")
        .expect("append first hop symlink");

    // Entry 3: symlink a/b/escape -> c/up/../..
    //
    // String normalization: dest/a/b/c/up/../.. -> dest/a/b (within dest --
    // PASS without fix).
    //
    // On disk: c/up resolves to ../../.. from dest/a/b, which is outside
    // dest.
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    header.set_mode(0o777);
    header.set_cksum();
    builder
        .append_link(&mut header, "a/b/escape", "c/up/../..")
        .expect("append second hop symlink");

    // Entry 4: hardlink exfil -> a/b/escape/../../etc/passwd
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Link);
    header.set_size(0);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_link(&mut header, "exfil", "a/b/escape/../../etc/passwd")
        .expect("append hardlink");

    builder.into_inner().expect("finish tar builder")
}

/// The second symlink in the chain must be rejected when `allow-symlinks` is
/// enabled. The archive should never extract the escape symlink to disk.
#[test]
#[cfg(unix)]
fn two_hop_symlink_chain_is_rejected() {
    let dest = TempDir::new().expect("temp dir");
    let config = SecurityConfig::default()
        .with_allow_symlinks(true)
        .with_allow_hardlinks(true)
        .validate()
        .expect("valid config");

    let data = build_two_hop_chain_tar();
    let cursor = Cursor::new(data);
    let mut archive = TarArchive::new(cursor);

    let result = archive.extract(
        dest.path(),
        &config,
        &ExtractionOptions::default(),
        &mut NoopProgress,
    );

    // Extraction must fail -- the escape symlink or hardlink must be rejected.
    assert!(
        result.is_err(),
        "two-hop symlink chain must be rejected, but extraction succeeded"
    );

    // Extraction failures surface as `PartialExtraction { source, report }`,
    // wrapping the triggering error. The source must be a symlink or
    // hardlink escape, not an unrelated I/O error.
    let err = result.unwrap_err();
    let source = match &err {
        ArchiveError::PartialExtraction { source, .. } => source.as_ref(),
        other => other,
    };
    assert_matches!(
        source,
        ArchiveError::SymlinkEscape { .. } | ArchiveError::HardlinkEscape { .. },
        "expected SymlinkEscape or HardlinkEscape, got: {err:?}"
    );

    // The escape symlink must NOT have been written to disk.
    assert!(
        !dest.path().join("a/b/escape").exists(),
        "escape symlink must not be written to disk"
    );
}

/// With symlinks disabled (default), the archive is rejected at the first
/// symlink entry -- the two-hop chain is never attempted.
#[test]
fn two_hop_chain_rejected_when_symlinks_disabled() {
    let dest = TempDir::new().expect("temp dir");
    let config = SecurityConfig::default().validate().expect("valid config"); // symlinks = false

    let data = build_two_hop_chain_tar();
    let cursor = Cursor::new(data);
    let mut archive = TarArchive::new(cursor);

    let result = archive.extract(
        dest.path(),
        &config,
        &ExtractionOptions::default(),
        &mut NoopProgress,
    );
    assert!(result.is_err(), "should be rejected with symlinks disabled");
}
