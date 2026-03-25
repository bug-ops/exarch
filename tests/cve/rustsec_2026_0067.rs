//! Regression test for RUSTSEC-2026-0067.
//!
//! `tar 0.4.44` `unpack_in` followed symlinks when applying permissions
//! (`chmod`), allowing an attacker to change permissions on arbitrary
//! directories outside the extraction root via a crafted symlink entry.
//! Fixed in `tar 0.4.45`.
//!
//! This test verifies that:
//! 1. Normal extraction with symlinks disabled works correctly.
//! 2. A symlink entry pointing outside the extraction root is rejected by
//!    exarch's security layer before reaching `tar::unpack_in`.

use exarch_core::formats::TarArchive;
use exarch_core::formats::traits::ArchiveFormat;
use exarch_core::SecurityConfig;
use std::io::Cursor;
use tempfile::TempDir;

/// Build a TAR archive with a symlink that points outside the extraction root.
///
/// Attack vector: attacker creates `escape -> /tmp` inside the archive, then
/// a directory entry `escape/evil/` which would `chmod` `/tmp/evil/` (the
/// real directory) — affecting a path outside the extraction root.
fn build_symlink_escape_tar() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    // Entry 1: symlink "escape" -> "/tmp" (absolute target, escapes root)
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    header.set_mode(0o777);
    header.set_cksum();
    builder
        .append_link(&mut header, "escape", "/tmp")
        .expect("failed to append symlink");

    // Entry 2: directory "escape/evil/" — with symlinks followed, this would
    // be outside the extraction root.
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_size(0);
    header.set_mode(0o755);
    header.set_cksum();
    builder
        .append_data(&mut header, "escape/evil/", &[] as &[u8])
        .expect("failed to append dir");

    builder.into_inner().expect("failed to finish builder")
}

#[test]
fn test_rustsec_2026_0067_symlink_escape_rejected() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let config = SecurityConfig::default();
    // Symlinks disabled by default — escape link must be rejected.

    let tar_data = build_symlink_escape_tar();
    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = ArchiveFormat::extract(&mut archive, temp.path(), &config);

    // Extraction must either fail (SymlinkEscape) or skip the symlink entry.
    // The extraction root must not contain a symlink pointing outside.
    if result.is_ok() {
        let escape_link = temp.path().join("escape");
        assert!(
            !escape_link.exists(),
            "symlink 'escape' must not be extracted when symlinks are disabled"
        );
    } else {
        let err = result.expect_err("already checked");
        // Any security error variant is acceptable — the key is that the
        // archive did not silently escape the root.
        let _ = err;
    }
}

#[test]
fn test_rustsec_2026_0067_normal_extraction_unaffected() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let config = SecurityConfig::default();

    // Build a safe archive with only regular files — must extract correctly.
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(5);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "hello.txt", &b"hello"[..])
        .expect("failed to append file");
    let tar_data = builder.into_inner().expect("failed to finish builder");

    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = ArchiveFormat::extract(&mut archive, temp.path(), &config);
    assert!(result.is_ok(), "normal extraction must succeed: {result:?}");
    assert!(
        temp.path().join("hello.txt").exists(),
        "extracted file must be present"
    );
}
