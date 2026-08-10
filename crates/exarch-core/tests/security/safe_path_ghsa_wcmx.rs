//! End-to-end regression test for GHSA-wcmx-7f9h-5mv5: on case-insensitive
//! filesystems (macOS, Windows), `SafePath`'s containment check compared a
//! canonicalized parent directory against the destination root as a raw
//! string prefix, so a sibling of the destination root sharing a name prefix
//! (e.g. `dest` vs. `destevil`) was wrongly treated as contained within
//! `dest`.
//!
//! This drives the attack through a real, pre-existing on-disk symlink so
//! the containment check runs against an actually canonicalized path — the
//! same code path a crafted archive entry resolving through a symlinked
//! directory would take — rather than a synthetic `Path` value.

#![allow(clippy::unwrap_used)]

use exarch_core::ArchiveError;
use exarch_core::DestDir;
use exarch_core::SafePath;
use exarch_core::SecurityConfig;
use std::assert_matches;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
#[cfg(unix)]
fn ghsa_wcmx_sibling_reached_via_symlink_is_rejected() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().unwrap();

    // Destination root: <temp>/dest
    let dest_root = temp.path().join("dest");
    std::fs::create_dir(&dest_root).unwrap();
    let dest = DestDir::new(dest_root.clone()).unwrap();

    // Pre-existing sibling directory that shares `dest_root`'s name as a
    // string prefix but is NOT a subdirectory of it: <temp>/destevil.
    let sibling = temp.path().join("destevil");
    std::fs::create_dir(&sibling).unwrap();

    // A symlink inside `dest` resolving to the sibling, so the validated
    // entry's canonicalized parent is the sibling directory rather than
    // `dest_root` itself.
    let escape_link = dest_root.join("escape");
    symlink(&sibling, &escape_link).unwrap();

    let config = SecurityConfig::default().validate().unwrap();
    let entry_path = PathBuf::from("escape/secret.txt");

    let result = SafePath::validate(&entry_path, &dest, &config);

    assert_matches!(
        result,
        Err(ArchiveError::PathTraversal { .. }),
        "sibling directory reached via symlink and sharing a name prefix with \
         the destination root must be rejected, got: {result:?}"
    );
}
