//! Regression test for GHSA-2367-c296-3mp2 variant (issue #130).
//!
//! When a TAR archive contains a hardlink entry followed by a plain-file entry
//! with the same name as the link, the two-pass extraction model defers hardlink
//! creation until after all plain files are written. Before the fix, `hard_link`
//! created a shared OS inode, meaning any subsequent write to `link_path` would
//! silently corrupt `target_path`.
//!
//! The fix replaces `fs::hard_link` with `fs::copy` so each extracted file has
//! its own independent inode.

use exarch_core::SecurityConfig;
use exarch_core::formats::TarArchive;
use exarch_core::formats::traits::ArchiveFormat;
use std::io::Cursor;
use tempfile::TempDir;

/// Build adversarial TAR: legit.txt, hardlink to legit.txt, plain "ATTACK" file
/// reusing the hardlink name. In the two-pass model:
///   First pass:  legit.txt extracted; hardlink deferred; link_to_legit (plain) extracted.
///   Second pass: hardlink created via fs::copy — independent inode, legit.txt untouched.
fn build_hardlink_inode_corruption_tar() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    // Entry 1: legitimate file
    let content = b"legit\n";
    let mut header = tar::Header::new_gnu();
    header.set_size(content.len() as u64);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "legit.txt", content.as_ref())
        .expect("append legit.txt");

    // Entry 2: hardlink to legit.txt
    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Link);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_link(&mut header, "link_to_legit", "legit.txt")
        .expect("append hardlink");

    // Entry 3: plain file with the same name as the hardlink — simulates an
    // attacker-controlled overwrite that would corrupt legit.txt via shared inode.
    let attack = b"ATTACK\n";
    let mut header = tar::Header::new_gnu();
    header.set_size(attack.len() as u64);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "link_to_legit", attack.as_ref())
        .expect("append attack file");

    builder.into_inner().expect("finish tar builder")
}

/// After extraction, `legit.txt` must contain the original content regardless
/// of what happens to `link_to_legit`.
#[test]
fn hardlink_does_not_corrupt_target() {
    let dest = TempDir::new().expect("temp dir");
    let mut config = SecurityConfig::default();
    config.allowed.hardlinks = true;

    let data = build_hardlink_inode_corruption_tar();
    let cursor = Cursor::new(data);
    let mut archive = TarArchive::new(cursor);

    // Extraction must succeed (or at worst fail without corrupting legit.txt on disk)
    let _ = archive.extract(dest.path(), &config);

    let legit = std::fs::read_to_string(dest.path().join("legit.txt"))
        .expect("legit.txt must exist after extraction");
    assert_eq!(
        legit, "legit\n",
        "legit.txt was corrupted via hardlink inode sharing"
    );
}

/// On Unix, after extraction `legit.txt` and `link_to_legit` must have different
/// inodes — content-copy must not create a shared OS hardlink.
#[test]
#[cfg(unix)]
fn hardlink_produces_independent_inode() {
    use std::os::unix::fs::MetadataExt;

    let dest = TempDir::new().expect("temp dir");
    let mut config = SecurityConfig::default();
    config.allowed.hardlinks = true;

    // Use only two entries so the hardlink is created without a conflicting plain file.
    let mut builder = tar::Builder::new(Vec::new());

    let content = b"legit\n";
    let mut header = tar::Header::new_gnu();
    header.set_size(content.len() as u64);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "legit.txt", content.as_ref())
        .expect("append legit.txt");

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Link);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_link(&mut header, "link_to_legit", "legit.txt")
        .expect("append hardlink");

    let data = builder.into_inner().expect("finish tar builder");
    let cursor = Cursor::new(data);
    let mut archive = TarArchive::new(cursor);
    archive.extract(dest.path(), &config).expect("extraction must succeed");

    let meta_legit = std::fs::metadata(dest.path().join("legit.txt")).expect("legit.txt metadata");
    let meta_link =
        std::fs::metadata(dest.path().join("link_to_legit")).expect("link_to_legit metadata");

    assert_ne!(
        meta_legit.ino(),
        meta_link.ino(),
        "hardlink created a shared inode — content-copy was not applied"
    );
}
