//! Regression test for GHSA-qh76-45cr-8xrc / CVE-2026-61725: 7z Zip-Slip.
//!
//! `sevenz_rust2::decompress()` (the upstream convenience API) had no
//! traversal guard and was vulnerable to Zip-Slip; fixed upstream in
//! sevenz-rust2 0.21.1 (hasenbanck/sevenz-rust2 commit ef760b61).
//!
//! exarch-core does not use that vulnerable API: `SevenZArchive` calls
//! `ArchiveReader::for_each_entries` directly and routes every entry through
//! `EntryValidator`, which is the sole authority on path safety. This test
//! proves that a crafted `.7z` archive with a relative-traversal entry name
//! or an absolute-path entry name is rejected by `SevenZArchive::extract`
//! before any file is written, mirroring upstream's own PoC/regression test.
//! Both entries are caught by the Step-1 pre-validation pass that runs
//! before any entry is read; the separate extraction-time re-validation
//! layer (`process_entry_inner`'s defense-in-depth check) is exercised
//! directly by `test_process_entry_inner_rejects_traversal_independently`
//! in `crates/exarch-core/src/formats/sevenz.rs`.

#![allow(clippy::unwrap_used)]

use exarch_core::ArchiveError;
use exarch_core::ExtractionOptions;
use exarch_core::SecurityConfig;
use exarch_core::formats::SevenZArchive;
use exarch_core::formats::traits::ArchiveFormat;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use std::io::Cursor;
use tempfile::TempDir;

/// Builds a minimal in-memory `.7z` archive with a single entry of the given
/// raw name, bypassing any path sanitization the writer might otherwise
/// apply — attackers control raw archive bytes.
fn make_sevenz_archive(entry_name: &str, data: &[u8]) -> Vec<u8> {
    let mut buf = Cursor::new(Vec::<u8>::new());
    {
        let mut writer = ArchiveWriter::new(&mut buf).unwrap();
        writer
            .push_archive_entry(ArchiveEntry::new_file(entry_name), Some(data))
            .unwrap();
        writer.finish().unwrap();
    }
    buf.set_position(0);
    buf.into_inner()
}

#[test]
fn test_ghsa_qh76_sevenz_relative_traversal_rejected() {
    let root = TempDir::new().unwrap();
    let dest = root.path().join("dest");
    std::fs::create_dir_all(&dest).unwrap();

    let data = make_sevenz_archive("../../sevenz_pwned_relative", b"pwned");
    let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();

    let result = archive.extract(
        &dest,
        &SecurityConfig::default(),
        &ExtractionOptions::default(),
        &mut exarch_core::NoopProgress,
    );

    assert!(
        matches!(result, Err(ArchiveError::PathTraversal { .. })),
        "relative traversal entry must be rejected with PathTraversal, got: {result:?}"
    );

    assert!(
        std::fs::read_dir(&dest).unwrap().next().is_none(),
        "dest must remain empty after a rejected extraction"
    );
    assert!(
        !root.path().join("sevenz_pwned_relative").exists(),
        "traversal target must not be created outside dest"
    );
}

#[test]
fn test_ghsa_qh76_sevenz_absolute_path_rejected() {
    let root = TempDir::new().unwrap();
    let dest = root.path().join("dest");
    std::fs::create_dir_all(&dest).unwrap();

    let data = make_sevenz_archive("/sevenz_pwned_absolute", b"pwned");
    let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();

    let result = archive.extract(
        &dest,
        &SecurityConfig::default(),
        &ExtractionOptions::default(),
        &mut exarch_core::NoopProgress,
    );

    assert!(
        matches!(result, Err(ArchiveError::PathTraversal { .. })),
        "absolute path entry must be rejected with PathTraversal, got: {result:?}"
    );

    // Asserting non-existence of the literal absolute path would be a
    // non-hermetic check against the real filesystem root (and could even
    // be misleading if CI ran as root while this guard was regressed).
    // `dest` staying empty is the load-bearing proof that nothing was
    // written anywhere.
    assert!(
        std::fs::read_dir(&dest).unwrap().next().is_none(),
        "dest must remain empty after a rejected extraction"
    );
}
