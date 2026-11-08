//! A 7z header whose sub-stream count differs from its number of streamed
//! files is refused when the archive is opened (#769): the sizes of every file
//! after a directory that owns a sub-stream would otherwise shift onto the
//! wrong entry, and a size-sum check cannot see a shift made of zero-size
//! sub-streams.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

mod common;

use std::assert_matches;
use std::path::PathBuf;

use common::RawEntry;
use common::solid_copy_7z;
use exarch_core::ArchiveError;
use exarch_core::DecompressionBudget;
use exarch_core::IntegrityCheck;
use exarch_core::Malformation;
use exarch_core::SecurityConfig;
use exarch_core::SolidArchives;
use exarch_core::SolidLimits;
use exarch_core::VerificationOptions;
use exarch_core::VerifyRequest;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use tempfile::TempDir;

fn solid_config() -> SecurityConfig {
    SecurityConfig::default().with_solid_archives(SolidArchives::Allow(SolidLimits::DEFAULT))
}

fn write(dir: &TempDir, entries: &[RawEntry<'_>]) -> PathBuf {
    let path = dir.path().join("shape.7z");
    std::fs::write(&path, solid_copy_7z(entries)).unwrap();
    path
}

fn assert_refused_at_open(err: &ArchiveError) {
    assert_matches!(
        err,
        ArchiveError::InvalidArchive(Malformation::SevenZHeaderUnreadable { .. }),
        "{err:?}"
    );
}

fn shapes() -> Vec<(&'static str, Vec<RawEntry<'static>>)> {
    vec![
        (
            "directory between payloads",
            vec![
                RawEntry::File("a.txt", b"AAAA"),
                RawEntry::DirWithSubStream("d"),
                RawEntry::File("b.txt", b"BBBB"),
            ],
        ),
        (
            "directory first",
            vec![
                RawEntry::DirWithSubStream("d"),
                RawEntry::File("a.txt", b"AAAA"),
                RawEntry::File("b.txt", b"BBBB"),
            ],
        ),
        (
            "two consecutive directories",
            vec![
                RawEntry::File("a.txt", b"AAAA"),
                RawEntry::DirWithSubStream("d1"),
                RawEntry::DirWithSubStream("d2"),
                RawEntry::File("b.txt", b"BBBB"),
            ],
        ),
        (
            "sizes sum to the block size while the files would shift",
            vec![
                RawEntry::File("a.txt", b"AAA"),
                RawEntry::DirWithSubStream("d"),
                RawEntry::File("b.txt", b"BBBBB"),
            ],
        ),
        (
            "directory last",
            vec![
                RawEntry::File("a.txt", b"AAAA"),
                RawEntry::File("b.txt", b"BBBB"),
                RawEntry::DirWithSubStream("d"),
            ],
        ),
    ]
}

#[test]
fn list_refuses_a_directory_with_a_sub_stream() {
    for (_, entries) in shapes() {
        let dir = TempDir::new().unwrap();
        let err = list_archive(write(&dir, &entries), &solid_config()).unwrap_err();
        assert_refused_at_open(&err);
    }
}

#[test]
fn verify_with_integrity_refuses_a_directory_with_a_sub_stream() {
    for (_, entries) in shapes() {
        let dir = TempDir::new().unwrap();
        let path = write(&dir, &entries);
        let options = VerificationOptions::default().with_integrity(IntegrityCheck::DecodeToEof(
            DecompressionBudget::try_from_bytes(1 << 20).unwrap(),
        ));
        let err = VerifyRequest::new(&solid_config())
            .with_options(options)
            .verify(&path)
            .unwrap_err();
        assert_refused_at_open(&err);
    }
}

#[test]
fn extract_refuses_a_directory_with_a_sub_stream_before_any_write() {
    for (label, entries) in shapes() {
        let dir = TempDir::new().unwrap();
        let path = write(&dir, &entries);
        let out = TempDir::new().unwrap();
        let err = extract_archive(&path, out.path(), &solid_config()).unwrap_err();
        assert_refused_at_open(&err);
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0, "{label}");
    }
}

#[test]
fn the_same_layout_without_the_sub_stream_extracts() {
    let dir = TempDir::new().unwrap();
    let path = write(
        &dir,
        &[
            RawEntry::File("a.txt", b"AAAA"),
            RawEntry::Dir("d"),
            RawEntry::File("b.txt", b"BBBB"),
        ],
    );
    let out = TempDir::new().unwrap();
    extract_archive(&path, out.path(), &solid_config()).unwrap();
    assert_eq!(std::fs::read(out.path().join("b.txt")).unwrap(), b"BBBB");
}
