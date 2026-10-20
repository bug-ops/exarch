//! Concatenated gzip members, bzip2 streams and xz streams are read in full
//! (#659).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::assert_matches;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::DecompressionBudget;
use exarch_core::IntegrityCheck;
use exarch_core::IntegrityStatus;
use exarch_core::IssueCategory;
use exarch_core::SecurityConfig;
use exarch_core::VerificationOptions;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use exarch_core::verify_archive_with_options;
use tempfile::TempDir;

const BLOCK: usize = 512;

type Encode = fn(&[u8]) -> Vec<u8>;

fn append(builder: &mut tar::Builder<Vec<u8>>, name: &str, data: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
    header.set_cksum();
    builder.append(&header, data).unwrap();
}

/// Tar stream with one entry per name; each entry occupies two blocks.
fn tar_stream(names: &[&str]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for name in names {
        append(&mut builder, name, b"payload");
    }
    builder.into_inner().unwrap()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn bzip2(data: &[u8]) -> Vec<u8> {
    let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn xz(data: &[u8]) -> Vec<u8> {
    let mut enc = xz2::write::XzEncoder::new(Vec::new(), 1);
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn zstd(data: &[u8]) -> Vec<u8> {
    zstd::encode_all(data, 1).unwrap()
}

/// One compressed member per entry; the end marker lands in the last member.
fn split_members(names: &[&str], encode: Encode) -> Vec<u8> {
    let stream = tar_stream(names);
    let mut out = Vec::new();
    for chunk in stream.chunks(2 * BLOCK) {
        out.extend_from_slice(&encode(chunk));
    }
    out
}

fn write(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn listed(path: &Path) -> Vec<String> {
    list_archive(path, &SecurityConfig::default())
        .unwrap()
        .entries()
        .iter()
        .map(|e| e.path.to_string_lossy().into_owned())
        .collect()
}

const CODECS: [(&str, Encode); 4] = [
    ("a.tar.gz", gzip),
    ("a.tar.bz2", bzip2),
    ("a.tar.xz", xz),
    ("a.tar.zst", zstd),
];

#[test]
fn list_and_extract_see_entries_of_every_member() {
    for (name, encode) in CODECS {
        let temp = TempDir::new().unwrap();
        let archive = write(
            &temp,
            name,
            &split_members(&["one.txt", "two.txt", "three.txt"], encode),
        );

        assert_eq!(
            listed(&archive),
            ["one.txt", "two.txt", "three.txt"],
            "{name}"
        );

        let out = TempDir::new().unwrap();
        extract_archive(&archive, out.path(), &SecurityConfig::default()).unwrap();
        for file in ["one.txt", "two.txt", "three.txt"] {
            assert!(out.path().join(file).is_file(), "{name} {file}");
        }
    }
}

#[test]
fn verify_reports_traversal_hidden_in_a_later_member() {
    for (name, encode) in CODECS {
        let temp = TempDir::new().unwrap();
        let archive = write(
            &temp,
            name,
            &split_members(&["ok.txt", "../escape.txt"], encode),
        );

        let err = verify_archive(&archive, &SecurityConfig::default()).unwrap_err();

        assert!(
            matches!(&err, ArchiveError::PathTraversal { path } if path.ends_with("escape.txt")),
            "{name}: {err:?}"
        );
    }
}

fn single_entry_stream(name: &str, data: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    append(&mut builder, name, data);
    builder.into_inner().unwrap()
}

fn integrity_options() -> VerificationOptions {
    VerificationOptions::default()
        .with_integrity(IntegrityCheck::DecodeToEof(DecompressionBudget::DEFAULT))
}

const BLOCK_CODECS: [(&str, Encode); 3] =
    [("a.tar.gz", gzip), ("a.tar.bz2", bzip2), ("a.tar.xz", xz)];

#[test]
fn zero_padding_after_last_member_is_accepted() {
    for (name, encode) in BLOCK_CODECS {
        let temp = TempDir::new().unwrap();
        let mut bytes = split_members(&["one.txt", "two.txt"], encode);
        bytes.extend_from_slice(&[0u8; 1024]);
        let archive = write(&temp, name, &bytes);

        assert_eq!(listed(&archive), ["one.txt", "two.txt"], "{name}");
        let report =
            verify_archive_with_options(&archive, &SecurityConfig::default(), &integrity_options())
                .unwrap();
        assert_eq!(report.integrity_status(), IntegrityStatus::Pass, "{name}");
    }
}

#[test]
fn trailing_garbage_after_last_member_fails_integrity_check() {
    for (name, encode) in BLOCK_CODECS {
        let temp = TempDir::new().unwrap();
        let mut bytes = split_members(&["one.txt", "two.txt"], encode);
        bytes.extend_from_slice(b"NOT-A-MEMBER");
        let archive = write(&temp, name, &bytes);

        let report =
            verify_archive_with_options(&archive, &SecurityConfig::default(), &integrity_options())
                .unwrap();

        assert_eq!(report.integrity_status(), IntegrityStatus::Fail, "{name}");
        assert!(
            report
                .issues()
                .iter()
                .any(|i| i.category == IssueCategory::CorruptData),
            "{name}"
        );
    }
}

#[test]
fn empty_and_all_zero_files_are_not_archives() {
    for (name, _) in BLOCK_CODECS {
        for bytes in [Vec::new(), vec![0u8; 1024]] {
            let temp = TempDir::new().unwrap();
            let archive = write(&temp, name, &bytes);

            let err = list_archive(&archive, &SecurityConfig::default()).unwrap_err();

            assert_matches!(err, ArchiveError::InvalidArchive(_), "{name}: {err:?}");
        }
    }
}

#[test]
fn quotas_span_every_member() {
    for (name, encode) in BLOCK_CODECS {
        let temp = TempDir::new().unwrap();
        let mut first = single_entry_stream("small.txt", b"x");
        first.truncate(2 * BLOCK);
        let mut bytes = encode(&first);
        bytes.extend_from_slice(&encode(&single_entry_stream(
            "big.bin",
            &vec![7u8; 200_000],
        )));
        let archive = write(&temp, name, &bytes);

        let per_file = SecurityConfig::default().with_max_file_size(1024);
        let total = SecurityConfig::default().with_max_total_size(100_000);
        for config in [per_file, total] {
            let out = TempDir::new().unwrap();
            let err = extract_archive(&archive, out.path(), &config).unwrap_err();
            let source = match err {
                ArchiveError::PartialExtraction { source, .. } => *source,
                other => other,
            };
            assert_matches!(source, ArchiveError::QuotaExceeded { .. }, "{name}");
        }
    }
}
