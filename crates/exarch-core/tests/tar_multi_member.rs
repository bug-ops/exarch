//! Concatenated gzip members, bzip2 streams and xz streams are read in full
//! (#659).

#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(clippy::disallowed_methods)]

use std::assert_matches;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::DecompressionBudget;
use exarch_core::IntegrityCheck;
use exarch_core::IntegrityStatus;
use exarch_core::IssueCategory;
use exarch_core::QuotaResource;
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
    let mut enc = liblzma::write::XzEncoder::new(Vec::new(), 1);
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

        assert_matches!(&err, ArchiveError::PathTraversal { path } if path.ends_with("escape.txt"),
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
                .any(|i| i.category() == IssueCategory::CorruptData),
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

        let per_file = SecurityConfig::default().with_max_file_size(exarch_core::non_zero!(1024));
        let total = SecurityConfig::default().with_max_total_size(exarch_core::non_zero!(100_000));
        for config in [per_file, total] {
            let out = TempDir::new().unwrap();
            let err = extract_archive(&archive, out.path(), &config).unwrap_err();
            let source = match err {
                ArchiveError::PartialExtraction(partial) => partial.into_parts().0,
                other => other,
            };
            assert_matches!(source, ArchiveError::QuotaExceeded { .. }, "{name}");
        }
    }
}

fn with_base(base: u64) -> SecurityConfig {
    let base = std::num::NonZeroU64::new(base).unwrap();
    SecurityConfig::default().with_compressed_member_allowance(base)
}

/// The tar stream cut into `chunk`-byte compressed members.
fn chunked_members(tar: &[u8], chunk: usize, encode: Encode) -> Vec<u8> {
    tar.chunks(chunk).flat_map(encode).collect()
}

fn assert_member_cap(err: ArchiveError, members: u64, allowance: u64, label: &str) {
    let source = match err {
        ArchiveError::PartialExtraction(partial) => partial.into_parts().0,
        other => other,
    };
    assert_matches!(
        source,
        ArchiveError::QuotaExceeded {
            resource: QuotaResource::CompressedMembers { members: m, allowance: a }
        } if m == members && a == allowance,
        "{label}"
    );
}

#[test]
fn empty_members_after_the_end_marker_stop_at_the_base_allowance() {
    for (name, encode) in [("a.tar.gz", gzip as Encode), ("a.tar.bz2", bzip2)] {
        for (empty, refused) in [(4usize, false), (5, true)] {
            let temp = TempDir::new().unwrap();
            let mut bytes = encode(&tar_stream(&["one.txt"]));
            for _ in 0..empty {
                bytes.extend_from_slice(&encode(b""));
            }
            let archive = write(&temp, name, &bytes);
            let config = with_base(5);
            let label = format!("{name} +{empty} empty");
            let out = TempDir::new().unwrap();
            let listed = list_archive(&archive, &config);
            let extracted = extract_archive(&archive, out.path(), &config);
            let verified = verify_archive_with_options(&archive, &config, &integrity_options());
            if refused {
                assert_member_cap(listed.unwrap_err(), 6, 5, &label);
                assert_member_cap(extracted.unwrap_err(), 6, 5, &label);
                let report = verified.expect(&label);
                assert!(
                    report
                        .issues()
                        .iter()
                        .any(|i| i.category() == IssueCategory::QuotaExceeded
                            && i.message().contains("compressed members (6 > allowance 5")),
                    "{label}"
                );
            } else {
                listed.expect(&label);
                extracted.expect(&label);
                verified.expect(&label);
            }
        }
    }
}

#[test]
fn many_members_before_the_end_marker_are_refused_too() {
    for (name, encode) in BLOCK_CODECS.iter().take(2) {
        let temp = TempDir::new().unwrap();
        let names: Vec<String> = (0..8).map(|i| format!("f{i}.txt")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let archive = write(&temp, name, &split_members(&refs, *encode));
        let err = list_archive(&archive, &with_base(3)).unwrap_err();
        assert_member_cap(err, 4, 3, name);
    }
}

#[test]
fn a_writer_flushing_every_16_kib_passes_at_any_size() {
    let tar = single_entry_stream("big.bin", &vec![7u8; 640 * 1024]);
    for (name, encode) in [("a.tar.gz", gzip as Encode), ("a.tar.bz2", bzip2)] {
        let temp = TempDir::new().unwrap();
        let archive = write(&temp, name, &chunked_members(&tar, 16 * 1024, encode));
        let config = with_base(3);
        let out = TempDir::new().unwrap();
        list_archive(&archive, &config).expect(name);
        extract_archive(&archive, out.path(), &config).expect(name);
        verify_archive(&archive, &config).expect(name);
    }
}

#[test]
fn a_writer_flushing_every_8_kib_runs_into_the_allowance() {
    let tar = single_entry_stream("big.bin", &vec![7u8; 640 * 1024]);
    let temp = TempDir::new().unwrap();
    let archive = write(&temp, "a.tar.gz", &chunked_members(&tar, 8 * 1024, gzip));
    let err = list_archive(&archive, &with_base(3)).unwrap_err();
    assert_member_cap(err, 6, 5, "8 KiB members");
    list_archive(&archive, &with_base(100)).unwrap();
}

#[test]
fn the_largest_base_admits_every_member_without_overflow() {
    for (name, encode) in [("a.tar.gz", gzip as Encode), ("a.tar.bz2", bzip2)] {
        let temp = TempDir::new().unwrap();
        let mut bytes = encode(&tar_stream(&["one.txt"]));
        for _ in 0..50 {
            bytes.extend_from_slice(&encode(b""));
        }
        let archive = write(&temp, name, &bytes);
        list_archive(&archive, &with_base(u64::MAX)).expect(name);
    }
}

#[test]
fn xz_and_zstd_are_not_governed_by_the_member_allowance() {
    for (name, encode) in [("a.tar.xz", xz as Encode), ("a.tar.zst", zstd)] {
        let temp = TempDir::new().unwrap();
        let names: Vec<String> = (0..8).map(|i| format!("f{i}.txt")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let archive = write(&temp, name, &split_members(&refs, encode));
        assert_eq!(
            list_archive(&archive, &with_base(1))
                .unwrap()
                .entries()
                .len(),
            8
        );
    }
}
