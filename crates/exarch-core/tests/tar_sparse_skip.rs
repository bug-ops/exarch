//! Old GNU sparse entries under `TarSparsePolicy::Expand` that are listed,
//! verified or skipped rather than written (issue #1349): the work scales
//! with the archived bytes and never with the size of the holes, and a
//! skipped entry stays bounded by the input that produced it.

#![expect(clippy::disallowed_methods, reason = "test fixture setup")]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]

mod tar_sparse_support;

use std::io::Cursor;
use std::io::Write as _;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::CompressionCodec;
use exarch_core::DecompressionBudget;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::IntegrityCheck;
use exarch_core::Limit;
use exarch_core::ListOptions;
use exarch_core::ListRequest;
use exarch_core::MemoryLimit;
use exarch_core::MemorySink;
use exarch_core::SecurityConfig;
use exarch_core::SinkExtractRequest;
use exarch_core::SinkOptions;
use exarch_core::TarSparsePolicy;
use exarch_core::VerificationOptions;
use exarch_core::VerificationStatus;
use exarch_core::VerifyRequest;
use exarch_core::ZipBombScope;
use exarch_core::list_archive;
use flate2::Compression;
use flate2::write::GzEncoder;
use tar_sparse_support::Sparse;
use tar_sparse_support::filled;
use tar_sparse_support::regular;
use tar_sparse_support::tar_of;
use tempfile::TempDir;

const MIB: usize = 1024 * 1024;
const HOLE_4_TIB: u64 = 1 << 42;
const HOLE_4_GIB: u64 = 1 << 32;

/// Per-file limit of the tight configs.
const FILE_LIMIT: u64 = 2 * MIB as u64;

fn unbounded() -> SecurityConfig {
    SecurityConfig::default()
        .with_tar_sparse(TarSparsePolicy::Expand)
        .with_max_file_size(Limit::Unbounded)
        .with_max_total_size(Limit::Unbounded)
}

/// Quotas that a large sparse entry exceeds and a ratio that zeros exceed,
/// with only `.txt` extracted.
fn tight() -> SecurityConfig {
    SecurityConfig::default()
        .with_tar_sparse(TarSparsePolicy::Expand)
        .with_max_file_size(exarch_core::non_zero!(FILE_LIMIT))
        .with_max_compression_ratio(exarch_core::ratio_limit!(10.0))
        .try_add_allowed_extension("txt")
        .unwrap()
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

/// Bytes gzip cannot shrink (xorshift output).
fn incompressible(len: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

/// A sparse member with one data region of `data` at offset 0 and a hole up
/// to `realsize`, followed by a regular `after.txt`.
fn archive(name: &str, data: Vec<u8>, realsize: u64) -> Vec<u8> {
    tar_of(&[
        Sparse::well_formed(name, &[(0, data)], realsize).bytes(),
        regular("after.txt", b"hello"),
    ])
}

fn root(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction(partial) => root(partial.cause()),
        other => other,
    }
}

fn is_skip_bomb(error: &ArchiveError) -> bool {
    matches!(
        root(error),
        ArchiveError::ZipBomb(d) if d.scope() == ZipBombScope::SkippedEntries
    )
}

fn gzip_reader(tar: &[u8]) -> ArchiveReader<'static> {
    ArchiveReader::tar(Cursor::new(gzip(tar)), Some(CompressionCodec::Gzip))
}

fn decode_to_eof() -> VerificationOptions {
    VerificationOptions::default()
        .with_integrity(IntegrityCheck::DecodeToEof(DecompressionBudget::DEFAULT))
}

fn list_gz(tar: &[u8], config: &SecurityConfig) -> Result<Vec<(String, u64)>, ArchiveError> {
    let manifest = ListRequest::new(config)
        .with_options(ListOptions::default())
        .list_reader(gzip_reader(tar))?;
    Ok(manifest
        .entries()
        .iter()
        .map(|entry| (entry.path.display().to_string(), entry.kind.size()))
        .collect())
}

fn extract_gz_to_memory(tar: &[u8], config: &SecurityConfig) -> Result<(), ArchiveError> {
    let mut sink = MemorySink::new(MemoryLimit::DEFAULT);
    SinkExtractRequest::new(config)
        .with_options(SinkOptions::default())
        .extract(gzip_reader(tar), &mut sink)
        .map(drop)
}

#[test]
fn list_with_expand_of_a_huge_hole_scales_with_the_archived_bytes() {
    let tar = archive("hole.bin", filled(b'A', 512), HOLE_4_TIB);
    let expected = vec![
        ("hole.bin".to_owned(), HOLE_4_TIB),
        ("after.txt".to_owned(), 5),
    ];

    assert_eq!(list_gz(&tar, &unbounded()).unwrap(), expected);

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("a.tar");
    std::fs::write(&path, &tar).unwrap();
    let listed: Vec<_> = list_archive(&path, &unbounded())
        .unwrap()
        .entries()
        .iter()
        .map(|entry| (entry.path.display().to_string(), entry.kind.size()))
        .collect();
    assert_eq!(listed, expected);
}

#[test]
fn verify_with_expand_of_a_huge_hole_passes_without_generating_the_hole() {
    let tar = archive("hole.bin", filled(b'A', 512), HOLE_4_TIB);

    let report = VerifyRequest::new(&unbounded())
        .with_options(decode_to_eof())
        .verify_reader(gzip_reader(&tar))
        .unwrap();

    assert_eq!(report.status(), VerificationStatus::Pass, "{report:?}");
}

#[test]
fn verify_with_expand_of_a_sparse_entry_with_a_truncated_payload_fails() {
    let tar = archive("hole.bin", incompressible(8192), HOLE_4_TIB);
    // The header block and 1000 bytes of the 8192-byte region.
    let truncated = &tar[..512 + 1000];

    let error = VerifyRequest::new(&unbounded())
        .with_options(decode_to_eof())
        .verify_reader(ArchiveReader::tar(Cursor::new(truncated.to_vec()), None))
        .unwrap_err();

    assert!(
        matches!(root(&error), ArchiveError::InvalidArchive(_)),
        "{error:?}"
    );
}

#[test]
fn extract_with_expand_skips_a_metered_huge_hole_entry_by_its_archived_size() {
    let tar = archive("hole.img", incompressible(4096), HOLE_4_GIB);
    let config = SecurityConfig::default()
        .with_tar_sparse(TarSparsePolicy::Expand)
        .try_add_allowed_extension("txt")
        .unwrap();
    let work = TempDir::new().unwrap();
    let archive = work.path().join("a.tar.gz");
    std::fs::write(&archive, gzip(&tar)).unwrap();

    let out: PathBuf = work.path().join("out");
    let report = ExtractRequest::new(&config)
        .with_options(ExtractionOptions::default())
        .extract(&archive, &out)
        .unwrap();

    assert_eq!(report.files_extracted, 1);
    assert_eq!(report.files_skipped(), 1);
    assert_eq!(std::fs::read(out.join("after.txt")).unwrap(), b"hello");
    let listed = list_archive(&archive, &config).unwrap();
    let paths: Vec<_> = listed.entries().iter().map(|e| e.path.clone()).collect();
    assert_eq!(
        paths,
        [PathBuf::from("hole.img"), PathBuf::from("after.txt")]
    );
}

#[test]
fn list_with_expand_skips_a_metered_huge_hole_entry_by_its_archived_size() {
    let tar = archive("hole.img", incompressible(4096), HOLE_4_GIB);
    let config = SecurityConfig::default()
        .with_tar_sparse(TarSparsePolicy::Expand)
        .try_add_allowed_extension("txt")
        .unwrap();

    assert_eq!(
        list_gz(&tar, &config).unwrap(),
        vec![
            ("hole.img".to_owned(), HOLE_4_GIB),
            ("after.txt".to_owned(), 5)
        ]
    );
}

#[test]
fn extract_with_expand_refuses_a_skipped_sparse_payload_that_out_decodes_its_input() {
    let tar = archive("hole.img", vec![0; 8 * MIB], HOLE_4_GIB);

    let extracted = extract_gz_to_memory(&tar, &tight()).unwrap_err();
    assert!(is_skip_bomb(&extracted), "{extracted:?}");

    let listed = list_gz(&tar, &tight()).unwrap_err();
    assert!(is_skip_bomb(&listed), "{listed:?}");

    let zstd = zstd::encode_all(&tar[..], 1).unwrap();
    let error = ListRequest::new(&tight())
        .with_options(ListOptions::default())
        .list_reader(ArchiveReader::tar(
            Cursor::new(zstd),
            Some(CompressionCodec::Zstd),
        ))
        .unwrap_err();
    assert!(is_skip_bomb(&error), "zstd: {error:?}");
}

#[test]
fn list_with_expand_admits_the_same_sparse_payload_when_the_quotas_allow_it() {
    let tar = archive("hole.img", vec![0; 8 * MIB], MIB as u64 * 9);
    let config = tight()
        .with_max_file_size(exarch_core::non_zero!(16 * MIB as u64))
        .try_add_allowed_extension("img")
        .unwrap();

    assert_eq!(
        list_gz(&tar, &config).unwrap(),
        vec![
            ("hole.img".to_owned(), MIB as u64 * 9),
            ("after.txt".to_owned(), 5)
        ]
    );
}
