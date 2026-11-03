//! A compressed TAR entry that is refused by quota or skipped by the extension
//! allowlist is not decoded for free: refusal stops at the header, and a
//! skipped entry is bounded by the input that produced it (issue #863).

#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(clippy::disallowed_methods)]

mod sink_support;

use std::assert_matches;
use std::io::Cursor;
use std::io::Read;
use std::io::Write as _;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::ExtractionOptions;
use exarch_core::ListOptions;
use exarch_core::MemoryLimit;
use exarch_core::MemorySink;
use exarch_core::SecurityConfig;
use exarch_core::SinkOptions;
use exarch_core::VerificationOptions;
use exarch_core::ZipBombScope;
use exarch_core::extract_archive_with_options;
use exarch_core::extract_to_sink;
use exarch_core::formats::CompressionCodec;
use exarch_core::formats::TarArchive;
use exarch_core::formats::traits::ArchiveFormat;
use exarch_core::list_reader;
use exarch_core::verify_reader;
use flate2::Compression;
use flate2::write::GzEncoder;
use tempfile::TempDir;

const MIB: usize = 1024 * 1024;

struct Counting<R> {
    inner: R,
    count: Arc<AtomicU64>,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

fn counted(bytes: Vec<u8>) -> (Counting<Cursor<Vec<u8>>>, Arc<AtomicU64>) {
    let count = Arc::new(AtomicU64::new(0));
    (
        Counting {
            inner: Cursor::new(bytes),
            count: Arc::clone(&count),
        },
        count,
    )
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn zeros_tar(name: &str, len: usize) -> Vec<u8> {
    sink_support::tar_archive(&[sink_support::tar_file(name, &vec![0; len]), {
        sink_support::tar_file("after.txt", b"hello")
    }])
}

fn root(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction { source, .. } => root(source),
        other => other,
    }
}

fn tight_config() -> SecurityConfig {
    SecurityConfig::default()
        .with_max_file_size(MIB as u64)
        .with_allowed_extensions(vec!["txt".into()])
}

fn assert_stopped_early(consumed: &AtomicU64, compressed_len: usize) {
    let consumed = usize::try_from(consumed.load(Ordering::Relaxed)).unwrap();
    assert!(
        consumed < compressed_len / 2,
        "read {consumed} of {compressed_len} compressed bytes"
    );
}

#[test]
fn list_refuses_an_over_quota_entry_without_decoding_it() {
    let gz = gzip(&zeros_tar("big.bin", 60 * MIB));
    let (reader, consumed) = counted(gz.clone());

    let error = list_reader(
        ArchiveReader::tar(reader, Some(CompressionCodec::Gzip)),
        &SecurityConfig::default(),
        &ListOptions::default(),
    )
    .unwrap_err();

    assert_matches!(root(&error), ArchiveError::QuotaExceeded { .. });
    assert_stopped_early(&consumed, gz.len());
}

#[test]
fn verify_refuses_an_over_quota_entry_without_decoding_it() {
    let gz = gzip(&zeros_tar("big.bin", 60 * MIB));
    let (reader, consumed) = counted(gz.clone());

    let report = verify_reader(
        ArchiveReader::tar(reader, Some(CompressionCodec::Gzip)),
        &SecurityConfig::default().with_max_total_size(MIB as u64),
        &VerificationOptions::default(),
    );

    assert!(report.is_err() || report.unwrap().status() != exarch_core::VerificationStatus::Pass);
    assert_stopped_early(&consumed, gz.len());
}

#[test]
fn a_skipped_entry_that_out_decodes_its_input_is_refused_early() {
    let gz = gzip(&zeros_tar("big.bin", 40 * MIB));
    let (reader, consumed) = counted(gz.clone());
    let mut sink = MemorySink::new(MemoryLimit::DEFAULT);

    let error = extract_to_sink(
        ArchiveReader::tar(reader, Some(CompressionCodec::Gzip)),
        &mut sink,
        &tight_config(),
        &SinkOptions::default(),
    )
    .unwrap_err();

    let ArchiveError::ZipBomb(details) = root(&error) else {
        panic!("expected a zip bomb, got {error:?}");
    };
    assert_eq!(details.scope(), ZipBombScope::SkippedEntries);
    assert_stopped_early(&consumed, gz.len());
}

#[test]
fn the_same_bomb_is_refused_on_a_path_and_an_existing_destination() {
    let work = TempDir::new().unwrap();
    let archive = work.path().join("bomb.tar.gz");
    std::fs::write(&archive, gzip(&zeros_tar("big.bin", 40 * MIB))).unwrap();
    let existing = TempDir::new().unwrap();
    std::fs::write(existing.path().join("keep"), b"x").unwrap();
    let fresh = work.path().join("fresh");

    for dest in [existing.path(), fresh.as_path()] {
        let error = extract_archive_with_options(
            &archive,
            dest,
            &tight_config(),
            &ExtractionOptions::default(),
        )
        .unwrap_err();
        assert_matches!(
            root(&error),
            ArchiveError::ZipBomb(d) if d.scope() == ZipBombScope::SkippedEntries
        );
    }
}

#[test]
fn filtering_never_refuses_what_extracting_whole_would_accept() {
    // 40 MiB of zeros compresses past the 100x ratio but is within the default
    // per-file limit, so both runs succeed.
    let work = TempDir::new().unwrap();
    let archive = work.path().join("a.tar.gz");
    std::fs::write(&archive, gzip(&zeros_tar("x.img", 40 * MIB))).unwrap();
    let default = SecurityConfig::default();
    let filtered = SecurityConfig::default().with_allowed_extensions(vec!["txt".into()]);

    for (name, config) in [("whole", &default), ("filtered", &filtered)] {
        let existing = TempDir::new().unwrap();
        std::fs::write(existing.path().join("keep"), b"x").unwrap();
        extract_archive_with_options(
            &archive,
            existing.path(),
            config,
            &ExtractionOptions::default(),
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[test]
fn plain_tar_with_skipped_data_passes_at_any_size() {
    let work = TempDir::new().unwrap();
    let archive = work.path().join("a.tar");
    std::fs::write(&archive, zeros_tar("big.bin", 40 * MIB)).unwrap();
    let dest = work.path().join("out");

    let report = extract_archive_with_options(
        &archive,
        &dest,
        &tight_config(),
        &ExtractionOptions::default(),
    )
    .unwrap();

    assert_eq!(report.files_extracted, 1);
    assert_eq!(report.files_skipped, 1);
}

#[test]
fn a_caller_decoded_stream_is_not_bounded_by_ratio() {
    let gz = gzip(&zeros_tar("big.bin", 40 * MIB));
    let decoder = flate2::read::GzDecoder::new(Cursor::new(gz));
    let work = TempDir::new().unwrap();

    let config = tight_config().validate().unwrap();
    let report = TarArchive::new(decoder)
        .extract(
            &work.path().join("out"),
            &config,
            &ExtractionOptions::default(),
            &mut exarch_core::NoopProgress,
        )
        .unwrap();

    assert_eq!(report.files_skipped, 1);
}
