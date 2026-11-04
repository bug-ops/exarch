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
use exarch_core::DecompressionBudget;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::IntegrityCheck;
use exarch_core::ListOptions;
use exarch_core::ListRequest;
use exarch_core::MemoryLimit;
use exarch_core::MemorySink;
use exarch_core::SecurityConfig;
use exarch_core::SinkExtractRequest;
use exarch_core::SinkOptions;
use exarch_core::VerificationOptions;
use exarch_core::VerificationStatus;
use exarch_core::VerifyRequest;
use exarch_core::ZipBombScope;
use exarch_core::formats::CompressionCodec;
use exarch_core::formats::TarArchive;
use exarch_core::formats::traits::ArchiveFormat;
use flate2::Compression;
use flate2::write::GzEncoder;
use tempfile::TempDir;

const MIB: usize = 1024 * 1024;

/// Per-file limit of the tight configs; entries at or below it are within the
/// quota the skipped entry would have been charged.
const FILE_LIMIT: usize = 2 * MIB;

/// Ratio of the tight configs. Gzip at its fastest level packs zeros about
/// 100:1, far above it.
const RATIO: f64 = 10.0;

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

fn tar_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut members: Vec<Vec<u8>> = entries
        .iter()
        .map(|(name, data)| sink_support::tar_file(name, data))
        .collect();
    members.push(sink_support::tar_file("after.txt", b"hello"));
    sink_support::tar_archive(&members)
}

fn zeros_tar(name: &str, len: usize) -> Vec<u8> {
    tar_of(&[(name, &vec![0; len])])
}

fn root(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction(partial) => root(partial.cause()),
        other => other,
    }
}

fn tight_config() -> SecurityConfig {
    SecurityConfig::default()
        .with_max_file_size(exarch_core::non_zero!(FILE_LIMIT as u64))
        .with_max_compression_ratio(exarch_core::ratio_limit!(RATIO))
        .try_add_allowed_extension("txt")
        .unwrap()
}

/// Extracts a gzip-compressed `tar` into memory under `config`.
fn extract_gz(tar: &[u8], config: &SecurityConfig) -> Result<(), ArchiveError> {
    let mut sink = MemorySink::new(MemoryLimit::DEFAULT);
    SinkExtractRequest::new(config)
        .with_options(SinkOptions::default())
        .extract(
            ArchiveReader::tar(Cursor::new(gzip(tar)), Some(CompressionCodec::Gzip)),
            &mut sink,
        )
        .map(drop)
}

fn assert_stopped_early(consumed: &AtomicU64, compressed_len: usize) {
    let consumed = usize::try_from(consumed.load(Ordering::Relaxed)).unwrap();
    assert!(
        consumed < compressed_len / 2,
        "read {consumed} of {compressed_len} compressed bytes"
    );
}

fn is_skip_bomb(error: &ArchiveError) -> bool {
    matches!(
        root(error),
        ArchiveError::ZipBomb(d) if d.scope() == ZipBombScope::SkippedEntries
    )
}

#[test]
fn list_refuses_an_over_quota_entry_without_decoding_it() {
    let gz = gzip(&zeros_tar("big.bin", 8 * MIB));
    let (reader, consumed) = counted(gz.clone());

    let error = ListRequest::new(
        &SecurityConfig::default().with_max_file_size(exarch_core::non_zero!(MIB as u64)),
    )
    .with_options(ListOptions::default())
    .list_reader(ArchiveReader::tar(reader, Some(CompressionCodec::Gzip)))
    .unwrap_err();

    assert_matches!(root(&error), ArchiveError::QuotaExceeded { .. });
    assert_stopped_early(&consumed, gz.len());
}

#[test]
fn verify_refuses_an_over_quota_entry_without_decoding_it() {
    let gz = gzip(&zeros_tar("big.bin", 8 * MIB));
    let (reader, consumed) = counted(gz.clone());

    let error = VerifyRequest::new(
        &SecurityConfig::default().with_max_total_size(exarch_core::non_zero!(MIB as u64)),
    )
    .with_options(VerificationOptions::default())
    .verify_reader(ArchiveReader::tar(reader, Some(CompressionCodec::Gzip)))
    .unwrap_err();

    assert_matches!(root(&error), ArchiveError::QuotaExceeded { .. });
    assert_stopped_early(&consumed, gz.len());
}

#[test]
fn a_skipped_entry_that_out_decodes_its_input_is_refused_early() {
    let gz = gzip(&zeros_tar("big.bin", 8 * MIB));
    let (reader, consumed) = counted(gz.clone());
    let mut sink = MemorySink::new(MemoryLimit::DEFAULT);

    let error = SinkExtractRequest::new(&tight_config())
        .with_options(SinkOptions::default())
        .extract(
            ArchiveReader::tar(reader, Some(CompressionCodec::Gzip)),
            &mut sink,
        )
        .unwrap_err();

    assert!(is_skip_bomb(&error), "{error:?}");
    assert_stopped_early(&consumed, gz.len());
}

#[test]
fn the_same_bomb_is_refused_on_a_path_and_an_existing_destination() {
    let work = TempDir::new().unwrap();
    let archive = work.path().join("bomb.tar.gz");
    std::fs::write(&archive, gzip(&zeros_tar("big.bin", 8 * MIB))).unwrap();
    let existing = TempDir::new().unwrap();
    std::fs::write(existing.path().join("keep"), b"x").unwrap();
    let fresh = work.path().join("fresh");

    for dest in [existing.path(), fresh.as_path()] {
        let error = ExtractRequest::new(&tight_config())
            .with_options(ExtractionOptions::default())
            .extract(&archive, dest)
            .unwrap_err();
        assert!(is_skip_bomb(&error), "{error:?}");
    }
}

/// The skip bound never refuses what extracting the archive whole would
/// accept, and is monotone in both of its parts: the quota-equivalent bound
/// (per-file and cumulative size) and the ratio bound.
#[test]
fn the_skip_bound_is_monotone_around_both_of_its_parts() {
    let config = tight_config();
    let zeros = |len: usize| vec![0u8; len];

    // At and below the quota-equivalent bound a compressible entry is skipped
    // freely, although it is far above the ratio bound.
    for len in [MIB, FILE_LIMIT - 1, FILE_LIMIT] {
        let outcome = extract_gz(&zeros_tar("x.img", len), &config);
        assert!(
            outcome.is_ok(),
            "{len} bytes within the file limit: {outcome:?}"
        );
    }

    // One byte above it the ratio bound decides: compressible data trips it,
    // data at ratio one passes it, and so does data a ratio below the limit.
    let over = FILE_LIMIT + 1;
    let outcome = extract_gz(&zeros_tar("x.img", over), &config).unwrap_err();
    assert!(is_skip_bomb(&outcome), "{outcome:?}");
    let noise = incompressible(over);
    let outcome = extract_gz(&tar_of(&[("x.img", &noise)]), &config);
    assert!(
        outcome.is_ok(),
        "ratio one passes the ratio bound: {outcome:?}"
    );

    // The cumulative part: each entry is within the file limit, but together
    // they pass `max_total_size`, so the entry that crosses it falls to the
    // ratio bound.
    let total = (FILE_LIMIT + FILE_LIMIT / 2) as u64;
    let config = config.with_max_total_size(std::num::NonZeroU64::new(total).unwrap());
    let outcome = extract_gz(&tar_of(&[("a.img", &zeros(FILE_LIMIT))]), &config);
    assert!(
        outcome.is_ok(),
        "one entry stays within the total: {outcome:?}"
    );
    let two = tar_of(&[("a.img", &zeros(FILE_LIMIT)), ("b.img", &zeros(FILE_LIMIT))]);
    let outcome = extract_gz(&two, &config).unwrap_err();
    assert!(is_skip_bomb(&outcome), "{outcome:?}");
    let two_noise = tar_of(&[
        ("a.img", &noise[..FILE_LIMIT]),
        ("b.img", &noise[..FILE_LIMIT]),
    ]);
    let outcome = extract_gz(&two_noise, &config);
    assert!(
        outcome.is_ok(),
        "the second entry is below the ratio bound: {outcome:?}"
    );

    // Raising the ratio removes the refusal, as the CLI hint says.
    let relaxed = tight_config().with_max_compression_ratio(exarch_core::ratio_limit!(1000.0));
    let outcome = extract_gz(&zeros_tar("x.img", over), &relaxed);
    assert!(outcome.is_ok(), "{outcome:?}");
}

#[test]
fn filtering_never_refuses_what_extracting_whole_would_accept() {
    let work = TempDir::new().unwrap();
    let archive = work.path().join("a.tar.gz");
    std::fs::write(&archive, gzip(&zeros_tar("x.img", FILE_LIMIT))).unwrap();
    let whole = SecurityConfig::default()
        .with_max_file_size(exarch_core::non_zero!(FILE_LIMIT as u64))
        .with_max_compression_ratio(exarch_core::ratio_limit!(RATIO));

    for (name, config) in [("whole", whole), ("filtered", tight_config())] {
        let existing = TempDir::new().unwrap();
        std::fs::write(existing.path().join("keep"), b"x").unwrap();
        ExtractRequest::new(&config)
            .with_options(ExtractionOptions::default())
            .extract(&archive, existing.path())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

fn verify_gz_decoding(tar: &[u8], config: &SecurityConfig) {
    let report = VerifyRequest::new(config)
        .with_options(decode_to_eof())
        .verify_reader(ArchiveReader::tar(
            Cursor::new(gzip(tar)),
            Some(CompressionCodec::Gzip),
        ))
        .unwrap();
    assert_eq!(report.status(), VerificationStatus::Pass, "{report:?}");
}

fn decode_to_eof() -> VerificationOptions {
    VerificationOptions::default()
        .with_integrity(IntegrityCheck::DecodeToEof(DecompressionBudget::DEFAULT))
}

#[test]
fn an_integrity_decode_of_a_skipped_bomb_is_refused_early() {
    let gz = gzip(&zeros_tar("big.bin", 8 * MIB));
    let (reader, consumed) = counted(gz.clone());

    let error = VerifyRequest::new(&tight_config())
        .with_options(decode_to_eof())
        .verify_reader(ArchiveReader::tar(reader, Some(CompressionCodec::Gzip)))
        .unwrap_err();

    assert!(is_skip_bomb(&error), "{error:?}");
    assert_stopped_early(&consumed, gz.len());
}

#[test]
fn the_same_bytes_pass_an_integrity_decode_when_the_entry_is_allowed() {
    let config = tight_config()
        .with_max_file_size(exarch_core::non_zero!(16 * MIB as u64))
        .try_add_allowed_extension("bin")
        .unwrap();

    verify_gz_decoding(&zeros_tar("big.bin", 8 * MIB), &config);
}

#[test]
fn a_small_skipped_entry_passes_an_integrity_decode() {
    verify_gz_decoding(&zeros_tar("x.img", FILE_LIMIT), &tight_config());
}

/// A metered entry must not leave its meter on for the entries after it.
#[test]
fn a_metered_skipped_entry_does_not_meter_the_allowed_entries_after_it() {
    let noise = incompressible(FILE_LIMIT + FILE_LIMIT / 4);
    let zeros = vec![0u8; FILE_LIMIT];
    let names: Vec<String> = (0..20).map(|i| format!("a{i}.txt")).collect();
    let mut entries: Vec<(&str, &[u8])> = vec![("big.bin", &noise)];
    entries.extend(names.iter().map(|name| (name.as_str(), &zeros[..])));
    let tar = tar_of(&entries);
    let config = tight_config();

    extract_gz(&tar, &config).unwrap();
    ListRequest::new(&config)
        .with_options(ListOptions::default())
        .list_reader(ArchiveReader::tar(
            Cursor::new(gzip(&tar)),
            Some(CompressionCodec::Gzip),
        ))
        .unwrap();
}

#[test]
fn plain_tar_with_skipped_data_passes_at_any_size() {
    let work = TempDir::new().unwrap();
    let archive = work.path().join("a.tar");
    std::fs::write(&archive, zeros_tar("big.bin", 8 * MIB)).unwrap();
    let dest = work.path().join("out");

    let report = ExtractRequest::new(&tight_config())
        .with_options(ExtractionOptions::default())
        .extract(&archive, &dest)
        .unwrap();

    assert_eq!(report.files_extracted, 1);
    assert_eq!(report.files_skipped(), 1);
}

#[test]
fn a_caller_decoded_stream_is_not_bounded_by_ratio() {
    let gz = gzip(&zeros_tar("big.bin", 8 * MIB));
    let decoder = flate2::read::GzDecoder::new(Cursor::new(gz));
    let work = TempDir::new().unwrap();

    let config = tight_config();
    let report = TarArchive::new(decoder, &config)
        .extract(
            &work.path().join("out"),
            &ExtractionOptions::default(),
            &mut exarch_core::NoopProgress,
        )
        .unwrap();

    assert_eq!(report.files_skipped(), 1);
}
