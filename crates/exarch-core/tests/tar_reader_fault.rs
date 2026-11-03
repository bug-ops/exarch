//! A read error raised by the archive source is `ArchiveError::Io` with its
//! errno wherever it lands in a TAR (header, PAX record, payload, skipped
//! drain, trailer), never a corrupt-archive verdict (issue #858).

#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(clippy::disallowed_methods)]

mod sink_support;

use std::io::Cursor;
use std::io::Read;
use std::io::Write as _;

use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::DecompressionBudget;
use exarch_core::IntegrityCheck;
use exarch_core::ListOptions;
use exarch_core::MemoryLimit;
use exarch_core::MemorySink;
use exarch_core::SecurityConfig;
use exarch_core::SinkOptions;
use exarch_core::VerificationOptions;
use exarch_core::extract_to_sink;
use exarch_core::formats::CompressionCodec;
use exarch_core::list_reader;
use exarch_core::verify_reader;
use flate2::Compression;
use flate2::write::GzEncoder;

const EIO: i32 = 5;

/// Serves `inner` until `remaining` bytes were read, then fails every read.
struct FailAfter {
    inner: Cursor<Vec<u8>>,
    remaining: usize,
}

impl Read for FailAfter {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(std::io::Error::from_raw_os_error(EIO));
        }
        let want = buf.len().min(self.remaining);
        let n = self.inner.read(&mut buf[..want])?;
        self.remaining -= n;
        Ok(n)
    }
}

fn faulty(bytes: &[u8], budget: usize) -> FailAfter {
    FailAfter {
        inner: Cursor::new(bytes.to_vec()),
        remaining: budget,
    }
}

fn root(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction { source, .. } => root(source),
        other => other,
    }
}

/// Fails the test unless `error` is an I/O error carrying the injected errno.
fn assert_is_the_injected_fault(error: &ArchiveError, context: &str) {
    match root(error) {
        ArchiveError::Io(io) => assert_eq!(io.raw_os_error(), Some(EIO), "{context}: {error:?}"),
        other => panic!("{context}: expected Io({EIO}), got {other:?}"),
    }
}

fn plain_tar() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    builder
        .append_pax_extensions([("comment", &b"a pax record"[..])])
        .unwrap();
    for (name, size) in [("a.txt", 3000usize), ("dir/b.bin", 5000), ("c.txt", 700)] {
        let mut header = tar::Header::new_gnu();
        header.set_size(size as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, name, &vec![7u8; size][..])
            .unwrap();
    }
    let long = format!("{}/long.txt", "d".repeat(120));
    let mut header = tar::Header::new_gnu();
    header.set_size(4);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, &long, &b"data"[..])
        .unwrap();
    builder.into_inner().unwrap()
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

type Run = fn(ArchiveReader<'static>, &SecurityConfig) -> Result<(), ArchiveError>;

fn run_extract(
    reader: ArchiveReader<'static>,
    config: &SecurityConfig,
) -> Result<(), ArchiveError> {
    let mut sink = MemorySink::new(MemoryLimit::DEFAULT);
    extract_to_sink(reader, &mut sink, config, &SinkOptions::default()).map(drop)
}

fn run_list(reader: ArchiveReader<'static>, config: &SecurityConfig) -> Result<(), ArchiveError> {
    list_reader(reader, config, &ListOptions::default()).map(drop)
}

fn run_verify(reader: ArchiveReader<'static>, config: &SecurityConfig) -> Result<(), ArchiveError> {
    let options = VerificationOptions::default()
        .with_integrity(IntegrityCheck::DecodeToEof(DecompressionBudget::DEFAULT));
    verify_reader(reader, config, &options).map(drop)
}

const RUNS: [(&str, Run); 3] = [
    ("extract", run_extract),
    ("list", run_list),
    ("verify", run_verify),
];

/// Runs every operation with the source failing after each `step`-th byte and
/// checks the outcome shape exactly:
///
/// - every error is `Io` carrying the injected errno, whatever the position;
/// - outcomes flip once: all positions before the first success fail, all after
///   it succeed (a fault never turns into a later success);
/// - every position before `must_fail_below` fails, because the operation needs
///   those bytes;
/// - a source that fails only after the archive's end (`len + 1`) succeeds.
///
/// Returns the number of failing positions per operation.
fn sweep(
    bytes: &[u8],
    codec: Option<CompressionCodec>,
    config: &SecurityConfig,
    step: usize,
    must_fail_below: usize,
) -> Vec<(&'static str, usize)> {
    let mut failures = Vec::new();
    for (name, run) in RUNS {
        let budgets: Vec<usize> = (0..bytes.len()).step_by(step).collect();
        let failed: Vec<bool> = budgets
            .iter()
            .map(|&budget| {
                let reader = ArchiveReader::tar(faulty(bytes, budget), codec);
                run(reader, config).err().is_some_and(|error| {
                    assert_is_the_injected_fault(&error, &format!("{name} at {budget}"));
                    true
                })
            })
            .collect();

        let first_ok = failed.iter().position(|f| !f).unwrap_or(failed.len());
        assert!(
            failed[first_ok..].iter().all(|f| !f),
            "{name}: a success is followed by a failure: {failed:?}"
        );
        let first_ok_budget = budgets.get(first_ok).copied().unwrap_or(bytes.len());
        assert!(
            first_ok_budget >= must_fail_below,
            "{name}: succeeded at {first_ok_budget} < {must_fail_below}"
        );

        let reader = ArchiveReader::tar(faulty(bytes, bytes.len() + 1), codec);
        run(reader, config).unwrap_or_else(|e| panic!("{name} at len + 1: {e:?}"));
        failures.push((name, first_ok));
    }
    failures
}

#[test]
fn a_plain_tar_reports_every_reader_fault_as_io() {
    let bytes = plain_tar();
    // The operations stop at the end-of-archive marker (two zero blocks).
    let marker = bytes.len() - 1024;
    let failures = sweep(&bytes, None, &SecurityConfig::default(), 7, marker);
    for (name, failed) in failures {
        assert!(
            failed >= marker / 7,
            "{name}: only {failed} positions failed"
        );
    }
}

#[test]
fn a_gzip_tar_reports_every_reader_fault_as_io() {
    let gz = gzip(&plain_tar());
    // The trailer drain reads a gzip stream to its end, so no position short
    // of the whole file succeeds.
    let failures = sweep(
        &gz,
        Some(CompressionCodec::Gzip),
        &SecurityConfig::default(),
        3,
        gz.len(),
    );
    for (name, failed) in failures {
        assert_eq!(failed, gz.len().div_ceil(3), "{name}");
    }
}

#[test]
fn a_fault_inside_a_skipped_drain_is_io() {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(100_000);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "big.bin", &vec![1u8; 100_000][..])
        .unwrap();
    let mut header = tar::Header::new_gnu();
    header.set_size(2);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "ok.txt", &b"hi"[..])
        .unwrap();
    let bytes = builder.into_inner().unwrap();
    let config = SecurityConfig::default().with_allowed_extensions(vec!["txt".into()]);

    // Every position inside the 100 000 skipped bytes is covered by the step.
    let marker = bytes.len() - 1024;
    let failures = sweep(&bytes, None, &config, 61, marker);
    for (name, failed) in failures {
        assert!(
            failed >= 100_000 / 61,
            "{name}: only {failed} positions failed"
        );
    }
}
