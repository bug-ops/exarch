#![allow(clippy::unwrap_used)]

use std::assert_matches;
use std::io::Cursor;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use super::*;
use crate::ArchiveError;
use crate::ExtractionOptions;
use crate::NoopProgress;
use crate::ReuseLimit;
use crate::SecurityConfig;
use crate::formats::zip::ZipArchive;
use crate::formats::zip::ZipMethod;
use crate::sink::SinkUsage;

fn limit(bytes: u64) -> ReuseLimit {
    ReuseLimit::new(NonZeroU64::new(bytes).unwrap())
}

fn plan(mode: DecodeReuse) -> ReusePlan {
    ReusePlan::of(mode, &SecurityConfig::default())
}

fn key_of(data: &[u8]) -> RetainKey {
    let mut crc = Crc::new();
    crc.update(data);
    RetainKey {
        method: ZipMethod::Deflate,
        data_start: 30,
        compressed: Compressed(data.len() as u64),
        size: Uncompressed(data.len() as u64),
        crc32: crc.sum(),
    }
}

fn capture_all(store: &mut ReuseStore, key: RetainKey, data: &[u8]) {
    let mut capture = store.capture(key).unwrap();
    capture.write_all(data).unwrap();
    capture.finish(data.len() as u64);
}

fn spooled(max: u64) -> ReuseStore {
    ReuseStore::new(plan(DecodeReuse::TempFile(limit(max)))).unwrap()
}

fn replayed(store: &mut ReuseStore, key: &RetainKey) -> io::Result<Vec<u8>> {
    let taken = store.take(key).unwrap();
    match store.retained(taken, key)? {
        Retained::Bytes(bytes) => Ok(bytes),
        Retained::Spooled(mut reader) => {
            let mut out = Vec::new();
            reader.read_to_end(&mut out)?;
            Ok(out)
        }
    }
}

fn stores() -> [ReuseStore; 2] {
    [
        ReuseStore::new(plan(DecodeReuse::Memory(limit(1 << 20)))).unwrap(),
        spooled(1 << 20),
    ]
}

#[test]
fn a_captured_entry_reads_back_as_written() {
    for mut store in stores() {
        let data = b"decoded bytes".repeat(100);
        let key = key_of(&data);
        capture_all(&mut store, key, &data);
        store.seal();
        assert_eq!(replayed(&mut store, &key).unwrap(), data);
    }
}

#[test]
fn entries_of_a_spool_read_back_at_their_own_offsets() {
    let mut store = spooled(1 << 20);
    let first = b"first entry".repeat(50);
    let second = b"second one!".repeat(70);
    let (a, b) = (
        RetainKey {
            method: ZipMethod::Deflate,
            data_start: 1,
            ..key_of(&first)
        },
        RetainKey {
            method: ZipMethod::Deflate,
            data_start: 2,
            ..key_of(&second)
        },
    );
    capture_all(&mut store, a, &first);
    capture_all(&mut store, b, &second);
    store.seal();
    assert_eq!(replayed(&mut store, &b).unwrap(), second);
    assert_eq!(replayed(&mut store, &a).unwrap(), first);
}

#[test]
fn an_entry_whose_checksum_differs_is_not_kept() {
    for mut store in stores() {
        let data = b"decoded bytes".to_vec();
        let key = RetainKey {
            crc32: key_of(&data).crc32 ^ 1,
            ..key_of(&data)
        };
        capture_all(&mut store, key, &data);
        store.seal();
        assert!(!store.holds(&key));
        assert_eq!(store.used(), 0);
    }
}

#[test]
fn an_entry_that_decoded_to_another_size_is_not_kept() {
    for mut store in stores() {
        let data = b"decoded bytes".to_vec();
        let key = key_of(&data);
        let mut capture = store.capture(key).unwrap();
        capture.write_all(&data).unwrap();
        capture.finish(data.len() as u64 + 1);
        assert!(!store.holds(&key));
        assert_eq!(store.used(), 0);
    }
}

#[test]
fn an_entry_over_the_limit_is_dropped_and_releases_its_bytes() {
    for mut store in [
        ReuseStore::new(plan(DecodeReuse::Memory(limit(64)))).unwrap(),
        spooled(64),
    ] {
        let data = vec![7u8; 200];
        let key = key_of(&data);
        assert!(
            store.capture(key).is_none(),
            "the declared size does not fit"
        );

        let forged = RetainKey {
            size: Uncompressed(40),
            ..key
        };
        let mut capture = store.capture(forged).unwrap();
        capture.write_all(&data).unwrap();
        capture.finish(40);
        assert!(!store.holds(&forged));
        assert_eq!(store.used(), 0);
    }
}

#[test]
fn a_dropped_capture_rolls_the_spool_back() {
    let mut store = spooled(1 << 20);
    let first = b"kept".repeat(30);
    let dropped = b"failed".repeat(30);
    let third = b"after".repeat(30);
    let keys = [
        RetainKey {
            method: ZipMethod::Deflate,
            data_start: 1,
            ..key_of(&first)
        },
        RetainKey {
            method: ZipMethod::Deflate,
            data_start: 2,
            ..key_of(&dropped)
        },
        RetainKey {
            method: ZipMethod::Deflate,
            data_start: 3,
            ..key_of(&third)
        },
    ];
    capture_all(&mut store, keys[0], &first);
    store.capture(keys[1]).unwrap().write_all(&dropped).unwrap();
    capture_all(&mut store, keys[2], &third);
    store.seal();
    assert_eq!(store.used(), (first.len() + third.len()) as u64);
    assert_eq!(replayed(&mut store, &keys[0]).unwrap(), first);
    assert_eq!(replayed(&mut store, &keys[2]).unwrap(), third);
    assert!(!store.holds(&keys[1]));
}

#[test]
fn replay_of_damaged_bytes_fails_with_the_checksum_error() {
    let data = b"decoded bytes".repeat(10);
    let key = key_of(&data);
    let mut damaged = data;
    damaged[3] ^= 0x10;
    let mut out = Vec::new();
    let error = ReplayReader::new(Cursor::new(damaged), key)
        .read_to_end(&mut out)
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), ZIP_INVALID_CHECKSUM);
}

#[test]
fn replay_of_short_bytes_fails_with_an_unexpected_end() {
    let data = b"decoded bytes".repeat(10);
    let key = key_of(&data);
    let mut out = Vec::new();
    let error = ReplayReader::new(Cursor::new(data[..data.len() - 1].to_vec()), key)
        .read_to_end(&mut out)
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
}

#[test]
fn a_store_that_cannot_be_made_keeps_nothing() {
    assert!(ReuseStore::new(plan(DecodeReuse::Off)).is_none());
}

struct Counting<R> {
    inner: R,
    read: Arc<AtomicU64>,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

impl<R: Seek> Seek for Counting<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

fn payload(index: usize) -> Vec<u8> {
    let words = [
        "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota", "kappa",
        "lambda", "mu", "nu", "xi", "omicron", "pi",
    ];
    let mut state = 0x9E37_79B9_u32.wrapping_add(u32::try_from(index).unwrap());
    (0..4000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            words[state as usize % words.len()]
        })
        .collect::<Vec<_>>()
        .join(" ")
        .into_bytes()
}

fn deflated_zip(entries: usize) -> Vec<u8> {
    zip_of(entries, zip::CompressionMethod::Deflated)
}

fn zip_of(entries: usize, method: zip::CompressionMethod) -> Vec<u8> {
    use zip::write::SimpleFileOptions;

    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default()
        .compression_method(method)
        .unix_permissions(0o644);
    for index in 0..entries {
        zip.start_file(format!("dir/file{index}.txt"), options)
            .unwrap();
        zip.write_all(&payload(index)).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

struct Opened {
    archive: ZipArchive<Counting<Cursor<Vec<u8>>>>,
    read: Arc<AtomicU64>,
    config: SecurityConfig,
}

fn mixed_zip() -> Vec<u8> {
    use zip::CompressionMethod;
    use zip::write::SimpleFileOptions;

    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let entries = [
        ("stored.txt", CompressionMethod::Stored, payload(0)),
        ("deflated.txt", CompressionMethod::Deflated, payload(1)),
        ("empty.txt", CompressionMethod::Deflated, Vec::new()),
        ("bzip2.txt", CompressionMethod::Bzip2, payload(2)),
        ("zstd.txt", CompressionMethod::Zstd, payload(3)),
    ];
    for (name, method, data) in entries {
        let options = SimpleFileOptions::default().compression_method(method);
        zip.start_file(name, options).unwrap();
        zip.write_all(&data).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

fn open(bytes: &[u8], reuse: DecodeReuse) -> Opened {
    let read = Arc::new(AtomicU64::new(0));
    let config = SecurityConfig::default();
    let reader = Counting {
        inner: Cursor::new(bytes.to_vec()),
        read: Arc::clone(&read),
    };
    Opened {
        archive: ZipArchive::for_extraction(reader, &config, reuse).unwrap(),
        read,
        config,
    }
}

fn extract(opened: &mut Opened, out: &std::path::Path) -> crate::Result<crate::ExtractionReport> {
    opened.archive.extract_in_place(
        out,
        &opened.config,
        &ExtractionOptions::default(),
        &mut NoopProgress,
    )
}

fn tree(root: &std::path::Path, entries: usize) -> Vec<Vec<u8>> {
    (0..entries)
        .map(|i| std::fs::read(root.join(format!("dir/file{i}.txt"))).unwrap())
        .collect()
}

#[test]
fn extraction_replays_every_deflate_entry_and_writes_the_same_files() {
    const ENTRIES: usize = 12;
    let bytes = deflated_zip(ENTRIES);
    let expected: Vec<_> = (0..ENTRIES).map(payload).collect();

    let off_dir = tempfile::tempdir().unwrap();
    let mut off = open(&bytes, DecodeReuse::Off);
    extract(&mut off, off_dir.path()).unwrap();
    assert_eq!(tree(off_dir.path(), ENTRIES), expected);
    let off_reads = off.read.load(Ordering::Relaxed);

    for mode in [
        DecodeReuse::Memory(ReuseLimit::DEFAULT),
        DecodeReuse::TempFile(ReuseLimit::DEFAULT),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut opened = open(&bytes, mode);
        let kept = opened.archive.structure_mut().reuse_mut().unwrap().used();
        assert_eq!(kept, expected.iter().map(|d| d.len() as u64).sum::<u64>());
        let report = extract(&mut opened, dir.path()).unwrap();
        assert_eq!(report.files_extracted, ENTRIES);
        assert_eq!(tree(dir.path(), ENTRIES), expected, "{mode:?}");
        let replays = opened
            .archive
            .structure_mut()
            .reuse_mut()
            .unwrap()
            .replays();
        assert_eq!(replays, ENTRIES, "{mode:?}");
        let reads = opened.read.load(Ordering::Relaxed);
        assert!(
            reads + bytes.len() as u64 / 2 < off_reads,
            "{mode:?}: {reads} bytes read with reuse, {off_reads} without"
        );
    }
}

#[test]
fn extraction_refuses_damaged_kept_output_as_io_without_decoding_again() {
    let bytes = deflated_zip(3);
    for mode in [
        DecodeReuse::Memory(ReuseLimit::DEFAULT),
        DecodeReuse::TempFile(ReuseLimit::DEFAULT),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut opened = open(&bytes, mode);
        opened
            .archive
            .structure_mut()
            .reuse_mut()
            .unwrap()
            .corrupt()
            .unwrap();
        let error = extract(&mut opened, dir.path()).unwrap_err();
        assert!(
            format!("{error:?}").contains(ZIP_INVALID_CHECKSUM),
            "{mode:?}: {error:?}"
        );
        let cause = match &error {
            ArchiveError::PartialExtraction(partial) => partial.cause(),
            other => other,
        };
        assert_matches!(
            cause,
            ArchiveError::Io(_),
            "{mode:?}: damaged kept output is a fault of the spool, not a malformed archive"
        );
    }
}

#[test]
fn a_limit_below_the_archive_keeps_what_fits_and_extracts_the_rest_normally() {
    const ENTRIES: usize = 6;
    let bytes = deflated_zip(ENTRIES);
    let one = payload(0).len() as u64;
    let dir = tempfile::tempdir().unwrap();
    let mut opened = open(&bytes, DecodeReuse::Memory(limit(one * 2 + one / 2)));
    extract(&mut opened, dir.path()).unwrap();
    let expected: Vec<_> = (0..ENTRIES).map(payload).collect();
    assert_eq!(tree(dir.path(), ENTRIES), expected);
    let replays = opened
        .archive
        .structure_mut()
        .reuse_mut()
        .unwrap()
        .replays();
    assert!((1..ENTRIES).contains(&replays), "{replays}");
}

#[test]
fn an_archive_opened_for_another_policy_is_not_served() {
    let bytes = deflated_zip(1);
    let opened = open(&bytes, DecodeReuse::Off);
    assert!(opened.archive.serves(&opened.config));
    let ignoring =
        SecurityConfig::default().with_zip_consistency(crate::ZipConsistencyPolicy::Ignore);
    let config = SecurityConfig::default();
    let skipped =
        ZipArchive::for_extraction(Cursor::new(bytes), &ignoring, DecodeReuse::Off).unwrap();
    assert!(skipped.serves(&ignoring));
    assert!(!skipped.serves(&config));
}

struct FailsAfter {
    inner: Cursor<Vec<u8>>,
    reads_left: usize,
}

impl Read for FailsAfter {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.reads_left == 0 {
            return Err(io::Error::from_raw_os_error(5));
        }
        self.reads_left -= 1;
        self.inner.read(buf)
    }
}

impl Seek for FailsAfter {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

#[test]
fn a_source_fault_while_opening_keeps_its_errno() {
    let bytes = deflated_zip(4);
    let config = SecurityConfig::default();
    let mut seen = false;
    for reads_left in 0..40 {
        let reader = FailsAfter {
            inner: Cursor::new(bytes.clone()),
            reads_left,
        };
        if let Err(crate::ArchiveError::Io(error)) =
            ZipArchive::for_extraction(reader, &config, DecodeReuse::Off)
        {
            assert_eq!(error.raw_os_error(), Some(5), "after {reads_left} reads");
            seen = true;
        }
    }
    assert!(seen, "no read fault surfaced as an I/O error");
}

#[test]
fn an_entry_the_limits_would_refuse_is_not_captured() {
    for mut store in stores() {
        let data = vec![0u8; 4096];
        let bomb = RetainKey {
            compressed: Compressed(4),
            ..key_of(&data)
        };
        assert!(store.capture(bomb).is_none(), "ratio");

        let config = SecurityConfig::default().with_max_file_size(crate::non_zero!(1024));
        let mut small =
            ReuseStore::new(ReusePlan::of(DecodeReuse::Memory(limit(1 << 20)), &config)).unwrap();
        assert!(small.capture(key_of(&data)).is_none(), "max_file_size");
    }
}

#[test]
fn a_capture_stops_once_it_passes_the_declared_size() {
    for mut store in stores() {
        let data = b"x".repeat(100);
        let key = key_of(&data);
        let mut capture = store.capture(key).unwrap();
        capture.write_all(&data).unwrap();
        capture.write_all(&data).unwrap();
        capture.finish(200);
        assert!(!store.holds(&key));
        assert_eq!(store.used(), 0);
    }
}

#[test]
fn the_limit_follows_the_decoder_memory_of_the_config() {
    let config = SecurityConfig::default().with_max_decoder_memory(crate::non_zero!(1024));
    let plan = ReusePlan::of(DecodeReuse::Memory(ReuseLimit::MAX), &config);
    let mut store = ReuseStore::new(plan).unwrap();
    let data = b"y".repeat(2048);
    assert!(store.capture(key_of(&data)).is_none());
    let fits = b"y".repeat(512);
    assert!(store.capture(key_of(&fits)).is_some());
}

#[test]
fn only_non_empty_compressed_entries_are_kept_and_replayed() {
    let bytes = mixed_zip();
    for mode in [
        DecodeReuse::Memory(ReuseLimit::DEFAULT),
        DecodeReuse::TempFile(ReuseLimit::DEFAULT),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut opened = open(&bytes, mode);
        extract(&mut opened, dir.path()).unwrap();
        let store = opened.archive.structure_mut().reuse_mut().unwrap();
        assert_eq!(store.replays(), 3, "{mode:?}");
        let on_disk = match mode {
            DecodeReuse::TempFile(_) => {
                (payload(1).len() + payload(2).len() + payload(3).len()) as u64
            }
            _ => 0,
        };
        assert_eq!(store.used(), on_disk, "{mode:?}");
        assert_eq!(std::fs::read(dir.path().join("empty.txt")).unwrap(), b"");
        assert_eq!(
            std::fs::read(dir.path().join("bzip2.txt")).unwrap(),
            payload(2)
        );
        assert_eq!(
            std::fs::read(dir.path().join("zstd.txt")).unwrap(),
            payload(3)
        );
    }
}

#[cfg(target_os = "wasi")]
#[test]
fn a_temp_file_store_is_never_made_on_wasi() {
    assert!(ReuseStore::new(plan(DecodeReuse::TempFile(ReuseLimit::DEFAULT))).is_none());
}

#[test]
fn nothing_is_kept_when_the_policy_skips_the_stream_checks() {
    let config =
        SecurityConfig::default().with_zip_consistency(crate::ZipConsistencyPolicy::Ignore);
    let mut archive = ZipArchive::for_extraction(
        Cursor::new(deflated_zip(3)),
        &config,
        DecodeReuse::Memory(ReuseLimit::DEFAULT),
    )
    .unwrap();
    assert!(archive.structure_mut().reuse_mut().is_none());
}

#[test]
fn bzip2_entries_are_decoded_once() {
    const ENTRIES: usize = 40;
    let bytes = zip_of(ENTRIES, zip::CompressionMethod::Bzip2);
    let expected: Vec<_> = (0..ENTRIES).map(payload).collect();

    let off_dir = tempfile::tempdir().unwrap();
    let mut off = open(&bytes, DecodeReuse::Off);
    extract(&mut off, off_dir.path()).unwrap();
    let off_reads = off.read.load(Ordering::Relaxed);

    let dir = tempfile::tempdir().unwrap();
    let mut opened = open(&bytes, DecodeReuse::Memory(ReuseLimit::DEFAULT));
    extract(&mut opened, dir.path()).unwrap();
    assert_eq!(tree(dir.path(), ENTRIES), expected);
    let store = opened.archive.structure_mut().reuse_mut().unwrap();
    assert_eq!(store.replays(), ENTRIES);
    let reads = opened.read.load(Ordering::Relaxed);
    assert!(
        reads + bytes.len() as u64 / 2 < off_reads,
        "{reads} bytes read with reuse, {off_reads} without"
    );
}

fn counted_zip_reader(bytes: &[u8]) -> (crate::ArchiveReader<'static>, Arc<AtomicU64>) {
    let read = Arc::new(AtomicU64::new(0));
    let reader = Counting {
        inner: Cursor::new(bytes.to_vec()),
        read: Arc::clone(&read),
    };
    let reader = crate::ArchiveReader::seekable(reader, crate::SeekableFormat::Zip);
    (reader, read)
}

#[test]
fn extraction_into_memory_decodes_each_entry_once_and_keeps_the_same_files() {
    const ENTRIES: usize = 40;
    for method in [
        zip::CompressionMethod::Deflated,
        zip::CompressionMethod::Bzip2,
        zip::CompressionMethod::Zstd,
    ] {
        let bytes = zip_of(ENTRIES, method);

        let (reader, plain_reads) = counted_zip_reader(&bytes);
        let mut plain = crate::MemorySink::default();
        crate::SinkExtractRequest::new(&SecurityConfig::default())
            .with_options(crate::SinkOptions::default())
            .extract(reader, &mut plain)
            .unwrap();

        let (reader, reads) = counted_zip_reader(&bytes);
        let (report, memory) = crate::extract_reader_to_memory(
            reader,
            &crate::MemoryExtractRequest::default(),
            &mut NoopProgress,
        )
        .unwrap();
        assert_eq!(report.files_extracted, ENTRIES);
        assert_eq!(memory.into_entries(), plain.into_entries(), "{method:?}");
        let reads = reads.load(Ordering::Relaxed);
        let plain_reads = plain_reads.load(Ordering::Relaxed);
        assert!(
            reads + bytes.len() as u64 / 2 < plain_reads,
            "{method:?}: {reads} bytes read with reuse, {plain_reads} without"
        );
    }
}

fn sink_capacity_of(error: &crate::ArchiveError) -> Option<u64> {
    match error {
        crate::ArchiveError::PartialExtraction(partial) => sink_capacity_of(partial.cause()),
        crate::ArchiveError::QuotaExceeded {
            resource: crate::QuotaResource::SinkCapacity { max },
        } => Some(*max),
        _ => None,
    }
}

#[test]
fn a_replayed_entry_meets_the_sink_limit_at_the_same_byte_as_a_decoded_one() {
    const ENTRIES: usize = 4;
    let bytes = deflated_zip(ENTRIES);
    let exact: u64 = (0..ENTRIES)
        .map(|i| {
            crate::MemorySink::charge_of(
                std::path::Path::new(&format!("dir/file{i}.txt")),
                payload(i).len() as u64,
            )
        })
        .sum();
    for (bytes_allowed, fits) in [(exact, true), (exact - 1, false)] {
        let limit = crate::MemoryLimit::new(NonZeroU64::new(bytes_allowed).unwrap());
        let request = crate::MemoryExtractRequest::default().with_limit(limit);
        let (reader, _) = counted_zip_reader(&bytes);
        let reused = crate::extract_reader_to_memory(reader, &request, &mut NoopProgress);

        let mut plain = crate::MemorySink::new(limit);
        let (reader, _) = counted_zip_reader(&bytes);
        let decoded = crate::SinkExtractRequest::new(&SecurityConfig::default())
            .with_options(crate::SinkOptions::default())
            .extract(reader, &mut plain);

        assert_eq!(reused.is_ok(), fits);
        assert_eq!(decoded.is_ok(), fits);
        if !fits {
            assert_eq!(
                sink_capacity_of(&reused.unwrap_err()),
                sink_capacity_of(&decoded.unwrap_err())
            );
        }
    }
}

#[test]
fn kept_output_and_sink_stay_within_the_shared_limit_before_every_entry() {
    let usage = SinkUsage::default();
    let mut store = ReuseStore::new(plan(DecodeReuse::Memory(limit(1 << 20)))).unwrap();
    store.share_limit_with_sink(usage.clone(), 100);

    let entries: Vec<Vec<u8>> = [40_u8, 30, 20]
        .iter()
        .map(|n| vec![*n; usize::from(*n)])
        .collect();
    let keys: Vec<_> = entries
        .iter()
        .enumerate()
        .map(|(i, data)| RetainKey {
            method: ZipMethod::Deflate,
            data_start: i as u64,
            ..key_of(data)
        })
        .collect();
    for (key, data) in keys.iter().zip(&entries) {
        capture_all(&mut store, *key, data);
    }
    assert_eq!(store.used(), 90);

    // The sink holds 50 bytes and the entry at hand charges 10, so the latest
    // kept entries go until at most 40 bytes are kept.
    usage.set(50);
    store.make_room(10);
    assert!(store.used() + 50 + 10 <= 100, "{}", store.used());
    assert!(store.holds(&keys[0]));
    assert!(!store.holds(&keys[1]));
    assert!(!store.holds(&keys[2]));

    let taken = store.take(&keys[0]).unwrap();
    assert_eq!(store.used(), 0);
    assert_matches!(
        store.retained(taken, &keys[0]).unwrap(),
        Retained::Bytes(bytes) if bytes == entries[0]
    );
}

fn ram_spooled(max: u64) -> ReuseStore {
    let spool = TempSpool::with_backing(SpoolBacking::Ram).unwrap();
    ReuseStore::with_spool(plan(DecodeReuse::TempFile(limit(max))), spool)
}

fn keyed(entries: &[Vec<u8>]) -> Vec<RetainKey> {
    entries
        .iter()
        .enumerate()
        .map(|(i, data)| RetainKey {
            method: ZipMethod::Deflate,
            data_start: i as u64,
            ..key_of(data)
        })
        .collect()
}

#[test]
fn a_ram_spool_is_charged_like_memory_and_evicts_by_truncation() {
    let usage = SinkUsage::default();
    let mut store = ram_spooled(1 << 20);
    store.share_limit_with_sink(usage.clone(), 100);

    let entries: Vec<Vec<u8>> = [40_u8, 30, 20]
        .iter()
        .map(|n| vec![*n; usize::from(*n)])
        .collect();
    let keys = keyed(&entries);
    for (key, data) in keys.iter().zip(&entries) {
        capture_all(&mut store, *key, data);
    }
    store.seal();
    assert_eq!(store.used(), 90);

    usage.set(50);
    store.make_room(10);
    assert_eq!(store.used(), 40);
    assert!(store.holds(&keys[0]));
    assert!(!store.holds(&keys[1]));
    assert!(!store.holds(&keys[2]));
    assert_eq!(replayed(&mut store, &keys[0]).unwrap(), entries[0]);

    let again = vec![9_u8; 25];
    let key = RetainKey {
        data_start: 7,
        ..key_of(&again)
    };
    capture_all(&mut store, key, &again);
    store.seal();
    assert_eq!(replayed(&mut store, &key).unwrap(), again);
}

#[test]
fn a_disk_spool_is_not_evicted_by_the_sink_budget() {
    let usage = SinkUsage::default();
    let mut store = spooled(1 << 20);
    store.share_limit_with_sink(usage.clone(), 100);
    let entries = vec![vec![1_u8; 40], vec![2_u8; 40]];
    let keys = keyed(&entries);
    for (key, data) in keys.iter().zip(&entries) {
        capture_all(&mut store, *key, data);
    }
    usage.set(90);
    store.make_room(10);
    assert!(keys.iter().all(|key| store.holds(key)));
}

#[test]
fn eviction_never_cuts_below_the_entry_just_taken() {
    let usage = SinkUsage::default();
    let mut store = ram_spooled(1 << 20);
    store.share_limit_with_sink(usage.clone(), 100);
    let entries = vec![vec![1_u8; 40], vec![2_u8; 30], vec![3_u8; 20]];
    let keys = keyed(&entries);
    for (key, data) in keys.iter().zip(&entries) {
        capture_all(&mut store, *key, data);
    }
    store.seal();

    // Extraction takes an entry, then makes room for the sink, then reads it.
    let taken = store.take(&keys[1]).unwrap();
    usage.set(100);
    store.make_room(0);
    assert!(!store.holds(&keys[0]));
    assert!(!store.holds(&keys[2]));
    match store.retained(taken, &keys[1]).unwrap() {
        Retained::Spooled(mut reader) => {
            let mut out = Vec::new();
            reader.read_to_end(&mut out).unwrap();
            assert_eq!(out, entries[1]);
        }
        Retained::Bytes(_) => panic!("a spool hands out a reader"),
    }
}
