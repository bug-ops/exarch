#![allow(clippy::unwrap_used)]

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
use crate::ExtractionOptions;
use crate::NoopProgress;
use crate::ReuseLimit;
use crate::SecurityConfig;
use crate::config::Validated;
use crate::formats::traits::ArchiveFormat;
use crate::formats::zip::ZipArchive;

fn limit(bytes: u64) -> ReuseLimit {
    ReuseLimit::new(NonZeroU64::new(bytes).unwrap())
}

fn plan(mode: DecodeReuse) -> ReusePlan {
    ReusePlan::of(mode, &SecurityConfig::default().validate().unwrap())
}

fn key_of(data: &[u8]) -> RetainKey {
    let mut crc = Crc::new();
    crc.update(data);
    RetainKey {
        data_start: 30,
        compressed: data.len() as u64,
        size: data.len() as u64,
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

fn replayed(store: &ReuseStore, key: &RetainKey) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    store.open(key).unwrap().read_to_end(&mut out)?;
    Ok(out)
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
        assert_eq!(replayed(&store, &key).unwrap(), data);
    }
}

#[test]
fn entries_of_a_spool_read_back_at_their_own_offsets() {
    let mut store = spooled(1 << 20);
    let first = b"first entry".repeat(50);
    let second = b"second one!".repeat(70);
    let (a, b) = (
        RetainKey {
            data_start: 1,
            ..key_of(&first)
        },
        RetainKey {
            data_start: 2,
            ..key_of(&second)
        },
    );
    capture_all(&mut store, a, &first);
    capture_all(&mut store, b, &second);
    store.seal();
    assert_eq!(replayed(&store, &b).unwrap(), second);
    assert_eq!(replayed(&store, &a).unwrap(), first);
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
        assert!(store.open(&key).is_none());
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
        assert!(store.open(&key).is_none());
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

        let forged = RetainKey { size: 40, ..key };
        let mut capture = store.capture(forged).unwrap();
        capture.write_all(&data).unwrap();
        capture.finish(40);
        assert!(store.open(&forged).is_none());
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
            data_start: 1,
            ..key_of(&first)
        },
        RetainKey {
            data_start: 2,
            ..key_of(&dropped)
        },
        RetainKey {
            data_start: 3,
            ..key_of(&third)
        },
    ];
    capture_all(&mut store, keys[0], &first);
    store.capture(keys[1]).unwrap().write_all(&dropped).unwrap();
    capture_all(&mut store, keys[2], &third);
    store.seal();
    assert_eq!(store.used(), (first.len() + third.len()) as u64);
    assert_eq!(replayed(&store, &keys[0]).unwrap(), first);
    assert_eq!(replayed(&store, &keys[2]).unwrap(), third);
    assert!(store.open(&keys[1]).is_none());
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
    use zip::write::SimpleFileOptions;

    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
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
    config: SecurityConfig<Validated>,
}

fn open(bytes: &[u8], reuse: DecodeReuse) -> Opened {
    let read = Arc::new(AtomicU64::new(0));
    let config = SecurityConfig::default().validate().unwrap();
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
    opened.archive.extract(
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
fn extraction_refuses_damaged_kept_output_without_decoding_again() {
    let bytes = deflated_zip(3);
    let dir = tempfile::tempdir().unwrap();
    let mut opened = open(&bytes, DecodeReuse::Memory(ReuseLimit::DEFAULT));
    opened
        .archive
        .structure_mut()
        .reuse_mut()
        .unwrap()
        .corrupt();
    let error = extract(&mut opened, dir.path()).unwrap_err();
    assert!(
        format!("{error:?}").contains(ZIP_INVALID_CHECKSUM),
        "{error:?}"
    );
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
    let ignoring = SecurityConfig::default()
        .with_zip_consistency(crate::ZipConsistencyPolicy::Ignore)
        .validate()
        .unwrap();
    let config = SecurityConfig::default().validate().unwrap();
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
    let config = SecurityConfig::default().validate().unwrap();
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
            compressed: 4,
            ..key_of(&data)
        };
        assert!(store.capture(bomb).is_none(), "ratio");

        let config = SecurityConfig::default()
            .with_max_file_size(1024)
            .validate()
            .unwrap();
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
        assert!(store.open(&key).is_none());
        assert_eq!(store.used(), 0);
    }
}

#[test]
fn the_limit_follows_the_decoder_memory_of_the_config() {
    let config = SecurityConfig::default()
        .with_max_decoder_memory(1024)
        .validate()
        .unwrap();
    let plan = ReusePlan::of(DecodeReuse::Memory(ReuseLimit::MAX), &config);
    let mut store = ReuseStore::new(plan).unwrap();
    let data = b"y".repeat(2048);
    assert!(store.capture(key_of(&data)).is_none());
    let fits = b"y".repeat(512);
    assert!(store.capture(key_of(&fits)).is_some());
}
