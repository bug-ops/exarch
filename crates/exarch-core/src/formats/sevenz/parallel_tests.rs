//! The parallel LZMA2 path hands the consumer what the sequential path does.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::decode::decode_archive_entries;
use super::decode::parallel_stream;
use crate::ParallelDecode;
use std::io::Cursor;

use sevenz_rust2::Archive;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use sevenz_rust2::EncoderConfiguration;
use sevenz_rust2::EncoderMethod;
use sevenz_rust2::Password;
use sevenz_rust2::SourceReader;
use sevenz_rust2::encoder_options::Lzma2Options;

use super::*;
use crate::formats::sevenz::lzma2::WorkerFault;

const CHUNK: u64 = 128 * 1024;

fn noisy(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|i| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            if i % 7 < 4 {
                (state >> 28) as u8
            } else {
                (state >> 24) as u8
            }
        })
        .collect()
}

/// One solid LZMA2 block written by `threads` writer threads, so it holds one
/// independent run per `CHUNK` of input.
fn lzma2_archive(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let options = Lzma2Options::from_level_mt(0, 4, CHUNK);
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    writer.set_content_methods(vec![
        EncoderConfiguration::new(EncoderMethod::LZMA2).with_options(options.into()),
    ]);
    let entries = files
        .iter()
        .map(|(name, data)| {
            let mut entry = ArchiveEntry::new_file(name);
            entry.has_stream = !data.is_empty();
            entry.size = data.len() as u64;
            entry
        })
        .collect();
    let readers = files
        .iter()
        .map(|(_, data)| SourceReader::from(Cursor::new(data.clone())))
        .collect();
    writer.push_archive_entries(entries, readers).unwrap();
    writer.finish().unwrap().into_inner()
}

fn files() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("first", noisy(700 * 1024, 1)),
        ("second", noisy(900 * 1024, 2)),
        ("third", noisy(300 * 1024 + 17, 3)),
    ]
}

fn bounded(bytes: u64) -> ParallelDecode {
    ParallelDecode::Bounded(std::num::NonZeroU64::new(bytes).unwrap())
}

type Events = Vec<(String, std::result::Result<Vec<u8>, String>)>;

/// Everything the consumer sees: each file's bytes or read error, and the
/// final result.
fn run(
    bytes: &[u8],
    parallel: ParallelDecode,
    knobs: DecodeKnobs,
    stop_after: usize,
) -> (Events, String) {
    let header = read_sevenz_header(&mut Cursor::new(bytes)).unwrap();
    run_archive(&header, bytes, parallel, knobs, stop_after)
}

fn run_archive(
    header: &SevenZHeader,
    bytes: &[u8],
    parallel: ParallelDecode,
    knobs: DecodeKnobs,
    stop_after: usize,
) -> (Events, String) {
    let mut events = Events::new();
    let result = decode_archive_entries(
        &mut Cursor::new(bytes.to_vec()),
        header,
        parallel,
        knobs,
        &mut |entry, reader| {
            let mut data = Vec::new();
            match reader.read_to_end(&mut data) {
                Ok(_) => events.push((entry.name.clone(), Ok(data))),
                Err(e) => {
                    events.push((entry.name.clone(), Err(format!("{:?} {e}", e.kind()))));
                    return Err(e.into());
                }
            }
            Ok(events.len() < stop_after)
        },
    );
    (events, format!("{result:?}"))
}

fn forced(threads: usize) -> DecodeKnobs {
    DecodeKnobs::new(1024, threads)
}

fn uses_the_parallel_path(bytes: &[u8], knobs: DecodeKnobs) -> bool {
    let header = read_sevenz_header(&mut Cursor::new(bytes)).unwrap();
    let block = header.block_indices().next().unwrap();
    parallel_stream(&header, block, 0..header.files().len(), knobs.min_unit).is_some()
}

#[test]
fn test_parallel_decode_hands_the_consumer_what_sequential_does() {
    let bytes = lzma2_archive(&files());
    let expected = run(&bytes, ParallelDecode::Sequential, forced(2), usize::MAX);
    assert_eq!(expected.0.len(), 3);
    assert!(expected.0.iter().all(|(_, data)| data.is_ok()));
    assert!(uses_the_parallel_path(&bytes, forced(2)));

    for threads in [2, 4] {
        for lookahead in [1, 300_000, 1 << 22, 1 << 30] {
            let actual = run(&bytes, bounded(lookahead), forced(threads), usize::MAX);
            assert_eq!(actual, expected, "threads {threads} lookahead {lookahead}");
        }
    }
}

#[test]
fn test_stock_7z_multi_threaded_fixture_matches_sequential() {
    let bytes = super::tests::load_fixture("lzma2-mt.7z");
    assert!(uses_the_parallel_path(&bytes, DecodeKnobs::new(1024, 2)));

    let expected = run(&bytes, ParallelDecode::Sequential, forced(2), usize::MAX);
    assert_eq!(expected.0.len(), 1);
    assert!(expected.0[0].1.is_ok());
    for lookahead in [1, 1 << 20] {
        let actual = run(
            &bytes,
            bounded(lookahead),
            DecodeKnobs::new(1024, 3),
            usize::MAX,
        );
        assert_eq!(actual, expected, "lookahead {lookahead}");
    }
}

#[test]
fn test_parallel_decode_stops_when_the_consumer_stops() {
    let bytes = lzma2_archive(&files());
    let expected = run(&bytes, ParallelDecode::Sequential, forced(2), 1);
    let actual = run(&bytes, bounded(1 << 22), forced(4), 1);
    assert_eq!(actual, expected);
    assert_eq!(actual.0.len(), 1);
}

#[test]
fn test_parallel_decode_reports_a_corrupt_stream_like_sequential() {
    let bytes = lzma2_archive(&files());
    let archive = Archive::read(&mut Cursor::new(bytes.clone()), &Password::empty()).unwrap();
    let pack_start = usize::try_from(SIGNATURE_HEADER_SIZE + archive.pack_pos()).unwrap();
    let pack_len = usize::try_from(archive.pack_sizes()[0]).unwrap();

    for fraction in [8, 3, 2] {
        let mut corrupt = bytes.clone();
        corrupt[pack_start + pack_len / fraction] ^= 0x5A;
        let expected = run(&corrupt, ParallelDecode::Sequential, forced(2), usize::MAX);
        let actual = run(&corrupt, bounded(1 << 22), forced(3), usize::MAX);

        assert!(expected.1.contains("Err"), "{expected:?}");
        assert!(actual.1.contains("Err"), "{actual:?}");
        let delivered = |events: &Events| {
            events
                .iter()
                .filter(|(_, data)| data.is_ok())
                .map(|(name, _)| name.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(delivered(&actual.0), delivered(&expected.0), "{fraction}");
    }
}

/// What a consumer reading in 4 KiB steps sees per file: the name, the bytes
/// read before any error, and whether the file ended without one.
type FileView = (String, Vec<u8>, bool);

fn run_in_steps(bytes: &[u8], parallel: ParallelDecode, knobs: DecodeKnobs) -> Vec<FileView> {
    let header = read_sevenz_header(&mut Cursor::new(bytes)).unwrap();
    let mut views = Vec::new();
    let _ = decode_archive_entries(
        &mut Cursor::new(bytes.to_vec()),
        &header,
        parallel,
        knobs,
        &mut |entry, reader| {
            let (mut data, mut buf) = (Vec::new(), [0u8; 4096]);
            let clean = loop {
                match reader.read(&mut buf) {
                    Ok(0) => break true,
                    Ok(n) => data.extend_from_slice(&buf[..n]),
                    Err(_) => break false,
                }
            };
            views.push((entry.name.clone(), data, clean));
            if clean {
                Ok(true)
            } else {
                Err(sevenz_rust2::Error::ChecksumVerificationFailed)
            }
        },
    );
    views
}

/// Many small files per run, so a failure late in a run sits behind intact
/// files that a whole-run error would swallow.
#[test]
fn test_parallel_decode_blames_the_file_that_holds_the_corruption() {
    let small: Vec<(String, Vec<u8>)> = (0..512u32)
        .map(|i| (format!("f{i:03}"), noisy(8192, i)))
        .collect();
    let named: Vec<(&str, Vec<u8>)> = small.iter().map(|(n, d)| (n.as_str(), d.clone())).collect();
    let options = Lzma2Options::from_level_mt(0, 4, 256 * 1024);
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    writer.set_content_methods(vec![
        EncoderConfiguration::new(EncoderMethod::LZMA2).with_options(options.into()),
    ]);
    let entries = named
        .iter()
        .map(|(name, data)| {
            let mut entry = ArchiveEntry::new_file(name);
            entry.has_stream = true;
            entry.size = data.len() as u64;
            entry
        })
        .collect();
    let readers = named
        .iter()
        .map(|(_, data)| SourceReader::from(Cursor::new(data.clone())))
        .collect();
    writer.push_archive_entries(entries, readers).unwrap();
    let bytes = writer.finish().unwrap().into_inner();

    let archive = Archive::read(&mut Cursor::new(bytes.clone()), &Password::empty()).unwrap();
    let pack_start = usize::try_from(SIGNATURE_HEADER_SIZE + archive.pack_pos()).unwrap();
    let pack_len = usize::try_from(archive.pack_sizes()[0]).unwrap();

    for percent in [37, 81] {
        let mut corrupt = bytes.clone();
        corrupt[pack_start + pack_len * percent / 100] ^= 0x5A;
        let expected = run_in_steps(&corrupt, ParallelDecode::Sequential, forced(2));
        let failing = expected.last().unwrap();
        assert!(!failing.2, "{percent}: sequential decode did not fail");

        let modes = [
            ("1 byte", bounded(1), forced(4)),
            ("1 MiB", bounded(1 << 20), forced(4)),
            ("128 MiB", bounded(128 << 20), forced(4)),
            ("128 MiB, 2 threads", bounded(128 << 20), forced(2)),
            ("production", bounded(128 << 20), DecodeKnobs::production()),
        ];
        for (label, parallel, knobs) in modes {
            let actual = run_in_steps(&corrupt, parallel, knobs);
            let file_names =
                |views: &[FileView]| views.iter().map(|v| v.0.clone()).collect::<Vec<_>>();
            assert_eq!(
                file_names(&actual),
                file_names(&expected),
                "{percent}% {label}"
            );
            let clean_flags = |views: &[FileView]| views.iter().map(|v| v.2).collect::<Vec<_>>();
            assert_eq!(
                clean_flags(&actual),
                clean_flags(&expected),
                "{percent}% {label}"
            );
            let finished = actual.len() - 1;
            assert_eq!(
                actual[..finished],
                expected[..finished],
                "{percent}% {label}"
            );
        }
    }
}

#[test]
fn test_parallel_decode_survives_an_injected_worker_panic() {
    let bytes = lzma2_archive(&files());
    let mut knobs = forced(3);
    knobs.fault = Some(WorkerFault::PanicOn(0));
    let (events, result) = run(&bytes, bounded(1 << 22), knobs, usize::MAX);

    assert!(result.contains("Err"), "{result}");
    assert!(events.iter().any(|(_, data)| data.is_err()));
}

#[test]
fn test_parallel_decode_falls_back_when_threads_cannot_be_spawned() {
    let bytes = lzma2_archive(&files());
    let expected = run(&bytes, ParallelDecode::Sequential, forced(2), usize::MAX);
    for failing in 0..3 {
        let mut knobs = forced(3);
        knobs.fault = Some(WorkerFault::SpawnFailsOn(failing));
        let actual = run(&bytes, bounded(1 << 22), knobs, usize::MAX);
        assert_eq!(actual, expected, "spawn {failing} failing");
    }
}

#[test]
fn test_blocks_that_are_not_one_lzma2_stream_stay_sequential() {
    let data = noisy(64 * 1024, 5);
    let copy = super::tests::build_solid_sevenz_archive(&[("copy", &data)], true);
    assert!(!uses_the_parallel_path(&copy, forced(2)));

    let small = lzma2_archive(&[("tiny", noisy(1500, 9))]);
    assert!(!uses_the_parallel_path(&small, forced(2)));
}

#[test]
fn test_bounded_with_one_thread_takes_the_sequential_path() {
    let bytes = lzma2_archive(&files());
    let expected = run(&bytes, ParallelDecode::Sequential, forced(2), usize::MAX);
    let mut knobs = forced(1);
    // A worker would panic; with one thread none is started.
    knobs.fault = Some(WorkerFault::PanicOn(0));
    let actual = run(&bytes, bounded(1 << 22), knobs, usize::MAX);
    assert_eq!(actual, expected);
}

/// A stream-less file inside the walked span of an otherwise eligible block,
/// which a hand-edited file table can produce; its size moves to the last file
/// so the files still account for the whole output.
fn archive_with_empty_file_in_the_span(bytes: &[u8]) -> SevenZHeader {
    let mut archive = Archive::read(&mut Cursor::new(bytes.to_vec()), &Password::empty()).unwrap();
    let moved = archive.files[1].size;
    archive.files[1].has_stream = false;
    archive.files[1].size = 0;
    archive.files[2].size += moved;
    archive.files[2].has_crc = false;
    SevenZHeader::assume_checked(archive)
}

#[test]
fn test_empty_file_inside_a_block_is_visited_and_can_stop_the_walk() {
    let bytes = lzma2_archive(&files());
    let header = archive_with_empty_file_in_the_span(&bytes);
    let block = header.block_indices().next().unwrap();
    assert!(parallel_stream(&header, block, 0..3, 1024).is_some());

    for stop_after in [2, usize::MAX] {
        let expected = run_archive(
            &header,
            &bytes,
            ParallelDecode::Sequential,
            forced(2),
            stop_after,
        );
        let actual = run_archive(&header, &bytes, bounded(1 << 22), forced(3), stop_after);
        assert_eq!(actual, expected, "stop after {stop_after}");
        assert_eq!(actual.0[1], ("second".to_string(), Ok(Vec::new())));
    }
}
