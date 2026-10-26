#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use proptest::prelude::*;

use super::*;

const PREFIX: usize = 7;

fn stored(reset: bool, data: &[u8]) -> Vec<u8> {
    let len = u16::try_from(data.len() - 1).unwrap();
    let mut chunk = vec![if reset { 1 } else { 2 }];
    chunk.extend_from_slice(&len.to_be_bytes());
    chunk.extend_from_slice(data);
    chunk
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 256).unwrap().wrapping_mul(31) ^ seed)
        .collect()
}

/// `runs` runs of `chunks` stored chunks of `chunk_len` bytes, each run opened
/// by a dictionary reset, closed by an end marker.
fn stored_stream(runs: usize, chunks: usize, chunk_len: usize) -> (Vec<u8>, Vec<u8>) {
    let (mut stream, mut expected) = (Vec::new(), Vec::new());
    for run in 0..runs {
        for chunk in 0..chunks {
            let data = pattern(
                chunk_len,
                u8::try_from((run * chunks + chunk) % 256).unwrap(),
            );
            stream.extend(stored(chunk == 0, &data));
            expected.extend(data);
        }
    }
    stream.push(0);
    (stream, expected)
}

fn knobs(min_unit: u64, threads: usize) -> DecodeKnobs {
    DecodeKnobs::new(min_unit, threads)
}

fn source(stream: &[u8]) -> Cursor<Vec<u8>> {
    let mut bytes = vec![0xAA; PREFIX];
    bytes.extend_from_slice(stream);
    bytes.extend_from_slice(&[0xBB; 5]);
    Cursor::new(bytes)
}

fn description(stream: &[u8], output_len: u64) -> Lzma2Stream {
    Lzma2Stream {
        offset: PREFIX as u64,
        len: stream.len() as u64,
        output_len,
        dict_size: 1 << 16,
    }
}

fn parallel(
    stream: &[u8],
    output_len: u64,
    knobs: DecodeKnobs,
    lookahead: u64,
) -> io::Result<Vec<u8>> {
    with_parallel_reader(
        source(stream),
        description(stream, output_len),
        knobs,
        lookahead,
        |reader| {
            let mut out = Vec::new();
            reader.take(output_len).read_to_end(&mut out)?;
            if out.len() as u64 == output_len {
                Ok(out)
            } else {
                Err(io::ErrorKind::UnexpectedEof.into())
            }
        },
    )
}

fn sequential(stream: &[u8], output_len: u64) -> io::Result<Vec<u8>> {
    let mut reader = Lzma2Reader::new(stream, 1 << 16, None);
    let mut out = vec![0; usize::try_from(output_len).unwrap()];
    reader.read_exact(&mut out)?;
    Ok(out)
}

fn assert_same_outcome(stream: &[u8], output_len: u64, knobs: DecodeKnobs, lookahead: u64) {
    let expected = sequential(stream, output_len);
    let actual = parallel(stream, output_len, knobs, lookahead);
    match (&expected, &actual) {
        (Ok(a), Ok(b)) => assert_eq!(a, b),
        (Err(_), Err(_)) => {}
        _ => panic!("sequential {expected:?} parallel {actual:?}"),
    }
}

fn planner_over<'a>(
    cell: &'a RefCell<Cursor<Vec<u8>>>,
    stream: &[u8],
    output_len: u64,
    min_unit: u64,
) -> Lzma2Planner<'a, Cursor<Vec<u8>>> {
    Lzma2Planner::new(
        PackSource {
            source: cell,
            stream: description(stream, output_len),
        },
        min_unit,
    )
}

#[test]
fn test_clean_stream_matches_for_every_budget_and_thread_count() {
    let (stream, expected) = stored_stream(6, 3, 5000);
    let len = expected.len() as u64;
    for threads in [1, 2, 4] {
        for lookahead in [0, 1 << 14, 1 << 20, u64::MAX] {
            let out = parallel(&stream, len, knobs(1, threads), lookahead).unwrap();
            assert_eq!(out, expected, "threads {threads} lookahead {lookahead}");
        }
    }
}

#[test]
fn test_planner_splits_only_at_resets_and_covers_the_stream() {
    let (stream, expected) = stored_stream(5, 4, 3000);
    let needed = expected.len() as u64;
    let cell = RefCell::new(source(&stream));
    let mut planner = planner_over(&cell, &stream, needed, 1);
    let (mut offset, mut output, mut units) = (0, 0, 0);
    while let Some(planned) = planner.next_unit(needed).unwrap() {
        let PlannedUnit::Buffered(unit) = planned else {
            panic!("unexpected tail {planned:?}");
        };
        assert_eq!(unit.offset, offset);
        assert_eq!(
            stream[usize::try_from(unit.offset).unwrap()],
            1,
            "a run opens with a reset"
        );
        offset += unit.packed;
        output += unit.output;
        units += 1;
    }
    assert_eq!(units, 5);
    assert_eq!(output, needed);
    assert_eq!(
        offset,
        stream.len() as u64 - 1,
        "the end marker is left out"
    );
}

#[test]
fn test_min_unit_coalesces_runs() {
    let (stream, expected) = stored_stream(8, 1, 1000);
    let needed = expected.len() as u64;
    let cell = RefCell::new(source(&stream));
    let mut planner = planner_over(&cell, &stream, needed, 2500);
    let mut sizes = Vec::new();
    while let Some(PlannedUnit::Buffered(unit)) = planner.next_unit(needed).unwrap() {
        sizes.push(unit.output);
    }
    assert_eq!(sizes, [3000, 3000, 2000]);
}

#[test]
fn test_unit_charge_covers_packed_output_and_window() {
    let unit = Lzma2Unit {
        offset: 0,
        packed: 1000,
        output: 4_000_000,
    };
    let charge = unit.charge(1 << 24).unwrap();
    assert_eq!(charge.retained, 4_000_000);
    let window = 8_000_000u64;
    assert_eq!(charge.transient, 1000 + window + window / 2 + UNIT_OVERHEAD);
    let small = Lzma2Unit {
        offset: 0,
        packed: 10,
        output: 10,
    };
    assert_eq!(
        small.charge(1 << 24).unwrap().transient,
        10 + MIN_WINDOW + MIN_WINDOW / 2 + UNIT_OVERHEAD
    );
    assert_eq!(
        small.charge(4096).unwrap().transient,
        10 + 2 * 4096 + UNIT_OVERHEAD
    );
}

#[test]
fn test_lookahead_acquire_and_release() {
    let mut lookahead = Lookahead { free: 100 };
    let charge = UnitCharge {
        transient: 30,
        retained: 40,
    };
    assert!(lookahead.acquire(charge));
    assert_eq!(lookahead.free, 30);
    assert!(!lookahead.acquire(charge));
    lookahead.release(30);
    assert!(!lookahead.acquire(UnitCharge {
        transient: 30,
        retained: 40
    }));
    lookahead.release(40);
    assert!(lookahead.acquire(charge));
    assert!(!lookahead.acquire(UnitCharge {
        transient: u64::MAX,
        retained: 1
    }));
}

/// A source that counts its seeks.
struct CountingSource {
    inner: Cursor<Vec<u8>>,
    seeks: std::rc::Rc<std::cell::Cell<usize>>,
}

impl Read for CountingSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Seek for CountingSource {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.seeks.set(self.seeks.get() + 1);
        self.inner.seek(pos)
    }
}

#[test]
fn test_planner_reads_headers_through_a_window_not_one_seek_each() {
    let (stream, expected) = stored_stream(1, 100_000, 1);
    let needed = expected.len() as u64;
    let seeks = std::rc::Rc::new(std::cell::Cell::new(0));
    let cell = RefCell::new(CountingSource {
        inner: source(&stream),
        seeks: seeks.clone(),
    });
    let mut planner = Lzma2Planner::new(
        PackSource {
            source: &cell,
            stream: description(&stream, needed),
        },
        1,
    );
    while planner.next_unit(needed).unwrap().is_some() {}

    let windows = stream.len() / usize::try_from(PLAN_WINDOW).unwrap() + 2;
    assert!(
        seeks.get() <= windows,
        "{} seeks for {} bytes of 1-byte chunks",
        seeks.get(),
        stream.len()
    );
}

#[test]
fn test_reader_is_poisoned_after_an_error() {
    let (mut stream, expected) = stored_stream(4, 2, 3000);
    stream[2 * 2 * 3003] = 0x03;
    let outcome = with_parallel_reader(
        source(&stream),
        description(&stream, expected.len() as u64),
        knobs(1, 3),
        1 << 20,
        |reader| {
            let mut sink = Vec::new();
            let first = reader.read_to_end(&mut sink);
            let mut byte = [0u8; 1];
            (first.is_err(), reader.read(&mut byte).is_err())
        },
    );
    assert_eq!(outcome, (true, true));
}

#[test]
fn test_stream_longer_than_needed_ignores_the_rest() {
    let (stream, expected) = stored_stream(4, 2, 4000);
    let needed = 2 * 4000 * 2;
    let out = parallel(&stream, needed, knobs(1, 3), 1 << 20).unwrap();
    assert_eq!(out, expected[..usize::try_from(needed).unwrap()]);
}

#[test]
fn test_chunk_crossing_needed_is_decoded_inline_as_a_tail() {
    let (stream, expected) = stored_stream(3, 2, 4000);
    let needed = 4000 * 3 + 123;
    let cell = RefCell::new(source(&stream));
    let mut planner = planner_over(&cell, &stream, needed, 1);
    let mut tail = None;
    while let Some(planned) = planner.next_unit(needed).unwrap() {
        if let PlannedUnit::Tail { offset } = planned {
            tail = Some(offset);
        }
    }
    assert_eq!(tail, Some(2 * 4003));
    let out = parallel(&stream, needed, knobs(1, 3), 1 << 20).unwrap();
    assert_eq!(out, expected[..usize::try_from(needed).unwrap()]);
}

#[test]
fn test_malformed_streams_fail_like_the_sequential_reader() {
    let (clean, expected) = stored_stream(4, 2, 3000);
    let len = expected.len() as u64;

    let mut bad_control = clean.clone();
    bad_control[2 * 2 * 3003] = 0x03;
    let truncated = clean[..clean.len() / 2 + 17].to_vec();
    let mut missing_end = clean.clone();
    missing_end.pop();
    let mut leading_non_reset = clean;
    leading_non_reset[0] = 2;
    let mut no_props = stored(true, &pattern(3000, 1));
    no_props.extend_from_slice(&[0xA0, 0, 9, 0, 9]);
    no_props.extend_from_slice(&[0; 10]);
    no_props.push(0);

    for (name, stream, needed) in [
        ("bad control byte", bad_control, len),
        ("truncated", truncated, len),
        ("missing end marker", missing_end, len),
        ("first chunk without reset", leading_non_reset, len),
        ("lzma chunk after a stored reset", no_props, 6000),
    ] {
        for threads in [2, 4] {
            let expected = sequential(&stream, needed);
            let actual = parallel(&stream, needed, knobs(1, threads), 1 << 20);
            assert_eq!(
                expected.is_ok(),
                actual.is_ok(),
                "{name}: {expected:?} {actual:?}"
            );
            if let (Ok(a), Ok(b)) = (&expected, &actual) {
                assert_eq!(a, b, "{name}");
            }
        }
    }
}

#[test]
fn test_missing_end_marker_is_not_needed_when_the_output_is_complete() {
    let (mut stream, expected) = stored_stream(4, 2, 3000);
    stream.pop();
    let out = parallel(&stream, expected.len() as u64, knobs(1, 3), 1 << 20).unwrap();
    assert_eq!(out, expected);
}

#[test]
fn test_plan_flood_of_tiny_runs_completes() {
    let (stream, expected) = stored_stream(3000, 1, 1);
    let out = parallel(&stream, expected.len() as u64, knobs(1, 4), 1 << 20).unwrap();
    assert_eq!(out, expected);
}

#[test]
fn test_unit_larger_than_the_budget_is_decoded_inline() {
    let (stream, expected) = stored_stream(4, 3, 20_000);
    let out = parallel(&stream, expected.len() as u64, knobs(1, 4), 1000).unwrap();
    assert_eq!(out, expected);
}

#[test]
fn test_worker_panic_is_an_error_not_a_panic() {
    let (stream, expected) = stored_stream(4, 2, 3000);
    let mut k = knobs(1, 3);
    k.fault = Some(WorkerFault::PanicOn(1));
    let err = parallel(&stream, expected.len() as u64, k, 1 << 20).unwrap_err();
    assert!(err.to_string().contains("panicked"), "{err}");
}

#[test]
fn test_worker_panic_after_an_early_consumer_exit_does_not_panic() {
    let (stream, expected) = stored_stream(6, 2, 3000);
    let mut k = knobs(1, 3);
    k.fault = Some(WorkerFault::PanicOn(2));
    let first = with_parallel_reader(
        source(&stream),
        description(&stream, expected.len() as u64),
        k,
        1 << 22,
        |reader| {
            let mut byte = [0u8; 1];
            reader.read_exact(&mut byte).map(|()| byte[0])
        },
    )
    .unwrap();
    assert_eq!(first, expected[0]);
}

#[test]
fn test_spawn_failure_falls_back_to_inline_decoding() {
    let (stream, expected) = stored_stream(5, 2, 3000);
    for failing in 0..4 {
        let mut k = knobs(1, 3);
        k.fault = Some(WorkerFault::SpawnFailsOn(failing));
        let out = parallel(&stream, expected.len() as u64, k, 1 << 20).unwrap();
        assert_eq!(out, expected, "spawn {failing} failing");
    }
}

#[test]
fn test_early_consumer_exit_joins_workers_in_flight() {
    let (stream, expected) = stored_stream(8, 2, 20_000);
    let first = with_parallel_reader(
        source(&stream),
        description(&stream, expected.len() as u64),
        knobs(1, 4),
        1 << 22,
        |reader| {
            let mut byte = [0u8; 1];
            reader.read_exact(&mut byte).map(|()| byte[0])
        },
    )
    .unwrap();
    assert_eq!(first, expected[0]);
}

#[test]
fn test_source_read_error_surfaces_as_a_read_error() {
    let (stream, expected) = stored_stream(4, 2, 3000);
    let short = &stream[..stream.len() - 100];
    let result = with_parallel_reader(
        Cursor::new(short.to_vec()),
        Lzma2Stream {
            offset: 0,
            len: stream.len() as u64,
            output_len: expected.len() as u64,
            dict_size: 1 << 16,
        },
        knobs(1, 3),
        1 << 20,
        |reader| io::copy(reader, &mut io::sink()),
    );
    assert!(result.is_err());
}

proptest! {
    #[test]
    fn prop_random_streams_match_the_sequential_reader(
        runs in proptest::collection::vec(
            (proptest::collection::vec(1usize..2000, 1..4), any::<u8>()), 1..12),
        min_unit in 1u64..5000,
        threads in 1usize..5,
        lookahead in prop_oneof![Just(0u64), Just(30_000u64), Just(1u64 << 22)],
        cut in 0usize..40,
    ) {
        let (mut stream, mut expected) = (Vec::new(), Vec::new());
        for (chunks, seed) in &runs {
            for (i, len) in chunks.iter().enumerate() {
                let data = pattern(*len, *seed);
                stream.extend(stored(i == 0, &data));
                expected.extend(data);
            }
        }
        stream.push(0);
        let needed = (expected.len() as u64).saturating_sub(cut as u64).max(1);
        assert_same_outcome(&stream, needed, knobs(min_unit, threads), lookahead);
    }
}
