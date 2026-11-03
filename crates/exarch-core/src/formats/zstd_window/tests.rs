#![allow(clippy::unwrap_used)]

use std::assert_matches;
use std::io::Cursor;
use std::io::Write;

use super::*;

const LOGS: [u32; 5] = [10, 16, 20, 26, 27];
const RAW_BLOCK_LIMIT: usize = 128 * 1024;

fn block_header(last: bool, kind: u32, size: usize) -> [u8; 3] {
    let value = (u32::try_from(size).unwrap() << 3) | (kind << 1) | u32::from(last);
    let bytes = value.to_le_bytes();
    [bytes[0], bytes[1], bytes[2]]
}

fn frame_with_window(window_byte: u8, content: &[u8]) -> Vec<u8> {
    let mut frame = FRAME_MAGIC.to_le_bytes().to_vec();
    frame.extend_from_slice(&[0x00, window_byte]);
    frame.extend_from_slice(&block_header(true, 0, content.len()));
    frame.extend_from_slice(content);
    frame
}

fn single_segment_frame(flag: u8, stored_size: u64, size: usize) -> Vec<u8> {
    let mut frame = FRAME_MAGIC.to_le_bytes().to_vec();
    frame.push(0x20 | (flag << 6));
    let width = match flag {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    frame.extend_from_slice(&stored_size.to_le_bytes()[..width]);
    let mut left = size;
    loop {
        let chunk = left.min(RAW_BLOCK_LIMIT);
        left -= chunk;
        frame.extend_from_slice(&block_header(left == 0, 1, chunk));
        frame.push(b'x');
        if left == 0 {
            return frame;
        }
    }
}

fn walked(bytes: &[u8]) -> ZstdWindows {
    let len = u64::try_from(bytes.len()).unwrap();
    walk(
        &mut Cursor::new(bytes),
        [ZstdRange {
            data_start: 0,
            end: len,
        }],
        len,
    )
    .unwrap()
}

fn libzstd_admits(bytes: &[u8], log: u32) -> bool {
    let mut decoder = zstd::Decoder::with_buffer(bytes).unwrap();
    decoder.window_log_max(log).unwrap();
    io::copy(&mut decoder, &mut io::sink()).is_ok()
}

fn assert_walker_agrees_with_libzstd(bytes: &[u8], label: &str) {
    assert_walker_vs_libzstd(bytes, label, true);
}

/// The walker must never admit what libzstd refuses. It may refuse what
/// libzstd admits through its single-pass shortcut (a whole frame with a
/// small content size, decoded without a window check), so `exact` asks for
/// equality only where that shortcut cannot apply.
fn assert_walker_vs_libzstd(bytes: &[u8], label: &str, exact: bool) {
    let ZstdWindows::Largest(window) = walked(bytes) else {
        panic!("{label}: no window found");
    };
    for log in LOGS {
        let walker = ZstdWindowLog(log).admits(window);
        let libzstd = libzstd_admits(bytes, log);
        let context = format!("{label}, limit 2^{log}, window {}", window.bytes());
        if exact {
            assert_eq!(walker, libzstd, "{context}");
        } else {
            assert!(!walker || libzstd, "{context}");
        }
    }
}

fn real_frame(log: u32, checksum: bool) -> Vec<u8> {
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 0).unwrap();
    encoder.include_contentsize(false).unwrap();
    encoder.include_checksum(checksum).unwrap();
    encoder
        .set_parameter(zstd::zstd_safe::CParameter::WindowLog(log))
        .unwrap();
    encoder.write_all(b"hello hello hello").unwrap();
    encoder.finish().unwrap()
}

fn skippable(body: &[u8]) -> Vec<u8> {
    let mut frame = SKIPPABLE_MAGIC.to_le_bytes().to_vec();
    frame.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
    frame.extend_from_slice(body);
    frame
}

#[test]
fn the_log_follows_the_largest_power_of_two_within_memory() {
    for (memory, log) in [
        (0, 10),
        (1, 10),
        (1023, 10),
        (1024, 10),
        (2047, 10),
        (2048, 11),
        ((1 << 20) - 1, 19),
        (1 << 20, 20),
        (128 << 20, 27),
        ((256 << 20) - 1, 27),
        (u64::MAX, 27),
    ] {
        assert_eq!(ZstdWindowLog::for_memory(memory).get(), log, "{memory}");
    }
}

#[test]
fn every_window_descriptor_matches_libzstd_at_every_limit() {
    for exponent in 0u8..32 {
        for mantissa in 0u8..8 {
            let bytes = frame_with_window((exponent << 3) | mantissa, b"hello");
            assert_walker_agrees_with_libzstd(&bytes, &format!("{exponent}/{mantissa}"));
        }
    }
}

#[test]
fn single_segment_sizes_around_each_limit_match_libzstd() {
    for log in LOGS {
        for size in [(1usize << log) - 1, 1 << log, (1 << log) + 1] {
            let bytes = single_segment_frame(2, size as u64, size);
            assert_walker_vs_libzstd(&bytes, &format!("2^{log} {size}"), size > 64 * 1024);
        }
    }
}

#[test]
fn the_two_byte_content_size_adds_256() {
    let bytes = single_segment_frame(1, 1000 - 256, 1000);
    assert_walker_vs_libzstd(&bytes, "two byte size", false);
    assert_eq!(
        walked(&bytes),
        ZstdWindows::Largest(ZstdWindow::of_bytes(1000))
    );
}

#[test]
fn a_dictionary_id_is_skipped_to_find_the_next_frame() {
    let mut first = FRAME_MAGIC.to_le_bytes().to_vec();
    first.extend_from_slice(&[0x01, 0x00, 0x00]);
    first.extend_from_slice(&block_header(true, 0, 0));
    let second = frame_with_window(0x48, b"x");
    let bytes = [first, second].concat();
    assert_eq!(
        walked(&bytes),
        ZstdWindows::Largest(ZstdWindow::of_bytes(1 << 19))
    );
}

#[test]
fn frames_with_checksums_and_skippable_frames_between_are_walked() {
    let bytes = [
        real_frame(16, true),
        skippable(b"padding"),
        real_frame(22, true),
        skippable(&[]),
    ]
    .concat();
    assert_eq!(
        walked(&bytes),
        ZstdWindows::Largest(ZstdWindow::of_bytes(1 << 22))
    );
}

#[test]
fn an_oversized_frame_right_after_the_first_is_found() {
    let bytes = [real_frame(16, false), real_frame(28, false)].concat();
    let ZstdWindows::Largest(window) = walked(&bytes) else {
        panic!("no window");
    };
    assert!(!ZstdWindowLog::LIBZSTD_DEFAULT.admits(window));
}

#[test]
fn the_walk_stops_at_the_first_byte_sequence_that_is_not_a_frame() {
    let bytes = [
        real_frame(16, false),
        b"not a frame".to_vec(),
        real_frame(28, false),
    ]
    .concat();
    assert_eq!(
        walked(&bytes),
        ZstdWindows::Largest(ZstdWindow::of_bytes(1 << 16))
    );
}

#[test]
fn a_skippable_frame_declaring_more_than_the_range_ends_the_walk() {
    let mut bytes = SKIPPABLE_MAGIC.to_le_bytes().to_vec();
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    bytes.extend_from_slice(&real_frame(28, false));
    assert_eq!(walked(&bytes), ZstdWindows::Largest(ZstdWindow::MIN));
}

#[test]
fn no_zstd_entries_and_empty_ranges_are_told_apart() {
    let none = walk(&mut Cursor::new(Vec::<u8>::new()), [], 10).unwrap();
    assert_eq!(none, ZstdWindows::NoZstdEntries);
    let empty = walk(
        &mut Cursor::new(Vec::<u8>::new()),
        [ZstdRange {
            data_start: 0,
            end: 0,
        }],
        10,
    )
    .unwrap();
    assert_eq!(empty, ZstdWindows::Largest(ZstdWindow::MIN));
}

#[test]
fn disjoint_entries_within_the_extent_are_walked_in_full() {
    let first = real_frame(16, false);
    let second = real_frame(20, false);
    let split = u64::try_from(first.len()).unwrap();
    let total = split + u64::try_from(second.len()).unwrap();
    let bytes = [first, second].concat();
    let found = walk(
        &mut Cursor::new(bytes),
        [
            ZstdRange {
                data_start: 0,
                end: split,
            },
            ZstdRange {
                data_start: split,
                end: total,
            },
        ],
        total,
    )
    .unwrap();
    assert_eq!(found, ZstdWindows::Largest(ZstdWindow::of_bytes(1 << 20)));
}

#[test]
fn entries_sharing_a_run_of_empty_blocks_exhaust_the_budget_quickly() {
    let mut bytes = FRAME_MAGIC.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0x00, 0x00]);
    bytes.extend(std::iter::repeat_n(0u8, 3 * 100_000));
    let len = u64::try_from(bytes.len()).unwrap();
    let found = walk(
        &mut Cursor::new(bytes),
        (0..5_000).map(|_| ZstdRange {
            data_start: 0,
            end: len,
        }),
        len,
    )
    .unwrap();
    assert_matches!(found, ZstdWindows::OverBudget);
}

fn walked_with_budget(bytes: &[u8], budget: u64) -> ZstdWindows {
    walk(
        &mut Cursor::new(bytes),
        [ZstdRange {
            data_start: 0,
            end: u64::try_from(bytes.len()).unwrap(),
        }],
        budget,
    )
    .unwrap()
}

#[test]
fn any_stop_caused_by_the_budget_is_over_budget_never_a_partial_window() {
    let frame = real_frame(28, false);
    let skippable = skippable(&[0u8; 64]);
    let streams = [
        [skippable, frame.clone()].concat(),
        [real_frame(16, false), frame.clone()].concat(),
        frame,
    ];
    for bytes in streams {
        let len = u64::try_from(bytes.len()).unwrap();
        for budget in 1..len {
            assert_eq!(
                walked_with_budget(&bytes, budget),
                ZstdWindows::OverBudget,
                "budget {budget} of {len}"
            );
        }
        assert_matches!(walked_with_budget(&bytes, len), ZstdWindows::Largest(_));
    }
}

#[test]
fn legacy_frame_magics_get_an_unbounded_window() {
    for magic in [0xFD2F_B51Eu32, 0xFD2F_B522, 0xFD2F_B525, 0xFD2F_B527] {
        let mut bytes = magic.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 16]);
        let ZstdWindows::Largest(window) = walked(&bytes) else {
            panic!("{magic:#x}: no window");
        };
        assert!(!ZstdWindowLog::LIBZSTD_DEFAULT.admits(window), "{magic:#x}");
    }
    for magic in [0xFD2F_B51Du32, 0xFD2F_B521, 0xFD2F_B528 + 1] {
        let mut bytes = magic.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 16]);
        assert_eq!(walked(&bytes), ZstdWindows::Largest(ZstdWindow::MIN));
    }
}
