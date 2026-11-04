//! `SinkOptions::decode_reuse` reaches the ZIP structural check on the callback
//! path (#890).
//!
//! A reverted wiring leaves every mode behaving as `Off`, which the peak heap
//! shows: a kept entry sits in the store next to the entry being delivered. The
//! test binary is its own because `#[global_allocator]` is process-wide, and
//! one test function owns the profiler.

#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

mod common;

use std::num::NonZeroU64;

use exarch_core::ArchiveReader;
use exarch_core::DecodeReuse;
use exarch_core::MemoryExtractRequest;
use exarch_core::NoopProgress;
use exarch_core::ReuseLimit;
use exarch_core::SinkOptions;
use exarch_core::extract_reader_to_callback;

const ENTRIES: usize = 64;
const ENTRY_LEN: usize = 256 * 1024;
const DECODED: u64 = (ENTRIES * ENTRY_LEN) as u64;
const HEADROOM: u64 = 2 * 1024 * 1024;

fn peak_heap(archive: &[u8], reuse: DecodeReuse) -> u64 {
    let reader = ArchiveReader::from_bytes(archive.to_vec(), None).unwrap();
    let request = MemoryExtractRequest::default()
        .with_options(SinkOptions::default().with_decode_reuse(reuse));
    let mut delivered = 0u64;

    let _profiler = dhat::Profiler::builder().testing().build();
    extract_reader_to_callback(
        reader,
        &request,
        |_, entry| {
            if let exarch_core::CallbackEntry::Stored(exarch_core::MemoryEntry::File {
                data, ..
            }) = entry
            {
                delivered += data.len() as u64;
            }
            Ok::<(), ()>(())
        },
        &mut NoopProgress,
    )
    .unwrap();
    let peak = dhat::HeapStats::get().max_bytes;

    assert_eq!(delivered, DECODED, "{reuse:?}");
    peak as u64
}

fn limit(bytes: u64) -> ReuseLimit {
    ReuseLimit::new(NonZeroU64::new(bytes).unwrap())
}

#[test]
fn the_sink_options_decode_reuse_decides_what_the_structural_check_keeps() {
    let archive = common::deflated_zip(ENTRIES, ENTRY_LEN);

    let off = peak_heap(&archive, DecodeReuse::Off);
    let kept_all = peak_heap(&archive, DecodeReuse::Memory(ReuseLimit::MAX));
    let tiny = peak_heap(&archive, DecodeReuse::Memory(limit(1024)));
    let below_entry = peak_heap(&archive, DecodeReuse::Memory(limit(ENTRY_LEN as u64 / 2)));
    let bounded_bytes = DECODED / 4;
    let bounded = peak_heap(&archive, DecodeReuse::Memory(limit(bounded_bytes)));
    let spooled = peak_heap(&archive, DecodeReuse::TempFile(ReuseLimit::MAX));

    assert!(
        kept_all >= off + DECODED / 2,
        "memory(MAX) kept nothing: {kept_all} bytes against {off} with Off"
    );
    assert!(
        tiny <= off + HEADROOM,
        "a 1 KiB limit kept an entry: {tiny} bytes against {off}"
    );
    assert!(
        below_entry <= off + HEADROOM,
        "an entry above the limit was kept: {below_entry} bytes against {off}"
    );
    assert!(
        bounded >= off + bounded_bytes / 2 && bounded <= off + bounded_bytes + HEADROOM,
        "a {bounded_bytes} byte limit gave {bounded} bytes against {off} with Off"
    );
    assert!(
        spooled <= off + HEADROOM,
        "temp file kept the decoded archive on the heap: {spooled} bytes against {off}"
    );
}
