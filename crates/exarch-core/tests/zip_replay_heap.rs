//! Keeping the census output of a ZIP costs bounded heap (#857).
//!
//! `DecodeReuse::TempFile` keeps the decoded entries on disk, so the heap stays
//! flat however much is kept; `DecodeReuse::Memory` holds at most its limit.
//! The test binary is its own because `#[global_allocator]` is process-wide,
//! and one test function owns the profiler.

#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

mod common;

use std::path::Path;

use exarch_core::DecodeReuse;
use exarch_core::ExtractionOptions;
use exarch_core::ReuseLimit;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive_with_options;
use tempfile::TempDir;

const ENTRIES: usize = 2048;
const ENTRY_LEN: usize = 16 * 1024;
const DECODED: u64 = (ENTRIES * ENTRY_LEN) as u64;
const HEADROOM: u64 = 8 * 1024 * 1024;

fn peak_heap(archive: &Path, reuse: DecodeReuse) -> u64 {
    let dest = TempDir::new().unwrap();
    let options = ExtractionOptions::default().with_decode_reuse(reuse);
    let config = SecurityConfig::default();

    let _profiler = dhat::Profiler::builder().testing().build();
    let report = extract_archive_with_options(archive, dest.path(), &config, &options).unwrap();
    let peak = dhat::HeapStats::get().max_bytes;

    assert_eq!(report.files_extracted, ENTRIES);
    assert_eq!(report.bytes_written, DECODED);
    peak as u64
}

#[test]
fn kept_output_stays_within_its_heap_budget() {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("big.zip");
    std::fs::write(&archive, common::deflated_zip(ENTRIES, ENTRY_LEN)).unwrap();

    let off = peak_heap(&archive, DecodeReuse::Off);
    let spooled = peak_heap(&archive, DecodeReuse::TempFile(ReuseLimit::DEFAULT));
    let memory = peak_heap(&archive, DecodeReuse::Memory(ReuseLimit::DEFAULT));

    assert!(
        spooled <= off + HEADROOM,
        "temp file: {spooled} bytes against {off} without reuse"
    );
    assert!(
        spooled < HEADROOM,
        "temp file kept the decoded archive on the heap: {spooled} bytes"
    );
    assert!(
        memory <= ReuseLimit::DEFAULT.get() + HEADROOM,
        "memory: {memory} bytes over a {} byte limit",
        ReuseLimit::DEFAULT.get()
    );
}
