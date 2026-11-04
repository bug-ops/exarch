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
use std::sync::Mutex;
use std::sync::PoisonError;

use exarch_core::DecodeReuse;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::ReuseLimit;
use exarch_core::SecurityConfig;
use exarch_testkit::raw_zip::RawEntry;
use exarch_testkit::raw_zip::RawZip;
use exarch_testkit::raw_zip::deflate_zeros;
use tempfile::TempDir;

/// dhat allows one profiler at a time.
static PROFILER: Mutex<()> = Mutex::new(());

const ENTRIES: usize = 2048;
const ENTRY_LEN: usize = 16 * 1024;
const DECODED: u64 = (ENTRIES * ENTRY_LEN) as u64;
const HEADROOM: u64 = 8 * 1024 * 1024;

fn peak_heap(archive: &Path, reuse: DecodeReuse) -> u64 {
    let dest = TempDir::new().unwrap();
    let options = ExtractionOptions::default().with_decode_reuse(reuse);
    let config = SecurityConfig::default();

    let _profiler = dhat::Profiler::builder().testing().build();
    let report = ExtractRequest::new(&config)
        .with_options(options)
        .extract(archive, dest.path())
        .unwrap();
    let peak = dhat::HeapStats::get().max_bytes;

    assert_eq!(report.files_extracted, ENTRIES);
    assert_eq!(report.bytes_written, DECODED);
    peak as u64
}

#[test]
fn kept_output_stays_within_its_heap_budget() {
    let _only = PROFILER.lock().unwrap_or_else(PoisonError::into_inner);
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

const ZEROS: u64 = 250 * 1024 * 1024;

fn zeros_zip(declared: u64) -> Vec<u8> {
    let mut crc = flate2::Crc::new();
    let chunk = vec![0u8; 1 << 20];
    let mut left = declared;
    while left > 0 {
        let take = usize::try_from(left.min(chunk.len() as u64)).unwrap();
        crc.update(&chunk[..take]);
        left -= take as u64;
    }
    let entry = RawEntry {
        method: 8,
        data: deflate_zeros(ZEROS),
        crc: crc.sum(),
        size: declared,
        ..RawEntry::stored("zeros.bin", b"")
    };
    RawZip::new(vec![entry]).build().bytes
}

/// Peak heap of an extraction that must be refused.
fn refused_peak(archive: &Path, reuse: DecodeReuse) -> u64 {
    let dest = TempDir::new().unwrap();
    let options = ExtractionOptions::default().with_decode_reuse(reuse);
    let config = SecurityConfig::default();

    let _profiler = dhat::Profiler::builder().testing().build();
    let result = ExtractRequest::new(&config)
        .with_options(options)
        .extract(archive, dest.path());
    let peak = dhat::HeapStats::get().max_bytes;

    assert!(result.is_err(), "the extraction must be refused");
    peak as u64
}

#[test]
fn entries_the_limits_refuse_are_never_kept() {
    let _only = PROFILER.lock().unwrap_or_else(PoisonError::into_inner);
    let dir = TempDir::new().unwrap();
    for (name, declared) in [("honest", ZEROS), ("forged", 1024)] {
        let archive = dir.path().join(format!("{name}.zip"));
        std::fs::write(&archive, zeros_zip(declared)).unwrap();

        let off = refused_peak(&archive, DecodeReuse::Off);
        for reuse in [
            DecodeReuse::Memory(ReuseLimit::MAX),
            DecodeReuse::TempFile(ReuseLimit::MAX),
        ] {
            let peak = refused_peak(&archive, reuse);
            assert!(
                peak <= off + HEADROOM,
                "{name} {reuse:?}: {peak} bytes against {off} without reuse"
            );
        }
    }
}
