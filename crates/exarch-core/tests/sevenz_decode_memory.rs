//! 7z extraction keeps peak heap bounded whatever the LZMA2 chunk layout
//! (#657, #673).
//!
//! sevenz-rust2's own multi-threaded LZMA2 reader buffers each whole work unit
//! with no output bound. exarch decodes sequentially under
//! `ParallelDecode::Sequential` and, otherwise, decodes runs ahead on worker
//! threads within the configured lookahead. Peak heap is measured with a
//! counting allocator; the test binary is its own because `#[global_allocator]`
//! is process-wide, and one test function owns the profiler.

#![allow(clippy::unwrap_used)]

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use std::io::Cursor;
use std::num::NonZeroU64;
use std::path::Path;

use exarch_core::ParallelDecode;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use sevenz_rust2::EncoderConfiguration;
use sevenz_rust2::EncoderMethod;
use sevenz_rust2::SourceReader;
use sevenz_rust2::encoder_options::Lzma2Options;
use tempfile::TempDir;

const CHUNK: u64 = 16 * 1024 * 1024;
const OUTPUT: usize = 64 * 1024 * 1024;
const WRITER_THREADS: u32 = 4;

fn multi_chunk_lzma2_archive() -> Vec<u8> {
    let mut options = Lzma2Options::from_level_mt(1, WRITER_THREADS, CHUNK);
    options.set_dictionary_size(64 * 1024);
    let pattern: Vec<u8> = (0..=u8::MAX).map(|b| b.wrapping_mul(31) >> 3).collect();
    let data: Vec<u8> = pattern.iter().copied().cycle().take(OUTPUT).collect();

    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    writer.set_content_methods(vec![
        EncoderConfiguration::new(EncoderMethod::LZMA2).with_options(options.into()),
    ]);
    let mut entry = ArchiveEntry::new_file("big");
    entry.has_stream = true;
    entry.size = data.len() as u64;
    writer
        .push_archive_entry(entry, Some(SourceReader::from(Cursor::new(data))))
        .unwrap();
    writer.finish().unwrap().into_inner()
}

fn bounded(bytes: u64) -> ParallelDecode {
    ParallelDecode::Bounded(NonZeroU64::new(bytes).unwrap())
}

/// Peak heap bytes of extracting `archive` under `parallel`.
fn peak_heap(archive: &Path, parallel: ParallelDecode) -> u64 {
    let dest = TempDir::new().unwrap();
    let config = SecurityConfig::default()
        .with_max_file_size(1 << 30)
        .with_max_total_size(1 << 30)
        .with_max_compression_ratio(1_000_000.0)
        .with_parallel_decode(parallel);

    let _profiler = dhat::Profiler::builder().testing().build();
    extract_archive(archive, dest.path(), &config).unwrap();
    let peak = dhat::HeapStats::get().max_bytes;

    assert_eq!(
        std::fs::metadata(dest.path().join("big")).unwrap().len(),
        OUTPUT as u64
    );
    peak as u64
}

#[test]
fn extract_peak_heap_follows_the_decode_mode() {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("big.7z");
    std::fs::write(&archive, multi_chunk_lzma2_archive()).unwrap();

    let sequential = peak_heap(&archive, ParallelDecode::Sequential);
    assert!(
        sequential < CHUNK / 2,
        "sequential peak heap {sequential} bytes shows work units buffered in memory"
    );

    // 40 MiB fits two of the 16 MiB runs next to the head's window.
    let lookahead = 40 * 1024 * 1024;
    let ahead = peak_heap(&archive, bounded(lookahead));
    let slack = 8 * 1024 * 1024;
    assert!(
        ahead <= lookahead + slack,
        "peak heap {ahead} bytes exceeds the {lookahead} byte lookahead"
    );
    if std::thread::available_parallelism().is_ok_and(|n| n.get() > 1) {
        assert!(
            ahead >= CHUNK,
            "peak heap {ahead} bytes shows no run was decoded ahead"
        );
    }

    let tiny = peak_heap(&archive, bounded(1024 * 1024));
    assert!(
        tiny < CHUNK / 2,
        "peak heap {tiny} bytes with a lookahead smaller than a run"
    );
}
