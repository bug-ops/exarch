//! 7z extraction decodes on one thread so memory stays bounded (#657).
//!
//! With more than one decoder thread, sevenz-rust2 reads an LZMA2 archive with
//! a multi-threaded reader whose workers buffer each whole work unit in memory
//! with no output bound. A multi-chunk LZMA2 archive therefore makes peak heap
//! grow with the chunk size and thread count, whatever `max_decoder_memory`
//! says. Peak heap is measured with a counting allocator; the test binary is
//! its own because `#[global_allocator]` is process-wide.

#![allow(clippy::unwrap_used)]

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use std::io::Cursor;

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

#[test]
fn extract_does_not_buffer_whole_lzma2_work_units() {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("big.7z");
    std::fs::write(&archive, multi_chunk_lzma2_archive()).unwrap();
    let dest = dir.path().join("out");
    let config = SecurityConfig::default()
        .with_max_file_size(1 << 30)
        .with_max_total_size(1 << 30)
        .with_max_compression_ratio(1_000_000.0);

    let _profiler = dhat::Profiler::builder().testing().build();
    extract_archive(&archive, &dest, &config).unwrap();
    let peak = dhat::HeapStats::get().max_bytes;

    assert_eq!(
        std::fs::metadata(dest.join("big")).unwrap().len(),
        OUTPUT as u64
    );
    // A multi-threaded decode holds at least one whole 16 MiB work unit.
    assert!(
        (peak as u64) < CHUNK / 2,
        "peak heap {peak} bytes shows work units buffered in memory"
    );
}
