//! Heap profiling for archive extraction operations.
//!
//! Uses dhat to track all heap allocations during extraction.
//! After running, open the generated `dhat-heap.json` in the dhat viewer:
//! <https://nnethercote.github.io/dh_view/dh_view.html>
//!
//! Usage:
//! ```sh
//! cargo run --example dhat_extraction --release
//! cargo run --example dhat_extraction --release -- zip
//! cargo run --example dhat_extraction --release -- tar
//! ```

#![allow(unsafe_code, clippy::unwrap_used)]

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use exarch_core::ExtractRequest;
use exarch_core::SecurityConfig;
use std::io::Cursor;
use std::io::Write;
use zip::write::SimpleFileOptions;
use zip::write::ZipWriter;

fn create_zip_in_memory(file_count: usize, file_size: usize) -> Vec<u8> {
    let buffer = Vec::new();
    let mut zip = ZipWriter::new(Cursor::new(buffer));
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let content = vec![0xAB_u8; file_size];

    for i in 0..file_count {
        let filename = format!("file{i:04}.txt");
        zip.start_file(&filename, options).unwrap();
        zip.write_all(&content).unwrap();
    }

    zip.finish().unwrap().into_inner()
}

fn create_tar_in_memory(file_count: usize, file_size: usize) -> Vec<u8> {
    let buffer = Vec::new();
    let mut builder = tar::Builder::new(buffer);
    let content = vec![0xAB_u8; file_size];

    for i in 0..file_count {
        let filename = format!("file{i:04}.txt");
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, &filename, &content[..])
            .unwrap();
    }

    builder.into_inner().unwrap()
}

fn profile_extraction(file_name: &str, data: &[u8]) {
    let config = SecurityConfig::default();
    let work = tempfile::tempdir().unwrap();
    let archive = work.path().join(file_name);
    std::fs::write(&archive, data).unwrap();
    let dest = tempfile::tempdir().unwrap();

    let _profiler = dhat::Profiler::new_heap();

    ExtractRequest::new(&config)
        .extract(&archive, dest.path())
        .unwrap();
}

fn profile_zip_extraction(file_count: usize, file_size: usize) {
    profile_extraction("archive.zip", &create_zip_in_memory(file_count, file_size));
}

fn profile_tar_extraction(file_count: usize, file_size: usize) {
    profile_extraction("archive.tar", &create_tar_in_memory(file_count, file_size));
}

fn main() {
    let format = std::env::args().nth(1).unwrap_or_else(|| "zip".to_string());

    let file_count = 500;
    let file_size = 1024;

    eprintln!("Profiling {format} extraction: {file_count} files x {file_size} bytes each");

    match format.as_str() {
        "zip" => profile_zip_extraction(file_count, file_size),
        "tar" => profile_tar_extraction(file_count, file_size),
        other => {
            eprintln!("Unknown format: {other}. Use 'zip' or 'tar'.");
            std::process::exit(1);
        }
    }
}
