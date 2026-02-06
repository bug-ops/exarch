//! Heap profiling for archive creation operations.
//!
//! Uses dhat to track all heap allocations during archive creation.
//! After running, open the generated `dhat-heap.json` in the dhat viewer:
//! <https://nnethercote.github.io/dh_view/dh_view.html>
//!
//! Usage:
//! ```sh
//! cargo run --example dhat_creation --release
//! cargo run --example dhat_creation --release -- tar
//! cargo run --example dhat_creation --release -- zip
//! ```

#![allow(unsafe_code, clippy::unwrap_used)]

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use exarch_core::create_archive;
use exarch_core::creation::CreationConfig;
use std::fs;

fn create_test_directory(root: &std::path::Path, file_count: usize, file_size: usize) {
    fs::create_dir_all(root).unwrap();
    let content = vec![0xAB_u8; file_size];

    for i in 0..file_count {
        fs::write(root.join(format!("file{i:04}.txt")), &content).unwrap();
    }
}

fn main() {
    let format = std::env::args().nth(1).unwrap_or_else(|| "zip".to_string());

    let file_count = 500;
    let file_size = 1024;

    let temp = tempfile::tempdir().unwrap();
    let source_dir = temp.path().join("source");
    create_test_directory(&source_dir, file_count, file_size);

    let extension = match format.as_str() {
        "tar" => "tar",
        "tar.gz" | "targz" => "tar.gz",
        "zip" => "zip",
        other => {
            eprintln!("Unknown format: {other}. Use 'tar', 'tar.gz', or 'zip'.");
            std::process::exit(1);
        }
    };

    let output = temp.path().join(format!("output.{extension}"));
    let config = CreationConfig::default();

    eprintln!("Profiling {extension} creation: {file_count} files x {file_size} bytes each");

    let _profiler = dhat::Profiler::new_heap();

    create_archive(&output, &[&source_dir], &config).unwrap();
}
