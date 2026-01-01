//! Benchmarks for progress callback overhead.
//!
//! Compares TAR and ZIP creation performance with and without progress
//! callbacks to measure overhead.

#![allow(clippy::unwrap_used)] // Allow unwrap in benchmarks for brevity

use criterion::Criterion;
use criterion::criterion_group;
use criterion::criterion_main;
use exarch_core::ProgressCallback;
use exarch_core::creation::CreationConfig;
use exarch_core::creation::tar::create_tar;
use exarch_core::creation::tar::create_tar_with_progress;
use exarch_core::creation::zip::create_zip;
use exarch_core::creation::zip::create_zip_with_progress;
use std::fs;
use std::hint::black_box;
use std::path::Path;
use tempfile::TempDir;

/// No-op progress callback for benchmarking.
struct NoOpProgress;

impl ProgressCallback for NoOpProgress {
    fn on_entry_start(&mut self, _path: &Path, _total: usize, _current: usize) {}

    fn on_bytes_written(&mut self, _bytes: u64) {}

    fn on_entry_complete(&mut self, _path: &Path) {}

    fn on_complete(&mut self) {}
}

/// Progress callback that actually does work (logging to a counter).
struct CountingProgress {
    entries: usize,
    bytes: u64,
}

impl ProgressCallback for CountingProgress {
    fn on_entry_start(&mut self, _path: &Path, _total: usize, _current: usize) {
        self.entries += 1;
    }

    fn on_bytes_written(&mut self, bytes: u64) {
        self.bytes += bytes;
    }

    fn on_entry_complete(&mut self, _path: &Path) {}

    fn on_complete(&mut self) {}
}

/// Creates a test directory with specified number of files.
fn create_test_directory(temp: &TempDir, file_count: usize, file_size: usize) {
    let root = temp.path();

    for i in 0..file_count {
        let content = "x".repeat(file_size);
        fs::write(root.join(format!("file_{i}.txt")), content).unwrap();
    }
}

fn benchmark_tar_no_progress(c: &mut Criterion) {
    let source = TempDir::new().unwrap();
    create_test_directory(&source, 100, 1024); // 100 files, 1 KB each

    let config = CreationConfig::default();

    c.bench_function("tar_creation_no_progress", |b| {
        b.iter(|| {
            let output = TempDir::new().unwrap();
            let archive = output.path().join("test.tar");
            black_box(create_tar(&archive, &[source.path()], &config).unwrap());
        });
    });
}

fn benchmark_tar_with_noop_progress(c: &mut Criterion) {
    let source = TempDir::new().unwrap();
    create_test_directory(&source, 100, 1024); // 100 files, 1 KB each

    let config = CreationConfig::default();

    c.bench_function("tar_creation_noop_progress", |b| {
        b.iter(|| {
            let output = TempDir::new().unwrap();
            let archive = output.path().join("test.tar");
            let mut progress = NoOpProgress;
            black_box(
                create_tar_with_progress(&archive, &[source.path()], &config, &mut progress)
                    .unwrap(),
            );
        });
    });
}

fn benchmark_tar_with_counting_progress(c: &mut Criterion) {
    let source = TempDir::new().unwrap();
    create_test_directory(&source, 100, 1024); // 100 files, 1 KB each

    let config = CreationConfig::default();

    c.bench_function("tar_creation_counting_progress", |b| {
        b.iter(|| {
            let output = TempDir::new().unwrap();
            let archive = output.path().join("test.tar");
            let mut progress = CountingProgress {
                entries: 0,
                bytes: 0,
            };
            black_box(
                create_tar_with_progress(&archive, &[source.path()], &config, &mut progress)
                    .unwrap(),
            );
        });
    });
}

fn benchmark_zip_no_progress(c: &mut Criterion) {
    let source = TempDir::new().unwrap();
    create_test_directory(&source, 100, 1024); // 100 files, 1 KB each

    let config = CreationConfig::default();

    c.bench_function("zip_creation_no_progress", |b| {
        b.iter(|| {
            let output = TempDir::new().unwrap();
            let archive = output.path().join("test.zip");
            black_box(create_zip(&archive, &[source.path()], &config).unwrap());
        });
    });
}

fn benchmark_zip_with_noop_progress(c: &mut Criterion) {
    let source = TempDir::new().unwrap();
    create_test_directory(&source, 100, 1024); // 100 files, 1 KB each

    let config = CreationConfig::default();

    c.bench_function("zip_creation_noop_progress", |b| {
        b.iter(|| {
            let output = TempDir::new().unwrap();
            let archive = output.path().join("test.zip");
            let mut progress = NoOpProgress;
            black_box(
                create_zip_with_progress(&archive, &[source.path()], &config, &mut progress)
                    .unwrap(),
            );
        });
    });
}

fn benchmark_zip_with_counting_progress(c: &mut Criterion) {
    let source = TempDir::new().unwrap();
    create_test_directory(&source, 100, 1024); // 100 files, 1 KB each

    let config = CreationConfig::default();

    c.bench_function("zip_creation_counting_progress", |b| {
        b.iter(|| {
            let output = TempDir::new().unwrap();
            let archive = output.path().join("test.zip");
            let mut progress = CountingProgress {
                entries: 0,
                bytes: 0,
            };
            black_box(
                create_zip_with_progress(&archive, &[source.path()], &config, &mut progress)
                    .unwrap(),
            );
        });
    });
}

criterion_group!(
    benches,
    benchmark_tar_no_progress,
    benchmark_tar_with_noop_progress,
    benchmark_tar_with_counting_progress,
    benchmark_zip_no_progress,
    benchmark_zip_with_noop_progress,
    benchmark_zip_with_counting_progress
);
criterion_main!(benches);
