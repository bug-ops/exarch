//! Benchmarks for exarch-core extraction.
//!
//! CRIT-006: Comprehensive extraction benchmarks for measuring optimization
//! effectiveness.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::BenchmarkId;
use criterion::Criterion;
use criterion::Throughput;
use criterion::criterion_group;
use criterion::criterion_main;
use exarch_core::SecurityConfig;
use exarch_core::formats::ZipArchive;
use exarch_core::formats::traits::ArchiveFormat;
use std::io::Cursor;
use std::io::Write;
use tempfile::TempDir;
use zip::write::SimpleFileOptions;
use zip::write::ZipWriter;

/// Creates a ZIP archive with many small files.
fn create_many_small_files_zip(file_count: usize) -> Vec<u8> {
    let buffer = Vec::new();
    let mut zip = ZipWriter::new(Cursor::new(buffer));
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    for i in 0..file_count {
        let filename = format!("file{i:04}.txt");
        zip.start_file(&filename, options).unwrap();
        zip.write_all(format!("content{i}").as_bytes()).unwrap();
    }

    zip.finish().unwrap().into_inner()
}

/// Creates a ZIP archive with a single large file.
fn create_large_file_zip(size_bytes: usize) -> Vec<u8> {
    let buffer = Vec::new();
    let mut zip = ZipWriter::new(Cursor::new(buffer));
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    zip.start_file("large_file.bin", options).unwrap();
    let data = vec![0xAB_u8; size_bytes];
    zip.write_all(&data).unwrap();

    zip.finish().unwrap().into_inner()
}

/// Creates a ZIP archive with nested directory structure.
fn create_nested_dirs_zip(depth: usize, files_per_dir: usize) -> Vec<u8> {
    let buffer = Vec::new();
    let mut zip = ZipWriter::new(Cursor::new(buffer));
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    fn add_level(
        zip: &mut ZipWriter<Cursor<Vec<u8>>>,
        options: SimpleFileOptions,
        current_depth: usize,
        max_depth: usize,
        prefix: &str,
        files_per_dir: usize,
    ) {
        if current_depth >= max_depth {
            return;
        }

        for i in 0..files_per_dir {
            let filename = format!("{prefix}file{i}.txt");
            zip.start_file(&filename, options).unwrap();
            zip.write_all(b"content").unwrap();
        }

        let next_prefix = format!("{prefix}subdir/");
        add_level(
            zip,
            options,
            current_depth + 1,
            max_depth,
            &next_prefix,
            files_per_dir,
        );
    }

    add_level(&mut zip, options, 0, depth, "", files_per_dir);
    zip.finish().unwrap().into_inner()
}

/// Creates a ZIP archive with DEFLATE compressed data.
fn create_deflate_compressed_zip(size_bytes: usize) -> Vec<u8> {
    let buffer = Vec::new();
    let mut zip = ZipWriter::new(Cursor::new(buffer));
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    zip.start_file("compressed.bin", options).unwrap();
    // Highly compressible data (all zeros)
    let data = vec![0u8; size_bytes];
    zip.write_all(&data).unwrap();

    zip.finish().unwrap().into_inner()
}

fn benchmark_security_config(c: &mut Criterion) {
    c.bench_function("create_default_config", |b| {
        b.iter(SecurityConfig::default);
    });
}

fn benchmark_many_small_files(c: &mut Criterion) {
    let mut group = c.benchmark_group("many_small_files");

    for file_count in [100, 1000, 10000] {
        let zip_data = create_many_small_files_zip(file_count);
        group.throughput(Throughput::Elements(file_count as u64));

        group.bench_with_input(
            BenchmarkId::from_parameter(file_count),
            &zip_data,
            |b, data| {
                b.iter(|| {
                    let temp = TempDir::new().unwrap();
                    let cursor = Cursor::new(data.clone());
                    let mut archive = ZipArchive::new(cursor).unwrap();
                    archive
                        .extract(temp.path(), &SecurityConfig::default())
                        .unwrap();
                });
            },
        );
    }

    group.finish();
}

fn benchmark_large_files(c: &mut Criterion) {
    let mut group = c.benchmark_group("large_files");

    for size_mb in [1, 10, 100] {
        let size_bytes = size_mb * 1024 * 1024;
        let zip_data = create_large_file_zip(size_bytes);
        group.throughput(Throughput::Bytes(size_bytes as u64));

        group.bench_with_input(
            BenchmarkId::new("size_mb", size_mb),
            &zip_data,
            |b, data| {
                b.iter(|| {
                    let temp = TempDir::new().unwrap();
                    let cursor = Cursor::new(data.clone());
                    let mut archive = ZipArchive::new(cursor).unwrap();
                    archive
                        .extract(temp.path(), &SecurityConfig::default())
                        .unwrap();
                });
            },
        );
    }

    group.finish();
}

fn benchmark_nested_directories(c: &mut Criterion) {
    let mut group = c.benchmark_group("nested_directories");

    for depth in [5, 10, 20] {
        let zip_data = create_nested_dirs_zip(depth, 2);
        group.throughput(Throughput::Elements(depth as u64 * 2));

        group.bench_with_input(BenchmarkId::from_parameter(depth), &zip_data, |b, data| {
            b.iter(|| {
                let temp = TempDir::new().unwrap();
                let cursor = Cursor::new(data.clone());
                let mut archive = ZipArchive::new(cursor).unwrap();
                archive
                    .extract(temp.path(), &SecurityConfig::default())
                    .unwrap();
            });
        });
    }

    group.finish();
}

fn benchmark_compression_methods(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression_methods");

    let size_bytes = 10 * 1024 * 1024; // 10 MB
    group.throughput(Throughput::Bytes(size_bytes as u64));

    // Stored (no compression)
    let stored_zip = create_large_file_zip(size_bytes);
    group.bench_with_input(
        BenchmarkId::new("method", "stored"),
        &stored_zip,
        |b, data| {
            b.iter(|| {
                let temp = TempDir::new().unwrap();
                let cursor = Cursor::new(data.clone());
                let mut archive = ZipArchive::new(cursor).unwrap();
                archive
                    .extract(temp.path(), &SecurityConfig::default())
                    .unwrap();
            });
        },
    );

    // DEFLATE compression
    let deflate_zip = create_deflate_compressed_zip(size_bytes);
    group.bench_with_input(
        BenchmarkId::new("method", "deflate"),
        &deflate_zip,
        |b, data| {
            b.iter(|| {
                let temp = TempDir::new().unwrap();
                let cursor = Cursor::new(data.clone());
                let mut archive = ZipArchive::new(cursor).unwrap();
                archive
                    .extract(temp.path(), &SecurityConfig::default())
                    .unwrap();
            });
        },
    );

    group.finish();
}

criterion_group!(
    benches,
    benchmark_security_config,
    benchmark_many_small_files,
    benchmark_large_files,
    benchmark_nested_directories,
    benchmark_compression_methods
);
criterion_main!(benches);
