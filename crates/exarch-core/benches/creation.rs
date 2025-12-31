//! Benchmarks for archive creation performance.
//!
//! Measures creation throughput across different formats, compression levels,
//! and directory structures.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::similar_names,
    clippy::cast_sign_loss,
    clippy::uninlined_format_args,
    clippy::items_after_statements,
    clippy::redundant_closure_for_method_calls,
    clippy::iter_filter_is_ok
)]

use criterion::BenchmarkId;
use criterion::Criterion;
use criterion::Throughput;
use criterion::criterion_group;
use criterion::criterion_main;
use exarch_core::create_archive;
use exarch_core::creation::CreationConfig;
use exarch_core::creation::filters;
use exarch_core::creation::walker::FilteredWalker;
use exarch_core::formats::detect::ArchiveType;
use std::fs;
use std::hint::black_box;
use std::path::Path;
use tempfile::TempDir;

/// Creates a test directory with a specified number of files.
///
/// Each file contains 1 KB of data for realistic benchmarking.
fn create_test_directory(temp: &TempDir, file_count: usize) -> std::path::PathBuf {
    let dir = temp.path().join("bench_data");
    fs::create_dir_all(&dir).unwrap();

    // Create files with 1 KB each
    let content = "x".repeat(1024);
    for i in 0..file_count {
        fs::write(dir.join(format!("file_{:05}.txt", i)), &content).unwrap();
    }

    dir
}

/// Creates a nested directory structure for benchmarking.
///
/// Creates a tree with specified depth and files per level.
fn create_nested_directory(
    temp: &TempDir,
    depth: usize,
    files_per_level: usize,
) -> std::path::PathBuf {
    let root = temp.path().join("nested");
    fs::create_dir_all(&root).unwrap();

    fn create_level(base: &Path, current_depth: usize, max_depth: usize, files: usize) {
        if current_depth >= max_depth {
            return;
        }

        // Create files at this level
        let content = "content\n";
        for i in 0..files {
            fs::write(base.join(format!("file_{}.txt", i)), content).unwrap();
        }

        // Create subdirectory
        let subdir = base.join(format!("level_{}", current_depth + 1));
        fs::create_dir_all(&subdir).unwrap();
        create_level(&subdir, current_depth + 1, max_depth, files);
    }

    create_level(&root, 0, depth, files_per_level);
    root
}

/// Creates a directory with mixed file sizes.
fn create_mixed_size_directory(temp: &TempDir) -> std::path::PathBuf {
    let dir = temp.path().join("mixed");
    fs::create_dir_all(&dir).unwrap();

    // Small files (1 KB each)
    for i in 0..50 {
        fs::write(dir.join(format!("small_{}.txt", i)), "x".repeat(1024)).unwrap();
    }

    // Medium files (100 KB each)
    for i in 0..10 {
        fs::write(
            dir.join(format!("medium_{}.txt", i)),
            "x".repeat(100 * 1024),
        )
        .unwrap();
    }

    // Large files (1 MB each)
    for i in 0..3 {
        fs::write(
            dir.join(format!("large_{}.bin", i)),
            vec![0xAB; 1024 * 1024],
        )
        .unwrap();
    }

    dir
}

/// Creates directory with hidden files and exclude patterns.
fn create_filtered_directory(temp: &TempDir) -> std::path::PathBuf {
    let dir = temp.path().join("filtered");
    fs::create_dir_all(&dir).unwrap();

    // Normal files
    for i in 0..100 {
        fs::write(dir.join(format!("file_{}.txt", i)), "content").unwrap();
    }

    // Hidden files
    for i in 0..20 {
        fs::write(dir.join(format!(".hidden_{}", i)), "secret").unwrap();
    }

    // Files matching exclude patterns
    for i in 0..15 {
        fs::write(dir.join(format!("temp_{}.tmp", i)), "temp").unwrap();
    }

    fs::create_dir_all(dir.join(".git")).unwrap();
    fs::write(dir.join(".git/config"), "git config").unwrap();

    dir
}

fn benchmark_create_tar_formats(c: &mut Criterion) {
    let mut group = c.benchmark_group("tar_formats");
    let temp = TempDir::new().unwrap();
    let source_dir = create_test_directory(&temp, 100);

    let formats = [
        ("tar", ArchiveType::Tar),
        ("tar.gz", ArchiveType::TarGz),
        ("tar.bz2", ArchiveType::TarBz2),
        ("tar.xz", ArchiveType::TarXz),
        ("tar.zst", ArchiveType::TarZst),
    ];

    for (name, format) in formats {
        group.bench_with_input(BenchmarkId::new("format", name), &format, |b, format| {
            b.iter(|| {
                let output = temp.path().join(format!("output.{}", name));
                let config = CreationConfig::default().with_format(Some(*format));
                let _ = create_archive(
                    black_box(&output),
                    black_box(&[&source_dir]),
                    black_box(&config),
                );
                fs::remove_file(&output).ok();
            });
        });
    }

    group.finish();
}

fn benchmark_create_zip(c: &mut Criterion) {
    let temp = TempDir::new().unwrap();
    let source_dir = create_test_directory(&temp, 100);
    let config = CreationConfig::default();

    c.bench_function("create_zip_100_files", |b| {
        b.iter(|| {
            let output = temp.path().join("output.zip");
            let _ = create_archive(
                black_box(&output),
                black_box(&[&source_dir]),
                black_box(&config),
            );
            fs::remove_file(&output).ok();
        });
    });
}

fn benchmark_compression_levels(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression_levels");
    let temp = TempDir::new().unwrap();
    let source_dir = create_test_directory(&temp, 50);

    for level in [1, 3, 6, 9] {
        group.bench_with_input(
            BenchmarkId::new("tar.gz_level", level),
            &level,
            |b, level| {
                b.iter(|| {
                    let output = temp.path().join("output.tar.gz");
                    let config = CreationConfig::default()
                        .with_format(Some(ArchiveType::TarGz))
                        .with_compression_level(*level);
                    let _ = create_archive(
                        black_box(&output),
                        black_box(&[&source_dir]),
                        black_box(&config),
                    );
                    fs::remove_file(&output).ok();
                });
            },
        );
    }

    group.finish();
}

fn benchmark_file_counts(c: &mut Criterion) {
    let mut group = c.benchmark_group("file_counts");

    for file_count in [10, 100, 500, 1000] {
        let temp = TempDir::new().unwrap();
        let source_dir = create_test_directory(&temp, file_count);
        let config = CreationConfig::default();

        group.throughput(Throughput::Elements(file_count as u64));

        group.bench_with_input(BenchmarkId::new("tar", file_count), &file_count, |b, _| {
            b.iter(|| {
                let output = temp.path().join("output.tar");
                let _ = create_archive(
                    black_box(&output),
                    black_box(&[&source_dir]),
                    black_box(&config),
                );
                fs::remove_file(&output).ok();
            });
        });
    }

    group.finish();
}

fn benchmark_nested_directories(c: &mut Criterion) {
    let mut group = c.benchmark_group("nested_directories");

    for depth in [5, 10, 20] {
        let temp = TempDir::new().unwrap();
        let source_dir = create_nested_directory(&temp, depth, 3);
        let config = CreationConfig::default();

        group.bench_with_input(BenchmarkId::new("depth", depth), &depth, |b, _| {
            b.iter(|| {
                let output = temp.path().join("output.tar");
                let _ = create_archive(
                    black_box(&output),
                    black_box(&[&source_dir]),
                    black_box(&config),
                );
                fs::remove_file(&output).ok();
            });
        });
    }

    group.finish();
}

fn benchmark_mixed_file_sizes(c: &mut Criterion) {
    let temp = TempDir::new().unwrap();
    let source_dir = create_mixed_size_directory(&temp);
    let config = CreationConfig::default();

    // Total: ~3.5 MB (50*1KB + 10*100KB + 3*1MB)
    let total_bytes = (50 * 1024) + (10 * 100 * 1024) + (3 * 1024 * 1024);

    let mut group = c.benchmark_group("mixed_sizes");
    group.throughput(Throughput::Bytes(total_bytes as u64));

    group.bench_function("tar", |b| {
        b.iter(|| {
            let output = temp.path().join("output.tar");
            let _ = create_archive(
                black_box(&output),
                black_box(&[&source_dir]),
                black_box(&config),
            );
            fs::remove_file(&output).ok();
        });
    });

    group.bench_function("tar.gz", |b| {
        b.iter(|| {
            let output = temp.path().join("output.tar.gz");
            let _ = create_archive(
                black_box(&output),
                black_box(&[&source_dir]),
                black_box(&config),
            );
            fs::remove_file(&output).ok();
        });
    });

    group.finish();
}

fn benchmark_directory_walker(c: &mut Criterion) {
    let mut group = c.benchmark_group("directory_walker");

    for file_count in [100, 500, 1000] {
        let temp = TempDir::new().unwrap();
        let source_dir = create_test_directory(&temp, file_count);
        let config = CreationConfig::default();

        group.throughput(Throughput::Elements(file_count as u64));

        group.bench_with_input(BenchmarkId::new("walk", file_count), &file_count, |b, _| {
            b.iter(|| {
                let walker = FilteredWalker::new(black_box(&source_dir), black_box(&config));
                let count = walker.walk().filter(|r| r.is_ok()).count();
                black_box(count);
            });
        });
    }

    group.finish();
}

fn benchmark_path_filtering(c: &mut Criterion) {
    let mut group = c.benchmark_group("path_filtering");

    let visible_path = Path::new("src/main.rs");
    let hidden_path = Path::new(".gitignore");
    let temp_path = Path::new("file.tmp");

    // Benchmark is_hidden
    group.bench_function("is_hidden_visible", |b| {
        b.iter(|| filters::is_hidden(black_box(visible_path)));
    });

    group.bench_function("is_hidden_hidden", |b| {
        b.iter(|| filters::is_hidden(black_box(hidden_path)));
    });

    // Benchmark matches_pattern
    group.bench_function("matches_pattern_exact", |b| {
        b.iter(|| filters::matches_pattern(black_box(hidden_path), black_box(".gitignore")));
    });

    group.bench_function("matches_pattern_extension", |b| {
        b.iter(|| filters::matches_pattern(black_box(temp_path), black_box("*.tmp")));
    });

    group.bench_function("matches_pattern_prefix", |b| {
        b.iter(|| filters::matches_pattern(black_box(temp_path), black_box("file*")));
    });

    // Benchmark should_skip
    let config = CreationConfig::default();

    group.bench_function("should_skip_visible", |b| {
        b.iter(|| filters::should_skip(black_box(visible_path), black_box(&config)));
    });

    group.bench_function("should_skip_hidden", |b| {
        b.iter(|| filters::should_skip(black_box(hidden_path), black_box(&config)));
    });

    group.bench_function("should_skip_excluded", |b| {
        b.iter(|| filters::should_skip(black_box(temp_path), black_box(&config)));
    });

    group.finish();
}

fn benchmark_filtered_walking(c: &mut Criterion) {
    let temp = TempDir::new().unwrap();
    let source_dir = create_filtered_directory(&temp);

    let mut group = c.benchmark_group("filtered_walking");

    // Default config: skips hidden and *.tmp
    let default_config = CreationConfig::default();
    group.bench_function("default_filters", |b| {
        b.iter(|| {
            let walker = FilteredWalker::new(black_box(&source_dir), black_box(&default_config));
            let count = walker.walk().filter(|r| r.is_ok()).count();
            black_box(count);
        });
    });

    // Include hidden files
    let include_hidden_config = CreationConfig::default().with_include_hidden(true);
    group.bench_function("include_hidden", |b| {
        b.iter(|| {
            let walker =
                FilteredWalker::new(black_box(&source_dir), black_box(&include_hidden_config));
            let count = walker.walk().filter(|r| r.is_ok()).count();
            black_box(count);
        });
    });

    // No filters at all
    let no_filter_config = CreationConfig::default()
        .with_include_hidden(true)
        .with_exclude_patterns(vec![]);
    group.bench_function("no_filters", |b| {
        b.iter(|| {
            let walker = FilteredWalker::new(black_box(&source_dir), black_box(&no_filter_config));
            let count = walker.walk().filter(|r| r.is_ok()).count();
            black_box(count);
        });
    });

    group.finish();
}

fn benchmark_multiple_sources(c: &mut Criterion) {
    let temp = TempDir::new().unwrap();

    let source1 = create_test_directory(&temp, 50);
    let source2 = temp.path().join("source2");
    fs::create_dir_all(&source2).unwrap();
    for i in 0..50 {
        fs::write(source2.join(format!("file_{}.txt", i)), "content").unwrap();
    }

    let config = CreationConfig::default();

    c.bench_function("tar_multiple_sources", |b| {
        b.iter(|| {
            let output = temp.path().join("output.tar");
            let sources = [source1.as_path(), source2.as_path()];
            let _ = create_archive(black_box(&output), black_box(&sources), black_box(&config));
            fs::remove_file(&output).ok();
        });
    });
}

fn benchmark_strip_prefix(c: &mut Criterion) {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("project");
    let src_dir = root.join("src");
    fs::create_dir_all(&src_dir).unwrap();

    for i in 0..100 {
        fs::write(src_dir.join(format!("file_{}.rs", i)), "code").unwrap();
    }

    let mut group = c.benchmark_group("strip_prefix");

    // Without strip_prefix
    let config_no_strip = CreationConfig::default();
    group.bench_function("no_strip", |b| {
        b.iter(|| {
            let output = temp.path().join("output.tar");
            let _ = create_archive(
                black_box(&output),
                black_box(&[&root]),
                black_box(&config_no_strip),
            );
            fs::remove_file(&output).ok();
        });
    });

    // With strip_prefix
    let config_strip =
        CreationConfig::default().with_strip_prefix(Some(std::path::PathBuf::from("src")));
    group.bench_function("with_strip", |b| {
        b.iter(|| {
            let output = temp.path().join("output.tar");
            let _ = create_archive(
                black_box(&output),
                black_box(&[&root]),
                black_box(&config_strip),
            );
            fs::remove_file(&output).ok();
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_create_tar_formats,
    benchmark_create_zip,
    benchmark_compression_levels,
    benchmark_file_counts,
    benchmark_nested_directories,
    benchmark_mixed_file_sizes,
    benchmark_directory_walker,
    benchmark_path_filtering,
    benchmark_filtered_walking,
    benchmark_multiple_sources,
    benchmark_strip_prefix,
);
criterion_main!(benches);
