//! Comprehensive extraction benchmarks for exarch.
//!
//! Measures extraction throughput across:
//! - Different archive formats (TAR, TAR+GZIP, TAR+ZSTD, ZIP, 7z)
//! - Different archive sizes (1MB, 10MB, 100MB)
//! - Different file structures (many small, few large, mixed)
//!
//! Performance targets from CLAUDE.md:
//! - TAR extraction: 500 MB/s
//! - ZIP extraction: 300 MB/s
//! - Path validation: < 1 us

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::items_after_statements,
    clippy::similar_names,
    missing_docs
)]

use criterion::BenchmarkGroup;
use criterion::BenchmarkId;
use criterion::Criterion;
use criterion::Throughput;
use criterion::criterion_group;
use criterion::criterion_main;
use criterion::measurement::WallTime;
use exarch_core::SecurityConfig;
use exarch_core::formats::SevenZArchive;
use exarch_core::formats::ZipArchive;
use exarch_core::formats::traits::ArchiveFormat;
use std::io::Cursor;
use std::io::Write;
use std::path::PathBuf;
use tempfile::TempDir;
use zip::write::SimpleFileOptions;
use zip::write::ZipWriter;

/// Returns path to benchmark fixtures directory.
fn fixtures_dir() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("benches/fixtures")
}

/// Returns path to test fixtures directory.
fn test_fixtures_dir() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures")
}

/// Returns fixture path if it exists, otherwise None.
fn get_fixture(name: &str) -> Option<PathBuf> {
    let path = fixtures_dir().join(name);
    if path.exists() { Some(path) } else { None }
}

/// Gets the uncompressed size of a fixture for throughput calculation.
fn get_fixture_size(name: &str) -> u64 {
    // Pre-calculated sizes based on fixture generation
    match name {
        "small_files.tar"
        | "small_files.tar.gz"
        | "small_files.tar.bz2"
        | "small_files.tar.xz"
        | "small_files.tar.zst"
        | "small_files.zip"
        | "small_files.7z" => 1024 * 1000, // ~1MB
        "medium_files.tar" | "medium_files.tar.gz" | "medium_files.zip" | "medium_files.7z" => {
            100 * 100 * 1024
        } // ~10MB
        "large_file.tar"
        | "large_file.tar.gz"
        | "large_file.zip"
        | "large_file.7z"
        | "compressible_large.tar"
        | "compressible_large.tar.gz"
        | "compressible_large.zip" => 100 * 1024 * 1024, // 100MB
        "nested_dirs.tar" | "nested_dirs.tar.gz" | "nested_dirs.zip" => 20 * 3 * 1024, // ~60KB
        "many_files.tar" | "many_files.tar.gz" | "many_files.zip" => 10000 * 20,       // ~200KB
        "mixed.tar" | "mixed.tar.gz" | "mixed.zip" => {
            500 * 1024 + 50 * 100 * 1024 + 5 * 1024 * 1024
        } // ~10.5MB
        _ => 0,
    }
}

/// Benchmark helper that extracts an archive and measures throughput.
fn bench_extraction(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    fixture_name: &str,
    config: &SecurityConfig,
) {
    let Some(fixture) = get_fixture(fixture_name) else {
        eprintln!("Skipping {name}: fixture {fixture_name} not found. Run generate_fixtures.sh");
        return;
    };

    let size = get_fixture_size(fixture_name);
    if size > 0 {
        group.throughput(Throughput::Bytes(size));
    }

    group.bench_with_input(BenchmarkId::new(name, fixture_name), &fixture, |b, path| {
        b.iter(|| {
            let temp = TempDir::new().unwrap();
            exarch_core::extract_archive(path, temp.path(), config).unwrap();
        });
    });
}

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

                    // Use config with increased limits for benchmarks
                    let config = SecurityConfig {
                        max_file_size: 200 * 1024 * 1024,  // 200 MB
                        max_total_size: 500 * 1024 * 1024, // 500 MB
                        ..SecurityConfig::default()
                    };

                    archive.extract(temp.path(), &config).unwrap();
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

/// Load 7z fixture from tests/fixtures/
fn load_7z_fixture(name: &str) -> Vec<u8> {
    let fixture_path = test_fixtures_dir().join(name);

    std::fs::read(&fixture_path).unwrap_or_else(|e| {
        panic!(
            "Failed to load 7z fixture {name}. Run tests/fixtures/generate_7z_fixtures.sh first. Error: {e}"
        )
    })
}

fn benchmark_sevenz_simple(c: &mut Criterion) {
    let mut group = c.benchmark_group("sevenz_extraction");

    let simple_data = load_7z_fixture("simple.7z");
    group.throughput(Throughput::Elements(2)); // 2 files

    group.bench_function("simple_7z", |b| {
        b.iter(|| {
            let temp = TempDir::new().unwrap();
            let cursor = Cursor::new(simple_data.clone());
            let mut archive = SevenZArchive::new(cursor).unwrap();
            archive
                .extract(temp.path(), &SecurityConfig::default())
                .unwrap();
        });
    });

    group.finish();
}

fn benchmark_sevenz_nested_dirs(c: &mut Criterion) {
    let mut group = c.benchmark_group("sevenz_nested");

    let nested_data = load_7z_fixture("nested-dirs.7z");
    group.throughput(Throughput::Elements(3)); // Approximate file count

    group.bench_function("nested_dirs_7z", |b| {
        b.iter(|| {
            let temp = TempDir::new().unwrap();
            let cursor = Cursor::new(nested_data.clone());
            let mut archive = SevenZArchive::new(cursor).unwrap();
            archive
                .extract(temp.path(), &SecurityConfig::default())
                .unwrap();
        });
    });

    group.finish();
}

fn benchmark_sevenz_large_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("sevenz_large_file");

    let large_data = load_7z_fixture("large-file.7z");
    let size_bytes: u64 = 50 * 1024; // 50 KB
    group.throughput(Throughput::Bytes(size_bytes));

    group.bench_function("large_file_7z", |b| {
        b.iter(|| {
            let temp = TempDir::new().unwrap();
            let cursor = Cursor::new(large_data.clone());
            let mut archive = SevenZArchive::new(cursor).unwrap();
            archive
                .extract(temp.path(), &SecurityConfig::default())
                .unwrap();
        });
    });

    group.finish();
}

/// File count scaling benchmark.
fn benchmark_file_count_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("file_count_scaling");

    for count in [100, 500, 1000, 5000] {
        let zip_data = {
            let buffer = Vec::new();
            let mut zip = ZipWriter::new(Cursor::new(buffer));
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

            for i in 0..count {
                let filename = format!("file{i:05}.txt");
                zip.start_file(&filename, options).unwrap();
                zip.write_all(b"x").unwrap();
            }

            zip.finish().unwrap().into_inner()
        };

        #[allow(clippy::cast_sign_loss)]
        let count_u64 = count as u64;
        group.throughput(Throughput::Elements(count_u64));
        group.bench_with_input(BenchmarkId::new("files", count), &zip_data, |b, data| {
            let config = SecurityConfig::default();
            b.iter(|| {
                let temp = TempDir::new().unwrap();
                let cursor = Cursor::new(data.clone());
                let mut archive = ZipArchive::new(cursor).unwrap();
                archive.extract(temp.path(), &config).unwrap();
            });
        });
    }

    group.finish();
}

/// Directory depth scaling benchmark.
fn benchmark_depth_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("depth_scaling");

    for depth in [5, 10, 20, 50] {
        let zip_data = {
            let buffer = Vec::new();
            let mut zip = ZipWriter::new(Cursor::new(buffer));
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

            // Create nested path
            let mut path = String::new();
            for level in 0..depth {
                use std::fmt::Write;
                write!(&mut path, "level{level}/").unwrap();
            }
            path.push_str("file.txt");

            zip.start_file(&path, options).unwrap();
            zip.write_all(b"content").unwrap();

            zip.finish().unwrap().into_inner()
        };

        group.bench_with_input(BenchmarkId::new("depth", depth), &zip_data, |b, data| {
            let config = SecurityConfig::default();
            b.iter(|| {
                let temp = TempDir::new().unwrap();
                let cursor = Cursor::new(data.clone());
                let mut archive = ZipArchive::new(cursor).unwrap();
                archive.extract(temp.path(), &config).unwrap();
            });
        });
    }

    group.finish();
}

/// File-based extraction benchmarks (uses fixtures from benches/fixtures/).
fn benchmark_file_extraction(c: &mut Criterion) {
    let mut group = c.benchmark_group("file_extraction");
    let config = SecurityConfig::default();

    // TAR extraction
    bench_extraction(&mut group, "tar_small", "small_files.tar", &config);
    bench_extraction(&mut group, "tar_gz_small", "small_files.tar.gz", &config);
    bench_extraction(&mut group, "tar_medium", "medium_files.tar", &config);
    bench_extraction(&mut group, "tar_gz_medium", "medium_files.tar.gz", &config);

    // ZIP extraction
    bench_extraction(&mut group, "zip_small", "small_files.zip", &config);
    bench_extraction(&mut group, "zip_medium", "medium_files.zip", &config);

    // Mixed structures
    bench_extraction(&mut group, "nested", "nested_dirs.tar.gz", &config);
    bench_extraction(&mut group, "mixed", "mixed.tar.gz", &config);

    group.finish();
}

/// Benchmarks for permission optimization verification.
///
/// Measures the performance impact of atomic permission setting during file
/// creation vs separate chmod syscall. This validates the claimed 50% syscall
/// reduction for permission-related operations.
#[cfg(unix)]
fn benchmark_permission_optimization(c: &mut Criterion) {
    use std::fs::File;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;

    let mut group = c.benchmark_group("permission_optimization");

    // Benchmark 1: Atomic mode setting during file creation (optimized)
    group.bench_function("atomic_mode_setting", |b| {
        b.iter(|| {
            let temp = TempDir::new().unwrap();
            let file_path = temp.path().join("test.txt");

            // Create file with mode set atomically (1 syscall)
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true).mode(0o644);

            let mut file = opts.open(&file_path).unwrap();
            file.write_all(b"test data").unwrap();
        });
    });

    // Benchmark 2: Separate chmod after creation (traditional approach)
    group.bench_function("separate_chmod", |b| {
        b.iter(|| {
            let temp = TempDir::new().unwrap();
            let file_path = temp.path().join("test.txt");

            // Create file (1 syscall)
            let mut file = File::create(&file_path).unwrap();
            file.write_all(b"test data").unwrap();
            drop(file);

            // Set permissions separately (2nd syscall)
            let perms = std::fs::Permissions::from_mode(0o644);
            std::fs::set_permissions(&file_path, perms).unwrap();
        });
    });

    // Benchmark 3: Many files with atomic mode setting
    group.bench_function("atomic_many_files", |b| {
        b.iter(|| {
            let temp = TempDir::new().unwrap();

            for i in 0..100 {
                let file_path = temp.path().join(format!("file{i}.txt"));
                let mut opts = OpenOptions::new();
                opts.write(true).create(true).truncate(true).mode(0o644);

                let mut file = opts.open(&file_path).unwrap();
                file.write_all(b"data").unwrap();
            }
        });
    });

    // Benchmark 4: Many files with separate chmod
    group.bench_function("chmod_many_files", |b| {
        b.iter(|| {
            let temp = TempDir::new().unwrap();

            for i in 0..100 {
                let file_path = temp.path().join(format!("file{i}.txt"));
                let mut file = File::create(&file_path).unwrap();
                file.write_all(b"data").unwrap();
                drop(file);

                let perms = std::fs::Permissions::from_mode(0o644);
                std::fs::set_permissions(&file_path, perms).unwrap();
            }
        });
    });

    group.finish();
}

/// H3: Non-Unix fallback benchmark (no-op for permission setting).
#[cfg(not(unix))]
fn benchmark_permission_optimization(_c: &mut Criterion) {
    // No-op on non-Unix platforms
}

criterion_group!(
    benches,
    benchmark_security_config,
    benchmark_many_small_files,
    benchmark_large_files,
    benchmark_nested_directories,
    benchmark_compression_methods,
    benchmark_sevenz_simple,
    benchmark_sevenz_nested_dirs,
    benchmark_sevenz_large_file,
    benchmark_file_count_scaling,
    benchmark_depth_scaling,
    benchmark_file_extraction,
    benchmark_permission_optimization,
);
criterion_main!(benches);
