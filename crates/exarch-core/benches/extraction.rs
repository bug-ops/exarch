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
#![allow(clippy::disallowed_methods)]
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
use exarch_core::ArchiveReader;
use exarch_core::ArchiveType;
use exarch_core::DecodeReuse;
use exarch_core::DestinationCheck;
use exarch_core::ExistingFiles;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::ListRequest;
use exarch_core::SecurityConfig;
use exarch_core::VerifyRequest;
use std::io::Cursor;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;
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

/// Returns a [`SecurityConfig`] suitable for benchmarks.
///
/// Disables zip bomb detection to allow testing highly compressed data,
/// and increases size/depth limits for stress testing benchmarks.
fn benchmark_config() -> SecurityConfig {
    SecurityConfig::default()
        .with_max_compression_ratio(exarch_core::ratio_limit!(f64::MAX))
        .with_max_file_size(exarch_core::non_zero!(500 * 1024 * 1024))
        .with_max_total_size(exarch_core::non_zero!(1024 * 1024 * 1024))
        .with_max_path_depth(exarch_core::non_zero!(100))
}

/// Alias of [`benchmark_config`] kept for the call sites that name it.
fn benchmark_config_validated() -> SecurityConfig {
    benchmark_config()
}

/// An archive written once to a scratch directory, so a timed loop measures
/// extraction through the request API and not the archive write.
struct ArchiveFile {
    _dir: TempDir,
    path: PathBuf,
}

fn write_archive(file_name: &str, data: &[u8]) -> ArchiveFile {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(file_name);
    std::fs::write(&path, data).unwrap();
    ArchiveFile { _dir: dir, path }
}

impl ArchiveFile {
    fn extract(&self, config: &SecurityConfig, options: &ExtractionOptions, dest: &Path) {
        ExtractRequest::new(config)
            .with_options(options.clone())
            .extract(&self.path, dest)
            .unwrap();
    }
}

fn zip_reader(data: &[u8]) -> ArchiveReader<'_> {
    ArchiveReader::of_type(Cursor::new(data), ArchiveType::Zip)
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

/// Creates a ZIP archive of stored entries that each carry a data descriptor,
/// as a streaming writer produces them.
fn create_stored_descriptor_zip(file_count: usize, payload_len: usize) -> Vec<u8> {
    let mut zip = ZipWriter::new_stream(Vec::new());
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let payload = vec![b'a'; payload_len];

    for i in 0..file_count {
        zip.start_file(format!("file{i:04}.txt"), options).unwrap();
        zip.write_all(&payload).unwrap();
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
                let data_file = write_archive("archive.zip", data);
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let temp = TempDir::new().unwrap();

                        let start = Instant::now();
                        data_file.extract(
                            &SecurityConfig::default(),
                            &ExtractionOptions::default(),
                            temp.path(),
                        );
                        total += start.elapsed();

                        drop(temp);
                    }
                    total
                });
            },
        );
    }

    group.finish();
}

/// How the entries of a nested archive follow one another.
#[derive(Clone, Copy)]
enum EntryOrder {
    /// Every directory's entries together, as an archiver writes them.
    Grouped,
    /// Consecutive entries alternate between the directories.
    Interleaved,
}

/// Creates a stored ZIP of `file_count` files spread over `fan_out`
/// directories, each `depth` levels below the root.
fn create_nested_files_zip(
    file_count: usize,
    fan_out: usize,
    depth: usize,
    order: EntryOrder,
) -> Vec<u8> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let levels = "level/".repeat(depth.saturating_sub(1));
    let per_dir = file_count.div_ceil(fan_out);

    for i in 0..file_count {
        let dir = match order {
            EntryOrder::Grouped => i / per_dir,
            EntryOrder::Interleaved => i % fan_out,
        };
        let filename = format!("dir{dir:03}/{levels}file{i:05}.txt");
        zip.start_file(&filename, options).unwrap();
        zip.write_all(b"x").unwrap();
    }

    zip.finish().unwrap().into_inner()
}

/// Cost of `check_destination` over the landings of a 10,000-entry archive
/// (#1169): flat, shallow and deep layouts, so a cost that grows with path
/// depth shows; the same layouts with two directories interleaved, which a
/// one-slot parent cache cannot serve; and a layout whose top directories are
/// symlinks, which no parent cache can keep. `replaceable_populated` and
/// `vacant_populated` run over a destination that holds every landing,
/// `vacant_empty` over one that holds none.
fn benchmark_check_destination(c: &mut Criterion) {
    const ENTRIES: usize = 10_000;
    let mut group = c.benchmark_group("check_destination");
    group.throughput(Throughput::Elements(ENTRIES as u64));
    let config = SecurityConfig::default().with_max_file_count(exarch_core::non_zero!(ENTRIES * 2));
    let aliasing = config.clone().with_allow_symlinks(true);
    let grouped = |depth| create_nested_files_zip(ENTRIES, 100, depth, EntryOrder::Grouped);
    let interleaved = |depth| create_nested_files_zip(ENTRIES, 2, depth, EntryOrder::Interleaved);

    for (name, data, config, aliased) in [
        ("flat", create_many_small_files_zip(ENTRIES), &config, false),
        ("sorted_depth_2", grouped(2), &config, false),
        ("sorted_depth_8", grouped(8), &config, false),
        ("unsorted_depth_2", interleaved(2), &config, false),
        ("unsorted_depth_8", interleaved(8), &config, false),
        ("symlinked_depth_8", grouped(8), &aliasing, true),
    ] {
        let file = write_archive("archive.zip", &data);
        let populated = TempDir::new().unwrap();
        file.extract(config, &ExtractionOptions::default(), populated.path());
        #[cfg(unix)]
        if aliased {
            for i in 0..100 {
                let link = populated.path().join(format!("dir{i:03}"));
                let real = populated.path().join(format!("real{i:03}"));
                std::fs::rename(&link, &real).unwrap();
                std::os::unix::fs::symlink(&real, &link).unwrap();
            }
        }
        #[cfg(not(unix))]
        if aliased {
            continue;
        }
        let empty = TempDir::new().unwrap();
        let listed = ListRequest::new(config)
            .for_extraction(&file.path, DecodeReuse::default())
            .unwrap();
        let mut runs = vec![(
            "replaceable_populated",
            DestinationCheck::Replaceable,
            &populated,
        )];
        if !aliased {
            runs.push(("vacant_populated", DestinationCheck::Vacant, &populated));
            runs.push(("vacant_empty", DestinationCheck::Vacant, &empty));
        }
        for (state, check, dest) in runs {
            group.bench_function(format!("{name}/{state}"), |b| {
                b.iter(|| std::hint::black_box(listed.check_destination(dest.path(), check)));
            });
        }
    }

    group.finish();
}

/// Cost of leaving every entry of a 10,000-file ZIP out, by the extension
/// allowlist and by an exclude pattern: the selection gate must stay within
/// 10% of the allowlist skip (spec 022 NFR-006). The two-thousand-pattern
/// lists (literal names, suffix names) end in `*.txt` and must stay within
/// 1.2x of `exclude_pattern`: direct patterns add no per-entry cost.
fn benchmark_skipped_entries(c: &mut Criterion) {
    const ENTRIES: usize = 10_000;
    let zip_data = create_many_small_files_zip(ENTRIES);
    let mut group = c.benchmark_group("skipped_entries");
    group.throughput(Throughput::Elements(ENTRIES as u64));

    let allowlist = SecurityConfig::default()
        .try_add_allowed_extension("md")
        .unwrap();
    let excluded = SecurityConfig::default().try_add_exclude("*.txt").unwrap();
    let mut fifty = SecurityConfig::default();
    for i in 0..49 {
        fifty = fifty.try_add_exclude(&format!("*.never{i}")).unwrap();
    }
    let fifty_excludes = fifty.try_add_exclude("*.txt").unwrap();
    let mut literals = SecurityConfig::default();
    let mut suffixes = SecurityConfig::default();
    for i in 0..1999 {
        literals = literals.try_add_exclude(&format!("never{i}")).unwrap();
        suffixes = suffixes.try_add_exclude(&format!("*.never{i}")).unwrap();
    }
    let two_thousand_literals = literals.try_add_exclude("*.txt").unwrap();
    let two_thousand_suffixes = suffixes.try_add_exclude("*.txt").unwrap();
    for (name, config) in [
        ("extension_allowlist", allowlist),
        ("exclude_pattern", excluded),
        ("fifty_exclude_patterns", fifty_excludes),
        ("two_thousand_literal_excludes", two_thousand_literals),
        ("two_thousand_suffix_excludes", two_thousand_suffixes),
    ] {
        let zip_data_file = write_archive("archive.zip", &zip_data);
        group.bench_function(name, |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let temp = TempDir::new().unwrap();

                    let start = Instant::now();
                    zip_data_file.extract(&config, &ExtractionOptions::default(), temp.path());
                    total += start.elapsed();
                }
                total
            });
        });
    }

    group.finish();
}

/// Cost of listing and verifying a 10,000-entry ZIP (SC-008).
///
/// `baseline_plain_scan` is the work opening did before the structural census:
/// one `zip` open plus a metadata-only read of every entry. `list` and
/// `verify` run through the request API, so each includes the open.
fn benchmark_zip_inspection(c: &mut Criterion) {
    const ENTRIES: usize = 10_000;
    let mut group = c.benchmark_group("zip_inspection");
    let data = create_many_small_files_zip(ENTRIES);
    let config = SecurityConfig::default().with_max_file_count(exarch_core::non_zero!(ENTRIES * 2));
    group.throughput(Throughput::Elements(ENTRIES as u64));

    group.bench_function("baseline_plain_scan", |b| {
        b.iter(|| {
            let mut archive = zip::ZipArchive::new(Cursor::new(&data[..])).unwrap();
            for index in 0..archive.len() {
                archive.by_index(index).unwrap();
            }
        });
    });
    group.bench_function("list", |b| {
        b.iter(|| {
            ListRequest::new(&config)
                .list_reader(zip_reader(&data))
                .unwrap()
        });
    });
    group.bench_function("verify", |b| {
        b.iter(|| {
            VerifyRequest::new(&config)
                .verify_reader(zip_reader(&data))
                .unwrap()
        });
    });

    let described = create_stored_descriptor_zip(ENTRIES, 256);
    group.bench_function("stored_descriptor_list", |b| {
        b.iter(|| {
            ListRequest::new(&config)
                .list_reader(zip_reader(&described))
                .unwrap()
        });
    });
    group.bench_function("stored_descriptor_verify", |b| {
        b.iter(|| {
            VerifyRequest::new(&config)
                .verify_reader(zip_reader(&described))
                .unwrap()
        });
    });

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
                let config = SecurityConfig::default()
                    .with_max_file_size(exarch_core::non_zero!(200 * 1024 * 1024))
                    .with_max_total_size(exarch_core::non_zero!(500 * 1024 * 1024));
                let data_file = write_archive("archive.zip", data);
                b.iter(|| {
                    let temp = TempDir::new().unwrap();
                    data_file.extract(&config, &ExtractionOptions::default(), temp.path());
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
            let data_file = write_archive("archive.zip", data);
            b.iter(|| {
                let temp = TempDir::new().unwrap();
                data_file.extract(
                    &SecurityConfig::default(),
                    &ExtractionOptions::default(),
                    temp.path(),
                );
            });
        });
    }

    group.finish();
}

fn benchmark_compression_methods(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression_methods");
    let config = benchmark_config_validated();

    let size_bytes = 10 * 1024 * 1024; // 10 MB
    group.throughput(Throughput::Bytes(size_bytes as u64));

    // Stored (no compression)
    let stored_zip = create_large_file_zip(size_bytes);
    group.bench_with_input(
        BenchmarkId::new("method", "stored"),
        &stored_zip,
        |b, data| {
            let data_file = write_archive("archive.zip", data);
            b.iter(|| {
                let temp = TempDir::new().unwrap();
                data_file.extract(&config, &ExtractionOptions::default(), temp.path());
            });
        },
    );

    // DEFLATE compression
    let deflate_zip = create_deflate_compressed_zip(size_bytes);
    group.bench_with_input(
        BenchmarkId::new("method", "deflate"),
        &deflate_zip,
        |b, data| {
            let data_file = write_archive("archive.zip", data);
            b.iter(|| {
                let temp = TempDir::new().unwrap();
                data_file.extract(&config, &ExtractionOptions::default(), temp.path());
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

    let simple_data_file = write_archive("archive.7z", &simple_data);
    group.bench_function("simple_7z", |b| {
        b.iter(|| {
            let temp = TempDir::new().unwrap();
            simple_data_file.extract(
                &SecurityConfig::default(),
                &ExtractionOptions::default(),
                temp.path(),
            );
        });
    });

    group.finish();
}

fn benchmark_sevenz_nested_dirs(c: &mut Criterion) {
    let mut group = c.benchmark_group("sevenz_nested");

    let nested_data = load_7z_fixture("nested-dirs.7z");
    group.throughput(Throughput::Elements(3)); // Approximate file count

    let nested_data_file = write_archive("archive.7z", &nested_data);
    group.bench_function("nested_dirs_7z", |b| {
        b.iter(|| {
            let temp = TempDir::new().unwrap();
            nested_data_file.extract(
                &SecurityConfig::default(),
                &ExtractionOptions::default(),
                temp.path(),
            );
        });
    });

    group.finish();
}

fn benchmark_sevenz_large_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("sevenz_large_file");

    let large_data = load_7z_fixture("large-file.7z");
    let size_bytes: u64 = 50 * 1024; // 50 KB
    group.throughput(Throughput::Bytes(size_bytes));
    let config = benchmark_config_validated();

    let large_data_file = write_archive("archive.7z", &large_data);
    group.bench_function("large_file_7z", |b| {
        b.iter(|| {
            let temp = TempDir::new().unwrap();
            large_data_file.extract(&config, &ExtractionOptions::default(), temp.path());
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
            let data_file = write_archive("archive.zip", data);
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let temp = TempDir::new().unwrap();

                    let start = Instant::now();
                    data_file.extract(&config, &ExtractionOptions::default(), temp.path());
                    total += start.elapsed();

                    drop(temp);
                }
                total
            });
        });
    }

    group.finish();
}

/// Directory depth scaling benchmark.
fn benchmark_depth_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("depth_scaling");
    let config = benchmark_config_validated();

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
            let data_file = write_archive("archive.zip", data);
            b.iter(|| {
                let temp = TempDir::new().unwrap();
                data_file.extract(&config, &ExtractionOptions::default(), temp.path());
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
    bench_extraction(&mut group, "tar_bz2_small", "small_files.tar.bz2", &config);
    bench_extraction(&mut group, "tar_xz_small", "small_files.tar.xz", &config);
    bench_extraction(&mut group, "tar_zst_small", "small_files.tar.zst", &config);
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

/// Compares `exarch-core`'s 7z extraction against the upstream
/// `sevenz_rust2::decompress_file` reference implementation on the same
/// fixtures (uses fixtures from benches/fixtures/). Gives a repo-native,
/// reproducible baseline for the write-path optimization in issue #492
/// instead of relying on ad hoc timing.
fn benchmark_sevenz_vs_reference(c: &mut Criterion) {
    let mut group = c.benchmark_group("sevenz_vs_reference");
    // generate_fixtures.sh's `7z a` defaults to solid compression.
    let config = benchmark_config().with_solid_archives(exarch_core::SolidArchives::Allow(
        exarch_core::SolidLimits::DEFAULT
            .with_max_block_memory(exarch_core::non_zero!(256 * 1024 * 1024)),
    ));

    for fixture_name in ["small_files.7z", "medium_files.7z"] {
        let Some(fixture) = get_fixture(fixture_name) else {
            eprintln!(
                "Skipping sevenz_vs_reference/{fixture_name}: fixture not found. Run generate_fixtures.sh"
            );
            continue;
        };

        let size = get_fixture_size(fixture_name);
        if size > 0 {
            group.throughput(Throughput::Bytes(size));
        }

        group.bench_with_input(
            BenchmarkId::new("exarch", fixture_name),
            &fixture,
            |b, path| {
                b.iter(|| {
                    let temp = TempDir::new().unwrap();
                    exarch_core::extract_archive(path, temp.path(), &config).unwrap();
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("sevenz_rust2", fixture_name),
            &fixture,
            |b, path| {
                b.iter(|| {
                    let temp = TempDir::new().unwrap();
                    sevenz_rust2::decompress_file(path, temp.path()).unwrap();
                });
            },
        );
    }

    group.finish();
}

/// Exercises 7z's overwrite/temp-file-then-rename write path, which
/// `benchmark_sevenz_vs_reference` never reaches since every extraction
/// there targets a fresh, empty directory (issue #492 adversarial review,
/// finding M3). Each iteration pre-populates the destination with a prior
/// extraction so every entry hits the `existing.is_some()` branch.
fn benchmark_sevenz_overwrite(c: &mut Criterion) {
    let mut group = c.benchmark_group("sevenz_overwrite");
    let config = benchmark_config().with_solid_archives(exarch_core::SolidArchives::Allow(
        exarch_core::SolidLimits::DEFAULT
            .with_max_block_memory(exarch_core::non_zero!(256 * 1024 * 1024)),
    ));
    let overwrite_options =
        ExtractionOptions::default().with_existing_files(ExistingFiles::Overwrite);

    for fixture_name in ["small_files.7z", "medium_files.7z"] {
        let Some(fixture) = get_fixture(fixture_name) else {
            eprintln!(
                "Skipping sevenz_overwrite/{fixture_name}: fixture not found. Run generate_fixtures.sh"
            );
            continue;
        };
        let data = std::fs::read(&fixture).unwrap();

        let size = get_fixture_size(fixture_name);
        if size > 0 {
            group.throughput(Throughput::Bytes(size));
        }

        group.bench_with_input(
            BenchmarkId::new("exarch_overwrite", fixture_name),
            &data,
            |b, data| {
                let archive = write_archive("archive.7z", data);
                b.iter_batched(
                    || {
                        let temp = TempDir::new().unwrap();
                        archive.extract(&config, &ExtractionOptions::default(), temp.path());
                        temp
                    },
                    |temp| archive.extract(&config, &overwrite_options, temp.path()),
                    criterion::BatchSize::LargeInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_security_config,
    benchmark_many_small_files,
    benchmark_skipped_entries,
    benchmark_check_destination,
    benchmark_zip_inspection,
    benchmark_large_files,
    benchmark_nested_directories,
    benchmark_compression_methods,
    benchmark_sevenz_simple,
    benchmark_sevenz_nested_dirs,
    benchmark_sevenz_large_file,
    benchmark_sevenz_vs_reference,
    benchmark_sevenz_overwrite,
    benchmark_file_count_scaling,
    benchmark_depth_scaling,
    benchmark_file_extraction,
    benchmark_permission_optimization,
);
criterion_main!(benches);
