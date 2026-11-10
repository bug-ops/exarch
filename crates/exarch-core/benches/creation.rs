//! Benchmarks for archive creation performance.
//!
//! Measures creation throughput across different formats, compression levels,
//! and directory structures.
#![allow(clippy::disallowed_methods)]
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
use exarch_core::CompressionLevel;
use exarch_core::CreatableFormat;
use exarch_core::CreateRequest;
use exarch_core::CreationConfig;
use exarch_core::Durability;
use exarch_core::EntryPattern;
use exarch_core::OutputFile;
use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::hint::black_box;
use std::io::Cursor;
use std::io::Seek;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use tempfile::TempDir;
use zip::CompressionMethod;
use zip::DateTime;
use zip::PreparedZipFile;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

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

/// Creates the archive without the fsyncs of the default durability, so the
/// benches measure the creation pipeline, and fails loudly when creation fails.
fn create_unsynced<P: AsRef<Path>>(output: &Path, sources: &[P], config: &CreationConfig) {
    CreateRequest::new(config)
        .create(
            &OutputFile::create_new(output).with_durability(Durability::Unsynced),
            sources,
        )
        .unwrap();
}

fn benchmark_staged_create_synced(c: &mut Criterion) {
    let temp = TempDir::new().unwrap();
    let source_dir = create_test_directory(&temp, 10);
    let config = CreationConfig::default();

    let mut group = c.benchmark_group("staged_create");
    group.bench_function("synced", |b| {
        b.iter(|| {
            let output = temp.path().join("output.tar");
            CreateRequest::new(&config)
                .create(
                    &OutputFile::create_new(black_box(&output)),
                    black_box(&[&source_dir]),
                )
                .unwrap();
            fs::remove_file(&output).unwrap();
        });
    });
    group.finish();
}

fn benchmark_create_tar_formats(c: &mut Criterion) {
    let mut group = c.benchmark_group("tar_formats");
    let temp = TempDir::new().unwrap();
    let source_dir = create_test_directory(&temp, 100);

    let formats = [
        ("tar", CreatableFormat::Tar),
        ("tar.gz", CreatableFormat::TarGz),
        ("tar.bz2", CreatableFormat::TarBz2),
        ("tar.xz", CreatableFormat::TarXz),
        ("tar.zst", CreatableFormat::TarZst),
    ];

    for (name, format) in formats {
        group.bench_with_input(BenchmarkId::new("format", name), &format, |b, _format| {
            b.iter(|| {
                let output = temp.path().join(format!("output.{}", name));
                let config = CreationConfig::default();
                create_unsynced(
                    black_box(&output),
                    black_box(&[&source_dir]),
                    black_box(&config),
                );
                fs::remove_file(&output).unwrap();
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
            create_unsynced(
                black_box(&output),
                black_box(&[&source_dir]),
                black_box(&config),
            );
            fs::remove_file(&output).unwrap();
        });
    });
}

fn benchmark_compression_levels(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression_levels");
    let temp = TempDir::new().unwrap();
    let source_dir = create_test_directory(&temp, 50);

    for level in [1u8, 3, 6, 9] {
        group.bench_with_input(
            BenchmarkId::new("tar.gz_level", level),
            &level,
            |b, level| {
                b.iter(|| {
                    let output = temp.path().join("output.tar.gz");
                    let config = CreationConfig::default()
                        .with_compression_level(CompressionLevel::try_from(*level).unwrap());
                    create_unsynced(
                        black_box(&output),
                        black_box(&[&source_dir]),
                        black_box(&config),
                    );
                    fs::remove_file(&output).unwrap();
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
                create_unsynced(
                    black_box(&output),
                    black_box(&[&source_dir]),
                    black_box(&config),
                );
                fs::remove_file(&output).unwrap();
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
                create_unsynced(
                    black_box(&output),
                    black_box(&[&source_dir]),
                    black_box(&config),
                );
                fs::remove_file(&output).unwrap();
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
            create_unsynced(
                black_box(&output),
                black_box(&[&source_dir]),
                black_box(&config),
            );
            fs::remove_file(&output).unwrap();
        });
    });

    group.bench_function("tar.gz", |b| {
        b.iter(|| {
            let output = temp.path().join("output.tar.gz");
            create_unsynced(
                black_box(&output),
                black_box(&[&source_dir]),
                black_box(&config),
            );
            fs::remove_file(&output).unwrap();
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
                let output = temp.path().join("bench_walk.tar");
                create_unsynced(
                    black_box(&output),
                    black_box(&[source_dir.as_path()]),
                    black_box(&config),
                );
                fs::remove_file(&output).unwrap();
            });
        });
    }

    group.finish();
}

fn benchmark_path_filtering(c: &mut Criterion) {
    let mut group = c.benchmark_group("path_filtering");

    let hidden_path = Path::new(".gitignore");
    let temp_path = Path::new("file.tmp");

    // Benchmark EntryPattern::matches
    let exact = EntryPattern::try_from(".gitignore").unwrap();
    let suffix = EntryPattern::try_from("*.tmp").unwrap();
    let prefix = EntryPattern::try_from("file*").unwrap();
    group.bench_function("matches_pattern_exact", |b| {
        b.iter(|| exact.matches(black_box(hidden_path)));
    });

    group.bench_function("matches_pattern_extension", |b| {
        b.iter(|| suffix.matches(black_box(temp_path)));
    });

    group.bench_function("matches_pattern_prefix", |b| {
        b.iter(|| prefix.matches(black_box(temp_path)));
    });

    let deep_path = Path::new("src/module/nested/deeper/file.rs");
    for (name, text) in [
        ("matches_glob_double_star", "src/**/*.rs"),
        ("matches_glob_single_star", "src/*/nested/*/file.rs"),
        ("matches_glob_class", "[a-c]*.tmp"),
    ] {
        let glob = EntryPattern::try_from(text).unwrap();
        group.bench_function(name, |b| {
            b.iter(|| glob.matches(black_box(deep_path)));
        });
    }

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
            let output = temp.path().join("bench_filtered_default.tar");
            create_unsynced(
                black_box(&output),
                black_box(&[source_dir.as_path()]),
                black_box(&default_config),
            );
            fs::remove_file(&output).unwrap();
        });
    });

    // Include hidden files
    let include_hidden_config = CreationConfig::default().with_include_hidden(true);
    group.bench_function("include_hidden", |b| {
        b.iter(|| {
            let output = temp.path().join("bench_filtered_hidden.tar");
            create_unsynced(
                black_box(&output),
                black_box(&[source_dir.as_path()]),
                black_box(&include_hidden_config),
            );
            fs::remove_file(&output).unwrap();
        });
    });

    // No filters at all
    let no_filter_config = CreationConfig::default()
        .with_include_hidden(true)
        .with_exclude_patterns(vec![]);
    group.bench_function("no_filters", |b| {
        b.iter(|| {
            let output = temp.path().join("bench_filtered_none.tar");
            create_unsynced(
                black_box(&output),
                black_box(&[source_dir.as_path()]),
                black_box(&no_filter_config),
            );
            fs::remove_file(&output).unwrap();
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
            create_unsynced(black_box(&output), black_box(&sources), black_box(&config));
            fs::remove_file(&output).unwrap();
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
            create_unsynced(
                black_box(&output),
                black_box(&[&root]),
                black_box(&config_no_strip),
            );
            fs::remove_file(&output).unwrap();
        });
    });

    // With strip_prefix
    let config_strip =
        CreationConfig::default().with_strip_prefix(Some(std::path::PathBuf::from("src")));
    group.bench_function("with_strip", |b| {
        b.iter(|| {
            let output = temp.path().join("output.tar");
            create_unsynced(
                black_box(&output),
                black_box(&[&root]),
                black_box(&config_strip),
            );
            fs::remove_file(&output).unwrap();
        });
    });

    group.finish();
}

const PROTOTYPE_FILES: usize = 2000;
const PROTOTYPE_FILE_BYTES: usize = 128 * 1024;
const PROTOTYPE_WORKERS: [usize; 4] = [1, 2, 4, 8];
const PROTOTYPE_ROOT: &str = "bench_data";

struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound).unwrap()).unwrap()
    }
}

/// Seeded text drawn from a 256-word vocabulary, compressible about 3x by
/// DEFLATE.
fn write_compressible_text(rng: &mut Xorshift, vocabulary: &[String], len: usize) -> Vec<u8> {
    let mut text = Vec::with_capacity(len + 16);
    while text.len() < len {
        let word = &vocabulary[rng.below(vocabulary.len())];
        text.extend_from_slice(word.as_bytes());
        text.push(if rng.below(12) == 0 { b'\n' } else { b' ' });
    }
    text.truncate(len);
    text
}

fn create_compressible_directory(temp: &TempDir) -> (PathBuf, Vec<PathBuf>) {
    let dir = temp.path().join(PROTOTYPE_ROOT);
    fs::create_dir_all(&dir).unwrap();
    let mut rng = Xorshift(0x9E37_79B9_7F4A_7C15);
    let vocabulary: Vec<String> = (0..256)
        .map(|_| {
            let len = 3 + rng.below(6);
            (0..len)
                .map(|_| char::from(b'a' + u8::try_from(rng.below(26)).unwrap()))
                .collect()
        })
        .collect();
    let files = (0..PROTOTYPE_FILES)
        .map(|i| {
            let path = dir.join(format!("file_{i:05}.txt"));
            fs::write(
                &path,
                write_compressible_text(&mut rng, &vocabulary, PROTOTYPE_FILE_BYTES),
            )
            .unwrap();
            path
        })
        .collect();
    (dir, files)
}

fn prototype_options(method: CompressionMethod, level: i64) -> SimpleFileOptions {
    SimpleFileOptions::default()
        .compression_method(method)
        .compression_level(Some(level))
        .unix_permissions(0o644)
        .last_modified_time(DateTime::from_date_and_time(2024, 1, 1, 0, 0, 0).unwrap())
}

fn archive_name(path: &Path) -> String {
    format!(
        "{PROTOTYPE_ROOT}/{}",
        path.file_name().unwrap().to_string_lossy()
    )
}

fn add_root_directory<W: Write + Seek>(zip: &mut ZipWriter<W>, options: SimpleFileOptions) {
    zip.add_directory(
        format!("{PROTOTYPE_ROOT}/"),
        options.unix_permissions(0o755),
    )
    .unwrap();
}

/// Streams every file through `start_file`, as `write_zip` does today.
fn write_streaming<W: Write + Seek>(out: W, files: &[PathBuf], options: SimpleFileOptions) -> W {
    let mut zip = ZipWriter::new(out);
    add_root_directory(&mut zip, options);
    for path in files {
        zip.start_file(archive_name(path), options).unwrap();
        std::io::copy(&mut File::open(path).unwrap(), &mut zip).unwrap();
    }
    zip.finish().unwrap()
}

/// Compresses entries on `workers` scoped threads and appends them in walk
/// order with `add_prepared_file`.
fn write_prepared<W: Write + Seek>(
    out: W,
    files: &[PathBuf],
    options: SimpleFileOptions,
    workers: usize,
) -> W {
    let mut zip = ZipWriter::new(out);
    add_root_directory(&mut zip, options);
    let next = AtomicUsize::new(0);
    let (tx, rx) = mpsc::channel();
    thread::scope(|scope| {
        for _ in 0..workers {
            let tx = tx.clone();
            let next = &next;
            scope.spawn(move || {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(path) = files.get(index) else { break };
                    let prepared =
                        PreparedZipFile::from_path(archive_name(path), path, options).unwrap();
                    tx.send((index, prepared)).unwrap();
                }
            });
        }
        drop(tx);
        let mut pending = BTreeMap::new();
        let mut expected = 0;
        for (index, prepared) in rx {
            pending.insert(index, prepared);
            while let Some(prepared) = pending.remove(&expected) {
                zip.add_prepared_file(prepared).unwrap();
                expected += 1;
            }
        }
    });
    zip.finish().unwrap()
}

fn first_difference(a: &[u8], b: &[u8]) -> Option<usize> {
    a.iter()
        .zip(b)
        .position(|(x, y)| x != y)
        .or_else(|| (a.len() != b.len()).then(|| a.len().min(b.len())))
}

/// Prints whether the streaming path and the prepared path agree, and asserts
/// that the prepared path is independent of the worker count.
fn report_byte_identity(label: &str, files: &[PathBuf], options: SimpleFileOptions) {
    let build =
        |f: &dyn Fn(Cursor<Vec<u8>>) -> Cursor<Vec<u8>>| f(Cursor::new(Vec::new())).into_inner();
    let streaming = build(&|out| write_streaming(out, files, options));
    let prepared: Vec<(usize, Vec<u8>)> = PROTOTYPE_WORKERS
        .iter()
        .map(|&n| (n, build(&|out| write_prepared(out, files, options, n))))
        .collect();
    let (_, base) = &prepared[0];
    eprintln!(
        "[{label}] streaming vs prepared(n=1): {:?} (bytes {} vs {})",
        first_difference(&streaming, base),
        streaming.len(),
        base.len()
    );
    for (n, bytes) in &prepared[1..] {
        assert_eq!(
            first_difference(base, bytes),
            None,
            "[{label}] prepared(n=1) differs from prepared(n={n})"
        );
    }
}

/// Opt-in (`EXARCH_BENCH_ZIP_PARALLEL=1`): builds a 256 MiB fixture.
fn benchmark_zip_parallel_prototype(c: &mut Criterion) {
    if std::env::var_os("EXARCH_BENCH_ZIP_PARALLEL").is_none() {
        return;
    }
    let temp = TempDir::new().unwrap();
    let (source_dir, files) = create_compressible_directory(&temp);
    eprintln!(
        "zip_parallel_prototype: {} cores, {} files x {} bytes",
        thread::available_parallelism().unwrap(),
        PROTOTYPE_FILES,
        PROTOTYPE_FILE_BYTES
    );
    let total_bytes = (PROTOTYPE_FILES * PROTOTYPE_FILE_BYTES) as u64;
    let level = i64::from(CompressionLevel::default().get());
    let methods = [
        ("deflate", CompressionMethod::Deflated, level),
        ("zstd", CompressionMethod::Zstd, 3),
    ];

    for (label, method, level) in methods {
        let options = prototype_options(method, level);
        report_byte_identity(label, &files, options);

        let mut group = c.benchmark_group(format!("zip_parallel_prototype/{label}"));
        group.sample_size(10);
        group.measurement_time(Duration::from_secs(30));
        group.throughput(Throughput::Bytes(total_bytes));
        let output = temp.path().join("output.zip");

        if label == "deflate" {
            let config = CreationConfig::default();
            group.bench_function("exarch_sequential", |b| {
                b.iter(|| {
                    create_unsynced(&output, &[&source_dir], &config);
                    fs::remove_file(&output).unwrap();
                });
            });
        }
        group.bench_function("streaming_sequential", |b| {
            b.iter(|| {
                write_streaming(File::create(&output).unwrap(), &files, options);
                fs::remove_file(&output).unwrap();
            });
        });
        for workers in PROTOTYPE_WORKERS {
            group.bench_with_input(
                BenchmarkId::new("prepared_workers", workers),
                &workers,
                |b, &workers| {
                    b.iter(|| {
                        write_prepared(File::create(&output).unwrap(), &files, options, workers);
                        fs::remove_file(&output).unwrap();
                    });
                },
            );
        }
        group.finish();
    }
}

criterion_group!(
    benches,
    benchmark_create_tar_formats,
    benchmark_staged_create_synced,
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
    benchmark_zip_parallel_prototype,
);
criterion_main!(benches);
