//! Security validation benchmarks for exarch.
//!
//! Measures validation performance:
//! - Path validation throughput (target: < 1 us per entry)
//! - Symlink validation
//! - Hardlink validation
//! - Compression ratio checks (zip bomb detection)
//!
//! These benchmarks are critical for ensuring security checks
//! do not become a bottleneck during extraction.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default,
    clippy::items_after_statements,
    missing_docs
)]

use criterion::Criterion;
use criterion::criterion_group;
use criterion::criterion_main;
use exarch_core::SecurityConfig;
use exarch_core::security::EntryValidator;
use exarch_core::security::HardlinkTracker;
use exarch_core::security::validate_compression_ratio;
use exarch_core::security::validate_symlink;
use exarch_core::types::DestDir;
use exarch_core::types::EntryType;
use exarch_core::types::SafePath;
use std::hint::black_box;
use std::path::Path;
use std::path::PathBuf;
use tempfile::TempDir;

/// Path validation benchmarks.
fn benchmark_path_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("path_validation");

    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();

    // Simple path (most common case)
    group.bench_function("simple_nonexistent", |b| {
        let path = PathBuf::from("foo/bar/baz.txt");
        b.iter(|| SafePath::validate(black_box(&path), black_box(&dest), black_box(&config)));
    });

    // Path with dots (requires normalization)
    group.bench_function("with_dot_components", |b| {
        let path = PathBuf::from("./foo/./bar/./baz.txt");
        b.iter(|| SafePath::validate(black_box(&path), black_box(&dest), black_box(&config)));
    });

    // Deep path (tests depth limits)
    group.bench_function("deep_path", |b| {
        let path = PathBuf::from("a/b/c/d/e/f/g/h/i/j/file.txt");
        b.iter(|| SafePath::validate(black_box(&path), black_box(&dest), black_box(&config)));
    });

    // Path with banned component (should fail fast)
    group.bench_function("banned_component", |b| {
        let path = PathBuf::from("foo/__MACOSX/bar.txt");
        b.iter(|| SafePath::validate(black_box(&path), black_box(&dest), black_box(&config)));
    });

    // No banned components config (optimized path)
    group.bench_function("no_banned_components", |b| {
        let mut config_no_banned = SecurityConfig::default();
        config_no_banned.banned_path_components.clear();
        let path = PathBuf::from("foo/bar/baz.txt");
        b.iter(|| {
            SafePath::validate(
                black_box(&path),
                black_box(&dest),
                black_box(&config_no_banned),
            )
        });
    });

    group.finish();
}

/// Path normalization benchmarks.
fn benchmark_normalization(c: &mut Criterion) {
    let mut group = c.benchmark_group("normalization");

    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();

    // Path without . components (should use Cow::Borrowed)
    group.bench_function("no_normalization_needed", |b| {
        let path = PathBuf::from("foo/bar/baz.txt");
        b.iter(|| SafePath::validate(black_box(&path), black_box(&dest), black_box(&config)));
    });

    // Path with many . components (requires normalization)
    group.bench_function("heavy_normalization", |b| {
        let path = PathBuf::from("./././foo/./././bar/./././baz.txt");
        b.iter(|| SafePath::validate(black_box(&path), black_box(&dest), black_box(&config)));
    });

    group.finish();
}

/// Symlink validation benchmarks.
fn benchmark_symlink_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("symlink_validation");

    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let mut config = SecurityConfig::default();
    config.allowed.symlinks = true;

    // Valid relative symlink
    group.bench_function("valid_relative", |b| {
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).unwrap();
        let target = PathBuf::from("target.txt");
        b.iter(|| {
            validate_symlink(
                black_box(&link),
                black_box(&target),
                black_box(&dest),
                black_box(&config),
            )
        });
    });

    // Valid symlink in subdirectory
    group.bench_function("valid_subdir", |b| {
        let link = SafePath::validate(&PathBuf::from("foo/link"), &dest, &config).unwrap();
        let target = PathBuf::from("../bar/target.txt");
        b.iter(|| {
            validate_symlink(
                black_box(&link),
                black_box(&target),
                black_box(&dest),
                black_box(&config),
            )
        });
    });

    // Escape attempt (should fail fast)
    group.bench_function("escape_reject", |b| {
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).unwrap();
        let target = PathBuf::from("../../etc/passwd");
        b.iter(|| {
            validate_symlink(
                black_box(&link),
                black_box(&target),
                black_box(&dest),
                black_box(&config),
            )
        });
    });

    // Disabled symlinks (should fail very fast)
    group.bench_function("disabled_reject", |b| {
        let disabled_config = SecurityConfig::default(); // symlinks disabled
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &disabled_config).unwrap();
        let target = PathBuf::from("target.txt");
        b.iter(|| {
            validate_symlink(
                black_box(&link),
                black_box(&target),
                black_box(&dest),
                black_box(&disabled_config),
            )
        });
    });

    group.finish();
}

/// Hardlink validation benchmarks.
fn benchmark_hardlink_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("hardlink_validation");

    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let mut config = SecurityConfig::default();
    config.allowed.hardlinks = true;

    // Valid hardlink
    group.bench_function("valid_target", |b| {
        let mut tracker = HardlinkTracker::new();
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).unwrap();
        let target = PathBuf::from("target.txt");
        b.iter(|| {
            tracker.validate_hardlink(
                black_box(&link),
                black_box(&target),
                black_box(&dest),
                black_box(&config),
            )
        });
    });

    // Multiple hardlinks (tracker grows)
    group.bench_function("multiple_unique_targets", |b| {
        b.iter(|| {
            let mut tracker = HardlinkTracker::new();
            for i in 0..100 {
                let link = SafePath::validate(&PathBuf::from(format!("link_{i}")), &dest, &config)
                    .unwrap();
                let target = PathBuf::from(format!("target_{i}.txt"));
                let _ = tracker.validate_hardlink(&link, &target, &dest, &config);
            }
            black_box(tracker.count())
        });
    });

    // Same target multiple times (de-duplication)
    group.bench_function("multiple_same_target", |b| {
        b.iter(|| {
            let mut tracker = HardlinkTracker::new();
            let target = PathBuf::from("shared_target.txt");
            for i in 0..100 {
                let link = SafePath::validate(&PathBuf::from(format!("link_{i}")), &dest, &config)
                    .unwrap();
                let _ = tracker.validate_hardlink(&link, &target, &dest, &config);
            }
            black_box(tracker.count())
        });
    });

    // Escape attempt (should fail fast)
    group.bench_function("escape_reject", |b| {
        let mut tracker = HardlinkTracker::new();
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).unwrap();
        let target = PathBuf::from("../../etc/passwd");
        b.iter(|| {
            tracker.validate_hardlink(
                black_box(&link),
                black_box(&target),
                black_box(&dest),
                black_box(&config),
            )
        });
    });

    group.finish();
}

/// Compression ratio validation (zip bomb detection).
fn benchmark_compression_ratio(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression_ratio");

    let config = SecurityConfig::default();

    // Normal ratio (should pass quickly)
    group.bench_function("normal_ratio", |b| {
        let compressed: u64 = 1000;
        let uncompressed: u64 = 2000; // 2x ratio
        b.iter(|| {
            validate_compression_ratio(
                black_box(compressed),
                black_box(uncompressed),
                black_box(&config),
            )
        });
    });

    // High but acceptable ratio
    group.bench_function("high_ratio", |b| {
        let compressed: u64 = 1000;
        let uncompressed: u64 = 50000; // 50x ratio
        b.iter(|| {
            validate_compression_ratio(
                black_box(compressed),
                black_box(uncompressed),
                black_box(&config),
            )
        });
    });

    // Bomb ratio (should fail)
    group.bench_function("bomb_ratio_reject", |b| {
        let compressed: u64 = 100;
        let uncompressed: u64 = 100_000_000; // 1M:1 ratio
        b.iter(|| {
            validate_compression_ratio(
                black_box(compressed),
                black_box(uncompressed),
                black_box(&config),
            )
        });
    });

    group.finish();
}

/// Entry validator orchestration benchmark.
fn benchmark_entry_validator(c: &mut Criterion) {
    let mut group = c.benchmark_group("entry_validator");

    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();

    // Single file entry
    group.bench_function("single_file", |b| {
        b.iter(|| {
            let mut validator = EntryValidator::new(&config, &dest);
            validator.validate_entry(
                black_box(Path::new("file.txt")),
                black_box(&EntryType::File),
                black_box(1024),
                black_box(None),
                black_box(Some(0o644)),
            )
        });
    });

    // File with compression ratio
    group.bench_function("file_with_compression", |b| {
        b.iter(|| {
            let mut validator = EntryValidator::new(&config, &dest);
            validator.validate_entry(
                black_box(Path::new("file.txt")),
                black_box(&EntryType::File),
                black_box(10240),
                black_box(Some(5120)), // 2x compression
                black_box(Some(0o644)),
            )
        });
    });

    // Directory entry
    group.bench_function("directory", |b| {
        b.iter(|| {
            let mut validator = EntryValidator::new(&config, &dest);
            validator.validate_entry(
                black_box(Path::new("subdir")),
                black_box(&EntryType::Directory),
                black_box(0),
                black_box(None),
                black_box(None),
            )
        });
    });

    // Multiple entries (simulates real extraction)
    group.bench_function("100_files", |b| {
        b.iter(|| {
            let mut validator = EntryValidator::new(&config, &dest);
            for i in 0..100 {
                let path = PathBuf::from(format!("dir/file_{i}.txt"));
                let _ = validator.validate_entry(&path, &EntryType::File, 1024, None, Some(0o644));
            }
            validator.finish()
        });
    });

    // Mixed entries
    group.bench_function("mixed_entries", |b| {
        let mut config_with_links = config.clone();
        config_with_links.allowed.symlinks = true;
        config_with_links.allowed.hardlinks = true;

        b.iter(|| {
            let mut validator = EntryValidator::new(&config_with_links, &dest);

            // Add directories
            for i in 0..10 {
                let path = PathBuf::from(format!("dir_{i}"));
                let _ = validator.validate_entry(&path, &EntryType::Directory, 0, None, None);
            }

            // Add files
            for i in 0..80 {
                let path = PathBuf::from(format!("dir_{}/file_{}.txt", i % 10, i));
                let _ =
                    validator.validate_entry(&path, &EntryType::File, 1024, Some(512), Some(0o644));
            }

            // Add symlinks
            for i in 0..5 {
                let path = PathBuf::from(format!("link_{i}"));
                let _ = validator.validate_entry(
                    &path,
                    &EntryType::Symlink {
                        target: PathBuf::from(format!("dir_0/file_{i}.txt")),
                    },
                    0,
                    None,
                    None,
                );
            }

            // Add hardlinks
            for i in 0..5 {
                let path = PathBuf::from(format!("hardlink_{i}"));
                let _ = validator.validate_entry(
                    &path,
                    &EntryType::Hardlink {
                        target: PathBuf::from(format!("dir_1/file_{i}.txt")),
                    },
                    0,
                    None,
                    None,
                );
            }

            validator.finish()
        });
    });

    group.finish();
}

/// Throughput benchmark - validate entries per second.
fn benchmark_validation_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("validation_throughput");

    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();

    // Pre-generate paths for consistent timing
    let paths: Vec<PathBuf> = (0..1000)
        .map(|i| PathBuf::from(format!("subdir/file_{i:04}.txt")))
        .collect();

    group.throughput(criterion::Throughput::Elements(1000));
    group.bench_function("1000_entries", |b| {
        b.iter(|| {
            let mut validator = EntryValidator::new(&config, &dest);
            for path in &paths {
                let _ = validator.validate_entry(path, &EntryType::File, 1024, None, Some(0o644));
            }
            validator.finish()
        });
    });

    group.finish();
}

/// `SecurityConfig` creation benchmark.
fn benchmark_security_config(c: &mut Criterion) {
    let mut group = c.benchmark_group("security_config");

    group.bench_function("default", |b| {
        b.iter(|| black_box(SecurityConfig::default()));
    });

    group.bench_function("clone", |b| {
        let config = SecurityConfig::default();
        b.iter(|| black_box(config.clone()));
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_path_validation,
    benchmark_normalization,
    benchmark_symlink_validation,
    benchmark_hardlink_validation,
    benchmark_compression_ratio,
    benchmark_entry_validator,
    benchmark_validation_throughput,
    benchmark_security_config,
);
criterion_main!(benches);
