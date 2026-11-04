//! Security validation benchmarks for exarch.
//!
//! Measures validation performance:
//! - Path validation throughput (target: < 1 us per entry)
//! - Symlink validation
//! - Hardlink validation
//! - Compression ratio checks (zip bomb detection)
//! - The whole entry pipeline, driven by in-memory archives
//!
//! These benchmarks are critical for ensuring security checks
//! do not become a bottleneck during extraction.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default,
    clippy::items_after_statements,
    clippy::too_many_lines,
    missing_docs
)]

use criterion::Criterion;
use criterion::criterion_group;
use criterion::criterion_main;
use exarch_core::AdmittedSize;
use exarch_core::ArchiveReader;
use exarch_core::CheckedLinkTarget;
use exarch_core::Compressed;
use exarch_core::EntrySink;
use exarch_core::SafePath;
use exarch_core::SanitizedMode;
use exarch_core::SecurityConfig;
use exarch_core::SinkOptions;
use exarch_core::Uncompressed;
use exarch_core::extract_to_sink;
use exarch_core::security::HardlinkTracker;
use exarch_core::security::validate_compression_ratio;
use exarch_core::security::validate_symlink;
use exarch_core::types::DestDir;
use std::hint::black_box;
use std::io;
use std::io::Cursor;
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
        let config_no_banned = config_no_banned;
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
    config.allowed.symlinks = exarch_core::Admit::Allow;

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
    config.allowed.hardlinks = exarch_core::Admit::Allow;

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
                Compressed(black_box(compressed)),
                Uncompressed(black_box(uncompressed)),
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
                Compressed(black_box(compressed)),
                Uncompressed(black_box(uncompressed)),
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
                Compressed(black_box(compressed)),
                Uncompressed(black_box(uncompressed)),
                black_box(&config),
            )
        });
    });

    group.finish();
}

/// A sink that stores nothing, so the benchmark measures validation and
/// placement only.
struct NullSink;

impl EntrySink for NullSink {
    type File = io::Sink;

    fn create_directory(&mut self, _: &SafePath) -> io::Result<()> {
        Ok(())
    }

    fn create_file(
        &mut self,
        _: &SafePath,
        _: Option<SanitizedMode>,
        _: AdmittedSize,
    ) -> io::Result<io::Sink> {
        Ok(io::sink())
    }

    fn finish_file(&mut self, _: &SafePath, _: io::Sink) -> io::Result<()> {
        Ok(())
    }

    fn create_symlink(&mut self, _: &SafePath, _: CheckedLinkTarget<'_>) -> io::Result<()> {
        Ok(())
    }

    fn create_hardlink(&mut self, _: &SafePath, _: &SafePath) -> io::Result<()> {
        Ok(())
    }
}

/// What an in-memory TAR archive holds.
struct TarSpec {
    directories: usize,
    files: usize,
    symlinks: usize,
    hardlinks: usize,
}

impl TarSpec {
    fn files(files: usize) -> Self {
        Self {
            directories: 0,
            files,
            symlinks: 0,
            hardlinks: 0,
        }
    }

    fn build(&self) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let append = |builder: &mut tar::Builder<Vec<u8>>,
                      name: &str,
                      kind: tar::EntryType,
                      link: Option<&str>,
                      data: &[u8]| {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(kind);
            header.set_mode(0o644);
            header.set_size(data.len() as u64);
            if let Some(link) = link {
                header.set_link_name(link).unwrap();
            }
            builder.append_data(&mut header, name, data).unwrap();
        };
        let payload = [0x61u8; 1024];
        for i in 0..self.directories {
            append(
                &mut builder,
                &format!("dir_{i}/"),
                tar::EntryType::Directory,
                None,
                &[],
            );
        }
        for i in 0..self.files {
            let dir = i % self.directories.max(1);
            let name = if self.directories == 0 {
                format!("dir/file_{i}.txt")
            } else {
                format!("dir_{dir}/file_{i}.txt")
            };
            append(&mut builder, &name, tar::EntryType::Regular, None, &payload);
        }
        for i in 0..self.symlinks {
            append(
                &mut builder,
                &format!("link_{i}"),
                tar::EntryType::Symlink,
                Some("dir_0/file_0.txt"),
                &[],
            );
        }
        for i in 0..self.hardlinks {
            append(
                &mut builder,
                &format!("hardlink_{i}"),
                tar::EntryType::Link,
                Some("dir_0/file_0.txt"),
                &[],
            );
        }
        builder.into_inner().unwrap()
    }
}

fn run_pipeline(archive: &[u8], config: &SecurityConfig) {
    extract_to_sink(
        ArchiveReader::tar(Cursor::new(archive), None),
        &mut NullSink,
        config,
        &SinkOptions::default(),
    )
    .unwrap();
}

/// The whole entry pipeline, driven by in-memory archives.
fn benchmark_entry_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("entry_pipeline");
    let config = SecurityConfig::default();

    let single = TarSpec::files(1).build();
    group.bench_function("single_file", |b| {
        b.iter(|| run_pipeline(black_box(&single), black_box(&config)));
    });

    let hundred = TarSpec::files(100).build();
    group.bench_function("100_files", |b| {
        b.iter(|| run_pipeline(black_box(&hundred), black_box(&config)));
    });

    let mixed = TarSpec {
        directories: 10,
        files: 80,
        symlinks: 5,
        hardlinks: 5,
    }
    .build();
    let config_with_links = SecurityConfig::default()
        .with_allow_symlinks(true)
        .with_allow_hardlinks(true);
    group.bench_function("mixed_entries", |b| {
        b.iter(|| run_pipeline(black_box(&mixed), black_box(&config_with_links)));
    });

    group.finish();
}

/// Throughput benchmark - validate entries per second.
fn benchmark_validation_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("validation_throughput");
    let config = SecurityConfig::default();

    let archive = TarSpec::files(1000).build();
    group.throughput(criterion::Throughput::Elements(1000));
    group.bench_function("1000_entries", |b| {
        b.iter(|| run_pipeline(black_box(&archive), black_box(&config)));
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
    benchmark_entry_pipeline,
    benchmark_validation_throughput,
    benchmark_security_config,
);
criterion_main!(benches);
