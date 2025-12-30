//! Benchmarks for path validation performance.

#![allow(clippy::unwrap_used, clippy::field_reassign_with_default)]

use criterion::Criterion;
use criterion::criterion_group;
use criterion::criterion_main;
use exarch_core::SecurityConfig;
use exarch_core::types::DestDir;
use exarch_core::types::SafePath;
use std::hint::black_box;
use std::path::PathBuf;
use tempfile::TempDir;

fn benchmark_path_validation(c: &mut Criterion) {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();

    let mut group = c.benchmark_group("path_validation");

    group.bench_function("simple_nonexistent", |b| {
        let path = PathBuf::from("foo/bar/baz.txt");
        b.iter(|| SafePath::validate(black_box(&path), black_box(&dest), black_box(&config)));
    });

    group.bench_function("with_dot_components", |b| {
        let path = PathBuf::from("./foo/./bar/./baz.txt");
        b.iter(|| SafePath::validate(black_box(&path), black_box(&dest), black_box(&config)));
    });

    group.bench_function("deep_path", |b| {
        let path = PathBuf::from("a/b/c/d/e/f/g/h/i/j/file.txt");
        b.iter(|| SafePath::validate(black_box(&path), black_box(&dest), black_box(&config)));
    });

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

fn benchmark_normalization(c: &mut Criterion) {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default();

    let mut group = c.benchmark_group("normalization");

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

criterion_group!(benches, benchmark_path_validation, benchmark_normalization);
criterion_main!(benches);
