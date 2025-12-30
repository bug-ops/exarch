//! Benchmarks for exarch-core extraction.

use criterion::{criterion_group, criterion_main, Criterion};
use exarch_core::SecurityConfig;

fn benchmark_security_config(c: &mut Criterion) {
    c.bench_function("create_default_config", |b| {
        b.iter(SecurityConfig::default);
    });
}

criterion_group!(benches, benchmark_security_config);
criterion_main!(benches);
