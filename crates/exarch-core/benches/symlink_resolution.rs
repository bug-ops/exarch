//! Symlink resolution benchmarks.
//!
//! Two shapes of extraction that spend their time resolving link targets:
//!
//! - `deep_chain`: 30 chained links, each reaching a directory 31 components
//!   deep through a `..`-prefixed target, with 2000 files written below the
//!   last link; every file walks the whole chain.
//! - `link_heavy`: 10000 link entries at depth 20, each validated against its
//!   parents and a target that crosses a sibling directory.
#![allow(clippy::disallowed_methods)]
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use criterion::Criterion;
use criterion::criterion_group;
use criterion::criterion_main;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;

const CHAIN_LINKS: usize = 30;
const CHAIN_COMPONENTS: usize = 31;
const CHAIN_FILES: usize = 2000;
const HEAVY_LINKS: usize = 10_000;
const HEAVY_DEPTH: usize = 20;

fn config() -> SecurityConfig {
    SecurityConfig::default()
        .with_allow_symlinks(true)
        .with_max_path_depth(exarch_core::non_zero!(200))
        .with_max_file_count(exarch_core::non_zero!(100_000))
}

fn header(kind: tar::EntryType, size: u64) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(kind);
    header.set_size(size);
    header.set_mode(0o755);
    header
}

fn nested(prefix: &str, components: usize) -> PathBuf {
    let mut path = PathBuf::from(prefix);
    for level in 1..components {
        path.push(format!("c{level}"));
    }
    path
}

fn link(builder: &mut tar::Builder<Vec<u8>>, at: &Path, target: &Path) {
    builder
        .append_link(&mut header(tar::EntryType::Symlink, 0), at, target)
        .unwrap();
}

fn deep_chain_archive() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for index in 1..=CHAIN_LINKS {
        let dir = nested(&format!("s{index}"), CHAIN_COMPONENTS);
        builder
            .append_data(
                &mut header(tar::EntryType::Directory, 0),
                format!("{}/", dir.display()),
                std::io::empty(),
            )
            .unwrap();
    }
    link(
        &mut builder,
        Path::new("k0"),
        &nested("s1", CHAIN_COMPONENTS),
    );
    for index in 1..CHAIN_LINKS {
        let at = nested(&format!("s{index}"), CHAIN_COMPONENTS).join(format!("k{index}"));
        let up = PathBuf::from("../".repeat(CHAIN_COMPONENTS));
        let target = up.join(nested(&format!("s{}", index + 1), CHAIN_COMPONENTS));
        link(&mut builder, &at, &target);
    }
    let through: PathBuf = (0..CHAIN_LINKS).map(|index| format!("k{index}")).collect();
    for file in 0..CHAIN_FILES {
        builder
            .append_data(
                &mut header(tar::EntryType::Regular, 1),
                through.join(format!("f{file}")),
                &b"x"[..],
            )
            .unwrap();
    }
    builder.into_inner().unwrap()
}

fn link_heavy_archive() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let dir = nested("a0", HEAVY_DEPTH);
    builder
        .append_data(
            &mut header(tar::EntryType::Directory, 0),
            format!("{}/", dir.display()),
            std::io::empty(),
        )
        .unwrap();
    builder
        .append_data(
            &mut header(tar::EntryType::Regular, 1),
            dir.join("t"),
            &b"x"[..],
        )
        .unwrap();
    for index in 0..HEAVY_LINKS {
        link(
            &mut builder,
            &dir.join(format!("l{index}")),
            Path::new("../c19/t"),
        );
    }
    builder.into_inner().unwrap()
}

fn extract_once(archive: &Path, config: &SecurityConfig) {
    let out = TempDir::new().unwrap();
    extract_archive(archive, out.path(), config).unwrap();
}

fn bench_shape(criterion: &mut Criterion, name: &str, bytes: &[u8]) {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("fixture.tar");
    std::fs::write(&archive, bytes).unwrap();
    let config = config();
    extract_once(&archive, &config);

    let mut group = criterion.benchmark_group("symlink_resolution");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));
    group.bench_function(name, |bencher| {
        bencher.iter(|| extract_once(&archive, &config));
    });
    group.finish();
}

fn benches(criterion: &mut Criterion) {
    bench_shape(criterion, "deep_chain", &deep_chain_archive());
    bench_shape(criterion, "link_heavy", &link_heavy_archive());
}

criterion_group!(symlink_resolution, benches);
criterion_main!(symlink_resolution);
