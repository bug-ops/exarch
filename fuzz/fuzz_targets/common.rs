//! Shared fuzz-harness helpers: the `SecurityConfig` every target reuses.
//!
//! Bounds are tight enough that a legitimate extraction cannot be mistaken
//! for a libFuzzer hang and memory use stays bounded (ASan + a solid 7z
//! block). Included via `#[path = "common.rs"] mod common;` in each target,
//! since cargo-fuzz targets are independent `[[bin]]` crate roots.
//!
//! Symlinks, hardlinks, and solid archives are deliberately allowed here,
//! unlike `SecurityConfig::default()`. The deny-by-default policy return in
//! `SafeSymlink::validate` / `HardlinkTracker::validate_hardlink` is a
//! one-line branch already exhaustively covered by
//! `crates/exarch-core/tests/security/`; fuzzing it repeatedly finds
//! nothing new. The escape-detection logic *behind* that branch -- the
//! subsystem behind this repo's two closed P0 advisories, GHSA-x8wr and
//! GHSA-j9wj -- is what a security-focused fuzz harness should spend its
//! cycles on, and it is unreachable unless these are enabled. Likewise,
//! `allow_solid_archives` gates `sevenz.rs`'s solid-block decode path, which
//! is what `with_max_solid_block_memory` below is meant to bound; left at
//! its default `false`, that bound would be dead configuration.

use std::sync::OnceLock;

use exarch_core::SecurityConfig;
use exarch_core::Unvalidated;
use exarch_core::Validated;

fn base_config() -> SecurityConfig<Unvalidated> {
    SecurityConfig::default()
        .with_max_file_size(1024 * 1024)
        .with_max_total_size(4 * 1024 * 1024)
        .with_max_file_count(64)
        .with_max_tar_metadata_bytes(64 * 1024)
        .with_max_solid_block_memory(1024 * 1024)
        .with_allow_symlinks(true)
        .with_allow_hardlinks(true)
        .with_allow_solid_archives(true)
}

/// For targets calling `ArchiveFormat::list`/`verify` directly, which require
/// an already-validated config.
#[allow(dead_code)]
pub fn validated() -> &'static SecurityConfig<Validated> {
    static CONFIG: OnceLock<SecurityConfig<Validated>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        base_config()
            .validate()
            .expect("fuzz harness SecurityConfig must be internally consistent")
    })
}

/// For `extract_archive`, which clones and validates its config internally
/// on every call.
#[allow(dead_code)]
pub fn unvalidated() -> &'static SecurityConfig<Unvalidated> {
    static CONFIG: OnceLock<SecurityConfig<Unvalidated>> = OnceLock::new();
    CONFIG.get_or_init(base_config)
}
