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
//! `SolidArchives::Allow` gates `sevenz.rs`'s solid-block decode path, which
//! is what the solid block limit below is meant to bound; left at its default
//! `Refuse`, that bound would not exist.

use std::num::NonZeroU64;
use std::sync::OnceLock;

use exarch_core::DecompressionBudget;
use exarch_core::IntegrityCheck;
use exarch_core::SecurityConfig;
use exarch_core::SolidArchives;
use exarch_core::SolidLimits;
use exarch_core::VerificationOptions;
use exarch_core::ZipConsistencyPolicy;

fn base_config() -> SecurityConfig {
    SecurityConfig::default()
        .with_max_file_size(exarch_core::non_zero!(1024 * 1024))
        .with_max_total_size(exarch_core::non_zero!(4 * 1024 * 1024))
        .with_max_file_count(exarch_core::non_zero!(64))
        .with_max_tar_metadata_bytes(exarch_core::non_zero!(64 * 1024))
        .with_allow_symlinks(true)
        .with_allow_hardlinks(true)
        .with_solid_archives(SolidArchives::Allow(
            SolidLimits::DEFAULT.with_max_block_memory(exarch_core::non_zero!(1024 * 1024)),
        ))
}

/// The harness config every target reuses.
#[allow(dead_code)]
pub fn config() -> &'static SecurityConfig {
    static CONFIG: OnceLock<SecurityConfig> = OnceLock::new();
    CONFIG.get_or_init(base_config)
}

/// Like [`config`], but with the ZIP structure policy relaxed so the archives
/// `Enforce` rejects early still reach listing and verification.
#[allow(dead_code)]
pub fn config_ignoring_zip_structure() -> &'static SecurityConfig {
    static CONFIG: OnceLock<SecurityConfig> = OnceLock::new();
    CONFIG.get_or_init(|| base_config().with_zip_consistency(ZipConsistencyPolicy::Ignore))
}

/// `verify` options with the integrity pass enabled under a small budget, so
/// the decode-to-EOF path is fuzzed without risking a libFuzzer timeout.
#[allow(dead_code)]
pub fn verification_options() -> VerificationOptions {
    let budget = DecompressionBudget::new(NonZeroU64::MIN.saturating_add(4 * 1024 * 1024 - 1));
    VerificationOptions::default().with_integrity(IntegrityCheck::DecodeToEof(budget))
}
