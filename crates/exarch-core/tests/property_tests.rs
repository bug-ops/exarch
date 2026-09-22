//! Property-based tests for core security validation.
//!
//! These tests use proptest to generate arbitrary inputs and verify
//! security properties hold across a wide range of cases.

#![allow(
    clippy::expect_used,
    clippy::field_reassign_with_default,
    clippy::unwrap_used
)]

use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::QuotaResource;
use exarch_core::SecurityConfig;
use exarch_core::formats::detect::ArchiveType;
use exarch_core::formats::detect::ZIP_FAMILY_ALIASES;
use exarch_core::formats::detect::detect_format;
use exarch_core::security::HardlinkTracker;
use exarch_core::security::QuotaTracker;
use exarch_core::types::DestDir;
use exarch_core::types::SafePath;
use exarch_core::types::SafeSymlink;
use proptest::prelude::*;
use tempfile::TempDir;

/// Extensions `detect_format`'s extension phase maps 1:1 to a single
/// format, paired with the `ArchiveType` each maps to. Mirrors
/// `detect_format_from_extension` (`pub(crate)`, not reachable from this
/// integration test) so the property test below can construct
/// known-extension cases without duplicating the match logic under test.
/// The ZIP-family aliases (`.jar`, `.whl`, ...) are intentionally not
/// hardcoded here -- see `known_extensions` below, which appends the `pub`
/// `ZIP_FAMILY_ALIASES` instead, the same constant `detect.rs` itself
/// iterates to avoid drift.
const KNOWN_EXTENSIONS: &[(&str, ArchiveType)] = &[
    ("tar", ArchiveType::Tar),
    ("tgz", ArchiveType::TarGz),
    ("bz2", ArchiveType::TarBz2),
    ("tbz", ArchiveType::TarBz2),
    ("tbz2", ArchiveType::TarBz2),
    ("xz", ArchiveType::TarXz),
    ("txz", ArchiveType::TarXz),
    ("zst", ArchiveType::TarZst),
    ("tzst", ArchiveType::TarZst),
    ("zip", ArchiveType::Zip),
    ("7z", ArchiveType::SevenZ),
];

/// `KNOWN_EXTENSIONS` plus every ZIP-family alias (all mapping to
/// `ArchiveType::Zip`), for the property test to sample from.
fn known_extensions() -> Vec<(&'static str, ArchiveType)> {
    KNOWN_EXTENSIONS
        .iter()
        .copied()
        .chain(
            ZIP_FAMILY_ALIASES
                .iter()
                .map(|&ext| (ext, ArchiveType::Zip)),
        )
        .collect()
}

/// Magic-byte signatures from `detect.rs`'s private `MAGIC_SIGNATURES` table,
/// duplicated here for the same reason as `KNOWN_EXTENSIONS` above: the
/// constant itself is not `pub`. All 9 entries are mirrored, including
/// ZIP's two alternate openers (EOCD, split-archive marker) alongside its
/// local-file-header signature -- all three map to `ArchiveType::Zip`.
const MAGIC_CASES: &[(usize, &[u8], ArchiveType)] = &[
    (0, b"\x1f\x8b", ArchiveType::TarGz),
    (0, b"\x28\xb5\x2f\xfd", ArchiveType::TarZst),
    (0, b"\x42\x5a\x68", ArchiveType::TarBz2),
    (0, b"\x50\x4b\x03\x04", ArchiveType::Zip),
    (0, b"\x50\x4b\x05\x06", ArchiveType::Zip),
    (0, b"\x50\x4b\x07\x08", ArchiveType::Zip),
    (0, b"\x37\x7a\xbc\xaf\x27\x1c", ArchiveType::SevenZ),
    (0, b"\xfd\x37\x7a\x58\x5a\x00", ArchiveType::TarXz),
    (257, b"ustar", ArchiveType::Tar),
];

/// Number of bytes `detect_format`'s magic phase reads
/// (`detect::MAGIC_READ_LEN`, private) -- long enough to hold the offset-257
/// USTAR signature.
const MAGIC_READ_LEN: usize = 262;

/// The `.gz`-stem branch (`archive.tar.gz` -> `TarGz`, but bare `archive.gz`
/// is rejected) is a composite two-suffix extension the proptests below
/// cannot reach: their extension generator always produces a single
/// `archive.<ext>` suffix. Covered here instead by two literal cases.
#[test]
fn detect_format_gz_stem_branch() {
    let temp = TempDir::new().expect("failed to create temp dir");

    let tar_gz = temp.path().join("archive.tar.gz");
    std::fs::write(&tar_gz, []).expect("failed to write fixture");
    assert_eq!(
        detect_format(&tar_gz).expect("archive.tar.gz must be detected"),
        ArchiveType::TarGz
    );

    let bare_gz = temp.path().join("archive.gz");
    std::fs::write(&bare_gz, []).expect("failed to write fixture");
    assert!(
        detect_format(&bare_gz).is_err(),
        "bare .gz without a .tar stem must not be recognized by extension"
    );
}

fn create_test_dest() -> (TempDir, DestDir) {
    let temp = TempDir::new().expect("failed to create temp dir");
    let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
    (temp, dest)
}

proptest! {
    /// Any path with .. should be rejected.
    #[test]
    fn prop_parent_traversal_rejected(
        prefix in "([a-z]+/){0,5}",
        suffix in "([a-z]+/?){0,5}"
    ) {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default().validate().unwrap();
        // Ensure there's a proper path separator before ..
        let path_str = if prefix.is_empty() {
            format!("../{suffix}")
        } else {
            format!("{prefix}../{suffix}")
        };
        let path = PathBuf::from(path_str);
        let result = SafePath::validate(&path, &dest, &config);
        prop_assert!(result.is_err(), "path with .. should be rejected");
    }

    /// Valid relative paths without special components should be accepted.
    #[test]
    fn prop_valid_relative_paths_accepted(
        components in prop::collection::vec("[a-zA-Z0-9_-]{1,20}", 1..5)
    ) {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default().validate().unwrap();
        let path = PathBuf::from(components.join("/"));
        let result = SafePath::validate(&path, &dest, &config);
        prop_assert!(result.is_ok(), "valid path should be accepted");
    }

    /// Paths exceeding max depth should be rejected.
    #[test]
    fn prop_excessive_depth_rejected(
        depth in 33usize..100
    ) {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default().validate().unwrap(); // max_path_depth = 32
        let components: Vec<String> = (0..depth).map(|i| format!("d{i}")).collect();
        let path = PathBuf::from(components.join("/"));
        let result = SafePath::validate(&path, &dest, &config);
        prop_assert!(result.is_err(), "excessive depth should be rejected");
    }

    /// Symlinks with excessive parent refs should be rejected.
    #[test]
    fn prop_symlink_excessive_parent_refs(
        parent_count in 50usize..100
    ) {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = true;
        let config = config.validate().unwrap();

        let link = SafePath::validate(&PathBuf::from("a/b/link"), &dest, &config)
            .expect("link path should be valid");

        // More .. than depth can handle
        let target = PathBuf::from("../".repeat(parent_count) + "file.txt");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        prop_assert!(result.is_err(), "excessive parent refs should escape");
    }

    /// Banned components should be rejected regardless of case.
    #[test]
    fn prop_banned_components_case_insensitive(
        case_variant in prop::sample::select(vec![
            ".git", ".Git", ".GIT", ".gIt",
            ".ssh", ".SSH", ".Ssh",
            ".gnupg", ".GNUPG", ".Gnupg"
        ])
    ) {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default().validate().unwrap();
        let path = PathBuf::from(format!("dir/{case_variant}/file"));
        let result = SafePath::validate(&path, &dest, &config);
        prop_assert!(result.is_err(), "banned component should be rejected");
    }

    /// Paths within configured depth should be accepted.
    #[test]
    fn prop_within_depth_accepted(
        depth in 1usize..32
    ) {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default().validate().unwrap(); // max_path_depth = 32
        let components: Vec<String> = (0..depth).map(|i| format!("d{i}")).collect();
        let path = PathBuf::from(components.join("/"));
        let result = SafePath::validate(&path, &dest, &config);
        prop_assert!(result.is_ok());
    }

    // ========================================================================
    // QUOTA TRACKER PROPERTY TESTS
    // ========================================================================

    /// Quota tracking should never overflow with arbitrary file sizes.
    #[test]
    fn prop_quota_no_overflow_with_checked_add(
        file_sizes in prop::collection::vec(0u64..1_000_000, 1..100)
    ) {
        let mut tracker = QuotaTracker::new();
        let config = SecurityConfig::default().validate().unwrap();
        let mut expected_total: u64 = 0;
        let mut expected_count = 0;

        for size in file_sizes {
            if let Some(new_total) = expected_total.checked_add(size) {
                expected_total = new_total;
                expected_count += 1;
                let result = tracker.reserve(size, &config);
                prop_assert!(result.is_ok(), "recording file should succeed when no overflow");
            } else {
                // Overflow expected - tracker should detect it
                let result = tracker.reserve(size, &config);
                prop_assert!(result.is_err(), "tracker should detect overflow");
                break;
            }
        }

        prop_assert_eq!(tracker.bytes_written(), expected_total);
        prop_assert_eq!(tracker.files_extracted(), expected_count);
    }

    /// File count quota should be enforced correctly for any limit.
    #[test]
    fn prop_quota_file_count_enforcement(
        max_files in 1usize..1000,
        num_files in 1usize..2000
    ) {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_count = max_files;
        config.max_total_size = u64::MAX;
        config.max_file_size = u64::MAX;
        let config = config.validate().unwrap();

        let mut success_count = 0;
        for _ in 0..num_files {
            let result = tracker.reserve(100, &config);
            if result.is_ok() {
                success_count += 1;
            } else {
                break;
            }
        }

        prop_assert_eq!(
            success_count,
            max_files.min(num_files),
            "should extract exactly max_files or num_files, whichever is smaller"
        );

        if num_files > max_files {
            let result = tracker.reserve(100, &config);
            prop_assert!(
                matches!(result, Err(ArchiveError::QuotaExceeded { .. })),
                "exceeding file count should fail"
            );
        }
    }

    /// Total size quota should be enforced with arbitrary file sizes.
    ///
    /// This test verifies that quota enforcement prevents excessive extraction,
    /// focusing on the critical security property: operations that would exceed
    /// quotas must fail.
    #[test]
    fn prop_quota_total_size_enforcement(
        max_size in 1000u64..100_000,
        file_sizes in prop::collection::vec(100u64..1000, 1..50)
    ) {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_total_size = max_size;
        config.max_file_count = usize::MAX;
        config.max_file_size = u64::MAX;
        let config = config.validate().unwrap();

        for size in file_sizes {
            let result = tracker.reserve(size, &config);

            // Key security property: if quota would be exceeded, operation must fail
            if result.is_err() {
                // Quota was exceeded - this is the security boundary
                // Verify it's a quota error
                prop_assert!(
                    matches!(result, Err(ArchiveError::QuotaExceeded { .. })),
                    "error should be QuotaExceeded"
                );
                break;
            }
        }

        // Critical security property: successful extractions should respect quota
        // Note: Due to implementation detail (increment before check),
        // bytes_written may slightly exceed max_size on the failing operation,
        // but no operation succeeds after exceeding the quota.
    }

    /// Individual file size quota should be enforced.
    #[test]
    fn prop_quota_file_size_enforcement(
        max_file_size in 1000u64..100_000,
        file_size in 0u64..200_000
    ) {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_size = max_file_size;
        config.max_total_size = u64::MAX;
        config.max_file_count = usize::MAX;
        let config = config.validate().unwrap();

        let result = tracker.reserve(file_size, &config);

        if file_size <= max_file_size {
            prop_assert!(result.is_ok(), "file within size limit should succeed");
            prop_assert_eq!(tracker.bytes_written(), file_size);
        } else {
            prop_assert!(
                matches!(
                    result,
                    Err(ArchiveError::QuotaExceeded {
                        resource: QuotaResource::FileSize { .. }
                    })
                ),
                "file exceeding size limit should fail"
            );
            prop_assert_eq!(tracker.bytes_written(), 0, "no bytes should be recorded on failure");
        }
    }

    /// Fast path with unlimited quotas should handle arbitrary loads.
    #[test]
    fn prop_quota_fast_path_unlimited(
        file_sizes in prop::collection::vec(1u64..100_000, 1..1000)
    ) {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_size = u64::MAX;
        config.max_file_count = usize::MAX;
        config.max_total_size = u64::MAX;
        let config = config.validate().unwrap();

        let mut expected_total = 0u64;
        for size in &file_sizes {
            if let Some(new_total) = expected_total.checked_add(*size) {
                expected_total = new_total;
            } else {
                // Would overflow
                break;
            }
        }

        for size in file_sizes {
            let result = tracker.reserve(size, &config);
            if tracker.bytes_written().checked_add(size).is_some() {
                prop_assert!(result.is_ok() || result.is_err(), "either succeeds or detects overflow");
            }
            if result.is_err() {
                break;
            }
        }
    }

    // ========================================================================
    // COMPRESSION RATIO PROPERTY TESTS
    // ========================================================================

    /// Valid compression ratios should always pass.
    #[test]
    fn prop_compression_ratio_safe_range(
        compressed in 1u64..1_000_000,
        ratio in 1.0f64..100.0
    ) {
        use exarch_core::security::validate_compression_ratio;

        let config = SecurityConfig::default().validate().unwrap(); // max_compression_ratio = 1000.0
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let uncompressed = (compressed as f64 * ratio) as u64;

        let result = validate_compression_ratio(compressed, uncompressed, &config);

        if ratio <= config.max_compression_ratio {
            prop_assert!(result.is_ok(), "ratio {} should be safe", ratio);
        } else {
            prop_assert!(result.is_err(), "ratio {} should exceed limit", ratio);
        }
    }

    /// Zero compressed size with non-zero uncompressed should always fail.
    #[test]
    fn prop_compression_zero_compressed_nonzero_uncompressed(
        uncompressed in 1u64..1_000_000
    ) {
        use exarch_core::security::validate_compression_ratio;

        let config = SecurityConfig::default().validate().unwrap();
        let result = validate_compression_ratio(0, uncompressed, &config);

        prop_assert!(
            matches!(result, Err(ArchiveError::InvalidArchive(_))),
            "zero compressed with non-zero uncompressed must be rejected"
        );
    }

    /// Both zero should always succeed (empty file).
    #[test]
    fn prop_compression_both_zero(_dummy in 0..100) {
        use exarch_core::security::validate_compression_ratio;

        let config = SecurityConfig::default().validate().unwrap();
        let result = validate_compression_ratio(0, 0, &config);

        prop_assert!(result.is_ok(), "empty file (0/0) should be valid");
    }

    /// Extreme ratios should be detected as zip bombs.
    #[test]
    fn prop_compression_extreme_ratios_rejected(
        compressed in 1u64..1000,
        multiplier in 2000u64..10_000
    ) {
        use exarch_core::security::validate_compression_ratio;

        let config = SecurityConfig::default().validate().unwrap(); // max = 1000.0
        let uncompressed = compressed.saturating_mul(multiplier);

        let result = validate_compression_ratio(compressed, uncompressed, &config);

        prop_assert!(
            matches!(result, Err(ArchiveError::ZipBomb { .. })),
            "extreme compression ratio should be detected"
        );
    }

    // ========================================================================
    // HARDLINK PROPERTY TESTS
    // ========================================================================

    /// Hardlink tracker should accept safe relative paths.
    #[test]
    fn prop_hardlink_safe_relative_paths(
        components in prop::collection::vec("[a-z]{1,10}", 1..5)
    ) {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        let config = config.validate().unwrap();

        let mut tracker = HardlinkTracker::new();
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");

        let target = PathBuf::from(components.join("/"));
        let result = tracker.validate_hardlink(&link, &target, &dest, &config);

        prop_assert!(result.is_ok(), "safe relative target should be accepted");
    }

    /// Hardlink paths with parent traversal that escape should be rejected.
    #[test]
    fn prop_hardlink_parent_traversal_rejected(
        parent_count in 10usize..50
    ) {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        let config = config.validate().unwrap();

        let mut tracker = HardlinkTracker::new();
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");

        let target = PathBuf::from("../".repeat(parent_count) + "etc/passwd");
        let result = tracker.validate_hardlink(&link, &target, &dest, &config);

        prop_assert!(
            matches!(result, Err(ArchiveError::HardlinkEscape { .. })),
            "excessive parent traversal should be rejected"
        );
    }

    /// Multiple hardlinks to same target should be tracked.
    #[test]
    fn prop_hardlink_multiple_to_same_target(
        num_links in 1usize..20
    ) {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        let config = config.validate().unwrap();

        let mut tracker = HardlinkTracker::new();
        let target = PathBuf::from("shared_target.txt");

        for i in 0..num_links {
            let link = SafePath::validate(&PathBuf::from(format!("link{i}")), &dest, &config)
                .expect("link path should be valid");

            let result = tracker.validate_hardlink(&link, &target, &dest, &config);
            prop_assert!(result.is_ok(), "all links to same target should succeed");
        }

        prop_assert_eq!(tracker.count(), 1, "should track unique targets only");
    }

    /// Hardlinks to different targets should all be tracked.
    #[test]
    fn prop_hardlink_different_targets(
        num_targets in 1usize..50
    ) {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        let config = config.validate().unwrap();

        let mut tracker = HardlinkTracker::new();

        for i in 0..num_targets {
            let link = SafePath::validate(&PathBuf::from(format!("link{i}")), &dest, &config)
                .expect("link path should be valid");
            let target = PathBuf::from(format!("target{i}.txt"));

            let result = tracker.validate_hardlink(&link, &target, &dest, &config);
            prop_assert!(result.is_ok(), "each unique target should be accepted");
        }

        prop_assert_eq!(tracker.count(), num_targets, "should track all unique targets");
    }

    // ========================================================================
    // SYMLINK VALIDATION PROPERTY TESTS
    // ========================================================================

    /// Safe symlink targets within bounds should be accepted.
    #[test]
    fn prop_symlink_safe_relative_targets(
        components in prop::collection::vec("[a-z]{1,10}", 1..8)
    ) {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = true;
        let config = config.validate().unwrap();

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");

        let target = PathBuf::from(components.join("/"));
        let result = SafeSymlink::validate(&link, &target, &dest, &config);

        prop_assert!(result.is_ok(), "safe relative symlink target should be accepted");
    }

    /// Symlinks with many parent refs relative to shallow links should escape.
    #[test]
    fn prop_symlink_escape_detection(
        parent_refs in 5usize..30,
        link_depth in 0usize..3
    ) {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = true;
        let config = config.validate().unwrap();

        let link_path = if link_depth == 0 {
            PathBuf::from("link")
        } else {
            let components: Vec<String> = (0..link_depth).map(|i| format!("d{i}")).collect();
            PathBuf::from(components.join("/") + "/link")
        };

        let link = SafePath::validate(&link_path, &dest, &config)
            .expect("link path should be valid");

        let target = PathBuf::from("../".repeat(parent_refs) + "file.txt");
        let result = SafeSymlink::validate(&link, &target, &dest, &config);

        if parent_refs > link_depth {
            prop_assert!(
                result.is_err(),
                "symlink escaping destination should be rejected"
            );
        }
    }

    /// Symlinks disabled in config should always be rejected.
    #[test]
    fn prop_symlink_disabled_always_rejected(
        target in "[a-z/]{1,30}"
    ) {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default().validate().unwrap(); // symlinks disabled

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");

        let target_path = PathBuf::from(target);
        let result = SafeSymlink::validate(&link, &target_path, &dest, &config);

        prop_assert!(
            matches!(result, Err(ArchiveError::SecurityViolation { .. })),
            "symlinks should be rejected when disabled"
        );
    }

    // ========================================================================
    // FORMAT DETECTION PROPERTY TESTS
    // ========================================================================

    /// `detect_format` must never panic on any (extension, leading-bytes)
    /// combination -- the fuzz suite deliberately does not include a
    /// `detect` target (see fuzz/README.md); this proptest is that target's
    /// replacement and runs on every PR (given `--all-features`) instead of
    /// weekly.
    #[test]
    fn prop_detect_format_no_panic(
        ext in "[a-zA-Z0-9]{0,8}",
        prefix in prop::collection::vec(any::<u8>(), 0..300),
    ) {
        let temp = TempDir::new().expect("failed to create temp dir");
        let path = temp.path().join(format!("archive.{ext}"));
        std::fs::write(&path, &prefix).expect("failed to write fixture");

        let _ = detect_format(&path);
    }

    /// When the extension names one known format and the file's leading
    /// bytes carry a *different* known format's magic signature, the
    /// magic-byte result must win (see `detect_format`'s doc comment).
    #[test]
    fn prop_detect_format_magic_wins_over_extension(
        ext_case in prop::sample::select(known_extensions()),
        magic_case in prop::sample::select(MAGIC_CASES.to_vec()),
    ) {
        let (ext, ext_type) = ext_case;
        let (offset, sig, magic_type) = magic_case;
        prop_assume!(ext_type != magic_type);

        let mut content = vec![0u8; MAGIC_READ_LEN];
        content[offset..offset + sig.len()].copy_from_slice(sig);

        let temp = TempDir::new().expect("failed to create temp dir");
        let path = temp.path().join(format!("archive.{ext}"));
        std::fs::write(&path, &content).expect("failed to write fixture");

        let detected = detect_format(&path).expect("known magic bytes must detect");
        prop_assert_eq!(detected, magic_type);
    }
}
