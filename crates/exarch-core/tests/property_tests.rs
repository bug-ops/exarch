//! Property-based tests for core types.

#![allow(clippy::expect_used, clippy::field_reassign_with_default)]

use exarch_core::SecurityConfig;
use exarch_core::types::DestDir;
use exarch_core::types::SafePath;
use exarch_core::types::SafeSymlink;
use proptest::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;

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
        let config = SecurityConfig::default();
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
        let config = SecurityConfig::default();
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
        let config = SecurityConfig::default(); // max_path_depth = 32
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
        config.allow_symlinks = true;

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
        let config = SecurityConfig::default();
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
        let config = SecurityConfig::default(); // max_path_depth = 32
        let components: Vec<String> = (0..depth).map(|i| format!("d{i}")).collect();
        let path = PathBuf::from(components.join("/"));
        let result = SafePath::validate(&path, &dest, &config);
        prop_assert!(result.is_ok());
    }
}
