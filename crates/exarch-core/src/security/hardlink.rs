//! Hardlink security validation and tracking.

use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;

use crate::ExtractionError;
use crate::Result;
use crate::SecurityConfig;
use crate::types::DestDir;
use crate::types::SafePath;
use crate::types::safe_symlink::resolve_through_symlinks;

/// Tracks hardlink targets during extraction.
///
/// Hardlinks in archives can be used for attacks:
/// 1. Link to files outside the extraction directory
/// 2. Create multiple hardlinks to the same file (resource exhaustion)
/// 3. Link to sensitive files (if absolute paths allowed)
///
/// This tracker ensures:
/// - Hardlinks are allowed in the security configuration
/// - Targets are relative paths
/// - Targets resolve within the destination directory
/// - Duplicate hardlinks are detected
///
/// # Two-Pass Validation
///
/// Hardlinks require two-pass validation:
/// 1. **First pass (during validation):** Track target paths, verify they're
///    within bounds
/// 2. **Second pass (after extraction):** Verify targets actually exist
///
/// This is necessary because hardlink targets may appear later in the archive.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::SecurityConfig;
/// use exarch_core::security::HardlinkTracker;
/// use exarch_core::types::DestDir;
/// use exarch_core::types::SafePath;
/// use std::path::Path;
/// use std::path::PathBuf;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dest = DestDir::new(PathBuf::from("/tmp"))?;
/// let mut config = SecurityConfig::default();
/// config.allowed.hardlinks = true;
///
/// let mut tracker = HardlinkTracker::new();
/// let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)?;
/// let target = Path::new("target.txt");
///
/// tracker.validate_hardlink(&link, target, &dest, &config)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Default)]
pub struct HardlinkTracker {
    /// Maps target path to the first link path that referenced it
    seen_targets: HashMap<PathBuf, PathBuf>,
}

impl HardlinkTracker {
    /// Creates a new hardlink tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen_targets: HashMap::new(),
        }
    }

    /// Validates that a hardlink target is safe and tracks it.
    ///
    /// # Performance
    ///
    /// Typical execution time: ~1-5 μs (`HashMap` insert + path validation)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Hardlinks are not allowed in configuration
    /// - Target is an absolute path
    /// - Target would escape the destination directory
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use exarch_core::SecurityConfig;
    /// use exarch_core::security::HardlinkTracker;
    /// use exarch_core::types::DestDir;
    /// use exarch_core::types::SafePath;
    /// use std::path::Path;
    /// use std::path::PathBuf;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let dest = DestDir::new(PathBuf::from("/tmp"))?;
    /// let mut config = SecurityConfig::default();
    /// config.allowed.hardlinks = true;
    ///
    /// let mut tracker = HardlinkTracker::new();
    /// let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)?;
    /// let target = Path::new("target.txt");
    ///
    /// tracker.validate_hardlink(&link, target, &dest, &config)?;
    /// # Ok(())
    /// # }
    /// ```
    #[allow(clippy::items_after_statements)]
    pub fn validate_hardlink(
        &mut self,
        link_path: &SafePath,
        target: &Path,
        dest: &DestDir,
        config: &SecurityConfig,
    ) -> Result<()> {
        // Check if hardlinks are allowed
        if !config.allowed.hardlinks {
            return Err(ExtractionError::SecurityViolation {
                reason: "hardlinks not allowed".into(),
            });
        }

        use std::path::Component;

        // H-SEC-2: Reject Windows-specific absolute path components in target (before
        // resolution) This prevents bypasses on Windows like C:\ or
        // \\server\share
        for component in target.components() {
            if matches!(component, Component::Prefix(_) | Component::RootDir) {
                return Err(ExtractionError::HardlinkEscape {
                    path: link_path.as_path().to_path_buf(),
                });
            }
        }

        // Also reject absolute targets (redundant with above, but keeps existing check)
        if target.is_absolute() {
            return Err(ExtractionError::HardlinkEscape {
                path: link_path.as_path().to_path_buf(),
            });
        }

        // Resolve target against destination, following any on-disk symlinks
        // encountered during traversal.
        //
        // String-based normalization is insufficient: if a previously extracted
        // symlink lies on the target path, a hardlink target can escape the
        // extraction root via on-disk resolution even though string normalization
        // would pass (two-hop chain bypass, GHSA-83g3-92jg-28cx variant — #116).
        let resolved =
            resolve_through_symlinks(dest.as_path(), target, dest.as_path(), link_path.as_path())
                .map_err(|_| ExtractionError::HardlinkEscape {
                path: link_path.as_path().to_path_buf(),
            })?;

        // Track this hardlink target (H-PERF-6: use entry API)
        self.seen_targets
            .entry(resolved)
            .or_insert_with(|| link_path.as_path().to_path_buf());

        Ok(())
    }

    /// Returns the number of tracked hardlinks.
    #[inline]
    #[must_use]
    pub fn count(&self) -> usize {
        self.seen_targets.len()
    }

    /// Checks if a target path has been seen before.
    #[must_use]
    pub fn has_target(&self, target: &Path) -> bool {
        self.seen_targets.contains_key(target)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_dest() -> (TempDir, DestDir) {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        (temp, dest)
    }

    #[test]
    fn test_hardlink_tracker_new() {
        let tracker = HardlinkTracker::new();
        assert_eq!(tracker.count(), 0);
    }

    #[test]
    fn test_validate_hardlink_allowed() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;

        let mut tracker = HardlinkTracker::new();
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).unwrap();
        let target = PathBuf::from("target.txt");

        assert!(
            tracker
                .validate_hardlink(&link, &target, &dest, &config)
                .is_ok()
        );
        assert_eq!(tracker.count(), 1);
    }

    #[test]
    fn test_validate_hardlink_disabled() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default(); // hardlinks disabled by default

        let mut tracker = HardlinkTracker::new();
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).unwrap();
        let target = PathBuf::from("target.txt");

        assert!(
            tracker
                .validate_hardlink(&link, &target, &dest, &config)
                .is_err()
        );
    }

    #[test]
    fn test_validate_hardlink_absolute_target() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;

        let mut tracker = HardlinkTracker::new();
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).unwrap();
        let target = PathBuf::from("/etc/passwd");

        let result = tracker.validate_hardlink(&link, &target, &dest, &config);
        assert!(matches!(
            result,
            Err(ExtractionError::HardlinkEscape { .. })
        ));
    }

    #[test]
    fn test_validate_hardlink_escape() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;

        let mut tracker = HardlinkTracker::new();
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).unwrap();
        let target = PathBuf::from("../../etc/passwd");

        let result = tracker.validate_hardlink(&link, &target, &dest, &config);
        assert!(matches!(
            result,
            Err(ExtractionError::HardlinkEscape { .. })
        ));
    }

    #[test]
    fn test_hardlink_tracker_multiple() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;

        let mut tracker = HardlinkTracker::new();

        let link1 = SafePath::validate(&PathBuf::from("link1"), &dest, &config).unwrap();
        let link2 = SafePath::validate(&PathBuf::from("link2"), &dest, &config).unwrap();

        tracker
            .validate_hardlink(&link1, &PathBuf::from("target1.txt"), &dest, &config)
            .unwrap();
        tracker
            .validate_hardlink(&link2, &PathBuf::from("target2.txt"), &dest, &config)
            .unwrap();

        assert_eq!(tracker.count(), 2);
    }

    #[test]
    fn test_hardlink_tracker_has_target() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;

        let mut tracker = HardlinkTracker::new();
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).unwrap();
        let target = PathBuf::from("target.txt");

        tracker
            .validate_hardlink(&link, &target, &dest, &config)
            .unwrap();

        let resolved_target = dest.as_path().join(&target);
        assert!(tracker.has_target(&resolved_target));
    }

    #[test]
    fn test_hardlink_tracker_relative_safe() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;

        let mut tracker = HardlinkTracker::new();
        let link = SafePath::validate(&PathBuf::from("foo/link"), &dest, &config).unwrap();
        // Safe relative path within destination
        let target = PathBuf::from("target.txt");

        let result = tracker.validate_hardlink(&link, &target, &dest, &config);
        assert!(result.is_ok());
    }

    // H-TEST-2: Duplicate hardlink to same target test
    #[test]
    fn test_duplicate_hardlink_to_same_target() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;

        let mut tracker = HardlinkTracker::new();
        let target = PathBuf::from("target.txt");

        // Create multiple hardlinks to the same target
        for i in 0..3 {
            let link =
                SafePath::validate(&PathBuf::from(format!("link{i}")), &dest, &config).unwrap();

            let result = tracker.validate_hardlink(&link, &target, &dest, &config);
            assert!(
                result.is_ok(),
                "multiple hardlinks to same target should be allowed"
            );
        }

        // All three links point to the same target, so only 1 unique target tracked
        assert_eq!(
            tracker.count(),
            1,
            "should track unique targets, not individual links"
        );
    }

    #[test]
    fn test_hardlink_different_targets() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;

        let mut tracker = HardlinkTracker::new();

        // Create hardlinks to different targets
        for i in 0..3 {
            let link =
                SafePath::validate(&PathBuf::from(format!("link{i}")), &dest, &config).unwrap();
            let target = PathBuf::from(format!("target{i}.txt"));

            tracker
                .validate_hardlink(&link, &target, &dest, &config)
                .unwrap();
        }

        // Three different targets
        assert_eq!(tracker.count(), 3, "should track each unique target");
    }

    /// Hardlink target that traverses through an already-extracted symlink must
    /// be rejected (two-hop chain, GHSA-83g3-92jg-28cx variant — issue #116).
    ///
    /// Entry 2 (symlink a/b/c/up -> ../..) is on disk when hardlink is
    /// validated. Target a/b/escape/../../etc/passwd: string normalization
    /// → dest/a/etc/passwd (looks safe), but if a/b/escape is an on-disk
    /// symlink resolving outside dest, the hardlink must be rejected.
    #[test]
    #[cfg(unix)]
    #[allow(clippy::unwrap_used)]
    fn test_hardlink_two_hop_chain_rejected() {
        use std::fs;
        use std::os::unix;

        let (temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;

        // Simulate on-disk state after extracting the two symlink entries.
        let a = temp.path().join("a");
        let b = a.join("b");
        let c = b.join("c");
        fs::create_dir_all(&c).unwrap();
        // a/b/c/up -> ../..  (first hop: resolves to a/)
        unix::fs::symlink("../..", c.join("up")).unwrap();
        // a/b/escape -> c/up/../..  (second hop: resolves outside dest on disk)
        unix::fs::symlink("c/up/../..", b.join("escape")).unwrap();

        let mut tracker = HardlinkTracker::new();
        let link = SafePath::validate(&PathBuf::from("exfil"), &dest, &config).unwrap();
        // Target traverses through the escape symlink
        let target = PathBuf::from("a/b/escape/../../etc/passwd");

        let result = tracker.validate_hardlink(&link, &target, &dest, &config);
        assert!(
            matches!(result, Err(ExtractionError::HardlinkEscape { .. })),
            "hardlink through two-hop symlink chain must be rejected"
        );
    }
}
