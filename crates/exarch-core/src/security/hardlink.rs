//! Hardlink security validation and tracking.

use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;

use crate::ExtractionError;
use crate::Result;
use crate::SecurityConfig;
use crate::types::DestDir;
use crate::types::SafePath;

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

        // Resolve target against destination
        let resolved = dest.as_path().join(target);

        let needs_normalization = resolved
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir));

        if !needs_normalization {
            // Path is already normalized, just verify it's within destination
            if !resolved.starts_with(dest.as_path()) {
                return Err(ExtractionError::HardlinkEscape {
                    path: link_path.as_path().to_path_buf(),
                });
            }

            // Track this hardlink target (H-PERF-6: use entry API)
            self.seen_targets
                .entry(resolved)
                .or_insert_with(|| link_path.as_path().to_path_buf());

            return Ok(());
        }

        // Normalize path: resolve .. and . components, detect escape attempts
        let mut normalized = PathBuf::new();
        for component in resolved.components() {
            match component {
                Component::ParentDir => {
                    if !normalized.pop() {
                        // Tried to go above root - escape attempt
                        return Err(ExtractionError::HardlinkEscape {
                            path: link_path.as_path().to_path_buf(),
                        });
                    }
                }
                Component::CurDir => {
                    // Skip current directory markers
                }
                // Keep Prefix/RootDir from resolved path (they come from dest, which is trusted)
                _ => {
                    normalized.push(component);
                }
            }
        }

        // Verify the normalized path is within destination
        // Note: We need to canonicalize the destination for proper comparison
        // since dest might have symlinks
        let dest_canonical = dest.as_path();
        if !normalized.starts_with(dest_canonical) {
            return Err(ExtractionError::HardlinkEscape {
                path: link_path.as_path().to_path_buf(),
            });
        }

        // Track this hardlink target using normalized path (H-PERF-6: use entry API)
        self.seen_targets
            .entry(normalized)
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
}
