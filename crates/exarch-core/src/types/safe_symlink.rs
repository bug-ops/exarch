//! Validated safe symlink type.

use crate::ExtractionError;
use crate::Result;
use crate::SecurityConfig;
use std::path::Path;
use std::path::PathBuf;

use super::DestDir;
use super::SafePath;

/// A validated symlink that is safe for extraction.
///
/// `SafeSymlink` represents a symbolic link where:
/// - The link path is a valid `SafePath`
/// - The target path is relative (not absolute)
/// - The resolved target stays within the destination directory
/// - Symlinks are allowed by the security configuration
///
/// # Security Properties
///
/// - Can ONLY be constructed through validation
/// - NO `From<PathBuf>` implementation (security critical)
/// - Target always resolves within destination directory
/// - Prevents symlink escape attacks
///
/// # Examples
///
/// ```no_run
/// use exarch_core::SecurityConfig;
/// use exarch_core::types::DestDir;
/// use exarch_core::types::SafePath;
/// use exarch_core::types::SafeSymlink;
/// use std::path::PathBuf;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dest = DestDir::new(PathBuf::from("/tmp"))?;
/// let mut config = SecurityConfig::default();
/// config.allowed.symlinks = true;
///
/// let link = SafePath::validate(&PathBuf::from("mylink"), &dest, &config)?;
/// let target = PathBuf::from("../target.txt");
///
/// let symlink = SafeSymlink::validate(&link, &target, &dest, &config)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeSymlink {
    link_path: PathBuf,
    target_path: PathBuf,
}

impl SafeSymlink {
    /// Validates and constructs a `SafeSymlink`.
    ///
    /// This is the ONLY way to construct a `SafeSymlink`. The validation
    /// process ensures the symlink is safe for extraction.
    ///
    /// # Validation Steps
    ///
    /// 1. Verify symlinks are allowed in the security configuration
    /// 2. Validate target is relative (reject absolute symlinks)
    /// 3. Resolve target against the link's parent directory
    /// 4. Verify resolved target stays within destination directory
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Symlinks are not allowed by configuration
    /// - Target is an absolute path
    /// - Resolved target escapes the destination directory
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use exarch_core::SecurityConfig;
    /// use exarch_core::types::DestDir;
    /// use exarch_core::types::SafePath;
    /// use exarch_core::types::SafeSymlink;
    /// use std::path::PathBuf;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let dest = DestDir::new(PathBuf::from("/tmp"))?;
    /// let mut config = SecurityConfig::default();
    /// config.allowed.symlinks = true;
    ///
    /// let link = SafePath::validate(&PathBuf::from("dir/link"), &dest, &config)?;
    /// let target = PathBuf::from("../file.txt");
    ///
    /// let symlink = SafeSymlink::validate(&link, &target, &dest, &config)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn validate(
        link: &SafePath,
        target: &Path,
        dest: &DestDir,
        config: &SecurityConfig,
    ) -> Result<Self> {
        // 1. Verify symlinks are allowed
        if !config.allowed.symlinks {
            return Err(ExtractionError::SecurityViolation {
                reason: "symlinks not allowed".into(),
            });
        }

        // 2. Validate target is relative
        if target.is_absolute() {
            return Err(ExtractionError::SymlinkEscape {
                path: link.as_path().to_path_buf(),
            });
        }

        // 2.5. Check target for banned components and depth (HIGH-005)
        let mut target_depth = 0;
        for component in target.components() {
            if let std::path::Component::Normal(comp) = component {
                target_depth += 1;
                let comp_str = comp.to_string_lossy();
                if !config.is_path_component_allowed(&comp_str) {
                    return Err(ExtractionError::SecurityViolation {
                        reason: format!("symlink target contains banned component: {comp_str}"),
                    });
                }
            }
        }

        // Validate target depth against max_path_depth
        if target_depth > config.max_path_depth {
            return Err(ExtractionError::SecurityViolation {
                reason: format!(
                    "symlink target depth {target_depth} exceeds maximum {}",
                    config.max_path_depth
                ),
            });
        }

        // 3. Verify parent directory chain doesn't contain symlinks (TOCTOU protection)
        // This prevents race conditions where an attacker replaces a parent directory
        // with a symlink between validation and extraction time.
        verify_parent_not_symlink(link.as_path(), dest)?;

        // 4. Resolve target against link's parent directory
        let link_parent = link.as_path().parent().unwrap_or_else(|| Path::new(""));
        let link_parent_full = dest.as_path().join(link_parent);

        // Join target to link's parent directory
        let mut resolved = link_parent_full.join(target);

        // Normalize the path by resolving .. and . components manually
        resolved = normalize_symlink_target(&resolved);

        // 5. Verify resolved target is within dest
        // We can't use canonicalize here because the target might not exist yet
        // Instead, we check if the normalized path starts with dest
        if !resolved.starts_with(dest.as_path()) {
            return Err(ExtractionError::SymlinkEscape {
                path: link.as_path().to_path_buf(),
            });
        }

        Ok(Self {
            link_path: link.as_path().to_path_buf(),
            target_path: target.to_path_buf(),
        })
    }

    /// Returns the link path.
    #[inline]
    #[must_use]
    pub fn link_path(&self) -> &Path {
        &self.link_path
    }

    /// Returns the target path.
    ///
    /// Note: This is the relative target path as stored in the symlink,
    /// not the resolved absolute path.
    #[inline]
    #[must_use]
    pub fn target_path(&self) -> &Path {
        &self.target_path
    }
}

/// Verifies that no component in the parent directory chain of `path` is a
/// symlink.
///
/// This function provides protection against TOCTOU (Time-Of-Check-Time-Of-Use)
/// race conditions where an attacker could replace a parent directory with a
/// symlink between validation and extraction time.
///
/// # Security Note
///
/// While this check significantly reduces the attack window, it doesn't
/// eliminate TOCTOU risks entirely. For untrusted archives, extraction should
/// always be performed in isolated environments (containers, chroot, etc.).
///
/// # Errors
///
/// Returns `SymlinkEscape` if any parent component is a symlink.
fn verify_parent_not_symlink(path: &Path, dest: &DestDir) -> Result<()> {
    let mut current = dest.as_path().to_path_buf();

    // Walk through each component of the path
    for component in path.components() {
        current.push(component);

        // Check if current path exists and is a symlink
        if current.exists() {
            let metadata = std::fs::symlink_metadata(&current).map_err(|_| {
                ExtractionError::SymlinkEscape {
                    path: path.to_path_buf(),
                }
            })?;

            if metadata.is_symlink() {
                return Err(ExtractionError::SymlinkEscape {
                    path: path.to_path_buf(),
                });
            }
        }
    }

    Ok(())
}

/// Normalizes a symlink target by manually resolving .. and . components.
///
/// This function is used instead of `canonicalize` because the target might
/// not exist yet during extraction planning.
fn normalize_symlink_target(path: &Path) -> PathBuf {
    // Pre-allocate with expected capacity to avoid reallocations
    let component_count = path.components().count();
    let mut components = Vec::with_capacity(component_count);

    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                // Pop the last component if possible
                components.pop();
            }
            std::path::Component::CurDir => {
                // Skip . components
            }
            _ => {
                components.push(component);
            }
        }
    }

    components.iter().collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Creates a temporary directory and wraps it in a `DestDir` for testing.
    ///
    /// Returns tuple of (`TempDir`, `DestDir`). `TempDir` must be kept alive
    /// for the duration of the test to prevent cleanup.
    fn create_test_dest() -> (TempDir, DestDir) {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        (temp, dest)
    }

    /// Creates a `SecurityConfig` with symlinks enabled for testing.
    fn create_config_with_symlinks() -> SecurityConfig {
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = true;
        config
    }

    #[test]
    fn test_safe_symlink_valid_internal() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("dir/link"), &dest, &config)
            .expect("link path should be valid");
        let target = PathBuf::from("../file.txt");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert!(result.is_ok());

        let symlink = result.expect("symlink should be valid");
        assert_eq!(symlink.link_path(), Path::new("dir/link"));
        assert_eq!(symlink.target_path(), Path::new("../file.txt"));
    }

    #[test]
    fn test_safe_symlink_reject_when_disabled() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = false;

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");
        let target = PathBuf::from("target.txt");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert!(matches!(
            result,
            Err(ExtractionError::SecurityViolation { .. })
        ));
    }

    #[test]
    #[cfg(unix)]
    fn test_safe_symlink_reject_absolute_target_unix() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");
        let target = PathBuf::from("/etc/passwd");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert!(matches!(result, Err(ExtractionError::SymlinkEscape { .. })));
    }

    #[test]
    #[cfg(windows)]
    fn test_safe_symlink_reject_absolute_target_windows() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");
        let target = PathBuf::from("C:\\Windows\\System32");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert!(matches!(result, Err(ExtractionError::SymlinkEscape { .. })));
    }

    #[test]
    fn test_safe_symlink_reject_external_target() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("deep/nested/link"), &dest, &config)
            .expect("link path should be valid");

        // Try to escape via multiple ..
        let target = PathBuf::from("../../../../etc/passwd");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert!(matches!(result, Err(ExtractionError::SymlinkEscape { .. })));
    }

    #[test]
    fn test_safe_symlink_relative_resolution() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        // Create a link in a subdirectory pointing to a file in parent
        let link = SafePath::validate(&PathBuf::from("subdir/link"), &dest, &config)
            .expect("link path should be valid");
        let target = PathBuf::from("../file.txt");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_safe_symlink_complex_relative_path() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("a/b/c/link"), &dest, &config)
            .expect("link path should be valid");

        // Target goes up and back down
        let target = PathBuf::from("../../d/e/file.txt");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_normalize_symlink_target() {
        // Test basic normalization
        let path = PathBuf::from("/tmp/a/b/../c/./d");
        let normalized = normalize_symlink_target(&path);
        assert_eq!(normalized, PathBuf::from("/tmp/a/c/d"));

        // Test multiple parent dirs
        let path = PathBuf::from("/tmp/a/b/c/../../d");
        let normalized = normalize_symlink_target(&path);
        assert_eq!(normalized, PathBuf::from("/tmp/a/d"));

        // Test current dir removal
        let path = PathBuf::from("/tmp/./a/./b");
        let normalized = normalize_symlink_target(&path);
        assert_eq!(normalized, PathBuf::from("/tmp/a/b"));
    }

    #[test]
    fn test_safe_symlink_equality() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");
        let target = PathBuf::from("target.txt");

        let symlink1 =
            SafeSymlink::validate(&link, &target, &dest, &config).expect("symlink should be valid");

        let link2 = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");
        let symlink2 = SafeSymlink::validate(&link2, &target, &dest, &config)
            .expect("symlink should be valid");

        assert_eq!(symlink1, symlink2);
    }

    #[test]
    fn test_safe_symlink_clone() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");
        let target = PathBuf::from("target.txt");

        let symlink =
            SafeSymlink::validate(&link, &target, &dest, &config).expect("symlink should be valid");
        let cloned = symlink.clone();

        assert_eq!(symlink, cloned);
    }

    // M-6: Test for symlink to non-existent internal target
    #[test]
    fn test_safe_symlink_to_nonexistent_internal_target() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");

        // Target doesn't exist but is internal
        let target = PathBuf::from("nonexistent_file.txt");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert!(
            result.is_ok(),
            "symlink to internal non-existent target should be allowed"
        );
    }

    // Test for circular symlink detection
    #[test]
    #[allow(clippy::unwrap_used)]
    #[cfg(unix)]
    fn test_circular_symlink_chains() {
        let (temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        // Create actual symlinks for circular chain
        // a -> b, b -> c, c -> a
        let a_path = temp.path().join("a");
        let b_path = temp.path().join("b");
        let c_path = temp.path().join("c");

        std::os::unix::fs::symlink("b", &a_path).unwrap();
        std::os::unix::fs::symlink("c", &b_path).unwrap();
        std::os::unix::fs::symlink("a", &c_path).unwrap();

        // Validation should not hang or panic
        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");
        let target = PathBuf::from("a"); // Points into circular chain

        // This should complete (not hang) and may succeed since we don't follow chains
        let _result = SafeSymlink::validate(&link, &target, &dest, &config);
    }

    // Deep symlink nesting stress tests
    #[test]
    fn test_safe_symlink_deep_nesting_stress() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        // Create deeply nested link
        let link = SafePath::validate(&PathBuf::from("a/b/c/d/e/f/g/h/i/j/link"), &dest, &config)
            .expect("link path should be valid");

        // Target that goes up and back down
        let target = PathBuf::from("../../../../../../../../../../x/y/z/file.txt");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert!(
            result.is_ok(),
            "deep relative path staying internal should succeed"
        );
    }

    #[test]
    fn test_safe_symlink_excessive_parent_refs() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("a/b/link"), &dest, &config)
            .expect("link path should be valid");

        // More .. than depth can handle
        let target = PathBuf::from("../".repeat(50) + "file.txt");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert!(matches!(result, Err(ExtractionError::SymlinkEscape { .. })));
    }

    // Test for symlink with banned target component
    #[test]
    fn test_safe_symlink_target_banned_component() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");

        // Target contains banned component
        let target = PathBuf::from(".git/config");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert!(
            matches!(result, Err(ExtractionError::SecurityViolation { .. })),
            "symlink to banned component should be rejected"
        );
    }

    #[test]
    fn test_safe_symlink_self_reference() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");

        // Symlink to itself (link -> link)
        let target = PathBuf::from("link");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert!(
            result.is_ok(),
            "self-referential symlink should be allowed (validation doesn't follow)"
        );
    }

    #[test]
    fn test_safe_symlink_empty_target() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config)
            .expect("link path should be valid");

        // Empty target
        let target = PathBuf::from("");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        // Empty target should resolve to link's parent directory
        assert!(result.is_ok(), "empty target should be allowed");
    }

    #[test]
    fn test_safe_symlink_current_dir_target() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("subdir/link"), &dest, &config)
            .expect("link path should be valid");

        // Target is current directory (.)
        let target = PathBuf::from(".");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert!(result.is_ok(), "current dir target should be allowed");
    }

    #[test]
    fn test_safe_symlink_parent_dir_target() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("a/b/link"), &dest, &config)
            .expect("link path should be valid");

        // Target is parent directory (..)
        let target = PathBuf::from("..");

        let result = SafeSymlink::validate(&link, &target, &dest, &config);
        assert!(result.is_ok(), "parent dir target should be allowed");
    }

    #[test]
    fn test_safe_symlink_getters() {
        let (_temp, dest) = create_test_dest();
        let config = create_config_with_symlinks();

        let link = SafePath::validate(&PathBuf::from("mylink"), &dest, &config)
            .expect("link path should be valid");
        let target = PathBuf::from("target.txt");

        let symlink =
            SafeSymlink::validate(&link, &target, &dest, &config).expect("symlink should be valid");

        // Test getters
        assert_eq!(symlink.link_path(), Path::new("mylink"));
        assert_eq!(symlink.target_path(), Path::new("target.txt"));
    }
}
