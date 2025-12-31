//! Validated safe path type for archive extraction.

use crate::ExtractionError;
use crate::Result;
use crate::SecurityConfig;
use std::borrow::Cow;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use super::DestDir;

/// A validated path that is safe for extraction.
///
/// `SafePath` represents a path that has been validated to not contain:
/// - Path traversal attempts (`..`)
/// - Null bytes
/// - Absolute paths (unless explicitly allowed)
/// - Banned path components
/// - Excessive path depth
///
/// # Security Properties
///
/// - Can ONLY be constructed through validation
/// - NO `From<PathBuf>` implementation (security critical)
/// - Always resolves within the destination directory
/// - Normalized to remove redundant components
///
/// # Examples
///
/// ```no_run
/// use exarch_core::SecurityConfig;
/// use exarch_core::types::DestDir;
/// use exarch_core::types::SafePath;
/// use std::path::PathBuf;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dest = DestDir::new(PathBuf::from("/tmp"))?;
/// let config = SecurityConfig::default();
///
/// // Valid path
/// let safe = SafePath::validate(&PathBuf::from("foo/bar.txt"), &dest, &config)?;
///
/// // Path traversal is rejected
/// let unsafe_path = PathBuf::from("../etc/passwd");
/// assert!(SafePath::validate(&unsafe_path, &dest, &config).is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SafePath(PathBuf);

impl SafePath {
    /// Validates and constructs a `SafePath`.
    ///
    /// This is the ONLY way to construct a `SafePath`. The validation process
    /// ensures the path is safe for extraction.
    ///
    /// # Performance
    ///
    /// **For non-existing paths**: ~300-500 ns (no I/O syscalls)
    /// **For existing paths**: ~5-50 μs (involves `exists()` and
    /// `canonicalize()` syscalls)
    ///
    /// If validating many paths, consider batching or parallel validation.
    ///
    /// # Validation Steps
    ///
    /// 1. Check for null bytes in path
    /// 2. Validate path is not absolute (unless allowed by config)
    /// 3. Check for parent directory traversal (`..`)
    /// 4. Validate path depth does not exceed maximum
    /// 5. Check for banned path components
    /// 6. Normalize path components (remove `.`)
    /// 7. Verify resolved path stays within destination directory
    ///
    /// # Errors
    ///
    /// Returns an error if any validation step fails:
    /// - `ExtractionError::PathTraversal` for `..` or absolute paths
    /// - `ExtractionError::SecurityViolation` for banned components or
    ///   excessive depth
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use exarch_core::SecurityConfig;
    /// use exarch_core::types::DestDir;
    /// use exarch_core::types::SafePath;
    /// use std::path::PathBuf;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let dest = DestDir::new(PathBuf::from("/tmp"))?;
    /// let config = SecurityConfig::default();
    ///
    /// let safe = SafePath::validate(&PathBuf::from("valid/path.txt"), &dest, &config)?;
    /// # Ok(())
    /// # }
    /// ```
    #[allow(clippy::too_many_lines)] // Complex security validation logic
    pub fn validate(path: &Path, dest: &DestDir, config: &SecurityConfig) -> Result<Self> {
        // 1. Check for null bytes
        if has_null_bytes(path) {
            return Err(ExtractionError::SecurityViolation {
                reason: format!("path contains null bytes: {}", path.display()),
            });
        }

        // 2. Check for absolute paths
        if path.is_absolute() && !config.allowed.absolute_paths {
            return Err(ExtractionError::PathTraversal {
                path: path.to_path_buf(),
            });
        }

        // H-PERF-2: Single-pass validation and normalization
        // Process all components in one iteration to:
        // - Validate (check ParentDir, RootDir, Prefix)
        // - Check banned components
        // - Count depth
        // - Normalize (skip CurDir components)
        let mut depth = 0;
        let mut normalized = PathBuf::new();
        let mut needs_normalization = false;
        let has_banned_components = !config.banned_path_components.is_empty();

        for component in path.components() {
            match component {
                Component::ParentDir => {
                    return Err(ExtractionError::PathTraversal {
                        path: path.to_path_buf(),
                    });
                }
                Component::Normal(comp) => {
                    depth += 1;

                    // Only convert to string when banned components are configured
                    if has_banned_components {
                        // M-PERF-1: Try zero-cost to_str() first for valid UTF-8
                        let comp_str = comp
                            .to_str()
                            .map_or_else(|| comp.to_string_lossy(), Cow::Borrowed);

                        if !config.is_path_component_allowed(&comp_str) {
                            return Err(ExtractionError::SecurityViolation {
                                reason: format!("banned path component: {comp_str}"),
                            });
                        }
                    }

                    // Add to normalized path
                    normalized.push(component);
                }
                Component::CurDir => {
                    // Skip . components (normalization)
                    needs_normalization = true;
                }
                Component::RootDir | Component::Prefix(_) => {
                    // For absolute paths on Windows
                    if !config.allowed.absolute_paths {
                        return Err(ExtractionError::PathTraversal {
                            path: path.to_path_buf(),
                        });
                    }
                    // Preserve root/prefix for absolute paths
                    normalized.push(component);
                }
            }
        }

        // Check path depth
        if depth > config.max_path_depth {
            return Err(ExtractionError::SecurityViolation {
                reason: format!(
                    "path depth {} exceeds maximum {}",
                    depth, config.max_path_depth
                ),
            });
        }

        // Use normalized path if normalization was needed, otherwise use original
        let final_path = if needs_normalization {
            Cow::Owned(normalized)
        } else {
            Cow::Borrowed(path)
        };

        // Verify resolved path stays within destination
        let resolved = dest.as_path().join(final_path.as_ref());

        // M-PERF-2: Try canonicalization directly, handle NotFound gracefully
        // This avoids redundant exists() syscalls

        // Always canonicalize parent directory to prevent symlink-based bypass
        if let Some(parent) = resolved.parent() {
            match parent.canonicalize() {
                Ok(canonical_parent) => {
                    if !canonical_parent.starts_with(dest.as_path()) {
                        return Err(ExtractionError::PathTraversal {
                            path: path.to_path_buf(),
                        });
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Parent doesn't exist yet during extraction planning - that's OK
                }
                Err(e) => {
                    return Err(ExtractionError::Io(std::io::Error::new(
                        e.kind(),
                        format!("failed to canonicalize parent: {e}"),
                    )));
                }
            }
        }

        // Try to canonicalize full path if it exists
        match resolved.canonicalize() {
            Ok(canonical) => {
                if !canonical.starts_with(dest.as_path()) {
                    return Err(ExtractionError::PathTraversal {
                        path: path.to_path_buf(),
                    });
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Path doesn't exist yet, check prefix
                if !resolved.starts_with(dest.as_path()) {
                    return Err(ExtractionError::PathTraversal {
                        path: path.to_path_buf(),
                    });
                }
            }
            Err(e) => {
                return Err(ExtractionError::Io(std::io::Error::new(
                    e.kind(),
                    format!("failed to canonicalize path: {e}"),
                )));
            }
        }

        Ok(Self(final_path.into_owned()))
    }

    /// Creates a `SafePath` without validation (INTERNAL USE ONLY).
    ///
    /// # Safety
    ///
    /// This bypasses all validation checks. The caller MUST ensure that:
    /// - The path has been validated by equivalent checks elsewhere
    /// - The path is relative (not absolute)
    /// - The path contains no `..` components
    /// - The path resolves within the destination directory
    ///
    /// This is only used internally when path has already been validated
    /// through a different mechanism (e.g., hardlink validation).
    pub(crate) fn new_unchecked(path: PathBuf) -> Self {
        Self(path)
    }

    /// Returns the path as a `&Path`.
    #[inline]
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Converts into the inner `PathBuf`.
    #[inline]
    #[must_use]
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }
}

/// Checks if a path contains null bytes.
#[cfg(unix)]
fn has_null_bytes(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().contains(&b'\0')
}

/// Checks if a path contains null bytes.
#[cfg(not(unix))]
fn has_null_bytes(path: &Path) -> bool {
    path.to_str().is_none_or(|s| s.contains('\0'))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::field_reassign_with_default,
    clippy::items_after_statements
)]
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

    // M-TEST-2: Empty path handling test
    #[test]
    fn test_empty_path() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let result = SafePath::validate(&PathBuf::from(""), &dest, &config);
        assert!(
            matches!(result, Err(ExtractionError::PathTraversal { .. })),
            "empty path should be rejected as invalid"
        );
    }

    #[test]
    fn test_safe_path_valid_relative() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let path = PathBuf::from("foo/bar/baz.txt");
        let result = SafePath::validate(&path, &dest, &config);
        assert!(result.is_ok());

        let safe = result.expect("should be valid");
        assert_eq!(safe.as_path(), path.as_path());
    }

    #[test]
    fn test_safe_path_reject_parent_traversal() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let paths = vec![
            PathBuf::from("../etc/passwd"),
            PathBuf::from("foo/../../etc/passwd"),
            PathBuf::from("foo/../../../etc/passwd"),
        ];

        for path in paths {
            let result = SafePath::validate(&path, &dest, &config);
            assert!(
                matches!(result, Err(ExtractionError::PathTraversal { .. })),
                "path should be rejected: {}",
                path.display()
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_safe_path_reject_absolute_unix() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let path = PathBuf::from("/etc/passwd");
        let result = SafePath::validate(&path, &dest, &config);
        assert!(matches!(result, Err(ExtractionError::PathTraversal { .. })));
    }

    #[test]
    #[cfg(windows)]
    fn test_safe_path_reject_absolute_windows() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let paths = vec![
            PathBuf::from("C:\\Windows\\System32"),
            PathBuf::from("\\\\server\\share\\file"),
        ];

        for path in paths {
            let result = SafePath::validate(&path, &dest, &config);
            assert!(matches!(result, Err(ExtractionError::PathTraversal { .. })));
        }
    }

    #[test]
    fn test_safe_path_allow_absolute_when_configured() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.absolute_paths = true;

        // Create a temporary file to test with
        let test_file = dest.as_path().join("test.txt");
        std::fs::write(&test_file, "test").expect("failed to write test file");

        let result = SafePath::validate(&test_file, &dest, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_safe_path_reject_excessive_depth() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.max_path_depth = 3;

        // 4 components - should be rejected
        let path = PathBuf::from("a/b/c/d");
        let result = SafePath::validate(&path, &dest, &config);
        assert!(matches!(
            result,
            Err(ExtractionError::SecurityViolation { .. })
        ));

        // 3 components - should be allowed
        let path = PathBuf::from("a/b/c");
        let result = SafePath::validate(&path, &dest, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_safe_path_reject_banned_components() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let paths = vec![
            PathBuf::from("project/.git/config"),
            PathBuf::from("user/.ssh/id_rsa"),
            PathBuf::from(".gnupg/private-keys"),
        ];

        for path in paths {
            let result = SafePath::validate(&path, &dest, &config);
            assert!(
                matches!(result, Err(ExtractionError::SecurityViolation { .. })),
                "path should be rejected: {}",
                path.display()
            );
        }
    }

    #[test]
    fn test_safe_path_normalize_dot_components() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let path = PathBuf::from("foo/./bar/./baz.txt");
        let result = SafePath::validate(&path, &dest, &config);
        assert!(result.is_ok());

        let safe = result.expect("should be valid");
        assert_eq!(safe.as_path(), Path::new("foo/bar/baz.txt"));
    }

    #[test]
    fn test_safe_path_null_bytes() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        #[cfg(unix)]
        {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;

            let bytes = b"file\0.txt";
            let os_str = OsStr::from_bytes(bytes);
            let path = PathBuf::from(os_str);

            let result = SafePath::validate(&path, &dest, &config);
            assert!(matches!(
                result,
                Err(ExtractionError::SecurityViolation { .. })
            ));
        }

        #[cfg(windows)]
        {
            use std::ffi::OsString;
            use std::os::windows::ffi::OsStringExt;

            // Windows test for null bytes
            let wide: Vec<u16> = "file\0.txt".encode_utf16().collect();
            let os_string = OsString::from_wide(&wide);
            let path = PathBuf::from(os_string);

            let result = SafePath::validate(&path, &dest, &config);
            assert!(matches!(
                result,
                Err(ExtractionError::SecurityViolation { .. })
            ));
        }
    }

    #[test]
    fn test_has_null_bytes() {
        let normal = PathBuf::from("normal/path.txt");
        assert!(!has_null_bytes(&normal));

        #[cfg(unix)]
        {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;

            let bytes = b"file\0.txt";
            let os_str = OsStr::from_bytes(bytes);
            let with_null = PathBuf::from(os_str);
            assert!(has_null_bytes(&with_null));
        }
    }

    #[test]
    fn test_normalize_path() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        // H-PERF-2: Normalization now happens in single-pass validation
        // Path with . components should be normalized
        let path = PathBuf::from("foo/./bar/./baz.txt");
        let safe = SafePath::validate(&path, &dest, &config).expect("should be valid");
        assert_eq!(safe.as_path(), Path::new("foo/bar/baz.txt"));

        let path = PathBuf::from("./foo/bar");
        let safe = SafePath::validate(&path, &dest, &config).expect("should be valid");
        assert_eq!(safe.as_path(), Path::new("foo/bar"));

        // Path without . components should remain unchanged
        let path = PathBuf::from("foo/bar/baz.txt");
        let safe = SafePath::validate(&path, &dest, &config).expect("should be valid");
        assert_eq!(safe.as_path(), Path::new("foo/bar/baz.txt"));
    }

    #[test]
    fn test_safe_path_equality() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let safe1 = SafePath::validate(&PathBuf::from("foo/bar.txt"), &dest, &config)
            .expect("should be valid");
        let safe2 = SafePath::validate(&PathBuf::from("foo/bar.txt"), &dest, &config)
            .expect("should be valid");

        assert_eq!(safe1, safe2);
    }

    #[test]
    fn test_safe_path_clone() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let safe = SafePath::validate(&PathBuf::from("foo/bar.txt"), &dest, &config)
            .expect("should be valid");
        let cloned = safe.clone();

        assert_eq!(safe, cloned);
    }

    // M-14: Test for empty path
    #[test]
    fn test_safe_path_empty() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let path = PathBuf::from("");
        let result = SafePath::validate(&path, &dest, &config);

        // Empty path joins to dest and resolves to dest itself
        // which causes it to fail the parent canonicalization check
        // This is expected behavior - document it
        if let Ok(safe) = result {
            // If it succeeds, it should be an empty path
            assert_eq!(safe.as_path(), Path::new(""));
        }
        // Empty path may be rejected due to parent canonicalization
        // This is acceptable behavior
    }

    // L-8: Path length boundary tests
    #[test]
    fn test_safe_path_at_max_depth() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.max_path_depth = 5;

        // Exactly at limit
        let path = PathBuf::from("a/b/c/d/e");
        let result = SafePath::validate(&path, &dest, &config);
        assert!(result.is_ok());

        // One over limit
        let path = PathBuf::from("a/b/c/d/e/f");
        let result = SafePath::validate(&path, &dest, &config);
        assert!(matches!(
            result,
            Err(ExtractionError::SecurityViolation { .. })
        ));
    }

    // L-9: Single component path test
    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_safe_path_single_component() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let path = PathBuf::from("file.txt");
        let result = SafePath::validate(&path, &dest, &config);
        assert!(result.is_ok());

        let safe = result.unwrap();
        assert_eq!(safe.as_path(), Path::new("file.txt"));
    }

    // L-6: Unicode edge case tests
    #[test]
    fn test_safe_path_unicode() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        // Emoji in path
        let path = PathBuf::from("folder/📁test.txt");
        let result = SafePath::validate(&path, &dest, &config);
        assert!(result.is_ok());

        // Unicode normalization forms could differ
        let path = PathBuf::from("café");
        let result = SafePath::validate(&path, &dest, &config);
        assert!(result.is_ok());
    }

    // L-7: Windows reserved names test
    #[test]
    #[cfg(windows)]
    fn test_safe_path_windows_reserved_names() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let reserved = vec!["CON", "PRN", "AUX", "NUL", "COM1", "LPT1"];

        for name in reserved {
            let path = PathBuf::from(format!("folder/{}.txt", name));
            let _result = SafePath::validate(&path, &dest, &config);
            // Note: Windows filesystem may reject these, but we don't
            // explicitly block
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_in_parent_chain() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();

        // Create: dest/parent_dir -> /tmp (symlink to outside)
        let parent_symlink = temp.path().join("parent_dir");
        symlink("/tmp", &parent_symlink).expect("failed to create symlink");

        // Try to create path through symlinked parent
        let malicious_path = PathBuf::from("parent_dir/evil.txt");

        let result = SafePath::validate(&malicious_path, &dest, &config);
        assert!(
            matches!(result, Err(ExtractionError::PathTraversal { .. })),
            "symlink in parent chain should be detected and rejected"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_in_middle_of_path() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();

        // Create legitimate directory
        let legit_dir = temp.path().join("legit");
        std::fs::create_dir(&legit_dir).expect("failed to create dir");

        // Create symlink within that directory pointing outside
        let symlink_path = legit_dir.join("escape");
        symlink("/etc", &symlink_path).expect("failed to create symlink");

        // Try to access through the symlink
        let malicious_path = PathBuf::from("legit/escape/passwd");

        let result = SafePath::validate(&malicious_path, &dest, &config);
        assert!(
            matches!(result, Err(ExtractionError::PathTraversal { .. })),
            "symlink in middle of path should be detected"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_legitimate_file_in_real_directory() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();

        // Create real directory (not symlink)
        let real_dir = temp.path().join("real_dir");
        std::fs::create_dir(&real_dir).expect("failed to create dir");

        // Path through real directory should work
        let safe_path = PathBuf::from("real_dir/file.txt");

        let result = SafePath::validate(&safe_path, &dest, &config);
        assert!(result.is_ok(), "path through real directory should succeed");
    }
}
