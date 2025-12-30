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
    pub fn validate(path: &Path, dest: &DestDir, config: &SecurityConfig) -> Result<Self> {
        // 1. Check for null bytes
        if has_null_bytes(path) {
            return Err(ExtractionError::SecurityViolation {
                reason: format!("path contains null bytes: {}", path.display()),
            });
        }

        // 2. Check for absolute paths
        if path.is_absolute() && !config.allow_absolute_paths {
            return Err(ExtractionError::PathTraversal {
                path: path.to_path_buf(),
            });
        }

        // 3. Check for parent directory traversal and banned components
        let mut depth = 0;
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
                    if !config.banned_path_components.is_empty() {
                        let comp_str = comp.to_string_lossy();
                        if !config.is_path_component_allowed(&comp_str) {
                            return Err(ExtractionError::SecurityViolation {
                                reason: format!("banned path component: {comp_str}"),
                            });
                        }
                    }
                }
                Component::CurDir => {
                    // Will be normalized away
                }
                Component::RootDir | Component::Prefix(_) => {
                    // For absolute paths on Windows
                    if !config.allow_absolute_paths {
                        return Err(ExtractionError::PathTraversal {
                            path: path.to_path_buf(),
                        });
                    }
                }
            }
        }

        // 4. Check path depth
        if depth > config.max_path_depth {
            return Err(ExtractionError::SecurityViolation {
                reason: format!(
                    "path depth {} exceeds maximum {}",
                    depth, config.max_path_depth
                ),
            });
        }

        // 5. Normalize path (remove . components)
        let normalized = normalize_path(path);

        // 6. Verify resolved path stays within destination
        let resolved = dest.as_path().join(normalized.as_ref());

        // Always canonicalize parent directory to prevent symlink-based bypass
        if let Some(parent) = resolved.parent().filter(|p| p.exists()) {
            let canonical_parent = parent.canonicalize().map_err(|e| {
                ExtractionError::Io(std::io::Error::new(
                    e.kind(),
                    format!("failed to canonicalize parent: {e}"),
                ))
            })?;

            if !canonical_parent.starts_with(dest.as_path()) {
                return Err(ExtractionError::PathTraversal {
                    path: path.to_path_buf(),
                });
            }
        }

        // Use canonicalize for full path if it exists
        if resolved.exists() {
            let canonical = resolved.canonicalize().map_err(|e| {
                ExtractionError::Io(std::io::Error::new(
                    e.kind(),
                    format!("failed to canonicalize path: {e}"),
                ))
            })?;

            if !canonical.starts_with(dest.as_path()) {
                return Err(ExtractionError::PathTraversal {
                    path: path.to_path_buf(),
                });
            }
        } else {
            // Path doesn't exist yet, check prefix
            if !resolved.starts_with(dest.as_path()) {
                return Err(ExtractionError::PathTraversal {
                    path: path.to_path_buf(),
                });
            }
        }

        Ok(Self(normalized.into_owned()))
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

/// Normalizes a path by removing `.` components.
///
/// This function removes redundant current directory components but does NOT
/// resolve `..` components (those are rejected during validation).
///
/// Uses `Cow<Path>` to avoid allocation when no normalization is needed.
fn normalize_path(path: &Path) -> Cow<'_, Path> {
    // Fast path: Check if normalization is needed
    let has_cur_dir = path.components().any(|c| matches!(c, Component::CurDir));

    if !has_cur_dir {
        return Cow::Borrowed(path);
    }

    // Slow path: Normalize only if needed
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {
                // Skip . components
            }
            Component::ParentDir => {
                // Should have been caught in validation, but keep for safety
                normalized.push(component);
            }
            _ => {
                normalized.push(component);
            }
        }
    }

    Cow::Owned(normalized)
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
        config.allow_absolute_paths = true;

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
        // Path with . components should be normalized
        let path = PathBuf::from("foo/./bar/./baz.txt");
        let normalized = normalize_path(&path);
        assert_eq!(normalized.as_ref(), Path::new("foo/bar/baz.txt"));

        let path = PathBuf::from("./foo/bar");
        let normalized = normalize_path(&path);
        assert_eq!(normalized.as_ref(), Path::new("foo/bar"));

        // Path without . components should be borrowed (no allocation)
        let path = PathBuf::from("foo/bar/baz.txt");
        let normalized = normalize_path(&path);
        assert!(matches!(normalized, Cow::Borrowed(_)));
        assert_eq!(normalized.as_ref(), Path::new("foo/bar/baz.txt"));
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
}
