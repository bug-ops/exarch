//! Validated safe path type for archive extraction.

use crate::ExtractionError;
use crate::Result;
use crate::SecurityConfig;
use crate::security::context::ValidationContext;
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
    /// This is the ONLY public way to construct a `SafePath`. The validation
    /// process ensures the path is safe for extraction.
    ///
    /// # Performance
    ///
    /// **For non-existing paths**: ~300-500 ns (no I/O syscalls)
    /// **For existing paths**: ~5-50 us (involves `exists()` and
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
    #[allow(clippy::too_many_lines)]
    pub fn validate(path: &Path, dest: &DestDir, config: &SecurityConfig) -> Result<Self> {
        let ctx = ValidationContext::new(config.allowed.symlinks);
        Self::validate_with_context(path, dest, config, &ctx)
    }

    /// Validates with optimization context that can skip `canonicalize()`.
    ///
    /// When a `ValidationContext` carries a `DirCache` reference, parent
    /// directories that we created are trusted without a `canonicalize()`
    /// syscall. When symlinks are impossible (disabled in config AND none
    /// seen), the full-path `canonicalize()` is also skipped.
    ///
    /// All other validation steps (null bytes, absolute paths, parent
    /// traversal, depth, banned components, prefix check) are always
    /// performed regardless of context.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn validate_with_context(
        path: &Path,
        dest: &DestDir,
        config: &SecurityConfig,
        ctx: &ValidationContext,
    ) -> Result<Self> {
        // Reject empty paths explicitly
        if path.as_os_str().is_empty() {
            return Err(ExtractionError::SecurityViolation {
                reason: "empty path not allowed".into(),
            });
        }

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

        // Single-pass validation and normalization
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

                    if has_banned_components {
                        let comp_str = comp
                            .to_str()
                            .map_or_else(|| comp.to_string_lossy(), Cow::Borrowed);

                        if !config.is_path_component_allowed(&comp_str) {
                            return Err(ExtractionError::SecurityViolation {
                                reason: format!("banned path component: {comp_str}"),
                            });
                        }
                    }

                    normalized.push(component);
                }
                Component::CurDir => {
                    needs_normalization = true;
                }
                Component::RootDir | Component::Prefix(_) => {
                    if !config.allowed.absolute_paths {
                        return Err(ExtractionError::PathTraversal {
                            path: path.to_path_buf(),
                        });
                    }
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

        let final_path = if needs_normalization {
            Cow::Owned(normalized)
        } else {
            Cow::Borrowed(path)
        };

        // Verify resolved path stays within destination
        let resolved = dest.as_path().join(final_path.as_ref());

        // Parent canonicalization: skip when parent is trusted (in DirCache)
        if let Some(parent) = resolved.parent()
            && !ctx.is_trusted_parent(parent)
        {
            match parent.canonicalize() {
                Ok(canonical_parent) => {
                    if !paths_start_with(&canonical_parent, dest.as_path()) {
                        return Err(ExtractionError::PathTraversal {
                            path: path.to_path_buf(),
                        });
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(ExtractionError::Io(std::io::Error::new(
                        e.kind(),
                        format!("failed to canonicalize parent: {e}"),
                    )));
                }
            }
        }

        // Full path canonicalization: skip when symlinks are impossible
        if ctx.needs_full_canonicalize() {
            match resolved.canonicalize() {
                Ok(canonical) => {
                    if !paths_start_with(&canonical, dest.as_path()) {
                        return Err(ExtractionError::PathTraversal {
                            path: path.to_path_buf(),
                        });
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if !paths_start_with(&resolved, dest.as_path()) {
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
        } else {
            // Symlinks impossible -- prefix check is still mandatory
            if !paths_start_with(&resolved, dest.as_path()) {
                return Err(ExtractionError::PathTraversal {
                    path: path.to_path_buf(),
                });
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

/// Case-insensitive path prefix check for macOS/Windows.
///
/// On case-insensitive filesystems (macOS, Windows), attackers can bypass
/// path validation using different case (e.g., `../../USERS/victim/.ssh/`).
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn paths_start_with(path: &Path, base: &Path) -> bool {
    // Convert both paths to lowercase strings for comparison
    let path_str = path.to_string_lossy().to_lowercase();
    let base_str = base.to_string_lossy().to_lowercase();
    path_str.starts_with(&base_str)
}

/// Case-sensitive path prefix check for Unix (not macOS).
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn paths_start_with(path: &Path, base: &Path) -> bool {
    path.starts_with(base)
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
    use crate::formats::common::DirCache;
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

    // Empty path handling test (MED-004)
    #[test]
    fn test_empty_path() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let result = SafePath::validate(&PathBuf::from(""), &dest, &config);
        assert!(
            matches!(result, Err(ExtractionError::SecurityViolation { .. })),
            "empty path should be explicitly rejected (MED-004)"
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

        // Normalization now happens in single-pass validation
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

    // Test for empty path (MED-004)
    #[test]
    fn test_safe_path_empty() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let path = PathBuf::from("");
        let result = SafePath::validate(&path, &dest, &config);

        // Empty paths are now explicitly rejected
        assert!(
            matches!(result, Err(ExtractionError::SecurityViolation { .. })),
            "empty path should be explicitly rejected"
        );
    }

    // Path length boundary tests
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

    // Single component path test
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

    // Unicode edge case tests
    #[test]
    fn test_safe_path_unicode() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        // Emoji in path
        let path = PathBuf::from("folder/\u{1f4c1}test.txt");
        let result = SafePath::validate(&path, &dest, &config);
        assert!(result.is_ok());

        // Unicode normalization forms could differ
        let path = PathBuf::from("caf\u{e9}");
        let result = SafePath::validate(&path, &dest, &config);
        assert!(result.is_ok());
    }

    // Windows reserved names test
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

    // --- Tests for validate_with_context optimization ---

    #[test]
    fn test_validate_with_context_trusted_parent_skips_canonicalize() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();

        // Create a real directory and register it in DirCache
        let sub_dir = dest.as_path().join("trusted_dir");
        let mut dir_cache = DirCache::new();
        dir_cache.ensure_dir(&sub_dir).expect("should create dir");

        let ctx = ValidationContext::new(false).with_dir_cache(&dir_cache);

        // Validate a path whose parent is in DirCache
        let path = PathBuf::from("trusted_dir/file.txt");
        let result = SafePath::validate_with_context(&path, &dest, &config, &ctx);
        assert!(result.is_ok(), "trusted parent should succeed: {result:?}");
    }

    #[test]
    fn test_validate_with_context_untrusted_parent_still_validates() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();

        let dir_cache = DirCache::new(); // empty cache
        let ctx = ValidationContext::new(false).with_dir_cache(&dir_cache);

        // Path whose parent is NOT in DirCache and doesn't exist
        let path = PathBuf::from("unknown_dir/file.txt");
        let result = SafePath::validate_with_context(&path, &dest, &config, &ctx);
        // Should succeed since parent doesn't exist (NotFound is OK)
        assert!(
            result.is_ok(),
            "non-existent parent should be OK: {result:?}"
        );
    }

    #[test]
    fn test_validate_with_context_symlink_free_fast_path() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default(); // symlinks = false

        // No dir_cache, no symlinks -> fast path (no canonicalize)
        let ctx = ValidationContext::new(false);
        let path = PathBuf::from("some/path/file.txt");
        let result = SafePath::validate_with_context(&path, &dest, &config, &ctx);
        assert!(result.is_ok(), "symlink-free fast path should work");
    }

    #[test]
    fn test_validate_with_context_symlink_seen_disables_fast_path() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        let mut ctx = ValidationContext::new(false);
        ctx.mark_symlink_seen();

        // After marking symlink seen, needs_full_canonicalize returns true
        assert!(ctx.needs_full_canonicalize());

        let path = PathBuf::from("file.txt");
        let result = SafePath::validate_with_context(&path, &dest, &config, &ctx);
        assert!(result.is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn test_validate_with_context_still_catches_symlink_attack() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();

        // Create a symlink pointing outside dest
        let malicious_link = temp.path().join("evil_dir");
        symlink("/tmp", &malicious_link).expect("failed to create symlink");

        // Even without context optimization, symlink attack must be caught.
        // Parent is NOT in DirCache so canonicalize will run.
        let dir_cache = DirCache::new();
        let ctx = ValidationContext::new(false).with_dir_cache(&dir_cache);

        let path = PathBuf::from("evil_dir/payload.txt");
        let result = SafePath::validate_with_context(&path, &dest, &config, &ctx);
        assert!(
            matches!(result, Err(ExtractionError::PathTraversal { .. })),
            "symlink attack must be caught even with context: {result:?}"
        );
    }

    // --- Additional tests for canonicalization optimization edge cases ---

    #[test]
    #[cfg(unix)]
    fn test_preexisting_symlink_in_dest_with_trusted_parent() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();

        // Create a real subdirectory and register in DirCache
        let sub_dir = dest.as_path().join("subdir");
        let mut dir_cache = DirCache::new();
        dir_cache.ensure_dir(&sub_dir).expect("should create dir");

        // Create a symlink INSIDE that directory pointing outside
        let evil_link = sub_dir.join("escape");
        symlink("/tmp", &evil_link).expect("failed to create symlink");

        // The resolved path is dest/subdir/escape/payload.txt. Its parent is
        // dest/subdir/escape, which is NOT in DirCache (only dest/subdir is).
        // Therefore the parent canonicalization layer still runs and catches
        // the symlink escape regardless of the symlink-free fast path.
        let ctx = ValidationContext::new(false).with_dir_cache(&dir_cache);
        let path = PathBuf::from("subdir/escape/payload.txt");
        let result = SafePath::validate_with_context(&path, &dest, &config, &ctx);
        assert!(
            matches!(result, Err(ExtractionError::PathTraversal { .. })),
            "parent canonicalization must catch symlink even in fast path: {result:?}"
        );

        // With symlink_seen marked, both parent AND full canonicalize run
        let mut ctx_with_symlink = ValidationContext::new(false).with_dir_cache(&dir_cache);
        ctx_with_symlink.mark_symlink_seen();
        let result_with_symlink =
            SafePath::validate_with_context(&path, &dest, &config, &ctx_with_symlink);
        assert!(
            matches!(
                result_with_symlink,
                Err(ExtractionError::PathTraversal { .. })
            ),
            "symlink attack must also be caught with symlink_seen=true: {result_with_symlink:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_as_direct_child_of_trusted_parent() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();

        // Create subdir and register in DirCache
        let sub_dir = dest.as_path().join("trusted");
        let mut dir_cache = DirCache::new();
        dir_cache.ensure_dir(&sub_dir).expect("should create dir");

        // Create symlink as a direct child: trusted/link -> /tmp
        let link = sub_dir.join("link");
        symlink("/tmp", &link).expect("failed to create symlink");

        // Path "trusted/link" has parent dest/trusted which IS in DirCache.
        // Parent canonicalize is skipped. But the symlink-free fast path only
        // does prefix check on the un-resolved path, which passes since the
        // path textually starts with dest. This is acceptable: the file being
        // extracted IS a direct child name, not a traversal through a symlink
        // directory. The symlink "link" itself would only be created if the
        // archive contained a symlink entry, which is blocked by config.
        let ctx = ValidationContext::new(false).with_dir_cache(&dir_cache);
        let path = PathBuf::from("trusted/link");
        let result = SafePath::validate_with_context(&path, &dest, &config, &ctx);
        assert!(
            result.is_ok(),
            "direct child of trusted parent is a file name, not traversal: {result:?}"
        );
    }

    #[test]
    fn test_validate_backward_compat_same_result() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();

        let test_paths = vec![
            PathBuf::from("file.txt"),
            PathBuf::from("dir/file.txt"),
            PathBuf::from("a/b/c/file.txt"),
            PathBuf::from("./normalized.txt"),
        ];

        for path in &test_paths {
            let result_validate = SafePath::validate(path, &dest, &config);
            let ctx = ValidationContext::new(config.allowed.symlinks);
            let result_with_ctx = SafePath::validate_with_context(path, &dest, &config, &ctx);

            assert_eq!(
                result_validate.is_ok(),
                result_with_ctx.is_ok(),
                "validate and validate_with_context should agree for path: {}",
                path.display()
            );

            if let (Ok(a), Ok(b)) = (&result_validate, &result_with_ctx) {
                assert_eq!(
                    a.as_path(),
                    b.as_path(),
                    "validate and validate_with_context should produce same SafePath"
                );
            }
        }
    }

    #[test]
    fn test_validate_backward_compat_error_paths() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();

        let error_paths = vec![
            PathBuf::from("../escape"),
            PathBuf::from(""),
            PathBuf::from("project/.git/config"),
        ];

        for path in &error_paths {
            let result_validate = SafePath::validate(path, &dest, &config);
            let ctx = ValidationContext::new(config.allowed.symlinks);
            let result_with_ctx = SafePath::validate_with_context(path, &dest, &config, &ctx);

            assert!(
                result_validate.is_err() && result_with_ctx.is_err(),
                "both should reject path: {}",
                path.display()
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_validate_with_context_symlinks_allowed_and_dir_cache() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();

        // Create dir and register in cache
        let sub = dest.as_path().join("safe_dir");
        let mut cache = DirCache::new();
        cache.ensure_dir(&sub).expect("should create dir");

        // Create symlink pointing outside in another location
        let evil = dest.as_path().join("evil");
        symlink("/tmp", &evil).expect("failed to create symlink");

        // With symlinks_allowed=true: needs_full_canonicalize is true,
        // so the full canonicalize runs and catches the symlink
        let ctx = ValidationContext::new(true).with_dir_cache(&cache);

        let safe_path = PathBuf::from("safe_dir/file.txt");
        let result = SafePath::validate_with_context(&safe_path, &dest, &config, &ctx);
        assert!(
            result.is_ok(),
            "safe path through cached dir should succeed: {result:?}"
        );

        let evil_path = PathBuf::from("evil/payload.txt");
        let result = SafePath::validate_with_context(&evil_path, &dest, &config, &ctx);
        assert!(
            matches!(result, Err(ExtractionError::PathTraversal { .. })),
            "symlink escape must be caught with symlinks_allowed + dir_cache: {result:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_free_fast_path_still_rejects_traversal() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        // Symlink-free fast path (no symlinks allowed, none seen)
        let ctx = ValidationContext::new(false);

        // These should still be caught by component-level checks
        let path = PathBuf::from("../escape.txt");
        let result = SafePath::validate_with_context(&path, &dest, &config, &ctx);
        assert!(
            matches!(result, Err(ExtractionError::PathTraversal { .. })),
            "parent traversal must be caught in fast path"
        );
    }

    #[test]
    fn test_validate_with_context_dir_cache_created_vs_preexisting() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();

        // Create directory manually (pre-existing, NOT in DirCache)
        let preexisting = dest.as_path().join("preexisting");
        std::fs::create_dir(&preexisting).expect("failed to create dir");

        // Create directory via DirCache (tracked)
        let tracked = dest.as_path().join("tracked");
        let mut cache = DirCache::new();
        cache.ensure_dir(&tracked).expect("should create dir");

        let ctx = ValidationContext::new(false).with_dir_cache(&cache);

        // Pre-existing dir is NOT trusted (not in cache), so canonicalize runs
        let path1 = PathBuf::from("preexisting/file.txt");
        let result1 = SafePath::validate_with_context(&path1, &dest, &config, &ctx);
        assert!(
            result1.is_ok(),
            "pre-existing dir should still validate: {result1:?}"
        );

        // Tracked dir IS trusted (in cache), parent canonicalize is skipped
        let path2 = PathBuf::from("tracked/file.txt");
        let result2 = SafePath::validate_with_context(&path2, &dest, &config, &ctx);
        assert!(result2.is_ok(), "tracked dir should validate: {result2:?}");
    }

    #[test]
    fn test_validate_with_context_no_parent() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();

        // Single-component path has dest itself as parent
        let cache = DirCache::new();
        let ctx = ValidationContext::new(false).with_dir_cache(&cache);

        let path = PathBuf::from("file.txt");
        let result = SafePath::validate_with_context(&path, &dest, &config, &ctx);
        assert!(result.is_ok(), "single component should work: {result:?}");
    }
}
