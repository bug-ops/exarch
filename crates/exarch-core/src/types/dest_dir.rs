//! Validated destination directory type.

use crate::ExtractionError;
use crate::Result;
use std::path::Path;
use std::path::PathBuf;

/// A validated destination directory for archive extraction.
///
/// This type represents a directory that has been validated to:
/// - Exist on the filesystem
/// - Be a directory (not a file)
/// - Be writable by the current process
/// - Be represented as an absolute canonical path
///
/// # Security Properties
///
/// Once constructed, a `DestDir` is guaranteed to be a valid, writable
/// directory. All paths are canonicalized to prevent TOCTOU
/// (time-of-check-time-of-use) attacks.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::types::DestDir;
/// use std::path::PathBuf;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dest = DestDir::new(PathBuf::from("/tmp/extraction"))?;
/// println!("Extracting to: {}", dest.as_path().display());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestDir(PathBuf);

impl DestDir {
    /// Creates a new `DestDir` after validating the path.
    ///
    /// # Validation
    ///
    /// This function performs the following checks:
    /// 1. Verifies the path exists
    /// 2. Verifies the path is a directory
    /// 3. Canonicalizes the path to an absolute path
    /// 4. Checks write permissions (platform-specific)
    ///
    /// # Security Considerations
    ///
    /// **TOCTOU Warning**: This function has a time-of-check-time-of-use
    /// (TOCTOU) race condition between the `exists()`, `is_dir()`, and
    /// `canonicalize()` calls. An attacker with filesystem access could
    /// replace the directory with a symlink between these checks.
    ///
    /// This is partially mitigated by:
    /// - Canonicalizing the path, which resolves symlinks
    /// - Validating all extracted paths against the canonical destination
    ///
    /// Full TOCTOU mitigation would require using `openat()` family of
    /// functions for all subsequent operations, which is platform-specific
    /// and complex.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The path does not exist
    /// - The path exists but is not a directory
    /// - The path cannot be canonicalized
    /// - The directory is not writable (on Unix)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use exarch_core::types::DestDir;
    /// use std::path::PathBuf;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let dest = DestDir::new(PathBuf::from("/tmp"))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        // Verify path exists
        if !path.exists() {
            return Err(ExtractionError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("destination directory does not exist: {}", path.display()),
            )));
        }

        // Verify it's a directory
        if !path.is_dir() {
            return Err(ExtractionError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("path is not a directory: {}", path.display()),
            )));
        }

        // Canonicalize to absolute path
        let canonical = path.canonicalize().map_err(|e| {
            ExtractionError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to canonicalize path {}: {}", path.display(), e),
            ))
        })?;

        // M-CODE-6: Check write permissions using libc::access() (Unix only)
        #[cfg(unix)]
        {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;

            // Use access() syscall to check effective write permissions
            let path_cstring = CString::new(canonical.as_os_str().as_bytes()).map_err(|_| {
                ExtractionError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "path contains null byte",
                ))
            })?;

            // SAFETY: access() is safe to call with a valid C string.
            // The pointer is valid for the duration of the call.
            // access() does not modify the string and returns immediately.
            #[allow(unsafe_code)]
            let result = unsafe { libc::access(path_cstring.as_ptr(), libc::W_OK) };

            if result != 0 {
                return Err(ExtractionError::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("directory is not writable: {}", canonical.display()),
                )));
            }
        }

        Ok(Self(canonical))
    }

    /// Returns the path as a `&Path`.
    #[inline]
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Joins a `SafePath` to this destination directory.
    ///
    /// This method combines the destination directory with a validated safe
    /// path to produce the final extraction path.
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
    /// let safe = SafePath::validate(&PathBuf::from("foo/bar.txt"), &dest, &config)?;
    ///
    /// let final_path = dest.join(&safe);
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    #[must_use]
    pub fn join(&self, safe_path: &super::SafePath) -> PathBuf {
        self.0.join(safe_path.as_path())
    }

    /// Joins a `Path` to this destination directory.
    ///
    /// This is a convenience method for joining arbitrary paths that
    /// have already been validated (e.g., from `SafeSymlink.link_path()`).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use exarch_core::types::DestDir;
    /// use std::path::Path;
    /// use std::path::PathBuf;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let dest = DestDir::new(PathBuf::from("/tmp"))?;
    /// let path = Path::new("foo/bar.txt");
    ///
    /// let final_path = dest.join_path(path);
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    #[must_use]
    pub fn join_path(&self, path: &Path) -> PathBuf {
        self.0.join(path)
    }

    /// Converts into the inner `PathBuf`.
    #[inline]
    #[must_use]
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_dest_dir_valid() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf());
        assert!(dest.is_ok());

        let dest = dest.expect("dest should be valid");
        assert!(dest.as_path().is_absolute());
    }

    #[test]
    fn test_dest_dir_nonexistent() {
        let path = PathBuf::from("/nonexistent/directory/that/does/not/exist");
        let result = DestDir::new(path);
        assert!(result.is_err());
        assert!(matches!(result, Err(ExtractionError::Io(_))));
    }

    #[test]
    fn test_dest_dir_not_a_directory() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let file_path = temp.path().join("file.txt");
        fs::write(&file_path, "test").expect("failed to write file");

        let result = DestDir::new(file_path);
        assert!(result.is_err());
        assert!(matches!(result, Err(ExtractionError::Io(_))));
    }

    #[test]
    fn test_dest_dir_canonicalization() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let subdir = temp.path().join("subdir");
        fs::create_dir(&subdir).expect("failed to create subdir");

        // Use a path with . in it
        let path_with_dot = subdir.join(".").join("..");
        let dest = DestDir::new(path_with_dot).expect("should create dest dir");

        // Should be canonicalized to absolute path
        assert!(dest.as_path().is_absolute());
        assert_eq!(dest.as_path(), temp.path().canonicalize().unwrap());
    }

    #[test]
    #[cfg(unix)]
    fn test_dest_dir_permissions_check() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("failed to create temp dir");
        let readonly_dir = temp.path().join("readonly");
        fs::create_dir(&readonly_dir).expect("failed to create dir");

        // Make directory read-only
        let mut perms = fs::metadata(&readonly_dir)
            .expect("failed to get metadata")
            .permissions();
        perms.set_mode(0o444);
        fs::set_permissions(&readonly_dir, perms).expect("failed to set permissions");

        let result = DestDir::new(readonly_dir.clone());

        // Restore permissions for cleanup
        let mut perms = fs::metadata(&readonly_dir)
            .expect("failed to get metadata")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&readonly_dir, perms).expect("failed to set permissions");

        assert!(result.is_err());
    }

    #[test]
    fn test_dest_dir_equality() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest1 = DestDir::new(temp.path().to_path_buf()).expect("should create");
        let dest2 = DestDir::new(temp.path().to_path_buf()).expect("should create");
        assert_eq!(dest1, dest2);
    }

    #[test]
    fn test_dest_dir_clone() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("should create");
        let cloned = dest.clone();
        assert_eq!(dest, cloned);
    }

    #[test]
    fn test_dest_dir_with_symlink() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let real_dir = temp.path().join("real");
        fs::create_dir(&real_dir).expect("failed to create real dir");

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let symlink_path = temp.path().join("link");
            symlink(&real_dir, &symlink_path).expect("failed to create symlink");

            // Should resolve symlink and create valid DestDir
            let dest = DestDir::new(symlink_path).expect("should create from symlink");
            assert!(
                dest.as_path().is_absolute(),
                "should be absolute canonical path"
            );
            // Canonical path should resolve to the real directory
            assert_eq!(
                dest.as_path(),
                real_dir.canonicalize().unwrap(),
                "should resolve symlink to real path"
            );
        }
    }

    #[test]
    fn test_dest_dir_nested_path() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let nested = temp.path().join("a").join("b").join("c");
        fs::create_dir_all(&nested).expect("failed to create nested dirs");

        let dest = DestDir::new(nested).expect("should create from nested path");
        assert!(dest.as_path().is_absolute());
    }

    #[test]
    fn test_dest_dir_into_path_buf() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("should create");
        let path = dest.clone().into_path_buf();

        assert!(path.is_absolute(), "converted path should be absolute");
        assert_eq!(path, dest.as_path(), "should match original path");
    }
}
