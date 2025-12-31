//! Path traversal validation.

use std::path::Path;

use crate::Result;
use crate::SecurityConfig;
use crate::types::DestDir;
use crate::types::SafePath;

/// Validates that a path does not contain traversal attempts.
///
/// This function delegates to `SafePath::validate()` which performs
/// comprehensive validation including:
/// - Null byte detection
/// - Absolute path rejection (unless allowed)
/// - Parent directory traversal (`..`) detection
/// - Path depth limiting
/// - Banned component checking
/// - Path normalization
/// - Destination boundary verification
///
/// # Performance
///
/// For non-existing paths: ~300-500 ns (no I/O syscalls)
/// For existing paths: ~5-50 μs (involves `canonicalize()` syscalls)
///
/// # Errors
///
/// Returns an error if the path contains:
/// - `ExtractionError::PathTraversal` for `..` or absolute paths
/// - `ExtractionError::SecurityViolation` for banned components or excessive
///   depth
///
/// # Examples
///
/// ```no_run
/// use exarch_core::SecurityConfig;
/// use exarch_core::security::validate_path;
/// use exarch_core::types::DestDir;
/// use std::path::Path;
/// use std::path::PathBuf;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dest = DestDir::new(PathBuf::from("/tmp"))?;
/// let config = SecurityConfig::default();
///
/// // Valid path
/// let path = Path::new("foo/bar.txt");
/// let safe_path = validate_path(path, &dest, &config)?;
///
/// // Path traversal is rejected
/// let path = Path::new("../etc/passwd");
/// assert!(validate_path(path, &dest, &config).is_err());
/// # Ok(())
/// # }
/// ```
pub fn validate_path(path: &Path, dest: &DestDir, config: &SecurityConfig) -> Result<SafePath> {
    SafePath::validate(path, dest, config)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn create_test_dest() -> (TempDir, DestDir) {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        (temp, dest)
    }

    #[test]
    fn test_validate_path_valid() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();
        let path = PathBuf::from("foo/bar.txt");
        assert!(validate_path(&path, &dest, &config).is_ok());
    }

    #[test]
    fn test_validate_path_traversal() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();
        let path = PathBuf::from("../etc/passwd");
        assert!(validate_path(&path, &dest, &config).is_err());
    }

    #[test]
    fn test_validate_path_absolute() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();
        let path = PathBuf::from("/etc/passwd");
        assert!(validate_path(&path, &dest, &config).is_err());
    }

    #[test]
    fn test_validate_path_nested() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();
        let path = PathBuf::from("foo/bar/baz/file.txt");
        assert!(validate_path(&path, &dest, &config).is_ok());
    }

    #[test]
    fn test_validate_path_current_dir() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default();
        let path = PathBuf::from("./foo/bar.txt");
        let result = validate_path(&path, &dest, &config);
        assert!(result.is_ok());
    }
}
