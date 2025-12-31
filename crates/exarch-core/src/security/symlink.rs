//! Symlink security validation.

use std::path::Path;

use crate::Result;
use crate::SecurityConfig;
use crate::types::DestDir;
use crate::types::SafePath;
use crate::types::SafeSymlink;

/// Validates that a symlink target is safe.
///
/// This function delegates to `SafeSymlink::validate()` which ensures:
/// - Symlinks are allowed in the security configuration
/// - Target is relative (no absolute symlink targets)
/// - Target resolves within the destination directory
/// - Target doesn't escape via parent directory traversal
///
/// # Performance
///
/// Typical execution time: ~5-50 μs (involves path resolution and
/// canonicalization)
///
/// # Errors
///
/// Returns an error if symlinks are not allowed or if the target
/// escapes the extraction directory:
/// - `ExtractionError::SecurityViolation` if symlinks disabled
/// - `ExtractionError::SymlinkEscape` if target is outside destination
///
/// # Examples
///
/// ```no_run
/// use exarch_core::SecurityConfig;
/// use exarch_core::security::validate_symlink;
/// use exarch_core::types::DestDir;
/// use exarch_core::types::SafePath;
/// use std::path::Path;
/// use std::path::PathBuf;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dest = DestDir::new(PathBuf::from("/tmp"))?;
/// let mut config = SecurityConfig::default();
/// config.allowed.symlinks = true;
///
/// let link_path = SafePath::validate(&PathBuf::from("link"), &dest, &config)?;
/// let target = Path::new("target.txt");
///
/// let safe_symlink = validate_symlink(&link_path, target, &dest, &config)?;
/// # Ok(())
/// # }
/// ```
pub fn validate_symlink(
    link_path: &SafePath,
    target: &Path,
    dest: &DestDir,
    config: &SecurityConfig,
) -> Result<SafeSymlink> {
    SafeSymlink::validate(link_path, target, dest, config)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]
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
    fn test_validate_symlink_allowed() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = true;

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).unwrap();
        let target = PathBuf::from("target.txt");
        assert!(validate_symlink(&link, &target, &dest, &config).is_ok());
    }

    #[test]
    fn test_validate_symlink_disabled() {
        let (_temp, dest) = create_test_dest();
        let config = SecurityConfig::default(); // symlinks disabled by default

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).unwrap();
        let target = PathBuf::from("target.txt");
        assert!(validate_symlink(&link, &target, &dest, &config).is_err());
    }

    #[test]
    fn test_validate_symlink_escape() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = true;

        let link = SafePath::validate(&PathBuf::from("link"), &dest, &config).unwrap();
        let target = PathBuf::from("../../etc/passwd");
        assert!(validate_symlink(&link, &target, &dest, &config).is_err());
    }

    #[test]
    fn test_validate_symlink_relative_safe() {
        let (_temp, dest) = create_test_dest();
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = true;

        let link = SafePath::validate(&PathBuf::from("foo/link"), &dest, &config).unwrap();
        let target = PathBuf::from("../bar/target.txt");
        let result = validate_symlink(&link, &target, &dest, &config);
        assert!(result.is_ok());
    }
}
