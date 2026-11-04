//! Utility functions for Node.js bindings.

use exarch_core::ArchiveError as CoreError;
use exarch_core::BoundaryPath;

pub use exarch_core::path_text;

/// Checks a path argument and returns the proof of the check.
///
/// Delegates to the shared boundary check in `exarch_core`; see
/// [`BoundaryPath::parse`] for the exact rules (null bytes, maximum length).
/// The core error is returned unconverted so it reaches JavaScript with the
/// same `SECURITY_VIOLATION` code as every other security-policy rejection
/// surfaced by this crate. The caller passes the returned value on, never the
/// raw string.
///
/// # Errors
///
/// Returns error if path contains null bytes or exceeds maximum length.
pub fn boundary_path(path: &str) -> Result<BoundaryPath, CoreError> {
    BoundaryPath::parse(path.to_owned())
}

/// [`boundary_path`] for every path of `paths`, stopping at the first refusal.
///
/// # Errors
///
/// Returns the error of the first path that is refused.
pub fn boundary_paths(paths: &[String]) -> Result<Vec<BoundaryPath>, CoreError> {
    paths.iter().map(|path| boundary_path(path)).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use exarch_core::MAX_PATH_LENGTH;

    #[test]
    fn test_validate_path_accepts_normal() {
        assert!(
            boundary_path("/tmp/test.tar.gz").is_ok(),
            "absolute paths should be accepted"
        );
        assert!(
            boundary_path("relative/path.tar").is_ok(),
            "relative paths should be accepted"
        );
        // Empty path is valid - callers may provide empty strings for defaults
        // or optional parameters. Core library handles empty path validation.
        assert!(boundary_path("").is_ok(), "empty paths should be accepted");
    }

    #[test]
    fn test_validate_path_rejects_null_bytes() {
        let result = boundary_path("/tmp/test\0malicious");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("null bytes"));
    }

    #[test]
    fn test_validate_path_rejects_too_long() {
        let long_path = "x".repeat(MAX_PATH_LENGTH + 1);
        let result = boundary_path(&long_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("maximum length"));
    }

    #[test]
    fn test_validate_path_accepts_max_length() {
        let max_path = "x".repeat(MAX_PATH_LENGTH);
        assert!(boundary_path(&max_path).is_ok());
    }
}
