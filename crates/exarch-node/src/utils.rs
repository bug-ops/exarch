//! Utility functions for Node.js bindings.

use napi::bindgen_prelude::*;

use crate::error::convert_error;

/// Validates a path string for security issues.
///
/// Delegates to the shared boundary check in `exarch_core`; see
/// [`exarch_core::validate_raw_path_str`] for the exact rules (null bytes,
/// maximum length). Errors are routed through [`convert_error`] so they
/// carry the same `SECURITY_VIOLATION:` code prefix as every other
/// security-policy rejection surfaced by this crate.
///
/// # Errors
///
/// Returns error if path contains null bytes or exceeds maximum length.
pub fn validate_path(path: &str) -> Result<()> {
    exarch_core::validate_raw_path_str(path).map_err(convert_error)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use exarch_core::MAX_PATH_LENGTH;

    #[test]
    fn test_validate_path_accepts_normal() {
        assert!(
            validate_path("/tmp/test.tar.gz").is_ok(),
            "absolute paths should be accepted"
        );
        assert!(
            validate_path("relative/path.tar").is_ok(),
            "relative paths should be accepted"
        );
        // Empty path is valid - callers may provide empty strings for defaults
        // or optional parameters. Core library handles empty path validation.
        assert!(validate_path("").is_ok(), "empty paths should be accepted");
    }

    #[test]
    fn test_validate_path_rejects_null_bytes() {
        let result = validate_path("/tmp/test\0malicious");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("null bytes"));
    }

    #[test]
    fn test_validate_path_rejects_too_long() {
        let long_path = "x".repeat(MAX_PATH_LENGTH + 1);
        let result = validate_path(&long_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("maximum length"));
    }

    #[test]
    fn test_validate_path_accepts_max_length() {
        let max_path = "x".repeat(MAX_PATH_LENGTH);
        assert!(validate_path(&max_path).is_ok());
    }
}
