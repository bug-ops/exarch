//! Utility functions for Node.js bindings.

use napi::bindgen_prelude::*;

/// Maximum path length in bytes (Linux/macOS `PATH_MAX` is typically 4096)
const MAX_PATH_LENGTH: usize = 4096;

/// Validates a path string for security issues.
///
/// Rejects:
/// - Paths containing null bytes (potential injection attacks)
/// - Paths exceeding `MAX_PATH_LENGTH` bytes (`DoS` prevention)
///
/// # Errors
///
/// Returns error if path contains null bytes or exceeds maximum length.
pub fn validate_path(path: &str) -> Result<()> {
    // Use constant-time null byte check to prevent timing side-channel attacks
    // The fold operation processes every byte regardless of when null is found
    let has_null = path.bytes().fold(false, |acc, b| acc | (b == 0));

    if has_null {
        return Err(Error::from_reason(
            "path contains null bytes - potential security issue",
        ));
    }

    if path.len() > MAX_PATH_LENGTH {
        // Pre-allocate string to avoid multiple allocations
        use std::fmt::Write;
        let mut msg = String::with_capacity(80);
        // Writing to a String never fails
        let _ = write!(
            &mut msg,
            "path exceeds maximum length of {MAX_PATH_LENGTH} bytes (got {} bytes)",
            path.len()
        );
        return Err(Error::from_reason(msg));
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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
