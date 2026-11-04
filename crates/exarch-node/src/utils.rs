//! Utility functions for Node.js bindings.

use exarch_core::ArchiveError as CoreError;
use std::path::Path;

use exarch_core::BoundaryPath;

/// An entry path as text.
///
/// A path that is valid UTF-8 is returned as it is. Any other path has each
/// byte that is not part of a valid sequence written as `\xNN` (a `?`-style
/// replacement character would merge distinct names), so two distinct paths
/// never render alike unless one of them literally contains that escape.
/// Used where refusing the path would hide the finding that reports it
/// (verification issues, progress, skip samples); listings and in-memory
/// entries refuse such paths instead.
pub fn path_text(path: &Path) -> String {
    if let Some(text) = path.to_str() {
        return text.to_owned();
    }
    escaped(path)
}

#[cfg(unix)]
fn escaped(path: &Path) -> String {
    use std::fmt::Write as _;
    use std::os::unix::ffi::OsStrExt;

    let mut out = String::new();
    for chunk in path.as_os_str().as_bytes().utf8_chunks() {
        out.push_str(chunk.valid());
        for byte in chunk.invalid() {
            // Writing to a String cannot fail.
            let _ = write!(out, "\\x{byte:02X}");
        }
    }
    out
}

#[cfg(not(unix))]
fn escaped(path: &Path) -> String {
    let debug = format!("{path:?}");
    debug.trim_matches('"').to_owned()
}

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

    #[test]
    fn test_path_text_keeps_utf8() {
        assert_eq!(path_text(Path::new("dir/a.txt")), "dir/a.txt");
    }

    #[cfg(unix)]
    #[test]
    fn test_path_text_escapes_invalid_bytes_without_merging_names() {
        use std::os::unix::ffi::OsStrExt;

        let first = Path::new(std::ffi::OsStr::from_bytes(b"a\xFFb"));
        let second = Path::new(std::ffi::OsStr::from_bytes(b"a\xFEb"));
        assert_eq!(path_text(first), "a\\xFFb");
        assert_ne!(path_text(first), path_text(second));
    }
}
