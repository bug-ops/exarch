//! Utility functions for Node.js bindings.

use exarch_core::ArchiveError as CoreError;
use std::path::Path;

use exarch_core::BoundaryPath;

/// An entry path as text, written so that two distinct paths never render
/// alike.
///
/// The encoding is injective: a backslash is written `\x5C`, and each byte of a
/// Unix path (or each unpaired UTF-16 unit of a Windows path) that is not part
/// of valid text is written `\xNN` (`\uNNNN`). Every other character is kept
/// as it is, so a name without backslashes and without invalid bytes renders
/// unchanged, and a literal `a\xFFb` renders as `a\x5CxFFb`, never as the
/// path `a<0xFF>b`.
///
/// Used where refusing the path would hide the finding that reports it
/// (verification issues, integrity gaps, skip samples, progress callbacks);
/// listings and in-memory entries refuse a path that is not valid UTF-8
/// instead.
pub fn path_text(path: &Path) -> String {
    let mut out = String::new();
    push_path(&mut out, path);
    out
}

fn push_text(out: &mut String, text: &str) {
    for ch in text.chars() {
        if ch == '\\' {
            out.push_str("\\x5C");
        } else {
            out.push(ch);
        }
    }
}

#[cfg(unix)]
fn push_path(out: &mut String, path: &Path) {
    use std::fmt::Write as _;
    use std::os::unix::ffi::OsStrExt;

    for chunk in path.as_os_str().as_bytes().utf8_chunks() {
        push_text(out, chunk.valid());
        for byte in chunk.invalid() {
            // Writing to a String cannot fail.
            let _ = write!(out, "\\x{byte:02X}");
        }
    }
}

#[cfg(windows)]
fn push_path(out: &mut String, path: &Path) {
    use std::fmt::Write as _;
    use std::os::windows::ffi::OsStrExt;

    for unit in char::decode_utf16(path.as_os_str().encode_wide()) {
        match unit {
            Ok(ch) => push_text(out, ch.encode_utf8(&mut [0; 4])),
            Err(unpaired) => {
                // Writing to a String cannot fail.
                let _ = write!(out, "\\u{:04X}", unpaired.unpaired_surrogate());
            }
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn push_path(out: &mut String, path: &Path) {
    push_text(out, &path.to_string_lossy());
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
    fn test_path_text_keeps_utf8_without_backslashes() {
        assert_eq!(path_text(Path::new("dir/a.txt")), "dir/a.txt");
    }

    #[test]
    fn test_path_text_escapes_the_backslash() {
        assert_eq!(path_text(Path::new("a\\xFFb")), "a\\x5CxFFb");
        assert_eq!(path_text(Path::new("a\\b")), "a\\x5Cb");
    }

    #[cfg(unix)]
    #[test]
    fn test_path_text_never_renders_distinct_paths_alike() {
        use std::os::unix::ffi::OsStrExt;

        let first_invalid = Path::new(std::ffi::OsStr::from_bytes(b"a\xFFb"));
        let other_invalid = Path::new(std::ffi::OsStr::from_bytes(b"a\xFEb"));
        let literal = Path::new("a\\xFFb");
        assert_eq!(path_text(first_invalid), "a\\xFFb");
        let all = [
            path_text(first_invalid),
            path_text(other_invalid),
            path_text(literal),
        ];
        for (i, a) in all.iter().enumerate() {
            assert!(all[i + 1..].iter().all(|b| a != b), "{all:?}");
        }
    }
}
