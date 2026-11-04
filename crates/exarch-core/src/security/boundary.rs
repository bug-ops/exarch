//! Raw path string validation shared by FFI bindings.
//!
//! Both `exarch-python` and `exarch-node` accept archive/output paths as
//! plain strings from their host language before any `Path`, `DestDir`, or
//! `SecurityConfig` exists to run them through `validate_path`. This module
//! centralizes that pre-flight check so the two bindings cannot drift on what
//! counts as a well-formed input string. Config list entries are parsed by
//! [`crate::Extension`] and [`crate::PathComponentName`].

use std::path::Path;

use crate::error::Result;
use crate::error::Violation;

/// Maximum length, in bytes, of a raw path string accepted at the FFI
/// boundary.
///
/// Linux and macOS define `PATH_MAX` as 4096 bytes. Bindings enforce the
/// same ceiling on every platform so behavior does not vary by OS and
/// pathological inputs are rejected before reaching the archive pipeline.
pub const MAX_PATH_LENGTH: usize = 4096;

/// A caller-supplied path string that passed the boundary checks.
///
/// This is the shared boundary check for `exarch-python` and `exarch-node`:
/// reject overlong strings and null bytes before doing anything else with
/// them. It intentionally does not perform traversal, symlink, or
/// destination-boundary checks — those require a `Path`, a `DestDir`, and a
/// `SecurityConfig`, and are handled later by `validate_path`.
///
/// The only constructor is [`BoundaryPath::parse`], so a binding entry point
/// that takes a `BoundaryPath` cannot receive an unchecked string.
///
/// # Check order
///
/// Length is checked before scanning for a null byte: `.len()` is an O(1)
/// lookup, so an oversized input is rejected without ever running the
/// O(n) null-byte scan below it — this serves the length check's own
/// `DoS`-prevention purpose.
///
/// # Null-byte detection
///
/// Uses [`str::contains`], which short-circuits on the first null byte.
/// This check validates the *format* of caller-supplied input (is this a
/// well-formed path string?) rather than comparing one secret against
/// another, so there is no timing side channel to defend against and
/// short-circuiting is safe.
///
/// # Examples
///
/// ```
/// use std::path::Path;
///
/// use exarch_core::BoundaryPath;
///
/// let path = BoundaryPath::parse("archive.tar.gz".to_owned())?;
/// assert_eq!(path.as_str(), "archive.tar.gz");
/// assert_eq!(AsRef::<Path>::as_ref(&path), Path::new("archive.tar.gz"));
/// assert!(BoundaryPath::parse("bad\0path".to_owned()).is_err());
/// assert!(BoundaryPath::parse("x".repeat(5000)).is_err());
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryPath(String);

impl BoundaryPath {
    /// Checks a raw path string and keeps it as proof of the check.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ArchiveError::SecurityViolation`] if `path` contains a
    /// null byte or exceeds [`MAX_PATH_LENGTH`] bytes.
    pub fn parse(path: String) -> Result<Self> {
        if path.len() > MAX_PATH_LENGTH {
            return Err(Violation::PathTooLong {
                len: path.len(),
                max: MAX_PATH_LENGTH,
            }
            .into());
        }

        if path.contains('\0') {
            return Err(Violation::NulInPathArgument.into());
        }

        Ok(Self(path))
    }

    /// The checked string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The checked string, by value.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<Path> for BoundaryPath {
    fn as_ref(&self) -> &Path {
        Path::new(&self.0)
    }
}

/// Maximum length, in bytes, of a single `SecurityConfig` entry — an
/// allowed extension or a banned path component.
pub const MAX_CONFIG_ENTRY_LENGTH: usize = 255;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::assert_matches;

    fn parse(path: &str) -> Result<BoundaryPath> {
        BoundaryPath::parse(path.to_owned())
    }

    #[test]
    fn test_parse_accepts_normal() {
        assert!(parse("/tmp/test.tar.gz").is_ok());
        assert!(parse("relative/path.tar").is_ok());
        assert!(parse("").is_ok());
    }

    #[test]
    fn test_parse_keeps_the_checked_string() {
        let path = parse("a/b.tar").unwrap();
        assert_eq!(path.as_str(), "a/b.tar");
        assert_eq!(AsRef::<Path>::as_ref(&path), Path::new("a/b.tar"));
        assert_eq!(path.into_string(), "a/b.tar");
    }

    #[test]
    fn test_parse_rejects_null_bytes() {
        let err = parse("/tmp/test\0malicious").expect_err("null byte");
        assert_eq!(
            err.security_violation(),
            Some(&Violation::NulInPathArgument)
        );
        assert_eq!(
            err.context().as_deref(),
            Some("path contains null bytes - potential security issue")
        );
    }

    #[test]
    fn test_parse_rejects_too_long() {
        let long_path = "x".repeat(MAX_PATH_LENGTH + 1);
        let err = parse(&long_path).expect_err("too long");
        assert_eq!(
            err.security_violation(),
            Some(&Violation::PathTooLong {
                len: long_path.len(),
                max: MAX_PATH_LENGTH
            })
        );
        assert_eq!(
            err.context().as_deref(),
            Some(
                format!(
                    "path exceeds maximum length of {MAX_PATH_LENGTH} bytes (got {} bytes)",
                    long_path.len()
                )
                .as_str()
            )
        );
    }

    #[test]
    fn test_parse_checks_length_before_null_byte() {
        let long_path_with_null = format!("{}\0", "x".repeat(MAX_PATH_LENGTH));
        let err = parse(&long_path_with_null).expect_err("too long");
        assert_matches!(
            err.security_violation(),
            Some(Violation::PathTooLong { .. })
        );
    }

    #[test]
    fn test_parse_accepts_max_length() {
        let max_path = "x".repeat(MAX_PATH_LENGTH);
        assert!(parse(&max_path).is_ok());
    }
}
