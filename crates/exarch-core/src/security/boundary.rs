//! Raw path string and config entry validation shared by FFI bindings.
//!
//! Both `exarch-python` and `exarch-node` accept archive/output paths as
//! plain strings from their host language before any `Path`, `DestDir`, or
//! `SecurityConfig` exists to run them through [`super::path::validate_path`].
//! They also accept caller-supplied `SecurityConfig` entries — allowed
//! extensions, banned path components — as plain strings before
//! [`crate::config::SecurityConfig::validate`] exists to check them. This
//! module centralizes both pre-flight checks so the two bindings cannot
//! drift on what counts as a well-formed input string.

use crate::error::ArchiveError;
use crate::error::Result;

/// Maximum length, in bytes, of a raw path string accepted at the FFI
/// boundary.
///
/// Linux and macOS define `PATH_MAX` as 4096 bytes. Bindings enforce the
/// same ceiling on every platform so behavior does not vary by OS and
/// pathological inputs are rejected before reaching the archive pipeline.
pub const MAX_PATH_LENGTH: usize = 4096;

/// Validates a raw, caller-supplied path string before it enters the
/// archive pipeline.
///
/// This is the shared boundary check for `exarch-python` and `exarch-node`:
/// reject overlong strings and null bytes before doing anything else with
/// them. It intentionally does not perform traversal, symlink, or
/// destination-boundary checks — those require a `Path`, a `DestDir`, and a
/// `SecurityConfig`, and are handled later by
/// [`super::path::validate_path`].
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
/// # Errors
///
/// Returns [`ArchiveError::SecurityViolation`] if `path` contains a null
/// byte or exceeds [`MAX_PATH_LENGTH`] bytes.
///
/// # Examples
///
/// ```
/// use exarch_core::validate_raw_path_str;
///
/// assert!(validate_raw_path_str("archive.tar.gz").is_ok());
/// assert!(validate_raw_path_str("bad\0path").is_err());
/// assert!(validate_raw_path_str(&"x".repeat(5000)).is_err());
/// ```
pub fn validate_raw_path_str(path: &str) -> Result<()> {
    if path.len() > MAX_PATH_LENGTH {
        return Err(ArchiveError::SecurityViolation {
            reason: format!(
                "path exceeds maximum length of {MAX_PATH_LENGTH} bytes (got {} bytes)",
                path.len()
            ),
        });
    }

    if path.contains('\0') {
        return Err(ArchiveError::SecurityViolation {
            reason: "path contains null bytes - potential security issue".to_string(),
        });
    }

    Ok(())
}

/// Maximum length, in bytes, of a single `SecurityConfig` entry — an
/// allowed extension or a banned path component.
pub const MAX_CONFIG_ENTRY_LENGTH: usize = 255;

/// Validates a single caller-supplied `SecurityConfig` entry string.
///
/// This is the shared boundary check for `exarch-python` and `exarch-node`
/// entry points that build `allowed_extensions` and `banned_path_components`
/// (`add_allowed_extension`, `add_banned_component`, and their `with_*`
/// equivalents), and is also called per-entry from
/// [`crate::config::SecurityConfig::validate`] as the backstop every entry
/// point funnels through. `field` names the caller's field for the error
/// message (e.g. `"extension"`, `"banned path component"`).
///
/// # Check order
///
/// 1. Length, checked before scanning for a null byte, for the same
///    O(1)-before-O(n) reason as [`validate_raw_path_str`].
/// 2. Null byte.
/// 3. Emptiness — unlike [`validate_raw_path_str`], which accepts `""`, an
///    empty entry is rejected here: in `banned_path_components` it is inert,
///    and in `allowed_extensions` it silently flips the config from "allow all"
///    to an allowlist that matches nothing.
///
/// # Errors
///
/// Returns [`ArchiveError::InvalidConfiguration`] if `value` exceeds
/// [`MAX_CONFIG_ENTRY_LENGTH`] bytes, contains a null byte, or is empty.
///
/// # Examples
///
/// ```
/// use exarch_core::validate_config_entry;
///
/// assert!(validate_config_entry("txt", "extension").is_ok());
/// assert!(validate_config_entry("", "extension").is_err());
/// assert!(validate_config_entry("bad\0ext", "extension").is_err());
/// assert!(validate_config_entry(&"x".repeat(256), "extension").is_err());
/// ```
pub fn validate_config_entry(value: &str, field: &str) -> Result<()> {
    if value.len() > MAX_CONFIG_ENTRY_LENGTH {
        return Err(ArchiveError::InvalidConfiguration {
            reason: format!(
                "{field} exceeds maximum length of {MAX_CONFIG_ENTRY_LENGTH} bytes (got {} bytes)",
                value.len()
            ),
        });
    }

    if value.contains('\0') {
        return Err(ArchiveError::InvalidConfiguration {
            reason: format!("{field} contains null bytes - potential security issue"),
        });
    }

    if value.is_empty() {
        return Err(ArchiveError::InvalidConfiguration {
            reason: format!("{field} must not be empty"),
        });
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_raw_path_str_accepts_normal() {
        assert!(validate_raw_path_str("/tmp/test.tar.gz").is_ok());
        assert!(validate_raw_path_str("relative/path.tar").is_ok());
        assert!(validate_raw_path_str("").is_ok());
    }

    #[test]
    fn test_validate_raw_path_str_rejects_null_bytes() {
        let err = validate_raw_path_str("/tmp/test\0malicious").expect_err("null byte");
        match err {
            ArchiveError::SecurityViolation { reason } => {
                assert_eq!(
                    reason,
                    "path contains null bytes - potential security issue"
                );
            }
            other => panic!("expected SecurityViolation, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_raw_path_str_rejects_too_long() {
        let long_path = "x".repeat(MAX_PATH_LENGTH + 1);
        let err = validate_raw_path_str(&long_path).expect_err("too long");
        match err {
            ArchiveError::SecurityViolation { reason } => {
                assert_eq!(
                    reason,
                    format!(
                        "path exceeds maximum length of {MAX_PATH_LENGTH} bytes (got {} bytes)",
                        long_path.len()
                    )
                );
            }
            other => panic!("expected SecurityViolation, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_raw_path_str_checks_length_before_null_byte() {
        let long_path_with_null = format!("{}\0", "x".repeat(MAX_PATH_LENGTH));
        let err = validate_raw_path_str(&long_path_with_null).expect_err("too long");
        match err {
            ArchiveError::SecurityViolation { reason } => {
                assert!(
                    reason.contains("maximum length"),
                    "length check should run first: {reason}"
                );
            }
            other => panic!("expected SecurityViolation, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_raw_path_str_accepts_max_length() {
        let max_path = "x".repeat(MAX_PATH_LENGTH);
        assert!(validate_raw_path_str(&max_path).is_ok());
    }

    #[test]
    fn test_validate_config_entry_accepts_normal() {
        assert!(validate_config_entry("txt", "extension").is_ok());
        assert!(validate_config_entry(".git", "banned path component").is_ok());
    }

    #[test]
    fn test_validate_config_entry_rejects_empty() {
        let err = validate_config_entry("", "extension").expect_err("empty");
        match err {
            ArchiveError::InvalidConfiguration { reason } => {
                assert_eq!(reason, "extension must not be empty");
            }
            other => panic!("expected InvalidConfiguration, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_config_entry_rejects_null_bytes() {
        let err = validate_config_entry("bad\0ext", "extension").expect_err("null byte");
        match err {
            ArchiveError::InvalidConfiguration { reason } => {
                assert_eq!(
                    reason,
                    "extension contains null bytes - potential security issue"
                );
            }
            other => panic!("expected InvalidConfiguration, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_config_entry_accepts_max_length() {
        let max_entry = "x".repeat(MAX_CONFIG_ENTRY_LENGTH);
        assert!(validate_config_entry(&max_entry, "extension").is_ok());
    }

    #[test]
    fn test_validate_config_entry_rejects_too_long() {
        let long_entry = "x".repeat(MAX_CONFIG_ENTRY_LENGTH + 1);
        let err = validate_config_entry(&long_entry, "extension").expect_err("too long");
        match err {
            ArchiveError::InvalidConfiguration { reason } => {
                assert_eq!(
                    reason,
                    format!(
                        "extension exceeds maximum length of {MAX_CONFIG_ENTRY_LENGTH} bytes (got {} bytes)",
                        long_entry.len()
                    )
                );
            }
            other => panic!("expected InvalidConfiguration, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_config_entry_rejects_multibyte_over_length() {
        // "日" is 3 bytes in UTF-8; 100 repeats is 300 bytes but only 100
        // chars.
        let multibyte_entry = "日".repeat(100);
        assert!(multibyte_entry.chars().count() < MAX_CONFIG_ENTRY_LENGTH);
        let err =
            validate_config_entry(&multibyte_entry, "extension").expect_err("too long in bytes");
        match err {
            ArchiveError::InvalidConfiguration { reason } => {
                assert!(
                    reason.contains("bytes"),
                    "message must use byte-length wording: {reason}"
                );
            }
            other => panic!("expected InvalidConfiguration, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_config_entry_checks_length_before_null_byte() {
        let long_entry_with_null = format!("{}\0", "x".repeat(MAX_CONFIG_ENTRY_LENGTH));
        let err = validate_config_entry(&long_entry_with_null, "extension").expect_err("too long");
        match err {
            ArchiveError::InvalidConfiguration { reason } => {
                assert!(
                    reason.contains("maximum length"),
                    "length check should run first: {reason}"
                );
            }
            other => panic!("expected InvalidConfiguration, got: {other:?}"),
        }
    }
}
