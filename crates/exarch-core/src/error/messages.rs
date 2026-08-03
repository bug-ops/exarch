//! FFI error message formatting.
//!
//! Provides consistent error messages across Python and Node.js bindings
//! while allowing platform-specific customization.

use super::redaction::sanitize_io_error_for_error;
use super::types::ArchiveError;

/// Error message for FFI consumption.
///
/// Contains structured error information that can be converted to
/// platform-specific error types (Python exceptions, Node.js Error objects).
#[derive(Debug, Clone)]
pub struct FfiErrorMessage {
    /// Error code (e.g., `PATH_TRAVERSAL`, `ZIP_BOMB`)
    pub code: &'static str,

    /// Human-readable error description
    pub description: String,

    /// Optional additional context
    pub context: Option<String>,
}

impl ArchiveError {
    /// Formats error for FFI consumption.
    ///
    /// Path and I/O-error text is redacted per the shared policy in
    /// [`super::redaction`] — see [`Self::redacted_path`] and
    /// [`sanitize_io_error_for_error`] — so this always applies the same
    /// policy `exarch-python` and `exarch-node` apply directly; there is no
    /// separate `sanitize_paths` toggle to keep in sync with theirs.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveError;
    /// use std::path::PathBuf;
    ///
    /// let error = ArchiveError::PathTraversal {
    ///     path: PathBuf::from("../../etc/passwd"),
    /// };
    ///
    /// let msg = error.to_ffi_message();
    /// assert_eq!(msg.code, "PATH_TRAVERSAL");
    /// // Archive-relative, attacker-authored path: never redacted (#462).
    /// assert!(msg.description.contains("../../etc/passwd"));
    /// ```
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn to_ffi_message(&self) -> FfiErrorMessage {
        let path = self
            .redacted_path()
            .unwrap_or_else(|| "<unknown>".to_string());
        match self {
            Self::PathTraversal { .. } => FfiErrorMessage {
                code: "PATH_TRAVERSAL",
                description: format!("path traversal detected: {path}"),
                context: None,
            },

            Self::SymlinkEscape { .. } => FfiErrorMessage {
                code: "SYMLINK_ESCAPE",
                description: format!("symlink target outside extraction directory: {path}"),
                context: None,
            },

            Self::HardlinkEscape { .. } => FfiErrorMessage {
                code: "HARDLINK_ESCAPE",
                description: format!("hardlink target outside extraction directory: {path}"),
                context: None,
            },

            Self::ZipBomb {
                compressed,
                uncompressed,
                ratio,
            } => FfiErrorMessage {
                code: "ZIP_BOMB",
                description: format!(
                    "potential zip bomb: compressed={compressed} bytes, uncompressed={uncompressed} bytes (ratio: {ratio:.2})"
                ),
                context: Some(format!("compression ratio: {ratio:.2}x")),
            },

            Self::QuotaExceeded { resource } => FfiErrorMessage {
                code: "QUOTA_EXCEEDED",
                description: resource.to_string(),
                context: None,
            },

            Self::SecurityViolation { reason } => FfiErrorMessage {
                code: "SECURITY_VIOLATION",
                description: format!("operation denied by security policy: {reason}"),
                context: None,
            },

            Self::InvalidArchive(reason) => FfiErrorMessage {
                code: "INVALID_ARCHIVE",
                description: format!("invalid archive: {reason}"),
                context: None,
            },

            Self::Io(io_err) => FfiErrorMessage {
                code: "IO_ERROR",
                description: sanitize_io_error_for_error(io_err),
                context: Some(io_err.kind().to_string()),
            },

            Self::InvalidPermissions { mode, .. } => FfiErrorMessage {
                code: "INVALID_PERMISSIONS",
                description: format!("invalid permissions for {path}: {mode:#o}"),
                context: None,
            },

            Self::SourceNotFound { .. } => FfiErrorMessage {
                code: "SOURCE_NOT_FOUND",
                description: format!("source path not found: {path}"),
                context: None,
            },

            Self::SourceNotAccessible { .. } => FfiErrorMessage {
                code: "SOURCE_NOT_ACCESSIBLE",
                description: format!("source path is not accessible: {path}"),
                context: None,
            },

            Self::OutputExists { .. } => FfiErrorMessage {
                code: "OUTPUT_EXISTS",
                description: format!("output file already exists: {path}"),
                context: None,
            },

            Self::InvalidCompressionLevel { level } => FfiErrorMessage {
                code: "INVALID_COMPRESSION_LEVEL",
                description: format!("invalid compression level {level}, must be 1-9"),
                context: None,
            },

            Self::UnknownFormat { .. } => FfiErrorMessage {
                code: "UNKNOWN_FORMAT",
                description: format!("cannot determine archive format from: {path}"),
                context: None,
            },

            Self::InvalidConfiguration { reason } => FfiErrorMessage {
                code: "INVALID_CONFIGURATION",
                description: format!("invalid configuration: {reason}"),
                context: None,
            },

            Self::PartialExtraction { source, .. } => source.to_ffi_message(),
        }
    }

    /// Returns the error code as a static string.
    ///
    /// Useful for matching on error types without full message formatting.
    #[must_use]
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::PathTraversal { .. } => "PATH_TRAVERSAL",
            Self::SymlinkEscape { .. } => "SYMLINK_ESCAPE",
            Self::HardlinkEscape { .. } => "HARDLINK_ESCAPE",
            Self::ZipBomb { .. } => "ZIP_BOMB",
            Self::QuotaExceeded { .. } => "QUOTA_EXCEEDED",
            Self::SecurityViolation { .. } => "SECURITY_VIOLATION",
            Self::InvalidArchive(_) => "INVALID_ARCHIVE",
            Self::Io(_) => "IO_ERROR",
            Self::InvalidPermissions { .. } => "INVALID_PERMISSIONS",
            Self::SourceNotFound { .. } => "SOURCE_NOT_FOUND",
            Self::SourceNotAccessible { .. } => "SOURCE_NOT_ACCESSIBLE",
            Self::OutputExists { .. } => "OUTPUT_EXISTS",
            Self::InvalidCompressionLevel { .. } => "INVALID_COMPRESSION_LEVEL",
            Self::UnknownFormat { .. } => "UNKNOWN_FORMAT",
            Self::InvalidConfiguration { .. } => "INVALID_CONFIGURATION",
            Self::PartialExtraction { source, .. } => source.error_code(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Regression test for #462: `PathTraversal` carries an
    /// archive-relative, attacker-authored path and must never be redacted,
    /// unlike a genuinely host-derived path variant (see the test below).
    #[test]
    fn test_attacker_path_never_redacted() {
        let error = ArchiveError::PathTraversal {
            path: PathBuf::from("../../etc/passwd"),
        };
        let msg = error.to_ffi_message();
        assert!(msg.description.contains("../../etc/passwd"));
    }

    /// Regression test for #453: `SourceNotFound` carries a host filesystem
    /// path; in release builds it must be redacted to filename-only. This
    /// only exercises the release-build branch — the debug-build behavior
    /// is covered directly in `super::redaction`.
    #[test]
    #[cfg(not(debug_assertions))]
    fn test_host_path_redacted_in_release() {
        let error = ArchiveError::SourceNotFound {
            path: PathBuf::from("/srv/secret/app/x.txt"),
        };
        let msg = error.to_ffi_message();
        assert!(msg.description.contains("x.txt"));
        assert!(!msg.description.contains("/srv/secret"));
    }

    /// Regression test for #453: `Io` messages must not leak a host path
    /// embedded in the free-form message text in release builds.
    #[test]
    #[cfg(not(debug_assertions))]
    fn test_io_error_redacted_in_release() {
        let error = ArchiveError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "directory is not writable: /srv/secret/app/private-output",
        ));
        let msg = error.to_ffi_message();
        assert!(!msg.description.contains("/srv/secret"));
    }

    #[test]
    fn test_error_codes_match() {
        let test_cases = vec![
            (
                ArchiveError::PathTraversal {
                    path: PathBuf::from("test"),
                },
                "PATH_TRAVERSAL",
            ),
            (
                ArchiveError::SymlinkEscape {
                    path: PathBuf::from("test"),
                },
                "SYMLINK_ESCAPE",
            ),
            (
                ArchiveError::ZipBomb {
                    compressed: 100,
                    uncompressed: 10000,
                    ratio: 100.0,
                },
                "ZIP_BOMB",
            ),
        ];

        for (error, expected_code) in test_cases {
            assert_eq!(error.error_code(), expected_code);
            assert_eq!(error.to_ffi_message().code, expected_code);
        }
    }

    #[test]
    fn test_all_error_variants_have_codes() {
        use super::super::types::QuotaResource;

        let errors = vec![
            ArchiveError::PathTraversal {
                path: PathBuf::from("test"),
            },
            ArchiveError::SymlinkEscape {
                path: PathBuf::from("test"),
            },
            ArchiveError::HardlinkEscape {
                path: PathBuf::from("test"),
            },
            ArchiveError::ZipBomb {
                compressed: 100,
                uncompressed: 10000,
                ratio: 100.0,
            },
            ArchiveError::QuotaExceeded {
                resource: QuotaResource::IntegerOverflow,
            },
            ArchiveError::SecurityViolation {
                reason: "test".into(),
            },
            ArchiveError::UnknownFormat {
                path: PathBuf::from("test.rar"),
            },
            ArchiveError::InvalidArchive("test".into()),
            ArchiveError::Io(std::io::Error::other("test")),
            ArchiveError::InvalidPermissions {
                path: PathBuf::from("test"),
                mode: 0o777,
            },
            ArchiveError::SourceNotFound {
                path: PathBuf::from("test"),
            },
            ArchiveError::SourceNotAccessible {
                path: PathBuf::from("test"),
            },
            ArchiveError::OutputExists {
                path: PathBuf::from("test"),
            },
            ArchiveError::InvalidCompressionLevel { level: 10 },
            ArchiveError::UnknownFormat {
                path: PathBuf::from("test"),
            },
            ArchiveError::InvalidConfiguration {
                reason: "test".into(),
            },
        ];

        for error in errors {
            let code = error.error_code();
            assert!(!code.is_empty(), "Error code should not be empty");

            let msg = error.to_ffi_message();
            assert_eq!(msg.code, code);
            assert!(!msg.description.is_empty());
        }
    }
}
