//! FFI error message formatting.
//!
//! Provides consistent error messages across Python and Node.js bindings
//! while allowing platform-specific customization.

use super::redaction::sanitize_io_error_for_error;
use super::types::ArchiveError;
use super::types::PolicySetting;

/// Error message for FFI consumption.
///
/// Contains structured error information that can be converted to
/// platform-specific error types (Python exceptions, Node.js Error objects).
///
/// `#[non_exhaustive]` and output-only: bindings read it, only
/// [`ArchiveError::to_ffi_message`] builds it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FfiErrorMessage {
    /// Error code (e.g., `PATH_TRAVERSAL`, `ZIP_BOMB`)
    pub code: &'static str,

    /// Human-readable error description
    pub description: String,

    /// Optional additional context
    pub context: Option<String>,

    /// The `SecurityConfig` setting whose current value refused the entry;
    /// see [`ArchiveError::relaxable_by`].
    pub relaxable_by: Option<PolicySetting>,
}

impl FfiErrorMessage {
    /// A message with no extra context and no relaxing setting.
    const fn plain(code: &'static str, description: String) -> Self {
        Self {
            code,
            description,
            context: None,
            relaxable_by: None,
        }
    }
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
    pub fn to_ffi_message(&self) -> FfiErrorMessage {
        let path = self
            .redacted_path()
            .unwrap_or_else(|| "<unknown>".to_string());
        match self {
            Self::PathTraversal { .. } => {
                FfiErrorMessage::plain("PATH_TRAVERSAL", format!("path traversal detected: {path}"))
            }

            Self::SymlinkEscape { .. } => FfiErrorMessage::plain(
                "SYMLINK_ESCAPE",
                format!("symlink target outside extraction directory: {path}"),
            ),

            Self::HardlinkEscape { .. } => FfiErrorMessage::plain(
                "HARDLINK_ESCAPE",
                format!("hardlink target outside extraction directory: {path}"),
            ),

            Self::ZipBomb(details) => FfiErrorMessage {
                code: "ZIP_BOMB",
                description: self.to_string(),
                context: Some(format!(
                    "{} compression ratio: {}",
                    details.scope(),
                    details.ratio()
                )),
                relaxable_by: None,
            },

            Self::ZipInconsistency(_) => {
                FfiErrorMessage::plain("ZIP_INCONSISTENCY", self.to_string())
            }

            Self::QuotaExceeded { resource } => {
                FfiErrorMessage::plain("QUOTA_EXCEEDED", resource.to_string())
            }

            Self::SecurityViolation {
                reason,
                relaxable_by,
                ..
            } => FfiErrorMessage {
                code: "SECURITY_VIOLATION",
                description: format!("operation denied by security policy: {reason}"),
                context: None,
                relaxable_by: *relaxable_by,
            },

            Self::InvalidArchive(reason) => {
                FfiErrorMessage::plain("INVALID_ARCHIVE", format!("invalid archive: {reason}"))
            }

            Self::Io(io_err) => FfiErrorMessage {
                code: "IO_ERROR",
                description: sanitize_io_error_for_error(io_err),
                context: Some(io_err.kind().to_string()),
                relaxable_by: None,
            },

            Self::InvalidPermissions { mode, .. } => FfiErrorMessage::plain(
                "INVALID_PERMISSIONS",
                format!("invalid permissions for {path}: {mode:#o}"),
            ),

            Self::SourceNotFound { .. } => {
                FfiErrorMessage::plain("SOURCE_NOT_FOUND", format!("source path not found: {path}"))
            }

            Self::SourceNotAccessible { .. } => FfiErrorMessage::plain(
                "SOURCE_NOT_ACCESSIBLE",
                format!("source path is not accessible: {path}"),
            ),

            Self::OutputExists { .. } => FfiErrorMessage::plain(
                "OUTPUT_EXISTS",
                format!("output file already exists: {path}"),
            ),

            Self::InvalidCompressionLevel { level } => FfiErrorMessage::plain(
                "INVALID_COMPRESSION_LEVEL",
                format!("invalid compression level {level}, must be 1-9"),
            ),

            Self::UnknownFormat { .. } => FfiErrorMessage::plain(
                "UNKNOWN_FORMAT",
                format!("cannot determine archive format from: {path}"),
            ),

            Self::InvalidConfiguration { reason } => FfiErrorMessage::plain(
                "INVALID_CONFIGURATION",
                format!("invalid configuration: {reason}"),
            ),

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
            Self::ZipBomb(_) => "ZIP_BOMB",
            Self::ZipInconsistency(_) => "ZIP_INCONSISTENCY",
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
    use super::super::types::ZipBombDetails;
    use super::super::types::ZipBombScope;
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
                ArchiveError::ZipBomb(ZipBombDetails::new(ZipBombScope::Entry, 100, 10000)),
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
            ArchiveError::ZipBomb(ZipBombDetails::new(ZipBombScope::Entry, 100, 10000)),
            ArchiveError::QuotaExceeded {
                resource: QuotaResource::IntegerOverflow,
            },
            ArchiveError::violation("test".into()),
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
