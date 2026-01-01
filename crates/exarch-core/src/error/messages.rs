//! FFI error message formatting.
//!
//! Provides consistent error messages across Python and Node.js bindings
//! while allowing platform-specific customization.

use std::path::Path;

use super::types::ExtractionError;

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

impl ExtractionError {
    /// Formats error for FFI consumption.
    ///
    /// # Arguments
    ///
    /// * `sanitize_paths` - If true, only show filename (not full path) for
    ///   security. Should be `false` in development, `true` in production
    ///   Node.js builds.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ExtractionError;
    /// use std::path::PathBuf;
    ///
    /// let error = ExtractionError::PathTraversal {
    ///     path: PathBuf::from("/etc/passwd"),
    /// };
    ///
    /// let msg = error.to_ffi_message(true);
    /// assert_eq!(msg.code, "PATH_TRAVERSAL");
    /// assert!(msg.description.contains("passwd")); // Only filename shown
    /// ```
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn to_ffi_message(&self, sanitize_paths: bool) -> FfiErrorMessage {
        match self {
            Self::PathTraversal { path } => FfiErrorMessage {
                code: "PATH_TRAVERSAL",
                description: format!(
                    "path traversal detected: {}",
                    format_path(path, sanitize_paths)
                ),
                context: None,
            },

            Self::SymlinkEscape { path } => FfiErrorMessage {
                code: "SYMLINK_ESCAPE",
                description: format!(
                    "symlink target outside extraction directory: {}",
                    format_path(path, sanitize_paths)
                ),
                context: None,
            },

            Self::HardlinkEscape { path } => FfiErrorMessage {
                code: "HARDLINK_ESCAPE",
                description: format!(
                    "hardlink target outside extraction directory: {}",
                    format_path(path, sanitize_paths)
                ),
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

            Self::UnsupportedFormat => FfiErrorMessage {
                code: "UNSUPPORTED_FORMAT",
                description: "unsupported archive format".into(),
                context: None,
            },

            Self::InvalidArchive(reason) => FfiErrorMessage {
                code: "INVALID_ARCHIVE",
                description: format!("invalid archive: {reason}"),
                context: None,
            },

            Self::Io(io_err) => FfiErrorMessage {
                code: "IO_ERROR",
                description: io_err.to_string(),
                context: Some(io_err.kind().to_string()),
            },

            Self::InvalidPermissions { path, mode } => FfiErrorMessage {
                code: "INVALID_PERMISSIONS",
                description: format!(
                    "invalid permissions for {}: {mode:#o}",
                    format_path(path, sanitize_paths)
                ),
                context: None,
            },

            Self::SourceNotFound { path } => FfiErrorMessage {
                code: "SOURCE_NOT_FOUND",
                description: format!(
                    "source path not found: {}",
                    format_path(path, sanitize_paths)
                ),
                context: None,
            },

            Self::SourceNotAccessible { path } => FfiErrorMessage {
                code: "SOURCE_NOT_ACCESSIBLE",
                description: format!(
                    "source path is not accessible: {}",
                    format_path(path, sanitize_paths)
                ),
                context: None,
            },

            Self::OutputExists { path } => FfiErrorMessage {
                code: "OUTPUT_EXISTS",
                description: format!(
                    "output file already exists: {}",
                    format_path(path, sanitize_paths)
                ),
                context: None,
            },

            Self::InvalidCompressionLevel { level } => FfiErrorMessage {
                code: "INVALID_COMPRESSION_LEVEL",
                description: format!("invalid compression level {level}, must be 1-9"),
                context: None,
            },

            Self::UnknownFormat { path } => FfiErrorMessage {
                code: "UNKNOWN_FORMAT",
                description: format!(
                    "cannot determine archive format from: {}",
                    format_path(path, sanitize_paths)
                ),
                context: None,
            },

            Self::InvalidConfiguration { reason } => FfiErrorMessage {
                code: "INVALID_CONFIGURATION",
                description: format!("invalid configuration: {reason}"),
                context: None,
            },
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
            Self::UnsupportedFormat => "UNSUPPORTED_FORMAT",
            Self::InvalidArchive(_) => "INVALID_ARCHIVE",
            Self::Io(_) => "IO_ERROR",
            Self::InvalidPermissions { .. } => "INVALID_PERMISSIONS",
            Self::SourceNotFound { .. } => "SOURCE_NOT_FOUND",
            Self::SourceNotAccessible { .. } => "SOURCE_NOT_ACCESSIBLE",
            Self::OutputExists { .. } => "OUTPUT_EXISTS",
            Self::InvalidCompressionLevel { .. } => "INVALID_COMPRESSION_LEVEL",
            Self::UnknownFormat { .. } => "UNKNOWN_FORMAT",
            Self::InvalidConfiguration { .. } => "INVALID_CONFIGURATION",
        }
    }
}

/// Formats a path for error messages.
///
/// If `sanitize` is true, only returns the filename (for production).
/// If `sanitize` is false, returns the full path (for development).
fn format_path(path: &Path, sanitize: bool) -> String {
    if sanitize {
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<unknown>")
            .to_string()
    } else {
        path.display().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_path_sanitization() {
        let error = ExtractionError::PathTraversal {
            path: PathBuf::from("/etc/passwd"),
        };

        // Development: full path
        let msg = error.to_ffi_message(false);
        assert!(msg.description.contains("/etc/passwd"));

        // Production: filename only
        let msg = error.to_ffi_message(true);
        assert!(msg.description.contains("passwd"));
        assert!(!msg.description.contains("/etc/"));
    }

    #[test]
    fn test_error_codes_match() {
        let test_cases = vec![
            (
                ExtractionError::PathTraversal {
                    path: PathBuf::from("test"),
                },
                "PATH_TRAVERSAL",
            ),
            (
                ExtractionError::SymlinkEscape {
                    path: PathBuf::from("test"),
                },
                "SYMLINK_ESCAPE",
            ),
            (
                ExtractionError::ZipBomb {
                    compressed: 100,
                    uncompressed: 10000,
                    ratio: 100.0,
                },
                "ZIP_BOMB",
            ),
        ];

        for (error, expected_code) in test_cases {
            assert_eq!(error.error_code(), expected_code);
            assert_eq!(error.to_ffi_message(false).code, expected_code);
        }
    }

    #[test]
    fn test_all_error_variants_have_codes() {
        use super::super::types::QuotaResource;

        let errors = vec![
            ExtractionError::PathTraversal {
                path: PathBuf::from("test"),
            },
            ExtractionError::SymlinkEscape {
                path: PathBuf::from("test"),
            },
            ExtractionError::HardlinkEscape {
                path: PathBuf::from("test"),
            },
            ExtractionError::ZipBomb {
                compressed: 100,
                uncompressed: 10000,
                ratio: 100.0,
            },
            ExtractionError::QuotaExceeded {
                resource: QuotaResource::IntegerOverflow,
            },
            ExtractionError::SecurityViolation {
                reason: "test".into(),
            },
            ExtractionError::UnsupportedFormat,
            ExtractionError::InvalidArchive("test".into()),
            ExtractionError::Io(std::io::Error::other("test")),
            ExtractionError::InvalidPermissions {
                path: PathBuf::from("test"),
                mode: 0o777,
            },
            ExtractionError::SourceNotFound {
                path: PathBuf::from("test"),
            },
            ExtractionError::SourceNotAccessible {
                path: PathBuf::from("test"),
            },
            ExtractionError::OutputExists {
                path: PathBuf::from("test"),
            },
            ExtractionError::InvalidCompressionLevel { level: 10 },
            ExtractionError::UnknownFormat {
                path: PathBuf::from("test"),
            },
            ExtractionError::InvalidConfiguration {
                reason: "test".into(),
            },
        ];

        for error in errors {
            let code = error.error_code();
            assert!(!code.is_empty(), "Error code should not be empty");

            let msg = error.to_ffi_message(false);
            assert_eq!(msg.code, code);
            assert!(!msg.description.is_empty());
        }
    }
}
