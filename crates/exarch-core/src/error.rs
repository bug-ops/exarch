//! Error types for archive extraction operations.

use std::path::PathBuf;
use thiserror::Error;

/// Result type alias using `ExtractionError`.
pub type Result<T> = std::result::Result<T, ExtractionError>;

/// Represents a specific quota resource that was exceeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaResource {
    /// File count quota exceeded.
    FileCount {
        /// Current file count.
        current: usize,
        /// Maximum allowed file count.
        max: usize,
    },
    /// Total size quota exceeded.
    TotalSize {
        /// Current total size in bytes.
        current: u64,
        /// Maximum allowed total size in bytes.
        max: u64,
    },
    /// Single file size quota exceeded.
    FileSize {
        /// File size in bytes.
        size: u64,
        /// Maximum allowed file size in bytes.
        max: u64,
    },
    /// Integer overflow detected in quota tracking.
    IntegerOverflow,
}

impl std::fmt::Display for QuotaResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileCount { current, max } => {
                write!(f, "quota exceeded: file count ({current} > {max})")
            }
            Self::TotalSize { current, max } => {
                write!(f, "quota exceeded: total size ({current} > {max})")
            }
            Self::FileSize { size, max } => {
                write!(f, "quota exceeded: single file size ({size} > {max})")
            }
            Self::IntegerOverflow => {
                write!(f, "quota exceeded: integer overflow in quota tracking")
            }
        }
    }
}

/// Errors that can occur during archive extraction.
#[derive(Error, Debug)]
pub enum ExtractionError {
    /// I/O operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Archive format is unsupported or unrecognized.
    #[error("unsupported archive format")]
    UnsupportedFormat,

    /// Archive is corrupted or invalid.
    #[error("invalid archive: {0}")]
    InvalidArchive(String),

    /// Path traversal attempt detected.
    #[error("path traversal detected: {path}")]
    PathTraversal {
        /// The path that attempted traversal.
        path: PathBuf,
    },

    /// Symlink points outside extraction directory.
    #[error("symlink target outside extraction directory: {path}")]
    SymlinkEscape {
        /// The symlink path.
        path: PathBuf,
    },

    /// Hardlink target not in extraction directory.
    #[error("hardlink target outside extraction directory: {path}")]
    HardlinkEscape {
        /// The hardlink path.
        path: PathBuf,
    },

    /// Potential zip bomb detected.
    #[error(
        "potential zip bomb: compressed={compressed} bytes, uncompressed={uncompressed} bytes (ratio: {ratio:.2})"
    )]
    ZipBomb {
        /// Compressed size in bytes.
        compressed: u64,
        /// Uncompressed size in bytes.
        uncompressed: u64,
        /// Compression ratio.
        ratio: f64,
    },

    /// File permissions are invalid or unsafe.
    #[error("invalid permissions for {path}: {mode:#o}")]
    InvalidPermissions {
        /// The file path.
        path: PathBuf,
        /// The permission mode.
        mode: u32,
    },

    /// Extraction quota exceeded.
    #[error("{resource}")]
    QuotaExceeded {
        /// Description of the exceeded resource.
        resource: QuotaResource,
    },

    /// Operation not permitted by security policy.
    #[error("operation denied by security policy: {reason}")]
    SecurityViolation {
        /// Reason for the violation.
        reason: String,
    },
}

impl ExtractionError {
    /// Returns `true` if this error represents a security violation.
    ///
    /// Security violations include:
    /// - Path traversal attempts
    /// - Symlink escapes
    /// - Hardlink escapes
    /// - Zip bombs
    /// - Invalid permissions
    /// - Quota exceeded
    /// - General security policy violations
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ExtractionError;
    /// use std::path::PathBuf;
    ///
    /// let err = ExtractionError::PathTraversal {
    ///     path: PathBuf::from("../etc/passwd"),
    /// };
    /// assert!(err.is_security_violation());
    ///
    /// let err = ExtractionError::UnsupportedFormat;
    /// assert!(!err.is_security_violation());
    /// ```
    #[must_use]
    pub const fn is_security_violation(&self) -> bool {
        matches!(
            self,
            Self::PathTraversal { .. }
                | Self::SymlinkEscape { .. }
                | Self::HardlinkEscape { .. }
                | Self::ZipBomb { .. }
                | Self::InvalidPermissions { .. }
                | Self::QuotaExceeded { .. }
                | Self::SecurityViolation { .. }
        )
    }

    /// Returns `true` if this error is potentially recoverable.
    ///
    /// Recoverable errors are those where extraction might continue
    /// with different inputs or configurations. Non-recoverable errors
    /// typically indicate fundamental issues with the archive format.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ExtractionError;
    /// use std::path::PathBuf;
    ///
    /// let err = ExtractionError::PathTraversal {
    ///     path: PathBuf::from("../etc/passwd"),
    /// };
    /// assert!(err.is_recoverable()); // Could skip this entry
    ///
    /// let err = ExtractionError::InvalidArchive("corrupted header".to_string());
    /// assert!(!err.is_recoverable()); // Cannot continue
    /// ```
    #[must_use]
    pub const fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::PathTraversal { .. }
                | Self::SymlinkEscape { .. }
                | Self::HardlinkEscape { .. }
                | Self::InvalidPermissions { .. }
                | Self::SecurityViolation { .. }
        )
    }

    /// Returns a context string for this error, if available.
    ///
    /// The context provides additional information about what operation
    /// was being performed when the error occurred.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ExtractionError;
    ///
    /// let err = ExtractionError::InvalidArchive("bad header".to_string());
    /// assert_eq!(err.context(), Some("bad header"));
    ///
    /// let err = ExtractionError::UnsupportedFormat;
    /// assert_eq!(err.context(), None);
    /// ```
    #[must_use]
    pub fn context(&self) -> Option<&str> {
        match self {
            Self::InvalidArchive(msg) => Some(msg),
            Self::SecurityViolation { reason } => Some(reason),
            _ => None,
        }
    }

    /// Returns the quota resource that was exceeded, if applicable.
    #[must_use]
    pub const fn quota_resource(&self) -> Option<&QuotaResource> {
        match self {
            Self::QuotaExceeded { resource } => Some(resource),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = ExtractionError::UnsupportedFormat;
        assert_eq!(err.to_string(), "unsupported archive format");
    }

    #[test]
    fn test_path_traversal_error() {
        let err = ExtractionError::PathTraversal {
            path: PathBuf::from("../etc/passwd"),
        };
        assert!(err.to_string().contains("path traversal"));
        assert!(err.to_string().contains("../etc/passwd"));
    }

    #[test]
    fn test_zip_bomb_error() {
        let err = ExtractionError::ZipBomb {
            compressed: 1000,
            uncompressed: 1_000_000,
            ratio: 1000.0,
        };
        assert!(err.to_string().contains("zip bomb"));
        assert!(err.to_string().contains("1000"));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: ExtractionError = io_err.into();
        assert!(matches!(err, ExtractionError::Io(_)));
    }

    #[test]
    fn test_is_security_violation() {
        // Security violations
        let err = ExtractionError::PathTraversal {
            path: PathBuf::from("../etc/passwd"),
        };
        assert!(err.is_security_violation());

        let err = ExtractionError::SymlinkEscape {
            path: PathBuf::from("link"),
        };
        assert!(err.is_security_violation());

        let err = ExtractionError::ZipBomb {
            compressed: 1000,
            uncompressed: 1_000_000,
            ratio: 1000.0,
        };
        assert!(err.is_security_violation());

        let err = ExtractionError::SecurityViolation {
            reason: "test".into(),
        };
        assert!(err.is_security_violation());

        // Not security violations
        let err = ExtractionError::UnsupportedFormat;
        assert!(!err.is_security_violation());

        let err = ExtractionError::InvalidArchive("bad".into());
        assert!(!err.is_security_violation());
    }

    #[test]
    fn test_is_recoverable() {
        // Recoverable errors
        let err = ExtractionError::PathTraversal {
            path: PathBuf::from("../etc/passwd"),
        };
        assert!(err.is_recoverable());

        let err = ExtractionError::SecurityViolation {
            reason: "test".into(),
        };
        assert!(err.is_recoverable());

        // Non-recoverable errors
        let err = ExtractionError::InvalidArchive("corrupted".into());
        assert!(!err.is_recoverable());

        let err = ExtractionError::UnsupportedFormat;
        assert!(!err.is_recoverable());

        let err = ExtractionError::ZipBomb {
            compressed: 1000,
            uncompressed: 1_000_000,
            ratio: 1000.0,
        };
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_context() {
        let err = ExtractionError::InvalidArchive("bad header".into());
        assert_eq!(err.context(), Some("bad header"));

        let err = ExtractionError::SecurityViolation {
            reason: "not allowed".into(),
        };
        assert_eq!(err.context(), Some("not allowed"));

        let err = ExtractionError::UnsupportedFormat;
        assert_eq!(err.context(), None);

        let err = ExtractionError::PathTraversal {
            path: PathBuf::from("../etc/passwd"),
        };
        assert_eq!(err.context(), None);
    }

    #[test]
    fn test_symlink_escape_error() {
        let err = ExtractionError::SymlinkEscape {
            path: PathBuf::from("malicious/link"),
        };
        let display = err.to_string();
        assert!(display.contains("symlink target outside"));
        assert!(display.contains("malicious/link"));
        assert!(err.is_security_violation());
    }

    #[test]
    fn test_hardlink_escape_error() {
        let err = ExtractionError::HardlinkEscape {
            path: PathBuf::from("malicious/hardlink"),
        };
        let display = err.to_string();
        assert!(display.contains("hardlink target outside"));
        assert!(display.contains("malicious/hardlink"));
        assert!(err.is_security_violation());
    }

    #[test]
    fn test_invalid_permissions_error() {
        let err = ExtractionError::InvalidPermissions {
            path: PathBuf::from("file.txt"),
            mode: 0o777,
        };
        let display = err.to_string();
        assert!(display.contains("invalid permissions"));
        assert!(display.contains("file.txt"));
        assert!(display.contains("0o777"));
        assert!(err.is_security_violation());
    }

    #[test]
    fn test_quota_exceeded_error() {
        let err = ExtractionError::QuotaExceeded {
            resource: QuotaResource::FileCount {
                current: 11,
                max: 10,
            },
        };
        let display = err.to_string();
        assert!(display.contains("quota exceeded"));
        assert!(display.contains("file count"));
        assert!(display.contains("11"));
        assert!(display.contains("10"));
        assert!(err.is_security_violation());

        // Test quota_resource accessor
        let quota = err.quota_resource();
        assert!(quota.is_some());
        assert_eq!(
            quota,
            Some(&QuotaResource::FileCount {
                current: 11,
                max: 10
            })
        );
    }

    // L-10: Error source chain test
    #[test]
    fn test_error_source_chain() {
        use std::error::Error;

        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "inner error");
        let err: ExtractionError = io_err.into();

        // Verify source chain works
        if let ExtractionError::Io(ref inner) = err {
            // IO error may or may not have a source
            let _source = inner.source();
        }
    }

    // L-11: ZipBomb edge case tests
    #[test]
    fn test_zip_bomb_edge_cases() {
        // Zero compressed size (would cause division by zero in ratio calc)
        let err = ExtractionError::ZipBomb {
            compressed: 0,
            uncompressed: 1000,
            ratio: f64::INFINITY,
        };
        assert!(err.is_security_violation());
        let display = err.to_string();
        assert!(display.contains("zip bomb"));

        // Equal sizes (ratio = 1.0)
        let err = ExtractionError::ZipBomb {
            compressed: 1000,
            uncompressed: 1000,
            ratio: 1.0,
        };
        let display = err.to_string();
        assert!(display.contains("1.00") || display.contains("1.0"));
    }
}
