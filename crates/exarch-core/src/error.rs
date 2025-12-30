//! Error types for archive extraction operations.

use std::path::PathBuf;
use thiserror::Error;

/// Result type alias using `ExtractionError`.
pub type Result<T> = std::result::Result<T, ExtractionError>;

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
    #[error("quota exceeded: {resource}")]
    QuotaExceeded {
        /// Description of the exceeded resource.
        resource: String,
    },

    /// Operation not permitted by security policy.
    #[error("operation denied by security policy: {reason}")]
    SecurityViolation {
        /// Reason for the violation.
        reason: String,
    },
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
}
