//! Error conversion for Node.js bindings.

use exarch_core::ExtractionError as CoreError;
use exarch_core::QuotaResource as CoreQuotaResource;
use napi::bindgen_prelude::*;
use std::path::Path;

/// Sanitizes path information for error messages.
///
/// In debug builds, returns the full path for detailed diagnostics.
/// In release builds, returns only the filename to avoid leaking internal
/// directory structures to potential attackers.
#[cfg(debug_assertions)]
fn sanitize_path_for_error(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(not(debug_assertions))]
fn sanitize_path_for_error(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("<unknown>")
        .to_string()
}

/// Converts Rust extraction errors to JavaScript exceptions.
///
/// This preserves error context and maps each Rust error variant to a
/// JavaScript error with a descriptive message prefixed with an error code.
///
/// Error codes enable JavaScript callers to distinguish error types:
/// - `PATH_TRAVERSAL`: Path traversal attempt detected
/// - `SYMLINK_ESCAPE`: Symlink points outside extraction directory
/// - `HARDLINK_ESCAPE`: Hardlink target outside extraction directory
/// - `ZIP_BOMB`: Potential zip bomb detected
/// - `INVALID_PERMISSIONS`: File permissions are invalid or unsafe
/// - `QUOTA_EXCEEDED`: Resource quota exceeded
/// - `SECURITY_VIOLATION`: Security policy violation
/// - `UNSUPPORTED_FORMAT`: Archive format not supported
/// - `INVALID_ARCHIVE`: Archive is corrupted
/// - `IO_ERROR`: I/O operation failed
#[allow(clippy::too_many_lines)]
pub fn convert_error(err: CoreError) -> Error {
    use std::fmt::Write;
    match err {
        CoreError::PathTraversal { path } => {
            let path_str = sanitize_path_for_error(&path);
            let mut msg = String::with_capacity(50 + path_str.len());
            msg.push_str("PATH_TRAVERSAL: path traversal detected: ");
            msg.push_str(&path_str);
            Error::new(Status::GenericFailure, msg)
        }
        CoreError::SymlinkEscape { path } => {
            let path_str = sanitize_path_for_error(&path);
            let mut msg = String::with_capacity(70 + path_str.len());
            msg.push_str("SYMLINK_ESCAPE: symlink target outside extraction directory: ");
            msg.push_str(&path_str);
            Error::new(Status::GenericFailure, msg)
        }
        CoreError::HardlinkEscape { path } => {
            let path_str = sanitize_path_for_error(&path);
            let mut msg = String::with_capacity(70 + path_str.len());
            msg.push_str("HARDLINK_ESCAPE: hardlink target outside extraction directory: ");
            msg.push_str(&path_str);
            Error::new(Status::GenericFailure, msg)
        }
        CoreError::ZipBomb {
            compressed,
            uncompressed,
            ratio,
        } => {
            let mut msg = String::with_capacity(150);
            // Writing to a String never fails
            let _ = write!(
                &mut msg,
                "ZIP_BOMB: potential zip bomb: compressed={compressed} bytes, uncompressed={uncompressed} bytes (ratio: {ratio:.2})"
            );
            Error::new(Status::GenericFailure, msg)
        }
        CoreError::InvalidPermissions { path, mode } => {
            let path_str = sanitize_path_for_error(&path);
            let mut msg = String::with_capacity(60 + path_str.len());
            // Writing to a String never fails
            let _ = write!(
                &mut msg,
                "INVALID_PERMISSIONS: invalid permissions for {path_str}: {mode:#o}"
            );
            Error::new(Status::GenericFailure, msg)
        }
        CoreError::QuotaExceeded { resource } => {
            let mut msg = String::with_capacity(100);
            // Writing to a String never fails
            match resource {
                CoreQuotaResource::FileCount { current, max } => {
                    let _ = write!(
                        &mut msg,
                        "QUOTA_EXCEEDED: quota exceeded: file count ({current} > {max})"
                    );
                }
                CoreQuotaResource::TotalSize { current, max } => {
                    let _ = write!(
                        &mut msg,
                        "QUOTA_EXCEEDED: quota exceeded: total size ({current} > {max})"
                    );
                }
                CoreQuotaResource::FileSize { size, max } => {
                    let _ = write!(
                        &mut msg,
                        "QUOTA_EXCEEDED: quota exceeded: file size ({size} > {max})"
                    );
                }
                CoreQuotaResource::IntegerOverflow => {
                    msg.push_str(
                        "QUOTA_EXCEEDED: quota exceeded: integer overflow in quota tracking",
                    );
                }
            }
            Error::new(Status::GenericFailure, msg)
        }
        CoreError::SecurityViolation { reason } => {
            let mut msg = String::with_capacity(60 + reason.len());
            msg.push_str("SECURITY_VIOLATION: operation denied by security policy: ");
            msg.push_str(&reason);
            Error::new(Status::GenericFailure, msg)
        }
        CoreError::UnsupportedFormat => Error::new(
            Status::GenericFailure,
            "UNSUPPORTED_FORMAT: unsupported archive format",
        ),
        CoreError::InvalidArchive(archive_msg) => {
            let mut msg = String::with_capacity(30 + archive_msg.len());
            msg.push_str("INVALID_ARCHIVE: invalid archive: ");
            msg.push_str(&archive_msg);
            Error::new(Status::GenericFailure, msg)
        }
        CoreError::Io(e) => {
            let e_str = e.to_string();
            let mut msg = String::with_capacity(10 + e_str.len());
            msg.push_str("IO_ERROR: ");
            msg.push_str(&e_str);
            Error::new(Status::GenericFailure, msg)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_path_traversal_conversion() {
        let err = CoreError::PathTraversal {
            path: PathBuf::from("../etc/passwd"),
        };
        let napi_err = convert_error(err);
        let err_str = napi_err.to_string();
        assert!(err_str.contains("PATH_TRAVERSAL"));
        assert!(err_str.contains("path traversal"));
        assert!(err_str.contains("../etc/passwd"));
    }

    #[test]
    fn test_symlink_escape_conversion() {
        let err = CoreError::SymlinkEscape {
            path: PathBuf::from("/etc/passwd"),
        };
        let napi_err = convert_error(err);
        let err_str = napi_err.to_string();
        assert!(err_str.contains("SYMLINK_ESCAPE"));
        assert!(err_str.contains("symlink target outside"));
        assert!(err_str.contains("/etc/passwd"));
    }

    #[test]
    fn test_hardlink_escape_conversion() {
        let err = CoreError::HardlinkEscape {
            path: PathBuf::from("/etc/shadow"),
        };
        let napi_err = convert_error(err);
        let err_str = napi_err.to_string();
        assert!(err_str.contains("HARDLINK_ESCAPE"));
        assert!(err_str.contains("hardlink target outside"));
        assert!(err_str.contains("/etc/shadow"));
    }

    #[test]
    fn test_zip_bomb_conversion() {
        let err = CoreError::ZipBomb {
            compressed: 1000,
            uncompressed: 1_000_000,
            ratio: 1000.0,
        };
        let napi_err = convert_error(err);
        let err_str = napi_err.to_string();
        assert!(err_str.contains("ZIP_BOMB"));
        assert!(err_str.contains("zip bomb"));
        assert!(err_str.contains("1000"));
    }

    #[test]
    fn test_invalid_permissions_conversion() {
        let err = CoreError::InvalidPermissions {
            path: PathBuf::from("malicious.sh"),
            mode: 0o777,
        };
        let napi_err = convert_error(err);
        let err_str = napi_err.to_string();
        assert!(err_str.contains("INVALID_PERMISSIONS"));
        assert!(err_str.contains("invalid permissions"));
        assert!(err_str.contains("777"));
        assert!(err_str.contains("malicious.sh"));
    }

    #[test]
    fn test_quota_exceeded_file_count_conversion() {
        let err = CoreError::QuotaExceeded {
            resource: CoreQuotaResource::FileCount {
                current: 11,
                max: 10,
            },
        };
        let napi_err = convert_error(err);
        let err_str = napi_err.to_string();
        assert!(err_str.contains("QUOTA_EXCEEDED"));
        assert!(err_str.contains("file count"));
    }

    #[test]
    fn test_quota_exceeded_total_size_conversion() {
        let err = CoreError::QuotaExceeded {
            resource: CoreQuotaResource::TotalSize {
                current: 1_000_000,
                max: 500_000,
            },
        };
        let napi_err = convert_error(err);
        let err_str = napi_err.to_string();
        assert!(err_str.contains("QUOTA_EXCEEDED"));
        assert!(err_str.contains("total size"));
    }

    #[test]
    fn test_quota_exceeded_file_size_conversion() {
        let err = CoreError::QuotaExceeded {
            resource: CoreQuotaResource::FileSize {
                size: 100_000_000,
                max: 50_000_000,
            },
        };
        let napi_err = convert_error(err);
        let err_str = napi_err.to_string();
        assert!(err_str.contains("QUOTA_EXCEEDED"));
        assert!(err_str.contains("file size"));
    }

    #[test]
    fn test_quota_exceeded_integer_overflow_conversion() {
        let err = CoreError::QuotaExceeded {
            resource: CoreQuotaResource::IntegerOverflow,
        };
        let napi_err = convert_error(err);
        let err_str = napi_err.to_string();
        assert!(err_str.contains("QUOTA_EXCEEDED"));
        assert!(err_str.contains("integer overflow"));
    }

    #[test]
    fn test_security_violation_conversion() {
        let err = CoreError::SecurityViolation {
            reason: "test violation".to_string(),
        };
        let napi_err = convert_error(err);
        let err_str = napi_err.to_string();
        assert!(err_str.contains("SECURITY_VIOLATION"));
        assert!(err_str.contains("security policy"));
        assert!(err_str.contains("test violation"));
    }

    #[test]
    fn test_unsupported_format_conversion() {
        let err = CoreError::UnsupportedFormat;
        let napi_err = convert_error(err);
        let err_str = napi_err.to_string();
        assert!(err_str.contains("UNSUPPORTED_FORMAT"));
        assert!(err_str.contains("unsupported archive format"));
    }

    #[test]
    fn test_invalid_archive_conversion() {
        let err = CoreError::InvalidArchive("corrupted header".to_string());
        let napi_err = convert_error(err);
        let err_str = napi_err.to_string();
        assert!(err_str.contains("INVALID_ARCHIVE"));
        assert!(err_str.contains("invalid archive"));
        assert!(err_str.contains("corrupted header"));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = CoreError::Io(io_err);
        let napi_err = convert_error(err);
        let err_str = napi_err.to_string();
        assert!(err_str.contains("IO_ERROR"));
        assert!(err_str.contains("file not found"));
    }
}
