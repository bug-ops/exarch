//! Python exception types for archive extraction errors.

use exarch_core::ExtractionError as CoreError;
use exarch_core::QuotaResource as CoreQuotaResource;
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

// Base exception for all extraction errors
create_exception!(exarch, ExtractionError, PyException);

// Specific exception types
create_exception!(exarch, PathTraversalError, ExtractionError);
create_exception!(exarch, SymlinkEscapeError, ExtractionError);
create_exception!(exarch, HardlinkEscapeError, ExtractionError);
create_exception!(exarch, ZipBombError, ExtractionError);
create_exception!(exarch, InvalidPermissionsError, ExtractionError);
create_exception!(exarch, QuotaExceededError, ExtractionError);
create_exception!(exarch, SecurityViolationError, ExtractionError);
create_exception!(exarch, UnsupportedFormatError, ExtractionError);
create_exception!(exarch, InvalidArchiveError, ExtractionError);

/// Converts Rust extraction errors to Python exceptions.
///
/// This preserves error context and maps each Rust error variant to the
/// appropriate Python exception type.
///
/// This function is a workaround for Rust's orphan rules, which prevent
/// implementing `From<CoreError> for PyErr` directly.
pub fn convert_error(err: CoreError) -> PyErr {
    match err {
        CoreError::PathTraversal { path } => {
            PathTraversalError::new_err(format!("path traversal detected: {}", path.display()))
        }
        CoreError::SymlinkEscape { path } => SymlinkEscapeError::new_err(format!(
            "symlink target outside extraction directory: {}",
            path.display()
        )),
        CoreError::HardlinkEscape { path } => HardlinkEscapeError::new_err(format!(
            "hardlink target outside extraction directory: {}",
            path.display()
        )),
        CoreError::ZipBomb {
            compressed,
            uncompressed,
            ratio,
        } => ZipBombError::new_err(format!(
            "potential zip bomb: compressed={compressed} bytes, uncompressed={uncompressed} bytes (ratio: {ratio:.2})"
        )),
        CoreError::InvalidPermissions { path, mode } => InvalidPermissionsError::new_err(format!(
            "invalid permissions for {}: {:#o}",
            path.display(),
            mode
        )),
        CoreError::QuotaExceeded { resource } => {
            let msg = match resource {
                CoreQuotaResource::FileCount { current, max } => {
                    format!("quota exceeded: file count ({current} > {max})")
                }
                CoreQuotaResource::TotalSize { current, max } => {
                    format!("quota exceeded: total size ({current} > {max})")
                }
                CoreQuotaResource::FileSize { size, max } => {
                    format!("quota exceeded: file size ({size} > {max})")
                }
                CoreQuotaResource::IntegerOverflow => {
                    "quota exceeded: integer overflow in quota tracking".to_string()
                }
            };
            QuotaExceededError::new_err(msg)
        }
        CoreError::SecurityViolation { reason } => SecurityViolationError::new_err(format!(
            "operation denied by security policy: {reason}"
        )),
        CoreError::UnsupportedFormat => {
            UnsupportedFormatError::new_err("unsupported archive format")
        }
        CoreError::InvalidArchive(msg) => {
            InvalidArchiveError::new_err(format!("invalid archive: {msg}"))
        }
        CoreError::Io(e) => PyErr::from(e),
    }
}

/// Registers all exception types with the Python module.
pub fn register_exceptions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("ExtractionError", m.py().get_type::<ExtractionError>())?;
    m.add(
        "PathTraversalError",
        m.py().get_type::<PathTraversalError>(),
    )?;
    m.add(
        "SymlinkEscapeError",
        m.py().get_type::<SymlinkEscapeError>(),
    )?;
    m.add(
        "HardlinkEscapeError",
        m.py().get_type::<HardlinkEscapeError>(),
    )?;
    m.add("ZipBombError", m.py().get_type::<ZipBombError>())?;
    m.add(
        "InvalidPermissionsError",
        m.py().get_type::<InvalidPermissionsError>(),
    )?;
    m.add(
        "QuotaExceededError",
        m.py().get_type::<QuotaExceededError>(),
    )?;
    m.add(
        "SecurityViolationError",
        m.py().get_type::<SecurityViolationError>(),
    )?;
    m.add(
        "UnsupportedFormatError",
        m.py().get_type::<UnsupportedFormatError>(),
    )?;
    m.add(
        "InvalidArchiveError",
        m.py().get_type::<InvalidArchiveError>(),
    )?;
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::uninlined_format_args
)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_path_traversal_conversion() {
        let err = CoreError::PathTraversal {
            path: PathBuf::from("../etc/passwd"),
        };
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("path traversal"),
            "Expected 'path traversal' in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("../etc/passwd"),
            "Expected path in error message, got: {}",
            err_str
        );
    }

    #[test]
    fn test_symlink_escape_conversion() {
        let err = CoreError::SymlinkEscape {
            path: PathBuf::from("/etc/passwd"),
        };
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("symlink target outside"),
            "Expected 'symlink target outside' in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("/etc/passwd"),
            "Expected path in error message, got: {}",
            err_str
        );
    }

    #[test]
    fn test_hardlink_escape_conversion() {
        let err = CoreError::HardlinkEscape {
            path: PathBuf::from("/etc/shadow"),
        };
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("hardlink target outside"),
            "Expected 'hardlink target outside' in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("/etc/shadow"),
            "Expected path in error message, got: {}",
            err_str
        );
    }

    #[test]
    fn test_zip_bomb_conversion() {
        let err = CoreError::ZipBomb {
            compressed: 1000,
            uncompressed: 1_000_000,
            ratio: 1000.0,
        };
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("zip bomb"),
            "Expected 'zip bomb' in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("1000"),
            "Expected compression ratio in error message, got: {}",
            err_str
        );
    }

    #[test]
    fn test_invalid_permissions_conversion() {
        let err = CoreError::InvalidPermissions {
            path: PathBuf::from("malicious.sh"),
            mode: 0o777,
        };
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("invalid permissions"),
            "Expected 'invalid permissions' in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("777"),
            "Expected permissions mode in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("malicious.sh"),
            "Expected filename in error message, got: {}",
            err_str
        );
    }

    #[test]
    fn test_quota_exceeded_file_count_conversion() {
        let err = CoreError::QuotaExceeded {
            resource: CoreQuotaResource::FileCount {
                current: 11,
                max: 10,
            },
        };
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("quota exceeded"),
            "Expected 'quota exceeded' in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("file count"),
            "Expected 'file count' in error message, got: {}",
            err_str
        );
    }

    #[test]
    fn test_quota_exceeded_total_size_conversion() {
        let err = CoreError::QuotaExceeded {
            resource: CoreQuotaResource::TotalSize {
                current: 1_000_000,
                max: 500_000,
            },
        };
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("quota exceeded"),
            "Expected 'quota exceeded' in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("total size"),
            "Expected 'total size' in error message, got: {}",
            err_str
        );
    }

    #[test]
    fn test_quota_exceeded_file_size_conversion() {
        let err = CoreError::QuotaExceeded {
            resource: CoreQuotaResource::FileSize {
                size: 100_000_000,
                max: 50_000_000,
            },
        };
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("quota exceeded"),
            "Expected 'quota exceeded' in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("file size"),
            "Expected 'file size' in error message, got: {}",
            err_str
        );
    }

    #[test]
    fn test_quota_exceeded_integer_overflow_conversion() {
        let err = CoreError::QuotaExceeded {
            resource: CoreQuotaResource::IntegerOverflow,
        };
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("quota exceeded"),
            "Expected 'quota exceeded' in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("integer overflow"),
            "Expected 'integer overflow' in error message, got: {}",
            err_str
        );
    }

    #[test]
    fn test_security_violation_conversion() {
        let err = CoreError::SecurityViolation {
            reason: "test violation".to_string(),
        };
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("security policy"),
            "Expected 'security policy' in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("test violation"),
            "Expected reason in error message, got: {}",
            err_str
        );
    }

    #[test]
    fn test_unsupported_format_conversion() {
        let err = CoreError::UnsupportedFormat;
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("unsupported archive format"),
            "Expected 'unsupported archive format' in error message, got: {}",
            err_str
        );
    }

    #[test]
    fn test_invalid_archive_conversion() {
        let err = CoreError::InvalidArchive("corrupted header".to_string());
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("invalid archive"),
            "Expected 'invalid archive' in error message, got: {}",
            err_str
        );
        assert!(
            err_str.contains("corrupted header"),
            "Expected reason in error message, got: {}",
            err_str
        );
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = CoreError::Io(io_err);
        let py_err = convert_error(err);
        let err_str = py_err.to_string();
        assert!(
            err_str.contains("file not found"),
            "Expected 'file not found' in error message, got: {}",
            err_str
        );
    }

    #[test]
    fn test_register_exceptions_adds_all_types() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let module = PyModule::new(py, "test_module").expect("Failed to create test module");
            register_exceptions(&module.as_borrowed()).expect("Failed to register exceptions");

            // Verify all exception types are registered
            assert!(
                module.getattr("ExtractionError").is_ok(),
                "ExtractionError not registered"
            );
            assert!(
                module.getattr("PathTraversalError").is_ok(),
                "PathTraversalError not registered"
            );
            assert!(
                module.getattr("SymlinkEscapeError").is_ok(),
                "SymlinkEscapeError not registered"
            );
            assert!(
                module.getattr("HardlinkEscapeError").is_ok(),
                "HardlinkEscapeError not registered"
            );
            assert!(
                module.getattr("ZipBombError").is_ok(),
                "ZipBombError not registered"
            );
            assert!(
                module.getattr("InvalidPermissionsError").is_ok(),
                "InvalidPermissionsError not registered"
            );
            assert!(
                module.getattr("QuotaExceededError").is_ok(),
                "QuotaExceededError not registered"
            );
            assert!(
                module.getattr("SecurityViolationError").is_ok(),
                "SecurityViolationError not registered"
            );
            assert!(
                module.getattr("UnsupportedFormatError").is_ok(),
                "UnsupportedFormatError not registered"
            );
            assert!(
                module.getattr("InvalidArchiveError").is_ok(),
                "InvalidArchiveError not registered"
            );
        });
    }
}
