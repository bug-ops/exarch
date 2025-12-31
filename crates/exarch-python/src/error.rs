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
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_path_traversal_conversion() {
        let err = CoreError::PathTraversal {
            path: PathBuf::from("../etc/passwd"),
        };
        let py_err = convert_error(err);
        assert!(py_err.to_string().contains("path traversal"));
    }

    #[test]
    fn test_zip_bomb_conversion() {
        let err = CoreError::ZipBomb {
            compressed: 1000,
            uncompressed: 1_000_000,
            ratio: 1000.0,
        };
        let py_err = convert_error(err);
        assert!(py_err.to_string().contains("zip bomb"));
    }

    #[test]
    fn test_quota_exceeded_conversion() {
        let err = CoreError::QuotaExceeded {
            resource: CoreQuotaResource::FileCount {
                current: 11,
                max: 10,
            },
        };
        let py_err = convert_error(err);
        assert!(py_err.to_string().contains("quota exceeded"));
        assert!(py_err.to_string().contains("file count"));
    }
}
