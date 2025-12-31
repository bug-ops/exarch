//! Python bindings for exarch-core.
//!
//! This module provides a Pythonic API for secure archive extraction with
//! built-in protection against path traversal, zip bombs, symlink attacks,
//! and other common vulnerabilities.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

mod config;
mod error;
mod report;

/// Maximum path length in bytes (Linux/macOS `PATH_MAX` is typically 4096)
const MAX_PATH_LENGTH: usize = 4096;

use config::PySecurityConfig;
use error::convert_error;
use error::register_exceptions;
use report::PyExtractionReport;

/// Extract an archive to the specified directory.
///
/// This function provides secure archive extraction with configurable
/// security policies. By default, it uses a restrictive security
/// configuration that blocks symlinks, hardlinks, absolute paths, and
/// enforces resource quotas.
///
/// # Arguments
///
/// * `archive_path` - Path to the archive file (str or pathlib.Path)
/// * `output_dir` - Directory where files will be extracted (str or
///   pathlib.Path)
/// * `config` - Optional `SecurityConfig` (uses secure defaults if None)
///
/// # Returns
///
/// `ExtractionReport` with extraction statistics
///
/// # Raises
///
/// * `ValueError` - Invalid argument type, null bytes in path, or path too long
/// * `PathTraversalError` - Path traversal attempt detected
/// * `SymlinkEscapeError` - Symlink points outside extraction directory
/// * `HardlinkEscapeError` - Hardlink target outside extraction directory
/// * `ZipBombError` - Potential zip bomb detected
/// * `InvalidPermissionsError` - File permissions are invalid or unsafe
/// * `QuotaExceededError` - Resource quota exceeded
/// * `SecurityViolationError` - Security policy violation
/// * `UnsupportedFormatError` - Archive format not supported
/// * `InvalidArchiveError` - Archive is corrupted
/// * `IOError` - I/O operation failed
///
/// # Security Considerations
///
/// ## GIL Release and TOCTOU
///
/// The GIL is released during extraction for performance. This creates a
/// Time-Of-Check-Time-Of-Use (TOCTOU) race condition where the archive file
/// could be modified between validation and extraction. This is an accepted
/// tradeoff for performance. For untrusted archives, ensure exclusive access
/// to the archive file during extraction.
///
/// ## Input Validation
///
/// - Paths containing null bytes are rejected (security)
/// - Paths exceeding 4096 bytes are rejected (`DoS` prevention)
/// - All validation happens at the Python boundary before calling core library
///
/// # Examples
///
/// ```python
/// from exarch import extract_archive, SecurityConfig
/// from pathlib import Path
///
/// # Use secure defaults with string paths
/// report = extract_archive("archive.tar.gz", "/tmp/output")
/// print(f"Extracted {report.files_extracted} files")
///
/// # Use pathlib.Path objects
/// archive = Path("archive.tar.gz")
/// output = Path("/tmp/output")
/// report = extract_archive(archive, output)
///
/// # Customize security settings
/// config = SecurityConfig().max_file_size(100 * 1024 * 1024)
/// report = extract_archive("archive.tar.gz", "/tmp/output", config)
/// ```
#[pyfunction]
#[pyo3(signature = (archive_path, output_dir, config=None))]
fn extract_archive(
    py: Python<'_>,
    archive_path: &Bound<'_, PyAny>,
    output_dir: &Bound<'_, PyAny>,
    config: Option<&PySecurityConfig>,
) -> PyResult<PyExtractionReport> {
    // Convert Path-like objects to strings
    let archive_path = path_to_string(py, archive_path)?;
    let output_dir = path_to_string(py, output_dir)?;

    // Get config reference or use default
    // Note: We need to create a default config if None is provided, since we need a
    // reference
    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    // Release GIL during I/O-heavy extraction
    // NOTE: TOCTOU race condition - archive contents can change between check and
    // extraction. This is an accepted limitation when releasing the GIL for
    // performance.
    let report = py
        .detach(|| exarch_core::extract_archive(&archive_path, &output_dir, config_ref))
        .map_err(convert_error)?;

    Ok(PyExtractionReport::from(report))
}

/// Converts a Path-like object to a string with validation.
///
/// Accepts both strings and `pathlib.Path` objects by calling `os.fspath()`.
///
/// # Security
///
/// - Rejects paths containing null bytes (potential injection attacks)
/// - Rejects paths exceeding `MAX_PATH_LENGTH` bytes (`DoS` prevention)
fn path_to_string(py: Python<'_>, path: &Bound<'_, PyAny>) -> PyResult<String> {
    // Try direct string extraction first
    let path_str = if let Ok(s) = path.extract::<String>() {
        s
    } else {
        // Try os.fspath() for Path objects
        let os = py.import("os")?;
        let fspath = os.getattr("fspath")?;
        let result = fspath.call1((path,))?;
        result.extract()?
    };

    // Validate: reject null bytes (security)
    if path_str.contains('\0') {
        return Err(PyValueError::new_err(
            "path contains null bytes - potential security issue",
        ));
    }

    // Validate: reject excessively long paths (DoS prevention)
    if path_str.len() > MAX_PATH_LENGTH {
        return Err(PyValueError::new_err(format!(
            "path exceeds maximum length of {} bytes (got {} bytes)",
            MAX_PATH_LENGTH,
            path_str.len()
        )));
    }

    Ok(path_str)
}

/// Python module definition.
#[pymodule]
fn exarch(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Module metadata
    m.add(
        "__doc__",
        "Memory-safe archive extraction library with security validation",
    )?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    // Top-level function
    m.add_function(wrap_pyfunction!(extract_archive, m)?)?;

    // Classes
    m.add_class::<PySecurityConfig>()?;
    m.add_class::<PyExtractionReport>()?;

    // Exception types
    register_exceptions(m)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyString;

    #[test]
    fn test_module_metadata() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let module = PyModule::new(py, "test_exarch").expect("Failed to create module");
            let result = exarch(&module.as_borrowed());
            assert!(
                result.is_ok(),
                "Module initialization failed: {:?}",
                result.err()
            );

            // Verify module has __doc__ and __version__
            assert!(
                module.getattr("__doc__").is_ok(),
                "Module missing __doc__ attribute"
            );
            assert!(
                module.getattr("__version__").is_ok(),
                "Module missing __version__ attribute"
            );

            // Verify main function is registered
            assert!(
                module.getattr("extract_archive").is_ok(),
                "extract_archive function not registered"
            );

            // Verify classes are registered
            assert!(
                module.getattr("SecurityConfig").is_ok(),
                "SecurityConfig class not registered"
            );
            assert!(
                module.getattr("ExtractionReport").is_ok(),
                "ExtractionReport class not registered"
            );
        });
    }

    #[test]
    fn test_path_to_string_with_string() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let path = PyString::new(py, "/tmp/test.tar.gz").into_any();
            let result = path_to_string(py, &path.as_borrowed());
            assert!(
                result.is_ok(),
                "Failed to convert string path: {:?}",
                result.err()
            );
            assert_eq!(result.unwrap(), "/tmp/test.tar.gz");
        });
    }

    #[test]
    fn test_path_to_string_empty() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let path = PyString::new(py, "").into_any();
            let result = path_to_string(py, &path.as_borrowed());
            assert!(
                result.is_ok(),
                "Failed to convert empty path: {:?}",
                result.err()
            );
            assert_eq!(result.unwrap(), "");
        });
    }

    #[test]
    fn test_path_to_string_with_path_object() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let pathlib = py.import("pathlib").expect("Failed to import pathlib");
            let path_class = pathlib.getattr("Path").expect("Failed to get Path class");
            let path = path_class
                .call1(("/tmp/test.tar.gz",))
                .expect("Failed to create Path object");
            let result = path_to_string(py, &path.as_borrowed());
            assert!(
                result.is_ok(),
                "Failed to convert Path object: {:?}",
                result.err()
            );
            assert_eq!(result.unwrap(), "/tmp/test.tar.gz");
        });
    }

    #[test]
    fn test_path_to_string_rejects_null_bytes() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let path = PyString::new(py, "/tmp/test\0malicious.tar.gz").into_any();
            let result = path_to_string(py, &path.as_borrowed());
            assert!(result.is_err(), "Should reject path with null bytes");
            let err_str = result.unwrap_err().to_string();
            assert!(
                err_str.contains("null bytes"),
                "Expected 'null bytes' in error, got: {}",
                err_str
            );
        });
    }

    #[test]
    fn test_path_to_string_rejects_too_long() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let long_path = "x".repeat(MAX_PATH_LENGTH + 1);
            let path = PyString::new(py, &long_path).into_any();
            let result = path_to_string(py, &path.as_borrowed());
            assert!(result.is_err(), "Should reject excessively long path");
            let err_str = result.unwrap_err().to_string();
            assert!(
                err_str.contains("maximum length"),
                "Expected 'maximum length' in error, got: {}",
                err_str
            );
        });
    }

    #[test]
    fn test_path_to_string_accepts_max_length() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let max_path = "x".repeat(MAX_PATH_LENGTH);
            let path = PyString::new(py, &max_path).into_any();
            let result = path_to_string(py, &path.as_borrowed());
            assert!(
                result.is_ok(),
                "Should accept path at maximum length: {:?}",
                result.err()
            );
            assert_eq!(result.unwrap().len(), MAX_PATH_LENGTH);
        });
    }
}
