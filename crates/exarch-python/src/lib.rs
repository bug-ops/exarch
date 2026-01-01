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

use config::PyCreationConfig;
use config::PySecurityConfig;
use error::convert_error;
use error::register_exceptions;
use report::PyArchiveEntry;
use report::PyArchiveManifest;
use report::PyCreationReport;
use report::PyExtractionReport;
use report::PyVerificationIssue;
use report::PyVerificationReport;

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
    let report = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        py.detach(|| exarch_core::extract_archive(&archive_path, &output_dir, config_ref))
    }))
    .map_err(|_| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Internal panic during extraction")
    })?
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

/// Create an archive from source files and directories.
///
/// # Arguments
///
/// * `output_path` - Path to output archive file (str or pathlib.Path)
/// * `sources` - List of source files/directories to include (str or
///   pathlib.Path)
/// * `config` - Optional `CreationConfig` (uses defaults if None)
///
/// # Returns
///
/// `CreationReport` with creation statistics
///
/// # Raises
///
/// * `ValueError` - Invalid arguments
/// * `IOError` - I/O operation failed
/// * `UnsupportedFormatError` - Archive format not supported
///
/// # Examples
///
/// ```python
/// from exarch import create_archive, CreationConfig
///
/// # Use defaults
/// report = create_archive("output.tar.gz", ["source_dir/"])
/// print(f"Created archive with {report.files_added} files")
///
/// # Customize configuration
/// config = CreationConfig().compression_level(9)
/// report = create_archive("output.tar.gz", ["src/"], config)
/// ```
#[pyfunction]
#[pyo3(signature = (output_path, sources, config=None))]
fn create_archive(
    py: Python<'_>,
    output_path: &Bound<'_, PyAny>,
    sources: &Bound<'_, PyAny>,
    config: Option<&PyCreationConfig>,
) -> PyResult<PyCreationReport> {
    let output_path = path_to_string(py, output_path)?;

    // Convert sources to Vec<String>
    let sources_list: Vec<Bound<'_, PyAny>> = sources.extract()?;
    let source_paths: Vec<String> = sources_list
        .iter()
        .map(|s| path_to_string(py, s))
        .collect::<PyResult<_>>()?;

    let default_config = exarch_core::creation::CreationConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    let report = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        py.detach(|| exarch_core::create_archive(&output_path, &source_paths, config_ref))
    }))
    .map_err(|_| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Internal panic during archive creation")
    })?
    .map_err(convert_error)?;

    Ok(PyCreationReport::from(report))
}

/// List archive contents without extracting.
///
/// # Arguments
///
/// * `archive_path` - Path to archive file (str or pathlib.Path)
/// * `config` - Optional `SecurityConfig` (uses secure defaults if None)
///
/// # Returns
///
/// `ArchiveManifest` with entry metadata
///
/// # Raises
///
/// * `ValueError` - Invalid arguments
/// * `IOError` - I/O operation failed
/// * `UnsupportedFormatError` - Archive format not supported
///
/// # Examples
///
/// ```python
/// from exarch import list_archive
///
/// manifest = list_archive("archive.tar.gz")
/// for entry in manifest.entries:
///     print(f"{entry.path}: {entry.size} bytes")
/// ```
#[pyfunction]
#[pyo3(signature = (archive_path, config=None))]
fn list_archive(
    py: Python<'_>,
    archive_path: &Bound<'_, PyAny>,
    config: Option<&PySecurityConfig>,
) -> PyResult<PyArchiveManifest> {
    let archive_path = path_to_string(py, archive_path)?;

    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    let manifest = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        py.detach(|| exarch_core::list_archive(&archive_path, config_ref))
    }))
    .map_err(|_| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Internal panic during archive listing")
    })?
    .map_err(convert_error)?;

    Ok(PyArchiveManifest::from(manifest))
}

/// Verify archive integrity and security.
///
/// # Arguments
///
/// * `archive_path` - Path to archive file (str or pathlib.Path)
/// * `config` - Optional `SecurityConfig` (uses secure defaults if None)
///
/// # Returns
///
/// `VerificationReport` with validation results
///
/// # Raises
///
/// * `ValueError` - Invalid arguments
/// * `IOError` - I/O operation failed
/// * `UnsupportedFormatError` - Archive format not supported
///
/// # Examples
///
/// ```python
/// from exarch import verify_archive
///
/// report = verify_archive("archive.tar.gz")
/// if report.is_safe():
///     print("Archive is safe to extract")
/// else:
///     for issue in report.issues:
///         print(f"[{issue.severity}] {issue.message}")
/// ```
#[pyfunction]
#[pyo3(signature = (archive_path, config=None))]
fn verify_archive(
    py: Python<'_>,
    archive_path: &Bound<'_, PyAny>,
    config: Option<&PySecurityConfig>,
) -> PyResult<PyVerificationReport> {
    let archive_path = path_to_string(py, archive_path)?;

    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    let report = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        py.detach(|| exarch_core::verify_archive(&archive_path, config_ref))
    }))
    .map_err(|_| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            "Internal panic during archive verification",
        )
    })?
    .map_err(convert_error)?;

    Ok(PyVerificationReport::from(report))
}

/// Create an archive with progress callback.
///
/// # Arguments
///
/// * `output_path` - Path to output archive file (str or pathlib.Path)
/// * `sources` - List of source files/directories to include (str or
///   pathlib.Path)
/// * `config` - Optional `CreationConfig` (uses defaults if None)
/// * `progress` - Optional progress callback function
///
/// Progress callback signature: `(path: str, total: int, current: int,
/// bytes_written: int) -> None`
///
/// # Returns
///
/// `CreationReport` with creation statistics
///
/// # Raises
///
/// * `ValueError` - Invalid arguments
/// * `IOError` - I/O operation failed
/// * `UnsupportedFormatError` - Archive format not supported
///
/// # Examples
///
/// ```python
/// from exarch import create_archive_with_progress
///
/// def progress(path: str, total: int, current: int, bytes: int):
///     print(f"{current}/{total}: {path} ({bytes} bytes)")
///
/// report = create_archive_with_progress(
///     "output.tar.gz", ["src/"], None, progress
/// )
/// ```
#[pyfunction]
#[pyo3(signature = (output_path, sources, config=None, progress=None))]
fn create_archive_with_progress(
    py: Python<'_>,
    output_path: &Bound<'_, PyAny>,
    sources: &Bound<'_, PyAny>,
    config: Option<&PyCreationConfig>,
    progress: Option<Py<PyAny>>,
) -> PyResult<PyCreationReport> {
    let output_path = path_to_string(py, output_path)?;

    // Convert sources to Vec<String>
    let sources_list: Vec<Bound<'_, PyAny>> = sources.extract()?;
    let source_paths: Vec<String> = sources_list
        .iter()
        .map(|s| path_to_string(py, s))
        .collect::<PyResult<_>>()?;

    let default_config = exarch_core::creation::CreationConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    // Create progress callback adapter
    if let Some(py_callback) = progress {
        let mut callback = PyProgressAdapter::new(py_callback);

        // CRITICAL: Do NOT release GIL when using Python callback!
        // Python callback requires GIL to call into Python.
        let report = exarch_core::create_archive_with_progress(
            &output_path,
            &source_paths,
            config_ref,
            &mut callback,
        )
        .map_err(convert_error)?;

        Ok(PyCreationReport::from(report))
    } else {
        // No progress callback - can release GIL
        let mut noop = exarch_core::NoopProgress;
        let report = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            py.detach(|| {
                exarch_core::create_archive_with_progress(
                    &output_path,
                    &source_paths,
                    config_ref,
                    &mut noop,
                )
            })
        }))
        .map_err(|_| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "Internal panic during archive creation with progress",
            )
        })?
        .map_err(convert_error)?;

        Ok(PyCreationReport::from(report))
    }
}

/// Adapter that calls Python callback from Rust.
struct PyProgressAdapter {
    callback: Py<PyAny>,
    accumulated_bytes: u64,
}

impl PyProgressAdapter {
    fn new(callback: Py<PyAny>) -> Self {
        Self {
            callback,
            accumulated_bytes: 0,
        }
    }
}

impl exarch_core::ProgressCallback for PyProgressAdapter {
    fn on_entry_start(&mut self, path: &std::path::Path, total: usize, current: usize) {
        Python::attach(|py| {
            let path_str = path.to_string_lossy().into_owned();
            let _ = self
                .callback
                .call1(py, (path_str, total, current, self.accumulated_bytes));
        });
    }

    fn on_bytes_written(&mut self, bytes: u64) {
        self.accumulated_bytes += bytes;
    }

    fn on_entry_complete(&mut self, _path: &std::path::Path) {
        // No-op: not exposed to Python (simplification)
    }

    fn on_complete(&mut self) {
        // No-op: Python can detect completion when function returns
    }
}

// SAFETY: We only call into Python when holding GIL via Python::attach
// This is required because ProgressCallback trait requires Send.
// The Py<PyAny> is Send-safe when accessed via GIL (Python::attach).
#[allow(unsafe_code)]
unsafe impl Send for PyProgressAdapter {}

/// Python module definition.
#[pymodule]
fn exarch(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Module metadata
    m.add(
        "__doc__",
        "Memory-safe archive extraction library with security validation",
    )?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    // Top-level functions
    m.add_function(wrap_pyfunction!(extract_archive, m)?)?;
    m.add_function(wrap_pyfunction!(create_archive, m)?)?;
    m.add_function(wrap_pyfunction!(create_archive_with_progress, m)?)?;
    m.add_function(wrap_pyfunction!(list_archive, m)?)?;
    m.add_function(wrap_pyfunction!(verify_archive, m)?)?;

    // Configuration classes
    m.add_class::<PySecurityConfig>()?;
    m.add_class::<PyCreationConfig>()?;

    // Report classes
    m.add_class::<PyExtractionReport>()?;
    m.add_class::<PyCreationReport>()?;
    m.add_class::<PyArchiveManifest>()?;
    m.add_class::<PyArchiveEntry>()?;
    m.add_class::<PyVerificationReport>()?;
    m.add_class::<PyVerificationIssue>()?;

    // Exception types
    register_exceptions(m)?;

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
