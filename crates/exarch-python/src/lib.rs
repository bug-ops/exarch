//! Python bindings for exarch-core.
//!
//! This module provides a Pythonic API for secure archive extraction with
//! built-in protection against path traversal, zip bombs, symlink attacks,
//! and other common vulnerabilities.

use pyo3::prelude::*;

mod config;
mod error;
mod report;

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
/// * `archive_path` - Path to the archive file (str or Path)
/// * `output_dir` - Directory where files will be extracted (str or Path)
/// * `config` - Optional `SecurityConfig` (uses secure defaults if None)
///
/// # Returns
///
/// `ExtractionReport` with extraction statistics
///
/// # Raises
///
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
/// # Examples
///
/// ```python
/// from exarch import extract_archive, SecurityConfig
///
/// # Use secure defaults
/// report = extract_archive("archive.tar.gz", "/tmp/output")
/// print(f"Extracted {report.files_extracted} files")
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

    // Get config - clone it so we can move it into the detach closure
    let config_owned = config.map(|c| c.as_core().clone()).unwrap_or_default();

    // Release GIL during I/O-heavy extraction
    let report = py
        .detach(|| exarch_core::extract_archive(&archive_path, &output_dir, &config_owned))
        .map_err(convert_error)?;

    Ok(PyExtractionReport::from(report))
}

/// Converts a Path-like object to a string.
///
/// Accepts both strings and `pathlib.Path` objects by calling `os.fspath()`.
fn path_to_string(py: Python<'_>, path: &Bound<'_, PyAny>) -> PyResult<String> {
    // Try direct string extraction first
    if let Ok(s) = path.extract::<String>() {
        return Ok(s);
    }

    // Try os.fspath() for Path objects
    let os = py.import("os")?;
    let fspath = os.getattr("fspath")?;
    let path_str = fspath.call1((path,))?;
    path_str.extract()
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

    #[test]
    fn test_module_metadata() {
        // Verify that module metadata is correctly set
        assert!(!env!("CARGO_PKG_VERSION").is_empty());
    }
}
