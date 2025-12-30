//! Python bindings for exarch-core.

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Extract an archive to the specified directory.
///
/// # Arguments
///
/// * `archive_path` - Path to the archive file
/// * `output_dir` - Directory where files will be extracted
///
/// # Returns
///
/// Dictionary with extraction statistics:
/// - `files_extracted`: Number of files extracted
/// - `bytes_written`: Total bytes written
/// - `duration_ms`: Extraction duration in milliseconds
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // PyO3 requires owned String
fn extract_archive(py: Python<'_>, archive_path: String, output_dir: String) -> PyResult<Py<PyAny>> {
    let config = exarch_core::SecurityConfig::default();

    match exarch_core::extract_archive(&archive_path, &output_dir, &config) {
        Ok(report) => {
            let dict = PyDict::new(py);
            dict.set_item("files_extracted", report.files_extracted)?;
            dict.set_item("bytes_written", report.bytes_written)?;
            dict.set_item("duration_ms", report.duration.as_millis())?;
            Ok(dict.into_any().unbind())
        }
        Err(e) => Err(PyRuntimeError::new_err(format!("Extraction failed: {e}"))),
    }
}

/// Python module definition.
#[pymodule]
fn exarch(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(extract_archive, m)?)?;
    Ok(())
}
