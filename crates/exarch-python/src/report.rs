//! Python bindings for `ExtractionReport`.

use exarch_core::ExtractionReport as CoreReport;
use pyo3::prelude::*;

/// Report of an archive extraction operation.
///
/// Contains statistics and metadata about the extraction process.
///
/// # Attributes
///
/// * `files_extracted` - Number of files successfully extracted
/// * `directories_created` - Number of directories created
/// * `symlinks_created` - Number of symlinks created
/// * `bytes_written` - Total bytes written to disk
/// * `duration_ms` - Extraction duration in milliseconds
/// * `files_skipped` - Number of files skipped due to security checks
/// * `warnings` - List of warning messages
#[pyclass(name = "ExtractionReport")]
#[derive(Clone)]
pub struct PyExtractionReport {
    inner: CoreReport,
}

#[pymethods]
impl PyExtractionReport {
    /// Number of files successfully extracted.
    #[getter]
    fn files_extracted(&self) -> usize {
        self.inner.files_extracted
    }

    /// Number of directories created.
    #[getter]
    fn directories_created(&self) -> usize {
        self.inner.directories_created
    }

    /// Number of symlinks created.
    #[getter]
    fn symlinks_created(&self) -> usize {
        self.inner.symlinks_created
    }

    /// Total bytes written to disk.
    #[getter]
    fn bytes_written(&self) -> u64 {
        self.inner.bytes_written
    }

    /// Extraction duration in milliseconds.
    #[getter]
    fn duration_ms(&self) -> u128 {
        self.inner.duration.as_millis()
    }

    /// Number of files skipped due to security checks.
    #[getter]
    fn files_skipped(&self) -> usize {
        self.inner.files_skipped
    }

    /// List of warning messages.
    #[getter]
    fn warnings(&self) -> Vec<String> {
        self.inner.warnings.clone()
    }

    /// Returns total number of items processed.
    fn total_items(&self) -> usize {
        self.inner.total_items()
    }

    /// Returns whether any warnings were generated.
    fn has_warnings(&self) -> bool {
        self.inner.has_warnings()
    }

    /// Returns a human-readable string representation.
    fn __str__(&self) -> String {
        format!(
            "ExtractionReport(files={}, dirs={}, symlinks={}, bytes={}, duration={}ms, skipped={}, warnings={})",
            self.inner.files_extracted,
            self.inner.directories_created,
            self.inner.symlinks_created,
            self.inner.bytes_written,
            self.inner.duration.as_millis(),
            self.inner.files_skipped,
            self.inner.warnings.len()
        )
    }

    /// Returns a debug string representation.
    fn __repr__(&self) -> String {
        self.__str__()
    }
}

impl From<CoreReport> for PyExtractionReport {
    fn from(inner: CoreReport) -> Self {
        Self { inner }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_extraction_report_properties() {
        let mut core_report = CoreReport::new();
        core_report.files_extracted = 10;
        core_report.directories_created = 5;
        core_report.symlinks_created = 2;
        core_report.bytes_written = 1024;
        core_report.duration = Duration::from_millis(500);
        core_report.files_skipped = 1;
        core_report.add_warning("Test warning".to_string());

        let py_report = PyExtractionReport::from(core_report);

        assert_eq!(py_report.files_extracted(), 10);
        assert_eq!(py_report.directories_created(), 5);
        assert_eq!(py_report.symlinks_created(), 2);
        assert_eq!(py_report.bytes_written(), 1024);
        assert_eq!(py_report.duration_ms(), 500);
        assert_eq!(py_report.files_skipped(), 1);
        assert_eq!(py_report.total_items(), 17);
        assert!(py_report.has_warnings());
        assert_eq!(py_report.warnings().len(), 1);
    }

    #[test]
    fn test_extraction_report_str() {
        let core_report = CoreReport::new();
        let py_report = PyExtractionReport::from(core_report);
        let s = py_report.__str__();
        assert!(s.contains("ExtractionReport"));
        assert!(s.contains("files="));
    }
}
