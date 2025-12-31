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

    /// Returns a copy of the warning messages list.
    ///
    /// # Performance
    ///
    /// This method clones the entire list on each access. If you need to access
    /// the warnings multiple times, cache the result in a local variable.
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
    ///
    /// # Performance
    ///
    /// This method allocates a new string on every call using `format!`.
    /// This is acceptable for debugging/logging but avoid calling in hot paths.
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
    ///
    /// # Performance
    ///
    /// This method allocates a new string on every call (delegates to
    /// `__str__`).
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

        assert_eq!(
            py_report.files_extracted(),
            10,
            "files_extracted should be 10"
        );
        assert_eq!(
            py_report.directories_created(),
            5,
            "directories_created should be 5"
        );
        assert_eq!(
            py_report.symlinks_created(),
            2,
            "symlinks_created should be 2"
        );
        assert_eq!(
            py_report.bytes_written(),
            1024,
            "bytes_written should be 1024"
        );
        assert_eq!(py_report.duration_ms(), 500, "duration_ms should be 500");
        assert_eq!(py_report.files_skipped(), 1, "files_skipped should be 1");
        assert_eq!(py_report.total_items(), 17, "total_items should be 17");
        assert!(py_report.has_warnings(), "should have warnings");
        assert_eq!(
            py_report.warnings().len(),
            1,
            "warnings list should have 1 item"
        );
    }

    #[test]
    fn test_extraction_report_zero_values() {
        let core_report = CoreReport::new();
        let py_report = PyExtractionReport::from(core_report);

        assert_eq!(
            py_report.files_extracted(),
            0,
            "files_extracted should default to 0"
        );
        assert_eq!(
            py_report.directories_created(),
            0,
            "directories_created should default to 0"
        );
        assert_eq!(
            py_report.symlinks_created(),
            0,
            "symlinks_created should default to 0"
        );
        assert_eq!(
            py_report.bytes_written(),
            0,
            "bytes_written should default to 0"
        );
        assert_eq!(
            py_report.files_skipped(),
            0,
            "files_skipped should default to 0"
        );
        assert_eq!(
            py_report.total_items(),
            0,
            "total_items should be 0 for empty report"
        );
        assert!(
            !py_report.has_warnings(),
            "should not have warnings by default"
        );
        assert_eq!(
            py_report.warnings().len(),
            0,
            "warnings list should be empty"
        );
    }

    #[test]
    fn test_extraction_report_large_values() {
        let mut core_report = CoreReport::new();
        core_report.files_extracted = 100_000;
        core_report.directories_created = 50_000;
        core_report.bytes_written = 10_000_000_000; // 10 GB
        core_report.duration = Duration::from_secs(3600); // 1 hour

        let py_report = PyExtractionReport::from(core_report);

        assert_eq!(
            py_report.files_extracted(),
            100_000,
            "Should handle large file counts"
        );
        assert_eq!(
            py_report.bytes_written(),
            10_000_000_000,
            "Should handle large byte counts"
        );
        assert_eq!(
            py_report.duration_ms(),
            3_600_000,
            "Should convert seconds to milliseconds correctly"
        );
    }

    #[test]
    fn test_extraction_report_str() {
        let core_report = CoreReport::new();
        let py_report = PyExtractionReport::from(core_report);
        let s = py_report.__str__();
        assert!(
            s.contains("ExtractionReport"),
            "__str__ should contain class name"
        );
        assert!(s.contains("files="), "__str__ should contain files field");
        assert!(s.contains("dirs="), "__str__ should contain dirs field");
        assert!(s.contains("bytes="), "__str__ should contain bytes field");
    }

    #[test]
    fn test_extraction_report_repr() {
        let core_report = CoreReport::new();
        let py_report = PyExtractionReport::from(core_report);
        let repr_str = py_report.__repr__();
        let str_str = py_report.__str__();
        assert_eq!(
            repr_str, str_str,
            "__repr__ should be equivalent to __str__"
        );
    }

    #[test]
    fn test_warnings_clone_behavior() {
        let mut core_report = CoreReport::new();
        core_report.add_warning("Warning 1".to_string());
        core_report.add_warning("Warning 2".to_string());

        let py_report = PyExtractionReport::from(core_report);

        // Get warnings twice to verify clone behavior
        let warnings1 = py_report.warnings();
        let warnings2 = py_report.warnings();

        assert_eq!(warnings1.len(), 2, "First call should return 2 warnings");
        assert_eq!(
            warnings2.len(),
            2,
            "Second call should also return 2 warnings"
        );
        assert_eq!(warnings1, warnings2, "Both calls should return equal lists");
    }
}
