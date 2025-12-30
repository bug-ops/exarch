//! Extraction operation reporting.

use std::time::Duration;

/// Report of an archive extraction operation.
///
/// Contains statistics and metadata about the extraction process.
#[derive(Debug, Clone, Default)]
pub struct ExtractionReport {
    /// Number of files successfully extracted.
    pub files_extracted: usize,

    /// Number of directories created.
    pub directories_created: usize,

    /// Number of symlinks created.
    pub symlinks_created: usize,

    /// Total bytes written to disk.
    pub bytes_written: u64,

    /// Duration of the extraction operation.
    pub duration: Duration,

    /// Number of files skipped due to security checks.
    pub files_skipped: usize,

    /// Warnings generated during extraction.
    pub warnings: Vec<String>,
}

impl ExtractionReport {
    /// Creates a new empty extraction report.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a warning message to the report.
    pub fn add_warning(&mut self, message: String) {
        self.warnings.push(message);
    }

    /// Returns total number of items processed.
    #[must_use]
    pub fn total_items(&self) -> usize {
        self.files_extracted + self.directories_created + self.symlinks_created
    }

    /// Returns whether any warnings were generated.
    #[must_use]
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_report() {
        let report = ExtractionReport::new();
        assert_eq!(report.files_extracted, 0);
        assert_eq!(report.directories_created, 0);
        assert_eq!(report.bytes_written, 0);
        assert!(!report.has_warnings());
    }

    #[test]
    fn test_add_warning() {
        let mut report = ExtractionReport::new();
        report.add_warning("Test warning".to_string());
        assert!(report.has_warnings());
        assert_eq!(report.warnings.len(), 1);
    }

    #[test]
    fn test_total_items() {
        let mut report = ExtractionReport::new();
        report.files_extracted = 10;
        report.directories_created = 5;
        report.symlinks_created = 2;
        assert_eq!(report.total_items(), 17);
    }
}
