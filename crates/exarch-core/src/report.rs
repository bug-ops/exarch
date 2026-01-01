//! Extraction operation reporting.

use std::path::Path;
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

/// Callback trait for progress reporting during archive operations.
///
/// Implement this trait to receive progress updates during extraction or
/// creation. The trait requires `Send` to allow use in multi-threaded contexts.
///
/// # Examples
///
/// ```
/// use exarch_core::ProgressCallback;
/// use std::path::Path;
///
/// struct SimpleProgress;
///
/// impl ProgressCallback for SimpleProgress {
///     fn on_entry_start(&mut self, path: &Path, total: usize, current: usize) {
///         println!("Processing {}/{}: {}", current, total, path.display());
///     }
///
///     fn on_bytes_written(&mut self, bytes: u64) {
///         // Track bytes written
///     }
///
///     fn on_entry_complete(&mut self, path: &Path) {
///         println!("Completed: {}", path.display());
///     }
///
///     fn on_complete(&mut self) {
///         println!("Operation complete");
///     }
/// }
/// ```
pub trait ProgressCallback: Send {
    /// Called when starting to process an entry.
    ///
    /// # Arguments
    ///
    /// * `path` - Path of the entry being processed
    /// * `total` - Total number of entries in the archive
    /// * `current` - Current entry number (1-indexed)
    fn on_entry_start(&mut self, path: &Path, total: usize, current: usize);

    /// Called when bytes are written during extraction or read during creation.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Number of bytes written/read in this update
    fn on_bytes_written(&mut self, bytes: u64);

    /// Called when an entry has been completely processed.
    ///
    /// # Arguments
    ///
    /// * `path` - Path of the entry that was completed
    fn on_entry_complete(&mut self, path: &Path);

    /// Called when the entire operation is complete.
    fn on_complete(&mut self);
}

/// No-op implementation of `ProgressCallback` that does nothing.
///
/// Use this when you don't need progress reporting but the API requires
/// a callback implementation.
#[derive(Debug, Default)]
pub struct NoopProgress;

impl ProgressCallback for NoopProgress {
    fn on_entry_start(&mut self, _path: &Path, _total: usize, _current: usize) {}

    fn on_bytes_written(&mut self, _bytes: u64) {}

    fn on_entry_complete(&mut self, _path: &Path) {}

    fn on_complete(&mut self) {}
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
