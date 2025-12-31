//! Archive creation operation reporting.

use std::time::Duration;

/// Report of an archive creation operation.
///
/// Contains statistics and metadata about the creation process.
///
/// # Examples
///
/// ```
/// use exarch_core::creation::CreationReport;
///
/// let mut report = CreationReport::default();
/// report.files_added = 10;
/// report.bytes_written = 1024;
/// report.bytes_compressed = 512;
///
/// assert_eq!(report.compression_ratio(), 2.0);
/// assert_eq!(report.compression_percentage(), 50.0);
/// ```
#[derive(Debug, Clone, Default)]
pub struct CreationReport {
    /// Number of files added to the archive.
    pub files_added: usize,

    /// Number of directories added to the archive.
    pub directories_added: usize,

    /// Number of symlinks added to the archive.
    pub symlinks_added: usize,

    /// Total bytes written to the archive (uncompressed).
    pub bytes_written: u64,

    /// Total bytes in the final archive (compressed).
    pub bytes_compressed: u64,

    /// Duration of the creation operation.
    pub duration: Duration,

    /// Number of files skipped (due to filters or errors).
    pub files_skipped: usize,

    /// Warnings generated during creation.
    pub warnings: Vec<String>,
}

impl CreationReport {
    /// Creates a new empty creation report.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a warning message to the report.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::CreationReport;
    ///
    /// let mut report = CreationReport::new();
    /// report.add_warning("File too large, skipped");
    /// assert!(report.has_warnings());
    /// ```
    pub fn add_warning(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }

    /// Returns whether any warnings were generated.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::CreationReport;
    ///
    /// let mut report = CreationReport::new();
    /// assert!(!report.has_warnings());
    ///
    /// report.add_warning("test warning");
    /// assert!(report.has_warnings());
    /// ```
    #[must_use]
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    /// Returns the compression ratio (uncompressed / compressed).
    ///
    /// Returns 0.0 if `bytes_compressed` is 0 or `bytes_written` is 0.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::CreationReport;
    ///
    /// let mut report = CreationReport::new();
    /// report.bytes_written = 1000;
    /// report.bytes_compressed = 500;
    /// assert_eq!(report.compression_ratio(), 2.0);
    ///
    /// // Edge case: zero compressed size
    /// report.bytes_compressed = 0;
    /// assert_eq!(report.compression_ratio(), 0.0);
    ///
    /// // Edge case: equal sizes (no compression)
    /// report.bytes_written = 1000;
    /// report.bytes_compressed = 1000;
    /// assert_eq!(report.compression_ratio(), 1.0);
    /// ```
    #[must_use]
    pub fn compression_ratio(&self) -> f64 {
        if self.bytes_compressed == 0 || self.bytes_written == 0 {
            return 0.0;
        }
        self.bytes_written as f64 / self.bytes_compressed as f64
    }

    /// Returns the compression percentage (space saved).
    ///
    /// Returns 0.0 if `bytes_written` is 0.
    /// Returns 100.0 if `bytes_compressed` is 0 (perfect compression).
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::CreationReport;
    ///
    /// let mut report = CreationReport::new();
    /// report.bytes_written = 1000;
    /// report.bytes_compressed = 500;
    /// assert_eq!(report.compression_percentage(), 50.0);
    ///
    /// // Edge case: no compression
    /// report.bytes_compressed = 1000;
    /// assert_eq!(report.compression_percentage(), 0.0);
    ///
    /// // Edge case: perfect compression
    /// report.bytes_compressed = 0;
    /// assert_eq!(report.compression_percentage(), 100.0);
    /// ```
    #[must_use]
    pub fn compression_percentage(&self) -> f64 {
        if self.bytes_written == 0 {
            return 0.0;
        }
        if self.bytes_compressed == 0 {
            return 100.0;
        }
        let saved = self.bytes_written.saturating_sub(self.bytes_compressed);
        (saved as f64 / self.bytes_written as f64) * 100.0
    }

    /// Returns total number of items added.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::CreationReport;
    ///
    /// let mut report = CreationReport::new();
    /// report.files_added = 10;
    /// report.directories_added = 5;
    /// report.symlinks_added = 2;
    /// assert_eq!(report.total_items(), 17);
    /// ```
    #[must_use]
    pub fn total_items(&self) -> usize {
        self.files_added + self.directories_added + self.symlinks_added
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation_report_default() {
        let report = CreationReport::default();
        assert_eq!(report.files_added, 0);
        assert_eq!(report.directories_added, 0);
        assert_eq!(report.symlinks_added, 0);
        assert_eq!(report.bytes_written, 0);
        assert_eq!(report.bytes_compressed, 0);
        assert_eq!(report.duration, Duration::default());
        assert_eq!(report.files_skipped, 0);
        assert!(report.warnings.is_empty());
        assert!(!report.has_warnings());
    }

    #[test]
    fn test_creation_report_new() {
        let report = CreationReport::new();
        assert_eq!(report.files_added, 0);
        assert!(!report.has_warnings());
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_creation_report_compression_ratio() {
        let mut report = CreationReport::new();

        // Normal case: 2:1 compression
        report.bytes_written = 1000;
        report.bytes_compressed = 500;
        assert_eq!(report.compression_ratio(), 2.0);

        // Edge case: no compression (1:1)
        report.bytes_written = 1000;
        report.bytes_compressed = 1000;
        assert_eq!(report.compression_ratio(), 1.0);

        // Edge case: expansion (worse than no compression)
        report.bytes_written = 500;
        report.bytes_compressed = 1000;
        assert_eq!(report.compression_ratio(), 0.5);

        // Edge case: zero compressed size
        report.bytes_written = 1000;
        report.bytes_compressed = 0;
        assert_eq!(report.compression_ratio(), 0.0);

        // Edge case: zero written size
        report.bytes_written = 0;
        report.bytes_compressed = 500;
        assert_eq!(report.compression_ratio(), 0.0);

        // Edge case: both zero
        report.bytes_written = 0;
        report.bytes_compressed = 0;
        assert_eq!(report.compression_ratio(), 0.0);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_creation_report_compression_percentage() {
        let mut report = CreationReport::new();

        // 50% compression
        report.bytes_written = 1000;
        report.bytes_compressed = 500;
        assert_eq!(report.compression_percentage(), 50.0);

        // 75% compression
        report.bytes_written = 1000;
        report.bytes_compressed = 250;
        assert_eq!(report.compression_percentage(), 75.0);

        // No compression
        report.bytes_written = 1000;
        report.bytes_compressed = 1000;
        assert_eq!(report.compression_percentage(), 0.0);

        // Expansion (negative compression)
        report.bytes_written = 500;
        report.bytes_compressed = 1000;
        assert_eq!(report.compression_percentage(), 0.0);

        // Edge case: perfect compression
        report.bytes_written = 1000;
        report.bytes_compressed = 0;
        assert_eq!(report.compression_percentage(), 100.0);

        // Edge case: zero written
        report.bytes_written = 0;
        report.bytes_compressed = 500;
        assert_eq!(report.compression_percentage(), 0.0);

        // Edge case: both zero
        report.bytes_written = 0;
        report.bytes_compressed = 0;
        assert_eq!(report.compression_percentage(), 0.0);
    }

    #[test]
    fn test_creation_report_warnings() {
        let mut report = CreationReport::new();
        assert!(!report.has_warnings());

        report.add_warning("Warning 1");
        assert!(report.has_warnings());
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.warnings[0], "Warning 1");

        report.add_warning("Warning 2".to_string());
        assert_eq!(report.warnings.len(), 2);
        assert_eq!(report.warnings[1], "Warning 2");

        let string_ref = String::from("Warning 3");
        report.add_warning(&string_ref);
        assert_eq!(report.warnings.len(), 3);
    }

    #[test]
    fn test_creation_report_total_items() {
        let mut report = CreationReport::new();
        assert_eq!(report.total_items(), 0);

        report.files_added = 10;
        report.directories_added = 5;
        report.symlinks_added = 2;
        assert_eq!(report.total_items(), 17);

        report.files_added = 0;
        assert_eq!(report.total_items(), 7);
    }

    #[test]
    fn test_creation_report_real_scenario() {
        let mut report = CreationReport::new();
        report.files_added = 100;
        report.directories_added = 20;
        report.symlinks_added = 5;
        report.bytes_written = 10 * 1024 * 1024; // 10 MB
        report.bytes_compressed = 3 * 1024 * 1024; // 3 MB
        report.duration = Duration::from_secs(2);
        report.files_skipped = 3;
        report.add_warning("Skipped 3 files due to size limit");

        assert_eq!(report.total_items(), 125);
        assert!(report.has_warnings());
        assert_eq!(report.warnings.len(), 1);

        // Compression ratio should be ~3.33 (10MB / 3MB)
        let ratio = report.compression_ratio();
        assert!((ratio - 3.333).abs() < 0.01);

        // Compression percentage should be ~70% ((10-3)/10 * 100)
        let percentage = report.compression_percentage();
        assert!((percentage - 70.0).abs() < 0.1);
    }
}
