//! Extraction quota tracking and validation.

use crate::{ExtractionError, Result, SecurityConfig};

/// Tracks resource usage during extraction.
#[derive(Debug, Default)]
pub struct QuotaTracker {
    files_extracted: usize,
    bytes_written: u64,
}

impl QuotaTracker {
    /// Creates a new quota tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a file extraction.
    ///
    /// # Errors
    ///
    /// Returns an error if quotas are exceeded.
    pub fn record_file(&mut self, size: u64, config: &SecurityConfig) -> Result<()> {
        self.files_extracted += 1;
        self.bytes_written += size;

        if self.files_extracted > config.max_file_count {
            return Err(ExtractionError::QuotaExceeded {
                resource: format!("file count ({} > {})", self.files_extracted, config.max_file_count),
            });
        }

        if self.bytes_written > config.max_total_size {
            return Err(ExtractionError::QuotaExceeded {
                resource: format!("total size ({} > {})", self.bytes_written, config.max_total_size),
            });
        }

        if size > config.max_file_size {
            return Err(ExtractionError::QuotaExceeded {
                resource: format!("single file size ({} > {})", size, config.max_file_size),
            });
        }

        Ok(())
    }

    /// Returns the number of files extracted.
    #[must_use]
    pub fn files_extracted(&self) -> usize {
        self.files_extracted
    }

    /// Returns the total bytes written.
    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quota_tracker_new() {
        let tracker = QuotaTracker::new();
        assert_eq!(tracker.files_extracted(), 0);
        assert_eq!(tracker.bytes_written(), 0);
    }

    #[test]
    fn test_quota_tracker_record_file() {
        let mut tracker = QuotaTracker::new();
        let config = SecurityConfig::default();

        assert!(tracker.record_file(1000, &config).is_ok());
        assert_eq!(tracker.files_extracted(), 1);
        assert_eq!(tracker.bytes_written(), 1000);
    }

    #[test]
    fn test_quota_tracker_exceed_file_count() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_count = 2;

        assert!(tracker.record_file(100, &config).is_ok());
        assert!(tracker.record_file(100, &config).is_ok());
        let result = tracker.record_file(100, &config);
        assert!(matches!(result, Err(ExtractionError::QuotaExceeded { .. })));
    }

    #[test]
    fn test_quota_tracker_exceed_total_size() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_total_size = 1000;

        assert!(tracker.record_file(600, &config).is_ok());
        let result = tracker.record_file(500, &config);
        assert!(matches!(result, Err(ExtractionError::QuotaExceeded { .. })));
    }

    #[test]
    fn test_quota_tracker_exceed_file_size() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_size = 1000;

        let result = tracker.record_file(2000, &config);
        assert!(matches!(result, Err(ExtractionError::QuotaExceeded { .. })));
    }
}
