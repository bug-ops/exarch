//! Extraction quota tracking and validation.

use crate::ExtractionError;
use crate::Result;
use crate::SecurityConfig;

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
    /// Returns an error if quotas are exceeded or integer overflow is detected.
    pub fn record_file(&mut self, size: u64, config: &SecurityConfig) -> Result<()> {
        // Check single file size quota first (before updating counters)
        if size > config.max_file_size {
            return Err(ExtractionError::QuotaExceeded {
                resource: crate::QuotaResource::FileSize {
                    size,
                    max: config.max_file_size,
                },
            });
        }

        // Update file count with overflow check
        self.files_extracted = self
            .files_extracted
            .checked_add(1)
            .ok_or(ExtractionError::QuotaExceeded {
                resource: crate::QuotaResource::IntegerOverflow,
            })?;

        // Update bytes written with overflow check
        self.bytes_written = self
            .bytes_written
            .checked_add(size)
            .ok_or(ExtractionError::QuotaExceeded {
                resource: crate::QuotaResource::IntegerOverflow,
            })?;

        // Check file count quota
        if self.files_extracted > config.max_file_count {
            return Err(ExtractionError::QuotaExceeded {
                resource: crate::QuotaResource::FileCount {
                    current: self.files_extracted,
                    max: config.max_file_count,
                },
            });
        }

        // Check total size quota
        if self.bytes_written > config.max_total_size {
            return Err(ExtractionError::QuotaExceeded {
                resource: crate::QuotaResource::TotalSize {
                    current: self.bytes_written,
                    max: config.max_total_size,
                },
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
#[allow(clippy::field_reassign_with_default)]
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

    // H-TEST-4: Quota boundary conditions test
    #[test]
    fn test_quota_exactly_at_file_count_limit() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_count = 3;
        config.max_total_size = u64::MAX;
        config.max_file_size = u64::MAX;

        // Exactly at file count limit should succeed
        assert!(
            tracker.record_file(100, &config).is_ok(),
            "file 1 should succeed"
        );
        assert!(
            tracker.record_file(100, &config).is_ok(),
            "file 2 should succeed"
        );
        assert!(
            tracker.record_file(100, &config).is_ok(),
            "file 3 should succeed"
        );
        assert_eq!(tracker.files_extracted(), 3, "should have 3 files");

        // One more should fail (exceeds limit)
        let result = tracker.record_file(100, &config);
        assert!(
            matches!(
                result,
                Err(ExtractionError::QuotaExceeded {
                    resource: crate::QuotaResource::FileCount { current: 4, max: 3 }
                })
            ),
            "file 4 should exceed quota"
        );
    }

    #[test]
    fn test_quota_exactly_at_total_size_limit() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_count = 100;
        config.max_total_size = 1000;
        config.max_file_size = u64::MAX;

        // Add files up to exactly the limit
        assert!(tracker.record_file(600, &config).is_ok());
        assert_eq!(tracker.bytes_written(), 600);

        assert!(tracker.record_file(400, &config).is_ok());
        assert_eq!(
            tracker.bytes_written(),
            1000,
            "should be exactly at limit"
        );

        // One more byte should fail
        let result = tracker.record_file(1, &config);
        assert!(
            matches!(
                result,
                Err(ExtractionError::QuotaExceeded {
                    resource: crate::QuotaResource::TotalSize { current: 1001, max: 1000 }
                })
            ),
            "exceeding total size should fail"
        );
    }

    #[test]
    fn test_quota_exactly_at_file_size_limit() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_count = 100;
        config.max_total_size = u64::MAX;
        config.max_file_size = 5000;

        // File exactly at limit should succeed
        assert!(
            tracker.record_file(5000, &config).is_ok(),
            "file exactly at limit should succeed"
        );

        // File one byte over should fail
        let result = tracker.record_file(5001, &config);
        assert!(
            matches!(
                result,
                Err(ExtractionError::QuotaExceeded {
                    resource: crate::QuotaResource::FileSize { size: 5001, max: 5000 }
                })
            ),
            "file exceeding limit should fail"
        );
    }

    #[test]
    fn test_quota_off_by_one_file_count() {
        let mut tracker = QuotaTracker::new();
        let mut config = SecurityConfig::default();
        config.max_file_count = 1;
        config.max_total_size = u64::MAX;
        config.max_file_size = u64::MAX;

        // First file should succeed
        assert!(tracker.record_file(100, &config).is_ok());

        // Second file should fail (max is 1)
        let result = tracker.record_file(100, &config);
        assert!(matches!(
            result,
            Err(ExtractionError::QuotaExceeded { .. })
        ));
    }
}
