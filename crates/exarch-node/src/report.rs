//! Node.js bindings for `ExtractionReport`.

use exarch_core::ExtractionReport as CoreReport;
use napi_derive::napi;

/// Report of an archive extraction operation.
///
/// Contains statistics and metadata about the extraction process.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct ExtractionReport {
    /// Number of files successfully extracted.
    pub files_extracted: u32,
    /// Number of directories created.
    pub directories_created: u32,
    /// Number of symlinks created.
    pub symlinks_created: u32,
    /// Total bytes written to disk.
    pub bytes_written: i64,
    /// Extraction duration in milliseconds.
    pub duration_ms: i64,
    /// Number of files skipped due to security checks.
    pub files_skipped: u32,
    /// List of warning messages.
    pub warnings: Vec<String>,
}

impl From<CoreReport> for ExtractionReport {
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    fn from(report: CoreReport) -> Self {
        // Use saturating conversions to prevent silent wraparound on overflow
        // This ensures audit trails remain accurate even for very large extractions
        Self {
            files_extracted: report.files_extracted.min(u32::MAX as usize) as u32,
            directories_created: report.directories_created.min(u32::MAX as usize) as u32,
            symlinks_created: report.symlinks_created.min(u32::MAX as usize) as u32,
            bytes_written: report.bytes_written.min(i64::MAX as u64) as i64,
            duration_ms: report.duration.as_millis().min(i64::MAX as u128) as i64,
            files_skipped: report.files_skipped.min(u32::MAX as usize) as u32,
            warnings: report.warnings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_extraction_report_conversion() {
        let mut core_report = CoreReport::new();
        core_report.files_extracted = 10;
        core_report.directories_created = 5;
        core_report.symlinks_created = 2;
        core_report.bytes_written = 1024;
        core_report.duration = Duration::from_millis(500);
        core_report.files_skipped = 1;
        core_report.add_warning("Test warning".to_string());

        let report = ExtractionReport::from(core_report);

        assert_eq!(report.files_extracted, 10);
        assert_eq!(report.directories_created, 5);
        assert_eq!(report.symlinks_created, 2);
        assert_eq!(report.bytes_written, 1024);
        assert_eq!(report.duration_ms, 500);
        assert_eq!(report.files_skipped, 1);
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.warnings[0], "Test warning");
    }

    #[test]
    fn test_extraction_report_zero_values() {
        let core_report = CoreReport::new();
        let report = ExtractionReport::from(core_report);

        assert_eq!(report.files_extracted, 0);
        assert_eq!(report.directories_created, 0);
        assert_eq!(report.symlinks_created, 0);
        assert_eq!(report.bytes_written, 0);
        assert_eq!(report.files_skipped, 0);
        assert_eq!(report.warnings.len(), 0);
    }

    #[test]
    fn test_extraction_report_large_values() {
        let mut core_report = CoreReport::new();
        core_report.files_extracted = 100_000;
        core_report.directories_created = 50_000;
        core_report.bytes_written = 10_000_000_000; // 10 GB
        core_report.duration = Duration::from_secs(3600); // 1 hour

        let report = ExtractionReport::from(core_report);

        assert_eq!(report.files_extracted, 100_000);
        assert_eq!(report.bytes_written, 10_000_000_000);
        assert_eq!(report.duration_ms, 3_600_000);
    }

    #[test]
    fn test_extraction_report_multiple_warnings() {
        let mut core_report = CoreReport::new();
        core_report.add_warning("Warning 1".to_string());
        core_report.add_warning("Warning 2".to_string());
        core_report.add_warning("Warning 3".to_string());

        let report = ExtractionReport::from(core_report);

        assert_eq!(report.warnings.len(), 3);
        assert_eq!(report.warnings[0], "Warning 1");
        assert_eq!(report.warnings[1], "Warning 2");
        assert_eq!(report.warnings[2], "Warning 3");
    }

    #[test]
    fn test_extraction_report_duration_hours() {
        let mut core_report = CoreReport::new();
        core_report.duration = Duration::from_secs(7200); // 2 hours

        let report = ExtractionReport::from(core_report);

        assert_eq!(
            report.duration_ms, 7_200_000,
            "2 hours should be 7,200,000 milliseconds"
        );
    }

    #[test]
    fn test_extraction_report_duration_zero() {
        let mut core_report = CoreReport::new();
        core_report.duration = Duration::from_secs(0);

        let report = ExtractionReport::from(core_report);

        assert_eq!(report.duration_ms, 0, "zero duration should be 0 ms");
    }

    #[test]
    fn test_extraction_report_duration_microseconds() {
        let mut core_report = CoreReport::new();
        core_report.duration = Duration::from_micros(1500); // 1.5 ms

        let report = ExtractionReport::from(core_report);

        assert_eq!(
            report.duration_ms, 1,
            "1500 microseconds should round to 1 millisecond"
        );
    }

    #[test]
    fn test_extraction_report_warnings_order_preserved() {
        let mut core_report = CoreReport::new();
        core_report.add_warning("First warning".to_string());
        core_report.add_warning("Second warning".to_string());
        core_report.add_warning("Third warning".to_string());

        let report = ExtractionReport::from(core_report);

        assert_eq!(report.warnings.len(), 3, "should have 3 warnings");
        assert_eq!(
            report.warnings[0], "First warning",
            "first warning should be at index 0"
        );
        assert_eq!(
            report.warnings[1], "Second warning",
            "second warning should be at index 1"
        );
        assert_eq!(
            report.warnings[2], "Third warning",
            "third warning should be at index 2"
        );
    }
}
