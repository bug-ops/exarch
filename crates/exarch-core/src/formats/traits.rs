//! Common traits for archive format handlers.

use std::path::Path;

use crate::ExtractionOptions;
use crate::ExtractionReport;
use crate::Result;
use crate::SecurityConfig;

/// Trait for archive format handlers.
pub trait ArchiveFormat {
    /// Extracts the archive to the specified directory.
    ///
    /// # Errors
    ///
    /// Returns an error if extraction fails or security checks are violated.
    fn extract(
        &mut self,
        output_dir: &Path,
        config: &SecurityConfig,
        options: &ExtractionOptions,
    ) -> Result<ExtractionReport>;

    /// Returns the archive format name.
    fn format_name(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestFormat;

    impl ArchiveFormat for TestFormat {
        fn extract(
            &mut self,
            _output_dir: &Path,
            _config: &SecurityConfig,
            _options: &ExtractionOptions,
        ) -> Result<ExtractionReport> {
            Ok(ExtractionReport::new())
        }

        fn format_name(&self) -> &'static str {
            "test"
        }
    }

    #[test]
    fn test_trait_implementation() {
        let format = TestFormat;
        assert_eq!(format.format_name(), "test");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_trait_extract_returns_report() {
        let mut format = TestFormat;
        let temp = tempfile::TempDir::new().unwrap();
        let config = SecurityConfig::default();
        let options = ExtractionOptions::default();
        let report = format.extract(temp.path(), &config, &options).unwrap();
        assert_eq!(report.files_extracted, 0);
    }
}
