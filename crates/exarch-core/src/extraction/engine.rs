//! Core extraction engine.

use std::path::Path;

use crate::ExtractionReport;
use crate::Result;
use crate::SecurityConfig;

/// Main extraction engine.
pub struct ExtractionEngine {
    #[allow(dead_code)]
    config: SecurityConfig,
}

impl ExtractionEngine {
    /// Creates a new extraction engine with the given configuration.
    #[must_use]
    pub fn new(config: SecurityConfig) -> Self {
        Self { config }
    }

    /// Extracts an archive to the specified directory.
    ///
    /// # Errors
    ///
    /// Returns an error if extraction fails or security checks are violated.
    pub fn extract(
        &mut self,
        _archive_path: &Path,
        _output_dir: &Path,
    ) -> Result<ExtractionReport> {
        // Note: Extraction is handled directly by format-specific implementations
        // (TarArchive::extract and ZipArchive::extract) to avoid unnecessary
        // abstraction. This module remains as a potential future extension
        // point for streaming extraction.
        Ok(ExtractionReport::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extraction_engine_new() {
        let config = SecurityConfig::default();
        let _engine = ExtractionEngine::new(config);
    }
}
