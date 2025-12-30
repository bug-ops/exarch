//! Core extraction engine.

use std::path::Path;

use crate::{ExtractionReport, Result, SecurityConfig};

/// Main extraction engine.
pub struct ExtractionEngine {
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
    pub fn extract(&mut self, _archive_path: &Path, _output_dir: &Path) -> Result<ExtractionReport> {
        // TODO: Implement extraction engine
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
