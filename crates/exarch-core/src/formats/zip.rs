//! ZIP archive format handler.

use std::path::Path;

use crate::{ExtractionReport, Result, SecurityConfig};

use super::traits::ArchiveFormat;

/// ZIP archive handler.
pub struct ZipArchive;

impl ZipArchive {
    /// Creates a new ZIP archive handler.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for ZipArchive {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchiveFormat for ZipArchive {
    fn extract(&mut self, _output_dir: &Path, _config: &SecurityConfig) -> Result<ExtractionReport> {
        // TODO: Implement ZIP extraction
        Ok(ExtractionReport::new())
    }

    fn format_name(&self) -> &str {
        "zip"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zip_archive_new() {
        let archive = ZipArchive::new();
        assert_eq!(archive.format_name(), "zip");
    }
}
