//! Tar archive format handler.

use std::path::Path;

use crate::{ExtractionReport, Result, SecurityConfig};

use super::traits::ArchiveFormat;

/// Tar archive handler.
pub struct TarArchive;

impl TarArchive {
    /// Creates a new tar archive handler.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for TarArchive {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchiveFormat for TarArchive {
    fn extract(&mut self, _output_dir: &Path, _config: &SecurityConfig) -> Result<ExtractionReport> {
        // TODO: Implement tar extraction
        Ok(ExtractionReport::new())
    }

    fn format_name(&self) -> &str {
        "tar"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tar_archive_new() {
        let archive = TarArchive::new();
        assert_eq!(archive.format_name(), "tar");
    }
}
