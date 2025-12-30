//! Archive types and builders.

use std::path::Path;
use std::path::PathBuf;

use crate::ExtractionReport;
use crate::Result;
use crate::SecurityConfig;

/// Represents an archive file with associated metadata.
#[derive(Debug)]
pub struct Archive {
    path: PathBuf,
    config: SecurityConfig,
}

impl Archive {
    /// Creates a new `Archive` from a file path.
    ///
    /// # Errors
    ///
    /// Returns an error if the file doesn't exist or cannot be accessed.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        Ok(Self {
            path,
            config: SecurityConfig::default(),
        })
    }

    /// Returns the path to the archive file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns a reference to the security configuration.
    #[must_use]
    pub fn config(&self) -> &SecurityConfig {
        &self.config
    }

    /// Extracts the archive to the specified directory.
    ///
    /// # Errors
    ///
    /// Returns an error if extraction fails or security checks are violated.
    pub fn extract<P: AsRef<Path>>(&self, output_dir: P) -> Result<ExtractionReport> {
        let _output_dir = output_dir.as_ref();
        // TODO: Implement extraction
        Ok(ExtractionReport::new())
    }
}

/// Builder for configuring archive extraction.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::ArchiveBuilder;
/// use exarch_core::SecurityConfig;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let report = ArchiveBuilder::new()
///     .archive("archive.tar.gz")
///     .output_dir("/tmp/output")
///     .config(SecurityConfig::permissive())
///     .extract()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Default)]
pub struct ArchiveBuilder {
    archive_path: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    config: Option<SecurityConfig>,
}

impl ArchiveBuilder {
    /// Creates a new `ArchiveBuilder`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the archive file path.
    #[must_use]
    pub fn archive<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.archive_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Sets the output directory.
    #[must_use]
    pub fn output_dir<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.output_dir = Some(path.as_ref().to_path_buf());
        self
    }

    /// Sets the security configuration.
    #[must_use]
    pub fn config(mut self, config: SecurityConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Executes the extraction with the configured settings.
    ///
    /// # Errors
    ///
    /// Returns an error if archive_path or output_dir are not set,
    /// or if extraction fails.
    pub fn extract(self) -> Result<ExtractionReport> {
        let archive_path =
            self.archive_path
                .ok_or_else(|| crate::ExtractionError::SecurityViolation {
                    reason: "archive path not set".to_string(),
                })?;

        let output_dir =
            self.output_dir
                .ok_or_else(|| crate::ExtractionError::SecurityViolation {
                    reason: "output directory not set".to_string(),
                })?;

        let config = self.config.unwrap_or_default();

        crate::api::extract_archive(archive_path, output_dir, &config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_archive_builder() {
        let builder = ArchiveBuilder::new()
            .archive("test.tar")
            .output_dir("/tmp/test");

        assert!(builder.archive_path.is_some());
        assert!(builder.output_dir.is_some());
    }

    #[test]
    fn test_archive_builder_missing_path() {
        let builder = ArchiveBuilder::new().output_dir("/tmp/test");
        let result = builder.extract();
        assert!(result.is_err());
    }

    #[test]
    fn test_archive_builder_missing_output() {
        let builder = ArchiveBuilder::new().archive("test.tar");
        let result = builder.extract();
        assert!(result.is_err());
    }
}
