//! Builder for creating archives with fluent API.

use std::path::Path;
use std::path::PathBuf;

use crate::creation::config::CreationConfig;
use crate::creation::report::CreationReport;
use crate::error::ExtractionError;
use crate::error::Result;
use crate::formats::detect::ArchiveType;

/// Builder for creating archives with fluent API.
///
/// Provides a convenient, type-safe interface for configuring and creating
/// archives with various compression formats and security options.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::creation::ArchiveCreator;
///
/// let report = ArchiveCreator::new()
///     .output("backup.tar.gz")
///     .add_source("src/")
///     .add_source("Cargo.toml")
///     .compression_level(9)
///     .create()?;
///
/// println!("Created archive with {} files", report.files_added);
/// # Ok::<(), exarch_core::ExtractionError>(())
/// ```
#[derive(Debug, Default)]
pub struct ArchiveCreator {
    output_path: Option<PathBuf>,
    sources: Vec<PathBuf>,
    config: CreationConfig,
}

impl ArchiveCreator {
    /// Creates a new `ArchiveCreator` with default settings.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::ArchiveCreator;
    ///
    /// let creator = ArchiveCreator::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the output archive path.
    ///
    /// The archive format is auto-detected from the file extension
    /// unless explicitly set via `format()`.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::ArchiveCreator;
    ///
    /// let creator = ArchiveCreator::new().output("backup.tar.gz");
    /// ```
    #[must_use]
    pub fn output<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.output_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Adds a source file or directory.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::ArchiveCreator;
    ///
    /// let creator = ArchiveCreator::new()
    ///     .add_source("src/")
    ///     .add_source("Cargo.toml");
    /// ```
    #[must_use]
    pub fn add_source<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.sources.push(path.as_ref().to_path_buf());
        self
    }

    /// Adds multiple source files or directories.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::ArchiveCreator;
    ///
    /// let creator = ArchiveCreator::new().sources(&["src/", "Cargo.toml", "README.md"]);
    /// ```
    #[must_use]
    pub fn sources<P: AsRef<Path>>(mut self, paths: &[P]) -> Self {
        self.sources
            .extend(paths.iter().map(|p| p.as_ref().to_path_buf()));
        self
    }

    /// Sets the full configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::ArchiveCreator;
    /// use exarch_core::creation::CreationConfig;
    ///
    /// let config = CreationConfig::default().with_follow_symlinks(true);
    ///
    /// let creator = ArchiveCreator::new().config(config);
    /// ```
    #[must_use]
    pub fn config(mut self, config: CreationConfig) -> Self {
        self.config = config;
        self
    }

    /// Sets the compression level (1-9).
    ///
    /// Higher values provide better compression but slower speed.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::ArchiveCreator;
    ///
    /// let creator = ArchiveCreator::new().compression_level(9); // Maximum compression
    /// ```
    #[must_use]
    pub fn compression_level(mut self, level: u8) -> Self {
        self.config.compression_level = Some(level);
        self
    }

    /// Sets whether to follow symlinks.
    ///
    /// Default: `false` (symlinks stored as symlinks).
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::ArchiveCreator;
    ///
    /// let creator = ArchiveCreator::new().follow_symlinks(true);
    /// ```
    #[must_use]
    pub fn follow_symlinks(mut self, follow: bool) -> Self {
        self.config.follow_symlinks = follow;
        self
    }

    /// Sets whether to include hidden files.
    ///
    /// Default: `false` (skip hidden files).
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::ArchiveCreator;
    ///
    /// let creator = ArchiveCreator::new().include_hidden(true);
    /// ```
    #[must_use]
    pub fn include_hidden(mut self, include: bool) -> Self {
        self.config.include_hidden = include;
        self
    }

    /// Adds an exclude pattern.
    ///
    /// Files matching this pattern will be skipped.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::ArchiveCreator;
    ///
    /// let creator = ArchiveCreator::new().exclude("*.log").exclude("target/");
    /// ```
    #[must_use]
    pub fn exclude<S: Into<String>>(mut self, pattern: S) -> Self {
        self.config.exclude_patterns.push(pattern.into());
        self
    }

    /// Sets the strip prefix for archive paths.
    ///
    /// If set, this prefix will be removed from all entry paths in the archive.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::ArchiveCreator;
    ///
    /// let creator = ArchiveCreator::new().strip_prefix("/base/path");
    /// ```
    #[must_use]
    pub fn strip_prefix<P: AsRef<Path>>(mut self, prefix: P) -> Self {
        self.config.strip_prefix = Some(prefix.as_ref().to_path_buf());
        self
    }

    /// Sets explicit archive format.
    ///
    /// If not set, format is auto-detected from output file extension.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::ArchiveCreator;
    /// use exarch_core::formats::detect::ArchiveType;
    ///
    /// let creator = ArchiveCreator::new().format(ArchiveType::TarGz);
    /// ```
    #[must_use]
    pub fn format(mut self, format: ArchiveType) -> Self {
        self.config.format = Some(format);
        self
    }

    /// Creates the archive.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Output path not set
    /// - No sources provided
    /// - Source files don't exist
    /// - I/O errors during creation
    /// - Invalid configuration (e.g., invalid compression level)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use exarch_core::creation::ArchiveCreator;
    ///
    /// let report = ArchiveCreator::new()
    ///     .output("backup.tar.gz")
    ///     .add_source("src/")
    ///     .create()?;
    /// # Ok::<(), exarch_core::ExtractionError>(())
    /// ```
    pub fn create(self) -> Result<CreationReport> {
        let output_path =
            self.output_path
                .ok_or_else(|| ExtractionError::InvalidConfiguration {
                    reason: "output path not set".to_string(),
                })?;

        if self.sources.is_empty() {
            return Err(ExtractionError::InvalidConfiguration {
                reason: "no source paths provided".to_string(),
            });
        }

        // Validate configuration
        self.config.validate()?;

        crate::api::create_archive(&output_path, &self.sources, &self.config)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::formats::detect::ArchiveType;
    use std::path::PathBuf;

    #[test]
    fn test_builder_basic() {
        let creator = ArchiveCreator::new()
            .output("test.tar.gz")
            .add_source("src/");

        assert_eq!(creator.output_path, Some(PathBuf::from("test.tar.gz")));
        assert_eq!(creator.sources, vec![PathBuf::from("src/")]);
    }

    #[test]
    fn test_builder_multiple_sources() {
        let creator = ArchiveCreator::new()
            .add_source("src/")
            .add_source("Cargo.toml")
            .add_source("README.md");

        assert_eq!(creator.sources.len(), 3);
        assert_eq!(creator.sources[0], PathBuf::from("src/"));
        assert_eq!(creator.sources[1], PathBuf::from("Cargo.toml"));
        assert_eq!(creator.sources[2], PathBuf::from("README.md"));
    }

    #[test]
    fn test_builder_sources_array() {
        let creator = ArchiveCreator::new().sources(&["src/", "Cargo.toml", "README.md"]);

        assert_eq!(creator.sources.len(), 3);
    }

    #[test]
    fn test_builder_config_methods() {
        let creator = ArchiveCreator::new()
            .compression_level(9)
            .follow_symlinks(true)
            .include_hidden(true)
            .exclude("*.log")
            .exclude("target/")
            .strip_prefix("/base")
            .format(ArchiveType::TarGz);

        assert_eq!(creator.config.compression_level, Some(9));
        assert!(creator.config.follow_symlinks);
        assert!(creator.config.include_hidden);
        assert!(
            creator
                .config
                .exclude_patterns
                .contains(&"*.log".to_string())
        );
        assert!(
            creator
                .config
                .exclude_patterns
                .contains(&"target/".to_string())
        );
        assert_eq!(creator.config.strip_prefix, Some(PathBuf::from("/base")));
        assert_eq!(creator.config.format, Some(ArchiveType::TarGz));
    }

    #[test]
    fn test_builder_no_output_error() {
        let creator = ArchiveCreator::new().add_source("src/");

        let result = creator.create();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ExtractionError::InvalidConfiguration { .. }
        ));
    }

    #[test]
    fn test_builder_no_sources_error() {
        let creator = ArchiveCreator::new().output("test.tar.gz");

        let result = creator.create();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ExtractionError::InvalidConfiguration { .. }
        ));
    }

    #[test]
    fn test_builder_compression_level() {
        let creator = ArchiveCreator::new().compression_level(9);

        assert_eq!(creator.config.compression_level, Some(9));
    }

    #[test]
    fn test_builder_exclude_patterns() {
        let creator = ArchiveCreator::new()
            .exclude("*.log")
            .exclude("*.tmp")
            .exclude(".git");

        assert!(
            creator
                .config
                .exclude_patterns
                .contains(&"*.log".to_string())
        );
        assert!(
            creator
                .config
                .exclude_patterns
                .contains(&"*.tmp".to_string())
        );
        assert!(
            creator
                .config
                .exclude_patterns
                .contains(&".git".to_string())
        );

        // Default exclude patterns should still be there
        assert!(
            creator
                .config
                .exclude_patterns
                .contains(&".DS_Store".to_string())
        );
    }

    #[test]
    fn test_builder_full_config() {
        let config = CreationConfig::default()
            .with_follow_symlinks(true)
            .with_compression_level(9);

        let creator = ArchiveCreator::new()
            .output("test.tar.gz")
            .add_source("src/")
            .config(config);

        assert!(creator.config.follow_symlinks);
        assert_eq!(creator.config.compression_level, Some(9));
    }

    #[test]
    fn test_builder_default() {
        let creator = ArchiveCreator::default();
        assert_eq!(creator.output_path, None);
        assert_eq!(creator.sources.len(), 0);
    }

    #[test]
    fn test_builder_new() {
        let creator = ArchiveCreator::new();
        assert_eq!(creator.output_path, None);
        assert_eq!(creator.sources.len(), 0);
    }
}
