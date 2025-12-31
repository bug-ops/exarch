//! Configuration for archive creation operations.

use crate::ExtractionError;
use crate::Result;
use crate::formats::detect::ArchiveType;
use std::path::PathBuf;

/// Configuration for archive creation operations.
///
/// Controls how archives are created from filesystem sources, including
/// security options, compression settings, and file filtering.
///
/// # Examples
///
/// ```
/// use exarch_core::creation::CreationConfig;
///
/// // Use secure defaults
/// let config = CreationConfig::default();
///
/// // Customize for specific needs
/// let custom = CreationConfig::default()
///     .with_follow_symlinks(true)
///     .with_compression_level(9);
/// ```
#[derive(Debug, Clone)]
pub struct CreationConfig {
    /// Follow symlinks when adding files to archive.
    ///
    /// Default: `false` (store symlinks as symlinks).
    ///
    /// Security note: Following symlinks may include unintended files
    /// from outside the source directory.
    pub follow_symlinks: bool,

    /// Include hidden files (files starting with '.').
    ///
    /// Default: `false` (skip hidden files).
    pub include_hidden: bool,

    /// Maximum size for a single file in bytes.
    ///
    /// Files larger than this limit will be skipped.
    /// `None` means no limit.
    ///
    /// Default: `None`.
    pub max_file_size: Option<u64>,

    /// Patterns to exclude from the archive.
    ///
    /// Files matching these patterns will be skipped.
    ///
    /// Default: `[".git", ".DS_Store", "*.tmp"]`.
    pub exclude_patterns: Vec<String>,

    /// Prefix to strip from entry paths in the archive.
    ///
    /// If set, this prefix will be removed from all entry paths.
    /// Useful for creating archives without deep directory nesting.
    ///
    /// Default: `None`.
    pub strip_prefix: Option<PathBuf>,

    /// Compression level (1-9).
    ///
    /// Higher values provide better compression but slower speed.
    /// `None` uses format-specific defaults.
    ///
    /// Default: `Some(6)` (balanced).
    ///
    /// Valid range: 1 (fastest) to 9 (best compression).
    pub compression_level: Option<u8>,

    /// Preserve file permissions in the archive.
    ///
    /// Default: `true`.
    pub preserve_permissions: bool,

    /// Archive format to create.
    ///
    /// `None` means auto-detect from output file extension.
    ///
    /// Default: `None`.
    pub format: Option<ArchiveType>,
}

impl Default for CreationConfig {
    /// Creates a `CreationConfig` with secure default settings.
    ///
    /// Default values:
    /// - `follow_symlinks`: `false`
    /// - `include_hidden`: `false`
    /// - `max_file_size`: `None`
    /// - `exclude_patterns`: `[".git", ".DS_Store", "*.tmp"]`
    /// - `strip_prefix`: `None`
    /// - `compression_level`: `Some(6)`
    /// - `preserve_permissions`: `true`
    /// - `format`: `None`
    fn default() -> Self {
        Self {
            follow_symlinks: false,
            include_hidden: false,
            max_file_size: None,
            exclude_patterns: vec![
                ".git".to_string(),
                ".DS_Store".to_string(),
                "*.tmp".to_string(),
            ],
            strip_prefix: None,
            compression_level: Some(6),
            preserve_permissions: true,
            format: None,
        }
    }
}

impl CreationConfig {
    /// Creates a new `CreationConfig` with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets whether to follow symlinks.
    #[must_use]
    pub fn with_follow_symlinks(mut self, follow: bool) -> Self {
        self.follow_symlinks = follow;
        self
    }

    /// Sets whether to include hidden files.
    #[must_use]
    pub fn with_include_hidden(mut self, include: bool) -> Self {
        self.include_hidden = include;
        self
    }

    /// Sets the maximum file size.
    #[must_use]
    pub fn with_max_file_size(mut self, max_size: Option<u64>) -> Self {
        self.max_file_size = max_size;
        self
    }

    /// Sets the exclude patterns.
    #[must_use]
    pub fn with_exclude_patterns(mut self, patterns: Vec<String>) -> Self {
        self.exclude_patterns = patterns;
        self
    }

    /// Sets the strip prefix.
    #[must_use]
    pub fn with_strip_prefix(mut self, prefix: Option<PathBuf>) -> Self {
        self.strip_prefix = prefix;
        self
    }

    /// Sets the compression level.
    ///
    /// # Panics
    ///
    /// Panics if the compression level is not in the range 1-9.
    /// Use `validate()` for non-panicking validation.
    #[must_use]
    pub fn with_compression_level(mut self, level: u8) -> Self {
        assert!((1..=9).contains(&level), "compression level must be 1-9");
        self.compression_level = Some(level);
        self
    }

    /// Sets whether to preserve permissions.
    #[must_use]
    pub fn with_preserve_permissions(mut self, preserve: bool) -> Self {
        self.preserve_permissions = preserve;
        self
    }

    /// Sets the archive format.
    #[must_use]
    pub fn with_format(mut self, format: Option<ArchiveType>) -> Self {
        self.format = format;
        self
    }

    /// Validates the configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Compression level is set but not in range 1-9
    pub fn validate(&self) -> Result<()> {
        if let Some(level) = self.compression_level
            && !(1..=9).contains(&level)
        {
            return Err(ExtractionError::InvalidCompressionLevel { level });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation_config_default() {
        let config = CreationConfig::default();
        assert!(!config.follow_symlinks);
        assert!(!config.include_hidden);
        assert_eq!(config.max_file_size, None);
        assert_eq!(config.exclude_patterns.len(), 3);
        assert!(config.exclude_patterns.contains(&".git".to_string()));
        assert!(config.exclude_patterns.contains(&".DS_Store".to_string()));
        assert!(config.exclude_patterns.contains(&"*.tmp".to_string()));
        assert_eq!(config.strip_prefix, None);
        assert_eq!(config.compression_level, Some(6));
        assert!(config.preserve_permissions);
        assert_eq!(config.format, None);
    }

    #[test]
    fn test_creation_config_builder() {
        let config = CreationConfig::default()
            .with_follow_symlinks(true)
            .with_include_hidden(true)
            .with_max_file_size(Some(1024 * 1024))
            .with_exclude_patterns(vec!["*.log".to_string()])
            .with_strip_prefix(Some(PathBuf::from("/base")))
            .with_compression_level(9)
            .with_preserve_permissions(false)
            .with_format(Some(ArchiveType::TarGz));

        assert!(config.follow_symlinks);
        assert!(config.include_hidden);
        assert_eq!(config.max_file_size, Some(1024 * 1024));
        assert_eq!(config.exclude_patterns, vec!["*.log".to_string()]);
        assert_eq!(config.strip_prefix, Some(PathBuf::from("/base")));
        assert_eq!(config.compression_level, Some(9));
        assert!(!config.preserve_permissions);
        assert_eq!(config.format, Some(ArchiveType::TarGz));
    }

    #[test]
    fn test_creation_config_validate_valid() {
        let config = CreationConfig::default();
        assert!(config.validate().is_ok());

        let config = CreationConfig::default().with_compression_level(1);
        assert!(config.validate().is_ok());

        let config = CreationConfig::default().with_compression_level(9);
        assert!(config.validate().is_ok());

        let config = CreationConfig {
            compression_level: None,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_creation_config_validate_invalid() {
        let config = CreationConfig {
            compression_level: Some(0),
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ExtractionError::InvalidCompressionLevel { level: 0 }
        ));

        let config = CreationConfig {
            compression_level: Some(10),
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ExtractionError::InvalidCompressionLevel { level: 10 }
        ));
    }

    #[test]
    #[should_panic(expected = "compression level must be 1-9")]
    fn test_creation_config_builder_invalid_compression() {
        let _config = CreationConfig::default().with_compression_level(0);
    }

    #[test]
    fn test_creation_config_new() {
        let config = CreationConfig::new();
        assert_eq!(config.compression_level, Some(6));
        assert!(config.preserve_permissions);
    }

    #[test]
    fn test_creation_config_secure_defaults() {
        let config = CreationConfig::default();

        // Security: Don't follow symlinks by default
        assert!(
            !config.follow_symlinks,
            "should not follow symlinks by default (security)"
        );

        // Security: Don't include hidden files by default
        assert!(
            !config.include_hidden,
            "should not include hidden files by default"
        );

        // Security: Exclude sensitive patterns
        assert!(
            config.exclude_patterns.contains(&".git".to_string()),
            "should exclude .git by default"
        );
    }
}
