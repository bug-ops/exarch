//! Configuration for archive creation operations.

use crate::ArchiveError;
use crate::Limit;
use crate::Result;
use crate::creation::filters::ExcludePattern;
use std::num::NonZeroU64;
use std::path::PathBuf;

/// A compression level on exarch's 1-9 scale; the default is 6.
///
/// Built only through [`TryFrom<u8>`] / [`TryFrom<u32>`], so the range is
/// checked once at the boundary and every codec mapping can rely on it.
///
/// # Examples
///
/// ```
/// use exarch_core::creation::CompressionLevel;
///
/// let level = CompressionLevel::try_from(9u8)?;
/// assert_eq!(level.get(), 9);
/// assert_eq!(CompressionLevel::default().get(), 6);
/// assert!(CompressionLevel::try_from(0u8).is_err());
/// assert!(CompressionLevel::try_from(10u32).is_err());
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompressionLevel(u8);

impl CompressionLevel {
    /// The level on the 1-9 scale.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl Default for CompressionLevel {
    fn default() -> Self {
        Self(6)
    }
}

impl TryFrom<u8> for CompressionLevel {
    type Error = ArchiveError;

    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidCompressionLevel`] if `level` is not in
    /// 1-9.
    fn try_from(level: u8) -> Result<Self> {
        if (1..=9).contains(&level) {
            Ok(Self(level))
        } else {
            Err(ArchiveError::InvalidCompressionLevel {
                level: u32::from(level),
            })
        }
    }
}

impl TryFrom<u32> for CompressionLevel {
    type Error = ArchiveError;

    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidCompressionLevel`] if `level` is not in
    /// 1-9.
    fn try_from(level: u32) -> Result<Self> {
        u8::try_from(level)
            .ok()
            .and_then(|level| Self::try_from(level).ok())
            .ok_or(ArchiveError::InvalidCompressionLevel { level })
    }
}

/// Configuration for archive creation operations.
///
/// Controls how archives are created from filesystem sources, including
/// security options, compression settings, and file filtering.
///
/// # Examples
///
/// ```
/// use exarch_core::creation::CompressionLevel;
/// use exarch_core::creation::CreationConfig;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Use secure defaults
/// let config = CreationConfig::default();
///
/// // Customize for specific needs
/// let custom = CreationConfig::default()
///     .with_follow_symlinks(true)
///     .with_compression_level(CompressionLevel::try_from(9u8)?);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
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
    /// [`Limit::Unbounded`] means no limit; a zero limit is unrepresentable.
    ///
    /// Default: [`Limit::Unbounded`].
    pub max_file_size: Limit<NonZeroU64>,

    /// Patterns to exclude from the archive.
    ///
    /// Files matching these patterns will be skipped.
    ///
    /// Default: `[".git", ".DS_Store", "*.tmp"]`.
    pub exclude_patterns: Vec<ExcludePattern>,

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
    ///
    /// Default: 6 (balanced).
    pub compression_level: CompressionLevel,

    /// Preserve file permissions in the archive.
    ///
    /// Default: `true`.
    pub preserve_permissions: bool,
}

impl Default for CreationConfig {
    /// Creates a `CreationConfig` with secure default settings.
    ///
    /// Default values:
    /// - `follow_symlinks`: `false`
    /// - `include_hidden`: `false`
    /// - `max_file_size`: [`Limit::Unbounded`]
    /// - `exclude_patterns`: `[".git", ".DS_Store", "*.tmp"]`
    /// - `strip_prefix`: `None`
    /// - `compression_level`: 6
    /// - `preserve_permissions`: `true`
    fn default() -> Self {
        Self {
            follow_symlinks: false,
            include_hidden: false,
            max_file_size: Limit::Unbounded,
            exclude_patterns: vec![
                ExcludePattern::exact(".git"),
                ExcludePattern::exact(".DS_Store"),
                ExcludePattern::suffix(".tmp"),
            ],
            strip_prefix: None,
            compression_level: CompressionLevel::default(),
            preserve_permissions: true,
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
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::CreationConfig;
    ///
    /// let config = CreationConfig::default().with_follow_symlinks(true);
    /// assert!(config.follow_symlinks);
    /// ```
    #[must_use]
    pub fn with_follow_symlinks(mut self, follow: bool) -> Self {
        self.follow_symlinks = follow;
        self
    }

    /// Sets whether to include hidden files.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::CreationConfig;
    ///
    /// let config = CreationConfig::default().with_include_hidden(true);
    /// assert!(config.include_hidden);
    /// ```
    #[must_use]
    pub fn with_include_hidden(mut self, include: bool) -> Self {
        self.include_hidden = include;
        self
    }

    /// Sets the maximum file size; larger files are skipped.
    ///
    /// Pass a [`NonZeroU64`] for a bound or [`Limit::Unbounded`] for none.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::Limit;
    /// use exarch_core::creation::CreationConfig;
    ///
    /// let config = CreationConfig::default().with_max_file_size(exarch_core::non_zero!(1024 * 1024));
    /// assert!(config.max_file_size.admits(1024 * 1024));
    /// assert!(!config.max_file_size.admits(1024 * 1024 + 1));
    ///
    /// let config = config.with_max_file_size(Limit::Unbounded);
    /// assert_eq!(config.max_file_size, Limit::Unbounded);
    /// ```
    #[must_use]
    pub fn with_max_file_size(mut self, max_size: impl Into<Limit<NonZeroU64>>) -> Self {
        self.max_file_size = max_size.into();
        self
    }

    /// Sets the exclude patterns.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::CreationConfig;
    /// use exarch_core::creation::ExcludePattern;
    ///
    /// let log = ExcludePattern::try_from("*.log")?;
    /// let config = CreationConfig::default().with_exclude_patterns(vec![log.clone()]);
    /// assert_eq!(config.exclude_patterns, vec![log]);
    /// # Ok::<(), exarch_core::ArchiveError>(())
    /// ```
    #[must_use]
    pub fn with_exclude_patterns(mut self, patterns: Vec<ExcludePattern>) -> Self {
        self.exclude_patterns = patterns;
        self
    }

    /// Sets the strip prefix.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::CreationConfig;
    /// use std::path::PathBuf;
    ///
    /// let config = CreationConfig::default().with_strip_prefix(Some(PathBuf::from("/base")));
    /// assert_eq!(config.strip_prefix, Some(PathBuf::from("/base")));
    /// ```
    #[must_use]
    pub fn with_strip_prefix(mut self, prefix: Option<PathBuf>) -> Self {
        self.strip_prefix = prefix;
        self
    }

    /// Sets the compression level.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::CompressionLevel;
    /// use exarch_core::creation::CreationConfig;
    ///
    /// let level = CompressionLevel::try_from(9u8)?;
    /// let config = CreationConfig::default().with_compression_level(level);
    /// assert_eq!(config.compression_level, level);
    /// # Ok::<(), exarch_core::ArchiveError>(())
    /// ```
    #[must_use]
    pub fn with_compression_level(mut self, level: CompressionLevel) -> Self {
        self.compression_level = level;
        self
    }

    /// Sets whether to preserve permissions.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::CreationConfig;
    ///
    /// let config = CreationConfig::default().with_preserve_permissions(false);
    /// assert!(!config.preserve_permissions);
    /// ```
    #[must_use]
    pub fn with_preserve_permissions(mut self, preserve: bool) -> Self {
        self.preserve_permissions = preserve;
        self
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn test_creation_config_default() {
        let config = CreationConfig::default();
        assert!(!config.follow_symlinks);
        assert!(!config.include_hidden);
        assert_eq!(config.max_file_size, Limit::Unbounded);
        assert_eq!(config.exclude_patterns.len(), 3);
        let shown: Vec<String> = config
            .exclude_patterns
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(shown, [".git", ".DS_Store", "*.tmp"]);
        assert_eq!(config.strip_prefix, None);
        assert_eq!(config.compression_level, CompressionLevel::default());
        assert!(config.preserve_permissions);
    }

    #[test]
    fn test_creation_config_builder() {
        let level = CompressionLevel::try_from(9u8).unwrap();
        let config = CreationConfig::default()
            .with_follow_symlinks(true)
            .with_include_hidden(true)
            .with_max_file_size(crate::non_zero!(1024 * 1024))
            .with_exclude_patterns(vec![ExcludePattern::try_from("*.log").unwrap()])
            .with_strip_prefix(Some(PathBuf::from("/base")))
            .with_compression_level(level)
            .with_preserve_permissions(false);

        assert!(config.follow_symlinks);
        assert!(config.include_hidden);
        assert_eq!(
            config.max_file_size,
            Limit::Bounded(crate::non_zero!(1024 * 1024))
        );
        assert_eq!(
            config.exclude_patterns,
            vec![ExcludePattern::try_from("*.log").unwrap()]
        );
        assert_eq!(config.strip_prefix, Some(PathBuf::from("/base")));
        assert_eq!(config.compression_level, level);
        assert!(!config.preserve_permissions);
    }

    #[test]
    fn test_compression_level_refuses_out_of_range() {
        for level in [0u8, 10, 200] {
            assert_matches!(
                CompressionLevel::try_from(level),
                Err(ArchiveError::InvalidCompressionLevel { level: l }) if l == u32::from(level)
            );
        }
        for level in [0u32, 10, 256, 4_294_967_295] {
            assert_matches!(
                CompressionLevel::try_from(level),
                Err(ArchiveError::InvalidCompressionLevel { level: l }) if l == level
            );
        }
    }

    #[test]
    fn test_compression_level_accepts_the_whole_scale() {
        for level in 1u8..=9 {
            assert_eq!(CompressionLevel::try_from(level).unwrap().get(), level);
            assert_eq!(
                CompressionLevel::try_from(u32::from(level)).unwrap().get(),
                level
            );
        }
        assert_eq!(CompressionLevel::default().get(), 6);
    }

    #[test]
    fn test_creation_config_new() {
        let config = CreationConfig::new();
        assert_eq!(config.compression_level, CompressionLevel::default());
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
            config
                .exclude_patterns
                .contains(&ExcludePattern::exact(".git")),
            "should exclude .git by default"
        );
    }
}
