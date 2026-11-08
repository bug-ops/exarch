//! Configuration for archive creation operations.

use crate::ArchiveError;
use crate::Limit;
use crate::PermissionPolicy;
use crate::Result;
use crate::creation::exclude_pattern::ExcludePattern;
use crate::error::RequestedLevel;
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
/// use exarch_core::CompressionLevel;
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
                level: RequestedLevel::Integer(i64::from(level)),
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
        Self::from_i128(i128::from(level))
    }
}

impl CompressionLevel {
    /// Parses an integer of any width, as a binding receives it.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidCompressionLevel`] carrying the
    /// requested value if it is not in 1-9.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::CompressionLevel;
    ///
    /// assert_eq!(CompressionLevel::from_i128(9)?.get(), 9);
    /// assert!(CompressionLevel::from_i128(-3).is_err());
    /// assert!(CompressionLevel::from_i128(1 << 40).is_err());
    /// # Ok::<(), exarch_core::ArchiveError>(())
    /// ```
    pub fn from_i128(level: i128) -> Result<Self> {
        u8::try_from(level)
            .ok()
            .filter(|level| (1..=9).contains(level))
            .map(Self)
            .ok_or_else(|| ArchiveError::InvalidCompressionLevel {
                level: i64::try_from(level)
                    .map_or(RequestedLevel::OutOfRange, RequestedLevel::Integer),
            })
    }

    /// Parses a floating-point number, as a JavaScript caller passes it.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidCompressionLevel`] carrying the
    /// requested value for a non-finite number, a fractional number or a whole
    /// number outside 1-9.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::CompressionLevel;
    ///
    /// assert_eq!(CompressionLevel::from_f64(6.0)?.get(), 6);
    /// assert!(CompressionLevel::from_f64(1.5).is_err());
    /// assert!(CompressionLevel::from_f64(f64::NAN).is_err());
    /// # Ok::<(), exarch_core::ArchiveError>(())
    /// ```
    #[expect(
        clippy::cast_possible_truncation,
        reason = "a whole number saturated by `as`; any value outside 1-9 is refused by from_i128"
    )]
    pub fn from_f64(level: f64) -> Result<Self> {
        if !level.is_finite() {
            return Err(ArchiveError::InvalidCompressionLevel {
                level: RequestedLevel::NonFinite,
            });
        }
        if level.fract() != 0.0 {
            return Err(ArchiveError::InvalidCompressionLevel {
                level: RequestedLevel::Fractional(level),
            });
        }
        Self::from_i128(level as i128)
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
/// use exarch_core::CompressionLevel;
/// use exarch_core::CreationConfig;
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

    /// Include hidden entries (names starting with '.').
    ///
    /// When `false`, a hidden file is skipped and a hidden directory below a
    /// source directory is skipped whole: it is never entered, so nothing
    /// inside it (`.ssh/id_rsa`, `.aws/credentials`) is archived, even under a
    /// visible name. The skipped directory is counted once as a hidden skip.
    /// A hidden source directory named by the caller, and a source file named
    /// directly, are archived regardless.
    ///
    /// The name on disk decides, before `strip_prefix` applies. With
    /// [`follow_symlinks`](Self::follow_symlinks) a link is judged by its own
    /// visible name, not its target's: a link `keys -> .ssh` is archived (its
    /// contents under `keys/`), while a hidden-named link to a directory is
    /// skipped.
    ///
    /// Default: `false` (skip hidden entries).
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

    /// Whether file permissions are stored in the archive.
    ///
    /// Default: [`PermissionPolicy::Preserve`].
    pub permissions: PermissionPolicy,
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
    /// - `permissions`: [`PermissionPolicy::Preserve`]
    fn default() -> Self {
        Self {
            follow_symlinks: false,
            include_hidden: false,
            max_file_size: Limit::Unbounded,
            exclude_patterns: vec![
                ExcludePattern::literal_name(".git"),
                ExcludePattern::literal_name(".DS_Store"),
                ExcludePattern::suffix_name(".tmp"),
            ],
            strip_prefix: None,
            compression_level: CompressionLevel::default(),
            permissions: PermissionPolicy::Preserve,
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
    /// use exarch_core::CreationConfig;
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
    /// use exarch_core::CreationConfig;
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
    /// use exarch_core::CreationConfig;
    /// use exarch_core::Limit;
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
    /// use exarch_core::CreationConfig;
    /// use exarch_core::ExcludePattern;
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
    /// use exarch_core::CreationConfig;
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
    /// use exarch_core::CompressionLevel;
    /// use exarch_core::CreationConfig;
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
    /// use exarch_core::CreationConfig;
    ///
    /// let config = CreationConfig::default().with_preserve_permissions(false);
    /// assert!(!config.permissions.preserves());
    /// ```
    #[must_use]
    pub fn with_preserve_permissions(mut self, preserve: bool) -> Self {
        self.permissions = PermissionPolicy::from_preserve(preserve);
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
        assert!(config.permissions.preserves());
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
        assert!(!config.permissions.preserves());
    }

    #[test]
    fn test_compression_level_refuses_out_of_range() {
        for level in [0u8, 10, 200] {
            assert_matches!(
                CompressionLevel::try_from(level),
                Err(ArchiveError::InvalidCompressionLevel { level: RequestedLevel::Integer(l) }) if l == i64::from(level)
            );
        }
        for level in [0u32, 10, 256, 4_294_967_295] {
            assert_matches!(
                CompressionLevel::try_from(level),
                Err(ArchiveError::InvalidCompressionLevel { level: RequestedLevel::Integer(l) }) if l == i64::from(level)
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
        assert!(config.permissions.preserves());
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
                .contains(&ExcludePattern::literal_name(".git")),
            "should exclude .git by default"
        );
    }
}
