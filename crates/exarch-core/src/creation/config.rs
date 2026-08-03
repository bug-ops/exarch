//! Configuration for archive creation operations.

use crate::ArchiveError;
use crate::Result;
use crate::config::Unvalidated;
use crate::config::Validated;
use crate::formats::detect::ArchiveType;
use std::marker::PhantomData;
use std::ops::Deref;
use std::ops::DerefMut;
use std::path::PathBuf;

/// The field data of a [`CreationConfig`], reachable via [`Deref`]/[`DerefMut`]
/// regardless of (or gated by) validation state.
///
/// Mirrors [`SecurityConfigFields`](crate::config::SecurityConfigFields): a
/// plain `#[non_exhaustive]` data bag that blocks external struct-literal
/// forging, while [`CreationConfig`]'s own private `fields` member blocks
/// re-wrapping a mutated bag into a `Validated` config. See that type's docs
/// for the full rationale — the same sealing boundary applies here.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CreationConfigFields {
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

impl Default for CreationConfigFields {
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
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Use secure defaults
/// let config = CreationConfig::default();
///
/// // Customize for specific needs
/// let custom = CreationConfig::default()
///     .with_follow_symlinks(true)
///     .with_compression_level(9)?;
/// # Ok(())
/// # }
/// ```
///
/// # Typestate
///
/// `CreationConfig` carries a phantom `State` type parameter —
/// [`Unvalidated`] (the default) or [`Validated`] — that tracks whether
/// [`validate`](CreationConfig::validate) has been called. Builder methods
/// are only available in the `Unvalidated` state; the low-level
/// `creation::tar::*` / `creation::zip::*` functions and
/// [`FormatCreator::create`](crate::formats::traits::FormatCreator::create)
/// require `CreationConfig<Validated>`. This makes skipping validation a
/// compile error instead of a runtime gap — a forged or hand-mutated
/// `compression_level` can no longer reach the `flate2`/`xz2` backends,
/// which panic on out-of-range values instead of returning an error.
///
/// # Sealing
///
/// Fields are private and reachable only through
/// <code>[Deref]<Target = [CreationConfigFields]></code>, so
/// `config.compression_level` continues to work as plain field access for
/// both states. [`DerefMut`] is implemented only for
/// `CreationConfig<Unvalidated>`, so a `CreationConfig<Validated>`'s fields
/// cannot be reassigned after the fact — the only way to produce one is
/// [`validate`](CreationConfig::validate) itself, and it stays that way for
/// its entire lifetime.
#[derive(Debug, Clone)]
pub struct CreationConfig<State = Unvalidated> {
    fields: CreationConfigFields,

    /// Typestate marker — see the "Typestate" section on the type-level docs.
    _marker: PhantomData<State>,
}

impl<State> Deref for CreationConfig<State> {
    type Target = CreationConfigFields;

    fn deref(&self) -> &CreationConfigFields {
        &self.fields
    }
}

/// Only `Unvalidated` configs are mutable — see the "Sealing" section on
/// [`CreationConfig`]'s type-level docs for why this is the crux of the
/// typestate guarantee.
impl DerefMut for CreationConfig<Unvalidated> {
    fn deref_mut(&mut self) -> &mut CreationConfigFields {
        &mut self.fields
    }
}

impl Default for CreationConfig<Unvalidated> {
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
            fields: CreationConfigFields::default(),
            _marker: PhantomData,
        }
    }
}

impl CreationConfig<Unvalidated> {
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
        self.fields.follow_symlinks = follow;
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
        self.fields.include_hidden = include;
        self
    }

    /// Sets the maximum file size.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::CreationConfig;
    ///
    /// let config = CreationConfig::default().with_max_file_size(Some(1024 * 1024));
    /// assert_eq!(config.max_file_size, Some(1024 * 1024));
    /// ```
    #[must_use]
    pub fn with_max_file_size(mut self, max_size: Option<u64>) -> Self {
        self.fields.max_file_size = max_size;
        self
    }

    /// Sets the exclude patterns.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::CreationConfig;
    ///
    /// let config = CreationConfig::default().with_exclude_patterns(vec!["*.log".to_string()]);
    /// assert_eq!(config.exclude_patterns, vec!["*.log".to_string()]);
    /// ```
    #[must_use]
    pub fn with_exclude_patterns(mut self, patterns: Vec<String>) -> Self {
        self.fields.exclude_patterns = patterns;
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
        self.fields.strip_prefix = prefix;
        self
    }

    /// Sets the compression level.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidCompressionLevel`] if `level` is not
    /// in the range 1–9.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::CreationConfig;
    ///
    /// let config = CreationConfig::default().with_compression_level(9)?;
    /// assert_eq!(config.compression_level, Some(9));
    /// # Ok::<(), exarch_core::ArchiveError>(())
    /// ```
    pub fn with_compression_level(mut self, level: u8) -> Result<Self> {
        if !(1..=9).contains(&level) {
            return Err(ArchiveError::InvalidCompressionLevel { level });
        }
        self.fields.compression_level = Some(level);
        Ok(self)
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
        self.fields.preserve_permissions = preserve;
        self
    }

    /// Sets the archive format.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::CreationConfig;
    /// use exarch_core::formats::detect::ArchiveType;
    ///
    /// let config = CreationConfig::default().with_format(Some(ArchiveType::TarGz));
    /// assert_eq!(config.format, Some(ArchiveType::TarGz));
    /// ```
    #[must_use]
    pub fn with_format(mut self, format: Option<ArchiveType>) -> Self {
        self.fields.format = format;
        self
    }

    /// Validates the configuration, transitioning to the [`Validated`]
    /// typestate on success.
    ///
    /// Consumes `self`: the only way to obtain a `CreationConfig<Validated>`,
    /// which is what the low-level `creation::tar::*` / `creation::zip::*`
    /// functions and
    /// [`FormatCreator::create`](crate::formats::traits::FormatCreator::create)
    /// require. Once returned, the `Validated` config's fields can no longer
    /// be reassigned (see the "Sealing" section on the type-level docs), so
    /// this check can never be silently invalidated afterward.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidCompressionLevel`] if `compression_level`
    /// is set but not in the range 1–9.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::creation::CreationConfig;
    ///
    /// let config = CreationConfig::default();
    /// assert!(config.validate().is_ok());
    /// ```
    pub fn validate(self) -> Result<CreationConfig<Validated>> {
        if let Some(level) = self.fields.compression_level
            && !(1..=9).contains(&level)
        {
            return Err(ArchiveError::InvalidCompressionLevel { level });
        }
        Ok(CreationConfig {
            fields: self.fields,
            _marker: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

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
    #[allow(clippy::unwrap_used)]
    fn test_creation_config_builder() {
        let config = CreationConfig::default()
            .with_follow_symlinks(true)
            .with_include_hidden(true)
            .with_max_file_size(Some(1024 * 1024))
            .with_exclude_patterns(vec!["*.log".to_string()])
            .with_strip_prefix(Some(PathBuf::from("/base")))
            .with_compression_level(9)
            .unwrap()
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
    #[allow(clippy::unwrap_used, clippy::field_reassign_with_default)]
    fn test_creation_config_validate_valid() {
        let config = CreationConfig::default();
        assert!(config.validate().is_ok());

        let config = CreationConfig::default().with_compression_level(1).unwrap();
        assert!(config.validate().is_ok());

        let config = CreationConfig::default().with_compression_level(9).unwrap();
        assert!(config.validate().is_ok());

        let mut config = CreationConfig::default();
        config.compression_level = None;
        assert!(config.validate().is_ok());
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::field_reassign_with_default)]
    fn test_creation_config_validate_invalid() {
        let mut config = CreationConfig::default();
        config.compression_level = Some(0);
        let result = config.validate();
        assert!(result.is_err());
        assert_matches!(
            result.unwrap_err(),
            ArchiveError::InvalidCompressionLevel { level: 0 }
        );

        let mut config = CreationConfig::default();
        config.compression_level = Some(10);
        let result = config.validate();
        assert!(result.is_err());
        assert_matches!(
            result.unwrap_err(),
            ArchiveError::InvalidCompressionLevel { level: 10 }
        );
    }

    #[test]
    fn test_creation_config_builder_invalid_compression() {
        assert_matches!(
            CreationConfig::default().with_compression_level(0),
            Err(ArchiveError::InvalidCompressionLevel { level: 0 })
        );
        assert_matches!(
            CreationConfig::default().with_compression_level(10),
            Err(ArchiveError::InvalidCompressionLevel { level: 10 })
        );
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

    /// Regression test for #443: a validated config must not let levels
    /// 10-255 reach the `flate2`/`xz2` backends, which panic (rather than
    /// error) on out-of-range values. `validate()` is the only path to
    /// `CreationConfig<Validated>`, and it rejects out-of-range levels
    /// regardless of how `compression_level` was set.
    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_validate_rejects_forged_out_of_range_compression_level() {
        let mut config = CreationConfig::default();
        config.compression_level = Some(200);
        let result = config.validate();
        assert_matches!(
            result,
            Err(ArchiveError::InvalidCompressionLevel { level: 200 })
        );
    }
}
