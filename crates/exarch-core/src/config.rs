//! Security configuration for archive extraction.

/// Feature flags controlling what archive features are allowed during
/// extraction.
///
/// All features default to `false` (deny-by-default security policy).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct AllowedFeatures {
    /// Allow symlinks in extracted archives.
    pub symlinks: bool,

    /// Allow hardlinks in extracted archives.
    pub hardlinks: bool,

    /// Allow absolute paths in archive entries.
    pub absolute_paths: bool,

    /// Allow world-writable files (mode 0o002).
    ///
    /// World-writable files pose security risks in multi-user environments.
    pub world_writable: bool,
}

/// Security configuration with default-deny settings.
///
/// This configuration controls various security checks performed during
/// archive extraction to prevent common vulnerabilities.
///
/// # Performance Note
///
/// This struct contains heap-allocated collections (`Vec<String>`). For
/// performance, pass by reference (`&SecurityConfig`) rather than cloning. If
/// shared ownership is needed across threads, consider wrapping in
/// `Arc<SecurityConfig>`.
///
/// # Examples
///
/// ```
/// use exarch_core::SecurityConfig;
///
/// // Use secure defaults
/// let config = SecurityConfig::default();
///
/// // Customize via fluent builder
/// let custom = SecurityConfig::default()
///     .with_max_file_size(100 * 1024 * 1024)
///     .with_max_total_size(1024 * 1024 * 1024)
///     .with_allow_symlinks(true);
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SecurityConfig {
    /// Maximum size for a single file in bytes.
    pub max_file_size: u64,

    /// Maximum total size for all extracted files in bytes.
    pub max_total_size: u64,

    /// Maximum compression ratio allowed (uncompressed / compressed).
    pub max_compression_ratio: f64,

    /// Maximum number of files that can be extracted.
    pub max_file_count: usize,

    /// Maximum path depth allowed.
    pub max_path_depth: usize,

    /// Feature flags controlling what archive features are allowed.
    ///
    /// Use this to enable symlinks, hardlinks, absolute paths, etc.
    pub allowed: AllowedFeatures,

    /// Preserve file permissions from archive.
    pub preserve_permissions: bool,

    /// List of allowed file extensions (empty = allow all).
    ///
    /// Extensions are matched case-insensitively (e.g., `"txt"` matches both
    /// `file.txt` and `file.TXT`). The leading dot must be omitted.
    ///
    /// When this list is non-empty, files without a file extension are treated
    /// as not allowed and will be skipped during extraction.
    pub allowed_extensions: Vec<String>,

    /// List of banned path components (e.g., ".git", ".ssh").
    pub banned_path_components: Vec<String>,

    /// Allow extraction from solid 7z archives.
    ///
    /// Solid archives compress multiple files together as a single block.
    /// While this provides better compression ratios, it has security
    /// implications:
    ///
    /// - **Memory exhaustion**: Extracting a single file requires decompressing
    ///   the entire solid block into memory
    /// - **Denial of service**: Malicious archives can create large solid
    ///   blocks that exhaust available memory
    ///
    /// **Security Recommendation**: Only enable for trusted archives.
    ///
    /// Default: `false` (solid archives rejected)
    pub allow_solid_archives: bool,

    /// Maximum memory for solid archive extraction (bytes).
    ///
    /// **7z Solid Archive Memory Model:**
    ///
    /// Solid compression in 7z stores multiple files in a single compressed
    /// block. Extracting ANY file requires decompressing the ENTIRE solid block
    /// into memory, which can cause memory exhaustion attacks.
    ///
    /// **Validation Strategy:**
    /// - Pre-validates total uncompressed size of all files in archive
    /// - This is a conservative heuristic (assumes single solid block)
    /// - Reason: `sevenz-rust2` v0.20 doesn't expose solid block boundaries
    ///
    /// **Security Guarantee:**
    /// - Total uncompressed data cannot exceed this limit
    /// - Combined with `max_file_size`, prevents unbounded memory growth
    /// - Enforced ONLY when `allow_solid_archives` is `true`
    ///
    /// **Note**: Only applies when `allow_solid_archives` is `true`.
    ///
    /// Default: 512 MB (536,870,912 bytes)
    ///
    /// **Recommendation:** Set to 1-2x available RAM for trusted archives only.
    pub max_solid_block_memory: u64,
}

impl Default for SecurityConfig {
    /// Creates a `SecurityConfig` with secure default settings.
    ///
    /// Default values:
    /// - `max_file_size`: 50 MB
    /// - `max_total_size`: 500 MB
    /// - `max_compression_ratio`: 100.0
    /// - `max_file_count`: 10,000
    /// - `max_path_depth`: 32
    /// - `allowed`: All features disabled (deny-by-default)
    /// - `preserve_permissions`: false
    /// - `allowed_extensions`: empty (allow all)
    /// - `banned_path_components`: `[".git", ".ssh", ".gnupg", ".aws", ".kube",
    ///   ".docker", ".env"]`
    /// - `allow_solid_archives`: false (solid archives rejected)
    /// - `max_solid_block_memory`: 512 MB
    fn default() -> Self {
        Self {
            max_file_size: 50 * 1024 * 1024,   // 50 MB
            max_total_size: 500 * 1024 * 1024, // 500 MB
            max_compression_ratio: 100.0,
            max_file_count: 10_000,
            max_path_depth: 32,
            allowed: AllowedFeatures::default(), // All false
            preserve_permissions: false,
            allowed_extensions: Vec::new(),
            banned_path_components: vec![
                ".git".to_string(),
                ".ssh".to_string(),
                ".gnupg".to_string(),
                ".aws".to_string(),
                ".kube".to_string(),
                ".docker".to_string(),
                ".env".to_string(),
            ],
            allow_solid_archives: false,
            max_solid_block_memory: 512 * 1024 * 1024, // 512 MB
        }
    }
}

impl SecurityConfig {
    /// Creates a permissive configuration for trusted archives.
    ///
    /// This configuration allows symlinks, hardlinks, absolute paths, and
    /// solid archives. Use only when extracting archives from trusted sources.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            allowed: AllowedFeatures {
                symlinks: true,
                hardlinks: true,
                absolute_paths: true,
                world_writable: true,
            },
            preserve_permissions: true,
            max_compression_ratio: 1000.0,
            banned_path_components: Vec::new(),
            allow_solid_archives: true,
            max_solid_block_memory: 1024 * 1024 * 1024, // 1 GB for permissive
            ..Default::default()
        }
    }

    /// Validates that the configuration values are logically consistent.
    ///
    /// Returns an error if any field has a value that would make security
    /// enforcement impossible (zero limits or non-positive ratio).
    ///
    /// # Errors
    ///
    /// Returns `ArchiveError::InvalidConfiguration` if:
    /// - `max_compression_ratio` is not positive
    /// - `max_file_size` is zero
    /// - `max_total_size` is zero
    /// - `max_path_depth` is zero
    /// - `max_file_count` is zero
    /// - `max_solid_block_memory` is zero
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default();
    /// assert!(config.validate().is_ok());
    ///
    /// let bad = SecurityConfig::default().with_max_file_size(0);
    /// assert!(bad.validate().is_err());
    /// ```
    pub fn validate(&self) -> crate::Result<()> {
        if !self.max_compression_ratio.is_finite() || self.max_compression_ratio <= 0.0 {
            return Err(crate::ArchiveError::InvalidConfiguration {
                reason: "max_compression_ratio must be positive".into(),
            });
        }
        if self.max_file_size == 0 {
            return Err(crate::ArchiveError::InvalidConfiguration {
                reason: "max_file_size must not be zero".into(),
            });
        }
        if self.max_total_size == 0 {
            return Err(crate::ArchiveError::InvalidConfiguration {
                reason: "max_total_size must not be zero".into(),
            });
        }
        if self.max_path_depth == 0 {
            return Err(crate::ArchiveError::InvalidConfiguration {
                reason: "max_path_depth must not be zero".into(),
            });
        }
        if self.max_file_count == 0 {
            return Err(crate::ArchiveError::InvalidConfiguration {
                reason: "max_file_count must not be zero".into(),
            });
        }
        if self.max_solid_block_memory == 0 {
            return Err(crate::ArchiveError::InvalidConfiguration {
                reason: "max_solid_block_memory must not be zero".into(),
            });
        }
        Ok(())
    }

    /// Sets the maximum size for a single extracted file in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default().with_max_file_size(100 * 1024 * 1024);
    /// assert_eq!(config.max_file_size, 100 * 1024 * 1024);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = size;
        self
    }

    /// Sets the maximum total size for all extracted files in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default().with_max_total_size(1024 * 1024 * 1024);
    /// assert_eq!(config.max_total_size, 1024 * 1024 * 1024);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_max_total_size(mut self, size: u64) -> Self {
        self.max_total_size = size;
        self
    }

    /// Sets the maximum allowed compression ratio (uncompressed / compressed).
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default().with_max_compression_ratio(50.0);
    /// assert_eq!(config.max_compression_ratio, 50.0);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_max_compression_ratio(mut self, ratio: f64) -> Self {
        self.max_compression_ratio = ratio;
        self
    }

    /// Sets the maximum number of files that can be extracted.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default().with_max_file_count(500);
    /// assert_eq!(config.max_file_count, 500);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_max_file_count(mut self, count: usize) -> Self {
        self.max_file_count = count;
        self
    }

    /// Sets the maximum path depth allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default().with_max_path_depth(16);
    /// assert_eq!(config.max_path_depth, 16);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_max_path_depth(mut self, depth: usize) -> Self {
        self.max_path_depth = depth;
        self
    }

    /// Sets the feature flags controlling allowed archive features.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    /// use exarch_core::config::AllowedFeatures;
    ///
    /// let features = AllowedFeatures::default();
    /// let config = SecurityConfig::default().with_allowed(features);
    /// assert!(!config.allowed.symlinks);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_allowed(mut self, allowed: AllowedFeatures) -> Self {
        self.allowed = allowed;
        self
    }

    /// Enables or disables symlinks in extracted archives.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default().with_allow_symlinks(true);
    /// assert!(config.allowed.symlinks);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_allow_symlinks(mut self, allow: bool) -> Self {
        self.allowed.symlinks = allow;
        self
    }

    /// Enables or disables hardlinks in extracted archives.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default().with_allow_hardlinks(true);
    /// assert!(config.allowed.hardlinks);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_allow_hardlinks(mut self, allow: bool) -> Self {
        self.allowed.hardlinks = allow;
        self
    }

    /// Enables or disables absolute paths in archive entries.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default().with_allow_absolute_paths(true);
    /// assert!(config.allowed.absolute_paths);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_allow_absolute_paths(mut self, allow: bool) -> Self {
        self.allowed.absolute_paths = allow;
        self
    }

    /// Enables or disables world-writable files.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default().with_allow_world_writable(true);
    /// assert!(config.allowed.world_writable);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_allow_world_writable(mut self, allow: bool) -> Self {
        self.allowed.world_writable = allow;
        self
    }

    /// Enables or disables preserving file permissions from the archive.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default().with_preserve_permissions(true);
    /// assert!(config.preserve_permissions);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_preserve_permissions(mut self, preserve: bool) -> Self {
        self.preserve_permissions = preserve;
        self
    }

    /// Sets the list of allowed file extensions.
    ///
    /// An empty list allows all extensions.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default()
    ///     .with_allowed_extensions(vec!["txt".to_string(), "pdf".to_string()]);
    /// assert!(config.is_extension_allowed("txt"));
    /// assert!(!config.is_extension_allowed("exe"));
    /// ```
    #[must_use]
    #[inline]
    pub fn with_allowed_extensions(mut self, extensions: Vec<String>) -> Self {
        self.allowed_extensions = extensions;
        self
    }

    /// Sets the list of banned path components.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default().with_banned_path_components(vec![".git".to_string()]);
    /// assert!(!config.is_path_component_allowed(".git"));
    /// assert!(config.is_path_component_allowed(".ssh"));
    /// ```
    #[must_use]
    #[inline]
    pub fn with_banned_path_components(mut self, components: Vec<String>) -> Self {
        self.banned_path_components = components;
        self
    }

    /// Enables or disables extraction from solid 7z archives.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default().with_allow_solid_archives(true);
    /// assert!(config.allow_solid_archives);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_allow_solid_archives(mut self, allow: bool) -> Self {
        self.allow_solid_archives = allow;
        self
    }

    /// Sets the maximum memory for solid archive extraction in bytes.
    ///
    /// Only applies when `allow_solid_archives` is `true`.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default()
    ///     .with_allow_solid_archives(true)
    ///     .with_max_solid_block_memory(1024 * 1024 * 1024);
    /// assert_eq!(config.max_solid_block_memory, 1024 * 1024 * 1024);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_max_solid_block_memory(mut self, size: u64) -> Self {
        self.max_solid_block_memory = size;
        self
    }

    /// Validates whether a path component is allowed.
    ///
    /// Comparison is case-insensitive to prevent bypass on case-insensitive
    /// filesystems (Windows, macOS default).
    #[must_use]
    pub fn is_path_component_allowed(&self, component: &str) -> bool {
        !self
            .banned_path_components
            .iter()
            .any(|banned| banned.eq_ignore_ascii_case(component))
    }

    /// Validates whether a file extension is allowed.
    ///
    /// When `allowed_extensions` is empty, all extensions are permitted.
    /// When it is non-empty, only listed extensions are permitted.
    #[must_use]
    pub fn is_extension_allowed(&self, extension: &str) -> bool {
        if self.allowed_extensions.is_empty() {
            return true;
        }
        self.allowed_extensions
            .iter()
            .any(|ext| ext.eq_ignore_ascii_case(extension))
    }

    /// Returns `true` if a file with the given optional extension may be
    /// extracted.
    ///
    /// When `allowed_extensions` is non-empty and `extension` is `None`
    /// (the file has no extension), the file is treated as not allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default().with_allowed_extensions(vec!["txt".to_string()]);
    ///
    /// assert!(config.is_path_extension_allowed(Some("txt")));
    /// assert!(!config.is_path_extension_allowed(Some("exe")));
    /// // Files without an extension are blocked when the allowlist is non-empty.
    /// assert!(!config.is_path_extension_allowed(None));
    ///
    /// // Empty allowlist permits everything, including extension-less files.
    /// let permissive = SecurityConfig::default();
    /// assert!(permissive.is_path_extension_allowed(None));
    /// ```
    #[must_use]
    pub fn is_path_extension_allowed(&self, extension: Option<&str>) -> bool {
        if self.allowed_extensions.is_empty() {
            return true;
        }
        extension.is_some_and(|ext| self.is_extension_allowed(ext))
    }
}

/// Options controlling extraction behavior (non-security).
///
/// Separate from `SecurityConfig` to keep security settings focused.
/// These options control operational behavior like atomicity.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ExtractionOptions {
    /// Extract atomically: use a temp dir in the same parent as the output
    /// directory, rename on success, and delete on failure.
    ///
    /// When enabled, extraction is all-or-nothing: if extraction fails,
    /// the output directory will not be created. This prevents partial
    /// extraction artifacts from remaining on disk.
    ///
    /// Note: cleanup is best-effort if the process is terminated via SIGKILL.
    pub atomic: bool,

    /// Skip duplicate entries silently instead of aborting.
    ///
    /// When `true` (default), if an archive contains two entries with the same
    /// destination path, the second entry is skipped and a warning is recorded
    /// in `ExtractionReport`. When `false`, duplicate entries cause an error.
    pub skip_duplicates: bool,
}

impl Default for ExtractionOptions {
    fn default() -> Self {
        Self {
            atomic: false,
            skip_duplicates: true,
        }
    }
}

impl ExtractionOptions {
    /// Enables or disables atomic extraction.
    ///
    /// When enabled, extraction is all-or-nothing: the output directory is not
    /// created if extraction fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ExtractionOptions;
    ///
    /// let opts = ExtractionOptions::default().with_atomic(true);
    /// assert!(opts.atomic);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_atomic(mut self, atomic: bool) -> Self {
        self.atomic = atomic;
        self
    }

    /// Enables or disables skipping duplicate entries silently.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ExtractionOptions;
    ///
    /// let opts = ExtractionOptions::default().with_skip_duplicates(false);
    /// assert!(!opts.skip_duplicates);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_skip_duplicates(mut self, skip: bool) -> Self {
        self.skip_duplicates = skip;
        self
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SecurityConfig::default();
        assert!(!config.allowed.symlinks);
        assert!(!config.allowed.hardlinks);
        assert!(!config.allowed.absolute_paths);
        assert_eq!(config.max_file_size, 50 * 1024 * 1024);
    }

    #[test]
    fn test_permissive_config() {
        let config = SecurityConfig::permissive();
        assert!(config.allowed.symlinks);
        assert!(config.allowed.hardlinks);
        assert!(config.allowed.absolute_paths);
    }

    #[test]
    fn test_extension_allowed_empty_list() {
        let config = SecurityConfig::default();
        assert!(config.is_extension_allowed("txt"));
        assert!(config.is_extension_allowed("pdf"));
    }

    #[test]
    fn test_extension_allowed_with_list() {
        let mut config = SecurityConfig::default();
        config.allowed_extensions = vec!["txt".to_string(), "pdf".to_string()];
        assert!(config.is_extension_allowed("txt"));
        assert!(config.is_extension_allowed("TXT"));
        assert!(!config.is_extension_allowed("exe"));
    }

    #[test]
    fn test_path_component_allowed() {
        let config = SecurityConfig::default();
        assert!(config.is_path_component_allowed("src"));
        assert!(!config.is_path_component_allowed(".git"));
        assert!(!config.is_path_component_allowed(".ssh"));

        // Case-insensitive matching prevents bypass
        assert!(!config.is_path_component_allowed(".Git"));
        assert!(!config.is_path_component_allowed(".GIT"));
        assert!(!config.is_path_component_allowed(".SSH"));
        assert!(!config.is_path_component_allowed(".Gnupg"));
    }

    // M-TEST-3: Config field validation
    #[test]
    fn test_config_default_security_flags() {
        let config = SecurityConfig::default();

        // All security-sensitive flags should be false by default (deny-by-default)
        assert!(
            !config.allowed.symlinks,
            "symlinks should be denied by default"
        );
        assert!(
            !config.allowed.hardlinks,
            "hardlinks should be denied by default"
        );
        assert!(
            !config.allowed.absolute_paths,
            "absolute paths should be denied by default"
        );
        assert!(
            !config.preserve_permissions,
            "permissions should not be preserved by default"
        );
        assert!(
            !config.allowed.world_writable,
            "world-writable should be denied by default"
        );
    }

    #[test]
    fn test_config_permissive_security_flags() {
        let config = SecurityConfig::permissive();

        // Permissive config should allow all features
        assert!(config.allowed.symlinks, "permissive allows symlinks");
        assert!(config.allowed.hardlinks, "permissive allows hardlinks");
        assert!(
            config.allowed.absolute_paths,
            "permissive allows absolute paths"
        );
        assert!(
            config.preserve_permissions,
            "permissive preserves permissions"
        );
        assert!(
            config.allowed.world_writable,
            "permissive allows world-writable"
        );
    }

    #[test]
    fn test_config_quota_limits() {
        let config = SecurityConfig::default();

        // Verify default quota values are sensible
        assert_eq!(config.max_file_size, 50 * 1024 * 1024, "50 MB file limit");
        assert_eq!(
            config.max_total_size,
            500 * 1024 * 1024,
            "500 MB total limit"
        );
        assert_eq!(config.max_file_count, 10_000, "10k file count limit");
        assert_eq!(config.max_path_depth, 32, "32 level depth limit");
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(
                config.max_compression_ratio, 100.0,
                "100x compression ratio limit"
            );
        }
    }

    #[test]
    fn test_config_banned_components_not_empty() {
        let config = SecurityConfig::default();

        // Default should ban common sensitive directories
        assert!(
            !config.banned_path_components.is_empty(),
            "should have banned components by default"
        );
        assert!(
            config.banned_path_components.contains(&".git".to_string()),
            "should ban .git"
        );
        assert!(
            config.banned_path_components.contains(&".ssh".to_string()),
            "should ban .ssh"
        );
    }

    #[test]
    fn test_config_solid_archives_default() {
        let config = SecurityConfig::default();

        // Solid archives should be denied by default (security)
        assert!(
            !config.allow_solid_archives,
            "solid archives should be denied by default"
        );
        assert_eq!(
            config.max_solid_block_memory,
            512 * 1024 * 1024,
            "max solid block memory should be 512 MB"
        );
    }

    #[test]
    fn test_config_permissive_solid_archives() {
        let config = SecurityConfig::permissive();

        // Permissive config should allow solid archives
        assert!(
            config.allow_solid_archives,
            "permissive config should allow solid archives"
        );
        assert_eq!(
            config.max_solid_block_memory,
            1024 * 1024 * 1024,
            "permissive should have 1 GB solid block limit"
        );
    }

    // Regression tests for #172: SecurityConfig::validate() must reject configs
    // that would make security enforcement impossible.

    #[test]
    fn test_validate_default_is_ok() {
        assert!(SecurityConfig::default().validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_negative_compression_ratio() {
        let cfg = SecurityConfig {
            max_compression_ratio: -1.0,
            ..SecurityConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_zero_compression_ratio() {
        let cfg = SecurityConfig {
            max_compression_ratio: 0.0,
            ..SecurityConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_zero_max_file_size() {
        let cfg = SecurityConfig {
            max_file_size: 0,
            ..SecurityConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_zero_max_total_size() {
        let cfg = SecurityConfig {
            max_total_size: 0,
            ..SecurityConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_zero_max_path_depth() {
        let cfg = SecurityConfig {
            max_path_depth: 0,
            ..SecurityConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_nan_compression_ratio() {
        let cfg = SecurityConfig {
            max_compression_ratio: f64::NAN,
            ..SecurityConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_infinite_compression_ratio() {
        let cfg = SecurityConfig {
            max_compression_ratio: f64::INFINITY,
            ..SecurityConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_zero_max_file_count() {
        let cfg = SecurityConfig {
            max_file_count: 0,
            ..SecurityConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_zero_max_solid_block_memory() {
        let cfg = SecurityConfig {
            max_solid_block_memory: 0,
            ..SecurityConfig::default()
        };
        assert!(cfg.validate().is_err());
    }
}
