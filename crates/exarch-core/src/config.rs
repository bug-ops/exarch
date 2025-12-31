//! Security configuration for archive extraction.

/// Feature flags controlling what archive features are allowed during
/// extraction.
///
/// All features default to `false` (deny-by-default security policy).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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
/// // Customize for specific needs
/// let custom = SecurityConfig {
///     max_file_size: 100 * 1024 * 1024,   // 100 MB
///     max_total_size: 1024 * 1024 * 1024, // 1 GB
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone)]
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
    pub allowed_extensions: Vec<String>,

    /// List of banned path components (e.g., ".git", ".ssh").
    pub banned_path_components: Vec<String>,
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
        }
    }
}

impl SecurityConfig {
    /// Creates a permissive configuration for trusted archives.
    ///
    /// This configuration allows symlinks, hardlinks, and absolute paths.
    /// Use only when extracting archives from trusted sources.
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
            ..Default::default()
        }
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
    #[must_use]
    pub fn is_extension_allowed(&self, extension: &str) -> bool {
        if self.allowed_extensions.is_empty() {
            return true;
        }
        self.allowed_extensions
            .iter()
            .any(|ext| ext.eq_ignore_ascii_case(extension))
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
}
