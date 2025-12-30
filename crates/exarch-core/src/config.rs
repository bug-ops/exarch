//! Security configuration for archive extraction.

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

    /// Allow symlinks in extracted archives.
    pub allow_symlinks: bool,

    /// Allow hardlinks in extracted archives.
    pub allow_hardlinks: bool,

    /// Allow absolute paths in archive entries.
    pub allow_absolute_paths: bool,

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
    /// - `allow_symlinks`: false (deny)
    /// - `allow_hardlinks`: false (deny)
    /// - `allow_absolute_paths`: false (deny)
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
            allow_symlinks: false,
            allow_hardlinks: false,
            allow_absolute_paths: false,
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
            allow_symlinks: true,
            allow_hardlinks: true,
            allow_absolute_paths: true,
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
        assert!(!config.allow_symlinks);
        assert!(!config.allow_hardlinks);
        assert!(!config.allow_absolute_paths);
        assert_eq!(config.max_file_size, 50 * 1024 * 1024);
    }

    #[test]
    fn test_permissive_config() {
        let config = SecurityConfig::permissive();
        assert!(config.allow_symlinks);
        assert!(config.allow_hardlinks);
        assert!(config.allow_absolute_paths);
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
}
