//! Node.js bindings for `SecurityConfig`.

use exarch_core::SecurityConfig as CoreConfig;
use napi::bindgen_prelude::Error;
use napi::bindgen_prelude::Result;
use napi_derive::napi;

/// Maximum length for file extension strings (e.g., ".tar.gz")
const MAX_EXTENSION_LENGTH: usize = 255;

/// Maximum length for path component strings
const MAX_COMPONENT_LENGTH: usize = 255;

/// Security configuration for archive extraction.
///
/// All security features default to deny (secure-by-default policy).
///
/// # Defaults
///
/// | Setting | Default Value |
/// |---------|--------------|
/// | `max_file_size` | 50 MB (52,428,800 bytes) |
/// | `max_total_size` | 500 MB (524,288,000 bytes) |
/// | `max_compression_ratio` | 100.0 |
/// | `max_file_count` | 10,000 |
/// | `max_path_depth` | 32 |
/// | `allow_symlinks` | false |
/// | `allow_hardlinks` | false |
/// | `allow_absolute_paths` | false |
/// | `allow_world_writable` | false |
/// | `preserve_permissions` | false |
/// | `allowed_extensions` | empty (all allowed) |
/// | `banned_path_components` | `.git`, `.ssh` |
#[napi]
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    inner: CoreConfig,
}

#[napi]
impl SecurityConfig {
    /// Creates a new `SecurityConfig` with secure defaults.
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: CoreConfig::default(),
        }
    }

    /// Creates a `SecurityConfig` with secure defaults.
    ///
    /// This is equivalent to calling `new SecurityConfig()`.
    #[napi(factory)]
    pub fn default() -> Self {
        Self::new()
    }

    /// Creates a permissive configuration for trusted archives.
    ///
    /// Enables: symlinks, hardlinks, absolute paths, world-writable files.
    /// Use only for archives from trusted sources.
    #[napi(factory)]
    pub fn permissive() -> Self {
        Self {
            inner: CoreConfig::permissive(),
        }
    }

    // Builder pattern methods - return Self for chaining

    /// Sets the maximum file size in bytes.
    ///
    /// # Errors
    ///
    /// Returns error if size is negative.
    #[napi]
    pub fn max_file_size(&mut self, size: i64) -> Result<&Self> {
        if size < 0 {
            return Err(Error::from_reason("max file size cannot be negative"));
        }
        #[allow(clippy::cast_sign_loss)]
        {
            self.inner.max_file_size = size as u64;
        }
        Ok(self)
    }

    /// Sets the maximum total size in bytes.
    ///
    /// # Errors
    ///
    /// Returns error if size is negative.
    #[napi]
    pub fn max_total_size(&mut self, size: i64) -> Result<&Self> {
        if size < 0 {
            return Err(Error::from_reason("max total size cannot be negative"));
        }
        #[allow(clippy::cast_sign_loss)]
        {
            self.inner.max_total_size = size as u64;
        }
        Ok(self)
    }

    /// Sets the maximum compression ratio.
    ///
    /// # Errors
    ///
    /// Returns error if ratio is not a positive finite number.
    #[napi]
    pub fn max_compression_ratio(&mut self, ratio: f64) -> Result<&Self> {
        if !ratio.is_finite() || ratio <= 0.0 {
            return Err(Error::from_reason(
                "compression ratio must be a positive finite number",
            ));
        }
        self.inner.max_compression_ratio = ratio;
        Ok(self)
    }

    /// Sets the maximum file count.
    #[napi]
    pub fn max_file_count(&mut self, count: u32) -> &Self {
        self.inner.max_file_count = count as usize;
        self
    }

    /// Sets the maximum path depth.
    #[napi]
    pub fn max_path_depth(&mut self, depth: u32) -> &Self {
        self.inner.max_path_depth = depth as usize;
        self
    }

    /// Allows or denies symlinks.
    #[napi]
    pub fn allow_symlinks(&mut self, allow: Option<bool>) -> &Self {
        self.inner.allowed.symlinks = allow.unwrap_or(true);
        self
    }

    /// Allows or denies hardlinks.
    #[napi]
    pub fn allow_hardlinks(&mut self, allow: Option<bool>) -> &Self {
        self.inner.allowed.hardlinks = allow.unwrap_or(true);
        self
    }

    /// Allows or denies absolute paths.
    #[napi]
    pub fn allow_absolute_paths(&mut self, allow: Option<bool>) -> &Self {
        self.inner.allowed.absolute_paths = allow.unwrap_or(true);
        self
    }

    /// Allows or denies world-writable files.
    #[napi]
    pub fn allow_world_writable(&mut self, allow: Option<bool>) -> &Self {
        self.inner.allowed.world_writable = allow.unwrap_or(true);
        self
    }

    /// Sets whether to preserve permissions from archive.
    #[napi]
    pub fn preserve_permissions(&mut self, preserve: Option<bool>) -> &Self {
        self.inner.preserve_permissions = preserve.unwrap_or(true);
        self
    }

    /// Adds an allowed file extension.
    ///
    /// # Errors
    ///
    /// Returns error if extension exceeds maximum length or contains null
    /// bytes.
    #[napi]
    pub fn add_allowed_extension(&mut self, ext: String) -> Result<&Self> {
        if ext.contains('\0') {
            return Err(Error::from_reason(
                "extension contains null bytes - potential security issue",
            ));
        }
        if ext.len() > MAX_EXTENSION_LENGTH {
            return Err(Error::from_reason(format!(
                "extension exceeds maximum length of {MAX_EXTENSION_LENGTH} characters"
            )));
        }
        self.inner.allowed_extensions.push(ext);
        Ok(self)
    }

    /// Adds a banned path component.
    ///
    /// # Errors
    ///
    /// Returns error if component exceeds maximum length or contains null
    /// bytes.
    #[napi]
    pub fn add_banned_component(&mut self, component: String) -> Result<&Self> {
        if component.contains('\0') {
            return Err(Error::from_reason(
                "component contains null bytes - potential security issue",
            ));
        }
        if component.len() > MAX_COMPONENT_LENGTH {
            return Err(Error::from_reason(format!(
                "component exceeds maximum length of {MAX_COMPONENT_LENGTH} characters"
            )));
        }
        self.inner.banned_path_components.push(component);
        Ok(self)
    }

    /// Finalizes the configuration (for API consistency).
    ///
    /// This method is provided for builder pattern consistency but is optional.
    /// The configuration is always valid and can be used directly.
    #[napi]
    pub fn build(&self) -> &Self {
        self
    }

    // Validation methods

    /// Checks if a path component is allowed.
    #[napi]
    #[allow(clippy::needless_pass_by_value)]
    pub fn is_path_component_allowed(&self, component: String) -> bool {
        self.inner.is_path_component_allowed(&component)
    }

    /// Checks if a file extension is allowed.
    #[napi]
    #[allow(clippy::needless_pass_by_value)]
    pub fn is_extension_allowed(&self, extension: String) -> bool {
        self.inner.is_extension_allowed(&extension)
    }

    // Property getters

    /// Maximum file size in bytes.
    #[napi(getter)]
    #[allow(clippy::cast_possible_wrap)]
    pub fn get_max_file_size(&self) -> i64 {
        self.inner.max_file_size as i64
    }

    /// Maximum total size in bytes.
    #[napi(getter)]
    #[allow(clippy::cast_possible_wrap)]
    pub fn get_max_total_size(&self) -> i64 {
        self.inner.max_total_size as i64
    }

    /// Maximum compression ratio.
    #[napi(getter)]
    pub fn get_max_compression_ratio(&self) -> f64 {
        self.inner.max_compression_ratio
    }

    /// Maximum file count.
    #[napi(getter)]
    #[allow(clippy::cast_possible_truncation)]
    pub fn get_max_file_count(&self) -> u32 {
        self.inner.max_file_count as u32
    }

    /// Maximum path depth.
    #[napi(getter)]
    #[allow(clippy::cast_possible_truncation)]
    pub fn get_max_path_depth(&self) -> u32 {
        self.inner.max_path_depth as u32
    }

    /// Whether to preserve permissions from archive.
    #[napi(getter)]
    pub fn get_preserve_permissions(&self) -> bool {
        self.inner.preserve_permissions
    }

    /// Whether symlinks are allowed.
    #[napi(getter)]
    pub fn get_allow_symlinks(&self) -> bool {
        self.inner.allowed.symlinks
    }

    /// Whether hardlinks are allowed.
    #[napi(getter)]
    pub fn get_allow_hardlinks(&self) -> bool {
        self.inner.allowed.hardlinks
    }

    /// Whether absolute paths are allowed.
    #[napi(getter)]
    pub fn get_allow_absolute_paths(&self) -> bool {
        self.inner.allowed.absolute_paths
    }

    /// Whether world-writable files are allowed.
    #[napi(getter)]
    pub fn get_allow_world_writable(&self) -> bool {
        self.inner.allowed.world_writable
    }

    /// List of allowed file extensions.
    ///
    /// Note: This getter clones the underlying data. For performance-critical
    /// code that only needs to count or check membership, use
    /// `getAllowedExtensionsCount()` or `hasAllowedExtension()` instead.
    #[napi(getter)]
    pub fn get_allowed_extensions(&self) -> Vec<String> {
        self.inner.allowed_extensions.clone()
    }

    /// Returns the number of allowed extensions.
    #[napi]
    #[allow(clippy::cast_possible_truncation)]
    pub fn get_allowed_extensions_count(&self) -> u32 {
        self.inner.allowed_extensions.len() as u32
    }

    /// Checks if a specific extension is in the allowed list.
    #[napi]
    #[allow(clippy::needless_pass_by_value)]
    pub fn has_allowed_extension(&self, ext: String) -> bool {
        self.inner.allowed_extensions.contains(&ext)
    }

    /// List of banned path components.
    ///
    /// Note: This getter clones the underlying data. For performance-critical
    /// code that only needs to count or check membership, use
    /// `getBannedPathComponentsCount()` or `hasBannedPathComponent()` instead.
    #[napi(getter)]
    pub fn get_banned_path_components(&self) -> Vec<String> {
        self.inner.banned_path_components.clone()
    }

    /// Returns the number of banned path components.
    #[napi]
    #[allow(clippy::cast_possible_truncation)]
    pub fn get_banned_path_components_count(&self) -> u32 {
        self.inner.banned_path_components.len() as u32
    }

    /// Checks if a specific component is in the banned list.
    #[napi]
    #[allow(clippy::needless_pass_by_value)]
    pub fn has_banned_path_component(&self, component: String) -> bool {
        self.inner.banned_path_components.contains(&component)
    }
}

impl SecurityConfig {
    /// Returns a reference to the inner `CoreConfig`.
    ///
    /// This is used internally to pass the configuration to the Rust extraction
    /// API.
    pub fn as_core(&self) -> &CoreConfig {
        &self.inner
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::float_cmp,
    clippy::unreadable_literal,
    clippy::manual_string_new,
    clippy::uninlined_format_args
)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SecurityConfig::new();
        assert_eq!(config.get_max_file_size(), 50 * 1024 * 1024);
        assert_eq!(config.get_max_total_size(), 500 * 1024 * 1024);
        assert_eq!(config.get_max_file_count(), 10_000);
        assert!(!config.get_preserve_permissions());
    }

    #[test]
    fn test_default_static_method() {
        let config = SecurityConfig::default();
        assert_eq!(config.get_max_file_size(), 50 * 1024 * 1024);
    }

    #[test]
    fn test_permissive_config() {
        let config = SecurityConfig::permissive();
        assert!(config.inner.allowed.symlinks);
        assert!(config.inner.allowed.hardlinks);
        assert!(config.inner.allowed.absolute_paths);
        assert!(config.get_preserve_permissions());
    }

    #[test]
    fn test_builder_pattern_method_chaining() {
        let mut config = SecurityConfig::new();
        config.max_file_size(100_000_000).unwrap();
        config.max_total_size(1_000_000_000).unwrap();
        config.max_file_count(50_000);

        assert_eq!(config.get_max_file_size(), 100_000_000);
        assert_eq!(config.get_max_total_size(), 1_000_000_000);
        assert_eq!(config.get_max_file_count(), 50_000);
    }

    #[test]
    fn test_builder_compression_ratio_valid() {
        let mut config = SecurityConfig::new();
        let result = config.max_compression_ratio(200.0);
        assert!(result.is_ok());
        assert_eq!(config.get_max_compression_ratio(), 200.0);
    }

    #[test]
    fn test_builder_compression_ratio_rejects_nan() {
        let mut config = SecurityConfig::new();
        let result = config.max_compression_ratio(f64::NAN);
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_compression_ratio_rejects_infinity() {
        let mut config = SecurityConfig::new();
        let result = config.max_compression_ratio(f64::INFINITY);
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_compression_ratio_rejects_negative() {
        let mut config = SecurityConfig::new();
        let result = config.max_compression_ratio(-10.0);
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_compression_ratio_rejects_zero() {
        let mut config = SecurityConfig::new();
        let result = config.max_compression_ratio(0.0);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_allowed_extension_valid() {
        let mut config = SecurityConfig::new();
        let result = config.add_allowed_extension(".txt".to_string());
        assert!(result.is_ok());
        assert!(
            config
                .get_allowed_extensions()
                .contains(&".txt".to_string())
        );
    }

    #[test]
    fn test_add_allowed_extension_rejects_null_bytes() {
        let mut config = SecurityConfig::new();
        let result = config.add_allowed_extension(".txt\0".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_add_allowed_extension_rejects_too_long() {
        let mut config = SecurityConfig::new();
        let long_ext = "x".repeat(MAX_EXTENSION_LENGTH + 1);
        let result = config.add_allowed_extension(long_ext);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_banned_component_valid() {
        let mut config = SecurityConfig::new();
        let result = config.add_banned_component("node_modules".to_string());
        assert!(result.is_ok());
        assert!(
            config
                .get_banned_path_components()
                .contains(&"node_modules".to_string())
        );
    }

    #[test]
    fn test_add_banned_component_rejects_null_bytes() {
        let mut config = SecurityConfig::new();
        let result = config.add_banned_component("bad\0".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_add_banned_component_rejects_too_long() {
        let mut config = SecurityConfig::new();
        let long_component = "x".repeat(MAX_COMPONENT_LENGTH + 1);
        let result = config.add_banned_component(long_component);
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_methods() {
        let config = SecurityConfig::new();
        assert!(config.is_path_component_allowed("src".to_string()));
        assert!(!config.is_path_component_allowed(".git".to_string()));
        assert!(!config.is_path_component_allowed(".ssh".to_string()));
    }

    #[test]
    fn test_is_extension_allowed_empty_list() {
        let config = SecurityConfig::new();
        assert!(config.is_extension_allowed("txt".to_string()));
    }

    #[test]
    fn test_as_core() {
        let config = SecurityConfig::new();
        let core_config = config.as_core();
        assert_eq!(core_config.max_file_size, 50 * 1024 * 1024);
    }

    // Integer boundary tests
    #[test]
    fn test_max_file_size_negative_value() {
        let mut config = SecurityConfig::new();
        let result = config.max_file_size(-1);
        assert!(result.is_err(), "negative file size should be rejected");
        assert!(
            result.unwrap_err().to_string().contains("negative"),
            "error should mention negative value"
        );
    }

    #[test]
    fn test_max_file_size_i64_max() {
        let mut config = SecurityConfig::new();
        let result = config.max_file_size(i64::MAX);
        assert!(result.is_ok(), "i64::MAX should be accepted");
        assert_eq!(
            config.get_max_file_size(),
            i64::MAX,
            "value should be stored correctly"
        );
    }

    #[test]
    fn test_max_total_size_negative_value() {
        let mut config = SecurityConfig::new();
        let result = config.max_total_size(-1);
        assert!(result.is_err(), "negative total size should be rejected");
        assert!(
            result.unwrap_err().to_string().contains("negative"),
            "error should mention negative value"
        );
    }

    #[test]
    fn test_max_total_size_i64_max() {
        let mut config = SecurityConfig::new();
        let result = config.max_total_size(i64::MAX);
        assert!(result.is_ok(), "i64::MAX should be accepted");
        assert_eq!(
            config.get_max_total_size(),
            i64::MAX,
            "value should be stored correctly"
        );
    }

    #[test]
    fn test_max_file_count_u32_max() {
        let mut config = SecurityConfig::new();
        config.max_file_count(u32::MAX);
        assert_eq!(
            config.get_max_file_count(),
            u32::MAX,
            "u32::MAX should be accepted"
        );
    }

    #[test]
    fn test_max_path_depth_u32_max() {
        let mut config = SecurityConfig::new();
        config.max_path_depth(u32::MAX);
        assert_eq!(
            config.get_max_path_depth(),
            u32::MAX,
            "u32::MAX should be accepted"
        );
    }

    #[test]
    fn test_max_file_size_zero() {
        let mut config = SecurityConfig::new();
        let result = config.max_file_size(0);
        assert!(result.is_ok(), "zero file size should be accepted");
        assert_eq!(config.get_max_file_size(), 0);
    }

    // Property getter tests
    #[test]
    fn test_property_getters_return_correct_values() {
        let mut config = SecurityConfig::new();
        config.max_file_size(100_000_000).unwrap();
        config.max_total_size(1_000_000_000).unwrap();
        config.max_compression_ratio(250.0).unwrap();
        config.max_file_count(50_000);
        config.max_path_depth(64);
        config.preserve_permissions(Some(true));

        assert_eq!(
            config.get_max_file_size(),
            100_000_000,
            "max_file_size getter should return set value"
        );
        assert_eq!(
            config.get_max_total_size(),
            1_000_000_000,
            "max_total_size getter should return set value"
        );
        assert_eq!(
            config.get_max_compression_ratio(),
            250.0,
            "max_compression_ratio getter should return set value"
        );
        assert_eq!(
            config.get_max_file_count(),
            50_000,
            "max_file_count getter should return set value"
        );
        assert_eq!(
            config.get_max_path_depth(),
            64,
            "max_path_depth getter should return set value"
        );
        assert!(
            config.get_preserve_permissions(),
            "preserve_permissions getter should return set value"
        );
    }

    #[test]
    fn test_allowed_extensions_getter_after_add() {
        let mut config = SecurityConfig::new();
        config.add_allowed_extension(".txt".to_string()).unwrap();
        config.add_allowed_extension(".md".to_string()).unwrap();

        let extensions = config.get_allowed_extensions();
        assert_eq!(extensions.len(), 2, "should have 2 allowed extensions");
        assert!(
            extensions.contains(&".txt".to_string()),
            "should contain .txt"
        );
        assert!(
            extensions.contains(&".md".to_string()),
            "should contain .md"
        );
    }

    #[test]
    fn test_banned_components_getter_after_add() {
        let mut config = SecurityConfig::new();
        // Default config already has 7 banned components
        let initial_count = config.get_banned_path_components().len();

        config
            .add_banned_component("node_modules".to_string())
            .unwrap();
        config
            .add_banned_component("test_component".to_string())
            .unwrap();

        let components = config.get_banned_path_components();
        assert_eq!(
            components.len(),
            initial_count + 2,
            "should have 2 additional banned components"
        );
        assert!(
            components.contains(&"node_modules".to_string()),
            "should contain node_modules"
        );
        assert!(
            components.contains(&"test_component".to_string()),
            "should contain test_component"
        );
    }

    // Validation edge case tests
    #[test]
    fn test_is_path_component_allowed_empty_string() {
        let config = SecurityConfig::new();
        assert!(
            config.is_path_component_allowed("".to_string()),
            "empty string should be allowed by default"
        );
    }

    #[test]
    fn test_is_path_component_allowed_unicode() {
        let config = SecurityConfig::new();
        assert!(
            config.is_path_component_allowed("日本語".to_string()),
            "unicode should be allowed"
        );
        assert!(
            config.is_path_component_allowed("файл".to_string()),
            "cyrillic should be allowed"
        );
    }

    #[test]
    fn test_is_path_component_allowed_with_spaces() {
        let config = SecurityConfig::new();
        assert!(
            config.is_path_component_allowed("my file".to_string()),
            "spaces should be allowed"
        );
    }

    #[test]
    fn test_is_path_component_allowed_special_chars() {
        let config = SecurityConfig::new();
        assert!(
            config.is_path_component_allowed("file@special#chars".to_string()),
            "special characters should be allowed"
        );
    }

    #[test]
    fn test_is_extension_allowed_with_allowed_list() {
        let mut config = SecurityConfig::new();
        config.add_allowed_extension(".txt".to_string()).unwrap();
        config.add_allowed_extension(".md".to_string()).unwrap();

        assert!(
            config.is_extension_allowed(".txt".to_string()),
            ".txt should be in allowed list"
        );
        assert!(
            config.is_extension_allowed(".md".to_string()),
            ".md should be in allowed list"
        );
        assert!(
            !config.is_extension_allowed(".exe".to_string()),
            ".exe should not be in allowed list"
        );
    }

    #[test]
    fn test_is_extension_allowed_empty_string() {
        let config = SecurityConfig::new();
        assert!(
            config.is_extension_allowed("".to_string()),
            "empty extension should be allowed when no allowed list"
        );
    }

    #[test]
    fn test_is_extension_allowed_case_sensitive() {
        let mut config = SecurityConfig::new();
        config.add_allowed_extension(".txt".to_string()).unwrap();

        assert!(
            config.is_extension_allowed(".txt".to_string()),
            "exact case should match"
        );
        // NOTE: Core library uses case-insensitive matching for extensions
        // This is intentional for cross-platform compatibility
        assert!(
            config.is_extension_allowed(".TXT".to_string()),
            "case-insensitive matching is used"
        );
    }

    // build() method tests
    #[test]
    fn test_build_returns_self() {
        let config = SecurityConfig::new();
        let built = config.build();
        assert_eq!(
            built.get_max_file_size(),
            config.get_max_file_size(),
            "build() should return same reference"
        );
    }

    #[test]
    fn test_builder_pattern_with_build() {
        let mut config = SecurityConfig::new();
        config.max_file_size(100_000_000).unwrap();
        config.max_total_size(1_000_000_000).unwrap();
        let result = config.build();

        assert_eq!(
            result.get_max_file_size(),
            100_000_000,
            "build() should work in builder chain"
        );
        assert_eq!(result.get_max_total_size(), 1_000_000_000);
    }

    // Float edge case tests
    #[test]
    fn test_builder_compression_ratio_rejects_negative_infinity() {
        let mut config = SecurityConfig::new();
        let result = config.max_compression_ratio(f64::NEG_INFINITY);
        assert!(result.is_err(), "negative infinity should be rejected");
    }

    #[test]
    fn test_builder_compression_ratio_accepts_very_small_positive() {
        let mut config = SecurityConfig::new();
        let result = config.max_compression_ratio(0.000001);
        assert!(
            result.is_ok(),
            "very small positive values should be accepted"
        );
        assert_eq!(config.get_max_compression_ratio(), 0.000001);
    }

    #[test]
    fn test_builder_compression_ratio_accepts_very_large() {
        let mut config = SecurityConfig::new();
        let result = config.max_compression_ratio(1_000_000.0);
        assert!(result.is_ok(), "very large values should be accepted");
        assert_eq!(config.get_max_compression_ratio(), 1_000_000.0);
    }

    // Clone and Debug tests
    #[test]
    fn test_security_config_clone() {
        let mut config = SecurityConfig::new();
        let _ = config.max_file_size(100_000_000).unwrap();

        let cloned = config.clone();
        assert_eq!(
            cloned.get_max_file_size(),
            100_000_000,
            "cloned config should have same values"
        );
    }

    #[test]
    fn test_security_config_debug() {
        let config = SecurityConfig::new();
        let debug_str = format!("{:?}", config);
        assert!(!debug_str.is_empty(), "debug output should not be empty");
        assert!(
            debug_str.contains("SecurityConfig"),
            "debug output should contain type name"
        );
    }

    // Tests for non-cloning getters
    #[test]
    fn test_get_allowed_extensions_count() {
        let mut config = SecurityConfig::new();
        assert_eq!(
            config.get_allowed_extensions_count(),
            0,
            "initial count should be 0"
        );

        config.add_allowed_extension(".txt".to_string()).unwrap();
        config.add_allowed_extension(".md".to_string()).unwrap();

        assert_eq!(
            config.get_allowed_extensions_count(),
            2,
            "count should reflect added extensions"
        );
    }

    #[test]
    fn test_has_allowed_extension() {
        let mut config = SecurityConfig::new();
        config.add_allowed_extension(".txt".to_string()).unwrap();

        assert!(
            config.has_allowed_extension(".txt".to_string()),
            "should find .txt"
        );
        assert!(
            !config.has_allowed_extension(".md".to_string()),
            "should not find .md"
        );
    }

    #[test]
    fn test_get_banned_path_components_count() {
        let mut config = SecurityConfig::new();
        // Default config already has 7 banned components
        let initial_count = config.get_banned_path_components_count();

        config
            .add_banned_component("node_modules".to_string())
            .unwrap();
        config
            .add_banned_component("custom_dir".to_string())
            .unwrap();

        assert_eq!(
            config.get_banned_path_components_count(),
            initial_count + 2,
            "count should reflect added components"
        );
    }

    #[test]
    fn test_has_banned_path_component() {
        let mut config = SecurityConfig::new();
        config
            .add_banned_component("node_modules".to_string())
            .unwrap();

        assert!(
            config.has_banned_path_component("node_modules".to_string()),
            "should find node_modules"
        );
        // .git is in default banned components
        assert!(
            config.has_banned_path_component(".git".to_string()),
            ".git should be in default banned components"
        );
    }
}
