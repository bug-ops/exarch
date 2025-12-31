//! Python bindings for `SecurityConfig`.

use exarch_core::SecurityConfig as CoreConfig;
use pyo3::prelude::*;

/// Security configuration for archive extraction.
///
/// All security features default to deny (secure-by-default policy).
///
/// # Attributes
///
/// * `max_file_size` - Maximum size for a single file in bytes (default: 50 MB)
/// * `max_total_size` - Maximum total size for all files in bytes (default: 500
///   MB)
/// * `max_compression_ratio` - Maximum compression ratio allowed (default:
///   100.0)
/// * `max_file_count` - Maximum number of files (default: 10,000)
/// * `max_path_depth` - Maximum path depth allowed (default: 32)
/// * `preserve_permissions` - Preserve file permissions from archive (default:
///   False)
/// * `allowed_extensions` - List of allowed file extensions (empty = allow all)
/// * `banned_path_components` - List of banned path components
///
/// # Examples
///
/// ```python
/// # Use secure defaults
/// config = SecurityConfig()
///
/// # Customize with builder pattern
/// config = (SecurityConfig()
///     .max_file_size(100 * 1024 * 1024)
///     .allow_symlinks(True))
///
/// # Use permissive configuration for trusted archives
/// config = SecurityConfig.permissive()
/// ```
#[pyclass(name = "SecurityConfig")]
#[derive(Clone)]
pub struct PySecurityConfig {
    inner: CoreConfig,
}

#[pymethods]
impl PySecurityConfig {
    /// Creates a new `SecurityConfig` with secure defaults.
    #[new]
    fn new() -> Self {
        Self {
            inner: CoreConfig::default(),
        }
    }

    /// Creates a `SecurityConfig` with secure defaults.
    ///
    /// This is equivalent to calling `SecurityConfig()`.
    #[staticmethod]
    fn default() -> Self {
        Self::new()
    }

    /// Creates a permissive configuration for trusted archives.
    ///
    /// Enables: symlinks, hardlinks, absolute paths, world-writable files.
    /// Use only for archives from trusted sources.
    #[staticmethod]
    fn permissive() -> Self {
        Self {
            inner: CoreConfig::permissive(),
        }
    }

    // Builder pattern methods - return Self for chaining

    /// Sets the maximum file size in bytes.
    fn max_file_size(mut slf: PyRefMut<'_, Self>, size: u64) -> PyRefMut<'_, Self> {
        slf.inner.max_file_size = size;
        slf
    }

    /// Sets the maximum total size in bytes.
    fn max_total_size(mut slf: PyRefMut<'_, Self>, size: u64) -> PyRefMut<'_, Self> {
        slf.inner.max_total_size = size;
        slf
    }

    /// Sets the maximum compression ratio.
    fn max_compression_ratio(mut slf: PyRefMut<'_, Self>, ratio: f64) -> PyRefMut<'_, Self> {
        slf.inner.max_compression_ratio = ratio;
        slf
    }

    /// Sets the maximum file count.
    fn max_file_count(mut slf: PyRefMut<'_, Self>, count: usize) -> PyRefMut<'_, Self> {
        slf.inner.max_file_count = count;
        slf
    }

    /// Sets the maximum path depth.
    fn max_path_depth(mut slf: PyRefMut<'_, Self>, depth: usize) -> PyRefMut<'_, Self> {
        slf.inner.max_path_depth = depth;
        slf
    }

    /// Allows or denies symlinks.
    #[pyo3(signature = (allow=true))]
    fn allow_symlinks(mut slf: PyRefMut<'_, Self>, allow: bool) -> PyRefMut<'_, Self> {
        slf.inner.allowed.symlinks = allow;
        slf
    }

    /// Allows or denies hardlinks.
    #[pyo3(signature = (allow=true))]
    fn allow_hardlinks(mut slf: PyRefMut<'_, Self>, allow: bool) -> PyRefMut<'_, Self> {
        slf.inner.allowed.hardlinks = allow;
        slf
    }

    /// Allows or denies absolute paths.
    #[pyo3(signature = (allow=true))]
    fn allow_absolute_paths(mut slf: PyRefMut<'_, Self>, allow: bool) -> PyRefMut<'_, Self> {
        slf.inner.allowed.absolute_paths = allow;
        slf
    }

    /// Allows or denies world-writable files.
    #[pyo3(signature = (allow=true))]
    fn allow_world_writable(mut slf: PyRefMut<'_, Self>, allow: bool) -> PyRefMut<'_, Self> {
        slf.inner.allowed.world_writable = allow;
        slf
    }

    /// Sets whether to preserve permissions from archive.
    #[pyo3(signature = (preserve=true))]
    fn preserve_permissions(mut slf: PyRefMut<'_, Self>, preserve: bool) -> PyRefMut<'_, Self> {
        slf.inner.preserve_permissions = preserve;
        slf
    }

    /// Adds an allowed file extension.
    fn add_allowed_extension(mut slf: PyRefMut<'_, Self>, ext: String) -> PyRefMut<'_, Self> {
        slf.inner.allowed_extensions.push(ext);
        slf
    }

    /// Adds a banned path component.
    fn add_banned_component(mut slf: PyRefMut<'_, Self>, component: String) -> PyRefMut<'_, Self> {
        slf.inner.banned_path_components.push(component);
        slf
    }

    /// Finalizes the configuration (for API consistency).
    ///
    /// This method is provided for builder pattern consistency but is optional.
    /// The configuration is always valid and can be used directly.
    fn build(slf: PyRefMut<'_, Self>) -> PyRefMut<'_, Self> {
        slf
    }

    // Validation methods

    /// Checks if a path component is allowed.
    fn is_path_component_allowed(&self, component: &str) -> bool {
        self.inner.is_path_component_allowed(component)
    }

    /// Checks if a file extension is allowed.
    fn is_extension_allowed(&self, extension: &str) -> bool {
        self.inner.is_extension_allowed(extension)
    }

    // Property getters and setters

    #[getter]
    fn get_max_file_size(&self) -> u64 {
        self.inner.max_file_size
    }

    #[setter]
    fn set_max_file_size(&mut self, value: u64) {
        self.inner.max_file_size = value;
    }

    #[getter]
    fn get_max_total_size(&self) -> u64 {
        self.inner.max_total_size
    }

    #[setter]
    fn set_max_total_size(&mut self, value: u64) {
        self.inner.max_total_size = value;
    }

    #[getter]
    fn get_max_compression_ratio(&self) -> f64 {
        self.inner.max_compression_ratio
    }

    #[setter]
    fn set_max_compression_ratio(&mut self, value: f64) {
        self.inner.max_compression_ratio = value;
    }

    #[getter]
    fn get_max_file_count(&self) -> usize {
        self.inner.max_file_count
    }

    #[setter]
    fn set_max_file_count(&mut self, value: usize) {
        self.inner.max_file_count = value;
    }

    #[getter]
    fn get_max_path_depth(&self) -> usize {
        self.inner.max_path_depth
    }

    #[setter]
    fn set_max_path_depth(&mut self, value: usize) {
        self.inner.max_path_depth = value;
    }

    #[getter]
    fn get_preserve_permissions(&self) -> bool {
        self.inner.preserve_permissions
    }

    #[setter]
    fn set_preserve_permissions(&mut self, value: bool) {
        self.inner.preserve_permissions = value;
    }

    #[getter]
    fn get_allowed_extensions(&self) -> Vec<String> {
        self.inner.allowed_extensions.clone()
    }

    #[setter]
    fn set_allowed_extensions(&mut self, value: Vec<String>) {
        self.inner.allowed_extensions = value;
    }

    #[getter]
    fn get_banned_path_components(&self) -> Vec<String> {
        self.inner.banned_path_components.clone()
    }

    #[setter]
    fn set_banned_path_components(&mut self, value: Vec<String>) {
        self.inner.banned_path_components = value;
    }

    /// Returns a debug string representation.
    fn __repr__(&self) -> String {
        format!(
            "SecurityConfig(max_file_size={}, max_total_size={}, max_compression_ratio={:.1}, max_file_count={}, max_path_depth={})",
            self.inner.max_file_size,
            self.inner.max_total_size,
            self.inner.max_compression_ratio,
            self.inner.max_file_count,
            self.inner.max_path_depth
        )
    }
}

impl PySecurityConfig {
    /// Returns a reference to the inner `CoreConfig`.
    ///
    /// This is used internally to pass the configuration to the Rust extraction
    /// API.
    pub fn as_core(&self) -> &CoreConfig {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PySecurityConfig::new();
        assert_eq!(config.get_max_file_size(), 50 * 1024 * 1024);
        assert_eq!(config.get_max_total_size(), 500 * 1024 * 1024);
        assert_eq!(config.get_max_file_count(), 10_000);
        assert!(!config.get_preserve_permissions());
    }

    #[test]
    fn test_permissive_config() {
        let config = PySecurityConfig::permissive();
        assert!(config.inner.allowed.symlinks);
        assert!(config.inner.allowed.hardlinks);
        assert!(config.inner.allowed.absolute_paths);
        assert!(config.get_preserve_permissions());
    }

    #[test]
    fn test_property_setters() {
        let mut config = PySecurityConfig::new();
        config.set_max_file_size(100_000_000);
        assert_eq!(config.get_max_file_size(), 100_000_000);
    }

    #[test]
    fn test_validation_methods() {
        let config = PySecurityConfig::new();
        assert!(config.is_path_component_allowed("src"));
        assert!(!config.is_path_component_allowed(".git"));
        assert!(!config.is_path_component_allowed(".ssh"));
    }

    #[test]
    fn test_repr() {
        let config = PySecurityConfig::new();
        let repr = config.__repr__();
        assert!(repr.contains("SecurityConfig"));
        assert!(repr.contains("max_file_size"));
    }
}
