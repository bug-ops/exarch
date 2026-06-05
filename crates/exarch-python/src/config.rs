//! Python bindings for `SecurityConfig`, `CreationConfig`, and
//! `ExtractionOptions`.

use exarch_core::ExtractionOptions as CoreExtractionOptions;
use exarch_core::SecurityConfig as CoreSecurityConfig;
use exarch_core::creation::CreationConfig as CoreCreationConfig;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// Maximum length for file extension strings (e.g., ".tar.gz")
const MAX_EXTENSION_LENGTH: usize = 255;

/// Maximum length for path component strings
const MAX_COMPONENT_LENGTH: usize = 255;

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
///     .with_max_file_size(100 * 1024 * 1024)
///     .allow_symlinks(True))
///
/// # Use permissive configuration for trusted archives
/// config = SecurityConfig.permissive()
/// ```
#[pyclass(name = "SecurityConfig", skip_from_py_object)]
#[derive(Clone)]
pub struct PySecurityConfig {
    inner: CoreSecurityConfig,
}

#[pymethods]
impl PySecurityConfig {
    /// Creates a new `SecurityConfig` with secure defaults.
    #[new]
    fn new() -> Self {
        Self {
            inner: CoreSecurityConfig::default(),
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
            inner: CoreSecurityConfig::permissive(),
        }
    }

    // Builder pattern methods - return Self for chaining

    /// Sets the maximum file size in bytes.
    fn with_max_file_size(mut slf: PyRefMut<'_, Self>, size: u64) -> PyRefMut<'_, Self> {
        slf.inner.max_file_size = size;
        slf
    }

    /// Sets the maximum total size in bytes.
    fn with_max_total_size(mut slf: PyRefMut<'_, Self>, size: u64) -> PyRefMut<'_, Self> {
        slf.inner.max_total_size = size;
        slf
    }

    /// Sets the maximum compression ratio.
    ///
    /// # Errors
    ///
    /// Returns `ValueError` if ratio is not a positive finite number.
    fn with_max_compression_ratio(
        mut slf: PyRefMut<'_, Self>,
        ratio: f64,
    ) -> PyResult<PyRefMut<'_, Self>> {
        if !ratio.is_finite() || ratio <= 0.0 {
            return Err(PyValueError::new_err(
                "compression ratio must be a positive finite number",
            ));
        }
        slf.inner.max_compression_ratio = ratio;
        Ok(slf)
    }

    /// Sets the maximum file count.
    fn with_max_file_count(mut slf: PyRefMut<'_, Self>, count: usize) -> PyRefMut<'_, Self> {
        slf.inner.max_file_count = count;
        slf
    }

    /// Sets the maximum path depth.
    fn with_max_path_depth(mut slf: PyRefMut<'_, Self>, depth: usize) -> PyRefMut<'_, Self> {
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

    /// Allows or denies solid 7z archives.
    ///
    /// Solid archives require reading all preceding entries to decompress any
    /// entry, which may allow a crafted archive to consume excessive
    /// memory. Disabled by default.
    #[pyo3(signature = (allow=true))]
    fn allow_solid_archives(mut slf: PyRefMut<'_, Self>, allow: bool) -> PyRefMut<'_, Self> {
        slf.inner.allow_solid_archives = allow;
        slf
    }

    /// Sets the maximum memory budget in bytes for decompressing a solid 7z
    /// block.
    ///
    /// Only enforced when `allow_solid_archives` is `True`. A crafted solid
    /// archive can force the decompressor to buffer many preceding entries in
    /// memory before reaching the target entry; this limit caps that buffer.
    ///
    /// # Errors
    ///
    /// Returns `ValueError` if `size` is zero.
    fn with_max_solid_block_memory(
        mut slf: PyRefMut<'_, Self>,
        size: u64,
    ) -> PyResult<PyRefMut<'_, Self>> {
        if size == 0 {
            return Err(PyValueError::new_err(
                "max_solid_block_memory must not be zero",
            ));
        }
        slf.inner.max_solid_block_memory = size;
        Ok(slf)
    }

    /// Sets whether to preserve permissions from archive.
    #[pyo3(signature = (preserve=true))]
    fn with_preserve_permissions(
        mut slf: PyRefMut<'_, Self>,
        preserve: bool,
    ) -> PyRefMut<'_, Self> {
        slf.inner.preserve_permissions = preserve;
        slf
    }

    /// Adds an allowed file extension.
    ///
    /// # Errors
    ///
    /// Returns `ValueError` if extension exceeds maximum length or contains
    /// null bytes.
    fn add_allowed_extension(
        mut slf: PyRefMut<'_, Self>,
        ext: String,
    ) -> PyResult<PyRefMut<'_, Self>> {
        if ext.contains('\0') {
            return Err(PyValueError::new_err(
                "extension contains null bytes - potential security issue",
            ));
        }
        if ext.len() > MAX_EXTENSION_LENGTH {
            return Err(PyValueError::new_err(format!(
                "extension exceeds maximum length of {MAX_EXTENSION_LENGTH} characters"
            )));
        }
        slf.inner.allowed_extensions.push(ext);
        Ok(slf)
    }

    /// Adds a banned path component.
    ///
    /// # Errors
    ///
    /// Returns `ValueError` if component exceeds maximum length or contains
    /// null bytes.
    fn add_banned_component(
        mut slf: PyRefMut<'_, Self>,
        component: String,
    ) -> PyResult<PyRefMut<'_, Self>> {
        if component.contains('\0') {
            return Err(PyValueError::new_err(
                "component contains null bytes - potential security issue",
            ));
        }
        if component.len() > MAX_COMPONENT_LENGTH {
            return Err(PyValueError::new_err(format!(
                "component exceeds maximum length of {MAX_COMPONENT_LENGTH} characters"
            )));
        }
        slf.inner.banned_path_components.push(component);
        Ok(slf)
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
    fn set_max_compression_ratio(&mut self, value: f64) -> PyResult<()> {
        if !value.is_finite() || value <= 0.0 {
            return Err(PyValueError::new_err(
                "compression ratio must be a positive finite number",
            ));
        }
        self.inner.max_compression_ratio = value;
        Ok(())
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
    fn get_max_solid_block_memory(&self) -> u64 {
        self.inner.max_solid_block_memory
    }

    #[setter]
    fn set_max_solid_block_memory(&mut self, value: u64) -> PyResult<()> {
        if value == 0 {
            return Err(PyValueError::new_err(
                "max_solid_block_memory must not be zero",
            ));
        }
        self.inner.max_solid_block_memory = value;
        Ok(())
    }

    /// Returns a copy of the allowed extensions list.
    ///
    /// # Performance
    ///
    /// This method clones the entire list on each access. If you need to access
    /// the extensions multiple times, cache the result in a local variable.
    #[getter]
    fn get_allowed_extensions(&self) -> Vec<String> {
        self.inner.allowed_extensions.clone()
    }

    #[setter]
    fn set_allowed_extensions(&mut self, value: Vec<String>) {
        self.inner.allowed_extensions = value;
    }

    /// Returns a copy of the banned path components list.
    ///
    /// # Performance
    ///
    /// This method clones the entire list on each access. If you need to access
    /// the components multiple times, cache the result in a local variable.
    #[getter]
    fn get_banned_path_components(&self) -> Vec<String> {
        self.inner.banned_path_components.clone()
    }

    #[setter]
    fn set_banned_path_components(&mut self, value: Vec<String>) {
        self.inner.banned_path_components = value;
    }

    /// Returns a debug string representation.
    ///
    /// # Performance
    ///
    /// This method allocates a new string on every call using `format!`.
    /// This is acceptable for debugging/logging but avoid calling in hot paths.
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
    /// Returns a reference to the inner `CoreSecurityConfig`.
    ///
    /// This is used internally to pass the configuration to the Rust extraction
    /// API.
    pub fn as_core(&self) -> &CoreSecurityConfig {
        &self.inner
    }
}

/// Configuration for archive creation.
///
/// Controls how archives are created from filesystem sources.
///
/// # Attributes
///
/// * `compression_level` - Compression level (1-9), default: 6
/// * `preserve_permissions` - Preserve file permissions, default: True
/// * `follow_symlinks` - Follow symlinks when adding files, default: False
/// * `include_hidden` - Include hidden files, default: False
/// * `exclude_patterns` - List of exclude patterns
/// * `max_file_size` - Maximum file size in bytes (None = no limit)
///
/// # Examples
///
/// ```python
/// # Use defaults
/// config = CreationConfig()
///
/// # Customize with builder pattern
/// config = (CreationConfig()
///     .with_compression_level(9)
///     .with_follow_symlinks(True))
/// ```
#[pyclass(name = "CreationConfig", skip_from_py_object)]
#[derive(Clone)]
pub struct PyCreationConfig {
    inner: CoreCreationConfig,
}

#[pymethods]
impl PyCreationConfig {
    /// Creates a new `CreationConfig` with default settings.
    #[new]
    fn new() -> Self {
        Self {
            inner: CoreCreationConfig::default(),
        }
    }

    /// Creates a `CreationConfig` with default settings.
    #[staticmethod]
    fn default() -> Self {
        Self::new()
    }

    /// Sets the compression level (1-9).
    ///
    /// # Errors
    ///
    /// Returns `ValueError` if level is not in range 1-9.
    fn with_compression_level(
        mut slf: PyRefMut<'_, Self>,
        level: u8,
    ) -> PyResult<PyRefMut<'_, Self>> {
        if !(1..=9).contains(&level) {
            return Err(PyValueError::new_err(
                "compression level must be in range 1-9",
            ));
        }
        slf.inner.compression_level = Some(level);
        Ok(slf)
    }

    /// Sets whether to preserve permissions.
    #[pyo3(signature = (preserve=true))]
    fn with_preserve_permissions(
        mut slf: PyRefMut<'_, Self>,
        preserve: bool,
    ) -> PyRefMut<'_, Self> {
        slf.inner.preserve_permissions = preserve;
        slf
    }

    /// Sets whether to follow symlinks.
    #[pyo3(signature = (follow=true))]
    fn with_follow_symlinks(mut slf: PyRefMut<'_, Self>, follow: bool) -> PyRefMut<'_, Self> {
        slf.inner.follow_symlinks = follow;
        slf
    }

    /// Sets whether to include hidden files.
    #[pyo3(signature = (include=true))]
    fn with_include_hidden(mut slf: PyRefMut<'_, Self>, include: bool) -> PyRefMut<'_, Self> {
        slf.inner.include_hidden = include;
        slf
    }

    /// Sets exclude patterns.
    fn with_exclude_patterns(
        mut slf: PyRefMut<'_, Self>,
        patterns: Vec<String>,
    ) -> PyRefMut<'_, Self> {
        slf.inner.exclude_patterns = patterns;
        slf
    }

    /// Sets maximum file size in bytes.
    fn with_max_file_size(mut slf: PyRefMut<'_, Self>, size: Option<u64>) -> PyRefMut<'_, Self> {
        slf.inner.max_file_size = size;
        slf
    }

    /// Finalizes the configuration.
    fn build(slf: PyRefMut<'_, Self>) -> PyRefMut<'_, Self> {
        slf
    }

    // Property getters and setters

    #[getter]
    fn get_compression_level(&self) -> Option<u8> {
        self.inner.compression_level
    }

    #[setter]
    fn set_compression_level(&mut self, value: Option<u8>) -> PyResult<()> {
        if let Some(level) = value
            && !(1..=9).contains(&level)
        {
            return Err(PyValueError::new_err(
                "compression level must be in range 1-9",
            ));
        }
        self.inner.compression_level = value;
        Ok(())
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
    fn get_follow_symlinks(&self) -> bool {
        self.inner.follow_symlinks
    }

    #[setter]
    fn set_follow_symlinks(&mut self, value: bool) {
        self.inner.follow_symlinks = value;
    }

    #[getter]
    fn get_include_hidden(&self) -> bool {
        self.inner.include_hidden
    }

    #[setter]
    fn set_include_hidden(&mut self, value: bool) {
        self.inner.include_hidden = value;
    }

    #[getter]
    fn get_exclude_patterns(&self) -> Vec<String> {
        self.inner.exclude_patterns.clone()
    }

    #[setter]
    fn set_exclude_patterns(&mut self, value: Vec<String>) {
        self.inner.exclude_patterns = value;
    }

    #[getter]
    fn get_max_file_size(&self) -> Option<u64> {
        self.inner.max_file_size
    }

    #[setter]
    fn set_max_file_size(&mut self, value: Option<u64>) {
        self.inner.max_file_size = value;
    }

    /// Returns a debug string representation.
    fn __repr__(&self) -> String {
        format!(
            "CreationConfig(compression_level={:?}, preserve_permissions={}, follow_symlinks={}, include_hidden={})",
            self.inner.compression_level,
            self.inner.preserve_permissions,
            self.inner.follow_symlinks,
            self.inner.include_hidden
        )
    }
}

impl PyCreationConfig {
    /// Returns a reference to the inner `CoreCreationConfig`.
    pub fn as_core(&self) -> &CoreCreationConfig {
        &self.inner
    }
}

/// Options controlling extraction behavior (non-security).
///
/// Separate from `SecurityConfig` to keep security settings focused.
/// These options control operational behavior such as duplicate handling.
///
/// # Attributes
///
/// * `skip_duplicates` - Skip duplicate entries silently instead of aborting
///   (default: `True`)
/// * `atomic` - Extract to a temp dir then rename atomically on success
///   (default: `False`)
///
/// # Examples
///
/// ```python
/// # Use defaults
/// opts = ExtractionOptions()
///
/// # Disable duplicate skipping
/// opts = ExtractionOptions().with_skip_duplicates(False)
///
/// # Enable atomic extraction
/// opts = ExtractionOptions().with_atomic(True)
/// ```
#[pyclass(name = "ExtractionOptions", skip_from_py_object)]
#[derive(Clone)]
pub struct PyExtractionOptions {
    inner: CoreExtractionOptions,
}

#[pymethods]
impl PyExtractionOptions {
    /// Creates a new `ExtractionOptions` with defaults.
    #[new]
    fn new() -> Self {
        Self {
            inner: CoreExtractionOptions::default(),
        }
    }

    /// Creates an `ExtractionOptions` with defaults.
    ///
    /// This is equivalent to calling `ExtractionOptions()`.
    #[staticmethod]
    fn default() -> Self {
        Self::new()
    }

    /// Sets whether duplicate archive entries are skipped silently.
    ///
    /// When `True` (default), duplicate entries produce a warning in the
    /// report. When `False`, a duplicate entry causes an error.
    #[pyo3(signature = (skip=true))]
    fn with_skip_duplicates(mut slf: PyRefMut<'_, Self>, skip: bool) -> PyRefMut<'_, Self> {
        slf.inner.skip_duplicates = skip;
        slf
    }

    /// Sets whether extraction uses a temporary directory for atomic commits.
    ///
    /// When `True`, files are extracted to a temp dir in the same parent as
    /// the output directory, then atomically renamed on completion. On failure
    /// the temp dir is removed, leaving the output directory untouched.
    /// Default: `False`.
    ///
    /// **Important:** atomic mode requires that the output directory does not
    /// already exist. If it does, extraction raises ``OutputExistsError``.
    /// Non-atomic mode extracts into an existing directory without error.
    ///
    /// # Examples
    ///
    /// ```python
    /// from exarch import ExtractionOptions
    /// opts = ExtractionOptions().with_atomic(True)
    /// assert opts.atomic == True
    /// ```
    #[pyo3(name = "with_atomic")]
    #[pyo3(signature = (atomic=true))]
    fn with_atomic(mut slf: PyRefMut<'_, Self>, atomic: bool) -> PyRefMut<'_, Self> {
        slf.inner.atomic = atomic;
        slf
    }

    /// Finalizes the configuration (for API consistency).
    fn build(slf: PyRefMut<'_, Self>) -> PyRefMut<'_, Self> {
        slf
    }

    #[getter]
    fn get_skip_duplicates(&self) -> bool {
        self.inner.skip_duplicates
    }

    #[setter]
    fn set_skip_duplicates(&mut self, value: bool) {
        self.inner.skip_duplicates = value;
    }

    #[getter]
    fn get_atomic(&self) -> bool {
        self.inner.atomic
    }

    #[setter]
    fn set_atomic(&mut self, value: bool) {
        self.inner.atomic = value;
    }

    /// Returns a debug string representation.
    fn __repr__(&self) -> String {
        format!(
            "ExtractionOptions(skip_duplicates={}, atomic={})",
            self.inner.skip_duplicates, self.inner.atomic
        )
    }
}

impl PyExtractionOptions {
    /// Returns a reference to the inner `CoreExtractionOptions`.
    pub fn as_core(&self) -> &CoreExtractionOptions {
        &self.inner
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::uninlined_format_args,
    clippy::float_cmp
)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PySecurityConfig::new();
        assert_eq!(
            config.get_max_file_size(),
            50 * 1024 * 1024,
            "Default max_file_size should be 50 MB"
        );
        assert_eq!(
            config.get_max_total_size(),
            500 * 1024 * 1024,
            "Default max_total_size should be 500 MB"
        );
        assert_eq!(
            config.get_max_file_count(),
            10_000,
            "Default max_file_count should be 10,000"
        );
        assert!(
            !config.get_preserve_permissions(),
            "Default preserve_permissions should be false"
        );
    }

    #[test]
    fn test_default_static_method() {
        let config = PySecurityConfig::default();
        assert_eq!(
            config.get_max_file_size(),
            50 * 1024 * 1024,
            "Static default() should have same values as new()"
        );
    }

    #[test]
    fn test_permissive_config() {
        let config = PySecurityConfig::permissive();
        assert!(
            config.inner.allowed.symlinks,
            "Permissive config should allow symlinks"
        );
        assert!(
            config.inner.allowed.hardlinks,
            "Permissive config should allow hardlinks"
        );
        assert!(
            config.inner.allowed.absolute_paths,
            "Permissive config should allow absolute paths"
        );
        assert!(
            config.get_preserve_permissions(),
            "Permissive config should preserve permissions"
        );
    }

    #[test]
    fn test_builder_pattern_method_chaining() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let config = PySecurityConfig::new();
            let py_config = Py::new(py, config).expect("Failed to create Py object");
            let obj = py_config.bind(py);

            // Call methods through Python API
            obj.call_method1("with_max_file_size", (100_000_000_u64,))
                .expect("with_max_file_size call failed");
            obj.call_method1("with_max_total_size", (1_000_000_000_u64,))
                .expect("with_max_total_size call failed");
            obj.call_method1("with_max_file_count", (50_000_usize,))
                .expect("with_max_file_count call failed");

            let result = py_config.borrow(py);
            assert_eq!(
                result.get_max_file_size(),
                100_000_000,
                "Builder pattern should set max_file_size"
            );
            assert_eq!(
                result.get_max_total_size(),
                1_000_000_000,
                "Builder pattern should set max_total_size"
            );
            assert_eq!(
                result.get_max_file_count(),
                50_000,
                "Builder pattern should set max_file_count"
            );
        });
    }

    #[test]
    fn test_builder_compression_ratio_valid() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let config = PySecurityConfig::new();
            let py_config = Py::new(py, config).expect("Failed to create Py object");
            let obj = py_config.bind(py);

            let result = obj.call_method1("with_max_compression_ratio", (200.0_f64,));
            assert!(result.is_ok(), "Should accept valid compression ratio");
            assert_eq!(
                py_config.borrow(py).get_max_compression_ratio(),
                200.0,
                "Compression ratio should be set"
            );
        });
    }

    #[test]
    fn test_builder_compression_ratio_rejects_nan() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let config = PySecurityConfig::new();
            let py_config = Py::new(py, config).expect("Failed to create Py object");
            let obj = py_config.bind(py);

            let result = obj.call_method1("with_max_compression_ratio", (f64::NAN,));
            assert!(result.is_err(), "Should reject NaN compression ratio");
        });
    }

    #[test]
    fn test_builder_compression_ratio_rejects_infinity() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let config = PySecurityConfig::new();
            let py_config = Py::new(py, config).expect("Failed to create Py object");
            let obj = py_config.bind(py);

            let result = obj.call_method1("with_max_compression_ratio", (f64::INFINITY,));
            assert!(result.is_err(), "Should reject infinite compression ratio");
        });
    }

    #[test]
    fn test_builder_compression_ratio_rejects_negative() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let config = PySecurityConfig::new();
            let py_config = Py::new(py, config).expect("Failed to create Py object");
            let obj = py_config.bind(py);

            let result = obj.call_method1("with_max_compression_ratio", (-10.0_f64,));
            assert!(result.is_err(), "Should reject negative compression ratio");
        });
    }

    #[test]
    fn test_builder_compression_ratio_rejects_zero() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let config = PySecurityConfig::new();
            let py_config = Py::new(py, config).expect("Failed to create Py object");
            let obj = py_config.bind(py);

            let result = obj.call_method1("with_max_compression_ratio", (0.0_f64,));
            assert!(result.is_err(), "Should reject zero compression ratio");
        });
    }

    #[test]
    fn test_property_setters_all_numeric() {
        let mut config = PySecurityConfig::new();

        config.set_max_file_size(100_000_000);
        assert_eq!(
            config.get_max_file_size(),
            100_000_000,
            "Property setter should update max_file_size"
        );

        config.set_max_total_size(2_000_000_000);
        assert_eq!(
            config.get_max_total_size(),
            2_000_000_000,
            "Property setter should update max_total_size"
        );

        config.set_max_file_count(20_000);
        assert_eq!(
            config.get_max_file_count(),
            20_000,
            "Property setter should update max_file_count"
        );

        config.set_max_path_depth(64);
        assert_eq!(
            config.get_max_path_depth(),
            64,
            "Property setter should update max_path_depth"
        );
    }

    #[test]
    fn test_property_setter_compression_ratio_valid() {
        let mut config = PySecurityConfig::new();
        let result = config.set_max_compression_ratio(150.0);
        assert!(
            result.is_ok(),
            "Should accept valid compression ratio: {:?}",
            result.err()
        );
        assert_eq!(config.get_max_compression_ratio(), 150.0);
    }

    #[test]
    fn test_property_setter_compression_ratio_rejects_invalid() {
        let mut config = PySecurityConfig::new();
        assert!(
            config.set_max_compression_ratio(f64::NAN).is_err(),
            "Should reject NaN"
        );
        assert!(
            config.set_max_compression_ratio(f64::INFINITY).is_err(),
            "Should reject Infinity"
        );
        assert!(
            config.set_max_compression_ratio(-5.0).is_err(),
            "Should reject negative"
        );
    }

    #[test]
    fn test_property_setter_preserve_permissions() {
        let mut config = PySecurityConfig::new();
        assert!(!config.get_preserve_permissions());

        config.set_preserve_permissions(true);
        assert!(
            config.get_preserve_permissions(),
            "Property setter should update preserve_permissions"
        );
    }

    #[test]
    fn test_add_allowed_extension_valid() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let config = PySecurityConfig::new();
            let py_config = Py::new(py, config).expect("Failed to create Py object");
            let obj = py_config.bind(py);

            let result = obj.call_method1("add_allowed_extension", (".txt",));
            assert!(result.is_ok(), "Should accept valid extension");

            let extensions = py_config.borrow(py).get_allowed_extensions();
            assert!(
                extensions.contains(&".txt".to_string()),
                "Extension should be added to list"
            );
        });
    }

    #[test]
    fn test_add_allowed_extension_rejects_null_bytes() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let config = PySecurityConfig::new();
            let py_config = Py::new(py, config).expect("Failed to create Py object");
            let obj = py_config.bind(py);

            let result = obj.call_method1("add_allowed_extension", (".txt\0",));
            assert!(result.is_err(), "Should reject extension with null bytes");
        });
    }

    #[test]
    fn test_add_allowed_extension_rejects_too_long() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let config = PySecurityConfig::new();
            let py_config = Py::new(py, config).expect("Failed to create Py object");
            let obj = py_config.bind(py);

            let long_ext = "x".repeat(MAX_EXTENSION_LENGTH + 1);
            let result = obj.call_method1("add_allowed_extension", (long_ext,));
            assert!(
                result.is_err(),
                "Should reject extension exceeding max length"
            );
        });
    }

    #[test]
    fn test_add_banned_component_valid() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let config = PySecurityConfig::new();
            let py_config = Py::new(py, config).expect("Failed to create Py object");
            let obj = py_config.bind(py);

            let result = obj.call_method1("add_banned_component", ("node_modules",));
            assert!(result.is_ok(), "Should accept valid component");

            let components = py_config.borrow(py).get_banned_path_components();
            assert!(
                components.contains(&"node_modules".to_string()),
                "Component should be added to list"
            );
        });
    }

    #[test]
    fn test_add_banned_component_rejects_null_bytes() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let config = PySecurityConfig::new();
            let py_config = Py::new(py, config).expect("Failed to create Py object");
            let obj = py_config.bind(py);

            let result = obj.call_method1("add_banned_component", ("bad\0",));
            assert!(result.is_err(), "Should reject component with null bytes");
        });
    }

    #[test]
    fn test_add_banned_component_rejects_too_long() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let config = PySecurityConfig::new();
            let py_config = Py::new(py, config).expect("Failed to create Py object");
            let obj = py_config.bind(py);

            let long_component = "x".repeat(MAX_COMPONENT_LENGTH + 1);
            let result = obj.call_method1("add_banned_component", (long_component,));
            assert!(
                result.is_err(),
                "Should reject component exceeding max length"
            );
        });
    }

    #[test]
    fn test_validation_methods() {
        let config = PySecurityConfig::new();
        assert!(
            config.is_path_component_allowed("src"),
            "Should allow normal path components"
        );
        assert!(
            !config.is_path_component_allowed(".git"),
            "Should reject .git directory"
        );
        assert!(
            !config.is_path_component_allowed(".ssh"),
            "Should reject .ssh directory"
        );
    }

    #[test]
    fn test_is_extension_allowed_empty_list() {
        let config = PySecurityConfig::new();
        assert!(
            config.is_extension_allowed("txt"),
            "Empty allowed_extensions list should allow all extensions"
        );
    }

    #[test]
    fn test_repr() {
        let config = PySecurityConfig::new();
        let repr = config.__repr__();
        assert!(
            repr.contains("SecurityConfig"),
            "repr should contain class name"
        );
        assert!(
            repr.contains("max_file_size"),
            "repr should contain max_file_size"
        );
    }

    #[test]
    fn test_as_core() {
        let config = PySecurityConfig::new();
        let core_config = config.as_core();
        assert_eq!(
            core_config.max_file_size,
            50 * 1024 * 1024,
            "as_core() should return reference to inner config"
        );
    }

    #[test]
    fn test_default_max_solid_block_memory() {
        let config = PySecurityConfig::new();
        assert_eq!(
            config.get_max_solid_block_memory(),
            512 * 1024 * 1024,
            "Default max_solid_block_memory should be 512 MB"
        );
    }

    #[test]
    fn test_builder_max_solid_block_memory_valid() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let config = PySecurityConfig::new();
            let py_config = Py::new(py, config).expect("Failed to create Py object");
            let obj = py_config.bind(py);

            let result = obj.call_method1("with_max_solid_block_memory", (256 * 1024 * 1024_u64,));
            assert!(result.is_ok(), "Should accept valid memory size");
            assert_eq!(
                py_config.borrow(py).get_max_solid_block_memory(),
                256 * 1024 * 1024,
                "with_max_solid_block_memory should be updated"
            );
        });
    }

    #[test]
    fn test_builder_max_solid_block_memory_rejects_zero() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let config = PySecurityConfig::new();
            let py_config = Py::new(py, config).expect("Failed to create Py object");
            let obj = py_config.bind(py);

            let result = obj.call_method1("with_max_solid_block_memory", (0_u64,));
            assert!(result.is_err(), "Should reject zero memory size");
        });
    }

    #[test]
    fn test_property_setter_max_solid_block_memory_valid() {
        let mut config = PySecurityConfig::new();
        let result = config.set_max_solid_block_memory(128 * 1024 * 1024);
        assert!(result.is_ok(), "Should accept valid memory size");
        assert_eq!(
            config.get_max_solid_block_memory(),
            128 * 1024 * 1024,
            "Property setter should update max_solid_block_memory"
        );
    }

    #[test]
    fn test_property_setter_max_solid_block_memory_rejects_zero() {
        let mut config = PySecurityConfig::new();
        assert!(
            config.set_max_solid_block_memory(0).is_err(),
            "Should reject zero"
        );
    }
}
