//! Python bindings for `SecurityConfig`, `CreationConfig`,
//! `ExtractionOptions`, and `VerificationOptions`.

use exarch_core::ArchiveError;
use exarch_core::CompressionLevel;
use exarch_core::ConfigProblem;
use exarch_core::ConfigSetting;
use exarch_core::CreationConfig as CoreCreationConfig;
use exarch_core::DecompressionBudget;
use exarch_core::EntryPattern;
use exarch_core::ExistingFiles;
use exarch_core::Extension;
use exarch_core::ExtensionFilter;
use exarch_core::ExtractionOptions as CoreExtractionOptions;
use exarch_core::IntegrityCheck;
use exarch_core::Limit;
use exarch_core::ListOptions as CoreListOptions;
use exarch_core::ParallelDecode;
use exarch_core::PathComponentName;
use exarch_core::PathRewrite;
use exarch_core::PermissionPolicy;
use exarch_core::RatioLimit;
use exarch_core::RequestedLevel;
use exarch_core::SecurityConfig as CoreSecurityConfig;
use exarch_core::Staging;
use exarch_core::StripComponents;
use exarch_core::VerificationOptions as CoreVerificationOptions;
use exarch_core::ZipConsistencyPolicy;
use exarch_core::positive_from_i128;
use pyo3::exceptions::PyOverflowError;
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyBool;
use pyo3::types::PyInt;
use std::num::NonZeroU64;
use std::num::NonZeroUsize;

use crate::buffer::parse_one;
use crate::error::convert_error;

/// A Python `int` as a setter receives it: `bool` is refused, and an integer
/// beyond 128 bits is kept as its sign, so every out-of-range value reaches
/// the core parsers instead of becoming pyo3's `OverflowError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PyInteger {
    /// An integer that fits in 128 bits.
    Fits(i128),
    /// An integer beyond 128 bits, kept as its sign.
    Beyond {
        /// Whether it is below zero.
        negative: bool,
    },
}

impl From<i64> for PyInteger {
    fn from(value: i64) -> Self {
        Self::Fits(i128::from(value))
    }
}

impl<'a, 'py> FromPyObject<'a, 'py> for PyInteger {
    type Error = PyErr;

    fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        if obj.is_instance_of::<PyBool>() {
            return Err(PyTypeError::new_err("expected an int, not bool"));
        }
        let py = obj.py();
        let index = if obj.is_instance_of::<PyInt>() {
            obj.to_owned().into_any()
        } else if obj.hasattr("__index__")? {
            obj.call_method0("__index__")?
        } else {
            return Err(PyTypeError::new_err(format!(
                "expected an int, got {}",
                obj.get_type().name()?
            )));
        };
        match index.extract::<i128>() {
            Ok(value) => Ok(Self::Fits(value)),
            Err(err) if err.is_instance_of::<PyOverflowError>(py) => Ok(Self::Beyond {
                negative: index.lt(0)?,
            }),
            Err(err) => Err(err),
        }
    }
}

/// A Python number for a ratio limit: `bool` is refused, and an integer too
/// large for a float is read as infinite so core refuses it as not finite.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PyRatio(f64);

impl<'a, 'py> FromPyObject<'a, 'py> for PyRatio {
    type Error = PyErr;

    fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        if obj.is_instance_of::<PyBool>() {
            return Err(PyTypeError::new_err("expected a number, not bool"));
        }
        match obj.extract::<f64>() {
            Ok(value) => Ok(Self(value)),
            Err(err) if err.is_instance_of::<PyOverflowError>(obj.py()) => Ok(Self(f64::INFINITY)),
            Err(err) => Err(err),
        }
    }
}

impl From<f64> for PyRatio {
    fn from(value: f64) -> Self {
        Self(value)
    }
}

impl PyRatio {
    fn limit(self) -> PyResult<RatioLimit> {
        self.limit_of(ConfigSetting::MaxCompressionRatio)
    }

    fn limit_of(self, setting: ConfigSetting) -> PyResult<RatioLimit> {
        RatioLimit::parse(setting, self.0).map_err(convert_error)
    }
}

impl PyInteger {
    fn refuse(setting: ConfigSetting, problem: ConfigProblem) -> PyErr {
        convert_error(ArchiveError::InvalidConfiguration { setting, problem })
    }

    /// The value as a positive 64-bit count of `setting`.
    pub fn positive(self, setting: ConfigSetting) -> PyResult<NonZeroU64> {
        match self {
            Self::Fits(value) => positive_from_i128(setting, value).map_err(convert_error),
            Self::Beyond { negative: true } => Err(Self::refuse(setting, ConfigProblem::Negative)),
            Self::Beyond { negative: false } => Err(Self::refuse(
                setting,
                ConfigProblem::TooLarge { max: u64::MAX },
            )),
        }
    }

    /// The value as a positive count of `setting` that fits in `usize`.
    pub fn positive_usize(self, setting: ConfigSetting) -> PyResult<NonZeroUsize> {
        NonZeroUsize::try_from(self.positive(setting)?).map_err(|_| {
            Self::refuse(
                setting,
                ConfigProblem::TooLarge {
                    max: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
                },
            )
        })
    }
}

fn bytes_limit(setting: ConfigSetting, value: PyInteger) -> PyResult<Limit<NonZeroU64>> {
    value.positive(setting).map(Limit::Bounded)
}

fn optional_bytes_limit(
    setting: ConfigSetting,
    value: Option<PyInteger>,
) -> PyResult<Limit<NonZeroU64>> {
    value.map_or(Ok(Limit::Unbounded), |bytes| bytes_limit(setting, bytes))
}

fn count_limit(setting: ConfigSetting, value: PyInteger) -> PyResult<Limit<NonZeroUsize>> {
    value.positive_usize(setting).map(Limit::Bounded)
}

/// The bound of a byte limit, or `None` when it is unbounded.
const fn bytes_bound(limit: Limit<NonZeroU64>) -> Option<u64> {
    match limit {
        Limit::Bounded(bound) => Some(bound.get()),
        Limit::Unbounded => None,
    }
}

/// The bound of a count limit, or `None` when it is unbounded.
const fn count_bound(limit: Limit<NonZeroUsize>) -> Option<usize> {
    match limit {
        Limit::Bounded(bound) => Some(bound.get()),
        Limit::Unbounded => None,
    }
}

fn parse_exclude_patterns(patterns: &[String]) -> PyResult<Vec<exarch_core::EntryPattern>> {
    patterns
        .iter()
        .map(|pattern| exarch_core::EntryPattern::try_from(pattern.as_str()).map_err(convert_error))
        .collect()
}

/// Parses the string form shared with `ExistingFiles::as_str`.
pub fn parse_existing_files(value: &str) -> PyResult<ExistingFiles> {
    parse_one(ConfigSetting::ExistingFiles, value)
}

/// Parses the string form shared with `Staging::as_str`.
pub fn parse_staging(value: &str) -> PyResult<Staging> {
    parse_one(ConfigSetting::Staging, value)
}

/// Parses a Python integer of any size into a [`CompressionLevel`], so every
/// out-of-range value is an `InvalidCompressionLevelError` rather than an
/// `OverflowError`.
fn compression_level(level: PyInteger) -> PyResult<CompressionLevel> {
    match level {
        PyInteger::Fits(level) => CompressionLevel::from_i128(level),
        PyInteger::Beyond { .. } => Err(ArchiveError::InvalidCompressionLevel {
            level: RequestedLevel::OutOfRange,
        }),
    }
    .map_err(convert_error)
}

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
///   100.0); not applied to solid 7z blocks, which use
///   `max_solid_compression_ratio`
/// * `max_file_count` - Maximum number of entries; every entry counts in every
///   operation and format: files, directories, links and skipped entries
///   (default: 10,000)
/// * `max_path_depth` - Maximum path depth allowed (default: 32)
/// * `preserve_permissions` - Preserve file permissions from archive (default:
///   False)
/// * `allowed_extensions` - List of allowed file extensions, or `None` to allow
///   every extension (the default); an empty list is refused, and assigning
///   `None` is the only way to clear the list
/// * `banned_path_components` - List of banned path components
/// * `allow_windows_reserved_names` - Whether names Windows reserves (`CON`,
///   `NUL`, ...) are extracted (default: False). On-disk extraction checks them
///   only on Windows; in-memory and callback extraction check them on every
///   host
/// * `max_tar_metadata_bytes` - Most bytes of TAR header and metadata records
///   between two entries (default: 4 MiB)
/// * `max_decoder_memory` - Most memory in bytes a compressed-TAR or 7z decoder
///   may hold (default: 256 MiB)
/// * `compressed_member_allowance` - Base number of gzip members or bzip2
///   streams a compressed TAR may hold (default: 10,000)
/// * `max_solid_compression_ratio` - Compression ratio limit of a whole solid
///   7z block, or `None` while solid archives are not allowed
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
///     .with_allow_symlinks(True))
///
/// # Use permissive configuration for trusted archives
/// config = SecurityConfig.permissive()
/// ```
#[pyclass(name = "SecurityConfig")]
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
    fn with_max_file_size(
        mut slf: PyRefMut<'_, Self>,
        size: PyInteger,
    ) -> PyResult<PyRefMut<'_, Self>> {
        slf.inner.max_file_size = bytes_limit(ConfigSetting::MaxFileSize, size)?;
        Ok(slf)
    }

    /// Sets the maximum total size in bytes.
    fn with_max_total_size(
        mut slf: PyRefMut<'_, Self>,
        size: PyInteger,
    ) -> PyResult<PyRefMut<'_, Self>> {
        slf.inner.max_total_size = bytes_limit(ConfigSetting::MaxTotalSize, size)?;
        Ok(slf)
    }

    /// Sets the maximum compression ratio.
    ///
    /// Solid 7z blocks are exempt: each block is checked as a whole against the
    /// limit of `with_max_solid_compression_ratio` (default 1000).
    ///
    /// # Errors
    ///
    /// Returns `ValueError` if ratio is not a positive finite number.
    fn with_max_compression_ratio(
        mut slf: PyRefMut<'_, Self>,
        ratio: PyRatio,
    ) -> PyResult<PyRefMut<'_, Self>> {
        slf.inner.max_compression_ratio = ratio.limit()?;
        Ok(slf)
    }

    /// Sets the maximum file count.
    fn with_max_file_count(
        mut slf: PyRefMut<'_, Self>,
        count: PyInteger,
    ) -> PyResult<PyRefMut<'_, Self>> {
        slf.inner.max_file_count = count_limit(ConfigSetting::MaxFileCount, count)?;
        Ok(slf)
    }

    /// Sets the maximum path depth.
    fn with_max_path_depth(
        mut slf: PyRefMut<'_, Self>,
        depth: PyInteger,
    ) -> PyResult<PyRefMut<'_, Self>> {
        slf.inner.max_path_depth = depth.positive_usize(ConfigSetting::MaxPathDepth)?;
        Ok(slf)
    }

    /// Allows or denies symlinks.
    #[pyo3(signature = (allow=true))]
    fn with_allow_symlinks(mut slf: PyRefMut<'_, Self>, allow: bool) -> PyRefMut<'_, Self> {
        slf.inner.allowed.symlinks = exarch_core::Admit::from_allowed(allow);
        slf
    }

    /// Allows or denies hardlinks.
    #[pyo3(signature = (allow=true))]
    fn with_allow_hardlinks(mut slf: PyRefMut<'_, Self>, allow: bool) -> PyRefMut<'_, Self> {
        slf.inner.allowed.hardlinks = exarch_core::Admit::from_allowed(allow);
        slf
    }

    /// Allows or denies absolute paths.
    #[pyo3(signature = (allow=true))]
    fn with_allow_absolute_paths(mut slf: PyRefMut<'_, Self>, allow: bool) -> PyRefMut<'_, Self> {
        slf.inner.allowed.absolute_paths = exarch_core::Admit::from_allowed(allow);
        slf
    }

    /// Allows or denies world-writable files.
    #[pyo3(signature = (allow=true))]
    fn with_allow_world_writable(mut slf: PyRefMut<'_, Self>, allow: bool) -> PyRefMut<'_, Self> {
        slf.inner.allowed.world_writable = exarch_core::Admit::from_allowed(allow);
        slf
    }

    /// Allows or denies names Windows reserves (`CON`, `NUL`, ...).
    ///
    /// Refused by default on every platform, because an archive extracted here
    /// may be unpacked on Windows later.
    #[pyo3(signature = (allow=true))]
    fn with_allow_windows_reserved_names(
        mut slf: PyRefMut<'_, Self>,
        allow: bool,
    ) -> PyRefMut<'_, Self> {
        slf.inner.allowed.windows_reserved_names = exarch_core::Admit::from_allowed(allow);
        slf
    }

    /// Sets the most bytes of TAR header and metadata records (GNU long names,
    /// PAX headers, sparse blocks) read between two consecutive entries.
    ///
    /// # Errors
    ///
    /// Returns `ValueError` if `size` is zero, negative or above 2**64 - 1.
    fn with_max_tar_metadata_bytes(
        mut slf: PyRefMut<'_, Self>,
        size: PyInteger,
    ) -> PyResult<PyRefMut<'_, Self>> {
        slf.inner.max_tar_metadata_bytes = size.positive(ConfigSetting::MaxTarMetadataBytes)?;
        Ok(slf)
    }

    /// Sets the most memory in bytes a decoder may hold while decoding a
    /// compressed TAR or a 7z block.
    ///
    /// # Errors
    ///
    /// Returns `ValueError` if `size` is zero, negative or above 2**64 - 1.
    fn with_max_decoder_memory(
        mut slf: PyRefMut<'_, Self>,
        size: PyInteger,
    ) -> PyResult<PyRefMut<'_, Self>> {
        slf.inner.max_decoder_memory = size.positive(ConfigSetting::MaxDecoderMemory)?;
        Ok(slf)
    }

    /// Sets the base number of gzip members or bzip2 streams a compressed TAR
    /// may hold; every 16 KiB of decoded output adds one more.
    ///
    /// # Errors
    ///
    /// Returns `ValueError` if `count` is zero, negative or above 2**64 - 1.
    fn with_compressed_member_allowance(
        mut slf: PyRefMut<'_, Self>,
        count: PyInteger,
    ) -> PyResult<PyRefMut<'_, Self>> {
        slf.inner.compressed_member_allowance =
            count.positive(ConfigSetting::CompressedMemberAllowance)?;
        Ok(slf)
    }

    /// Sets the compression ratio limit of a whole solid 7z block.
    ///
    /// The limit exists only while `allow_solid_archives` is `True`.
    ///
    /// # Errors
    ///
    /// Returns `ValueError` if `ratio` is not a positive finite number or solid
    /// archives are not allowed.
    fn with_max_solid_compression_ratio(
        mut slf: PyRefMut<'_, Self>,
        ratio: PyRatio,
    ) -> PyResult<PyRefMut<'_, Self>> {
        slf.try_set_max_solid_compression_ratio(ratio)?;
        Ok(slf)
    }

    /// Allows or denies solid 7z archives.
    ///
    /// Solid archives require reading all preceding entries to decompress any
    /// entry, which may allow a crafted archive to consume excessive
    /// memory. Disabled by default.
    ///
    /// Allowing keeps solid limits that are already set. `allow=False` drops
    /// them, so allowing again afterwards starts from the defaults (512 MiB
    /// per block, ratio 1000), not from a limit set earlier.
    #[pyo3(signature = (allow=true))]
    fn with_allow_solid_archives(mut slf: PyRefMut<'_, Self>, allow: bool) -> PyRefMut<'_, Self> {
        slf.inner.solid_archives = slf.inner.solid_archives.with_allowed(allow);
        slf
    }

    /// Sets how ZIP archives with ambiguous structure are handled.
    ///
    /// `"enforce"` (the default, also for `permissive()`) rejects archives
    /// whose local and central headers disagree, that repeat a name, overlap
    /// entries or hide records. `"ignore"` keeps the central directory
    /// interpretation without structural findings.
    ///
    /// # Errors
    ///
    /// Returns `ValueError` for any other string.
    fn with_zip_consistency<'py>(
        mut slf: PyRefMut<'py, Self>,
        policy: &str,
    ) -> PyResult<PyRefMut<'py, Self>> {
        slf.inner.zip_consistency = parse_zip_consistency(policy)?;
        Ok(slf)
    }

    /// Sets the memory in bytes for decoding independent LZMA2 runs of a 7z
    /// block ahead on worker threads, or `None` to decode on one thread.
    ///
    /// The default is 128 MiB (1 GiB for `permissive()`). A stock 7-Zip
    /// archive has 64 MiB runs and needs about 100 MiB per extra concurrent
    /// run. A valid archive decodes to the same bytes either way and a corrupt
    /// one fails the same file. Each call may start up to 16 worker threads and
    /// hold its own lookahead, so concurrent calls multiply both.
    ///
    /// # Errors
    ///
    /// Returns `ValueError` if `size` is zero, negative or above 2**64 - 1.
    #[pyo3(signature = (size))]
    fn with_parallel_decode_memory(
        mut slf: PyRefMut<'_, Self>,
        size: Option<PyInteger>,
    ) -> PyResult<PyRefMut<'_, Self>> {
        slf.inner.parallel_decode = parse_parallel_decode_memory(size)?;
        Ok(slf)
    }

    /// Sets the maximum decoded size in bytes of a solid 7z block.
    ///
    /// The limit bounds the decoded volume of each solid block, not resident
    /// memory, and exists only while `allow_solid_archives` is `True`.
    ///
    /// # Errors
    ///
    /// Returns `ValueError` if `size` is zero or solid archives are not
    /// allowed.
    fn with_max_solid_block_memory(
        mut slf: PyRefMut<'_, Self>,
        size: PyInteger,
    ) -> PyResult<PyRefMut<'_, Self>> {
        slf.try_set_max_solid_block_memory(size)?;
        Ok(slf)
    }

    /// Sets whether to preserve permissions from archive.
    #[pyo3(signature = (preserve=true))]
    fn with_preserve_permissions(
        mut slf: PyRefMut<'_, Self>,
        preserve: bool,
    ) -> PyRefMut<'_, Self> {
        slf.inner.permissions = PermissionPolicy::from_preserve(preserve);
        slf
    }

    /// Adds an allowed file extension.
    ///
    /// # Errors
    ///
    /// Returns `ValueError` if the extension is empty, exceeds maximum
    /// length, or holds a null byte, whitespace, a separator or an inner dot.
    /// A leading dot is accepted and removed, and the value is lowercased.
    fn add_allowed_extension<'a>(
        mut slf: PyRefMut<'a, Self>,
        ext: &str,
    ) -> PyResult<PyRefMut<'a, Self>> {
        let ext = Extension::try_from(ext).map_err(convert_error)?;
        slf.inner.allowed_extensions =
            std::mem::take(&mut slf.inner.allowed_extensions).with_added(ext);
        Ok(slf)
    }

    /// Adds a banned path component.
    ///
    /// # Errors
    ///
    /// Returns `ValueError` if the component is empty, exceeds maximum
    /// length, or holds a null byte, a path separator, `.` or `..`.
    fn add_banned_component<'a>(
        mut slf: PyRefMut<'a, Self>,
        component: &str,
    ) -> PyResult<PyRefMut<'a, Self>> {
        let component = PathComponentName::try_from(component).map_err(convert_error)?;
        slf.inner.banned_path_components.push(component);
        Ok(slf)
    }

    /// Adds an include pattern: only entries that match an include pattern (and
    /// no exclude pattern) are extracted, listed as extracted and verified as
    /// extracted.
    ///
    /// Patterns use the grammar of `CreationConfig` exclude patterns and are
    /// matched against the normalized archive path before any stripping. An
    /// include pattern that matches nothing fails the extraction after the scan
    /// with `InvalidConfigurationError` (`setting == "entry_include"`, with the
    /// unmatched `patterns`).
    ///
    /// # Errors
    ///
    /// `InvalidConfigurationError` (`setting == "entry_include"`) for a refused
    /// pattern.
    fn add_include_pattern<'a>(
        mut slf: PyRefMut<'a, Self>,
        pattern: &str,
    ) -> PyResult<PyRefMut<'a, Self>> {
        slf.inner = slf
            .inner
            .clone()
            .try_add_include(pattern)
            .map_err(convert_error)?;
        Ok(slf)
    }

    /// Adds an exclude pattern: a matching entry is not extracted, whatever the
    /// include patterns say. A pattern that matches nothing is not an error.
    ///
    /// # Errors
    ///
    /// `InvalidConfigurationError` (`setting == "entry_exclude"`) for a refused
    /// pattern.
    fn add_exclude_pattern<'a>(
        mut slf: PyRefMut<'a, Self>,
        pattern: &str,
    ) -> PyResult<PyRefMut<'a, Self>> {
        slf.inner = slf
            .inner
            .clone()
            .try_add_exclude(pattern)
            .map_err(convert_error)?;
        Ok(slf)
    }

    /// Drops this many leading path components from every selected entry.
    ///
    /// Order of operations: the entry name is validated, matched against the
    /// include and exclude patterns on its original path, stripped, and the
    /// stripped name is validated again. An entry the strip consumes entirely
    /// is skipped (`"stripped_away"`). Replaces `with_flatten`.
    ///
    /// # Errors
    ///
    /// `InvalidConfigurationError` (`setting == "strip_components"`) for zero,
    /// a negative or non-integer value, or one above `max_path_depth`.
    fn with_strip_components(
        mut slf: PyRefMut<'_, Self>,
        count: PyInteger,
    ) -> PyResult<PyRefMut<'_, Self>> {
        slf.try_set_strip_components(Some(count))?;
        Ok(slf)
    }

    /// Lands every regular file under the destination root by its final path
    /// component only. Directories are skipped; a symlink or hardlink entry is
    /// refused. Replaces `with_strip_components`.
    #[pyo3(signature = (flatten=true))]
    fn with_flatten(mut slf: PyRefMut<'_, Self>, flatten: bool) -> PyRefMut<'_, Self> {
        slf.set_flatten(flatten);
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
        self.inner.is_extension_allowed(Some(extension))
    }

    // Property getters and setters

    #[getter]
    fn get_max_file_size(&self) -> Option<u64> {
        bytes_bound(self.inner.max_file_size)
    }

    #[setter]
    fn set_max_file_size(&mut self, value: PyInteger) -> PyResult<()> {
        self.inner.max_file_size = bytes_limit(ConfigSetting::MaxFileSize, value)?;
        Ok(())
    }

    #[getter]
    fn get_max_total_size(&self) -> Option<u64> {
        bytes_bound(self.inner.max_total_size)
    }

    #[setter]
    fn set_max_total_size(&mut self, value: PyInteger) -> PyResult<()> {
        self.inner.max_total_size = bytes_limit(ConfigSetting::MaxTotalSize, value)?;
        Ok(())
    }

    #[getter]
    fn get_max_compression_ratio(&self) -> f64 {
        self.inner.max_compression_ratio.get()
    }

    #[setter]
    fn set_max_compression_ratio(&mut self, value: PyRatio) -> PyResult<()> {
        self.inner.max_compression_ratio = value.limit()?;
        Ok(())
    }

    #[getter]
    fn get_max_file_count(&self) -> Option<usize> {
        count_bound(self.inner.max_file_count)
    }

    #[setter]
    fn set_max_file_count(&mut self, value: PyInteger) -> PyResult<()> {
        self.inner.max_file_count = count_limit(ConfigSetting::MaxFileCount, value)?;
        Ok(())
    }

    #[getter]
    fn get_max_path_depth(&self) -> usize {
        self.inner.max_path_depth.get()
    }

    #[setter]
    fn set_max_path_depth(&mut self, value: PyInteger) -> PyResult<()> {
        self.inner.max_path_depth = value.positive_usize(ConfigSetting::MaxPathDepth)?;
        Ok(())
    }

    #[getter]
    fn get_preserve_permissions(&self) -> bool {
        self.inner.permissions.preserves()
    }

    #[setter]
    fn set_preserve_permissions(&mut self, value: bool) {
        self.inner.permissions = PermissionPolicy::from_preserve(value);
    }

    /// Returns whether symlinks are allowed.
    #[getter]
    fn get_allow_symlinks(&self) -> bool {
        self.inner.allowed.symlinks.is_allowed()
    }

    /// Returns whether hardlinks are allowed.
    #[getter]
    fn get_allow_hardlinks(&self) -> bool {
        self.inner.allowed.hardlinks.is_allowed()
    }

    /// Returns whether absolute paths are allowed.
    #[getter]
    fn get_allow_absolute_paths(&self) -> bool {
        self.inner.allowed.absolute_paths.is_allowed()
    }

    /// Returns whether world-writable files are allowed.
    #[getter]
    fn get_allow_world_writable(&self) -> bool {
        self.inner.allowed.world_writable.is_allowed()
    }

    /// Returns whether solid 7z archives are allowed.
    #[getter]
    fn get_allow_solid_archives(&self) -> bool {
        self.inner.solid_archives.is_allowed()
    }

    /// Returns how ZIP archives with ambiguous structure are handled
    /// (`"enforce"` or `"ignore"`).
    #[getter]
    fn get_zip_consistency(&self) -> &'static str {
        self.inner.zip_consistency.as_str()
    }

    #[setter]
    fn set_zip_consistency(&mut self, value: &str) -> PyResult<()> {
        self.inner.zip_consistency = parse_zip_consistency(value)?;
        Ok(())
    }

    /// Returns the lookahead memory in bytes for parallel 7z LZMA2 decoding,
    /// or `None` when decoding runs on one thread.
    #[getter]
    fn get_parallel_decode_memory(&self) -> Option<u64> {
        self.inner.parallel_decode.lookahead().map(NonZeroU64::get)
    }

    #[setter]
    fn set_parallel_decode_memory(&mut self, value: Option<PyInteger>) -> PyResult<()> {
        self.inner.parallel_decode = parse_parallel_decode_memory(value)?;
        Ok(())
    }

    /// Returns the maximum decoded size in bytes of a solid 7z block, or
    /// `None` while solid archives are not allowed.
    #[getter]
    fn get_max_solid_block_memory(&self) -> Option<u64> {
        self.inner
            .solid_archives
            .limits()
            .map(|limits| limits.max_block_memory.get())
    }

    #[setter]
    fn set_max_solid_block_memory(&mut self, value: PyInteger) -> PyResult<()> {
        self.try_set_max_solid_block_memory(value)
    }

    /// Returns the compression ratio limit of a whole solid 7z block, or
    /// `None` while solid archives are not allowed.
    #[getter]
    fn get_max_solid_compression_ratio(&self) -> Option<f64> {
        self.inner
            .solid_archives
            .limits()
            .map(|limits| limits.max_ratio.get())
    }

    #[setter]
    fn set_max_solid_compression_ratio(&mut self, value: PyRatio) -> PyResult<()> {
        self.try_set_max_solid_compression_ratio(value)
    }

    /// Returns whether names Windows reserves are allowed.
    #[getter]
    fn get_allow_windows_reserved_names(&self) -> bool {
        self.inner.allowed.windows_reserved_names.is_allowed()
    }

    #[getter]
    fn get_max_tar_metadata_bytes(&self) -> u64 {
        self.inner.max_tar_metadata_bytes.get()
    }

    #[setter]
    fn set_max_tar_metadata_bytes(&mut self, value: PyInteger) -> PyResult<()> {
        self.inner.max_tar_metadata_bytes = value.positive(ConfigSetting::MaxTarMetadataBytes)?;
        Ok(())
    }

    #[getter]
    fn get_max_decoder_memory(&self) -> u64 {
        self.inner.max_decoder_memory.get()
    }

    #[setter]
    fn set_max_decoder_memory(&mut self, value: PyInteger) -> PyResult<()> {
        self.inner.max_decoder_memory = value.positive(ConfigSetting::MaxDecoderMemory)?;
        Ok(())
    }

    #[getter]
    fn get_compressed_member_allowance(&self) -> u64 {
        self.inner.compressed_member_allowance.get()
    }

    #[setter]
    fn set_compressed_member_allowance(&mut self, value: PyInteger) -> PyResult<()> {
        self.inner.compressed_member_allowance =
            value.positive(ConfigSetting::CompressedMemberAllowance)?;
        Ok(())
    }

    /// Returns a copy of the allowed extensions list, or `None` when every
    /// extension is allowed.
    ///
    /// # Performance
    ///
    /// This method clones the entire list on each access. If you need to access
    /// the extensions multiple times, cache the result in a local variable.
    #[getter]
    fn get_allowed_extensions(&self) -> Option<Vec<String>> {
        self.inner.allowed_extensions.as_only().map(|extensions| {
            extensions
                .as_slice()
                .iter()
                .map(|ext| ext.as_str().to_owned())
                .collect()
        })
    }

    /// Replaces the allowed extensions; `None` allows every extension.
    ///
    /// # Errors
    ///
    /// `InvalidConfigurationError` (`setting == "allowed_extension"`) for an
    /// empty list or a malformed extension.
    #[setter]
    fn set_allowed_extensions(&mut self, value: Option<Vec<String>>) -> PyResult<()> {
        self.inner.allowed_extensions = match value {
            None => ExtensionFilter::Any,
            Some(values) => ExtensionFilter::only(
                values
                    .iter()
                    .map(|ext| Extension::try_from(ext.as_str()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(convert_error)?,
            )
            .map_err(convert_error)?,
        };
        Ok(())
    }

    /// Returns a copy of the banned path components list.
    ///
    /// # Performance
    ///
    /// This method clones the entire list on each access. If you need to access
    /// the components multiple times, cache the result in a local variable.
    #[getter]
    fn get_banned_path_components(&self) -> Vec<String> {
        self.inner
            .banned_path_components
            .iter()
            .map(|component| component.as_str().to_owned())
            .collect()
    }

    #[setter]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "PyO3 setters receive the extracted list by value"
    )]
    fn set_banned_path_components(&mut self, value: Vec<String>) -> PyResult<()> {
        self.inner.banned_path_components = value
            .iter()
            .map(|component| PathComponentName::try_from(component.as_str()))
            .collect::<Result<_, _>>()
            .map_err(convert_error)?;
        Ok(())
    }

    /// The include patterns, in the order they were added. Empty means every
    /// entry is a candidate.
    #[getter]
    fn get_include_patterns(&self) -> Vec<String> {
        self.inner
            .selection
            .include()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// Replaces the include patterns; an empty list removes them.
    #[setter]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "PyO3 setters receive the extracted list by value"
    )]
    fn set_include_patterns(&mut self, value: Vec<String>) -> PyResult<()> {
        let include = parse_entry_patterns(ConfigSetting::EntryInclude, &value)?;
        self.inner.selection = std::mem::take(&mut self.inner.selection).with_include_list(include);
        Ok(())
    }

    /// The exclude patterns, in the order they were added.
    #[getter]
    fn get_exclude_patterns(&self) -> Vec<String> {
        self.inner
            .selection
            .exclude()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// Replaces the exclude patterns; an empty list removes them.
    #[setter]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "PyO3 setters receive the extracted list by value"
    )]
    fn set_exclude_patterns(&mut self, value: Vec<String>) -> PyResult<()> {
        let exclude = parse_entry_patterns(ConfigSetting::EntryExclude, &value)?;
        self.inner.selection = std::mem::take(&mut self.inner.selection).with_exclude_list(exclude);
        Ok(())
    }

    /// How many leading components are dropped, or `None` when no strip is set.
    #[getter]
    fn get_strip_components(&self) -> Option<usize> {
        match self.inner.selection.rewrite() {
            PathRewrite::Strip(strip) => Some(strip.get().get()),
            _ => None,
        }
    }

    /// Sets the strip count; `None` removes a strip (a flatten stays).
    #[setter]
    fn set_strip_components(&mut self, value: Option<PyInteger>) -> PyResult<()> {
        self.try_set_strip_components(value)
    }

    /// Whether files land by their final component only.
    #[getter]
    fn get_flatten(&self) -> bool {
        self.inner.selection.rewrite() == PathRewrite::Flatten
    }

    /// `True` flattens (replacing a strip); `False` removes a flatten (a strip
    /// stays).
    #[setter(flatten)]
    fn set_flatten_property(&mut self, value: bool) {
        self.set_flatten(value);
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
            self.inner.max_file_size.ceiling(),
            self.inner.max_total_size.ceiling(),
            self.inner.max_compression_ratio.get(),
            self.inner.max_file_count.ceiling(),
            self.inner.max_path_depth
        )
    }
}

/// Parses entry patterns, each refused one naming `setting`.
fn parse_entry_patterns(
    setting: ConfigSetting,
    patterns: &[String],
) -> PyResult<Vec<EntryPattern>> {
    patterns
        .iter()
        .map(|pattern| EntryPattern::parse_for(setting, pattern).map_err(convert_error))
        .collect()
}

/// Maps the Python value of `parallel_decode_memory` (`None` or a positive
/// byte count) to the core mode.
fn parse_parallel_decode_memory(value: Option<PyInteger>) -> PyResult<ParallelDecode> {
    value
        .map(|bytes| bytes.positive(ConfigSetting::ParallelDecodeMemory))
        .transpose()
        .map(ParallelDecode::from_bytes)
}

/// Parses the string form shared with `ZipConsistencyPolicy::as_str`.
fn parse_zip_consistency(value: &str) -> PyResult<ZipConsistencyPolicy> {
    parse_one(ConfigSetting::ZipConsistency, value)
}

impl PySecurityConfig {
    /// Returns a reference to the inner `CoreSecurityConfig`.
    ///
    /// This is used internally to pass the configuration to the Rust extraction
    /// API.
    pub fn as_core(&self) -> &CoreSecurityConfig {
        &self.inner
    }

    /// A copy of the inner `CoreSecurityConfig`, or the secure default.
    ///
    /// Taken as an owned value so no borrow of the Python object is held while
    /// the GIL is released: a concurrent setter would otherwise raise
    /// `RuntimeError: Already borrowed`.
    pub fn snapshot(config: Option<PyRef<'_, Self>>) -> CoreSecurityConfig {
        config.map_or_else(CoreSecurityConfig::default, |c| c.inner.clone())
    }

    /// Shared by the builder and the property setter of `strip_components`.
    /// `None` removes a strip; a flatten is left alone.
    fn try_set_strip_components(&mut self, count: Option<PyInteger>) -> PyResult<()> {
        let strip = count
            .map(|count| {
                let count = count.positive(ConfigSetting::StripComponents)?;
                StripComponents::new(count, self.inner.max_path_depth).map_err(convert_error)
            })
            .transpose()?;
        self.inner.selection = std::mem::take(&mut self.inner.selection).with_strip(strip);
        Ok(())
    }

    /// Shared by the builder and the property setter of `flatten`.
    fn set_flatten(&mut self, flatten: bool) {
        self.inner.selection = std::mem::take(&mut self.inner.selection).with_flatten(flatten);
    }

    /// Shared by the builder and the property setter of
    /// `max_solid_compression_ratio`.
    fn try_set_max_solid_compression_ratio(&mut self, ratio: PyRatio) -> PyResult<()> {
        let ratio = ratio.limit_of(ConfigSetting::MaxSolidCompressionRatio)?;
        self.inner.solid_archives = self
            .inner
            .solid_archives
            .with_max_ratio(ratio)
            .map_err(convert_error)?;
        Ok(())
    }

    /// Shared by the builder and the property setter of
    /// `max_solid_block_memory`.
    fn try_set_max_solid_block_memory(&mut self, size: PyInteger) -> PyResult<()> {
        let max_block_memory = size.positive(ConfigSetting::MaxSolidBlockMemory)?;
        self.inner.solid_archives = self
            .inner
            .solid_archives
            .with_max_block_memory(max_block_memory)
            .map_err(convert_error)?;
        Ok(())
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
#[pyclass(name = "CreationConfig")]
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
        level: PyInteger,
    ) -> PyResult<PyRefMut<'_, Self>> {
        slf.inner.compression_level = compression_level(level)?;
        Ok(slf)
    }

    /// Sets whether to preserve permissions.
    #[pyo3(signature = (preserve=true))]
    fn with_preserve_permissions(
        mut slf: PyRefMut<'_, Self>,
        preserve: bool,
    ) -> PyRefMut<'_, Self> {
        slf.inner.permissions = PermissionPolicy::from_preserve(preserve);
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

    /// Sets exclude patterns, matched against the archive entry path.
    ///
    /// Patterns are globs: `*` and `?` match within one path component (`?` is
    /// exactly one byte), `[a-c]` is a positive ASCII class, `**` as a whole
    /// component spans directories. A name without `/` matches any path
    /// component at any depth, and so its subtree; a pattern with a `/`
    /// anywhere matches from the archive root and its subtree.
    ///
    /// # Errors
    ///
    /// `InvalidConfigurationError` (`setting == "exclude_pattern"`) for syntax
    /// the matcher does not support: a leading `!`, `{`/`}`, `**` glued to
    /// other characters, negated, POSIX or non-ASCII classes, an unterminated
    /// class, a class range outside `0-9`/`a-z`/`A-Z`, commas and edge
    /// whitespace.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "pyo3 passes the extracted list by value"
    )]
    fn with_exclude_patterns(
        mut slf: PyRefMut<'_, Self>,
        patterns: Vec<String>,
    ) -> PyResult<PyRefMut<'_, Self>> {
        slf.inner.exclude_patterns = parse_exclude_patterns(&patterns)?;
        Ok(slf)
    }

    /// Sets maximum file size in bytes; `None` removes the limit.
    ///
    /// # Errors
    ///
    /// Raises the configuration error if `size` is zero.
    fn with_max_file_size(
        mut slf: PyRefMut<'_, Self>,
        size: Option<PyInteger>,
    ) -> PyResult<PyRefMut<'_, Self>> {
        slf.inner.max_file_size = optional_bytes_limit(ConfigSetting::MaxFileSize, size)?;
        Ok(slf)
    }

    /// Finalizes the configuration.
    fn build(slf: PyRefMut<'_, Self>) -> PyRefMut<'_, Self> {
        slf
    }

    // Property getters and setters

    #[getter]
    fn get_compression_level(&self) -> u8 {
        self.inner.compression_level.get()
    }

    /// Sets the level; `None` resets it to the default, 6.
    #[setter]
    fn set_compression_level(&mut self, value: Option<PyInteger>) -> PyResult<()> {
        self.inner.compression_level = value
            .map(compression_level)
            .transpose()?
            .unwrap_or_default();
        Ok(())
    }

    #[getter]
    fn get_preserve_permissions(&self) -> bool {
        self.inner.permissions.preserves()
    }

    #[setter]
    fn set_preserve_permissions(&mut self, value: bool) {
        self.inner.permissions = PermissionPolicy::from_preserve(value);
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
        self.inner
            .exclude_patterns
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[setter]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "PyO3 setters receive the extracted list by value"
    )]
    fn set_exclude_patterns(&mut self, value: Vec<String>) -> PyResult<()> {
        self.inner.exclude_patterns = parse_exclude_patterns(&value)?;
        Ok(())
    }

    #[getter]
    fn get_max_file_size(&self) -> Option<u64> {
        bytes_bound(self.inner.max_file_size)
    }

    #[setter]
    fn set_max_file_size(&mut self, value: Option<PyInteger>) -> PyResult<()> {
        self.inner.max_file_size = optional_bytes_limit(ConfigSetting::MaxFileSize, value)?;
        Ok(())
    }

    /// Returns a debug string representation.
    fn __repr__(&self) -> String {
        format!(
            "CreationConfig(compression_level={:?}, preserve_permissions={}, follow_symlinks={}, include_hidden={})",
            self.inner.compression_level,
            self.inner.permissions.preserves(),
            self.inner.follow_symlinks,
            self.inner.include_hidden
        )
    }
}

impl PyCreationConfig {
    /// A copy of the inner `CoreCreationConfig`, or the default; see
    /// [`PySecurityConfig::snapshot`] for why it is owned.
    pub fn snapshot(config: Option<PyRef<'_, Self>>) -> CoreCreationConfig {
        config.map_or_else(CoreCreationConfig::default, |c| c.inner.clone())
    }
}

/// Options controlling extraction behavior (non-security).
///
/// Separate from `SecurityConfig` to keep security settings focused.
/// These options control operational behavior such as how existing files are
/// treated.
///
/// # Attributes
///
/// * `existing_files` - What to do with a file that already exists at a landing
///   path, or that an earlier entry created: `"skip"` (default) keeps it and
///   counts a duplicate, `"overwrite"` replaces it where the entry kinds allow,
///   `"refuse"` fails with `OutputExistsError` and never overwrites
/// * `staging` - Where files are written first: `"in_place"` (default) writes
///   into the destination, `"atomic"` extracts into a temporary sibling
///   directory and renames it onto a destination that is absent or empty,
///   `"atomic_replace"` also swaps it over an existing directory, replacing it
///   as a whole
///
/// # Examples
///
/// ```python
/// # Use defaults
/// opts = ExtractionOptions()
///
/// # Refuse to touch anything that already exists
/// opts = ExtractionOptions().with_existing_files("refuse")
///
/// # Extract atomically
/// opts = ExtractionOptions().with_staging("atomic")
/// ```
#[pyclass(name = "ExtractionOptions")]
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

    /// Sets how an existing file at a landing path is treated.
    ///
    /// `"skip"` (default) keeps the existing file and counts the entry as a
    /// duplicate skip; `"overwrite"` replaces it where the entry kinds allow;
    /// `"refuse"` raises `OutputExistsError` for any occupant and never
    /// overwrites. A kind conflict is refused under every value.
    ///
    /// # Errors
    ///
    /// `InvalidConfigurationError` (`setting == "existing_files"`) for any
    /// other string.
    fn with_existing_files<'py>(
        mut slf: PyRefMut<'py, Self>,
        value: &str,
    ) -> PyResult<PyRefMut<'py, Self>> {
        slf.inner.existing_files = parse_existing_files(value)?;
        Ok(slf)
    }

    /// Sets where extracted files are written first.
    ///
    /// * `"in_place"` (default) writes into the destination, which may already
    ///   hold files.
    /// * `"atomic"` extracts into a temporary directory next to the destination
    ///   and renames it into place on success; a failure or cancellation
    ///   removes it. A destination that holds content raises
    ///   `OutputExistsError` before anything is extracted, and one that is not
    ///   a directory raises `InvalidConfigurationError`. A symlinked
    ///   destination is resolved first.
    /// * `"atomic_replace"` is `"atomic"`, and also swaps the staged tree over
    ///   an existing destination directory, replacing it as a whole. The
    ///   original is renamed aside only once extraction succeeded and restored
    ///   if the swap fails. A destination that is a filesystem root, the
    ///   archive's directory or an ancestor of it, or the working directory is
    ///   refused with `InvalidConfigurationError`.
    ///
    /// The staging directory is private (`0700`) while the archive extracts.
    /// On Unix the published root then takes the mode of the destination it
    /// replaces (or fills), never setuid; with `"atomic_replace"` also its
    /// owner as far as the caller may, and with `"atomic"` never the uid and
    /// the group only when the caller owns the destination. On Windows the
    /// staging directory is owner-only while the run lasts and the published
    /// root inherits the ACL of the destination's parent, and `"atomic"` onto
    /// an existing empty directory raises `OutputExistsError`.
    ///
    /// `extract_archive_to_memory` and `extract_archive_to_callback` take no
    /// staging.
    ///
    /// # Errors
    ///
    /// `InvalidConfigurationError` (`setting == "staging"`) for any other
    /// string.
    ///
    /// # Examples
    ///
    /// ```python
    /// from exarch import ExtractionOptions
    /// opts = ExtractionOptions().with_staging("atomic")
    /// assert opts.staging == "atomic"
    /// ```
    fn with_staging<'py>(
        mut slf: PyRefMut<'py, Self>,
        value: &str,
    ) -> PyResult<PyRefMut<'py, Self>> {
        slf.inner.staging = parse_staging(value)?;
        Ok(slf)
    }

    /// Finalizes the configuration (for API consistency).
    fn build(slf: PyRefMut<'_, Self>) -> PyRefMut<'_, Self> {
        slf
    }

    #[getter]
    fn get_existing_files(&self) -> &'static str {
        self.inner.existing_files.as_str()
    }

    #[setter]
    fn set_existing_files(&mut self, value: &str) -> PyResult<()> {
        self.inner.existing_files = parse_existing_files(value)?;
        Ok(())
    }

    #[getter]
    fn get_staging(&self) -> &'static str {
        self.inner.staging.as_str()
    }

    #[setter]
    fn set_staging(&mut self, value: &str) -> PyResult<()> {
        self.inner.staging = parse_staging(value)?;
        Ok(())
    }

    /// Returns a debug string representation.
    fn __repr__(&self) -> String {
        format!(
            "ExtractionOptions(existing_files={:?}, staging={:?})",
            self.inner.existing_files.as_str(),
            self.inner.staging.as_str()
        )
    }
}

impl PyExtractionOptions {
    /// A copy of the inner `CoreExtractionOptions`, taken so no borrow of the
    /// Python object outlives the call that reads it.
    pub fn snapshot(options: Option<PyRef<'_, Self>>) -> CoreExtractionOptions {
        options.map_or_else(CoreExtractionOptions::default, |o| o.inner.clone())
    }
}

/// Options controlling verification behavior (non-security).
///
/// By default `verify_archive` checks metadata only and reports
/// `integrity_status` as `"SKIPPED"`. `with_integrity_check` additionally
/// decodes the payload so checksums and codec framing are verified.
///
/// # Attributes
///
/// * `integrity_check` - Whether payload integrity is checked (default:
///   `False`)
/// * `decompression_budget` - Extra bytes the check may decode beyond listing
///   (500 MiB unless set), or `None` when the check is off
///
/// # Examples
///
/// ```python
/// from exarch import VerificationOptions, verify_archive
///
/// opts = VerificationOptions().with_integrity_check()
/// report = verify_archive("archive.zip", options=opts)
/// print(report.integrity_status)  # "OK", "FAILED" or "INCOMPLETE"
/// ```
#[pyclass(name = "VerificationOptions")]
#[derive(Clone)]
pub struct PyVerificationOptions {
    inner: CoreVerificationOptions,
}

#[pymethods]
impl PyVerificationOptions {
    /// Creates a new `VerificationOptions` with defaults (no integrity check).
    #[new]
    fn new() -> Self {
        Self {
            inner: CoreVerificationOptions::default(),
        }
    }

    /// Creates a `VerificationOptions` with defaults.
    ///
    /// This is equivalent to calling `VerificationOptions()`.
    #[staticmethod]
    fn default() -> Self {
        Self::new()
    }

    /// Enables the payload integrity check.
    ///
    /// `budget` bounds the extra bytes decoded beyond listing; `None` uses the
    /// default of 500 MiB, which does not follow `max_total_size`.
    ///
    /// # Raises
    ///
    /// * `ValueError` - `budget` is zero or negative
    #[pyo3(signature = (budget=None))]
    fn with_integrity_check(
        mut slf: PyRefMut<'_, Self>,
        budget: Option<PyInteger>,
    ) -> PyResult<PyRefMut<'_, Self>> {
        let budget = match budget {
            Some(bytes) => {
                let bytes = bytes.positive(ConfigSetting::DecompressionBudget)?;
                DecompressionBudget::try_from_bytes(bytes.get()).map_err(convert_error)?
            }
            None => DecompressionBudget::DEFAULT,
        };
        slf.inner.integrity = IntegrityCheck::DecodeToEof(budget);
        Ok(slf)
    }

    /// Whether the payload integrity check is enabled.
    #[getter]
    fn get_integrity_check(&self) -> bool {
        self.inner.integrity.budget().is_some()
    }

    /// Budget in bytes when the integrity check is enabled, else `None`.
    #[getter]
    fn get_decompression_budget(&self) -> Option<u64> {
        self.inner.integrity.budget().map(DecompressionBudget::get)
    }

    /// Returns a debug string representation.
    fn __repr__(&self) -> String {
        let check = if self.get_integrity_check() {
            "True"
        } else {
            "False"
        };
        let budget = self
            .get_decompression_budget()
            .map_or_else(|| "None".to_owned(), |bytes| bytes.to_string());
        format!("VerificationOptions(integrity_check={check}, decompression_budget={budget})")
    }
}

/// Options controlling listing behavior.
///
/// Listing a 7z archive leaves link targets unread by default, so it decodes no
/// entry data; `with_stored_targets` reads them.
///
/// # Attributes
///
/// * `stored_targets` - Whether link targets kept in entry data are read:
///   `"skip"` (default) or `"read"`
///
/// # Examples
///
/// ```python
/// from exarch import ListOptions, list_archive
///
/// manifest = list_archive("archive.7z", options=ListOptions().with_stored_targets())
/// ```
#[pyclass(name = "ListOptions")]
#[derive(Clone)]
pub struct PyListOptions {
    inner: CoreListOptions,
}

#[pymethods]
impl PyListOptions {
    /// Creates a new `ListOptions` with defaults (link targets unread).
    #[new]
    fn new() -> Self {
        Self {
            inner: CoreListOptions::default(),
        }
    }

    /// Creates a `ListOptions` with defaults.
    #[staticmethod]
    fn default() -> Self {
        Self::new()
    }

    /// Sets whether link targets kept in entry data are read, which decodes the
    /// blocks that hold them: `"skip"` or `"read"`.
    #[pyo3(signature = (targets="read"))]
    fn with_stored_targets<'a>(
        mut slf: PyRefMut<'a, Self>,
        targets: &str,
    ) -> PyResult<PyRefMut<'a, Self>> {
        slf.inner.stored_targets = parse_one(ConfigSetting::StoredTargets, targets)?;
        Ok(slf)
    }

    /// Whether link targets kept in entry data are read: `"skip"` or `"read"`.
    #[getter]
    fn get_stored_targets(&self) -> &'static str {
        self.inner.stored_targets.as_str()
    }

    /// Returns a debug string representation.
    fn __repr__(&self) -> String {
        format!(
            "ListOptions(stored_targets={:?})",
            self.get_stored_targets()
        )
    }
}

impl PyListOptions {
    /// A copy of the inner `CoreListOptions`, or the default; see
    /// [`PySecurityConfig::snapshot`] for why it is owned.
    pub fn snapshot(options: Option<PyRef<'_, Self>>) -> CoreListOptions {
        options.map_or_else(CoreListOptions::default, |o| o.inner)
    }
}

impl PyVerificationOptions {
    /// A copy of the inner `CoreVerificationOptions`, or the default; see
    /// [`PySecurityConfig::snapshot`] for why it is owned.
    pub fn snapshot(options: Option<PyRef<'_, Self>>) -> CoreVerificationOptions {
        options.map_or_else(CoreVerificationOptions::default, |o| o.inner)
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
    use exarch_core::MAX_CONFIG_ENTRY_LENGTH;
    use exarch_core::SolidLimits;

    use super::*;

    #[test]
    fn documented_numbers_follow_core_constants() {
        assert_eq!(
            CompressionLevel::DEFAULT.get(),
            6,
            "docs and exarch.pyi say 6"
        );
        assert_eq!(
            exarch_core::MAX_PATH_LENGTH,
            4096,
            "docs of extract_archive say 4096"
        );
        assert_eq!(
            SolidLimits::DEFAULT.max_ratio.get(),
            1000.0,
            "docs and exarch.pyi say 1000"
        );
        let defaults = exarch_core::SecurityConfig::default();
        assert_eq!(
            defaults.max_tar_metadata_bytes.get(),
            4 * 1024 * 1024,
            "docs say 4 MiB"
        );
        assert_eq!(
            defaults.max_decoder_memory.get(),
            256 * 1024 * 1024,
            "docs say 256 MiB"
        );
        assert_eq!(
            defaults.compressed_member_allowance.get(),
            10_000,
            "docs say 10,000"
        );
    }

    #[test]
    fn test_default_config() {
        let config = PySecurityConfig::new();
        assert_eq!(
            config.get_max_file_size(),
            Some(50 * 1024 * 1024),
            "Default max_file_size should be 50 MB"
        );
        assert_eq!(
            config.get_max_total_size(),
            Some(500 * 1024 * 1024),
            "Default max_total_size should be 500 MB"
        );
        assert_eq!(
            config.get_max_file_count(),
            Some(10_000),
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
            Some(50 * 1024 * 1024),
            "Static default() should have same values as new()"
        );
    }

    #[test]
    fn test_permissive_config() {
        let config = PySecurityConfig::permissive();
        assert!(
            config.inner.allowed.symlinks.is_allowed(),
            "Permissive config should allow symlinks"
        );
        assert!(
            config.inner.allowed.hardlinks.is_allowed(),
            "Permissive config should allow hardlinks"
        );
        assert!(
            config.inner.allowed.absolute_paths.is_allowed(),
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
                Some(100_000_000),
                "Builder pattern should set max_file_size"
            );
            assert_eq!(
                result.get_max_total_size(),
                Some(1_000_000_000),
                "Builder pattern should set max_total_size"
            );
            assert_eq!(
                result.get_max_file_count(),
                Some(50_000),
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

        config
            .set_max_file_size(PyInteger::from(100_000_000))
            .unwrap();
        assert_eq!(
            config.get_max_file_size(),
            Some(100_000_000),
            "Property setter should update max_file_size"
        );

        config
            .set_max_total_size(PyInteger::from(2_000_000_000))
            .unwrap();
        assert_eq!(
            config.get_max_total_size(),
            Some(2_000_000_000),
            "Property setter should update max_total_size"
        );

        config.set_max_file_count(PyInteger::from(20_000)).unwrap();
        assert_eq!(
            config.get_max_file_count(),
            Some(20_000),
            "Property setter should update max_file_count"
        );

        config.set_max_path_depth(PyInteger::from(64)).unwrap();
        assert_eq!(
            config.get_max_path_depth(),
            64,
            "Property setter should update max_path_depth"
        );
    }

    #[test]
    fn test_property_setter_compression_ratio_valid() {
        let mut config = PySecurityConfig::new();
        let result = config.set_max_compression_ratio(PyRatio::from(150.0));
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
            config
                .set_max_compression_ratio(PyRatio::from(f64::NAN))
                .is_err(),
            "Should reject NaN"
        );
        assert!(
            config
                .set_max_compression_ratio(PyRatio::from(f64::INFINITY))
                .is_err(),
            "Should reject Infinity"
        );
        assert!(
            config
                .set_max_compression_ratio(PyRatio::from(-5.0))
                .is_err(),
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
                extensions.is_some_and(|list| list.contains(&"txt".to_string())),
                "Extension should be added to list"
            );
        });
    }

    #[test]
    fn test_add_allowed_extension_rejects_unusable_values() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            for raw in [" gz", "tar.gz", "a/b"] {
                let py_config =
                    Py::new(py, PySecurityConfig::new()).expect("Failed to create Py object");
                let result = py_config
                    .bind(py)
                    .call_method1("add_allowed_extension", (raw,));
                assert!(result.is_err(), "{raw:?} must be refused");
            }
        });
    }

    #[test]
    fn test_add_banned_component_rejects_separators() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            for raw in ["a/b", ".."] {
                let py_config =
                    Py::new(py, PySecurityConfig::new()).expect("Failed to create Py object");
                let result = py_config
                    .bind(py)
                    .call_method1("add_banned_component", (raw,));
                assert!(result.is_err(), "{raw:?} must be refused");
            }
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

            let long_ext = "x".repeat(MAX_CONFIG_ENTRY_LENGTH + 1);
            let result = obj.call_method1("add_allowed_extension", (long_ext,));
            assert!(
                result.is_err(),
                "Should reject extension exceeding max length"
            );
        });
    }

    #[test]
    fn test_add_allowed_extension_rejects_empty() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let config = PySecurityConfig::new();
            let py_config = Py::new(py, config).expect("Failed to create Py object");
            let obj = py_config.bind(py);

            let result = obj.call_method1("add_allowed_extension", ("",));
            assert!(result.is_err(), "Should reject empty extension");
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

            let long_component = "x".repeat(MAX_CONFIG_ENTRY_LENGTH + 1);
            let result = obj.call_method1("add_banned_component", (long_component,));
            assert!(
                result.is_err(),
                "Should reject component exceeding max length"
            );
        });
    }

    #[test]
    fn test_add_banned_component_rejects_empty() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let config = PySecurityConfig::new();
            let py_config = Py::new(py, config).expect("Failed to create Py object");
            let obj = py_config.bind(py);

            let result = obj.call_method1("add_banned_component", ("",));
            assert!(result.is_err(), "Should reject empty component");
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
    fn test_is_extension_allowed_without_a_list() {
        let config = PySecurityConfig::new();
        assert!(
            config.is_extension_allowed("txt"),
            "no allowlist should allow all extensions"
        );
        assert_eq!(config.get_allowed_extensions(), None);
    }

    #[test]
    fn test_empty_allowed_extensions_is_refused_and_none_clears() {
        pyo3::Python::initialize();
        let mut config = PySecurityConfig::new();
        assert!(config.set_allowed_extensions(Some(vec![])).is_err());
        assert_eq!(config.get_allowed_extensions(), None);

        config
            .set_allowed_extensions(Some(vec!["txt".to_owned()]))
            .expect("one extension");
        assert_eq!(
            config.get_allowed_extensions(),
            Some(vec!["txt".to_owned()])
        );
        assert!(config.set_allowed_extensions(Some(vec![])).is_err());
        assert_eq!(
            config.get_allowed_extensions(),
            Some(vec!["txt".to_owned()])
        );

        config.set_allowed_extensions(None).expect("None clears");
        assert_eq!(config.get_allowed_extensions(), None);
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
            core_config.max_file_size.ceiling(),
            50 * 1024 * 1024,
            "as_core() should return reference to inner config"
        );
    }

    #[test]
    fn test_default_max_solid_block_memory() {
        let mut config = PySecurityConfig::new();
        assert_eq!(
            config.get_max_solid_block_memory(),
            None,
            "No limit is reported while solid archives are refused"
        );
        config.inner.solid_archives = config.inner.solid_archives.with_allowed(true);
        assert_eq!(
            config.get_max_solid_block_memory(),
            Some(512 * 1024 * 1024),
            "Default max_solid_block_memory should be 512 MB once allowed"
        );
    }

    #[test]
    fn test_max_solid_block_memory_refused_while_solid_archives_are_refused() {
        let mut config = PySecurityConfig::new();
        assert!(
            config
                .set_max_solid_block_memory(PyInteger::from(1024))
                .is_err(),
            "Should refuse a limit that would be ignored"
        );
        assert_eq!(config.get_max_solid_block_memory(), None);
    }

    #[test]
    fn test_builder_max_solid_block_memory_valid() {
        pyo3::Python::initialize();
        Python::attach(|py| {
            let mut config = PySecurityConfig::new();
            config.inner.solid_archives = config.inner.solid_archives.with_allowed(true);
            let py_config = Py::new(py, config).expect("Failed to create Py object");
            let obj = py_config.bind(py);

            let result = obj.call_method1("with_max_solid_block_memory", (256 * 1024 * 1024_u64,));
            assert!(result.is_ok(), "Should accept valid memory size");
            assert_eq!(
                py_config.borrow(py).get_max_solid_block_memory(),
                Some(256 * 1024 * 1024),
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
        config.inner.solid_archives = config.inner.solid_archives.with_allowed(true);
        let result = config.set_max_solid_block_memory(PyInteger::from(128 * 1024 * 1024));
        assert!(result.is_ok(), "Should accept valid memory size");
        assert_eq!(
            config.get_max_solid_block_memory(),
            Some(128 * 1024 * 1024),
            "Property setter should update max_solid_block_memory"
        );
    }

    #[test]
    fn test_property_setter_max_solid_block_memory_rejects_zero() {
        let mut config = PySecurityConfig::new();
        assert!(
            config
                .set_max_solid_block_memory(PyInteger::from(0))
                .is_err(),
            "Should reject zero"
        );
    }

    #[test]
    fn test_parallel_decode_memory_defaults_and_setter() {
        const MIB: u64 = 1024 * 1024;
        let mut config = PySecurityConfig::new();
        assert_eq!(config.get_parallel_decode_memory(), Some(128 * MIB));
        assert_eq!(
            PySecurityConfig::permissive().get_parallel_decode_memory(),
            Some(1024 * MIB)
        );

        config
            .set_parallel_decode_memory(Some(PyInteger::Fits(i128::from(64 * MIB))))
            .unwrap();
        assert_eq!(config.get_parallel_decode_memory(), Some(64 * MIB));
        config.set_parallel_decode_memory(None).unwrap();
        assert_eq!(config.get_parallel_decode_memory(), None);
        assert!(
            config
                .set_parallel_decode_memory(Some(PyInteger::from(0)))
                .is_err()
        );
        assert!(
            config
                .set_parallel_decode_memory(Some(PyInteger::from(-1)))
                .is_err()
        );
        assert!(
            config
                .set_parallel_decode_memory(Some(PyInteger::Fits(1 << 70)))
                .is_err()
        );
        assert_eq!(config.get_parallel_decode_memory(), None);
    }
}
