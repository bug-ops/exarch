//! Node.js bindings for `SecurityConfig`, `ExtractionOptions` and
//! `VerificationOptions`.

use std::num::NonZeroU64;
use std::num::NonZeroUsize;

use exarch_core::ArchiveError as CoreError;
use exarch_core::ConfigProblem;
use exarch_core::ConfigSetting;
use exarch_core::Extension;
use exarch_core::Limit;
use exarch_core::ParallelDecode;
use exarch_core::PathComponentName;
use exarch_core::RatioLimit;
use exarch_core::SecurityConfig as CoreConfig;
use exarch_core::ZipConsistencyPolicy as CorePolicy;
use exarch_core::creation::CompressionLevel;
use exarch_core::non_zero_u64;
use exarch_core::non_zero_usize;
use napi::Env;
use napi::bindgen_prelude::Either;
use napi::bindgen_prelude::Error;
use napi::bindgen_prelude::Null;
use napi::bindgen_prelude::Result;
use napi_derive::napi;

use crate::error::IntoJsError;
use crate::report::saturating_i64;
use crate::report::unknown_variant;

/// Parses a JavaScript byte count: a negative value and zero are refusals
/// naming `setting`.
fn byte_count(setting: ConfigSetting, size: i64) -> std::result::Result<NonZeroU64, CoreError> {
    let bytes = u64::try_from(size).map_err(|_| CoreError::InvalidConfiguration {
        setting,
        problem: ConfigProblem::Negative,
    })?;
    non_zero_u64(setting, bytes)
}

/// [`byte_count`] as a bounded limit.
fn byte_limit(
    setting: ConfigSetting,
    size: i64,
) -> std::result::Result<Limit<NonZeroU64>, CoreError> {
    byte_count(setting, size).map(Limit::Bounded)
}

/// Largest integer a JavaScript number holds exactly (2^53 - 1).
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// A positive whole byte count held exactly by `bytes`, or `None`.
///
/// napi's integer conversion would truncate `1.5` to `1`; a fraction is a
/// caller mistake and is refused instead.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "bytes is a whole number in 1..=2^53-1 here"
)]
pub fn exact_positive_bytes(bytes: f64) -> Option<NonZeroU64> {
    let whole =
        bytes.is_finite() && bytes.fract() == 0.0 && (1.0..=MAX_SAFE_INTEGER).contains(&bytes);
    whole.then(|| NonZeroU64::new(bytes as u64)).flatten()
}

/// How ZIP archives with ambiguous structure are handled.
///
/// `enforce` (the default, also for `SecurityConfig.permissive()`) rejects
/// archives whose local and central headers disagree, that repeat a name,
/// overlap entries or hide records. `ignore` keeps the central directory
/// interpretation without structural findings.
// Values must equal `exarch_core::ZipConsistencyPolicy::as_str`.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZipConsistencyPolicy {
    /// Reject or report structurally ambiguous ZIP archives.
    #[napi(value = "enforce")]
    Enforce,
    /// Use the central directory interpretation without structural findings.
    #[napi(value = "ignore")]
    Ignore,
}

impl From<ZipConsistencyPolicy> for CorePolicy {
    fn from(policy: ZipConsistencyPolicy) -> Self {
        match policy {
            ZipConsistencyPolicy::Enforce => Self::Enforce,
            ZipConsistencyPolicy::Ignore => Self::Ignore,
        }
    }
}

impl TryFrom<CorePolicy> for ZipConsistencyPolicy {
    type Error = Error;

    fn try_from(policy: CorePolicy) -> Result<Self> {
        match policy {
            CorePolicy::Enforce => Ok(Self::Enforce),
            CorePolicy::Ignore => Ok(Self::Ignore),
            other => Err(unknown_variant("ZIP consistency policy", other.as_str())),
        }
    }
}

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
/// | `banned_path_components` | `.git`, `.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`, `.env` |
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
    /// Throws `INVALID_CONFIGURATION` (`setting` is `max_file_size`) if size is
    /// negative or zero.
    #[napi(js_name = "setMaxFileSize")]
    pub fn set_max_file_size(&mut self, env: Env, size: i64) -> Result<&Self> {
        self.try_set_max_file_size(size)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Sets the maximum total size in bytes.
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is `max_total_size`) if size
    /// is negative or zero.
    #[napi(js_name = "setMaxTotalSize")]
    pub fn set_max_total_size(&mut self, env: Env, size: i64) -> Result<&Self> {
        self.try_set_max_total_size(size)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Sets the maximum compression ratio.
    ///
    /// Solid 7z blocks are exempt: each block is checked as a whole against a
    /// fixed 1000x limit that is configurable only from the Rust API.
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is `max_compression_ratio`) if
    /// ratio is not a positive finite number.
    #[napi(js_name = "setMaxCompressionRatio")]
    pub fn set_max_compression_ratio(&mut self, env: Env, ratio: f64) -> Result<&Self> {
        self.try_set_max_compression_ratio(ratio)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Sets the maximum file count.
    ///
    /// `extractArchive` counts files, symlinks and hardlinks, not directories;
    /// `listArchive` and `verifyArchive` count every entry.
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is `max_file_count`) if count
    /// is zero.
    #[napi(js_name = "setMaxFileCount")]
    pub fn set_max_file_count(&mut self, env: Env, count: u32) -> Result<&Self> {
        self.try_set_max_file_count(count)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Sets the maximum path depth.
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is `max_path_depth`) if depth
    /// is zero.
    #[napi(js_name = "setMaxPathDepth")]
    pub fn set_max_path_depth(&mut self, env: Env, depth: u32) -> Result<&Self> {
        self.try_set_max_path_depth(depth)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Allows or denies symlinks.
    #[napi(js_name = "setAllowSymlinks")]
    pub fn set_allow_symlinks(&mut self, allow: bool) -> &Self {
        self.inner.allowed.symlinks = exarch_core::Admit::from_allowed(allow);
        self
    }

    /// Allows or denies hardlinks.
    #[napi(js_name = "setAllowHardlinks")]
    pub fn set_allow_hardlinks(&mut self, allow: bool) -> &Self {
        self.inner.allowed.hardlinks = exarch_core::Admit::from_allowed(allow);
        self
    }

    /// Allows or denies absolute paths.
    #[napi(js_name = "setAllowAbsolutePaths")]
    pub fn set_allow_absolute_paths(&mut self, allow: bool) -> &Self {
        self.inner.allowed.absolute_paths = exarch_core::Admit::from_allowed(allow);
        self
    }

    /// Allows or denies world-writable files.
    #[napi(js_name = "setAllowWorldWritable")]
    pub fn set_allow_world_writable(&mut self, allow: bool) -> &Self {
        self.inner.allowed.world_writable = exarch_core::Admit::from_allowed(allow);
        self
    }

    /// Allows or denies solid 7z archives.
    ///
    /// Solid archives require reading all preceding entries to decompress any
    /// entry, which may allow a crafted archive to consume excessive
    /// memory. Disabled by default.
    #[napi(js_name = "setAllowSolidArchives")]
    pub fn set_allow_solid_archives(&mut self, allow: bool) -> &Self {
        self.inner.solid_archives = self.inner.solid_archives.with_allowed(allow);
        self
    }

    /// Sets how ZIP archives with ambiguous structure are handled.
    #[napi(js_name = "setZipConsistency")]
    pub fn set_zip_consistency(&mut self, policy: ZipConsistencyPolicy) -> &Self {
        self.inner.zip_consistency = policy.into();
        self
    }

    /// Sets the memory in bytes for decoding independent LZMA2 runs of a 7z
    /// block ahead on worker threads, or `null` to decode on one thread.
    ///
    /// The default is 128 MiB (1 GiB for `SecurityConfig.permissive()`). A
    /// stock 7-Zip archive has 64 MiB runs and needs about 100 MiB per extra
    /// concurrent run. A valid archive decodes to the same bytes either way and
    /// a corrupt one fails the same file. Each call may start up to 16 worker
    /// threads and hold its own lookahead, so concurrent calls multiply both.
    ///
    /// # Errors
    ///
    /// Returns error if `size` is not a positive whole number of bytes.
    #[napi(js_name = "setParallelDecodeMemory")]
    pub fn set_parallel_decode_memory(&mut self, size: Option<f64>) -> Result<&Self> {
        let lookahead = size
            .map(|bytes| {
                exact_positive_bytes(bytes).ok_or_else(|| {
                    Error::from_reason(
                        "parallel decode memory must be a positive whole number of bytes (use null to disable)",
                    )
                })
            })
            .transpose()?;
        self.inner.parallel_decode = ParallelDecode::from(lookahead);
        Ok(self)
    }

    /// Sets the maximum decoded size of a solid 7z block, in bytes.
    ///
    /// The limit bounds the decoded volume of each solid block, not resident
    /// memory. It exists only while solid archives are allowed, so call
    /// `setAllowSolidArchives(true)` first. Default: 512 MB.
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is `max_solid_block_memory`)
    /// if size is negative or zero, or while solid archives are not allowed.
    #[napi(js_name = "setMaxSolidBlockMemory")]
    pub fn set_max_solid_block_memory(&mut self, env: Env, size: i64) -> Result<&Self> {
        self.try_set_max_solid_block_memory(size)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Sets whether to preserve permissions from archive.
    #[napi(js_name = "setPreservePermissions")]
    pub fn set_preserve_permissions(&mut self, preserve: bool) -> &Self {
        self.inner.preserve_permissions = preserve;
        self
    }

    /// Adds an allowed file extension.
    ///
    /// A leading dot is accepted and removed, and the value is lowercased.
    ///
    /// # Errors
    ///
    /// Returns error if the extension is empty, exceeds maximum length, or
    /// contains a null byte, whitespace, a path separator or an inner dot.
    #[napi]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "napi cannot take a JavaScript string by reference"
    )]
    pub fn add_allowed_extension(&mut self, env: Env, ext: String) -> Result<&Self> {
        self.try_add_allowed_extension(&ext)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Adds a banned path component.
    ///
    /// # Errors
    ///
    /// Returns error if the component is empty, exceeds maximum length, or
    /// contains a null byte, a path separator, `.` or `..`.
    #[napi]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "napi cannot take a JavaScript string by reference"
    )]
    pub fn add_banned_component(&mut self, env: Env, component: String) -> Result<&Self> {
        self.try_add_banned_component(&component)
            .map_err(|err| err.into_js_error(env))?;
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
    pub fn get_max_file_size(&self) -> i64 {
        saturating_i64(self.inner.max_file_size.ceiling())
    }

    /// Maximum total size in bytes.
    #[napi(getter)]
    pub fn get_max_total_size(&self) -> i64 {
        saturating_i64(self.inner.max_total_size.ceiling())
    }

    /// Maximum compression ratio.
    #[napi(getter)]
    pub fn get_max_compression_ratio(&self) -> f64 {
        self.inner.max_compression_ratio.get()
    }

    /// Maximum file count.
    #[napi(getter)]
    #[allow(clippy::cast_possible_truncation)]
    pub fn get_max_file_count(&self) -> u32 {
        self.inner.max_file_count.ceiling() as u32
    }

    /// Maximum path depth.
    #[napi(getter)]
    #[allow(clippy::cast_possible_truncation)]
    pub fn get_max_path_depth(&self) -> u32 {
        self.inner.max_path_depth.get() as u32
    }

    /// Whether to preserve permissions from archive.
    #[napi(getter)]
    pub fn get_preserve_permissions(&self) -> bool {
        self.inner.preserve_permissions
    }

    /// Whether symlinks are allowed.
    #[napi(getter)]
    pub fn get_allow_symlinks(&self) -> bool {
        self.inner.allowed.symlinks.is_allowed()
    }

    /// Whether hardlinks are allowed.
    #[napi(getter)]
    pub fn get_allow_hardlinks(&self) -> bool {
        self.inner.allowed.hardlinks.is_allowed()
    }

    /// Whether absolute paths are allowed.
    #[napi(getter)]
    pub fn get_allow_absolute_paths(&self) -> bool {
        self.inner.allowed.absolute_paths.is_allowed()
    }

    /// Whether world-writable files are allowed.
    #[napi(getter)]
    pub fn get_allow_world_writable(&self) -> bool {
        self.inner.allowed.world_writable.is_allowed()
    }

    /// Whether solid 7z archives are allowed.
    #[napi(getter)]
    pub fn get_allow_solid_archives(&self) -> bool {
        self.inner.solid_archives.is_allowed()
    }

    /// How ZIP archives with ambiguous structure are handled.
    ///
    /// # Errors
    ///
    /// Returns error if this binding is older than `exarch-core` and does not
    /// know the policy.
    #[napi(getter)]
    pub fn get_zip_consistency(&self) -> Result<ZipConsistencyPolicy> {
        self.inner.zip_consistency.try_into()
    }

    /// Memory in bytes for decoding 7z LZMA2 runs ahead on worker threads, or
    /// `null` when decoding runs on one thread.
    #[napi(getter)]
    pub fn get_parallel_decode_memory(&self) -> Option<i64> {
        self.inner
            .parallel_decode
            .lookahead()
            .map(|bytes| saturating_i64(bytes.get()))
    }

    /// Maximum decoded size in bytes of a solid 7z block, or `null` while
    /// solid archives are not allowed.
    #[napi(getter)]
    pub fn get_max_solid_block_memory(&self) -> Option<i64> {
        self.inner
            .solid_archives
            .limits()
            .map(|limits| saturating_i64(limits.max_block_memory.get()))
    }

    /// List of allowed file extensions.
    ///
    /// Note: This getter clones the underlying data. For performance-critical
    /// code that only needs to count or check membership, use
    /// `getAllowedExtensionsCount()` or `hasAllowedExtension()` instead.
    #[napi(getter)]
    pub fn get_allowed_extensions(&self) -> Vec<String> {
        self.inner
            .allowed_extensions
            .iter()
            .map(|ext| ext.as_str().to_owned())
            .collect()
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
        Extension::try_from(ext.as_str())
            .is_ok_and(|ext| self.inner.allowed_extensions.contains(&ext))
    }

    /// List of banned path components.
    ///
    /// Note: This getter clones the underlying data. For performance-critical
    /// code that only needs to count or check membership, use
    /// `getBannedPathComponentsCount()` or `hasBannedPathComponent()` instead.
    #[napi(getter)]
    pub fn get_banned_path_components(&self) -> Vec<String> {
        self.inner
            .banned_path_components
            .iter()
            .map(|component| component.as_str().to_owned())
            .collect()
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
        self.inner
            .banned_path_components
            .iter()
            .any(|banned| banned.matches(&component))
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

    /// Env-free core of `setMaxFileSize`.
    fn try_set_max_file_size(&mut self, size: i64) -> std::result::Result<(), CoreError> {
        self.inner.max_file_size = byte_limit(ConfigSetting::MaxFileSize, size)?;
        Ok(())
    }

    /// Env-free core of `setMaxTotalSize`.
    fn try_set_max_total_size(&mut self, size: i64) -> std::result::Result<(), CoreError> {
        self.inner.max_total_size = byte_limit(ConfigSetting::MaxTotalSize, size)?;
        Ok(())
    }

    /// Env-free core of `setMaxCompressionRatio`.
    fn try_set_max_compression_ratio(&mut self, ratio: f64) -> std::result::Result<(), CoreError> {
        self.inner.max_compression_ratio =
            RatioLimit::parse(ConfigSetting::MaxCompressionRatio, ratio)?;
        Ok(())
    }

    /// Env-free core of `setMaxFileCount`.
    fn try_set_max_file_count(&mut self, count: u32) -> std::result::Result<(), CoreError> {
        self.inner.max_file_count =
            Limit::<NonZeroUsize>::parse(ConfigSetting::MaxFileCount, count as usize)?;
        Ok(())
    }

    /// Env-free core of `setMaxPathDepth`.
    fn try_set_max_path_depth(&mut self, depth: u32) -> std::result::Result<(), CoreError> {
        self.inner.max_path_depth = non_zero_usize(ConfigSetting::MaxPathDepth, depth as usize)?;
        Ok(())
    }

    /// Env-free core of `setMaxSolidBlockMemory`.
    fn try_set_max_solid_block_memory(&mut self, size: i64) -> std::result::Result<(), CoreError> {
        let max_block_memory = byte_count(ConfigSetting::MaxSolidBlockMemory, size)?;
        self.inner.solid_archives = self
            .inner
            .solid_archives
            .with_max_block_memory(max_block_memory)?;
        Ok(())
    }

    /// Env-free core of `addAllowedExtension`, so the validation is testable
    /// without a JS environment.
    fn try_add_allowed_extension(&mut self, ext: &str) -> std::result::Result<(), CoreError> {
        let ext = Extension::try_from(ext)?;
        self.inner.allowed_extensions.push(ext);
        Ok(())
    }

    /// Env-free core of `addBannedComponent`.
    fn try_add_banned_component(&mut self, component: &str) -> std::result::Result<(), CoreError> {
        let component = PathComponentName::try_from(component)?;
        self.inner.banned_path_components.push(component);
        Ok(())
    }
}

/// Configuration for archive creation operations.
///
/// Controls how archives are created from filesystem sources, including
/// security options, compression settings, and file filtering.
///
/// # Defaults
///
/// | Setting | Default Value |
/// |---------|--------------|
/// | `compression_level` | 6 (balanced) |
/// | `preserve_permissions` | true |
/// | `follow_symlinks` | false (secure) |
/// | `include_hidden` | false |
/// | `max_file_size` | `null` (no limit) |
/// | `exclude_patterns` | `[".git", ".DS_Store", "*.tmp"]` |
#[napi]
#[derive(Debug, Clone)]
pub struct CreationConfig {
    inner: exarch_core::creation::CreationConfig,
}

#[napi]
impl CreationConfig {
    /// Creates a new `CreationConfig` with secure defaults.
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: exarch_core::creation::CreationConfig::default(),
        }
    }

    /// Creates a `CreationConfig` with secure defaults.
    ///
    /// This is equivalent to calling `new CreationConfig()`.
    #[napi(factory)]
    pub fn default() -> Self {
        Self::new()
    }

    /// Sets the compression level (1-9).
    ///
    /// Higher values provide better compression but slower speed.
    /// Default: 6 (balanced).
    ///
    /// # Errors
    ///
    /// Returns error if level is not in range 1-9.
    #[napi(js_name = "setCompressionLevel")]
    pub fn set_compression_level(&mut self, env: Env, level: u32) -> Result<&Self> {
        self.try_set_compression_level(level)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Sets whether to preserve file permissions from source.
    ///
    /// Default: true.
    #[napi(js_name = "setPreservePermissions")]
    pub fn set_preserve_permissions(&mut self, preserve: bool) -> &Self {
        self.inner.preserve_permissions = preserve;
        self
    }

    /// Sets whether to follow symlinks when adding files.
    ///
    /// Default: false (store symlinks as symlinks).
    ///
    /// Security note: Following symlinks may include unintended files
    /// from outside the source directory.
    #[napi(js_name = "setFollowSymlinks")]
    pub fn set_follow_symlinks(&mut self, follow: bool) -> &Self {
        self.inner.follow_symlinks = follow;
        self
    }

    /// Sets whether to include hidden files (files starting with '.').
    ///
    /// Default: false.
    #[napi(js_name = "setIncludeHidden")]
    pub fn set_include_hidden(&mut self, include: bool) -> &Self {
        self.inner.include_hidden = include;
        self
    }

    /// Sets maximum size for a single file in bytes, or `null` for no limit.
    ///
    /// Files larger than this limit will be skipped.
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is `max_file_size`) if size is
    /// negative or zero. Pass `null` to remove the limit.
    #[napi(js_name = "setMaxFileSize")]
    pub fn set_max_file_size(&mut self, env: Env, size: Either<i64, Null>) -> Result<&Self> {
        let size = match size {
            Either::A(bytes) => Some(bytes),
            Either::B(_) => None,
        };
        self.try_set_max_file_size(size)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Adds an exclude pattern.
    ///
    /// Files matching this pattern will be skipped.
    ///
    /// # Errors
    ///
    /// Returns error if pattern contains null bytes.
    #[napi]
    pub fn add_exclude_pattern(&mut self, pattern: String) -> Result<&Self> {
        if pattern.contains('\0') {
            return Err(Error::from_reason(
                "pattern contains null bytes - potential security issue",
            ));
        }
        self.inner.exclude_patterns.push(pattern);
        Ok(self)
    }

    /// Finalizes the configuration (for API consistency).
    #[napi]
    pub fn build(&self) -> &Self {
        self
    }

    // Property getters

    /// Compression level (1-9).
    #[napi(getter)]
    pub fn get_compression_level(&self) -> u32 {
        u32::from(self.inner.compression_level.get())
    }

    /// Whether to preserve permissions.
    #[napi(getter)]
    pub fn get_preserve_permissions(&self) -> bool {
        self.inner.preserve_permissions
    }

    /// Whether to follow symlinks.
    #[napi(getter)]
    pub fn get_follow_symlinks(&self) -> bool {
        self.inner.follow_symlinks
    }

    /// Whether to include hidden files.
    #[napi(getter)]
    pub fn get_include_hidden(&self) -> bool {
        self.inner.include_hidden
    }

    /// Maximum file size in bytes, or `null` when unbounded.
    #[napi(getter)]
    pub fn get_max_file_size(&self) -> Option<i64> {
        match self.inner.max_file_size {
            Limit::Bounded(bound) => Some(saturating_i64(bound.get())),
            Limit::Unbounded => None,
        }
    }

    /// List of exclude patterns.
    #[napi(getter)]
    pub fn get_exclude_patterns(&self) -> Vec<String> {
        self.inner.exclude_patterns.clone()
    }
}

impl CreationConfig {
    /// Env-free core of `setMaxFileSize`; `None` removes the limit.
    fn try_set_max_file_size(&mut self, size: Option<i64>) -> std::result::Result<(), CoreError> {
        self.inner.max_file_size = match size {
            Some(bytes) => byte_limit(ConfigSetting::MaxFileSize, bytes)?,
            None => Limit::Unbounded,
        };
        Ok(())
    }

    /// Env-free core of `setCompressionLevel`, so the validation is testable
    /// without a JS environment.
    fn try_set_compression_level(&mut self, level: u32) -> std::result::Result<(), CoreError> {
        self.inner.compression_level = CompressionLevel::try_from(level)?;
        Ok(())
    }

    /// Returns a reference to the inner `CoreCreationConfig`.
    pub fn as_core(&self) -> &exarch_core::creation::CreationConfig {
        &self.inner
    }
}

/// Options controlling extraction behavior (non-security).
///
/// Separate from `SecurityConfig` to keep security settings focused.
/// These options control operational behavior such as duplicate handling.
///
/// # Defaults
///
/// | Setting | Default Value |
/// |---------|--------------|
/// | `skipDuplicates` | `true` |
/// | `atomic` | `false` |
#[napi]
#[derive(Debug, Clone)]
pub struct ExtractionOptions {
    inner: exarch_core::ExtractionOptions,
}

#[napi]
impl ExtractionOptions {
    /// Creates a new `ExtractionOptions` with defaults.
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: exarch_core::ExtractionOptions::default(),
        }
    }

    /// Creates an `ExtractionOptions` with defaults.
    ///
    /// This is equivalent to calling `new ExtractionOptions()`.
    #[napi(factory)]
    pub fn default() -> Self {
        Self::new()
    }

    /// Sets whether duplicate archive entries are skipped silently.
    ///
    /// When `true` (default), duplicate entries produce a warning in the
    /// report. When `false`, a duplicate entry causes an error.
    #[napi(js_name = "withSkipDuplicates")]
    pub fn with_skip_duplicates(&mut self, skip: bool) -> &Self {
        self.inner.skip_duplicates = skip;
        self
    }

    /// Sets whether extraction uses a temporary directory for atomic commits.
    ///
    /// When `true`, files are extracted to a temp dir in the same parent as
    /// the output directory, then atomically renamed on completion. On failure
    /// the temp dir is removed, leaving the output directory untouched.
    /// Default: `false`.
    ///
    /// **Important:** atomic mode requires that the output directory does not
    /// already exist. If it does, extraction fails with an
    /// output-already-exists error. Non-atomic mode extracts into an
    /// existing directory without error.
    #[napi(js_name = "withAtomic")]
    pub fn with_atomic(&mut self, atomic: bool) -> &Self {
        self.inner.atomic = atomic;
        self
    }

    /// Finalizes the configuration (for API consistency).
    #[napi]
    pub fn build(&self) -> &Self {
        self
    }

    /// Whether duplicate entries are skipped silently.
    #[napi(getter)]
    pub fn get_skip_duplicates(&self) -> bool {
        self.inner.skip_duplicates
    }

    /// Whether atomic extraction is enabled.
    #[napi(getter)]
    pub fn get_atomic(&self) -> bool {
        self.inner.atomic
    }
}

impl ExtractionOptions {
    /// Returns a reference to the inner `CoreExtractionOptions`.
    ///
    /// Used internally to pass options to the Rust extraction API.
    pub fn as_core(&self) -> &exarch_core::ExtractionOptions {
        &self.inner
    }
}

/// Options controlling verification behavior (non-security).
///
/// By default `verifyArchive` checks metadata only and reports
/// `integrityStatus` as `'SKIPPED'`. `withIntegrityCheck` additionally decodes
/// the payload so checksums and codec framing are verified.
///
/// # Defaults
///
/// | Setting | Default Value |
/// |---------|--------------|
/// | `integrityCheck` | `false` |
/// | `decompressionBudget` | none (500 MiB when the check is enabled) |
#[napi]
#[derive(Debug, Clone)]
pub struct VerificationOptions {
    inner: exarch_core::VerificationOptions,
}

#[napi]
impl VerificationOptions {
    /// Creates a new `VerificationOptions` with defaults (no integrity check).
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: exarch_core::VerificationOptions::default(),
        }
    }

    /// Creates a `VerificationOptions` with defaults.
    ///
    /// This is equivalent to calling `new VerificationOptions()`.
    #[napi(factory)]
    pub fn default() -> Self {
        Self::new()
    }

    /// Enables the payload integrity check.
    ///
    /// `budget` bounds the extra bytes decoded beyond listing; omit it for the
    /// default of 500 MiB, which does not follow `maxTotalSize`.
    ///
    /// # Errors
    ///
    /// Returns error if `budget` is zero or negative.
    #[napi(js_name = "withIntegrityCheck")]
    pub fn with_integrity_check(&mut self, env: Env, budget: Option<i64>) -> Result<&Self> {
        self.try_with_integrity_check(budget)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Whether the payload integrity check is enabled.
    #[napi(getter)]
    pub fn get_integrity_check(&self) -> bool {
        !matches!(self.inner.integrity, exarch_core::IntegrityCheck::Skip)
    }

    /// Budget in bytes when the integrity check is enabled.
    #[napi(getter)]
    pub fn get_decompression_budget(&self) -> Option<i64> {
        match self.inner.integrity {
            exarch_core::IntegrityCheck::DecodeToEof(budget) => Some(saturating_i64(budget.get())),
            _ => None,
        }
    }
}

impl VerificationOptions {
    /// Returns a reference to the inner `CoreVerificationOptions`.
    pub fn as_core(&self) -> &exarch_core::VerificationOptions {
        &self.inner
    }

    /// Env-free core of `withIntegrityCheck`.
    fn try_with_integrity_check(
        &mut self,
        budget: Option<i64>,
    ) -> std::result::Result<(), CoreError> {
        let budget = match budget {
            Some(bytes) => exarch_core::DecompressionBudget::try_from_bytes(
                u64::try_from(bytes).unwrap_or_default(),
            )?,
            None => exarch_core::DecompressionBudget::DEFAULT,
        };
        self.inner.integrity = exarch_core::IntegrityCheck::DecodeToEof(budget);
        Ok(())
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
    use exarch_core::MAX_CONFIG_ENTRY_LENGTH;
    use std::assert_matches;

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
    fn test_size_getters_clamp_values_above_i64_max() {
        let mut config = SecurityConfig::new();
        config.inner.max_file_size = exarch_core::Limit::Unbounded;
        config.inner.max_total_size = exarch_core::Limit::Unbounded;
        config.inner.solid_archives = exarch_core::SolidArchives::Allow(
            exarch_core::SolidLimits::DEFAULT.with_max_block_memory(NonZeroU64::MAX),
        );
        assert_eq!(config.get_max_file_size(), i64::MAX);
        assert_eq!(config.get_max_total_size(), i64::MAX);
        assert_eq!(config.get_max_solid_block_memory(), Some(i64::MAX));

        let mut creation = CreationConfig::new();
        creation.inner.max_file_size = exarch_core::Limit::Bounded(NonZeroU64::MAX);
        assert_eq!(creation.get_max_file_size(), Some(i64::MAX));
    }

    #[test]
    fn test_default_static_method() {
        let config = SecurityConfig::default();
        assert_eq!(config.get_max_file_size(), 50 * 1024 * 1024);
    }

    #[test]
    fn test_permissive_config() {
        let config = SecurityConfig::permissive();
        assert!(config.inner.allowed.symlinks.is_allowed());
        assert!(config.inner.allowed.hardlinks.is_allowed());
        assert!(config.inner.allowed.absolute_paths.is_allowed());
        assert!(config.get_preserve_permissions());
    }

    #[test]
    fn test_builder_pattern_method_chaining() {
        let mut config = SecurityConfig::new();
        config.try_set_max_file_size(100_000_000).unwrap();
        config.try_set_max_total_size(1_000_000_000).unwrap();
        config.try_set_max_file_count(50_000).unwrap();

        assert_eq!(config.get_max_file_size(), 100_000_000);
        assert_eq!(config.get_max_total_size(), 1_000_000_000);
        assert_eq!(config.get_max_file_count(), 50_000);
    }

    #[test]
    fn test_builder_compression_ratio_valid() {
        let mut config = SecurityConfig::new();
        let result = config.try_set_max_compression_ratio(200.0);
        assert!(result.is_ok());
        assert_eq!(config.get_max_compression_ratio(), 200.0);
    }

    #[test]
    fn test_builder_compression_ratio_rejects_nan() {
        let mut config = SecurityConfig::new();
        let result = config.try_set_max_compression_ratio(f64::NAN);
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_compression_ratio_rejects_infinity() {
        let mut config = SecurityConfig::new();
        let result = config.try_set_max_compression_ratio(f64::INFINITY);
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_compression_ratio_rejects_negative() {
        let mut config = SecurityConfig::new();
        let result = config.try_set_max_compression_ratio(-10.0);
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_compression_ratio_rejects_zero() {
        let mut config = SecurityConfig::new();
        let result = config.try_set_max_compression_ratio(0.0);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_allowed_extension_valid() {
        let mut config = SecurityConfig::new();
        let result = config.try_add_allowed_extension(".txt");
        assert!(result.is_ok());
        assert!(config.get_allowed_extensions().contains(&"txt".to_string()));
        assert!(config.has_allowed_extension(".TXT".to_string()));
    }

    #[test]
    fn test_add_allowed_extension_rejects_unusable_values() {
        for raw in [" gz", "tar.gz", "a/b", "..txt"] {
            let mut config = SecurityConfig::new();
            assert!(config.try_add_allowed_extension(raw).is_err(), "{raw:?}");
        }
    }

    #[test]
    fn test_add_banned_component_rejects_separators_and_dots() {
        for raw in ["a/b", "a\\b", ".", ".."] {
            let mut config = SecurityConfig::new();
            assert!(config.try_add_banned_component(raw).is_err(), "{raw:?}");
        }
    }

    #[test]
    fn test_add_allowed_extension_rejects_null_bytes() {
        let mut config = SecurityConfig::new();
        let result = config.try_add_allowed_extension(".txt\0");
        assert!(result.is_err());
    }

    #[test]
    fn test_add_allowed_extension_rejects_too_long() {
        let mut config = SecurityConfig::new();
        let long_ext = "x".repeat(MAX_CONFIG_ENTRY_LENGTH + 1);
        let result = config.try_add_allowed_extension(&long_ext);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_allowed_extension_rejects_empty() {
        let mut config = SecurityConfig::new();
        let result = config.try_add_allowed_extension("");
        assert!(result.is_err());
    }

    #[test]
    fn test_add_banned_component_valid() {
        let mut config = SecurityConfig::new();
        let result = config.try_add_banned_component("node_modules");
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
        let result = config.try_add_banned_component("bad\0");
        assert!(result.is_err());
    }

    #[test]
    fn test_add_banned_component_rejects_too_long() {
        let mut config = SecurityConfig::new();
        let long_component = "x".repeat(MAX_CONFIG_ENTRY_LENGTH + 1);
        let result = config.try_add_banned_component(&long_component);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_banned_component_rejects_empty() {
        let mut config = SecurityConfig::new();
        let result = config.try_add_banned_component("");
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
        assert_eq!(core_config.max_file_size.ceiling(), 50 * 1024 * 1024);
    }

    // Integer boundary tests
    #[test]
    fn test_max_file_size_negative_value() {
        let mut config = SecurityConfig::new();
        let result = config.try_set_max_file_size(-1);
        assert!(result.is_err(), "negative file size should be rejected");
        assert!(
            result.unwrap_err().to_string().contains("negative"),
            "error should mention negative value"
        );
    }

    #[test]
    fn test_max_file_size_i64_max() {
        let mut config = SecurityConfig::new();
        let result = config.try_set_max_file_size(i64::MAX);
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
        let result = config.try_set_max_total_size(-1);
        assert!(result.is_err(), "negative total size should be rejected");
        assert!(
            result.unwrap_err().to_string().contains("negative"),
            "error should mention negative value"
        );
    }

    #[test]
    fn test_max_total_size_i64_max() {
        let mut config = SecurityConfig::new();
        let result = config.try_set_max_total_size(i64::MAX);
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
        config.try_set_max_file_count(u32::MAX).unwrap();
        assert_eq!(
            config.get_max_file_count(),
            u32::MAX,
            "u32::MAX should be accepted"
        );
    }

    #[test]
    fn test_max_path_depth_u32_max() {
        let mut config = SecurityConfig::new();
        config.try_set_max_path_depth(u32::MAX).unwrap();
        assert_eq!(
            config.get_max_path_depth(),
            u32::MAX,
            "u32::MAX should be accepted"
        );
    }

    #[test]
    fn test_max_file_size_zero() {
        let mut config = SecurityConfig::new();
        let err = config.try_set_max_file_size(0).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid configuration: max_file_size must not be zero"
        );
        assert_eq!(config.get_max_file_size(), 50 * 1024 * 1024);
    }

    // Property getter tests
    #[test]
    fn test_property_getters_return_correct_values() {
        let mut config = SecurityConfig::new();
        config.try_set_max_file_size(100_000_000).unwrap();
        config.try_set_max_total_size(1_000_000_000).unwrap();
        config.try_set_max_compression_ratio(250.0).unwrap();
        config.try_set_max_file_count(50_000).unwrap();
        config.try_set_max_path_depth(64).unwrap();
        config.set_preserve_permissions(true);

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
    fn test_allow_solid_archives_default_and_round_trip() {
        let config = SecurityConfig::new();
        assert!(
            !config.get_allow_solid_archives(),
            "allow_solid_archives should default to false"
        );

        let mut config = SecurityConfig::new();
        config.set_allow_solid_archives(true);
        assert!(
            config.get_allow_solid_archives(),
            "allow_solid_archives getter should reflect setter value"
        );
    }

    #[test]
    fn test_max_solid_block_memory_default() {
        let mut config = SecurityConfig::new();
        assert_eq!(
            config.get_max_solid_block_memory(),
            None,
            "no limit is reported while solid archives are refused"
        );
        config.set_allow_solid_archives(true);
        assert_eq!(
            config.get_max_solid_block_memory(),
            Some(512 * 1024 * 1024),
            "max_solid_block_memory should default to 512 MB once allowed"
        );
    }

    #[test]
    fn test_max_solid_block_memory_refused_while_solid_archives_are_refused() {
        let mut config = SecurityConfig::new();
        let err = config
            .try_set_max_solid_block_memory(256 * 1024 * 1024)
            .unwrap_err();
        assert_eq!(
            err.ffi_kind().setting(),
            Some(ConfigSetting::MaxSolidBlockMemory)
        );
        assert_eq!(config.get_max_solid_block_memory(), None);
    }

    #[test]
    fn test_disallowing_solid_archives_drops_the_limit() {
        let mut config = SecurityConfig::new();
        config.set_allow_solid_archives(true);
        config.try_set_max_solid_block_memory(1024).unwrap();
        config.set_allow_solid_archives(true);
        assert_eq!(config.get_max_solid_block_memory(), Some(1024));
        config.set_allow_solid_archives(false);
        assert_eq!(config.get_max_solid_block_memory(), None);
    }

    #[test]
    fn test_max_solid_block_memory_round_trip() {
        let mut config = SecurityConfig::new();
        config.set_allow_solid_archives(true);
        let result = config.try_set_max_solid_block_memory(256 * 1024 * 1024);
        assert!(result.is_ok());
        assert_eq!(
            config.get_max_solid_block_memory(),
            Some(256 * 1024 * 1024),
            "getter should reflect set value"
        );
    }

    #[test]
    fn test_max_solid_block_memory_rejects_negative() {
        let mut config = SecurityConfig::new();
        let result = config.try_set_max_solid_block_memory(-1);
        assert!(result.is_err(), "negative value should be rejected");
        assert!(
            result.unwrap_err().to_string().contains("negative"),
            "error should mention the negative value"
        );
    }

    #[test]
    fn test_max_solid_block_memory_rejects_zero() {
        let mut config = SecurityConfig::new();
        let result = config.try_set_max_solid_block_memory(0);
        assert!(result.is_err(), "zero should be rejected");
    }

    #[test]
    fn test_max_solid_block_memory_accepts_one_byte() {
        let mut config = SecurityConfig::new();
        config.set_allow_solid_archives(true);
        let result = config.try_set_max_solid_block_memory(1);
        assert!(result.is_ok(), "1 byte should be accepted");
        assert_eq!(config.get_max_solid_block_memory(), Some(1));
    }

    #[test]
    fn test_allowed_extensions_getter_after_add() {
        let mut config = SecurityConfig::new();
        config.try_add_allowed_extension(".txt").unwrap();
        config.try_add_allowed_extension(".md").unwrap();

        let extensions = config.get_allowed_extensions();
        assert_eq!(extensions.len(), 2, "should have 2 allowed extensions");
        assert!(
            extensions.contains(&"txt".to_string()),
            "should contain .txt"
        );
        assert!(extensions.contains(&"md".to_string()), "should contain .md");
    }

    #[test]
    fn test_banned_components_getter_after_add() {
        let mut config = SecurityConfig::new();
        // Default config already has 7 banned components
        let initial_count = config.get_banned_path_components().len();

        config.try_add_banned_component("node_modules").unwrap();
        config.try_add_banned_component("test_component").unwrap();

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
        config.try_add_allowed_extension(".txt").unwrap();
        config.try_add_allowed_extension(".md").unwrap();

        assert!(
            config.is_extension_allowed("txt".to_string()),
            ".txt should be in allowed list"
        );
        assert!(
            config.is_extension_allowed("md".to_string()),
            ".md should be in allowed list"
        );
        assert!(
            !config.is_extension_allowed("exe".to_string()),
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
        config.try_add_allowed_extension(".txt").unwrap();

        assert!(
            config.is_extension_allowed("txt".to_string()),
            "exact case should match"
        );
        // NOTE: Core library uses case-insensitive matching for extensions
        // This is intentional for cross-platform compatibility
        assert!(
            config.is_extension_allowed("TXT".to_string()),
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
        config.try_set_max_file_size(100_000_000).unwrap();
        config.try_set_max_total_size(1_000_000_000).unwrap();
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
        let result = config.try_set_max_compression_ratio(f64::NEG_INFINITY);
        assert!(result.is_err(), "negative infinity should be rejected");
    }

    #[test]
    fn test_builder_compression_ratio_accepts_very_small_positive() {
        let mut config = SecurityConfig::new();
        let result = config.try_set_max_compression_ratio(0.000001);
        assert!(
            result.is_ok(),
            "very small positive values should be accepted"
        );
        assert_eq!(config.get_max_compression_ratio(), 0.000001);
    }

    #[test]
    fn test_builder_compression_ratio_accepts_very_large() {
        let mut config = SecurityConfig::new();
        let result = config.try_set_max_compression_ratio(1_000_000.0);
        assert!(result.is_ok(), "very large values should be accepted");
        assert_eq!(config.get_max_compression_ratio(), 1_000_000.0);
    }

    // Clone and Debug tests
    #[test]
    fn test_security_config_clone() {
        let mut config = SecurityConfig::new();
        config.try_set_max_file_size(100_000_000).unwrap();

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

        config.try_add_allowed_extension(".txt").unwrap();
        config.try_add_allowed_extension(".md").unwrap();

        assert_eq!(
            config.get_allowed_extensions_count(),
            2,
            "count should reflect added extensions"
        );
    }

    #[test]
    fn test_has_allowed_extension() {
        let mut config = SecurityConfig::new();
        config.try_add_allowed_extension(".txt").unwrap();

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

        config.try_add_banned_component("node_modules").unwrap();
        config.try_add_banned_component("custom_dir").unwrap();

        assert_eq!(
            config.get_banned_path_components_count(),
            initial_count + 2,
            "count should reflect added components"
        );
    }

    #[test]
    fn test_has_banned_path_component() {
        let mut config = SecurityConfig::new();
        config.try_add_banned_component("node_modules").unwrap();

        assert!(
            config.has_banned_path_component("node_modules".to_string()),
            "should find node_modules"
        );
        // .git is in default banned components
        assert!(
            config.has_banned_path_component(".git".to_string()),
            ".git should be in default banned components"
        );
        assert!(
            config.has_banned_path_component(".GIT".to_string()),
            "matching ignores ASCII case"
        );
    }

    // CreationConfig tests
    #[test]
    fn test_creation_config_default() {
        let config = CreationConfig::new();
        assert_eq!(config.get_compression_level(), 6);
        assert!(config.get_preserve_permissions());
        assert!(!config.get_follow_symlinks());
        assert!(!config.get_include_hidden());
        assert_eq!(config.get_max_file_size(), None);
        assert_eq!(config.get_exclude_patterns().len(), 3);
    }

    #[test]
    fn test_creation_config_builder() {
        let mut config = CreationConfig::new();
        config.try_set_compression_level(9).unwrap();
        config.set_preserve_permissions(false);
        config.set_follow_symlinks(true);
        config.set_include_hidden(true);
        config.try_set_max_file_size(Some(1_000_000)).unwrap();

        assert_eq!(config.get_compression_level(), 9);
        assert!(!config.get_preserve_permissions());
        assert!(config.get_follow_symlinks());
        assert!(config.get_include_hidden());
        assert_eq!(config.get_max_file_size(), Some(1_000_000));
    }

    #[test]
    fn test_creation_config_compression_level_rejects_invalid() {
        let mut config = CreationConfig::new();
        assert!(config.try_set_compression_level(0).is_err());
        assert!(config.try_set_compression_level(10).is_err());
    }

    #[test]
    fn test_creation_config_compression_level_accepts_valid() {
        let mut config = CreationConfig::new();
        assert!(config.try_set_compression_level(1).is_ok());
        assert!(config.try_set_compression_level(9).is_ok());
    }

    #[test]
    fn test_creation_config_max_file_size_rejects_zero_and_negative() {
        let mut config = CreationConfig::new();
        config.try_set_max_file_size(Some(10)).unwrap();
        for bad in [0, -1] {
            let err = config.try_set_max_file_size(Some(bad)).unwrap_err();
            assert_matches!(
                err,
                CoreError::InvalidConfiguration {
                    setting: ConfigSetting::MaxFileSize,
                    ..
                }
            );
        }
        assert_eq!(config.get_max_file_size(), Some(10));
    }

    #[test]
    fn test_creation_config_max_file_size_none_is_unbounded() {
        let mut config = CreationConfig::new();
        config.try_set_max_file_size(Some(10)).unwrap();
        config.try_set_max_file_size(None).unwrap();
        assert_eq!(config.get_max_file_size(), None);
        assert_eq!(config.as_core().max_file_size, Limit::Unbounded);
    }

    #[test]
    fn test_creation_config_add_exclude_pattern() {
        let mut config = CreationConfig::new();
        config.add_exclude_pattern("*.log".to_string()).unwrap();
        let patterns = config.get_exclude_patterns();
        assert!(patterns.contains(&"*.log".to_string()));
    }

    #[test]
    fn test_creation_config_add_exclude_pattern_rejects_null() {
        let mut config = CreationConfig::new();
        let result = config.add_exclude_pattern("bad\0pattern".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_creation_config_as_core() {
        let config = CreationConfig::new();
        let core = config.as_core();
        assert_eq!(core.compression_level, CompressionLevel::default());
    }

    #[test]
    fn test_parallel_decode_memory_defaults_and_round_trips() {
        const MIB: i64 = 1024 * 1024;
        let mut config = SecurityConfig::new();
        assert_eq!(config.get_parallel_decode_memory(), Some(128 * MIB));
        assert_eq!(
            SecurityConfig::permissive().get_parallel_decode_memory(),
            Some(1024 * MIB)
        );

        config
            .set_parallel_decode_memory(Some(256.0 * 1048576.0))
            .unwrap();
        assert_eq!(config.get_parallel_decode_memory(), Some(256 * MIB));
        config.set_parallel_decode_memory(None).unwrap();
        assert_eq!(config.get_parallel_decode_memory(), None);
    }

    #[test]
    fn test_parallel_decode_memory_rejects_zero_and_negative() {
        let mut config = SecurityConfig::new();
        assert!(config.set_parallel_decode_memory(Some(0.0)).is_err());
        assert!(config.set_parallel_decode_memory(Some(-1.0)).is_err());
        assert!(config.set_parallel_decode_memory(Some(1.5)).is_err());
        assert!(config.set_parallel_decode_memory(Some(f64::NAN)).is_err());
        assert!(
            config
                .set_parallel_decode_memory(Some(f64::INFINITY))
                .is_err()
        );
        assert!(config.set_parallel_decode_memory(Some(1.0e300)).is_err());
        assert_eq!(config.get_parallel_decode_memory(), Some(128 * 1024 * 1024));
    }

    #[test]
    fn test_zip_consistency_defaults_to_enforce_and_round_trips() {
        let mut config = SecurityConfig::new();
        assert_eq!(
            config.get_zip_consistency().unwrap(),
            ZipConsistencyPolicy::Enforce
        );
        assert_eq!(
            SecurityConfig::permissive().get_zip_consistency().unwrap(),
            ZipConsistencyPolicy::Enforce
        );

        config.set_zip_consistency(ZipConsistencyPolicy::Ignore);
        assert_eq!(
            config.get_zip_consistency().unwrap(),
            ZipConsistencyPolicy::Ignore
        );
    }

    #[test]
    fn test_zip_consistency_policy_covers_every_core_variant() {
        for core in CorePolicy::ALL {
            let policy = ZipConsistencyPolicy::try_from(*core).unwrap();
            assert_eq!(CorePolicy::from(policy), *core);
        }
    }

    #[test]
    fn test_index_d_ts_policy_union_matches_core() {
        let values: Vec<_> = CorePolicy::ALL
            .iter()
            .map(|p| format!("'{}'", p.as_str()))
            .collect();
        let expected = format!("export type ZipConsistencyPolicy = {}", values.join(" | "));
        let dts = include_str!("../index.d.ts");
        assert!(
            dts.lines().any(|l| l == expected),
            "index.d.ts out of sync with exarch-core, expected line:\n{expected}"
        );
    }
}
