//! Node.js bindings for `SecurityConfig`, `ExtractionOptions` and
//! `VerificationOptions`.

use std::num::NonZeroU64;
use std::num::NonZeroUsize;

use exarch_core::ArchiveError as CoreError;
use exarch_core::CompressionLevel;
use exarch_core::ConfigProblem;
use exarch_core::ConfigSetting;
use exarch_core::DecodeReuse;
use exarch_core::DecodeReuseKind as CoreDecodeReuseKind;
use exarch_core::EntryPattern;
use exarch_core::EntrySelection;
use exarch_core::ExistingFiles as CoreExistingFiles;
use exarch_core::Extension;
use exarch_core::ExtensionFilter;
use exarch_core::Limit;
use exarch_core::ParallelDecode;
use exarch_core::PathComponentName;
use exarch_core::PathRewrite;
use exarch_core::PermissionPolicy;
use exarch_core::RatioLimit;
use exarch_core::ReuseLimit;
use exarch_core::SecurityConfig as CoreConfig;
use exarch_core::Staging as CoreStaging;
use exarch_core::StoredTargets as CoreStoredTargets;
use exarch_core::StripComponents;
use exarch_core::ZipConsistencyPolicy as CorePolicy;
use exarch_core::positive_from_f64;
use napi::Env;
use napi::bindgen_prelude::Either;
use napi::bindgen_prelude::Null;
use napi::bindgen_prelude::Result;
use napi_derive::napi;

use crate::error::IntoJsError;
use crate::mirror::mirror_from_closed_core;
use crate::mirror::mirror_from_core;
use crate::mirror::mirror_into_core;
use crate::report::MAX_SAFE_INTEGER;
use crate::report::saturating_i64;
use crate::report::saturating_u32;

/// Parses a JavaScript byte count: a negative, fractional, non-finite or
/// out-of-range value and zero are refusals naming `setting`.
fn byte_count(setting: ConfigSetting, size: f64) -> std::result::Result<NonZeroU64, CoreError> {
    positive_from_f64(setting, size)
}

/// [`byte_count`] as a bounded limit.
fn byte_limit(
    setting: ConfigSetting,
    size: f64,
) -> std::result::Result<Limit<NonZeroU64>, CoreError> {
    byte_count(setting, size).map(Limit::Bounded)
}

/// Parses a JavaScript count the way [`byte_count`] does, for a `usize` field.
fn count_value(setting: ConfigSetting, count: f64) -> std::result::Result<NonZeroUsize, CoreError> {
    let count = positive_from_f64(setting, count)?;
    NonZeroUsize::try_from(count).map_err(|_| CoreError::InvalidConfiguration {
        setting,
        problem: ConfigProblem::TooLarge {
            max: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
        },
    })
}

/// A byte limit as the JavaScript number it is held in, `None` when unbounded.
fn bounded_bytes(limit: Limit<NonZeroU64>) -> Option<i64> {
    match limit {
        Limit::Bounded(bytes) => Some(saturating_i64(bytes.get())),
        Limit::Unbounded => None,
    }
}

/// A count as the JavaScript number it is held in, clamped to the largest
/// integer a number holds exactly (2^53 - 1).
#[expect(
    clippy::cast_precision_loss,
    reason = "the value is clamped to 2^53 - 1, which an f64 holds exactly"
)]
fn exact_f64(value: usize) -> f64 {
    u64::try_from(value)
        .unwrap_or(u64::MAX)
        .min(MAX_SAFE_INTEGER) as f64
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

mirror_into_core!(
    ZipConsistencyPolicy => CorePolicy,
    [Enforce, Ignore]
);

mirror_from_core!(
    ZipConsistencyPolicy,
    CorePolicy,
    "ZIP consistency policy",
    [Enforce, Ignore]
);

/// What extraction does when a destination path is already occupied.
///
/// `skip` (the default) keeps the occupant and counts a skip. `overwrite`
/// replaces an occupant where the kinds allow it. `refuse` fails with
/// `OUTPUT_EXISTS` instead of touching anything the run did not create.
// Values must equal `exarch_core::ExistingFiles::as_str`.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExistingFiles {
    /// Keep the occupant and count a skip.
    #[napi(value = "skip")]
    Skip,
    /// Replace the occupant where the kinds allow it.
    #[napi(value = "overwrite")]
    Overwrite,
    /// Fail on any occupant the run did not create.
    #[napi(value = "refuse")]
    Refuse,
}

mirror_into_core!(
    ExistingFiles => CoreExistingFiles,
    [Skip, Overwrite, Refuse]
);

mirror_from_core!(
    ExistingFiles,
    CoreExistingFiles,
    "existing-files policy",
    [Skip, Overwrite, Refuse]
);

/// Where a ZIP extraction into a sink keeps decoded output between the
/// structural check and the write, so a deflate entry is decoded once.
///
/// `off` (the default for sinks) keeps nothing. `memory` keeps decoded entries
/// in memory. `temp_file` keeps them in an unnamed temporary file that holds
/// the archive's plaintext until the extraction ends.
// Values must equal `exarch_core::DecodeReuseKind::as_str`.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeReuseKind {
    /// Keep nothing; every entry is decoded twice.
    #[napi(value = "off")]
    Off,
    /// Keep decoded entries in memory.
    #[napi(value = "memory")]
    Memory,
    /// Keep decoded entries in a temporary file.
    #[napi(value = "temp_file")]
    TempFile,
}

mirror_into_core!(
    DecodeReuseKind => CoreDecodeReuseKind,
    [Off, Memory, TempFile]
);

mirror_from_closed_core!(
    CoreDecodeReuseKind => DecodeReuseKind,
    [Off, Memory, TempFile]
);

/// How extraction stages its output before it is visible at the destination.
///
/// `in_place` (the default) writes directly into the destination. `atomic`
/// extracts into a sibling directory and renames it onto a destination that
/// does not exist or is empty. `atomic_replace` does the same and swaps the
/// staged tree over an existing destination directory, replacing it as a whole.
// Values must equal `exarch_core::Staging::as_str`.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Staging {
    /// Write directly into the destination.
    #[napi(value = "in_place")]
    InPlace,
    /// Stage in a sibling directory and rename it onto an empty destination.
    #[napi(value = "atomic")]
    Atomic,
    /// Stage in a sibling directory and swap it over an existing destination.
    #[napi(value = "atomic_replace")]
    AtomicReplace,
}

mirror_into_core!(
    Staging => CoreStaging,
    [InPlace, Atomic, AtomicReplace]
);

mirror_from_core!(
    Staging,
    CoreStaging,
    "staging mode",
    [InPlace, Atomic, AtomicReplace]
);

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
/// | `allowed_extensions` | `null` (all allowed) |
/// | `banned_path_components` | `.git`, `.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`, `.env` |
/// | `include` / `exclude` | none (every entry is selected) |
/// | `stripComponents` / `flatten` | off (every path is kept) |
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
    /// not a positive whole number up to 2^53 - 1 (zero, negative, fractional,
    /// `NaN` and infinite values are refused, never wrapped).
    #[napi(js_name = "withMaxFileSize")]
    pub fn with_max_file_size(&mut self, env: Env, size: f64) -> Result<&Self> {
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
    #[napi(js_name = "withMaxTotalSize")]
    pub fn with_max_total_size(&mut self, env: Env, size: f64) -> Result<&Self> {
        self.try_set_max_total_size(size)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Sets the maximum compression ratio.
    ///
    /// Solid 7z blocks are exempt: each block is checked as a whole against a
    /// limit of `withMaxSolidCompressionRatio` (default 1000).
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is `max_compression_ratio`) if
    /// ratio is not a positive finite number.
    #[napi(js_name = "withMaxCompressionRatio")]
    pub fn with_max_compression_ratio(&mut self, env: Env, ratio: f64) -> Result<&Self> {
        self.try_set_max_compression_ratio(ratio)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Sets the maximum file count.
    ///
    /// Every entry counts in every operation and format: files, directories,
    /// links and skipped entries.
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is `max_file_count`) if count
    /// is not a positive whole number up to 2^53 - 1.
    #[napi(js_name = "withMaxFileCount")]
    pub fn with_max_file_count(&mut self, env: Env, count: f64) -> Result<&Self> {
        self.try_set_max_file_count(count)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Sets the maximum path depth.
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is `max_path_depth`) if depth
    /// is not a positive whole number up to 2^53 - 1.
    #[napi(js_name = "withMaxPathDepth")]
    pub fn with_max_path_depth(&mut self, env: Env, depth: f64) -> Result<&Self> {
        self.try_set_max_path_depth(depth)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Allows or denies symlinks.
    #[napi(js_name = "withAllowSymlinks")]
    pub fn with_allow_symlinks(&mut self, allow: bool) -> &Self {
        self.inner.allowed.symlinks = exarch_core::Admit::from_allowed(allow);
        self
    }

    /// Allows or denies hardlinks.
    #[napi(js_name = "withAllowHardlinks")]
    pub fn with_allow_hardlinks(&mut self, allow: bool) -> &Self {
        self.inner.allowed.hardlinks = exarch_core::Admit::from_allowed(allow);
        self
    }

    /// Allows or denies absolute paths.
    #[napi(js_name = "withAllowAbsolutePaths")]
    pub fn with_allow_absolute_paths(&mut self, allow: bool) -> &Self {
        self.inner.allowed.absolute_paths = exarch_core::Admit::from_allowed(allow);
        self
    }

    /// Allows or denies world-writable files.
    #[napi(js_name = "withAllowWorldWritable")]
    pub fn with_allow_world_writable(&mut self, allow: bool) -> &Self {
        self.inner.allowed.world_writable = exarch_core::Admit::from_allowed(allow);
        self
    }

    /// Allows or denies solid 7z archives.
    ///
    /// Solid archives require reading all preceding entries to decompress any
    /// entry, which may allow a crafted archive to consume excessive
    /// memory. Disabled by default.
    #[napi(js_name = "withAllowSolidArchives")]
    pub fn with_allow_solid_archives(&mut self, allow: bool) -> &Self {
        self.inner.solid_archives = self.inner.solid_archives.with_allowed(allow);
        self
    }

    /// Allows or denies Windows reserved device names (`CON`, `NUL`, `COM1`,
    /// ...) as path components.
    ///
    /// On-disk extraction checks these names only on Windows; in-memory and
    /// callback extraction (the portable path model) check them on every host.
    /// Denied by default.
    #[napi(js_name = "withAllowWindowsReservedNames")]
    pub fn with_allow_windows_reserved_names(&mut self, allow: bool) -> &Self {
        self.inner.allowed.windows_reserved_names = exarch_core::Admit::from_allowed(allow);
        self
    }

    /// Sets the budget in bytes for TAR metadata and for the decoded bytes
    /// that follow the end-of-archive marker of a compressed TAR.
    ///
    /// Default: 4 MiB.
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is `max_tar_metadata_bytes`)
    /// if `size` is not a positive whole number of bytes.
    #[napi(js_name = "withMaxTarMetadataBytes")]
    pub fn with_max_tar_metadata_bytes(&mut self, env: Env, size: f64) -> Result<&Self> {
        self.try_set_max_tar_metadata_bytes(size)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Sets the memory in bytes a decoder may use for its dictionary or
    /// window.
    ///
    /// Default: 256 MiB.
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is `max_decoder_memory`) if
    /// `size` is not a positive whole number of bytes.
    #[napi(js_name = "withMaxDecoderMemory")]
    pub fn with_max_decoder_memory(&mut self, env: Env, size: f64) -> Result<&Self> {
        self.try_set_max_decoder_memory(size)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Sets the base number of gzip members or bzip2 streams a compressed TAR
    /// may hold; every 16 KiB of decoded output adds one more.
    ///
    /// Default: 10,000.
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is
    /// `compressed_member_allowance`) if `count` is not a positive whole
    /// number.
    #[napi(js_name = "withCompressedMemberAllowance")]
    pub fn with_compressed_member_allowance(&mut self, env: Env, count: f64) -> Result<&Self> {
        self.try_set_compressed_member_allowance(count)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Sets the compression ratio limit of a solid 7z block.
    ///
    /// It exists only while solid archives are allowed, so call
    /// `withAllowSolidArchives(true)` first.
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is
    /// `max_solid_compression_ratio`) if `ratio` is not a positive finite
    /// number, or while solid archives are not allowed.
    #[napi(js_name = "withMaxSolidCompressionRatio")]
    pub fn with_max_solid_compression_ratio(&mut self, env: Env, ratio: f64) -> Result<&Self> {
        self.try_set_max_solid_compression_ratio(ratio)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Sets how ZIP archives with ambiguous structure are handled.
    #[napi(js_name = "withZipConsistency")]
    pub fn with_zip_consistency(&mut self, policy: ZipConsistencyPolicy) -> &Self {
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
    /// Throws `INVALID_CONFIGURATION` (`setting` is `parallel_decode_memory`)
    /// if `size` is not a positive whole number of bytes.
    #[napi(js_name = "withParallelDecodeMemory")]
    pub fn with_parallel_decode_memory(&mut self, env: Env, size: Option<f64>) -> Result<&Self> {
        self.try_set_parallel_decode_memory(size)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Sets the maximum decoded size of a solid 7z block, in bytes.
    ///
    /// The limit bounds the decoded volume of each solid block, not resident
    /// memory. It exists only while solid archives are allowed, so call
    /// `withAllowSolidArchives(true)` first. Default: 512 MB.
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is `max_solid_block_memory`)
    /// if size is negative or zero, or while solid archives are not allowed.
    #[napi(js_name = "withMaxSolidBlockMemory")]
    pub fn with_max_solid_block_memory(&mut self, env: Env, size: f64) -> Result<&Self> {
        self.try_set_max_solid_block_memory(size)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Sets whether to preserve permissions from archive.
    #[napi(js_name = "withPreservePermissions")]
    pub fn with_preserve_permissions(&mut self, preserve: bool) -> &Self {
        self.inner.permissions = PermissionPolicy::from_preserve(preserve);
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
    pub fn add_banned_component(&mut self, env: Env, component: String) -> Result<&Self> {
        self.try_add_banned_component(&component)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Replaces the allowed file extensions, or lifts the allowlist.
    ///
    /// An array restricts extraction to those extensions (a leading dot is
    /// accepted and removed, and values are lowercased); `null` allows every
    /// extension again. The list is validated as a whole: on an error the
    /// previous allowlist stays.
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is `allowed_extension`) for
    /// an empty array, which would otherwise read as "allow everything", and
    /// for any value `addAllowedExtension` refuses.
    #[napi(js_name = "withAllowedExtensions")]
    pub fn with_allowed_extensions(
        &mut self,
        env: Env,
        extensions: Either<Vec<String>, Null>,
    ) -> Result<&Self> {
        let extensions = match extensions {
            Either::A(list) => Some(list),
            Either::B(_) => None,
        };
        self.try_set_allowed_extensions(extensions.as_deref())
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Replaces the banned path components, so the defaults can be dropped.
    ///
    /// An empty array bans nothing. The list is validated as a whole: on an
    /// error the previous list stays.
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is `banned_path_component`)
    /// for any value `addBannedComponent` refuses.
    #[napi(js_name = "withBannedComponents")]
    pub fn with_banned_components(&mut self, env: Env, components: Vec<String>) -> Result<&Self> {
        self.try_set_banned_components(&components)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Adds an include pattern: only entries that match an include pattern (and
    /// no exclude pattern) are extracted, listed as extracted or verified as
    /// extracted.
    ///
    /// The syntax is that of `CreationConfig.addExcludePattern` (globs: `*`,
    /// `?`, `[a-c]`, `**`). A pattern is matched against the entry's archive
    /// path before any stripping, and is case-sensitive on every host.
    /// An include pattern that matches no entry fails the extraction after the
    /// scan with `INVALID_CONFIGURATION` (`setting` is `entry_include`) and
    /// `unmatchedPatterns`.
    ///
    /// Operations apply, in order: path validation of the original name,
    /// selection, then `stripComponents` or `flatten`, then validation of the
    /// rewritten name.
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is `entry_include`) for a
    /// pattern shape that is refused.
    #[napi(js_name = "addIncludePattern")]
    pub fn add_include_pattern(&mut self, env: Env, pattern: String) -> Result<&Self> {
        self.try_set_include_patterns(Some(std::slice::from_ref(&pattern)), SelectionEdit::Append)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Replaces the include patterns; an empty array selects every entry.
    ///
    /// The list is validated as a whole: on an error the previous patterns
    /// stay. See `addIncludePattern` for the pattern shapes.
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is `entry_include`) for a
    /// pattern shape that is refused.
    #[napi(js_name = "withIncludePatterns")]
    pub fn with_include_patterns(&mut self, env: Env, patterns: Vec<String>) -> Result<&Self> {
        self.try_set_include_patterns(Some(&patterns), SelectionEdit::Replace)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Adds an exclude pattern: an entry that matches one is never extracted,
    /// whatever the include patterns say. A pattern that matches nothing is not
    /// an error.
    ///
    /// The shapes and matching rules are those of `addIncludePattern`.
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is `entry_exclude`) for a
    /// pattern shape that is refused.
    #[napi(js_name = "addExcludePattern")]
    pub fn add_exclude_pattern(&mut self, env: Env, pattern: String) -> Result<&Self> {
        self.try_set_exclude_patterns(std::slice::from_ref(&pattern), SelectionEdit::Append)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Replaces the exclude patterns; an empty array excludes nothing.
    ///
    /// The list is validated as a whole: on an error the previous patterns
    /// stay.
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is `entry_exclude`) for a
    /// pattern shape that is refused.
    #[napi(js_name = "withExcludePatterns")]
    pub fn with_exclude_patterns(&mut self, env: Env, patterns: Vec<String>) -> Result<&Self> {
        self.try_set_exclude_patterns(&patterns, SelectionEdit::Replace)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Drops the first `count` leading path components of every extracted
    /// entry, like `tar --strip-components`; `null` removes a strip count and
    /// leaves `flatten` as it is.
    ///
    /// An entry with no component left is skipped and counted as
    /// `'stripped_away'`. Include and exclude patterns match the path before
    /// stripping. Setting a strip count replaces `flatten`, and the maximum
    /// is the current `maxPathDepth`, so set that first.
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is `strip_components`) if
    /// `count` is not a positive whole number up to 2^53 - 1 or exceeds
    /// `maxPathDepth`.
    #[napi(js_name = "withStripComponents")]
    pub fn with_strip_components(&mut self, env: Env, count: Either<f64, Null>) -> Result<&Self> {
        let count = match count {
            Either::A(count) => Some(count),
            Either::B(_) => None,
        };
        self.try_set_strip_components(count)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Lands every regular file in the destination root under its final path
    /// component; `false` keeps every path.
    ///
    /// Directory entries are skipped and counted as `'stripped_away'`; a
    /// symlink or hardlink entry is refused with `SECURITY_VIOLATION`
    /// (`subCode` is `LINK_POLICY`). Files that share a final name follow
    /// `existingFiles`. Setting `flatten` replaces a strip count, and
    /// `withStripComponents(null)` leaves `flatten` as it is.
    #[napi(js_name = "withFlatten")]
    pub fn with_flatten(&mut self, flatten: bool) -> &Self {
        self.try_set_flatten(flatten);
        self
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
    pub fn is_path_component_allowed(&self, component: String) -> bool {
        self.inner.is_path_component_allowed(&component)
    }

    /// Checks if a file extension is allowed.
    #[napi]
    pub fn is_extension_allowed(&self, extension: String) -> bool {
        self.inner.is_extension_allowed(Some(&extension))
    }

    // Property getters

    /// Maximum file size in bytes, or `null` when unbounded.
    #[napi(getter)]
    pub fn get_max_file_size(&self) -> Option<i64> {
        bounded_bytes(self.inner.max_file_size)
    }

    /// Maximum total size in bytes, or `null` when unbounded.
    #[napi(getter)]
    pub fn get_max_total_size(&self) -> Option<i64> {
        bounded_bytes(self.inner.max_total_size)
    }

    /// Maximum compression ratio.
    #[napi(getter)]
    pub fn get_max_compression_ratio(&self) -> f64 {
        self.inner.max_compression_ratio.get()
    }

    /// Maximum file count, or `null` when unbounded.
    #[napi(getter)]
    pub fn get_max_file_count(&self) -> Option<f64> {
        match self.inner.max_file_count {
            Limit::Bounded(count) => Some(exact_f64(count.get())),
            Limit::Unbounded => None,
        }
    }

    /// Maximum path depth.
    #[napi(getter)]
    pub fn get_max_path_depth(&self) -> f64 {
        exact_f64(self.inner.max_path_depth.get())
    }

    /// Whether to preserve permissions from archive.
    #[napi(getter)]
    pub fn get_preserve_permissions(&self) -> bool {
        self.inner.permissions.preserves()
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

    /// How ZIP archives with ambiguous structure are handled. A policy newer
    /// than this binding is reported as core's token.
    #[napi(getter, ts_return_type = "ZipConsistencyPolicy | (string & {})")]
    pub fn get_zip_consistency(&self) -> String {
        self.inner.zip_consistency.as_str().to_owned()
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

    /// Whether Windows reserved device names are allowed as path components.
    #[napi(getter)]
    pub fn get_allow_windows_reserved_names(&self) -> bool {
        self.inner.allowed.windows_reserved_names.is_allowed()
    }

    /// Budget in bytes for TAR metadata.
    #[napi(getter)]
    pub fn get_max_tar_metadata_bytes(&self) -> i64 {
        saturating_i64(self.inner.max_tar_metadata_bytes.get())
    }

    /// Memory in bytes a decoder may use for its dictionary or window.
    #[napi(getter)]
    pub fn get_max_decoder_memory(&self) -> i64 {
        saturating_i64(self.inner.max_decoder_memory.get())
    }

    /// Base number of gzip members or bzip2 streams a compressed TAR may
    /// hold.
    #[napi(getter)]
    pub fn get_compressed_member_allowance(&self) -> i64 {
        saturating_i64(self.inner.compressed_member_allowance.get())
    }

    /// Compression ratio limit of a solid 7z block, or `null` while solid
    /// archives are not allowed.
    #[napi(getter)]
    pub fn get_max_solid_compression_ratio(&self) -> Option<f64> {
        self.inner
            .solid_archives
            .limits()
            .map(|limits| limits.max_ratio.get())
    }

    /// List of allowed file extensions, or `null` when every extension is
    /// allowed.
    ///
    /// Note: This getter clones the underlying data. For performance-critical
    /// code that only needs to count or check membership, use
    /// `getAllowedExtensionsCount()` or `hasAllowedExtension()` instead.
    #[napi(getter)]
    pub fn get_allowed_extensions(&self) -> Option<Vec<String>> {
        self.inner.allowed_extensions.as_only().map(|extensions| {
            extensions
                .as_slice()
                .iter()
                .map(|ext| ext.as_str().to_owned())
                .collect()
        })
    }

    /// Returns the number of allowed extensions, `0` when every extension is
    /// allowed.
    #[napi]
    pub fn get_allowed_extensions_count(&self) -> u32 {
        self.inner
            .allowed_extensions
            .as_only()
            .map_or_default(|extensions| saturating_u32(extensions.as_slice().len()))
    }

    /// Checks if a specific extension is in the allowed list.
    #[napi]
    pub fn has_allowed_extension(&self, ext: String) -> bool {
        Extension::try_from(ext.as_str()).is_ok_and(|ext| {
            self.inner
                .allowed_extensions
                .as_only()
                .is_some_and(|extensions| extensions.as_slice().contains(&ext))
        })
    }

    /// The include patterns, as they were given.
    #[napi(getter)]
    pub fn get_include_patterns(&self) -> Vec<String> {
        self.inner
            .selection
            .include()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// The exclude patterns, as they were given.
    #[napi(getter)]
    pub fn get_exclude_patterns(&self) -> Vec<String> {
        self.inner
            .selection
            .exclude()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// The number of leading path components dropped, or `null` while paths
    /// are kept or flattened.
    #[napi(getter)]
    pub fn get_strip_components(&self) -> Option<f64> {
        match self.inner.selection.rewrite() {
            PathRewrite::Strip(count) => Some(exact_f64(count.get().get())),
            _ => None,
        }
    }

    /// Whether every regular file lands under its final path component.
    #[napi(getter)]
    pub fn get_flatten(&self) -> bool {
        self.inner.selection.rewrite() == PathRewrite::Flatten
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
    pub fn get_banned_path_components_count(&self) -> u32 {
        saturating_u32(self.inner.banned_path_components.len())
    }

    /// Checks if a specific component is in the banned list.
    #[napi]
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

    /// Env-free core of `withMaxFileSize`.
    fn try_set_max_file_size(&mut self, size: f64) -> std::result::Result<(), CoreError> {
        self.inner.max_file_size = byte_limit(ConfigSetting::MaxFileSize, size)?;
        Ok(())
    }

    /// Env-free core of `withMaxTotalSize`.
    fn try_set_max_total_size(&mut self, size: f64) -> std::result::Result<(), CoreError> {
        self.inner.max_total_size = byte_limit(ConfigSetting::MaxTotalSize, size)?;
        Ok(())
    }

    /// Env-free core of `withMaxCompressionRatio`.
    fn try_set_max_compression_ratio(&mut self, ratio: f64) -> std::result::Result<(), CoreError> {
        self.inner.max_compression_ratio =
            RatioLimit::parse(ConfigSetting::MaxCompressionRatio, ratio)?;
        Ok(())
    }

    /// Env-free core of `withMaxFileCount`.
    fn try_set_max_file_count(&mut self, count: f64) -> std::result::Result<(), CoreError> {
        self.inner.max_file_count =
            Limit::Bounded(count_value(ConfigSetting::MaxFileCount, count)?);
        Ok(())
    }

    /// Env-free core of `withMaxPathDepth`.
    fn try_set_max_path_depth(&mut self, depth: f64) -> std::result::Result<(), CoreError> {
        self.inner.max_path_depth = count_value(ConfigSetting::MaxPathDepth, depth)?;
        Ok(())
    }

    /// Env-free core of `withParallelDecodeMemory`.
    fn try_set_parallel_decode_memory(
        &mut self,
        size: Option<f64>,
    ) -> std::result::Result<(), CoreError> {
        let lookahead = size
            .map(|bytes| positive_from_f64(ConfigSetting::ParallelDecodeMemory, bytes))
            .transpose()?;
        self.inner.parallel_decode = ParallelDecode::from_bytes(lookahead);
        Ok(())
    }

    /// Env-free core of `withMaxSolidBlockMemory`.
    fn try_set_max_solid_block_memory(&mut self, size: f64) -> std::result::Result<(), CoreError> {
        let max_block_memory = byte_count(ConfigSetting::MaxSolidBlockMemory, size)?;
        self.inner.solid_archives = self
            .inner
            .solid_archives
            .with_max_block_memory(max_block_memory)?;
        Ok(())
    }

    /// Env-free core of `withMaxTarMetadataBytes`.
    fn try_set_max_tar_metadata_bytes(&mut self, size: f64) -> std::result::Result<(), CoreError> {
        self.inner.max_tar_metadata_bytes = byte_count(ConfigSetting::MaxTarMetadataBytes, size)?;
        Ok(())
    }

    /// Env-free core of `withMaxDecoderMemory`.
    fn try_set_max_decoder_memory(&mut self, size: f64) -> std::result::Result<(), CoreError> {
        self.inner.max_decoder_memory = byte_count(ConfigSetting::MaxDecoderMemory, size)?;
        Ok(())
    }

    /// Env-free core of `withCompressedMemberAllowance`.
    fn try_set_compressed_member_allowance(
        &mut self,
        count: f64,
    ) -> std::result::Result<(), CoreError> {
        self.inner.compressed_member_allowance =
            byte_count(ConfigSetting::CompressedMemberAllowance, count)?;
        Ok(())
    }

    /// Env-free core of `withMaxSolidCompressionRatio`.
    fn try_set_max_solid_compression_ratio(
        &mut self,
        ratio: f64,
    ) -> std::result::Result<(), CoreError> {
        let ratio = RatioLimit::parse(ConfigSetting::MaxSolidCompressionRatio, ratio)?;
        self.inner.solid_archives = self.inner.solid_archives.with_max_ratio(ratio)?;
        Ok(())
    }

    /// Env-free core of `addAllowedExtension`, so the validation is testable
    /// without a JS environment.
    fn try_add_allowed_extension(&mut self, ext: &str) -> std::result::Result<(), CoreError> {
        let ext = Extension::try_from(ext)?;
        self.inner.allowed_extensions =
            std::mem::take(&mut self.inner.allowed_extensions).with_added(ext);
        Ok(())
    }

    /// Env-free core of `addBannedComponent`.
    fn try_add_banned_component(&mut self, component: &str) -> std::result::Result<(), CoreError> {
        let component = PathComponentName::try_from(component)?;
        self.inner.banned_path_components.push(component);
        Ok(())
    }

    /// Env-free core of `withAllowedExtensions`; `None` lifts the allowlist.
    fn try_set_allowed_extensions(
        &mut self,
        extensions: Option<&[String]>,
    ) -> std::result::Result<(), CoreError> {
        self.inner.allowed_extensions = match extensions {
            None => ExtensionFilter::Any,
            Some(raw) => ExtensionFilter::only(
                raw.iter()
                    .map(|ext| Extension::try_from(ext.as_str()))
                    .collect::<std::result::Result<_, _>>()?,
            )?,
        };
        Ok(())
    }

    /// Env-free core of `withBannedComponents`.
    fn try_set_banned_components(
        &mut self,
        components: &[String],
    ) -> std::result::Result<(), CoreError> {
        self.inner.banned_path_components = components
            .iter()
            .map(|component| PathComponentName::try_from(component.as_str()))
            .collect::<std::result::Result<_, _>>()?;
        Ok(())
    }

    /// Env-free core of `addIncludePattern` and `withIncludePatterns`.
    fn try_set_include_patterns(
        &mut self,
        patterns: Option<&[String]>,
        edit: SelectionEdit,
    ) -> std::result::Result<(), CoreError> {
        let parsed = parse_patterns(ConfigSetting::EntryInclude, patterns.unwrap_or_default())?;
        let selection = std::mem::take(&mut self.inner.selection);
        self.inner.selection = match edit {
            SelectionEdit::Append => parsed
                .into_iter()
                .fold(selection, EntrySelection::with_include),
            SelectionEdit::Replace => selection.with_include_list(parsed),
        };
        Ok(())
    }

    /// Env-free core of `addExcludePattern` and `withExcludePatterns`.
    fn try_set_exclude_patterns(
        &mut self,
        patterns: &[String],
        edit: SelectionEdit,
    ) -> std::result::Result<(), CoreError> {
        let parsed = parse_patterns(ConfigSetting::EntryExclude, patterns)?;
        let selection = std::mem::take(&mut self.inner.selection);
        self.inner.selection = match edit {
            SelectionEdit::Append => parsed
                .into_iter()
                .fold(selection, EntrySelection::with_exclude),
            SelectionEdit::Replace => selection.with_exclude_list(parsed),
        };
        Ok(())
    }

    /// Env-free core of `withStripComponents`; `None` drops a strip count and
    /// leaves `flatten` as it is.
    fn try_set_strip_components(
        &mut self,
        count: Option<f64>,
    ) -> std::result::Result<(), CoreError> {
        let strip = count
            .map(|count| {
                let count = positive_from_f64(ConfigSetting::StripComponents, count)?;
                StripComponents::new(count, self.inner.max_path_depth)
            })
            .transpose()?;
        self.inner.selection = std::mem::take(&mut self.inner.selection).with_strip(strip);
        Ok(())
    }

    /// Env-free core of `withFlatten`.
    fn try_set_flatten(&mut self, flatten: bool) {
        self.inner.selection = std::mem::take(&mut self.inner.selection).with_flatten(flatten);
    }
}

/// Whether a pattern list edit adds to the current patterns or replaces them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectionEdit {
    Append,
    Replace,
}

/// Parses every pattern before any is kept, so one refusal changes nothing.
fn parse_patterns(
    setting: ConfigSetting,
    patterns: &[String],
) -> std::result::Result<Vec<EntryPattern>, CoreError> {
    patterns
        .iter()
        .map(|pattern| EntryPattern::parse_for(setting, pattern))
        .collect()
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
/// | `compression_level` | exarch-core's default level (`compressionLevel` reports it) |
/// | `preserve_permissions` | true |
/// | `follow_symlinks` | false (secure) |
/// | `include_hidden` | false |
/// | `max_file_size` | `null` (no limit) |
/// | `exclude_patterns` | `[".git", ".DS_Store", "*.tmp"]` |
#[napi]
#[derive(Debug, Clone)]
pub struct CreationConfig {
    inner: exarch_core::CreationConfig,
}

#[napi]
impl CreationConfig {
    /// Creates a new `CreationConfig` with secure defaults.
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: exarch_core::CreationConfig::default(),
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
    /// Throws `INVALID_COMPRESSION_LEVEL` if level is not a whole number from 1
    /// to 9 (a fraction, `NaN`, a negative or an out-of-range number is
    /// refused, never wrapped).
    #[napi(js_name = "withCompressionLevel")]
    pub fn with_compression_level(&mut self, env: Env, level: f64) -> Result<&Self> {
        self.try_set_compression_level(level)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Sets whether to preserve file permissions from source.
    ///
    /// Default: true.
    #[napi(js_name = "withPreservePermissions")]
    pub fn with_preserve_permissions(&mut self, preserve: bool) -> &Self {
        self.inner.permissions = PermissionPolicy::from_preserve(preserve);
        self
    }

    /// Sets whether to follow symlinks when adding files.
    ///
    /// Default: false (store symlinks as symlinks).
    ///
    /// Security note: Following symlinks may include unintended files
    /// from outside the source directory.
    #[napi(js_name = "withFollowSymlinks")]
    pub fn with_follow_symlinks(&mut self, follow: bool) -> &Self {
        self.inner.follow_symlinks = follow;
        self
    }

    /// Sets whether to include hidden files (files starting with '.').
    ///
    /// Default: false.
    #[napi(js_name = "withIncludeHidden")]
    pub fn with_include_hidden(&mut self, include: bool) -> &Self {
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
    #[napi(js_name = "withMaxFileSize")]
    pub fn with_max_file_size(&mut self, env: Env, size: Either<f64, Null>) -> Result<&Self> {
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
    /// Files matching this pattern will be skipped. Patterns are globs: `*` and
    /// `?` match within one path component (`?` is exactly one byte), `[a-c]`
    /// is a positive ASCII class, `**` as a whole component spans directories.
    /// A name without `/` matches any path component, and so its subtree; a
    /// pattern with a `/` anywhere (a trailing one included) matches from the
    /// archive root and its subtree. A pattern matches the entry's archive
    /// path, never the ancestors of a source directory, so write `build`, not
    /// `src/build`, for a source `src`.
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is `exclude_pattern`) for any
    /// unsupported syntax instead of silently excluding nothing: an empty
    /// pattern, one with a null byte, leading or trailing whitespace, a comma,
    /// a leading `!`, `{` or `}`, `**` glued to other characters, a negated,
    /// POSIX or non-ASCII class, an unterminated class, a class range outside
    /// `0-9`, `a-z` and `A-Z`, `.` or `..` as a component, an absolute path or
    /// one over 255 bytes.
    #[napi]
    pub fn add_exclude_pattern(&mut self, env: Env, pattern: String) -> Result<&Self> {
        self.try_add_exclude_pattern(&pattern)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Replaces the exclude patterns, so the defaults can be dropped.
    ///
    /// An empty array excludes nothing. The list is validated as a whole: on
    /// an error the previous patterns stay.
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is `exclude_pattern`) for any
    /// pattern `addExcludePattern` refuses.
    #[napi(js_name = "withExcludePatterns")]
    pub fn with_exclude_patterns(&mut self, env: Env, patterns: Vec<String>) -> Result<&Self> {
        self.try_set_exclude_patterns(&patterns)
            .map_err(|err| err.into_js_error(env))?;
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
        self.inner.permissions.preserves()
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
        self.inner
            .exclude_patterns
            .iter()
            .map(ToString::to_string)
            .collect()
    }
}

impl CreationConfig {
    /// Env-free core of `addExcludePattern`.
    fn try_add_exclude_pattern(&mut self, pattern: &str) -> std::result::Result<(), CoreError> {
        let pattern = exarch_core::EntryPattern::try_from(pattern)?;
        self.inner.exclude_patterns.push(pattern);
        Ok(())
    }

    /// Env-free core of `withExcludePatterns`.
    fn try_set_exclude_patterns(
        &mut self,
        patterns: &[String],
    ) -> std::result::Result<(), CoreError> {
        self.inner.exclude_patterns = patterns
            .iter()
            .map(|pattern| exarch_core::EntryPattern::try_from(pattern.as_str()))
            .collect::<std::result::Result<_, _>>()?;
        Ok(())
    }

    /// Env-free core of `withMaxFileSize`; `None` removes the limit.
    fn try_set_max_file_size(&mut self, size: Option<f64>) -> std::result::Result<(), CoreError> {
        self.inner.max_file_size = match size {
            Some(bytes) => byte_limit(ConfigSetting::MaxFileSize, bytes)?,
            None => Limit::Unbounded,
        };
        Ok(())
    }

    /// Env-free core of `withCompressionLevel`, so the validation is testable
    /// without a JS environment.
    fn try_set_compression_level(&mut self, level: f64) -> std::result::Result<(), CoreError> {
        self.inner.compression_level = CompressionLevel::from_f64(level)?;
        Ok(())
    }

    /// Returns a reference to the inner `CoreCreationConfig`.
    pub fn as_core(&self) -> &exarch_core::CreationConfig {
        &self.inner
    }
}

/// Options controlling extraction behavior (non-security).
///
/// Separate from `SecurityConfig` to keep security settings focused.
/// These options control operational behavior such as occupied-path handling.
///
/// # Defaults
///
/// | Setting | Default Value |
/// |---------|--------------|
/// | `existingFiles` | `'skip'` |
/// | `staging` | `'in_place'` |
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

    /// Sets what happens when a destination path is already occupied.
    ///
    /// `'skip'` (default) keeps the occupant and counts a skip, which also
    /// covers a duplicate entry inside the archive. `'overwrite'` replaces the
    /// occupant where the kinds allow it. `'refuse'` fails with
    /// `OUTPUT_EXISTS` and never overwrites.
    #[napi(js_name = "withExistingFiles")]
    pub fn with_existing_files(&mut self, policy: ExistingFiles) -> &Self {
        self.inner.existing_files = policy.into();
        self
    }

    /// Sets how extraction stages its output: `'in_place'` (default),
    /// `'atomic'` or `'atomic_replace'`.
    ///
    /// `'atomic'` extracts into a temporary sibling directory and renames it
    /// onto the output directory on completion; on failure the temporary
    /// directory is removed and the output directory is untouched. It needs an
    /// output directory that does not exist or is empty: one that holds
    /// content fails with `OUTPUT_EXISTS` before anything is extracted.
    ///
    /// `'atomic_replace'` also replaces an existing output directory as a
    /// whole: the original is moved aside only after the extraction succeeded
    /// and is restored if the swap fails. A destination that is a filesystem
    /// root, the archive or a directory that contains it, or the working
    /// directory or one that contains it, is refused with
    /// `INVALID_CONFIGURATION` (`setting` is `output_path`, `protectedPath`
    /// names the reason).
    ///
    /// The staging directory is private (`0700`) while the archive extracts. On
    /// Unix the published root then takes the mode of the destination it
    /// replaces (or fills), never setuid; with `'atomic_replace'` also its
    /// owner as far as the caller may, and with `'atomic'` never the uid and
    /// the group only when the caller owns the destination. On Windows the
    /// staging directory inherits the ACL of the destination's parent, and
    /// `'atomic'` onto an existing empty directory fails with `OUTPUT_EXISTS`.
    #[napi(js_name = "withStaging")]
    pub fn with_staging(&mut self, staging: Staging) -> &Self {
        self.inner.staging = staging.into();
        self
    }

    /// Finalizes the configuration (for API consistency).
    #[napi]
    pub fn build(&self) -> &Self {
        self
    }

    /// What happens when a destination path is already occupied. A policy
    /// newer than this binding is reported as core's token.
    #[napi(getter, ts_return_type = "ExistingFiles | (string & {})")]
    pub fn get_existing_files(&self) -> String {
        self.inner.existing_files.as_str().to_owned()
    }

    /// How extraction stages its output. A mode newer than this binding is
    /// reported as core's token.
    #[napi(getter, ts_return_type = "Staging | (string & {})")]
    pub fn get_staging(&self) -> String {
        self.inner.staging.as_str().to_owned()
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

/// Options for extraction into memory or into a callback.
///
/// A sink has no directory to rename, so unlike `ExtractionOptions` there is
/// no `staging` setting: only the existing-files policy carries over.
///
/// # Defaults
///
/// | Setting | Default Value |
/// |---------|--------------|
/// | `existingFiles` | `'skip'` |
#[napi]
#[derive(Debug, Clone)]
pub struct SinkOptions {
    inner: exarch_core::SinkOptions,
}

#[napi]
impl SinkOptions {
    /// Creates a new `SinkOptions` with defaults.
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: exarch_core::SinkOptions::default(),
        }
    }

    /// Sets what happens when a delivery path is already occupied.
    ///
    /// `'skip'` (default) skips and counts a duplicate entry. `'overwrite'`
    /// delivers it again. `'refuse'` fails with `OUTPUT_EXISTS`.
    #[napi(js_name = "withExistingFiles")]
    pub fn with_existing_files(&mut self, policy: ExistingFiles) -> &Self {
        self.inner = self.inner.with_existing_files(policy.into());
        self
    }

    /// What happens when a delivery path is already occupied. A policy newer
    /// than this binding is reported as core's token.
    #[napi(getter, ts_return_type = "ExistingFiles | (string & {})")]
    pub fn get_existing_files(&self) -> String {
        self.inner.existing_files.as_str().to_owned()
    }

    /// Sets where a ZIP extraction keeps decoded output so a deflate entry is
    /// decoded once: `'off'` (default), `'memory'` or `'temp_file'`.
    ///
    /// `limit` is the most bytes kept, at most 256 MiB (default 32 MiB); it
    /// needs `'memory'` or `'temp_file'`.
    ///
    /// # Errors
    ///
    /// Throws `INVALID_CONFIGURATION` (`setting` is `decode_reuse_limit`) if
    /// `limit` is not a positive whole number up to 2^53 - 1, or is given with
    /// `'off'`.
    #[napi(js_name = "withDecodeReuse")]
    pub fn with_decode_reuse(
        &mut self,
        env: Env,
        mode: DecodeReuseKind,
        limit: Option<f64>,
    ) -> Result<&Self> {
        self.try_set_decode_reuse(mode, limit)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Where a ZIP extraction keeps decoded output.
    #[napi(getter)]
    pub fn get_decode_reuse(&self) -> DecodeReuseKind {
        self.inner.decode_reuse.kind().into()
    }

    /// The most bytes kept for reuse, or `null` while decode reuse is `'off'`.
    #[napi(getter)]
    pub fn get_decode_reuse_limit(&self) -> Option<i64> {
        self.inner
            .decode_reuse
            .limit()
            .map(|limit| saturating_i64(limit.get()))
    }
}

impl SinkOptions {
    /// Env-free core of `withDecodeReuse`.
    fn try_set_decode_reuse(
        &mut self,
        mode: DecodeReuseKind,
        limit: Option<f64>,
    ) -> std::result::Result<(), CoreError> {
        let limit = limit
            .map(|bytes| {
                positive_from_f64(ConfigSetting::DecodeReuseLimit, bytes).map(ReuseLimit::new)
            })
            .transpose()?;
        self.inner.decode_reuse = DecodeReuse::from_parts(mode.into(), limit)?;
        Ok(())
    }

    /// Returns the inner `CoreSinkOptions`.
    pub fn to_core(&self) -> exarch_core::SinkOptions {
        self.inner
    }
}

/// Whether listing reads the symlink targets a 7z archive keeps in compressed
/// entry data.
///
/// Reading them decodes part of the archive, which in a solid block can be
/// most of it, so `'skip'` is the default and reports such a target as
/// `'unread'`. Other formats always report their targets.
// Values must equal the core `StoredTargets` variants, lower-cased.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredTargets {
    /// Leave 7z link targets unread (the default).
    #[napi(value = "skip")]
    Skip,
    /// Read the targets, decoding the blocks that hold them.
    #[napi(value = "read")]
    Read,
}

mirror_into_core!(StoredTargets => CoreStoredTargets, [Skip, Read]);

mirror_from_core!(
    StoredTargets,
    CoreStoredTargets,
    "stored-targets policy",
    [Skip, Read]
);

/// Options controlling listing behavior (non-security).
///
/// # Defaults
///
/// | Setting | Default Value |
/// |---------|--------------|
/// | `storedTargets` | `'skip'` |
#[napi]
#[derive(Debug, Clone)]
pub struct ListOptions {
    inner: exarch_core::ListOptions,
}

#[napi]
impl ListOptions {
    /// Creates a new `ListOptions` with defaults (7z link targets unread).
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: exarch_core::ListOptions::default(),
        }
    }

    /// Creates a `ListOptions` with defaults.
    ///
    /// This is equivalent to calling `new ListOptions()`.
    #[napi(factory)]
    pub fn default() -> Self {
        Self::new()
    }

    /// Sets whether the link targets a 7z archive keeps in entry data are
    /// read.
    #[napi(js_name = "withStoredTargets")]
    pub fn with_stored_targets(&mut self, targets: StoredTargets) -> &Self {
        self.inner = self.inner.with_stored_targets(targets.into());
        self
    }

    /// Whether 7z link targets are read. A policy newer than this binding is
    /// reported as core's token.
    #[napi(getter, ts_return_type = "StoredTargets | (string & {})")]
    pub fn get_stored_targets(&self) -> String {
        self.inner.stored_targets.as_str().to_owned()
    }
}

impl ListOptions {
    /// The inner core options.
    pub const fn to_core(&self) -> exarch_core::ListOptions {
        self.inner
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
    pub fn with_integrity_check(&mut self, env: Env, budget: Option<f64>) -> Result<&Self> {
        self.try_with_integrity_check(budget)
            .map_err(|err| err.into_js_error(env))?;
        Ok(self)
    }

    /// Whether the payload integrity check is enabled.
    #[napi(getter)]
    pub fn get_integrity_check(&self) -> bool {
        self.inner.integrity.budget().is_some()
    }

    /// Budget in bytes when the integrity check is enabled.
    #[napi(getter)]
    pub fn get_decompression_budget(&self) -> Option<i64> {
        self.inner
            .integrity
            .budget()
            .map(|budget| saturating_i64(budget.get()))
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
        budget: Option<f64>,
    ) -> std::result::Result<(), CoreError> {
        let budget = match budget {
            Some(bytes) => exarch_core::DecompressionBudget::try_from_bytes(
                positive_from_f64(ConfigSetting::DecompressionBudget, bytes)?.get(),
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

    /// Largest integer a JavaScript number holds exactly.
    const MAX_SAFE: f64 = 9_007_199_254_740_991.0;
    const MAX_SAFE_INT: i64 = 9_007_199_254_740_991;

    #[test]
    fn documented_numbers_follow_core_constants() {
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
        let config = SecurityConfig::new();
        assert_eq!(config.get_max_file_size(), Some(50 * 1024 * 1024));
        assert_eq!(config.get_max_total_size(), Some(500 * 1024 * 1024));
        assert_eq!(config.get_max_file_count(), Some(10_000.0));
        assert!(!config.get_preserve_permissions());
    }

    #[test]
    fn test_size_getters_clamp_values_above_max_safe_integer() {
        let mut config = SecurityConfig::new();
        config.inner.max_file_size = exarch_core::Limit::Unbounded;
        config.inner.max_total_size = exarch_core::Limit::Unbounded;
        config.inner.solid_archives = exarch_core::SolidArchives::Allow(
            exarch_core::SolidLimits::DEFAULT.with_max_block_memory(NonZeroU64::MAX),
        );
        assert_eq!(config.get_max_file_size(), None);
        assert_eq!(config.get_max_total_size(), None);
        assert_eq!(config.get_max_solid_block_memory(), Some(MAX_SAFE_INT));

        let mut creation = CreationConfig::new();
        creation.inner.max_file_size = exarch_core::Limit::Bounded(NonZeroU64::MAX);
        assert_eq!(creation.get_max_file_size(), Some(MAX_SAFE_INT));
    }

    #[test]
    fn test_default_static_method() {
        let config = SecurityConfig::default();
        assert_eq!(config.get_max_file_size(), Some(50 * 1024 * 1024));
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
        config.try_set_max_file_size(100_000_000.0).unwrap();
        config.try_set_max_total_size(1_000_000_000.0).unwrap();
        config.try_set_max_file_count(50_000.0).unwrap();

        assert_eq!(config.get_max_file_size(), Some(100_000_000));
        assert_eq!(config.get_max_total_size(), Some(1_000_000_000));
        assert_eq!(config.get_max_file_count(), Some(50_000.0));
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
        assert_eq!(
            config.get_allowed_extensions(),
            Some(vec!["txt".to_owned()])
        );
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
        let result = config.try_set_max_file_size(-1.0);
        assert!(result.is_err(), "negative file size should be rejected");
        assert!(
            result.unwrap_err().to_string().contains("negative"),
            "error should mention negative value"
        );
    }

    #[test]
    fn test_max_file_size_i64_max() {
        let mut config = SecurityConfig::new();
        let result = config.try_set_max_file_size(MAX_SAFE);
        assert!(result.is_ok(), "2^53 - 1 should be accepted");
        assert_eq!(
            config.get_max_file_size(),
            Some(MAX_SAFE_INT),
            "value should be stored correctly"
        );
    }

    #[test]
    fn test_max_total_size_negative_value() {
        let mut config = SecurityConfig::new();
        let result = config.try_set_max_total_size(-1.0);
        assert!(result.is_err(), "negative total size should be rejected");
        assert!(
            result.unwrap_err().to_string().contains("negative"),
            "error should mention negative value"
        );
    }

    #[test]
    fn test_max_total_size_i64_max() {
        let mut config = SecurityConfig::new();
        let result = config.try_set_max_total_size(MAX_SAFE);
        assert!(result.is_ok(), "2^53 - 1 should be accepted");
        assert_eq!(
            config.get_max_total_size(),
            Some(MAX_SAFE_INT),
            "value should be stored correctly"
        );
    }

    #[test]
    fn test_max_file_count_u32_max() {
        let mut config = SecurityConfig::new();
        config.try_set_max_file_count(f64::from(u32::MAX)).unwrap();
        assert_eq!(
            config.get_max_file_count(),
            Some(f64::from(u32::MAX)),
            "u32::MAX should be accepted"
        );
    }

    #[test]
    fn test_max_path_depth_u32_max() {
        let mut config = SecurityConfig::new();
        config.try_set_max_path_depth(f64::from(u32::MAX)).unwrap();
        assert_eq!(
            config.get_max_path_depth(),
            f64::from(u32::MAX),
            "u32::MAX should be accepted"
        );
    }

    #[test]
    fn test_max_file_size_zero() {
        let mut config = SecurityConfig::new();
        let err = config.try_set_max_file_size(0.0).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid configuration: max_file_size must not be zero"
        );
        assert_eq!(config.get_max_file_size(), Some(50 * 1024 * 1024));
    }

    // Property getter tests
    #[test]
    fn test_property_getters_return_correct_values() {
        let mut config = SecurityConfig::new();
        config.try_set_max_file_size(100_000_000.0).unwrap();
        config.try_set_max_total_size(1_000_000_000.0).unwrap();
        config.try_set_max_compression_ratio(250.0).unwrap();
        config.try_set_max_file_count(50_000.0).unwrap();
        config.try_set_max_path_depth(64.0).unwrap();
        config.with_preserve_permissions(true);

        assert_eq!(
            config.get_max_file_size(),
            Some(100_000_000),
            "max_file_size getter should return set value"
        );
        assert_eq!(
            config.get_max_total_size(),
            Some(1_000_000_000),
            "max_total_size getter should return set value"
        );
        assert_eq!(
            config.get_max_compression_ratio(),
            250.0,
            "max_compression_ratio getter should return set value"
        );
        assert_eq!(
            config.get_max_file_count(),
            Some(50_000.0),
            "max_file_count getter should return set value"
        );
        assert_eq!(
            config.get_max_path_depth(),
            64.0,
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
        config.with_allow_solid_archives(true);
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
        config.with_allow_solid_archives(true);
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
            .try_set_max_solid_block_memory(256.0 * 1024.0 * 1024.0)
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
        config.with_allow_solid_archives(true);
        config.try_set_max_solid_block_memory(1024.0).unwrap();
        config.with_allow_solid_archives(true);
        assert_eq!(config.get_max_solid_block_memory(), Some(1024));
        config.with_allow_solid_archives(false);
        assert_eq!(config.get_max_solid_block_memory(), None);
    }

    #[test]
    fn test_max_solid_block_memory_round_trip() {
        let mut config = SecurityConfig::new();
        config.with_allow_solid_archives(true);
        let result = config.try_set_max_solid_block_memory(256.0 * 1024.0 * 1024.0);
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
        let result = config.try_set_max_solid_block_memory(-1.0);
        assert!(result.is_err(), "negative value should be rejected");
        assert!(
            result.unwrap_err().to_string().contains("negative"),
            "error should mention the negative value"
        );
    }

    #[test]
    fn test_max_solid_block_memory_rejects_zero() {
        let mut config = SecurityConfig::new();
        let result = config.try_set_max_solid_block_memory(0.0);
        assert!(result.is_err(), "zero should be rejected");
    }

    #[test]
    fn test_max_solid_block_memory_accepts_one_byte() {
        let mut config = SecurityConfig::new();
        config.with_allow_solid_archives(true);
        let result = config.try_set_max_solid_block_memory(1.0);
        assert!(result.is_ok(), "1 byte should be accepted");
        assert_eq!(config.get_max_solid_block_memory(), Some(1));
    }

    #[test]
    fn test_allowed_extensions_getter_after_add() {
        let mut config = SecurityConfig::new();
        config.try_add_allowed_extension(".txt").unwrap();
        config.try_add_allowed_extension(".md").unwrap();

        let extensions = config.get_allowed_extensions().unwrap();
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
        config.try_set_max_file_size(100_000_000.0).unwrap();
        config.try_set_max_total_size(1_000_000_000.0).unwrap();
        let result = config.build();

        assert_eq!(
            result.get_max_file_size(),
            Some(100_000_000),
            "build() should work in builder chain"
        );
        assert_eq!(result.get_max_total_size(), Some(1_000_000_000));
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
        config.try_set_max_file_size(100_000_000.0).unwrap();

        let cloned = config.clone();
        assert_eq!(
            cloned.get_max_file_size(),
            Some(100_000_000),
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
        config.try_set_compression_level(9.0).unwrap();
        config.with_preserve_permissions(false);
        config.with_follow_symlinks(true);
        config.with_include_hidden(true);
        config.try_set_max_file_size(Some(1_000_000.0)).unwrap();

        assert_eq!(config.get_compression_level(), 9);
        assert!(!config.get_preserve_permissions());
        assert!(config.get_follow_symlinks());
        assert!(config.get_include_hidden());
        assert_eq!(config.get_max_file_size(), Some(1_000_000));
    }

    #[test]
    fn test_creation_config_compression_level_rejects_invalid() {
        let mut config = CreationConfig::new();
        assert!(config.try_set_compression_level(0.0).is_err());
        assert!(config.try_set_compression_level(10.0).is_err());
    }

    #[test]
    fn test_creation_config_compression_level_accepts_valid() {
        let mut config = CreationConfig::new();
        assert!(config.try_set_compression_level(1.0).is_ok());
        assert!(config.try_set_compression_level(9.0).is_ok());
    }

    #[test]
    fn test_creation_config_max_file_size_rejects_zero_and_negative() {
        let mut config = CreationConfig::new();
        config.try_set_max_file_size(Some(10.0)).unwrap();
        for bad in [0.0, -1.0] {
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
        config.try_set_max_file_size(Some(10.0)).unwrap();
        config.try_set_max_file_size(None).unwrap();
        assert_eq!(config.get_max_file_size(), None);
        assert_eq!(config.as_core().max_file_size, Limit::Unbounded);
    }

    #[test]
    fn test_creation_config_add_exclude_pattern() {
        let mut config = CreationConfig::new();
        config.try_add_exclude_pattern("*.log").unwrap();
        let patterns = config.get_exclude_patterns();
        assert!(patterns.contains(&"*.log".to_string()));
    }

    #[test]
    fn test_creation_config_add_exclude_pattern_rejects_null() {
        let mut config = CreationConfig::new();
        let err = config.try_add_exclude_pattern("bad\0pattern").unwrap_err();
        assert_matches!(
            err,
            CoreError::InvalidConfiguration {
                setting: ConfigSetting::ExcludePattern,
                problem: ConfigProblem::PatternRefused {
                    reason: exarch_core::PatternRefusal::ContainsNul,
                    ..
                }
            }
        );
    }

    #[test]
    fn test_compression_level_refusals_are_typed_and_keep_the_previous_level() {
        use exarch_core::RequestedLevel as Requested;

        let mut config = CreationConfig::new();
        for (level, expected) in [
            (10.0, Requested::Integer(10)),
            (-3.0, Requested::Integer(-3)),
            (1.5, Requested::Fractional(1.5)),
            (f64::NAN, Requested::NonFinite),
            (f64::INFINITY, Requested::NonFinite),
            (4_294_967_302.0, Requested::Integer(4_294_967_302)),
        ] {
            let Err(CoreError::InvalidCompressionLevel { level: got }) =
                config.try_set_compression_level(level)
            else {
                panic!("{level} must be refused as an invalid compression level");
            };
            assert_eq!(format!("{got:?}"), format!("{expected:?}"), "{level}");
        }
        assert_eq!(config.get_compression_level(), 6);
    }

    #[test]
    fn test_creation_config_add_exclude_pattern_refuses_unsupported_glob_syntax() {
        for (shape, reason) in [
            ("{a}", exarch_core::PatternRefusal::BraceAlternation),
            ("[a", exarch_core::PatternRefusal::UnterminatedClass),
            ("{a,b}", exarch_core::PatternRefusal::ContainsComma),
            ("!a.txt", exarch_core::PatternRefusal::LeadingNegation),
            ("a**b", exarch_core::PatternRefusal::UnsupportedWildcard),
            (" .env", exarch_core::PatternRefusal::PaddedWithBlank),
            ("a,b", exarch_core::PatternRefusal::ContainsComma),
        ] {
            let mut config = CreationConfig::new();
            let err = config.try_add_exclude_pattern(shape).unwrap_err();
            assert_matches!(
                err,
                CoreError::InvalidConfiguration {
                    setting: ConfigSetting::ExcludePattern,
                    problem: ConfigProblem::PatternRefused { reason: got, .. }
                } if got == reason,
                "{shape}"
            );
        }
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
            .try_set_parallel_decode_memory(Some(256.0 * 1048576.0))
            .unwrap();
        assert_eq!(config.get_parallel_decode_memory(), Some(256 * MIB));
        config.try_set_parallel_decode_memory(None).unwrap();
        assert_eq!(config.get_parallel_decode_memory(), None);
    }

    #[test]
    fn test_parallel_decode_memory_rejects_zero_and_negative() {
        let mut config = SecurityConfig::new();
        assert!(config.try_set_parallel_decode_memory(Some(0.0)).is_err());
        assert!(config.try_set_parallel_decode_memory(Some(-1.0)).is_err());
        assert!(config.try_set_parallel_decode_memory(Some(1.5)).is_err());
        assert!(
            config
                .try_set_parallel_decode_memory(Some(f64::NAN))
                .is_err()
        );
        assert!(
            config
                .try_set_parallel_decode_memory(Some(f64::INFINITY))
                .is_err()
        );
        assert!(
            config
                .try_set_parallel_decode_memory(Some(1.0e300))
                .is_err()
        );
        assert_eq!(config.get_parallel_decode_memory(), Some(128 * 1024 * 1024));
    }

    #[test]
    fn test_zip_consistency_defaults_to_enforce_and_round_trips() {
        let mut config = SecurityConfig::new();
        assert_eq!(config.get_zip_consistency(), "enforce");
        assert_eq!(
            SecurityConfig::permissive().get_zip_consistency(),
            "enforce"
        );

        config.with_zip_consistency(ZipConsistencyPolicy::Ignore);
        assert_eq!(config.get_zip_consistency(), "ignore");
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

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn test_allowed_extensions_getter_is_null_for_any() {
        assert_eq!(SecurityConfig::new().get_allowed_extensions(), None);
    }

    #[test]
    fn test_set_allowed_extensions_replaces_and_null_lifts() {
        let mut config = SecurityConfig::new();
        config.try_add_allowed_extension("txt").unwrap();
        config
            .try_set_allowed_extensions(Some(&strings(&[".MD", "rs"])))
            .unwrap();
        assert_eq!(
            config.get_allowed_extensions(),
            Some(strings(&["md", "rs"]))
        );
        config.try_set_allowed_extensions(None).unwrap();
        assert_eq!(config.get_allowed_extensions(), None);
    }

    #[test]
    fn test_set_allowed_extensions_refuses_empty_list_and_keeps_previous() {
        let mut config = SecurityConfig::new();
        config
            .try_set_allowed_extensions(Some(&strings(&["txt"])))
            .unwrap();
        let err = config.try_set_allowed_extensions(Some(&[])).unwrap_err();
        assert_matches!(
            err,
            CoreError::InvalidConfiguration {
                setting: ConfigSetting::AllowedExtension,
                problem: ConfigProblem::Empty,
            }
        );
        assert_eq!(config.get_allowed_extensions(), Some(strings(&["txt"])));
    }

    #[test]
    fn test_set_allowed_extensions_is_all_or_nothing() {
        let mut config = SecurityConfig::new();
        config
            .try_set_allowed_extensions(Some(&strings(&["txt"])))
            .unwrap();
        assert!(
            config
                .try_set_allowed_extensions(Some(&strings(&["md", "a/b"])))
                .is_err()
        );
        assert_eq!(config.get_allowed_extensions(), Some(strings(&["txt"])));
    }

    #[test]
    fn test_set_banned_components_replaces_clears_and_is_all_or_nothing() {
        let mut config = SecurityConfig::new();
        config
            .try_set_banned_components(&strings(&["node_modules", "tmp"]))
            .unwrap();
        assert_eq!(
            config.get_banned_path_components(),
            strings(&["node_modules", "tmp"])
        );
        assert!(
            config
                .try_set_banned_components(&strings(&["ok", ".."]))
                .is_err()
        );
        assert_eq!(
            config.get_banned_path_components(),
            strings(&["node_modules", "tmp"])
        );
        config.try_set_banned_components(&[]).unwrap();
        assert!(config.get_banned_path_components().is_empty());
    }

    #[test]
    fn test_set_exclude_patterns_replaces_clears_and_is_all_or_nothing() {
        let mut config = CreationConfig::new();
        config
            .try_set_exclude_patterns(&strings(&["target", "*.log"]))
            .unwrap();
        assert_eq!(config.get_exclude_patterns(), strings(&["target", "*.log"]));
        let err = config
            .try_set_exclude_patterns(&strings(&["ok", "bad\0pattern"]))
            .unwrap_err();
        assert_matches!(
            err,
            CoreError::InvalidConfiguration {
                setting: ConfigSetting::ExcludePattern,
                ..
            }
        );
        assert_eq!(config.get_exclude_patterns(), strings(&["target", "*.log"]));
        config.try_set_exclude_patterns(&[]).unwrap();
        assert!(config.get_exclude_patterns().is_empty());
    }

    #[test]
    fn test_existing_files_defaults_to_skip_and_round_trips() {
        let mut options = ExtractionOptions::new();
        assert_eq!(options.get_existing_files(), "skip");
        for policy in [
            ExistingFiles::Overwrite,
            ExistingFiles::Refuse,
            ExistingFiles::Skip,
        ] {
            options.with_existing_files(policy);
            assert_eq!(
                options.get_existing_files(),
                CoreExistingFiles::from(policy).as_str()
            );
        }

        let mut sink = SinkOptions::new();
        assert_eq!(sink.get_existing_files(), "skip");
        sink.with_existing_files(ExistingFiles::Refuse);
        assert_eq!(sink.get_existing_files(), "refuse");
        assert_eq!(sink.to_core().existing_files, CoreExistingFiles::Refuse);
    }

    #[test]
    fn test_existing_files_covers_every_core_variant() {
        for core in CoreExistingFiles::ALL {
            let policy = ExistingFiles::try_from(*core).unwrap();
            assert_eq!(CoreExistingFiles::from(policy), *core);
        }
    }

    #[test]
    fn test_index_d_ts_existing_files_union_matches_core() {
        let values: Vec<_> = CoreExistingFiles::ALL
            .iter()
            .map(|p| format!("'{}'", p.as_str()))
            .collect();
        let expected = format!("export type ExistingFiles = {}", values.join(" | "));
        let dts = include_str!("../index.d.ts");
        assert!(
            dts.lines().any(|l| l == expected),
            "index.d.ts out of sync with exarch-core, expected line:\n{expected}"
        );
    }

    #[test]
    fn test_sink_decode_reuse_defaults_to_off_and_round_trips() {
        let mut sink = SinkOptions::new();
        assert_eq!(sink.get_decode_reuse(), DecodeReuseKind::Off);
        assert_eq!(sink.get_decode_reuse_limit(), None);

        sink.try_set_decode_reuse(DecodeReuseKind::Memory, None)
            .unwrap();
        assert_eq!(sink.get_decode_reuse(), DecodeReuseKind::Memory);
        assert_eq!(
            sink.get_decode_reuse_limit(),
            Some(i64::try_from(ReuseLimit::DEFAULT.get()).unwrap())
        );

        sink.try_set_decode_reuse(DecodeReuseKind::TempFile, Some(1024.0))
            .unwrap();
        assert_eq!(sink.get_decode_reuse(), DecodeReuseKind::TempFile);
        assert_eq!(sink.get_decode_reuse_limit(), Some(1024));
        assert_eq!(
            sink.to_core().decode_reuse,
            DecodeReuse::TempFile(ReuseLimit::new(NonZeroU64::new(1024).unwrap()))
        );

        sink.try_set_decode_reuse(DecodeReuseKind::Off, None)
            .unwrap();
        assert_eq!(sink.get_decode_reuse_limit(), None);
    }

    #[test]
    fn test_sink_decode_reuse_clamps_the_limit_and_refuses_bad_ones() {
        let mut sink = SinkOptions::new();
        sink.try_set_decode_reuse(DecodeReuseKind::Memory, Some(MAX_SAFE))
            .unwrap();
        assert_eq!(
            sink.get_decode_reuse_limit(),
            Some(i64::try_from(ReuseLimit::MAX.get()).unwrap())
        );

        for bad in [0.0, -1.0, 1.5, f64::NAN] {
            let err = sink
                .try_set_decode_reuse(DecodeReuseKind::Memory, Some(bad))
                .unwrap_err();
            assert_matches!(
                err,
                CoreError::InvalidConfiguration {
                    setting: ConfigSetting::DecodeReuseLimit,
                    ..
                }
            );
        }
        let err = sink
            .try_set_decode_reuse(DecodeReuseKind::Off, Some(1.0))
            .unwrap_err();
        assert_matches!(
            err,
            CoreError::InvalidConfiguration {
                setting: ConfigSetting::DecodeReuseLimit,
                problem: ConfigProblem::NotSupported,
            }
        );
        assert_eq!(sink.get_decode_reuse(), DecodeReuseKind::Memory);
    }

    #[test]
    fn test_index_d_ts_decode_reuse_union_matches_core() {
        let values: Vec<_> = CoreDecodeReuseKind::ALL
            .iter()
            .map(|p| format!("'{}'", p.as_str()))
            .collect();
        let expected = format!("export type DecodeReuseKind = {}", values.join(" | "));
        let dts = include_str!("../index.d.ts");
        assert!(
            dts.lines().any(|l| l == expected),
            "index.d.ts out of sync with exarch-core, expected line:\n{expected}"
        );
    }

    #[test]
    fn test_stored_targets_covers_every_core_variant() {
        for core in CoreStoredTargets::ALL {
            let targets = StoredTargets::try_from(*core).unwrap();
            assert_eq!(CoreStoredTargets::from(targets), *core);
        }
    }

    #[test]
    fn test_index_d_ts_stored_targets_union_matches_core() {
        let values: Vec<_> = CoreStoredTargets::ALL
            .iter()
            .map(|p| format!("'{}'", p.as_str()))
            .collect();
        let expected = format!("export type StoredTargets = {}", values.join(" | "));
        let dts = include_str!("../index.d.ts");
        assert!(
            dts.lines().any(|l| l == expected),
            "index.d.ts out of sync with exarch-core, expected line:\n{expected}"
        );
    }

    #[test]
    fn test_list_options_default_and_round_trip() {
        let mut options = ListOptions::new();
        assert_eq!(options.get_stored_targets(), "skip");
        options.with_stored_targets(StoredTargets::Read);
        assert_eq!(options.get_stored_targets(), "read");
        assert_eq!(options.to_core().stored_targets, CoreStoredTargets::Read);
    }

    #[test]
    fn test_staging_defaults_to_in_place_and_round_trips() {
        let mut options = ExtractionOptions::new();
        assert_eq!(options.get_staging(), "in_place");
        for staging in [Staging::AtomicReplace, Staging::Atomic, Staging::InPlace] {
            options.with_staging(staging);
            assert_eq!(options.get_staging(), CoreStaging::from(staging).as_str());
        }
        options.with_staging(Staging::AtomicReplace);
        assert_eq!(options.as_core().staging, CoreStaging::AtomicReplace);
    }

    #[test]
    fn test_staging_covers_every_core_variant() {
        for core in CoreStaging::ALL {
            let staging = Staging::try_from(*core).unwrap();
            assert_eq!(CoreStaging::from(staging), *core);
        }
    }

    #[test]
    fn test_index_d_ts_staging_union_matches_core() {
        let values: Vec<_> = CoreStaging::ALL
            .iter()
            .map(|p| format!("'{}'", p.as_str()))
            .collect();
        let expected = format!("export type Staging = {}", values.join(" | "));
        let dts = include_str!("../index.d.ts");
        assert!(
            dts.lines().any(|l| l == expected),
            "index.d.ts out of sync with exarch-core, expected line:\n{expected}"
        );
    }

    #[test]
    fn test_selection_defaults_to_every_entry_and_keeps_paths() {
        let config = SecurityConfig::new();
        assert!(config.get_include_patterns().is_empty());
        assert!(config.get_exclude_patterns().is_empty());
        assert_eq!(config.get_strip_components(), None);
        assert!(!config.get_flatten());
        assert!(config.as_core().selection.is_default());
    }

    #[test]
    fn test_include_and_exclude_patterns_append_replace_and_clear() {
        let mut config = SecurityConfig::new();
        config
            .try_set_include_patterns(Some(&strings(&["src"])), SelectionEdit::Append)
            .unwrap();
        config
            .try_set_include_patterns(Some(&strings(&["docs/api"])), SelectionEdit::Append)
            .unwrap();
        config
            .try_set_exclude_patterns(&strings(&["*.tmp"]), SelectionEdit::Append)
            .unwrap();
        assert_eq!(config.get_include_patterns(), strings(&["src", "docs/api"]));
        assert_eq!(config.get_exclude_patterns(), strings(&["*.tmp"]));

        config
            .try_set_include_patterns(Some(&strings(&["lib"])), SelectionEdit::Replace)
            .unwrap();
        assert_eq!(config.get_include_patterns(), strings(&["lib"]));
        assert_eq!(config.get_exclude_patterns(), strings(&["*.tmp"]));

        config
            .try_set_include_patterns(Some(&[]), SelectionEdit::Replace)
            .unwrap();
        config
            .try_set_exclude_patterns(&[], SelectionEdit::Replace)
            .unwrap();
        assert!(config.as_core().selection.is_default());
    }

    #[test]
    fn test_selection_patterns_are_validated_as_a_whole_with_their_own_setting() {
        let mut config = SecurityConfig::new();
        config
            .try_set_include_patterns(Some(&strings(&["src"])), SelectionEdit::Replace)
            .unwrap();
        let err = config
            .try_set_include_patterns(Some(&strings(&["ok", "/x"])), SelectionEdit::Replace)
            .unwrap_err();
        assert_matches!(
            err,
            CoreError::InvalidConfiguration {
                setting: ConfigSetting::EntryInclude,
                ..
            }
        );
        assert_eq!(config.get_include_patterns(), strings(&["src"]));

        let err = config
            .try_set_exclude_patterns(&strings(&["a,b"]), SelectionEdit::Append)
            .unwrap_err();
        assert_matches!(
            err,
            CoreError::InvalidConfiguration {
                setting: ConfigSetting::EntryExclude,
                ..
            }
        );
        assert!(config.get_exclude_patterns().is_empty());
    }

    #[test]
    fn test_strip_components_flatten_and_the_include_lists_are_independent() {
        let mut config = SecurityConfig::new();
        config
            .try_set_include_patterns(Some(&strings(&["src"])), SelectionEdit::Append)
            .unwrap();
        config.try_set_strip_components(Some(2.0)).unwrap();
        assert_eq!(config.get_strip_components(), Some(2.0));
        assert!(!config.get_flatten());
        assert_eq!(config.get_include_patterns(), strings(&["src"]));

        config.try_set_flatten(true);
        assert!(config.get_flatten());
        assert_eq!(
            config.get_strip_components(),
            None,
            "flatten replaces strip"
        );

        config.try_set_strip_components(Some(1.0)).unwrap();
        assert!(!config.get_flatten(), "strip replaces flatten");

        config.try_set_flatten(false);
        assert_eq!(
            config.get_strip_components(),
            Some(1.0),
            "false keeps a strip count"
        );
        config.try_set_strip_components(None).unwrap();
        assert_eq!(config.as_core().selection.rewrite(), PathRewrite::Keep);

        config.try_set_flatten(true);
        config.try_set_strip_components(None).unwrap();
        assert!(
            config.get_flatten(),
            "clearing the strip count keeps flatten"
        );
        config.try_set_flatten(false);
        assert_eq!(config.as_core().selection.rewrite(), PathRewrite::Keep);
    }

    #[test]
    fn test_strip_components_refusals_name_the_setting_and_keep_the_previous_value() {
        let mut config = SecurityConfig::new();
        config.try_set_strip_components(Some(1.0)).unwrap();
        let too_deep =
            f64::from(u32::try_from(config.as_core().max_path_depth.get()).unwrap()) + 1.0;
        for bad in [0.0, -1.0, 1.5, f64::NAN, f64::INFINITY, too_deep, MAX_SAFE] {
            let err = config.try_set_strip_components(Some(bad)).unwrap_err();
            assert_matches!(
                err,
                CoreError::InvalidConfiguration {
                    setting: ConfigSetting::StripComponents,
                    ..
                }
            );
            assert_eq!(config.get_strip_components(), Some(1.0), "{bad}");
        }
    }
}
