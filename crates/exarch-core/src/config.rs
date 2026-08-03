//! Security configuration for archive extraction.

use std::marker::PhantomData;
use std::ops::Deref;
use std::ops::DerefMut;

/// Marker type for a [`SecurityConfig`] whose invariants have not yet been
/// checked.
///
/// This is the default type parameter for [`SecurityConfig`]. The fluent
/// `with_*` builder methods and [`SecurityConfig::validate`] are only
/// available in this state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Unvalidated;

/// Marker type for a [`SecurityConfig`] whose invariants have been checked.
///
/// Reachable only through [`SecurityConfig::validate`]. Every entry point
/// that performs security-sensitive work — the
/// [`ArchiveFormat`](crate::formats::traits::ArchiveFormat) trait and
/// everything it calls — requires a `SecurityConfig<Validated>`, so an
/// unvalidated configuration (e.g. one with `max_file_size == 0`) can never
/// reach extraction, listing, or verification. The compiler enforces this;
/// it is not a convention callers must remember to follow.
///
/// Once validated, a config's fields can still be *read* (via [`Deref`]) but
/// no longer *written*: [`DerefMut`] is implemented only for
/// `SecurityConfig<Unvalidated>`, so `cfg.max_compression_ratio = f64::NAN`
/// on a `SecurityConfig<Validated>` is a compile error, not a runtime
/// invariant violation. This is what makes the typestate airtight — without
/// it, a caller could validate a config and then mutate it back into an
/// invalid state before passing it to `ArchiveFormat::extract`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Validated;

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

/// The field data of a [`SecurityConfig`], reachable via [`Deref`]/[`DerefMut`]
/// regardless of (or gated by) validation state.
///
/// This type is not itself part of the sealing boundary — it is a plain data
/// bag with `pub` fields, and nothing stops external code from naming it or
/// cloning one out of a `&SecurityConfig`. The boundary is
/// [`SecurityConfig`]'s own private `fields` member: there is no public API
/// that takes a bare `SecurityConfigFields` and wraps it back into a
/// `SecurityConfig<Validated>`, so an externally-forged or externally-mutated
/// `SecurityConfigFields` value can never be smuggled into a `Validated`
/// config. It exists purely so [`SecurityConfig`] can implement `Deref`/
/// `DerefMut` and keep `cfg.max_file_size`-style field access working for
/// every existing caller instead of forcing a getter-method migration.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SecurityConfigFields {
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

    /// Maximum bytes the TAR reader may consume for headers and metadata
    /// records in the gap between two consecutive entries.
    ///
    /// **TAR Metadata Buffering Model:**
    ///
    /// GNU long-name (`L`), GNU long-link (`K`), and PAX extended header
    /// (`x`/`g`) records are buffered fully into memory by the underlying
    /// `tar` crate *before* any entry reaches the entry validator or quota
    /// tracker — a crafted record can declare a multi-gigabyte length backed
    /// by a tiny compressed stream, exhausting memory with no quota
    /// enforcement (metadata-entry decompression bomb).
    ///
    /// **Enforcement Strategy:**
    /// - A read-budget wrapper meters bytes the `tar` crate reads while
    ///   searching for the next entry (headers, long-name/long-link/PAX
    ///   records, GNU sparse extension blocks) and returns an error once
    ///   `max_tar_metadata_bytes` is exceeded, before any oversized allocation
    ///   completes
    /// - Applies uniformly to `extract`, `list`, and `verify`
    /// - The window this bounds contains no entry *data* — only metadata — so
    ///   it does not interact with `max_file_size`/`max_total_size`. Draining
    ///   an unread entry before the next header search is a separate concern
    ///   (see `formats::tar_metadata_limit`'s module docs) bounded by
    ///   synthesized-byte accounting, not by this or any other quota value
    /// - Legitimate long-path/xattr metadata records are at most a few
    ///   kilobytes each, and a GNU tar sparse file with heavy fragmentation can
    ///   use up to a few thousand 512-byte extension blocks; either or both
    ///   share this single budget (not "plus" each other), so the default
    ///   leaves headroom for either shape, not necessarily both at their
    ///   extremes simultaneously
    /// - The real peak memory this bounds is roughly 5x the configured value
    ///   (GNU sparse extension blocks expand into multiple `EntryIo` records
    ///   per block before the growth is charged against this budget), not an
    ///   exact multiple — treat it as an order-of-magnitude ceiling, not a
    ///   tight bound
    ///
    /// Default: 4 MiB (4,194,304 bytes)
    pub max_tar_metadata_bytes: u64,

    /// Internal only — not part of the public builder API, and never set by
    /// `SecurityConfig::default()`/`permissive()` construction paths that
    /// external callers use.
    ///
    /// When `true`, `list_archive`'s entry-path NUL-byte check, symlink/
    /// hardlink target NUL-byte/emptiness check, and missing-link-target
    /// check are all skipped, instead of aborting the listing pass. Set only
    /// by `inspection::verify::listing_config_for_verify` for
    /// `verify_archive`'s internal pre-flight listing step, so a NUL-byte or
    /// empty/missing link target reaches `verify_entry`'s own equivalent
    /// checks (`SafePath::validate`, `SafeSymlink::validate`) and surfaces as
    /// a graceful `VerificationIssue` in the report, matching `verify`'s
    /// behavior before these list-level checks existed. Bare `list_archive`
    /// always leaves this `false`, so `exarch list` still hard-aborts on
    /// these conditions.
    pub(crate) relaxed_for_verify_preflight: bool,
}

impl Default for SecurityConfigFields {
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
            max_tar_metadata_bytes: 4 * 1024 * 1024,   // 4 MiB
            relaxed_for_verify_preflight: false,
        }
    }
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
///
/// # Typestate
///
/// `SecurityConfig` carries a phantom `State` type parameter — [`Unvalidated`]
/// (the default) or [`Validated`] — that tracks whether
/// [`validate`](SecurityConfig::validate) has been called. Builder methods
/// are only available in the `Unvalidated` state; security-sensitive APIs
/// (the [`ArchiveFormat`](crate::formats::traits::ArchiveFormat) trait and
/// everything downstream of it) require `SecurityConfig<Validated>`. This
/// makes skipping validation a compile error instead of a runtime gap.
///
/// # Sealing
///
/// Fields are private and reachable only through
/// <code>[Deref]<Target = [SecurityConfigFields]></code>, so
/// `cfg.max_file_size` continues to work as plain field access for both states.
/// [`DerefMut`] is implemented only for
/// `SecurityConfig<Unvalidated>`, so a `SecurityConfig<Validated>`'s fields
/// cannot be reassigned after the fact — the only way to produce one is
/// [`validate`](SecurityConfig::validate) itself, and it stays that way for
/// its entire lifetime.
#[derive(Debug, Clone)]
pub struct SecurityConfig<State = Unvalidated> {
    fields: SecurityConfigFields,

    /// Typestate marker — see the "Typestate" section on the type-level docs.
    _marker: PhantomData<State>,
}

impl<State> Deref for SecurityConfig<State> {
    type Target = SecurityConfigFields;

    fn deref(&self) -> &SecurityConfigFields {
        &self.fields
    }
}

/// Only `Unvalidated` configs are mutable — see the "Sealing" section on
/// [`SecurityConfig`]'s type-level docs for why this is the crux of the
/// typestate guarantee.
impl DerefMut for SecurityConfig<Unvalidated> {
    fn deref_mut(&mut self) -> &mut SecurityConfigFields {
        &mut self.fields
    }
}

impl Default for SecurityConfig<Unvalidated> {
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
    /// - `max_tar_metadata_bytes`: 4 MiB
    fn default() -> Self {
        Self {
            fields: SecurityConfigFields::default(),
            _marker: PhantomData,
        }
    }
}

impl SecurityConfig<Unvalidated> {
    /// Creates a permissive configuration for trusted archives.
    ///
    /// This configuration allows symlinks, hardlinks, absolute paths, and
    /// solid archives. Use only when extracting archives from trusted sources.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            fields: SecurityConfigFields {
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
                max_tar_metadata_bytes: 16 * 1024 * 1024,   // 16 MiB for permissive
                ..SecurityConfigFields::default()
            },
            _marker: PhantomData,
        }
    }

    /// Validates that the configuration values are logically consistent,
    /// transitioning to the [`Validated`] typestate on success.
    ///
    /// Returns an error if any field has a value that would make security
    /// enforcement impossible (zero limits or non-positive ratio). Consumes
    /// `self`: the only way to obtain a `SecurityConfig<Validated>`, which is
    /// what every security-sensitive API in this crate requires. Once
    /// returned, the `Validated` config's fields can no longer be reassigned
    /// (see the "Sealing" section on the type-level docs), so this check can
    /// never be silently invalidated afterward.
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
    /// - `max_tar_metadata_bytes` is zero
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
    pub fn validate(self) -> crate::Result<SecurityConfig<Validated>> {
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
        if self.max_tar_metadata_bytes == 0 {
            return Err(crate::ArchiveError::InvalidConfiguration {
                reason: "max_tar_metadata_bytes must not be zero".into(),
            });
        }
        Ok(SecurityConfig {
            fields: self.fields,
            _marker: PhantomData,
        })
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
        self.fields.max_file_size = size;
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
        self.fields.max_total_size = size;
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
        self.fields.max_compression_ratio = ratio;
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
        self.fields.max_file_count = count;
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
        self.fields.max_path_depth = depth;
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
        self.fields.allowed = allowed;
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
        self.fields.allowed.symlinks = allow;
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
        self.fields.allowed.hardlinks = allow;
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
        self.fields.allowed.absolute_paths = allow;
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
        self.fields.allowed.world_writable = allow;
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
        self.fields.preserve_permissions = preserve;
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
        self.fields.allowed_extensions = extensions;
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
        self.fields.banned_path_components = components;
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
        self.fields.allow_solid_archives = allow;
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
        self.fields.max_solid_block_memory = size;
        self
    }

    /// Sets the maximum bytes the TAR reader may consume for headers and
    /// metadata records (GNU long-name/long-link, PAX extended headers, GNU
    /// sparse extension blocks) in the gap between two consecutive entries.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default().with_max_tar_metadata_bytes(64 * 1024);
    /// assert_eq!(config.max_tar_metadata_bytes, 64 * 1024);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_max_tar_metadata_bytes(mut self, size: u64) -> Self {
        self.fields.max_tar_metadata_bytes = size;
        self
    }

    /// Marks this config as the internal pre-flight listing pass inside
    /// `verify_archive`. Not part of the public API — see
    /// `relaxed_for_verify_preflight`'s field doc for what this relaxes.
    ///
    /// Production code builds this state via
    /// `SecurityConfig::as_relaxed_for_verify_preflight` instead (it must
    /// work on both typestates); this builder-style variant exists only so
    /// `Unvalidated`-only test call sites don't need direct field writes.
    #[cfg(test)]
    #[must_use]
    #[inline]
    pub(crate) fn with_relaxed_for_verify_preflight(mut self) -> Self {
        self.fields.relaxed_for_verify_preflight = true;
        self
    }
}

/// Read-only queries and crate-internal helpers available regardless of
/// validation state.
impl<State> SecurityConfig<State> {
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

    /// Returns a clone with `max_file_size` relaxed to unlimited and
    /// `relaxed_for_verify_preflight` set, preserving `State`.
    ///
    /// Crate-internal escape hatch backing
    /// `inspection::verify::listing_config_for_verify`. Sound for both
    /// typestates: it only ever *relaxes* two fields whose overridden values
    /// (`u64::MAX`, `true`) can never fail
    /// [`validate`](SecurityConfig::validate)'s checks, so a `Validated`
    /// input yields a still-genuinely-valid `Validated` output without
    /// re-running `validate()`. This must not be generalized into an
    /// arbitrary-field mutator — that would reopen the exact hole
    /// `DerefMut`'s state-gating exists to close.
    #[must_use]
    pub(crate) fn as_relaxed_for_verify_preflight(&self) -> Self {
        let mut fields = self.fields.clone();
        fields.max_file_size = u64::MAX;
        fields.relaxed_for_verify_preflight = true;
        Self {
            fields,
            _marker: PhantomData,
        }
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
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]
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

    #[test]
    fn test_config_tar_metadata_bytes_default() {
        let config = SecurityConfig::default();
        assert_eq!(
            config.max_tar_metadata_bytes,
            4 * 1024 * 1024,
            "max TAR metadata bytes should be 4 MiB by default"
        );
    }

    #[test]
    fn test_config_permissive_tar_metadata_bytes() {
        let config = SecurityConfig::permissive();
        assert_eq!(
            config.max_tar_metadata_bytes,
            16 * 1024 * 1024,
            "permissive should have 16 MiB TAR metadata budget"
        );
    }

    #[test]
    fn test_with_max_tar_metadata_bytes_builder() {
        let config = SecurityConfig::default().with_max_tar_metadata_bytes(2048);
        assert_eq!(config.max_tar_metadata_bytes, 2048);
    }

    // Regression tests for #172: SecurityConfig::validate() must reject configs
    // that would make security enforcement impossible.

    #[test]
    fn test_validate_default_is_ok() {
        assert!(SecurityConfig::default().validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_negative_compression_ratio() {
        let mut cfg = SecurityConfig::default();
        cfg.max_compression_ratio = -1.0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_zero_compression_ratio() {
        let mut cfg = SecurityConfig::default();
        cfg.max_compression_ratio = 0.0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_zero_max_file_size() {
        let mut cfg = SecurityConfig::default();
        cfg.max_file_size = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_zero_max_total_size() {
        let mut cfg = SecurityConfig::default();
        cfg.max_total_size = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_zero_max_path_depth() {
        let mut cfg = SecurityConfig::default();
        cfg.max_path_depth = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_nan_compression_ratio() {
        let mut cfg = SecurityConfig::default();
        cfg.max_compression_ratio = f64::NAN;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_infinite_compression_ratio() {
        let mut cfg = SecurityConfig::default();
        cfg.max_compression_ratio = f64::INFINITY;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_zero_max_file_count() {
        let mut cfg = SecurityConfig::default();
        cfg.max_file_count = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_zero_max_solid_block_memory() {
        let mut cfg = SecurityConfig::default();
        cfg.max_solid_block_memory = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_zero_max_tar_metadata_bytes() {
        let mut cfg = SecurityConfig::default();
        cfg.max_tar_metadata_bytes = 0;
        assert!(cfg.validate().is_err());
    }

    // Regression test for the C1 finding on #433/#434/#435: a
    // `SecurityConfig<Validated>` must not be mutable. `DerefMut` is only
    // implemented for `SecurityConfig<Unvalidated>`, so this is enforced at
    // compile time — see `tests/ui/validated_config_field_mutation.rs` for
    // the corresponding compile-fail fixture. This test only pins the
    // read-side behavior: fields remain readable after validation.
    #[test]
    fn test_validated_config_fields_remain_readable() {
        let validated = SecurityConfig::default()
            .with_max_file_size(123)
            .validate()
            .expect("valid config");
        assert_eq!(validated.max_file_size, 123);
    }
}
