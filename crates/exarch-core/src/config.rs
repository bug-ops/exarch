//! Security configuration for archive extraction.

use std::num::NonZeroU64;
use std::num::NonZeroUsize;

use crate::ConfigProblem;
use crate::ConfigSetting;
use crate::Limit;
use crate::RatioLimit;
use crate::closed_enum::closed_enum;
use crate::non_zero;
use crate::non_zero_u64;
use crate::types::Extension;
use crate::types::PathComponentName;

closed_enum! {
    /// Whether an archive feature is admitted.
    ///
    /// Names the stored state of each [`AllowedFeatures`] field instead of an
    /// unlabeled `bool`. The default is [`Refuse`](Admit::Refuse), the
    /// deny-by-default policy.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::Admit;
    /// use exarch_core::SecurityConfig;
    ///
    /// assert_eq!(SecurityConfig::default().allowed.symlinks, Admit::Refuse);
    /// let config = SecurityConfig::default().with_allow_symlinks(true);
    /// assert!(config.allowed.symlinks.is_allowed());
    /// assert_eq!(Admit::from_allowed(false), Admit::Refuse);
    /// ```
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
    pub enum Admit {
        /// The feature is refused
        #[default]
        Refuse => "refuse",

        /// The feature is admitted
        Allow => "allow",
    }
}

impl Admit {
    /// Returns `true` for [`Allow`](Admit::Allow).
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }

    /// [`Allow`](Admit::Allow) when `allowed` is `true`, otherwise
    /// [`Refuse`](Admit::Refuse).
    #[must_use]
    pub const fn from_allowed(allowed: bool) -> Self {
        if allowed { Self::Allow } else { Self::Refuse }
    }
}

/// Feature flags controlling what archive features are allowed during
/// extraction.
///
/// All features default to [`Admit::Refuse`] (deny-by-default security policy).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct AllowedFeatures {
    /// Allow symlinks in extracted archives.
    pub symlinks: Admit,

    /// Allow hardlinks in extracted archives.
    pub hardlinks: Admit,

    /// Allow absolute paths in archive entries.
    pub absolute_paths: Admit,

    /// Allow world-writable files (mode 0o002).
    ///
    /// World-writable files pose security risks in multi-user environments.
    pub world_writable: Admit,

    /// Allow Windows reserved device names (`CON`, `NUL`, `COM1`, ...) as path
    /// components.
    ///
    /// Only consulted when extracting on Windows; has no effect elsewhere.
    /// There is no CLI or binding opt-out, and the permissive preset does not
    /// enable it.
    pub windows_reserved_names: Admit,
}

const DEFAULT_BANNED_PATH_COMPONENTS: [&str; 7] =
    [".git", ".ssh", ".gnupg", ".aws", ".kube", ".docker", ".env"];

fn default_banned_path_components() -> Vec<PathComponentName> {
    // The constants are valid by construction;
    // `default_banned_components_are_all_usable` pins it.
    DEFAULT_BANNED_PATH_COMPONENTS
        .iter()
        .filter_map(|name| PathComponentName::try_from(*name).ok())
        .collect()
}

closed_enum! {
    /// How ZIP structure that different readers interpret differently is
    /// handled.
    ///
    /// A ZIP archive stores each entry's metadata twice, in a local header and
    /// in the central directory. Random-access readers follow the central
    /// directory and streaming readers follow the local headers, so an
    /// archive whose copies disagree, that hides records, repeats a name or
    /// overlaps entries is a parser differential ("Zip Cloaking").
    ///
    /// `Enforce` (the default, also for [`SecurityConfig::permissive`])
    /// rejects such archives in `extract` and `list` and reports them in
    /// `verify`. `Ignore` keeps the central-directory interpretation and
    /// raises no structural finding; resource limits still apply.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    /// use exarch_core::ZipConsistencyPolicy;
    ///
    /// assert_eq!(
    ///     SecurityConfig::default().zip_consistency,
    ///     ZipConsistencyPolicy::Enforce
    /// );
    /// let relaxed = SecurityConfig::default().with_zip_consistency(ZipConsistencyPolicy::Ignore);
    /// assert_eq!(relaxed.zip_consistency.as_str(), "ignore");
    /// ```
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum ZipConsistencyPolicy {
        /// Reject or report structurally ambiguous ZIP archives
        #[default]
        Enforce => "enforce",

        /// Use the central directory interpretation without structural findings
        Ignore => "ignore",
    }
}

/// Limits applied to a solid 7z archive that is admitted.
///
/// A solid block compresses several files into one stream, so no per-file
/// ratio exists: `max_ratio` replaces
/// [`max_compression_ratio`](SecurityConfig::max_compression_ratio) for its
/// members. The limits exist only inside [`SolidArchives::Allow`], so they
/// cannot be set while solid archives are refused.
///
/// # Examples
///
/// ```
/// use exarch_core::SolidLimits;
///
/// let limits = SolidLimits::DEFAULT.with_max_block_memory(exarch_core::non_zero!(1 << 20));
/// assert_eq!(limits.max_block_memory.get(), 1 << 20);
/// assert_eq!(limits.max_ratio, SolidLimits::DEFAULT.max_ratio);
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct SolidLimits {
    /// Maximum decoded size of a solid archive, in bytes.
    ///
    /// Solid members share one compressed stream, so a crafted block can
    /// declare a far larger decoded size than its compressed size suggests.
    /// The check compares the declared uncompressed sizes of the archive's
    /// files with this value before any data is decoded.
    pub max_block_memory: NonZeroU64,

    /// Maximum compression ratio of a whole solid block (summed uncompressed
    /// size of its files / compressed size of its pack streams).
    pub max_ratio: RatioLimit,
}

impl SolidLimits {
    /// 512 MiB of block memory and a ratio of 1000: the limits of
    /// [`SecurityConfig::default`] once solid archives are allowed.
    pub const DEFAULT: Self = Self {
        max_block_memory: non_zero!(512 * 1024 * 1024),
        max_ratio: crate::ratio_limit!(1000.0),
    };
    /// 1 GiB of block memory and a ratio of 10,000, as in
    /// [`SecurityConfig::permissive`].
    pub const PERMISSIVE: Self = Self {
        max_block_memory: non_zero!(1024 * 1024 * 1024),
        max_ratio: crate::ratio_limit!(10_000.0),
    };

    /// Limits from explicit values.
    #[must_use]
    pub const fn new(max_block_memory: NonZeroU64, max_ratio: RatioLimit) -> Self {
        Self {
            max_block_memory,
            max_ratio,
        }
    }

    /// Replaces [`max_block_memory`](Self::max_block_memory).
    #[must_use]
    pub const fn with_max_block_memory(mut self, max_block_memory: NonZeroU64) -> Self {
        self.max_block_memory = max_block_memory;
        self
    }

    /// Replaces [`max_ratio`](Self::max_ratio).
    #[must_use]
    pub const fn with_max_ratio(mut self, max_ratio: RatioLimit) -> Self {
        self.max_ratio = max_ratio;
        self
    }
}

impl Default for SolidLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Whether solid 7z archives are extracted, and under which limits.
///
/// Solid archives compress several files into one block, so extracting any
/// file requires decoding the block. A crafted archive can declare a huge
/// block, which makes admitting solid archives a memory and CPU risk: enable
/// them only for trusted input. The limits live in [`Allow`](Self::Allow), so
/// they cannot be set and then ignored while the policy is
/// [`Refuse`](Self::Refuse).
///
/// # Examples
///
/// ```
/// use exarch_core::SecurityConfig;
/// use exarch_core::SolidArchives;
/// use exarch_core::SolidLimits;
///
/// assert_eq!(
///     SecurityConfig::default().solid_archives,
///     SolidArchives::Refuse
/// );
/// let config = SecurityConfig::default().with_allow_solid_archives(true);
/// assert_eq!(config.solid_archives.limits(), Some(SolidLimits::DEFAULT));
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[non_exhaustive]
pub enum SolidArchives {
    /// Solid archives are rejected
    #[default]
    Refuse,

    /// Solid archives are extracted within these limits
    Allow(SolidLimits),
}

impl SolidArchives {
    /// The limits of an admitted policy, or `None` under
    /// [`Refuse`](Self::Refuse).
    #[must_use]
    pub const fn limits(self) -> Option<SolidLimits> {
        match self {
            Self::Refuse => None,
            Self::Allow(limits) => Some(limits),
        }
    }

    /// Returns `true` for [`Allow`](Self::Allow).
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allow(_))
    }

    /// Admits or refuses solid archives.
    ///
    /// `true` keeps the limits of an already admitted policy and otherwise
    /// admits under [`SolidLimits::DEFAULT`]; `false` refuses and drops any
    /// limits.
    #[must_use]
    pub const fn with_allowed(self, allow: bool) -> Self {
        match (allow, self) {
            (true, admitted @ Self::Allow(_)) => admitted,
            (true, Self::Refuse) => Self::Allow(SolidLimits::DEFAULT),
            (false, _) => Self::Refuse,
        }
    }

    /// Replaces the limits of an admitted policy.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ArchiveError::InvalidConfiguration`] naming
    /// [`ConfigSetting::MaxSolidBlockMemory`] under [`Refuse`](Self::Refuse),
    /// because the limits would be silently ignored.
    pub fn with_limits(self, limits: SolidLimits) -> crate::Result<Self> {
        match self {
            Self::Allow(_) => Ok(Self::Allow(limits)),
            Self::Refuse => Err(crate::ArchiveError::InvalidConfiguration {
                setting: ConfigSetting::MaxSolidBlockMemory,
                problem: ConfigProblem::NotSupported,
            }),
        }
    }

    /// Replaces only the block memory limit of an admitted policy, keeping its
    /// ratio.
    ///
    /// # Errors
    ///
    /// Fails as [`with_limits`](Self::with_limits) does.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SolidArchives;
    /// use exarch_core::SolidLimits;
    ///
    /// let memory = exarch_core::non_zero!(1 << 20);
    /// assert!(SolidArchives::Refuse.with_max_block_memory(memory).is_err());
    ///
    /// let allowed = SolidArchives::Allow(SolidLimits::PERMISSIVE).with_max_block_memory(memory)?;
    /// let limits = allowed.limits().expect("an admitted policy has limits");
    /// assert_eq!(limits.max_block_memory, memory);
    /// assert_eq!(limits.max_ratio, SolidLimits::PERMISSIVE.max_ratio);
    /// # Ok::<(), exarch_core::ArchiveError>(())
    /// ```
    pub fn with_max_block_memory(self, max_block_memory: NonZeroU64) -> crate::Result<Self> {
        match self {
            Self::Allow(limits) => Ok(Self::Allow(limits.with_max_block_memory(max_block_memory))),
            Self::Refuse => self.with_limits(SolidLimits::DEFAULT),
        }
    }
}

/// How much extra memory a 7z block may use to decode LZMA2 runs ahead on
/// worker threads.
///
/// An LZMA2 stream written with multiple threads (7-Zip's default for large
/// inputs) consists of independent runs, so several can be decoded at once.
/// Decoded runs wait in memory until the consumer reaches them, so the
/// lookahead is bounded: `Bounded(n)` lets in-flight runs hold at most `n`
/// bytes on top of the decoder window that
/// [`max_decoder_memory`](SecurityConfig::max_decoder_memory) already
/// admits. `Sequential` decodes on the calling thread only.
///
/// Archives written with runs of a few MiB decode within about 10% of an
/// unbounded multi-threaded reader at the default; a stock 7-Zip archive has
/// 64 MiB runs and needs about 100 MiB of lookahead
/// per extra concurrent run.
///
/// A valid archive decodes to the same bytes in either mode, and a corrupt one
/// fails the same file with the same error kind; only how many leading bytes
/// that file received can differ.
///
/// # Concurrency
///
/// The limit applies to one extraction or verification. Each call may start
/// up to 16 worker threads and hold its own lookahead, so concurrent calls
/// (for example from several Python threads or Node promises) multiply both
/// the threads and the memory. Size the setting for the number of calls that
/// can run at once, or use `Sequential`.
///
/// # Examples
///
/// ```
/// use std::num::NonZeroU64;
///
/// use exarch_core::ParallelDecode;
/// use exarch_core::SecurityConfig;
///
/// assert_eq!(
///     SecurityConfig::default().parallel_decode,
///     ParallelDecode::Bounded(NonZeroU64::new(128 * 1024 * 1024).unwrap())
/// );
/// let config = SecurityConfig::default().with_parallel_decode(ParallelDecode::Sequential);
/// assert_eq!(config.parallel_decode, ParallelDecode::Sequential);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParallelDecode {
    /// Decode on the calling thread only
    Sequential,

    /// Decode runs ahead on worker threads, holding at most this many bytes
    Bounded(NonZeroU64),
}

/// Default base of the compressed member allowance.
pub(crate) const DEFAULT_MEMBER_ALLOWANCE: NonZeroU64 = non_zero!(10_000);

impl ParallelDecode {
    /// Default lookahead: 128 MiB.
    pub const DEFAULT_BYTES: NonZeroU64 = non_zero!(128 * 1024 * 1024);

    /// The lookahead memory in bytes, or `None` for [`Sequential`].
    ///
    /// [`Sequential`]: ParallelDecode::Sequential
    ///
    /// # Examples
    ///
    /// ```
    /// use std::num::NonZeroU64;
    ///
    /// use exarch_core::ParallelDecode;
    ///
    /// assert_eq!(ParallelDecode::Sequential.lookahead(), None);
    /// let bytes = NonZeroU64::new(1 << 20).unwrap();
    /// assert_eq!(ParallelDecode::Bounded(bytes).lookahead(), Some(bytes));
    /// ```
    #[must_use]
    pub const fn lookahead(self) -> Option<NonZeroU64> {
        match self {
            Self::Sequential => None,
            Self::Bounded(bytes) => Some(bytes),
        }
    }
}

impl ParallelDecode {
    /// The mode for an optional lookahead: `None` is
    /// [`Sequential`](Self::Sequential).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::num::NonZeroU64;
    ///
    /// use exarch_core::ParallelDecode;
    ///
    /// assert_eq!(ParallelDecode::from_bytes(None), ParallelDecode::Sequential);
    /// let bytes = NonZeroU64::MIN;
    /// assert_eq!(
    ///     ParallelDecode::from_bytes(Some(bytes)),
    ///     ParallelDecode::Bounded(bytes)
    /// );
    /// ```
    #[must_use]
    pub const fn from_bytes(lookahead: Option<NonZeroU64>) -> Self {
        match lookahead {
            Some(bytes) => Self::Bounded(bytes),
            None => Self::Sequential,
        }
    }
}

impl From<Option<NonZeroU64>> for ParallelDecode {
    fn from(lookahead: Option<NonZeroU64>) -> Self {
        Self::from_bytes(lookahead)
    }
}

impl Default for ParallelDecode {
    fn default() -> Self {
        Self::Bounded(Self::DEFAULT_BYTES)
    }
}

/// Security configuration with default-deny settings.
///
/// This configuration controls various security checks performed during
/// archive extraction to prevent common vulnerabilities.
///
/// # Performance Note
///
/// This struct contains heap-allocated collections
/// (`Vec<Extension>`/`Vec<PathComponentName>`). For performance, pass by
/// reference (`&SecurityConfig`) rather than cloning. If shared ownership is
/// needed across threads, consider wrapping in `Arc<SecurityConfig>`.
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
///     .with_max_file_size(exarch_core::non_zero!(100 * 1024 * 1024))
///     .with_max_total_size(exarch_core::non_zero!(1024 * 1024 * 1024))
///     .with_allow_symlinks(true);
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SecurityConfig {
    /// Maximum size for a single file in bytes.
    pub max_file_size: Limit<NonZeroU64>,

    /// Maximum total size for all extracted files in bytes.
    pub max_total_size: Limit<NonZeroU64>,

    /// Maximum compression ratio allowed (uncompressed / compressed).
    pub max_compression_ratio: RatioLimit,

    /// Maximum number of entries that can be extracted.
    ///
    /// The extraction API counts files, symlinks and hardlinks, not
    /// directories. `list` and `verify`, and the CLI's `extract` (which lists
    /// the archive first), count every entry.
    pub max_file_count: Limit<NonZeroUsize>,

    /// Maximum path depth allowed.
    pub max_path_depth: NonZeroUsize,

    /// Feature flags controlling what archive features are allowed.
    ///
    /// Use this to enable symlinks, hardlinks, absolute paths, etc.
    pub allowed: AllowedFeatures,

    /// Preserve file permissions from archive.
    pub preserve_permissions: bool,

    /// List of allowed file extensions (empty = allow all).
    ///
    /// Extensions are matched case-insensitively (e.g., `txt` matches both
    /// `file.txt` and `file.TXT`); [`Extension`] normalizes a leading dot away.
    ///
    /// When this list is non-empty, files without a file extension are treated
    /// as not allowed and will be skipped during extraction.
    pub allowed_extensions: Vec<Extension>,

    /// List of banned path components (e.g., ".git", ".ssh").
    pub banned_path_components: Vec<PathComponentName>,

    /// Whether solid 7z archives are extracted, and under which limits.
    ///
    /// Solid archives compress multiple files together as a single block.
    /// While this provides better compression ratios, it has security
    /// implications:
    ///
    /// - **Denial of service**: a malicious archive can declare very large
    ///   solid blocks that exhaust CPU time and disk space
    /// - **Decoded volume**: the block limit bounds the decoded size of the
    ///   archive's files, not resident memory; decoding streams, and the memory
    ///   of parallel decoding is bounded by
    ///   [`parallel_decode`](Self::parallel_decode)
    ///
    /// **Security Recommendation**: Only enable for trusted archives.
    ///
    /// Default: [`SolidArchives::Refuse`] (solid archives rejected). The limits
    /// of an admitted policy default to [`SolidLimits::DEFAULT`] (512 MiB,
    /// ratio 1000).
    pub solid_archives: SolidArchives,

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
    /// - Also caps the decoded bytes that follow the end-of-archive marker of a
    ///   compressed TAR, which extraction, listing and `verify` with integrity
    ///   read to the end of the stream so the codec's trailer (a gzip CRC) is
    ///   checked. That cap never falls below 1 MiB (it covers `tar -b 2048`
    ///   record padding), so lowering this value under 1 MiB does not tighten
    ///   it; a longer tail is refused naming the effective cap
    ///
    /// Default: 4 MiB (4,194,304 bytes)
    pub max_tar_metadata_bytes: NonZeroU64,

    /// Maximum memory in bytes a decoder may use for its dictionary or window.
    ///
    /// The xz block header declares the LZMA2 dictionary size (up to 4 GiB)
    /// and a zstd frame header declares its window (up to 2^41 bytes), so
    /// without a limit a tiny archive can drive resident memory far beyond
    /// what the output quotas allow. Archives that need more fail with
    /// `QuotaExceeded { DecoderMemory }`.
    ///
    /// - xz: bounds the decoder's dictionary and state; applies to `extract`,
    ///   `list` and `verify` of `.tar.xz`.
    /// - zstd: bounds the window to the largest power of two at or below this
    ///   value, at most 128 MiB (libzstd's own ceiling), so a limit of 3 MiB
    ///   admits windows up to 2 MiB. It applies to `.tar.zst` and to ZIP
    ///   entries, which are checked from their frame headers: a ZIP archive
    ///   with a larger window is refused by `extract`, `list` and `verify`
    ///   before any entry is listed or extracted. Windows of 1 KiB or less are
    ///   always admitted, and the decoder's fixed state is not counted.
    /// - 7z: also admits the 7z decoder window; the lookahead of parallel 7z
    ///   decoding is budgeted separately by
    ///   [`parallel_decode`](Self::parallel_decode).
    ///
    /// Other codecs are bounded by their format (bzip2 blocks of at most
    /// 900 KB). Not exposed through the CLI or language bindings.
    ///
    /// Default: 256 MiB (268,435,456 bytes)
    pub max_decoder_memory: NonZeroU64,

    /// Base number of gzip members or bzip2 streams a compressed TAR may hold.
    ///
    /// `gzip -dc` and `bzip2 -dc` decode every member, and each costs a decoder
    /// setup, so a stream of empty members would burn time without producing
    /// output the size quotas could count. Member `n` may start only while
    /// `n <= allowance`, where `allowance = compressed_member_allowance +
    /// decoded_bytes / 16 KiB`; a stream that starts a member beyond that
    /// fails with `QuotaExceeded { CompressedMembers }`. The output term lets
    /// writers that flush a member per record (bgzf blocks are at most 64 KiB)
    /// pass at any output size, provided they average 16 KiB or more per
    /// member. A gzip or bzip2 stream averaging less than that over large
    /// outputs must raise this value. Applies to `extract`, `list` and
    /// `verify` of `.tar.gz` and `.tar.bz2`; xz and zstd are not governed by
    /// it. Not exposed through the CLI or language bindings.
    ///
    /// Default: 10,000 (100,000 for [`SecurityConfig::permissive`])
    pub compressed_member_allowance: NonZeroU64,

    /// Lookahead memory for decoding independent LZMA2 runs of a 7z block on
    /// worker threads.
    ///
    /// Applies to `extract` and `verify` with integrity checking of 7z
    /// archives. It is separate from `max_decoder_memory`, which keeps
    /// bounding the decoder window. See [`ParallelDecode`].
    ///
    /// Default: `Bounded` at 128 MiB (1 GiB for [`SecurityConfig::permissive`])
    pub parallel_decode: ParallelDecode,

    /// How ZIP archives with ambiguous structure are handled.
    ///
    /// Default: [`ZipConsistencyPolicy::Enforce`], including for
    /// [`SecurityConfig::permissive`]. Pre-ZIP64 archives with more than
    /// 65535 entries (wrapped end-record count) and archives with orphaned
    /// local headers, or with a central directory signature in a gap before an
    /// entry (left by in-place updaters), are rejected under `Enforce`.
    pub zip_consistency: ZipConsistencyPolicy,
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
    /// - `allowed`: All features refused (deny-by-default)
    /// - `preserve_permissions`: false
    /// - `allowed_extensions`: empty (allow all)
    /// - `banned_path_components`: `[".git", ".ssh", ".gnupg", ".aws", ".kube",
    ///   ".docker", ".env"]`
    /// - `solid_archives`: [`SolidArchives::Refuse`] (solid archives rejected)
    /// - `max_tar_metadata_bytes`: 4 MiB
    /// - `max_decoder_memory`: 256 MiB
    /// - `compressed_member_allowance`: 10,000
    /// - `parallel_decode`: `Bounded` at 128 MiB
    /// - `zip_consistency`: `Enforce`
    fn default() -> Self {
        Self {
            max_file_size: Limit::Bounded(non_zero!(50 * 1024 * 1024)), // 50 MB
            max_total_size: Limit::Bounded(non_zero!(500 * 1024 * 1024)), // 500 MB
            max_compression_ratio: crate::ratio_limit!(100.0),
            max_file_count: Limit::Bounded(non_zero!(10_000)),
            max_path_depth: non_zero!(32),
            allowed: AllowedFeatures::default(), // All false
            preserve_permissions: false,
            allowed_extensions: Vec::new(),
            banned_path_components: default_banned_path_components(),
            solid_archives: SolidArchives::Refuse,
            max_tar_metadata_bytes: non_zero!(4 * 1024 * 1024), // 4 MiB
            max_decoder_memory: non_zero!(256 * 1024 * 1024),   // 256 MiB
            compressed_member_allowance: DEFAULT_MEMBER_ALLOWANCE,
            parallel_decode: ParallelDecode::Bounded(ParallelDecode::DEFAULT_BYTES),
            zip_consistency: ZipConsistencyPolicy::Enforce,
        }
    }
}

/// Lookahead memory of [`SecurityConfig::permissive`]: 1 GiB.
const PERMISSIVE_PARALLEL_DECODE: NonZeroU64 = non_zero!(1024 * 1024 * 1024);

impl SecurityConfig {
    /// Creates a permissive configuration for trusted archives.
    ///
    /// This configuration allows symlinks, hardlinks, absolute paths, and
    /// solid archives. Use only when extracting archives from trusted sources.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            allowed: AllowedFeatures {
                symlinks: Admit::Allow,
                hardlinks: Admit::Allow,
                absolute_paths: Admit::Allow,
                world_writable: Admit::Allow,
                windows_reserved_names: Admit::Refuse,
            },
            preserve_permissions: true,
            max_compression_ratio: crate::ratio_limit!(1000.0),
            banned_path_components: Vec::new(),
            solid_archives: SolidArchives::Allow(SolidLimits::PERMISSIVE),
            max_tar_metadata_bytes: non_zero!(16 * 1024 * 1024), // 16 MiB for permissive
            max_decoder_memory: non_zero!(1024 * 1024 * 1024),   // 1 GiB for permissive
            compressed_member_allowance: non_zero!(100_000),
            parallel_decode: ParallelDecode::Bounded(PERMISSIVE_PARALLEL_DECODE),
            ..Self::default()
        }
    }

    /// Sets the maximum size for a single extracted file in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config =
    ///     SecurityConfig::default().with_max_file_size(exarch_core::non_zero!(100 * 1024 * 1024));
    /// assert!(config.max_file_size.admits(100 * 1024 * 1024));
    /// ```
    #[must_use]
    #[inline]
    pub fn with_max_file_size(mut self, size: impl Into<Limit<NonZeroU64>>) -> Self {
        self.max_file_size = size.into();
        self
    }

    /// Sets the maximum total size for all extracted files in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config =
    ///     SecurityConfig::default().with_max_total_size(exarch_core::non_zero!(1024 * 1024 * 1024));
    /// assert_eq!(config.max_total_size.ceiling(), 1024 * 1024 * 1024);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_max_total_size(mut self, size: impl Into<Limit<NonZeroU64>>) -> Self {
        self.max_total_size = size.into();
        self
    }

    /// Sets the maximum allowed compression ratio (uncompressed / compressed).
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config =
    ///     SecurityConfig::default().with_max_compression_ratio(exarch_core::ratio_limit!(50.0));
    /// assert_eq!(config.max_compression_ratio.get(), 50.0);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_max_compression_ratio(mut self, ratio: RatioLimit) -> Self {
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
    /// let config = SecurityConfig::default().with_max_file_count(exarch_core::non_zero!(500));
    /// assert_eq!(config.max_file_count.ceiling(), 500);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_max_file_count(mut self, count: impl Into<Limit<NonZeroUsize>>) -> Self {
        self.max_file_count = count.into();
        self
    }

    /// Sets the maximum path depth allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default().with_max_path_depth(exarch_core::non_zero!(16));
    /// assert_eq!(config.max_path_depth.get(), 16);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_max_path_depth(mut self, depth: NonZeroUsize) -> Self {
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
    /// assert!(!config.allowed.symlinks.is_allowed());
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
    /// assert!(config.allowed.symlinks.is_allowed());
    /// ```
    #[must_use]
    #[inline]
    pub fn with_allow_symlinks(mut self, allow: bool) -> Self {
        self.allowed.symlinks = Admit::from_allowed(allow);
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
    /// assert!(config.allowed.hardlinks.is_allowed());
    /// ```
    #[must_use]
    #[inline]
    pub fn with_allow_hardlinks(mut self, allow: bool) -> Self {
        self.allowed.hardlinks = Admit::from_allowed(allow);
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
    /// assert!(config.allowed.absolute_paths.is_allowed());
    /// ```
    #[must_use]
    #[inline]
    pub fn with_allow_absolute_paths(mut self, allow: bool) -> Self {
        self.allowed.absolute_paths = Admit::from_allowed(allow);
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
    /// assert!(config.allowed.world_writable.is_allowed());
    /// ```
    #[must_use]
    #[inline]
    pub fn with_allow_world_writable(mut self, allow: bool) -> Self {
        self.allowed.world_writable = Admit::from_allowed(allow);
        self
    }

    /// Enables or disables Windows reserved device names (`CON`, `NUL`,
    /// `COM1`, ...) as path components. Only consulted on Windows.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default().with_allow_windows_reserved_names(true);
    /// assert!(config.allowed.windows_reserved_names.is_allowed());
    /// ```
    #[must_use]
    #[inline]
    pub fn with_allow_windows_reserved_names(mut self, allow: bool) -> Self {
        self.allowed.windows_reserved_names = Admit::from_allowed(allow);
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
    ///     .try_add_allowed_extension(".txt")?
    ///     .try_add_allowed_extension("pdf")?;
    /// assert!(config.is_extension_allowed(Some("txt")));
    /// assert!(!config.is_extension_allowed(Some("exe")));
    /// # Ok::<(), exarch_core::ArchiveError>(())
    /// ```
    #[must_use]
    #[inline]
    pub fn with_allowed_extensions(mut self, extensions: Vec<Extension>) -> Self {
        self.allowed_extensions = extensions;
        self
    }

    /// Appends one allowed extension, parsed by [`Extension`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::ArchiveError::InvalidConfiguration`] when `extension`
    /// is not a usable extension.
    pub fn try_add_allowed_extension(mut self, extension: &str) -> crate::Result<Self> {
        self.allowed_extensions
            .push(Extension::try_from(extension)?);
        Ok(self)
    }

    /// Appends one banned path component, parsed by [`PathComponentName`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::ArchiveError::InvalidConfiguration`] when `component`
    /// is not a usable path component name.
    pub fn try_add_banned_path_component(mut self, component: &str) -> crate::Result<Self> {
        self.banned_path_components
            .push(PathComponentName::try_from(component)?);
        Ok(self)
    }

    /// Sets the list of banned path components.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default()
    ///     .with_banned_path_components(Vec::new())
    ///     .try_add_banned_path_component(".git")?;
    /// assert!(!config.is_path_component_allowed(".git"));
    /// assert!(config.is_path_component_allowed(".ssh"));
    /// # Ok::<(), exarch_core::ArchiveError>(())
    /// ```
    #[must_use]
    #[inline]
    pub fn with_banned_path_components(mut self, components: Vec<PathComponentName>) -> Self {
        self.banned_path_components = components;
        self
    }

    /// Sets the solid 7z archive policy together with its limits.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    /// use exarch_core::SolidArchives;
    /// use exarch_core::SolidLimits;
    ///
    /// let limits = SolidLimits::DEFAULT.with_max_block_memory(exarch_core::non_zero!(1 << 30));
    /// let config = SecurityConfig::default().with_solid_archives(SolidArchives::Allow(limits));
    /// assert_eq!(config.solid_archives.limits(), Some(limits));
    /// ```
    #[must_use]
    #[inline]
    pub fn with_solid_archives(mut self, solid: SolidArchives) -> Self {
        self.solid_archives = solid;
        self
    }

    /// Enables or disables extraction from solid 7z archives.
    ///
    /// `true` keeps the limits of an already admitted policy and otherwise
    /// admits solid archives under [`SolidLimits::DEFAULT`]; a previous
    /// [`Refuse`](SolidArchives::Refuse) therefore never carries limits over.
    /// `false` refuses solid archives and drops any limits.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default().with_allow_solid_archives(true);
    /// assert!(config.solid_archives.is_allowed());
    /// ```
    #[must_use]
    #[inline]
    pub fn with_allow_solid_archives(mut self, allow: bool) -> Self {
        self.solid_archives = self.solid_archives.with_allowed(allow);
        self
    }

    /// Sets the limits of an already admitted solid archive policy.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ArchiveError::InvalidConfiguration`] naming
    /// [`ConfigSetting::MaxSolidBlockMemory`] when solid archives are refused,
    /// because the limits would be silently ignored.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    /// use exarch_core::SolidLimits;
    ///
    /// let limits = SolidLimits::DEFAULT.with_max_block_memory(exarch_core::non_zero!(1 << 30));
    /// assert!(SecurityConfig::default().with_solid_limits(limits).is_err());
    ///
    /// let config = SecurityConfig::default()
    ///     .with_allow_solid_archives(true)
    ///     .with_solid_limits(limits)?;
    /// assert_eq!(config.solid_archives.limits(), Some(limits));
    /// # Ok::<(), exarch_core::ArchiveError>(())
    /// ```
    pub fn with_solid_limits(mut self, limits: SolidLimits) -> crate::Result<Self> {
        self.solid_archives = self.solid_archives.with_limits(limits)?;
        Ok(self)
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
    /// let config =
    ///     SecurityConfig::default().with_max_tar_metadata_bytes(exarch_core::non_zero!(64 * 1024));
    /// assert_eq!(config.max_tar_metadata_bytes.get(), 64 * 1024);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_max_tar_metadata_bytes(mut self, size: NonZeroU64) -> Self {
        self.max_tar_metadata_bytes = size;
        self
    }

    /// Sets the maximum memory a decoder may use, in bytes: the xz
    /// dictionary, and the zstd window as the largest power of two within it.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config =
    ///     SecurityConfig::default().with_max_decoder_memory(exarch_core::non_zero!(64 * 1024 * 1024));
    /// assert_eq!(config.max_decoder_memory.get(), 64 * 1024 * 1024);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_max_decoder_memory(mut self, size: NonZeroU64) -> Self {
        self.max_decoder_memory = size;
        self
    }

    /// Sets the base number of gzip members or bzip2 streams a compressed TAR
    /// may hold, before the allowance of one more per 16 KiB of output.
    ///
    /// See [`compressed_member_allowance`](SecurityConfig::compressed_member_allowance).
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// use std::num::NonZeroU64;
    ///
    /// let base = NonZeroU64::new(50_000).unwrap();
    /// let config = SecurityConfig::default().with_compressed_member_allowance(base);
    /// assert_eq!(config.compressed_member_allowance, base);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_compressed_member_allowance(mut self, base: NonZeroU64) -> Self {
        self.compressed_member_allowance = base;
        self
    }

    /// Sets the lookahead memory for parallel 7z LZMA2 decoding.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ParallelDecode;
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default().with_parallel_decode(ParallelDecode::Sequential);
    /// assert_eq!(config.parallel_decode, ParallelDecode::Sequential);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_parallel_decode(mut self, mode: ParallelDecode) -> Self {
        self.parallel_decode = mode;
        self
    }

    /// Sets how ZIP archives with ambiguous structure are handled.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    /// use exarch_core::ZipConsistencyPolicy;
    ///
    /// let config = SecurityConfig::default().with_zip_consistency(ZipConsistencyPolicy::Ignore);
    /// assert_eq!(config.zip_consistency, ZipConsistencyPolicy::Ignore);
    /// ```
    #[must_use]
    #[inline]
    pub fn with_zip_consistency(mut self, policy: ZipConsistencyPolicy) -> Self {
        self.zip_consistency = policy;
        self
    }
}

/// Read-only queries.
impl SecurityConfig {
    /// Validates whether a path component is allowed.
    ///
    /// Comparison is case-insensitive to prevent bypass on case-insensitive
    /// filesystems (Windows, macOS default).
    #[must_use]
    pub fn is_path_component_allowed(&self, component: &str) -> bool {
        !self
            .banned_path_components
            .iter()
            .any(|banned| banned.matches(component))
    }

    /// Returns `true` if a file with the given optional extension may be
    /// extracted.
    ///
    /// When `allowed_extensions` is empty, all files are permitted. When it is
    /// non-empty, only listed extensions are permitted (ignoring ASCII case),
    /// and `extension` being `None` (the file has no extension) is not
    /// allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityConfig;
    ///
    /// let config = SecurityConfig::default().try_add_allowed_extension("txt")?;
    ///
    /// assert!(config.is_extension_allowed(Some("txt")));
    /// assert!(!config.is_extension_allowed(Some("exe")));
    /// // Files without an extension are blocked when the allowlist is non-empty.
    /// assert!(!config.is_extension_allowed(None));
    ///
    /// // Empty allowlist permits everything, including extension-less files.
    /// let permissive = SecurityConfig::default();
    /// assert!(permissive.is_extension_allowed(None));
    /// # Ok::<(), exarch_core::ArchiveError>(())
    /// ```
    #[must_use]
    pub fn is_extension_allowed(&self, extension: Option<&str>) -> bool {
        self.allowed_extensions.is_empty()
            || extension.is_some_and(|ext| self.allowed_extensions.iter().any(|a| a.matches(ext)))
    }

    /// The config of a list pass that precedes extraction: the same quota,
    /// path, allowlist and decoder limits, with the flags that only matter once
    /// bytes are written reset to their deny-by-default values.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "first caller arrives with the request API")
    )]
    pub(crate) fn for_listing(&self) -> Self {
        let mut listing = self.clone();
        listing.allowed.symlinks = Admit::Refuse;
        listing.allowed.hardlinks = Admit::Refuse;
        listing.allowed.world_writable = Admit::Refuse;
        listing.preserve_permissions = false;
        listing
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

    /// Where a ZIP extraction keeps the output its structural check already
    /// decoded, so deflate entries are decoded once instead of twice.
    ///
    /// Defaults to [`DecodeReuse::Memory`] with [`ReuseLimit::DEFAULT`]. Only
    /// extractions that write into a directory use it; see [`DecodeReuse`].
    pub decode_reuse: DecodeReuse,
}

impl Default for ExtractionOptions {
    fn default() -> Self {
        Self {
            atomic: false,
            skip_duplicates: true,
            decode_reuse: DecodeReuse::default(),
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

    /// Chooses where ZIP extraction keeps the census output for reuse.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::DecodeReuse;
    /// use exarch_core::ExtractionOptions;
    ///
    /// let opts = ExtractionOptions::default().with_decode_reuse(DecodeReuse::Off);
    /// assert_eq!(opts.decode_reuse, DecodeReuse::Off);
    /// ```
    #[must_use]
    #[inline]
    pub const fn with_decode_reuse(mut self, reuse: DecodeReuse) -> Self {
        self.decode_reuse = reuse;
        self
    }
}

/// The most decoded bytes a ZIP extraction keeps for reuse.
///
/// The structural check of a ZIP archive decodes deflate entries to find where
/// their streams end, and extraction would decode them again. With a
/// [`DecodeReuse`] mode other than `Off`, the check keeps what it decoded, up
/// to this limit, and extraction writes the kept bytes instead.
///
/// # Examples
///
/// ```
/// use std::num::NonZeroU64;
///
/// use exarch_core::ReuseLimit;
///
/// let limit = ReuseLimit::new(NonZeroU64::MIN);
/// assert_eq!(limit.get(), 1);
/// assert_eq!(
///     ReuseLimit::new(NonZeroU64::MAX).get(),
///     ReuseLimit::MAX.get()
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReuseLimit(NonZeroU64);

impl ReuseLimit {
    /// 32 MiB: covers a typical source archive and stays below the
    /// per-extraction decoder ceilings.
    pub const DEFAULT: Self = Self(non_zero!(32 * 1024 * 1024));
    /// 256 MiB, the most the structural check decodes in its first pass.
    pub const MAX: Self = Self(non_zero!(256 * 1024 * 1024));
    pub(crate) const MAX_BYTES: u64 = Self::MAX.0.get();

    /// A limit of `bytes`, clamped to [`ReuseLimit::MAX`].
    #[must_use]
    pub const fn new(bytes: NonZeroU64) -> Self {
        if bytes.get() > Self::MAX_BYTES {
            Self::MAX
        } else {
            Self(bytes)
        }
    }

    /// The limit in bytes.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Where a ZIP extraction keeps decoded output between the structural check and
/// the write, so a deflate entry is decoded once.
///
/// The check that refuses entry data past a stream end decodes each deflate
/// entry, and extraction decodes it again. A kept entry is checked against its
/// CRC-32 again when it is read back, so a damaged store is refused like a
/// damaged archive, and an entry that was not kept is decoded from the archive
/// as before.
///
/// The bytes kept never exceed the smallest of the mode's [`ReuseLimit`], the
/// config's `max_decoder_memory` and its `max_total_size`, and an entry that
/// `max_file_size` or `max_compression_ratio` would refuse is not kept, so a
/// memory-capped container can lower `max_decoder_memory` to bound the cost.
///
/// Reuse applies to extractions that write into a directory
/// ([`extract_archive`](crate::extract_archive) and
/// [`ListedArchive::extract`](crate::ListedArchive::extract)). Sink and
/// callback extraction keeps output only when
/// [`SinkOptions::decode_reuse`](crate::SinkOptions::decode_reuse) opts in, and
/// defaults to `Off`; listing and verification never keep output. Bzip2 and
/// zstd entries are always decoded twice.
///
/// An entry above the mode's [`ReuseLimit`] is decoded twice whatever the mode
/// is: the default [`ReuseLimit::DEFAULT`] of 32 MiB leaves a larger member
/// decoded twice under [`extract_archive`](crate::extract_archive). With
/// `TempFile` the plaintext of the kept entries sits in the temporary
/// directory until the extraction ends, and the limit bounds only the store,
/// not the memory the entry being written uses on top of it.
///
/// # Examples
///
/// ```
/// use exarch_core::DecodeReuse;
/// use exarch_core::ReuseLimit;
///
/// assert_eq!(
///     DecodeReuse::default(),
///     DecodeReuse::Memory(ReuseLimit::DEFAULT)
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeReuse {
    /// Keep nothing; every entry is decoded twice.
    Off,
    /// Keep decoded entries in memory, up to the limit.
    ///
    /// Works on every target and writes nothing outside the destination.
    Memory(ReuseLimit),
    /// Keep decoded entries in an unnamed temporary file, up to the limit.
    ///
    /// The file lives in the platform's temporary directory (memory on a
    /// tmpfs, so it is RAM there) and holds the plaintext of the archive until
    /// the extraction ends. When no temporary file can be created, or on WASI,
    /// nothing is kept.
    ///
    /// Writing the spool and reading it back is paid in kernel time on every
    /// byte kept. Measured (2026-11, macOS, release CLI, a shared host at a
    /// load average of 5 to 12, deflate ZIPs of 10 MiB members at a
    /// compression ratio of about 2.2): 1.15x the wall time of the build
    /// before decode reuse for an archive of 100 MiB decoded (a 47 MB ZIP)
    /// and 1.18x for 300 MiB decoded (a 140 MB ZIP). Most of the excess is
    /// system time; user time rose by about 0.05 s of the 0.13 s excess on the
    /// larger archive. [`Memory`](Self::Memory) measures 1.07x on the 100 MiB
    /// one.
    TempFile(ReuseLimit),
}

impl Default for DecodeReuse {
    fn default() -> Self {
        Self::Memory(ReuseLimit::DEFAULT)
    }
}

/// Upper bound on the bytes `verify` decodes to check payload integrity.
///
/// The budget bounds the work done **beyond what listing already does**: ZIP
/// entries and 7z blocks are charged their declared uncompressed size before
/// they are decoded. TAR entry content is never charged because listing
/// decodes it anyway, and neither is the compressed TAR tail after the end
/// marker: that read is bounded by `max_tar_metadata_bytes` (at least 1 MiB)
/// instead. The default is a fixed 500 MiB, equal to the default
/// `max_total_size`; it does not follow a raised `max_total_size`.
///
/// # Examples
///
/// ```
/// use exarch_core::DecompressionBudget;
///
/// assert!(DecompressionBudget::try_from_bytes(0).is_err());
/// let budget = DecompressionBudget::try_from_bytes(1024)?;
/// assert_eq!(budget.get(), 1024);
/// assert_eq!(DecompressionBudget::default(), DecompressionBudget::DEFAULT);
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DecompressionBudget(std::num::NonZeroU64);

impl DecompressionBudget {
    /// The default budget: 500 MiB.
    pub const DEFAULT: Self = Self(non_zero!(500 * 1024 * 1024));

    /// Creates a budget from a non-zero byte count.
    #[must_use]
    pub const fn new(bytes: std::num::NonZeroU64) -> Self {
        Self(bytes)
    }

    /// Creates a budget from a byte count.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidConfiguration`](crate::ArchiveError) when
    /// `bytes` is zero.
    pub fn try_from_bytes(bytes: u64) -> crate::Result<Self> {
        non_zero_u64(ConfigSetting::DecompressionBudget, bytes).map(Self)
    }

    /// Returns the budget in bytes.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl Default for DecompressionBudget {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Whether `verify` checks payload integrity.
///
/// A budget without the check is unrepresentable: the budget lives inside the
/// [`DecodeToEof`](Self::DecodeToEof) variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum IntegrityCheck {
    /// Metadata-only verification (the default).
    #[default]
    Skip,

    /// Decode payload to the decoder's EOF so checksums and codec framing are
    /// verified, spending at most the given budget on extra decoding.
    DecodeToEof(DecompressionBudget),
}

/// Options controlling `verify` behavior.
///
/// # Examples
///
/// ```
/// use exarch_core::DecompressionBudget;
/// use exarch_core::IntegrityCheck;
/// use exarch_core::VerificationOptions;
///
/// let options = VerificationOptions::default();
/// assert_eq!(options.integrity, IntegrityCheck::Skip);
///
/// let options = options.with_integrity(IntegrityCheck::DecodeToEof(DecompressionBudget::DEFAULT));
/// assert_ne!(options.integrity, IntegrityCheck::Skip);
/// ```
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct VerificationOptions {
    /// Payload integrity check mode.
    pub integrity: IntegrityCheck,
}

impl VerificationOptions {
    /// Sets the payload integrity check mode.
    #[must_use]
    pub fn with_integrity(mut self, integrity: IntegrityCheck) -> Self {
        self.integrity = integrity;
        self
    }
}

/// Whether listing reads the symlink targets a format keeps in compressed
/// entry data.
///
/// 7z keeps link targets in compressed entry data, so reading them decodes
/// part of the archive, which in a solid block can be most of it. Listing
/// therefore skips them by default. Other formats always report their targets:
/// TAR keeps them in headers, and ZIP reads them from a small local entry. This
/// is a Rust API option only; the Python and Node `list_archive` skip 7z
/// targets.
///
/// # Examples
///
/// ```
/// use exarch_core::StoredTargets;
///
/// assert_eq!(StoredTargets::default(), StoredTargets::Skip);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum StoredTargets {
    /// Leave 7z link targets unread, so listing decodes no entry data (the
    /// default).
    #[default]
    Skip,

    /// Read the targets, decoding the blocks that hold them.
    Read,
}

/// Options controlling `list` behavior.
///
/// # Examples
///
/// ```
/// use exarch_core::ListOptions;
/// use exarch_core::StoredTargets;
///
/// let options = ListOptions::default();
/// assert_eq!(options.stored_targets, StoredTargets::Skip);
///
/// let options = options.with_stored_targets(StoredTargets::Read);
/// assert_eq!(options.stored_targets, StoredTargets::Read);
/// ```
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct ListOptions {
    /// Whether to read the link targets a format keeps in entry data.
    pub stored_targets: StoredTargets,
}

impl ListOptions {
    /// Sets whether link targets kept in entry data are read.
    #[must_use]
    pub fn with_stored_targets(mut self, stored_targets: StoredTargets) -> Self {
        self.stored_targets = stored_targets;
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
    use std::assert_matches;

    use super::*;

    #[test]
    fn test_default_config() {
        let config = SecurityConfig::default();
        assert!(!config.allowed.symlinks.is_allowed());
        assert!(!config.allowed.hardlinks.is_allowed());
        assert!(!config.allowed.absolute_paths.is_allowed());
        assert_eq!(config.max_file_size.ceiling(), 50 * 1024 * 1024);
    }

    #[test]
    fn test_permissive_config() {
        let config = SecurityConfig::permissive();
        assert!(config.allowed.symlinks.is_allowed());
        assert!(config.allowed.hardlinks.is_allowed());
        assert!(config.allowed.absolute_paths.is_allowed());
    }

    #[test]
    fn test_extension_allowed_empty_list() {
        let config = SecurityConfig::default();
        assert!(config.is_extension_allowed(Some("txt")));
        assert!(config.is_extension_allowed(Some("pdf")));
    }

    #[test]
    fn test_extension_allowed_with_list() {
        let mut config = SecurityConfig::default();
        config.allowed_extensions = vec![
            Extension::try_from("txt").unwrap(),
            Extension::try_from("pdf").unwrap(),
        ];
        assert!(config.is_extension_allowed(Some("txt")));
        assert!(config.is_extension_allowed(Some("TXT")));
        assert!(!config.is_extension_allowed(Some("exe")));
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

        // All security-sensitive flags should be false by default
        // (deny-by-default)
        assert!(
            !config.allowed.symlinks.is_allowed(),
            "symlinks should be denied by default"
        );
        assert!(
            !config.allowed.hardlinks.is_allowed(),
            "hardlinks should be denied by default"
        );
        assert!(
            !config.allowed.absolute_paths.is_allowed(),
            "absolute paths should be denied by default"
        );
        assert!(
            !config.preserve_permissions,
            "permissions should not be preserved by default"
        );
        assert!(
            !config.allowed.world_writable.is_allowed(),
            "world-writable should be denied by default"
        );
    }

    #[test]
    fn test_config_permissive_security_flags() {
        let config = SecurityConfig::permissive();

        // Permissive config should allow all features
        assert!(
            config.allowed.symlinks.is_allowed(),
            "permissive allows symlinks"
        );
        assert!(
            config.allowed.hardlinks.is_allowed(),
            "permissive allows hardlinks"
        );
        assert!(
            config.allowed.absolute_paths.is_allowed(),
            "permissive allows absolute paths"
        );
        assert!(
            config.preserve_permissions,
            "permissive preserves permissions"
        );
        assert!(
            config.allowed.world_writable.is_allowed(),
            "permissive allows world-writable"
        );
    }

    #[test]
    fn test_config_quota_limits() {
        let config = SecurityConfig::default();

        // Verify default quota values are sensible
        assert_eq!(
            config.max_file_size.ceiling(),
            50 * 1024 * 1024,
            "50 MB file limit"
        );
        assert_eq!(
            config.max_total_size.ceiling(),
            500 * 1024 * 1024,
            "500 MB total limit"
        );
        assert_eq!(
            config.max_file_count.ceiling(),
            10_000,
            "10k file count limit"
        );
        assert_eq!(config.max_path_depth.get(), 32, "32 level depth limit");
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(
                config.max_compression_ratio.get(),
                100.0,
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
            config
                .banned_path_components
                .contains(&PathComponentName::try_from(".git").unwrap()),
            "should ban .git"
        );
        assert!(
            config
                .banned_path_components
                .contains(&PathComponentName::try_from(".ssh").unwrap()),
            "should ban .ssh"
        );
    }

    #[test]
    fn test_config_solid_archives_default() {
        let config = SecurityConfig::default();

        // Solid archives should be denied by default (security)
        assert_eq!(
            config.solid_archives,
            SolidArchives::Refuse,
            "solid archives should be denied by default"
        );
        assert_eq!(
            SolidLimits::DEFAULT.max_block_memory.get(),
            512 * 1024 * 1024,
            "max solid block memory should be 512 MB"
        );
    }

    #[test]
    fn test_config_permissive_solid_archives() {
        let config = SecurityConfig::permissive();

        // Permissive config should allow solid archives
        assert_eq!(
            config.solid_archives,
            SolidArchives::Allow(SolidLimits::PERMISSIVE),
            "permissive config should allow solid archives"
        );
        assert_eq!(
            SolidLimits::PERMISSIVE.max_block_memory.get(),
            1024 * 1024 * 1024,
            "permissive should have 1 GB solid block limit"
        );
    }

    #[test]
    fn test_config_tar_metadata_bytes_default() {
        let config = SecurityConfig::default();
        assert_eq!(
            config.max_tar_metadata_bytes.get(),
            4 * 1024 * 1024,
            "max TAR metadata bytes should be 4 MiB by default"
        );
    }

    #[test]
    fn test_config_permissive_tar_metadata_bytes() {
        let config = SecurityConfig::permissive();
        assert_eq!(
            config.max_tar_metadata_bytes.get(),
            16 * 1024 * 1024,
            "permissive should have 16 MiB TAR metadata budget"
        );
    }

    #[test]
    fn test_with_max_tar_metadata_bytes_builder() {
        let config = SecurityConfig::default().with_max_tar_metadata_bytes(crate::non_zero!(2048));
        assert_eq!(config.max_tar_metadata_bytes.get(), 2048);
    }

    #[test]
    fn test_solid_compression_ratio_defaults() {
        assert_eq!(SolidLimits::DEFAULT.max_ratio.get(), 1000.0);
        assert_eq!(SolidLimits::PERMISSIVE.max_ratio.get(), 10_000.0);
    }

    #[test]
    fn allowing_solid_archives_keeps_admitted_limits_and_resets_a_refusal() {
        let custom = SolidLimits::DEFAULT.with_max_block_memory(crate::non_zero!(4096));
        let kept = SecurityConfig::default()
            .with_solid_archives(SolidArchives::Allow(custom))
            .with_allow_solid_archives(true);
        assert_eq!(kept.solid_archives, SolidArchives::Allow(custom));

        let reset = SecurityConfig::default().with_allow_solid_archives(true);
        assert_eq!(
            reset.solid_archives,
            SolidArchives::Allow(SolidLimits::DEFAULT)
        );

        let refused = SecurityConfig::default()
            .with_solid_archives(SolidArchives::Allow(custom))
            .with_allow_solid_archives(false);
        assert_eq!(refused.solid_archives, SolidArchives::Refuse);
    }

    #[test]
    fn solid_limits_cannot_be_set_while_solid_archives_are_refused() {
        let err = SecurityConfig::default()
            .with_solid_limits(SolidLimits::DEFAULT)
            .unwrap_err();
        assert_matches!(
            err,
            crate::ArchiveError::InvalidConfiguration {
                setting: ConfigSetting::MaxSolidBlockMemory,
                problem: ConfigProblem::NotSupported,
            }
        );
        let custom = SolidLimits::DEFAULT.with_max_block_memory(crate::non_zero!(4096));
        let config = SecurityConfig::default()
            .with_allow_solid_archives(true)
            .with_solid_limits(custom)
            .unwrap();
        assert_eq!(config.solid_archives.limits(), Some(custom));
    }

    #[test]
    fn admit_converts_to_and_from_a_bool() {
        assert_eq!(Admit::from_allowed(true), Admit::Allow);
        assert_eq!(Admit::from_allowed(false), Admit::Refuse);
        assert!(Admit::Allow.is_allowed());
        assert!(!Admit::Refuse.is_allowed());
        assert_eq!(Admit::default(), Admit::Refuse);
    }

    #[test]
    fn for_listing_resets_write_time_flags_only() {
        let listing = SecurityConfig::permissive().for_listing();
        assert_eq!(listing.allowed.symlinks, Admit::Refuse);
        assert_eq!(listing.allowed.hardlinks, Admit::Refuse);
        assert_eq!(listing.allowed.world_writable, Admit::Refuse);
        assert!(!listing.preserve_permissions);
        assert_eq!(listing.allowed.absolute_paths, Admit::Allow);
        assert_eq!(
            listing.solid_archives,
            SecurityConfig::permissive().solid_archives
        );
        assert_eq!(
            listing.max_decoder_memory,
            SecurityConfig::permissive().max_decoder_memory
        );
    }

    #[test]
    fn test_compressed_member_allowance_defaults() {
        assert_eq!(
            SecurityConfig::default().compressed_member_allowance.get(),
            10_000
        );
        assert_eq!(
            SecurityConfig::permissive()
                .compressed_member_allowance
                .get(),
            100_000
        );
    }

    #[test]
    fn test_parallel_decode_defaults() {
        let bytes = |config: SecurityConfig| match config.parallel_decode {
            ParallelDecode::Bounded(n) => n.get(),
            ParallelDecode::Sequential => 0,
        };
        assert_eq!(bytes(SecurityConfig::default()), 128 * 1024 * 1024);
        assert_eq!(bytes(SecurityConfig::permissive()), 1024 * 1024 * 1024);
    }

    #[test]
    fn test_max_decoder_memory_defaults() {
        assert_eq!(
            SecurityConfig::default().max_decoder_memory.get(),
            256 * 1024 * 1024
        );
        assert_eq!(
            SecurityConfig::permissive().max_decoder_memory.get(),
            1024 * 1024 * 1024
        );
    }

    // Regression tests for #449 and #871: malformed `allowed_extensions` /
    // `banned_path_components` entries are refused at construction, so a
    // config can never hold one.

    #[test]
    fn test_try_add_refuses_unusable_entries() {
        let long = "x".repeat(256);
        for raw in ["", "bad\0ext", " gz", "tar.gz", "a/b", long.as_str()] {
            assert!(
                SecurityConfig::default()
                    .try_add_allowed_extension(raw)
                    .is_err(),
                "{raw:?}"
            );
        }
        for raw in ["", "bad\0", "a/b", "..", long.as_str()] {
            assert!(
                SecurityConfig::default()
                    .try_add_banned_path_component(raw)
                    .is_err(),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn test_dotted_extension_is_normalized_and_matches_any_case() {
        let cfg = SecurityConfig::default()
            .try_add_allowed_extension(".txt")
            .unwrap();
        assert!(cfg.is_extension_allowed(Some("txt")));
        assert!(crate::formats::common::is_extension_allowed(
            std::path::Path::new("A.TXT"),
            &cfg
        ));
        assert!(cfg.is_extension_allowed(Some("TXT")));
        assert!(!cfg.is_extension_allowed(Some("md")));
    }

    #[test]
    fn default_banned_components_are_all_usable() {
        assert_eq!(
            default_banned_path_components().len(),
            DEFAULT_BANNED_PATH_COMPONENTS.len()
        );
    }
}
