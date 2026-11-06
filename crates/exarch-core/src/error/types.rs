//! Core error types for archive operations.

use std::borrow::Cow;
use std::path::PathBuf;
use thiserror::Error;

use super::config_error::ConfigProblem;
use super::config_error::ConfigSetting;
use super::malformation::Malformation;
use super::replace::ReplaceFailure;
use super::tar_ambiguity::TarAmbiguity;
use super::tar_trailer::TarTrailerRefusal;
use super::violation::Violation;
use super::zip_inconsistency::ZipInconsistency;
use crate::closed_enum::closed_enum;
use crate::security::Compressed;
use crate::security::Uncompressed;

/// Result type alias using [`ArchiveError`].
pub type Result<T> = std::result::Result<T, ArchiveError>;

closed_enum! {
    /// What a zip bomb size check was measured over.
    ///
    /// `#[non_exhaustive]` so a future measurement scope is not a breaking change
    /// for downstream matches.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ZipBombScope;
    ///
    /// assert_eq!(ZipBombScope::SolidBlock.to_string(), "solid block");
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub enum ZipBombScope {
        /// One archive entry, checked against `max_compression_ratio`.
        Entry => "entry",
        /// A whole solid block, checked against `SolidLimits::max_ratio`.
        SolidBlock => "solid block",
        /// The entries of a compressed TAR that were decoded only to be
        /// skipped, checked against `max_compression_ratio` over the input
        /// read so far.
        SkippedEntries => "skipped entries",
    }
}

closed_enum! {
    /// The `SecurityConfig` setting whose current value refused an entry.
    ///
    /// Changing it removes that refusal only: the entry can still fail a later
    /// check, for example a symlink that escapes the destination fails with
    /// [`ArchiveError::SymlinkEscape`] once symlinks are allowed. Refusals that
    /// no `SecurityConfig` value relaxes carry no `PolicySetting`.
    ///
    /// `#[non_exhaustive]` so a future relaxable setting is not a breaking
    /// change for downstream matches.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::PolicySetting;
    ///
    /// assert_eq!(PolicySetting::Symlinks.as_str(), "symlinks");
    /// assert!(PolicySetting::ALL.contains(&PolicySetting::MaxPathDepth));
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum PolicySetting {
        /// `SecurityConfig::with_allow_symlinks`.
        Symlinks => "symlinks",
        /// `SecurityConfig::with_allow_hardlinks`.
        Hardlinks => "hardlinks",
        /// `SecurityConfig::with_allow_solid_archives`.
        SolidArchives => "solid_archives",
        /// `SecurityConfig::with_banned_path_components`.
        BannedComponents => "banned_components",
        /// `SecurityConfig::with_max_path_depth`.
        MaxPathDepth => "max_path_depth",
        /// `SecurityConfig::with_allow_windows_reserved_names`.
        WindowsReservedNames => "windows_reserved_names",
        /// `SecurityConfig::with_max_tar_metadata_bytes`.
        MaxTarMetadataBytes => "max_tar_metadata_bytes",
    }
}

/// A compression level exactly as the caller asked for it.
///
/// Carries what a refused level looked like, including values a `u32` cannot
/// hold, so a front end can echo `-3`, `1.5` or `2^40` back.
///
/// # Examples
///
/// ```
/// use exarch_core::RequestedLevel;
///
/// assert_eq!(RequestedLevel::Integer(-3).to_string(), "-3");
/// assert_eq!(RequestedLevel::Fractional(1.5).to_string(), "1.5");
/// assert_eq!(RequestedLevel::NonFinite.to_string(), "a non-finite number");
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum RequestedLevel {
    /// A whole number.
    Integer(i128),
    /// A finite number with a fractional part.
    Fractional(f64),
    /// NaN or an infinity.
    NonFinite,
}

impl std::fmt::Display for RequestedLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Integer(level) => write!(f, "{level}"),
            Self::Fractional(level) => write!(f, "{level}"),
            Self::NonFinite => f.write_str("a non-finite number"),
        }
    }
}

/// Compression ratio of a checked size pair.
///
/// `Unbounded` replaces a division by zero, so a ratio is never infinite or
/// `NaN`.
///
/// # Examples
///
/// ```
/// use exarch_core::CompressionRatio;
///
/// assert_eq!(CompressionRatio::Finite(12.5).to_string(), "12.50");
/// assert_eq!(CompressionRatio::Unbounded.to_string(), "unbounded");
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompressionRatio {
    /// Uncompressed size divided by compressed size.
    Finite(f64),
    /// Data is claimed from zero compressed bytes.
    Unbounded,
}

impl std::fmt::Display for CompressionRatio {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Finite(ratio) => write!(f, "{ratio:.2}"),
            Self::Unbounded => f.write_str("unbounded"),
        }
    }
}

/// Sizes and scope of a rejected compression ratio.
///
/// The ratio is derived from the sizes, so it cannot contradict them.
///
/// # Examples
///
/// ```
/// use exarch_core::Compressed;
/// use exarch_core::CompressionRatio;
/// use exarch_core::Uncompressed;
/// use exarch_core::ZipBombDetails;
/// use exarch_core::ZipBombScope;
///
/// let details = ZipBombDetails::new(
///     ZipBombScope::Entry,
///     Compressed(1000),
///     Uncompressed(1_000_000),
/// );
/// assert_eq!(details.scope(), ZipBombScope::Entry);
/// assert_eq!(details.ratio(), CompressionRatio::Finite(1000.0));
///
/// let forged = ZipBombDetails::new(ZipBombScope::Entry, Compressed(0), Uncompressed(10));
/// assert_eq!(forged.ratio(), CompressionRatio::Unbounded);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZipBombDetails {
    scope: ZipBombScope,
    compressed: Compressed,
    uncompressed: Uncompressed,
}

impl ZipBombDetails {
    /// Creates details for a size pair measured over `scope`.
    #[must_use]
    pub const fn new(
        scope: ZipBombScope,
        compressed: Compressed,
        uncompressed: Uncompressed,
    ) -> Self {
        Self {
            scope,
            compressed,
            uncompressed,
        }
    }

    /// What the sizes were measured over.
    #[must_use]
    pub const fn scope(&self) -> ZipBombScope {
        self.scope
    }

    /// Compressed size in bytes.
    #[must_use]
    pub const fn compressed(&self) -> u64 {
        self.compressed.0
    }

    /// Uncompressed size in bytes.
    #[must_use]
    pub const fn uncompressed(&self) -> u64 {
        self.uncompressed.0
    }

    /// Compression ratio of the recorded sizes.
    #[must_use]
    #[expect(
        clippy::cast_precision_loss,
        reason = "the ratio is approximate by design"
    )]
    pub fn ratio(&self) -> CompressionRatio {
        match (self.compressed.0, self.uncompressed.0) {
            (0, 0) => CompressionRatio::Finite(0.0),
            (0, _) => CompressionRatio::Unbounded,
            (compressed, uncompressed) => {
                CompressionRatio::Finite(uncompressed as f64 / compressed as f64)
            }
        }
    }
}

impl std::fmt::Display for ZipBombDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "compressed={} bytes, uncompressed={} bytes (ratio: {}, scope: {})",
            self.compressed.0,
            self.uncompressed.0,
            self.ratio(),
            self.scope
        )
    }
}

/// Represents a specific quota resource that was exceeded.
///
/// `#[non_exhaustive]` so a future quota dimension is not a breaking change
/// for downstream matches.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum QuotaResource {
    /// File count quota exceeded.
    FileCount {
        /// Current file count.
        current: usize,
        /// Maximum allowed file count.
        max: usize,
    },
    /// Total size quota exceeded.
    TotalSize {
        /// Current total size in bytes.
        current: u64,
        /// Maximum allowed total size in bytes.
        max: u64,
    },
    /// Single file size quota exceeded.
    FileSize {
        /// File size in bytes.
        size: u64,
        /// Maximum allowed file size in bytes.
        max: u64,
    },
    /// Integer overflow detected in quota tracking.
    IntegerOverflow,
    /// Decompressor memory limit exceeded (xz dictionary and state).
    DecoderMemory {
        /// Maximum allowed decoder memory in bytes.
        max: u64,
    },
    /// A gzip or bzip2 stream holds more members than its allowance admits.
    CompressedMembers {
        /// The member that was refused, counting from one.
        members: u64,
        /// The most members the stream could have started at that point: the
        /// configured base plus one per 16 KiB of output so far.
        allowance: u64,
    },
    /// Node budget of the in-memory destination model exceeded.
    TreeNodes {
        /// Maximum allowed number of distinct names.
        max: usize,
    },
    /// Capacity of an in-memory sink exceeded.
    SinkCapacity {
        /// Maximum number of payload bytes the sink accepts.
        max: u64,
    },
    /// A solid 7z archive declares more decoded bytes than the solid block
    /// limit admits.
    SolidBlockMemory {
        /// What `current` was summed over.
        scope: SolidMemoryScope,
        /// Declared decoded size in bytes.
        current: u64,
        /// Maximum decoded size in bytes: the solid block limit.
        max: u64,
    },
}

closed_enum! {
    /// What a refused solid decoded size was summed over.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SolidMemoryScope;
    ///
    /// assert_eq!(SolidMemoryScope::Block.as_str(), "block");
    /// assert_eq!(SolidMemoryScope::ALL.len(), 2);
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub enum SolidMemoryScope {
        /// One solid block, checked against the block limit.
        Block => "block",
        /// All blocks of the archive, held to the block limit while
        /// `max_total_size` is unbounded.
        Archive => "archive",
    }
}

closed_enum! {
    /// Payload-free discriminant of a [`QuotaResource`].
    ///
    /// Front ends match on it instead of on the payload-carrying enum, and
    /// iterate [`QuotaKind::ALL`] in a test so a new quota dimension fails a
    /// test instead of silently taking a wildcard arm.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::QuotaKind;
    /// use exarch_core::QuotaResource;
    ///
    /// let resource = QuotaResource::DecoderMemory { max: 1 };
    /// assert_eq!(resource.kind(), QuotaKind::DecoderMemory);
    /// assert!(QuotaKind::ALL.contains(&QuotaKind::TreeNodes));
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub enum QuotaKind {
        /// [`QuotaResource::FileCount`].
        FileCount => "file_count",
        /// [`QuotaResource::TotalSize`].
        TotalSize => "total_size",
        /// [`QuotaResource::FileSize`].
        FileSize => "file_size",
        /// [`QuotaResource::IntegerOverflow`].
        IntegerOverflow => "integer_overflow",
        /// [`QuotaResource::DecoderMemory`].
        DecoderMemory => "decoder_memory",
        /// [`QuotaResource::CompressedMembers`].
        CompressedMembers => "compressed_members",
        /// [`QuotaResource::TreeNodes`].
        TreeNodes => "tree_nodes",
        /// [`QuotaResource::SinkCapacity`].
        SinkCapacity => "sink_capacity",
        /// [`QuotaResource::SolidBlockMemory`].
        SolidBlockMemory => "solid_block_memory",
    }
}

impl QuotaResource {
    /// The payload-free discriminant of this resource.
    #[must_use]
    pub const fn kind(&self) -> QuotaKind {
        match self {
            Self::FileCount { .. } => QuotaKind::FileCount,
            Self::TotalSize { .. } => QuotaKind::TotalSize,
            Self::FileSize { .. } => QuotaKind::FileSize,
            Self::IntegerOverflow => QuotaKind::IntegerOverflow,
            Self::DecoderMemory { .. } => QuotaKind::DecoderMemory,
            Self::CompressedMembers { .. } => QuotaKind::CompressedMembers,
            Self::TreeNodes { .. } => QuotaKind::TreeNodes,
            Self::SinkCapacity { .. } => QuotaKind::SinkCapacity,
            Self::SolidBlockMemory { .. } => QuotaKind::SolidBlockMemory,
        }
    }
}

impl std::fmt::Display for QuotaResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileCount { current, max } => {
                write!(f, "quota exceeded: file count ({current} > {max})")
            }
            Self::TotalSize { current, max } => {
                write!(f, "quota exceeded: total size ({current} > {max})")
            }
            Self::FileSize { size, max } => {
                write!(f, "quota exceeded: single file size ({size} > {max})")
            }
            Self::IntegerOverflow => {
                write!(f, "quota exceeded: integer overflow in quota tracking")
            }
            Self::DecoderMemory { max } => {
                write!(f, "quota exceeded: decoder memory (> {max} bytes)")
            }
            Self::CompressedMembers { members, allowance } => {
                write!(
                    f,
                    "quota exceeded: compressed members ({members} > allowance {allowance} = \
                     base + 1 per 16 KiB decoded)"
                )
            }
            Self::TreeNodes { max } => {
                write!(
                    f,
                    "quota exceeded: destination tree nodes (> {max}, bounded by max_file_count x max_path_depth)"
                )
            }
            Self::SinkCapacity { max } => {
                write!(f, "quota exceeded: sink capacity (> {max} bytes)")
            }
            Self::SolidBlockMemory {
                scope: SolidMemoryScope::Block,
                current,
                max,
            } => write!(f, "quota exceeded: solid block size ({current} > {max})"),
            Self::SolidBlockMemory {
                scope: SolidMemoryScope::Archive,
                current,
                max,
            } => write!(
                f,
                "quota exceeded: solid archive size over all blocks ({current} > {max})"
            ),
        }
    }
}

/// Why the format of an archive supplied as a reader could not be used.
///
/// `#[non_exhaustive]` so a future reason is not a breaking change for
/// downstream matches.
///
/// # Examples
///
/// ```
/// use exarch_core::ReaderFormatError;
/// use exarch_core::SeekableFormat;
///
/// let err = ReaderFormatError::NeedsSeek(SeekableFormat::Zip);
/// assert_eq!(err.to_string(), "zip archives need a seekable reader");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReaderFormatError {
    /// The leading bytes match no supported format.
    Unrecognized,
    /// The format is recognized but needs a seekable source.
    NeedsSeek(crate::SeekableFormat),
    /// The format is recognized but the archive does not start at the
    /// reader's start.
    NotAtStart(crate::SeekableFormat),
}

impl std::fmt::Display for ReaderFormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unrecognized => f.write_str("archive format not recognized from its content"),
            Self::NeedsSeek(format) => {
                write!(f, "{} archives need a seekable reader", format.as_str())
            }
            Self::NotAtStart(format) => write!(
                f,
                "{} archive does not start at the beginning of the reader",
                format.as_str()
            ),
        }
    }
}

/// Errors that can occur during archive operations (extraction, creation,
/// listing, verification).
///
/// `#[non_exhaustive]` so a future error variant is not a breaking change
/// for downstream matches.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ArchiveError {
    /// I/O operation failed.
    #[error("I/O error: {0}")]
    Io(std::io::Error),

    /// Archive is corrupted or invalid.
    #[error("invalid archive: {0}")]
    InvalidArchive(Malformation),

    /// A TAR header is read differently by different TAR readers.
    ///
    /// [`Self::error_code`] and the binding kind are those of
    /// [`Self::InvalidArchive`].
    #[error("invalid archive: ambiguous TAR header: {0}")]
    TarAmbiguity(TarAmbiguity),

    /// The bytes after the end-of-archive marker of a compressed TAR were
    /// refused: more than the cap, corrupt or truncated.
    ///
    /// [`Self::error_code`] and the binding kind are those of
    /// [`Self::SecurityViolation`] for an over-cap tail (relaxable by
    /// [`PolicySetting::MaxTarMetadataBytes`]) and of [`Self::InvalidArchive`]
    /// otherwise.
    #[error("{0}")]
    TarTrailer(TarTrailerRefusal),

    /// Path traversal attempt detected.
    #[error("path traversal detected: {path}")]
    PathTraversal {
        /// The path that attempted traversal.
        path: PathBuf,
    },

    /// Symlink points outside extraction directory.
    #[error("symlink target outside extraction directory: {path}")]
    SymlinkEscape {
        /// The symlink path.
        path: PathBuf,
    },

    /// Hardlink target not in extraction directory.
    #[error("hardlink target outside extraction directory: {path}")]
    HardlinkEscape {
        /// The hardlink path.
        path: PathBuf,
    },

    /// Potential zip bomb detected.
    #[error("potential zip bomb: {0}")]
    ZipBomb(ZipBombDetails),

    /// A ZIP archive is structurally ambiguous between readers.
    #[error("ZIP structure inconsistency: {0}")]
    ZipInconsistency(ZipInconsistency),

    /// File permissions are invalid or unsafe.
    #[error("invalid permissions for {path}: {:#o}", .mode.get())]
    InvalidPermissions {
        /// The file path.
        path: PathBuf,
        /// The raw permission mode as the archive recorded it.
        mode: crate::RawMode,
    },

    /// Extraction quota exceeded.
    #[error("{resource}")]
    QuotaExceeded {
        /// Description of the exceeded resource.
        resource: QuotaResource,
    },

    /// Operation not permitted by security policy.
    ///
    /// The kind fixes the message, the sub-code and the `SecurityConfig`
    /// setting that relaxes the refusal.
    #[error("operation denied by security policy: {kind}")]
    #[non_exhaustive]
    SecurityViolation {
        /// Why the operation was denied.
        kind: Violation,
    },

    /// Source path not found.
    #[error("source path not found: {path}")]
    SourceNotFound {
        /// The source path.
        path: PathBuf,
    },

    /// A creation source exists but cannot be read.
    ///
    /// Covers opening, reading, listing and resolving a source, so `error`
    /// keeps the cause (permission, I/O failure, link loop).
    #[error("source path is not accessible: {path}: {error}")]
    SourceNotAccessible {
        /// The source path.
        path: PathBuf,
        /// The failure that made the source unreadable.
        error: std::io::Error,
    },

    /// Output file already exists.
    #[error("output file already exists: {path}")]
    OutputExists {
        /// The output path.
        path: PathBuf,
    },

    /// Invalid compression level.
    #[error("invalid compression level {level}, must be 1-9")]
    InvalidCompressionLevel {
        /// The level that was asked for.
        level: RequestedLevel,
    },

    /// Cannot determine archive format.
    #[error("cannot determine archive format from: {path}")]
    UnknownFormat {
        /// The path with unknown format.
        path: PathBuf,
    },

    /// The format of an archive supplied as a reader could not be used.
    #[error("{0}")]
    ReaderFormat(ReaderFormatError),

    /// Invalid configuration provided.
    #[error("invalid configuration: {}", super::config_error::message(*setting, problem))]
    InvalidConfiguration {
        /// The setting or input that was refused.
        setting: ConfigSetting,
        /// Why it was refused.
        problem: ConfigProblem,
    },

    /// The operation was cancelled through
    /// [`ProgressCallback::is_cancelled`](crate::ProgressCallback::is_cancelled).
    ///
    /// An extraction that had already recorded progress is reported as
    /// [`Self::PartialExtraction`] wrapping this error.
    #[error("operation cancelled")]
    Cancelled,

    /// The destination holds paths that the occupied-path policy refuses to
    /// touch.
    ///
    /// Raised for [`ExistingFiles::Refuse`](crate::ExistingFiles::Refuse) and
    /// by
    /// [`ListedArchive::check_destination`](crate::ListedArchive::check_destination).
    /// `destination` is a host path and is redacted like any other.
    #[error("destination {} already holds {} of the paths to extract", .destination.display(), .conflicts.len())]
    DestinationOccupied {
        /// The extraction destination.
        destination: PathBuf,
        /// The archive-relative paths that are occupied.
        conflicts: Box<[PathBuf]>,
    },

    /// A staged creation published its archive, but an empty reservation file
    /// it made at the output path is still there.
    #[error("an empty reservation file remains at {}: {error}", .path.display())]
    OutputReservationLeft {
        /// The output path that holds the leftover file.
        path: PathBuf,
        /// The failure that left it.
        error: std::io::Error,
    },

    /// Replacing an existing destination as a whole failed.
    #[error("{0}")]
    ReplaceFailed(ReplaceFailure),

    /// Extraction stopped mid-archive after recording progress.
    ///
    /// `writes` says whether that output is still on disk
    /// ([`PartialWrites::Kept`]), was discarded by atomic rollback
    /// ([`PartialWrites::RolledBack`]), or was never written anywhere
    /// ([`PartialWrites::Discarded`]).
    #[error(transparent)]
    PartialExtraction(Partial),
}

/// An extraction that stopped after recording progress.
///
/// The cause is never itself a partial extraction: [`Partial::new`] looks
/// through one level of wrapping, so every accessor of [`ArchiveError`] can
/// look through exactly one level without recursion.
///
/// # Examples
///
/// ```
/// use exarch_core::ArchiveError;
/// use exarch_core::ExtractionReport;
/// use exarch_core::Partial;
/// use exarch_core::PartialWrites;
/// use exarch_core::Violation;
///
/// let cause = ArchiveError::from(Violation::EncryptedArchive);
/// let inner = Partial::new(cause, ExtractionReport::default(), PartialWrites::Kept);
/// let outer = Partial::new(
///     ArchiveError::PartialExtraction(inner),
///     ExtractionReport::default(),
///     PartialWrites::RolledBack,
/// );
/// assert!(!matches!(outer.cause(), ArchiveError::PartialExtraction(_)));
/// assert_eq!(outer.writes(), PartialWrites::RolledBack);
/// ```
#[derive(Debug)]
pub struct Partial {
    cause: Box<ArchiveError>,
    report: crate::ExtractionReport,
    writes: PartialWrites,
}

impl Partial {
    /// Records that `cause` stopped an extraction that had produced `report`.
    ///
    /// A `cause` that is itself a partial extraction is unwrapped first: its
    /// innermost cause is kept, `report` (the outer one, which accumulated the
    /// inner) wins, and the more severe `writes` wins, so a rollback or discard
    /// is never reported as kept.
    #[must_use]
    pub fn new(
        cause: ArchiveError,
        report: crate::ExtractionReport,
        writes: PartialWrites,
    ) -> Self {
        match cause {
            ArchiveError::PartialExtraction(inner) => Self {
                cause: inner.cause,
                report,
                writes: if writes == PartialWrites::Kept {
                    inner.writes
                } else {
                    writes
                },
            },
            other => Self {
                cause: Box::new(other),
                report,
                writes,
            },
        }
    }

    /// The original error that stopped extraction.
    #[must_use]
    pub fn cause(&self) -> &ArchiveError {
        &self.cause
    }

    /// What was written before the error.
    #[must_use]
    pub fn report(&self) -> &crate::ExtractionReport {
        &self.report
    }

    /// Whether the reported writes are still on disk.
    #[must_use]
    pub const fn writes(&self) -> PartialWrites {
        self.writes
    }

    /// Splits into the cause, the report and the fate of the writes.
    #[must_use]
    pub fn into_parts(self) -> (ArchiveError, crate::ExtractionReport, PartialWrites) {
        (*self.cause, self.report, self.writes)
    }

    fn with_writes(self, writes: PartialWrites) -> Self {
        Self { writes, ..self }
    }
}

impl std::fmt::Display for Partial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.cause.fmt(f)
    }
}

impl std::error::Error for Partial {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.cause)
    }
}

closed_enum! {
    /// Fate of the files recorded in a [`ArchiveError::PartialExtraction`] report.
    ///
    /// Atomic extraction discards its temporary directory on failure, and an
    /// in-memory extraction drops what it collected, so the report's counters
    /// describe work that no longer exists. Front ends use this state to avoid
    /// presenting those counters as leftovers.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::PartialWrites;
    ///
    /// assert_eq!(PartialWrites::Kept.as_str(), "kept");
    /// assert_eq!(PartialWrites::RolledBack.to_string(), "rolled_back");
    /// assert_eq!(PartialWrites::Discarded.as_str(), "discarded");
    /// assert_eq!(PartialWrites::ALL.len(), 3);
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum PartialWrites {
        /// The written files remain in the destination.
        Kept => "kept",
        /// Atomic extraction discarded the written files with its temporary
        /// directory.
        ///
        /// Cleanup is best effort: a failed removal can leave a `.tmp*` sibling
        /// in the destination's parent directory.
        RolledBack => "rolled_back",
        /// The extraction collected its entries in memory, wrote nothing to a
        /// destination, and dropped them with the error.
        Discarded => "discarded",
    }
}

impl From<std::io::Error> for ArchiveError {
    fn from(e: std::io::Error) -> Self {
        crate::formats::tar_metadata_limit::budget_violation(&e).unwrap_or(Self::Io(e))
    }
}

impl From<Malformation> for ArchiveError {
    fn from(malformation: Malformation) -> Self {
        Self::InvalidArchive(malformation)
    }
}

impl ArchiveError {
    /// A malformed-archive refusal that has no family of its own.
    pub(crate) fn unclassified(reason: impl Into<Box<str>>) -> Self {
        Self::InvalidArchive(Malformation::unclassified(reason))
    }

    /// Returns the typed refusal of an [`Self::InvalidArchive`], looking
    /// through [`Self::PartialExtraction`].
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveError;
    /// use exarch_core::Malformation;
    ///
    /// let err = ArchiveError::from(Malformation::PackSizesOverflow);
    /// assert_eq!(err.malformation(), Some(&Malformation::PackSizesOverflow));
    /// ```
    #[must_use]
    pub fn malformation(&self) -> Option<&Malformation> {
        match self {
            Self::InvalidArchive(malformation) => Some(malformation),
            Self::PartialExtraction(partial) => partial.cause().malformation(),
            _ => None,
        }
    }
}

impl From<Violation> for ArchiveError {
    fn from(kind: Violation) -> Self {
        Self::SecurityViolation { kind }
    }
}

impl From<TarTrailerRefusal> for ArchiveError {
    fn from(refusal: TarTrailerRefusal) -> Self {
        Self::TarTrailer(refusal)
    }
}

impl From<TarAmbiguity> for ArchiveError {
    fn from(ambiguity: TarAmbiguity) -> Self {
        Self::TarAmbiguity(ambiguity)
    }
}

impl ArchiveError {
    /// Returns the `SecurityConfig` setting whose current value refused the
    /// entry, if this is a [`Self::SecurityViolation`] that a setting relaxes.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveError;
    /// use exarch_core::Violation;
    ///
    /// assert_eq!(
    ///     ArchiveError::from(Violation::EncryptedArchive).relaxable_by(),
    ///     None
    /// );
    /// ```
    #[must_use]
    pub fn relaxable_by(&self) -> Option<PolicySetting> {
        match self {
            Self::SecurityViolation { kind } => kind.relaxable_by(),
            Self::TarTrailer(refusal) => refusal.relaxable_by(),
            Self::PartialExtraction(partial) => partial.cause().relaxable_by(),
            _ => None,
        }
    }

    /// Returns the typed refusal of a [`Self::SecurityViolation`], looking
    /// through [`Self::PartialExtraction`].
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveError;
    /// use exarch_core::Violation;
    ///
    /// let err = ArchiveError::from(Violation::EncryptedArchive);
    /// assert_eq!(err.security_violation(), Some(&Violation::EncryptedArchive));
    /// ```
    #[must_use]
    pub fn security_violation(&self) -> Option<&Violation> {
        match self {
            Self::SecurityViolation { kind } => Some(kind),
            Self::PartialExtraction(partial) => partial.cause().security_violation(),
            _ => None,
        }
    }

    /// Returns `true` if this error represents a security violation.
    ///
    /// Security violations include:
    /// - Path traversal attempts
    /// - Symlink escapes
    /// - Hardlink escapes
    /// - Zip bombs
    /// - ZIP structure inconsistencies
    /// - Invalid permissions
    /// - Quota exceeded
    /// - General security policy violations
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveError;
    /// use exarch_core::Malformation;
    /// use std::path::PathBuf;
    ///
    /// let err = ArchiveError::PathTraversal {
    ///     path: PathBuf::from("../etc/passwd"),
    /// };
    /// assert!(err.is_security_violation());
    ///
    /// let err = ArchiveError::from(Malformation::SymlinkTargetNotUtf8);
    /// assert!(!err.is_security_violation());
    /// ```
    #[must_use]
    pub fn is_security_violation(&self) -> bool {
        match self {
            Self::PartialExtraction(partial) => partial.cause().is_security_violation(),
            Self::TarTrailer(refusal) => refusal.is_policy_refusal(),
            _ => matches!(
                self,
                Self::PathTraversal { .. }
                    | Self::SymlinkEscape { .. }
                    | Self::HardlinkEscape { .. }
                    | Self::ZipBomb(_)
                    | Self::ZipInconsistency(_)
                    | Self::InvalidPermissions { .. }
                    | Self::QuotaExceeded { .. }
                    | Self::SecurityViolation { .. }
            ),
        }
    }

    /// Returns `true` if this error is potentially recoverable.
    ///
    /// Recoverable errors are those where extraction might continue
    /// with different inputs or configurations. Non-recoverable errors
    /// typically indicate fundamental issues with the archive format.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveError;
    /// use exarch_core::Malformation;
    /// use std::path::PathBuf;
    ///
    /// let err = ArchiveError::PathTraversal {
    ///     path: PathBuf::from("../etc/passwd"),
    /// };
    /// assert!(err.is_recoverable()); // Could skip this entry
    ///
    /// let err = ArchiveError::from(Malformation::SymlinkTargetNotUtf8);
    /// assert!(!err.is_recoverable()); // Cannot continue
    /// ```
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::PartialExtraction(partial) => partial.cause().is_recoverable(),
            Self::TarTrailer(refusal) => refusal.is_policy_refusal(),
            _ => matches!(
                self,
                Self::PathTraversal { .. }
                    | Self::SymlinkEscape { .. }
                    | Self::HardlinkEscape { .. }
                    | Self::InvalidPermissions { .. }
                    | Self::SecurityViolation { .. }
            ),
        }
    }

    /// Returns a context string for this error, if available.
    ///
    /// The context provides additional information about what operation
    /// was being performed when the error occurred.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveError;
    /// use exarch_core::Malformation;
    /// use std::path::PathBuf;
    ///
    /// let err = ArchiveError::from(Malformation::SymlinkTargetNotUtf8);
    /// assert_eq!(
    ///     err.context().as_deref(),
    ///     Some("symlink target is not valid UTF-8")
    /// );
    ///
    /// let err = ArchiveError::UnknownFormat {
    ///     path: PathBuf::from("archive.rar"),
    /// };
    /// assert_eq!(err.context(), None);
    /// ```
    #[must_use]
    pub fn context(&self) -> Option<Cow<'_, str>> {
        match self {
            Self::InvalidArchive(m) => Some(Cow::Owned(m.to_string())),
            Self::SecurityViolation { kind } => Some(Cow::Owned(kind.to_string())),
            Self::PartialExtraction(partial) => partial.cause().context(),
            _ => None,
        }
    }

    /// Returns the quota resource that was exceeded, if applicable.
    #[must_use]
    pub fn quota_resource(&self) -> Option<&QuotaResource> {
        match self {
            Self::QuotaExceeded { resource } => Some(resource),
            Self::PartialExtraction(partial) => partial.cause().quota_resource(),
            _ => None,
        }
    }

    /// Wraps `err` in [`Self::PartialExtraction`] if `report` recorded any
    /// processed items, skipped files, or warnings, otherwise returns `err`
    /// unchanged.
    ///
    /// Format handlers call this at every point where extraction can fail
    /// mid-archive, so callers can distinguish "nothing was written" from
    /// "extraction stopped partway through" without each handler
    /// reimplementing the same check. A report is considered worth surfacing
    /// even when [`ExtractionReport::total_items`] is zero, since an archive
    /// where every entry before the failure was rejected (e.g. by an
    /// extension allowlist) still accumulates `files_skipped` and
    /// `warnings` that the caller should see.
    #[must_use]
    pub(crate) fn partial_or(report: crate::ExtractionReport, err: Self) -> Self {
        if report.total_items() > 0 || report.files_skipped() > 0 || report.has_warnings() {
            Self::PartialExtraction(Partial::new(err, report, PartialWrites::Kept))
        } else {
            err
        }
    }

    /// Marks a [`Self::PartialExtraction`] as discarded by atomic rollback;
    /// any other error is returned unchanged.
    ///
    /// [`ExtractRequest`](crate::ExtractRequest)
    /// applies this itself for atomic extraction. Callers that stage and
    /// discard output on their own can use it to keep the reported
    /// [`PartialWrites`] truthful.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveError;
    /// use exarch_core::ExtractionReport;
    /// use exarch_core::Partial;
    /// use exarch_core::PartialWrites;
    /// use exarch_core::Violation;
    ///
    /// let err = ArchiveError::PartialExtraction(Partial::new(
    ///     ArchiveError::from(Violation::EncryptedArchive),
    ///     ExtractionReport::default(),
    ///     PartialWrites::Kept,
    /// ));
    /// match err.rolled_back() {
    ///     ArchiveError::PartialExtraction(partial) => {
    ///         assert_eq!(partial.writes(), PartialWrites::RolledBack);
    ///     }
    ///     other => panic!("unexpected: {other:?}"),
    /// }
    /// ```
    #[must_use]
    pub fn rolled_back(self) -> Self {
        match self {
            Self::PartialExtraction(partial) => {
                Self::PartialExtraction(partial.with_writes(PartialWrites::RolledBack))
            }
            other => other,
        }
    }

    /// Marks a [`Self::PartialExtraction`] as never written to a destination,
    /// for an in-memory extraction that drops its entries on failure; any
    /// other error is returned unchanged.
    #[must_use]
    pub(crate) fn discarded(self) -> Self {
        match self {
            Self::PartialExtraction(partial) => {
                Self::PartialExtraction(partial.with_writes(PartialWrites::Discarded))
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn test_discarded_marks_only_partial_extractions() {
        let partial = ArchiveError::PartialExtraction(crate::Partial::new(
            ArchiveError::from(Violation::EncryptedArchive),
            crate::ExtractionReport::default(),
            PartialWrites::Kept,
        ));
        assert_matches!(
            partial.discarded(),
            ArchiveError::PartialExtraction(partial) if partial.writes() == PartialWrites::Discarded
        );
        assert_matches!(
            ArchiveError::from(Violation::EncryptedArchive).discarded(),
            ArchiveError::SecurityViolation { .. }
        );
    }

    #[test]
    fn test_error_display() {
        let err = ArchiveError::UnknownFormat {
            path: PathBuf::from("archive.rar"),
        };
        assert_eq!(
            err.to_string(),
            "cannot determine archive format from: archive.rar"
        );
    }

    #[test]
    fn test_path_traversal_error() {
        let err = ArchiveError::PathTraversal {
            path: PathBuf::from("../etc/passwd"),
        };
        assert!(err.to_string().contains("path traversal"));
        assert!(err.to_string().contains("../etc/passwd"));
    }

    #[test]
    fn test_zip_bomb_error() {
        let err = ArchiveError::ZipBomb(ZipBombDetails::new(
            ZipBombScope::Entry,
            Compressed(1000),
            Uncompressed(1_000_000),
        ));
        assert!(err.to_string().contains("zip bomb"));
        assert!(err.to_string().contains("1000"));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: ArchiveError = io_err.into();
        assert_matches!(err, ArchiveError::Io(_));
    }

    #[test]
    fn test_is_security_violation() {
        // Security violations
        let err = ArchiveError::PathTraversal {
            path: PathBuf::from("../etc/passwd"),
        };
        assert!(err.is_security_violation());

        let err = ArchiveError::SymlinkEscape {
            path: PathBuf::from("link"),
        };
        assert!(err.is_security_violation());

        let err = ArchiveError::ZipBomb(ZipBombDetails::new(
            ZipBombScope::Entry,
            Compressed(1000),
            Uncompressed(1_000_000),
        ));
        assert!(err.is_security_violation());

        let err = ArchiveError::from(Violation::EncryptedArchive);
        assert!(err.is_security_violation());

        // Not security violations
        let err = ArchiveError::UnknownFormat {
            path: PathBuf::from("archive.rar"),
        };
        assert!(!err.is_security_violation());

        let err = ArchiveError::unclassified("bad");
        assert!(!err.is_security_violation());
    }

    #[test]
    fn test_is_recoverable() {
        // Recoverable errors
        let err = ArchiveError::PathTraversal {
            path: PathBuf::from("../etc/passwd"),
        };
        assert!(err.is_recoverable());

        let err = ArchiveError::from(Violation::EncryptedArchive);
        assert!(err.is_recoverable());

        // Non-recoverable errors
        let err = ArchiveError::unclassified("corrupted");
        assert!(!err.is_recoverable());

        let err = ArchiveError::UnknownFormat {
            path: PathBuf::from("archive.rar"),
        };
        assert!(!err.is_recoverable());

        let err = ArchiveError::ZipBomb(ZipBombDetails::new(
            ZipBombScope::Entry,
            Compressed(1000),
            Uncompressed(1_000_000),
        ));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_context() {
        let err = ArchiveError::unclassified("bad header");
        assert_eq!(err.context().as_deref(), Some("bad header"));

        let err = ArchiveError::from(Violation::SymlinksUnsupported);
        assert_eq!(
            err.context().as_deref(),
            Some("symlinks are not supported on this platform")
        );

        let err = ArchiveError::UnknownFormat {
            path: PathBuf::from("archive.rar"),
        };
        assert_eq!(err.context(), None);

        let err = ArchiveError::PathTraversal {
            path: PathBuf::from("../etc/passwd"),
        };
        assert_eq!(err.context(), None);
    }

    #[test]
    fn test_symlink_escape_error() {
        let err = ArchiveError::SymlinkEscape {
            path: PathBuf::from("malicious/link"),
        };
        let display = err.to_string();
        assert!(display.contains("symlink target outside"));
        assert!(display.contains("malicious/link"));
        assert!(err.is_security_violation());
    }

    #[test]
    fn test_hardlink_escape_error() {
        let err = ArchiveError::HardlinkEscape {
            path: PathBuf::from("malicious/hardlink"),
        };
        let display = err.to_string();
        assert!(display.contains("hardlink target outside"));
        assert!(display.contains("malicious/hardlink"));
        assert!(err.is_security_violation());
    }

    #[test]
    fn test_invalid_permissions_error() {
        let err = ArchiveError::InvalidPermissions {
            path: PathBuf::from("file.txt"),
            mode: crate::RawMode::new(0o777),
        };
        let display = err.to_string();
        assert!(display.contains("invalid permissions"));
        assert!(display.contains("file.txt"));
        assert!(display.contains("0o777"));
        assert!(err.is_security_violation());
    }

    #[test]
    fn test_quota_exceeded_error() {
        let err = ArchiveError::QuotaExceeded {
            resource: QuotaResource::FileCount {
                current: 11,
                max: 10,
            },
        };
        let display = err.to_string();
        assert!(display.contains("quota exceeded"));
        assert!(display.contains("file count"));
        assert!(display.contains("11"));
        assert!(display.contains("10"));
        assert!(err.is_security_violation());

        // Test quota_resource accessor
        let quota = err.quota_resource();
        assert!(quota.is_some());
        assert_eq!(
            quota,
            Some(&QuotaResource::FileCount {
                current: 11,
                max: 10
            })
        );
    }

    // L-10: Error source chain test
    #[test]
    fn test_error_source_chain() {
        use std::error::Error;

        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "inner error");
        let err: ArchiveError = io_err.into();

        // Verify source chain works
        if let ArchiveError::Io(ref inner) = err {
            // IO error may or may not have a source
            let _source = inner.source();
        }
    }

    // Regression test for #177: ArchiveError::Io must not expose the inner
    // std::io::Error as an error source. The manual From impl intentionally
    // omits #[source] so callers building error chains (anyhow, thiserror)
    // do not append the OS message a second time after ArchiveError::Io's
    // own Display.
    #[test]
    fn test_io_error_no_source_chain() {
        use std::error::Error;

        let os_message = "permission denied";
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, os_message);
        let err: ArchiveError = io_err.into();

        // Display must contain the OS message exactly once.
        let display = err.to_string();
        assert_eq!(
            display.matches(os_message).count(),
            1,
            "OS error message duplicated in Display: {display:?}"
        );

        // source() must be None — no chain continuation that would re-print the
        // message.
        assert!(
            err.source().is_none(),
            "ArchiveError::Io must not expose inner io::Error as source"
        );
    }

    #[test]
    fn test_zip_bomb_display_per_scope() {
        let entry = ArchiveError::ZipBomb(ZipBombDetails::new(
            ZipBombScope::Entry,
            Compressed(1000),
            Uncompressed(1_000_000),
        ));
        assert_eq!(
            entry.to_string(),
            "potential zip bomb: compressed=1000 bytes, uncompressed=1000000 bytes (ratio: 1000.00, scope: entry)"
        );

        let solid = ArchiveError::ZipBomb(ZipBombDetails::new(
            ZipBombScope::SolidBlock,
            Compressed(10),
            Uncompressed(20_000),
        ));
        assert!(solid.to_string().contains("scope: solid block"));
    }

    #[test]
    fn test_zip_bomb_zero_compressed_is_unbounded() {
        let details = ZipBombDetails::new(ZipBombScope::Entry, Compressed(0), Uncompressed(1000));
        assert_eq!(details.ratio(), CompressionRatio::Unbounded);
        let err = ArchiveError::ZipBomb(details);
        assert!(err.is_security_violation());
        let display = err.to_string();
        assert!(display.contains("ratio: unbounded"));
        assert!(!display.contains("inf") && !display.contains("NaN"));
    }

    #[test]
    fn test_zip_bomb_ratio_is_derived_from_sizes() {
        assert_eq!(
            ZipBombDetails::new(ZipBombScope::Entry, Compressed(1000), Uncompressed(1000)).ratio(),
            CompressionRatio::Finite(1.0)
        );
        assert_eq!(
            ZipBombDetails::new(ZipBombScope::Entry, Compressed(0), Uncompressed(0)).ratio(),
            CompressionRatio::Finite(0.0)
        );
    }

    #[test]
    fn test_source_not_found_error() {
        let err = ArchiveError::SourceNotFound {
            path: PathBuf::from("/nonexistent/path"),
        };
        let display = err.to_string();
        assert!(display.contains("source path not found"));
        assert!(display.contains("/nonexistent/path"));
        assert!(!err.is_security_violation());
    }

    #[test]
    fn test_source_not_accessible_error() {
        let err = ArchiveError::SourceNotAccessible {
            path: PathBuf::from("/restricted/path"),
            error: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        };
        let display = err.to_string();
        assert!(display.contains("source path is not accessible"));
        assert!(display.contains("/restricted/path"));
        assert!(display.contains("permission denied"));
        assert!(!err.is_security_violation());
    }

    #[test]
    fn test_output_exists_error() {
        let err = ArchiveError::OutputExists {
            path: PathBuf::from("output.tar.gz"),
        };
        let display = err.to_string();
        assert!(display.contains("output file already exists"));
        assert!(display.contains("output.tar.gz"));
        assert!(!err.is_security_violation());
    }

    #[test]
    fn test_invalid_compression_level_error() {
        let err = ArchiveError::InvalidCompressionLevel {
            level: RequestedLevel::Integer(0),
        };
        let display = err.to_string();
        assert!(display.contains("invalid compression level"));
        assert!(display.contains('0'));
        assert!(display.contains("must be 1-9"));
        assert!(!err.is_security_violation());

        let err = ArchiveError::InvalidCompressionLevel {
            level: RequestedLevel::Integer(10),
        };
        let display = err.to_string();
        assert!(display.contains("10"));
    }

    #[test]
    fn test_unknown_format_error() {
        let err = ArchiveError::UnknownFormat {
            path: PathBuf::from("archive.rar"),
        };
        let display = err.to_string();
        assert!(display.contains("cannot determine archive format"));
        assert!(display.contains("archive.rar"));
        assert!(!err.is_security_violation());
    }

    #[test]
    fn test_invalid_configuration_error() {
        let err = ArchiveError::InvalidConfiguration {
            setting: ConfigSetting::OutputPath,
            problem: ConfigProblem::NotSet,
        };
        let display = err.to_string();
        assert!(display.contains("invalid configuration"));
        assert!(display.contains("output path not set"));
        assert!(!err.is_security_violation());
    }

    #[test]
    fn test_partial_extraction_display_shows_source() {
        use crate::ExtractionReport;
        let source = ArchiveError::QuotaExceeded {
            resource: QuotaResource::FileCount {
                current: 11,
                max: 10,
            },
        };
        let err = ArchiveError::PartialExtraction(crate::Partial::new(
            source,
            ExtractionReport::new(),
            PartialWrites::Kept,
        ));
        let display = err.to_string();
        assert!(display.contains("quota exceeded"));
    }

    #[test]
    fn test_partial_extraction_delegates_is_security_violation() {
        use crate::ExtractionReport;
        let security_err = ArchiveError::PathTraversal {
            path: PathBuf::from("../etc/passwd"),
        };
        let err = ArchiveError::PartialExtraction(crate::Partial::new(
            security_err,
            ExtractionReport::new(),
            PartialWrites::Kept,
        ));
        assert!(err.is_security_violation());

        let non_security_err = ArchiveError::unclassified("bad");
        let err2 = ArchiveError::PartialExtraction(crate::Partial::new(
            non_security_err,
            ExtractionReport::new(),
            PartialWrites::Kept,
        ));
        assert!(!err2.is_security_violation());
    }

    #[test]
    fn test_partial_extraction_delegates_is_recoverable() {
        use crate::ExtractionReport;
        let recoverable = ArchiveError::PathTraversal {
            path: PathBuf::from("../etc/passwd"),
        };
        let err = ArchiveError::PartialExtraction(crate::Partial::new(
            recoverable,
            ExtractionReport::new(),
            PartialWrites::Kept,
        ));
        assert!(err.is_recoverable());
    }

    fn partial_with(files: usize, writes: PartialWrites) -> Partial {
        let report = crate::ExtractionReport {
            files_extracted: files,
            ..crate::ExtractionReport::default()
        };
        Partial::new(
            ArchiveError::from(Violation::EncryptedArchive),
            report,
            writes,
        )
    }

    #[test]
    fn test_nested_partial_keeps_the_innermost_cause_and_the_outer_report() {
        let nested = Partial::new(
            ArchiveError::PartialExtraction(partial_with(1, PartialWrites::Kept)),
            crate::ExtractionReport {
                files_extracted: 5,
                ..crate::ExtractionReport::default()
            },
            PartialWrites::Kept,
        );
        assert_matches!(nested.cause(), ArchiveError::SecurityViolation { .. });
        assert_eq!(nested.report().files_extracted, 5);
    }

    #[test]
    fn test_nested_partial_keeps_the_more_severe_writes() {
        for (inner, outer, expected) in [
            (
                PartialWrites::Kept,
                PartialWrites::Kept,
                PartialWrites::Kept,
            ),
            (
                PartialWrites::RolledBack,
                PartialWrites::Kept,
                PartialWrites::RolledBack,
            ),
            (
                PartialWrites::Discarded,
                PartialWrites::Kept,
                PartialWrites::Discarded,
            ),
            (
                PartialWrites::Kept,
                PartialWrites::RolledBack,
                PartialWrites::RolledBack,
            ),
            (
                PartialWrites::Kept,
                PartialWrites::Discarded,
                PartialWrites::Discarded,
            ),
        ] {
            let nested = Partial::new(
                ArchiveError::PartialExtraction(partial_with(1, inner)),
                crate::ExtractionReport::default(),
                outer,
            );
            assert_eq!(nested.writes(), expected, "{inner:?} inside {outer:?}");
        }
    }

    #[test]
    fn test_partial_or_never_nests() {
        let inner = ArchiveError::PartialExtraction(partial_with(1, PartialWrites::Kept));
        let report = crate::ExtractionReport {
            files_extracted: 2,
            ..crate::ExtractionReport::default()
        };
        let ArchiveError::PartialExtraction(outer) = ArchiveError::partial_or(report, inner) else {
            panic!("expected a partial extraction");
        };
        assert!(!matches!(outer.cause(), ArchiveError::PartialExtraction(_)));
        assert_eq!(outer.report().files_extracted, 2);
    }

    #[test]
    fn test_partial_or_wraps_when_report_has_items() {
        use crate::ExtractionReport;

        let mut report = ExtractionReport::new();
        report.files_extracted = 1;
        let err = ArchiveError::unclassified("bad entry");

        let result = ArchiveError::partial_or(report, err);
        assert_matches!(
            result,
            ArchiveError::PartialExtraction(_),
            "expected PartialExtraction when report has processed items, got: {result:?}"
        );
    }

    #[test]
    fn test_partial_or_passes_through_when_report_empty() {
        use crate::ExtractionReport;

        let report = ExtractionReport::new();
        let err = ArchiveError::unclassified("bad entry");

        let result = ArchiveError::partial_or(report, err);
        assert_matches!(
            result,
            ArchiveError::InvalidArchive(_),
            "expected the original error unwrapped when report is empty, got: {result:?}"
        );
    }

    #[test]
    fn test_partial_or_wraps_when_report_has_only_files_skipped() {
        use crate::ExtractionReport;

        let mut report = ExtractionReport::new();
        for name in ["a", "b"] {
            let recorded = report
                .skipped
                .record(crate::Skip::new(crate::SkipKind::Duplicate, name));
            assert!(recorded.is_ok());
        }
        let err = ArchiveError::unclassified("bad entry");

        let result = ArchiveError::partial_or(report, err);
        assert_matches!(
            result,
            ArchiveError::PartialExtraction(_),
            "expected PartialExtraction when report has files_skipped > 0 but zero total_items \
             and no warnings, got: {result:?}"
        );
    }

    #[test]
    fn test_partial_or_wraps_when_report_has_only_warnings() {
        use crate::ExtractionReport;

        let mut report = ExtractionReport::new();
        report.add_warning(crate::ExtractionWarning::AntiItemsSkipped { count: 1 });
        let err = ArchiveError::unclassified("bad entry");

        let result = ArchiveError::partial_or(report, err);
        assert_matches!(
            result,
            ArchiveError::PartialExtraction(_),
            "expected PartialExtraction when report has a warning but zero total_items and zero \
             files_skipped, got: {result:?}"
        );
    }

    #[test]
    fn test_partial_extraction_delegates_error_code() {
        use crate::ExtractionReport;
        let source = ArchiveError::ZipBomb(ZipBombDetails::new(
            ZipBombScope::Entry,
            Compressed(100),
            Uncompressed(100_000),
        ));
        let err = ArchiveError::PartialExtraction(crate::Partial::new(
            source,
            ExtractionReport::new(),
            PartialWrites::Kept,
        ));
        assert_eq!(err.error_code(), crate::ErrorCode::ZipBomb);
    }
}
