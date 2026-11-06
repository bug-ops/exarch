//! FFI error message formatting.
//!
//! The single source of binding-facing error data: a stable [`ErrorCode`], a
//! typed [`FfiKind`] with the payload each code carries, a redacted
//! description and the fate of partial output. Python, Node.js and the CLI
//! consume [`FfiErrorMessage`] instead of re-matching [`ArchiveError`].

use super::config_error::ConfigSetting;
use super::redaction::sanitize_io_error_for_error;
use super::types::ArchiveError;
use super::types::PartialWrites;
use super::types::PolicySetting;
use super::types::QuotaKind;
use super::types::ReaderFormatError;
use super::types::ZipBombScope;
use crate::ExtractionReport;
use crate::closed_enum::closed_enum;

closed_enum! {
    /// Stable machine-readable identifier of an [`ArchiveError`] variant.
    ///
    /// The spellings are part of every binding's observable contract; the
    /// bindings take them from [`ErrorCode::as_str`].
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ErrorCode;
    ///
    /// assert_eq!(ErrorCode::ZipBomb.as_str(), "ZIP_BOMB");
    /// assert!(ErrorCode::ALL.contains(&ErrorCode::PathTraversal));
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub enum ErrorCode {
        /// [`ArchiveError::PathTraversal`].
        PathTraversal => "PATH_TRAVERSAL",
        /// [`ArchiveError::SymlinkEscape`].
        SymlinkEscape => "SYMLINK_ESCAPE",
        /// [`ArchiveError::HardlinkEscape`].
        HardlinkEscape => "HARDLINK_ESCAPE",
        /// [`ArchiveError::ZipBomb`].
        ZipBomb => "ZIP_BOMB",
        /// [`ArchiveError::ZipInconsistency`].
        ZipInconsistency => "ZIP_INCONSISTENCY",
        /// [`ArchiveError::QuotaExceeded`].
        QuotaExceeded => "QUOTA_EXCEEDED",
        /// [`ArchiveError::SecurityViolation`].
        SecurityViolation => "SECURITY_VIOLATION",
        /// [`ArchiveError::InvalidArchive`].
        InvalidArchive => "INVALID_ARCHIVE",
        /// [`ArchiveError::Io`].
        IoError => "IO_ERROR",
        /// [`ArchiveError::InvalidPermissions`].
        InvalidPermissions => "INVALID_PERMISSIONS",
        /// [`ArchiveError::SourceNotFound`].
        SourceNotFound => "SOURCE_NOT_FOUND",
        /// [`ArchiveError::SourceNotAccessible`].
        SourceNotAccessible => "SOURCE_NOT_ACCESSIBLE",
        /// [`ArchiveError::OutputExists`].
        OutputExists => "OUTPUT_EXISTS",
        /// [`ArchiveError::InvalidCompressionLevel`].
        InvalidCompressionLevel => "INVALID_COMPRESSION_LEVEL",
        /// [`ArchiveError::UnknownFormat`].
        UnknownFormat => "UNKNOWN_FORMAT",
        /// [`ArchiveError::InvalidConfiguration`].
        InvalidConfiguration => "INVALID_CONFIGURATION",
        /// [`ArchiveError::Cancelled`].
        Cancelled => "CANCELLED",
    }
}

closed_enum! {
    /// Finer classification of an [`ErrorCode::InvalidArchive`] error.
    ///
    /// Bindings expose it so callers can tell a TAR refusal from any other
    /// malformed archive without parsing the message.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::InvalidArchiveSubCode;
    ///
    /// assert_eq!(InvalidArchiveSubCode::TarTrailer.as_str(), "TAR_TRAILER");
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub enum InvalidArchiveSubCode {
        /// [`ArchiveError::TarAmbiguity`].
        TarAmbiguity => "TAR_AMBIGUITY",
        /// A corrupt or truncated stream after the TAR end-of-archive marker.
        TarTrailer => "TAR_TRAILER",
        /// A link entry whose target is missing, unreadable or unusable.
        LinkTarget => "LINK_TARGET",
        /// An entry path that is already taken.
        DuplicateEntry => "DUPLICATE_ENTRY",
        /// An entry path or name that cannot be read.
        EntryName => "ENTRY_NAME",
        /// A declared size that contradicts the archive.
        DeclaredSize => "DECLARED_SIZE",
        /// An entry whose integrity decode failed.
        Integrity => "INTEGRITY",
        /// A failure of the ZIP reader or of the structural check built on it:
        /// the archive or an entry cannot be opened or read, the census and
        /// the reader disagree about the central directory, an entry's data
        /// range is not representable, or the zstd entries cannot be walked
        /// within the archive extent.
        ///
        /// It also covers I/O failures the `zip` crate wraps into its own
        /// errors. A wrapped I/O error surfaces as [`ErrorCode::IoError`] during
        /// the structure scan at open, where the reader's own fault is
        /// preferred, but as this code when extraction, listing or the
        /// descriptor-tail re-read hit it.
        ZipReader => "ZIP_READER",
        /// A failure of the TAR reader: an entry, its PAX header or the entry
        /// stream cannot be read, or the reader was used after an entry was
        /// abandoned.
        TarReader => "TAR_READER",
        /// A failure of the 7z reader: the header cannot be parsed or is
        /// inconsistent, a block uses an unsupported coder, or `sevenz-rust2`
        /// reports an error with no kind of its own.
        SevenZReader => "SEVENZ_READER",
    }
}

closed_enum! {
    /// Finer classification of an [`ErrorCode::SecurityViolation`] error.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::SecurityViolationSubCode;
    ///
    /// assert_eq!(SecurityViolationSubCode::TarTrailer.as_str(), "TAR_TRAILER");
    /// assert_eq!(SecurityViolationSubCode::PathName.as_str(), "PATH_NAME");
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub enum SecurityViolationSubCode {
        /// An entry or argument path is refused by name rules.
        PathName => "PATH_NAME",
        /// A path or symlink target is deeper than the limit.
        PathDepth => "PATH_DEPTH",
        /// The target of a symlink or hardlink cannot be accepted.
        LinkTarget => "LINK_TARGET",
        /// The kind of link is disabled by the configuration.
        LinkPolicy => "LINK_POLICY",
        /// A symlink already at or above the entry's location blocks it.
        ExistingSymlink => "EXISTING_SYMLINK",
        /// An entry type exarch does not extract.
        EntryType => "ENTRY_TYPE",
        /// A root entry that is not a directory.
        RootEntry => "ROOT_ENTRY",
        /// An encrypted archive or entry.
        Encrypted => "ENCRYPTED",
        /// A compression method exarch does not read.
        CompressionMethod => "COMPRESSION_METHOD",
        /// A solid archive while solid archives are disabled.
        SolidArchive => "SOLID_ARCHIVE",
        /// A stream disagrees with the size its archive declared.
        DeclaredSize => "DECLARED_SIZE",
        /// A file changed while it was being copied.
        ConcurrentChange => "CONCURRENT_CHANGE",
        /// A TAR metadata or synthetic-byte budget was exceeded.
        TarMetadata => "TAR_METADATA",
        /// An over-cap tail after the TAR end-of-archive marker.
        TarTrailer => "TAR_TRAILER",
        /// The host platform cannot do what the entry asks.
        Platform => "PLATFORM",
        /// An existing output conflicts with an entry.
        OutputConflict => "OUTPUT_CONFLICT",
        /// A source path to archive lies outside the archive root.
        SourcePath => "SOURCE_PATH",
    }
}

/// The finer classification of an error, tagged with the class it refines.
///
/// The variant is the error class, so a pair of class and sub-code that core
/// never produces cannot be built.
///
/// # Examples
///
/// ```
/// use exarch_core::InvalidArchiveSubCode;
/// use exarch_core::SubCode;
///
/// let code = SubCode::InvalidArchive(InvalidArchiveSubCode::TarTrailer);
/// assert_eq!(code.as_str(), "TAR_TRAILER");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SubCode {
    /// Refines [`ErrorCode::InvalidArchive`].
    InvalidArchive(InvalidArchiveSubCode),
    /// Refines [`ErrorCode::SecurityViolation`].
    SecurityViolation(SecurityViolationSubCode),
    /// Refines [`ErrorCode::QuotaExceeded`] with the quota that was exceeded.
    Quota(QuotaKind),
    /// Refines [`ErrorCode::ZipBomb`] with what the ratio was measured over.
    ZipBomb(ZipBombScope),
}

impl SubCode {
    /// Every sub-code of a quota error, in [`QuotaKind::ALL`] order.
    pub const QUOTA_ALL: &'static [Self] = &[
        Self::Quota(QuotaKind::FileCount),
        Self::Quota(QuotaKind::TotalSize),
        Self::Quota(QuotaKind::FileSize),
        Self::Quota(QuotaKind::IntegerOverflow),
        Self::Quota(QuotaKind::DecoderMemory),
        Self::Quota(QuotaKind::CompressedMembers),
        Self::Quota(QuotaKind::TreeNodes),
        Self::Quota(QuotaKind::SinkCapacity),
        Self::Quota(QuotaKind::SolidBlockMemory),
    ];
    /// Every sub-code of a zip-bomb error, in [`ZipBombScope::ALL`] order.
    pub const ZIP_BOMB_ALL: &'static [Self] = &[
        Self::ZipBomb(ZipBombScope::Entry),
        Self::ZipBomb(ZipBombScope::SolidBlock),
        Self::ZipBomb(ZipBombScope::SkippedEntries),
    ];

    /// The stable string form of the wrapped sub-code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArchive(code) => code.as_str(),
            Self::SecurityViolation(code) => code.as_str(),
            Self::Quota(kind) => quota_sub_code(kind),
            Self::ZipBomb(scope) => zip_bomb_sub_code(scope),
        }
    }
}

/// The `SCREAMING_SNAKE` sub-code of a quota, distinct from the `snake_case`
/// [`QuotaKind::as_str`] that the CLI and Python/Node `kind` fields use.
const fn quota_sub_code(kind: QuotaKind) -> &'static str {
    match kind {
        QuotaKind::FileCount => "FILE_COUNT",
        QuotaKind::TotalSize => "TOTAL_SIZE",
        QuotaKind::FileSize => "FILE_SIZE",
        QuotaKind::IntegerOverflow => "INTEGER_OVERFLOW",
        QuotaKind::DecoderMemory => "DECODER_MEMORY",
        QuotaKind::CompressedMembers => "COMPRESSED_MEMBERS",
        QuotaKind::TreeNodes => "TREE_NODES",
        QuotaKind::SinkCapacity => "SINK_CAPACITY",
        QuotaKind::SolidBlockMemory => "SOLID_BLOCK_MEMORY",
    }
}

/// The `SCREAMING_SNAKE` sub-code of a zip-bomb scope, distinct from the
/// human-readable [`ZipBombScope::as_str`] used in messages.
const fn zip_bomb_sub_code(scope: ZipBombScope) -> &'static str {
    match scope {
        ZipBombScope::Entry => "ENTRY",
        ZipBombScope::SolidBlock => "SOLID_BLOCK",
        ZipBombScope::SkippedEntries => "SKIPPED_ENTRIES",
    }
}

impl std::fmt::Display for SubCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The error class of an [`FfiErrorMessage`], with the payload that class
/// carries.
///
/// One variant per [`ErrorCode`]; [`FfiKind::code`] is the bijection.
/// Payload lives inside the variant so a binding cannot read a field that
/// does not exist for the class.
///
/// # Examples
///
/// ```
/// use exarch_core::ArchiveError;
/// use exarch_core::ErrorCode;
/// use exarch_core::FfiKind;
/// use exarch_core::SecurityViolationSubCode;
/// use exarch_core::Violation;
/// use std::assert_matches;
///
/// let msg = ArchiveError::from(Violation::EncryptedArchive).into_ffi_message();
/// assert_matches!(
///     msg.kind,
///     FfiKind::SecurityViolation {
///         relaxable_by: None,
///         sub_code: SecurityViolationSubCode::Encrypted,
///         ..
///     }
/// );
/// assert_eq!(msg.kind.code(), ErrorCode::SecurityViolation);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FfiKind {
    /// Entry path escapes the destination.
    PathTraversal,
    /// Symlink target escapes the destination.
    SymlinkEscape,
    /// Hardlink target escapes the destination.
    HardlinkEscape,
    /// Compression ratio limit exceeded.
    #[non_exhaustive]
    ZipBomb {
        /// What the refused ratio was measured over.
        scope: ZipBombScope,
    },
    /// ZIP structure is ambiguous or self-contradictory.
    ZipInconsistency,
    /// A quota was exceeded.
    #[non_exhaustive]
    QuotaExceeded {
        /// The quota dimension that was exceeded.
        kind: QuotaKind,
    },
    /// Denied by security policy.
    #[non_exhaustive]
    SecurityViolation {
        /// The `SecurityConfig` setting whose current value refused the
        /// entry; see [`ArchiveError::relaxable_by`].
        relaxable_by: Option<PolicySetting>,
        /// The family of the refusal.
        sub_code: SecurityViolationSubCode,
    },
    /// Archive is corrupted or malformed.
    #[non_exhaustive]
    InvalidArchive {
        /// Finer classification, when the failure has one.
        sub_code: Option<InvalidArchiveSubCode>,
    },
    /// I/O failure of the given kind.
    Io(std::io::ErrorKind),
    /// Invalid permission bits.
    InvalidPermissions,
    /// The operation was cancelled by its progress callback.
    Cancelled,
    /// Creation source does not exist.
    SourceNotFound,
    /// Creation source cannot be read.
    SourceNotAccessible,
    /// Output file already exists.
    OutputExists,
    /// Compression level out of range.
    InvalidCompressionLevel,
    /// Archive format could not be determined.
    UnknownFormat,
    /// Configuration is invalid.
    #[non_exhaustive]
    InvalidConfiguration {
        /// The setting or input that was refused; `None` for a reader format
        /// that cannot be used.
        setting: Option<ConfigSetting>,
    },
}

impl FfiKind {
    /// The `SecurityConfig` setting whose current value refused the entry, if
    /// this is a [`FfiKind::SecurityViolation`] that a setting can relax.
    #[must_use]
    pub const fn relaxable_by(&self) -> Option<PolicySetting> {
        match self {
            Self::SecurityViolation { relaxable_by, .. } => *relaxable_by,
            Self::PathTraversal
            | Self::SymlinkEscape
            | Self::HardlinkEscape
            | Self::ZipBomb { .. }
            | Self::ZipInconsistency
            | Self::QuotaExceeded { .. }
            | Self::InvalidArchive { .. }
            | Self::Io(_)
            | Self::InvalidPermissions
            | Self::Cancelled
            | Self::SourceNotFound
            | Self::SourceNotAccessible
            | Self::OutputExists
            | Self::InvalidCompressionLevel
            | Self::UnknownFormat
            | Self::InvalidConfiguration { .. } => None,
        }
    }

    /// The configuration setting or input that was refused, if this is a
    /// [`FfiKind::InvalidConfiguration`] that names one.
    #[must_use]
    pub const fn setting(&self) -> Option<ConfigSetting> {
        match self {
            Self::InvalidConfiguration { setting } => *setting,
            _ => None,
        }
    }

    /// The finer classification of this error, when it has one.
    #[must_use]
    pub const fn sub_code(&self) -> Option<SubCode> {
        match self {
            Self::SecurityViolation { sub_code, .. } => Some(SubCode::SecurityViolation(*sub_code)),
            Self::InvalidArchive {
                sub_code: Some(code),
            } => Some(SubCode::InvalidArchive(*code)),
            Self::ZipBomb { scope } => Some(SubCode::ZipBomb(*scope)),
            Self::QuotaExceeded { kind } => Some(SubCode::Quota(*kind)),
            Self::InvalidArchive { sub_code: None }
            | Self::PathTraversal
            | Self::SymlinkEscape
            | Self::HardlinkEscape
            | Self::ZipInconsistency
            | Self::Io(_)
            | Self::InvalidPermissions
            | Self::Cancelled
            | Self::SourceNotFound
            | Self::SourceNotAccessible
            | Self::OutputExists
            | Self::InvalidCompressionLevel
            | Self::UnknownFormat
            | Self::InvalidConfiguration { .. } => None,
        }
    }

    /// The stable [`ErrorCode`] of this class.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::PathTraversal => ErrorCode::PathTraversal,
            Self::SymlinkEscape => ErrorCode::SymlinkEscape,
            Self::HardlinkEscape => ErrorCode::HardlinkEscape,
            Self::ZipBomb { .. } => ErrorCode::ZipBomb,
            Self::ZipInconsistency => ErrorCode::ZipInconsistency,
            Self::QuotaExceeded { .. } => ErrorCode::QuotaExceeded,
            Self::SecurityViolation { .. } => ErrorCode::SecurityViolation,
            Self::InvalidArchive { .. } => ErrorCode::InvalidArchive,
            Self::Io(_) => ErrorCode::IoError,
            Self::InvalidPermissions => ErrorCode::InvalidPermissions,
            Self::Cancelled => ErrorCode::Cancelled,
            Self::SourceNotFound => ErrorCode::SourceNotFound,
            Self::SourceNotAccessible => ErrorCode::SourceNotAccessible,
            Self::OutputExists => ErrorCode::OutputExists,
            Self::InvalidCompressionLevel => ErrorCode::InvalidCompressionLevel,
            Self::UnknownFormat => ErrorCode::UnknownFormat,
            Self::InvalidConfiguration { .. } => ErrorCode::InvalidConfiguration,
        }
    }
}

/// What happened to the output of an extraction that stopped part-way.
///
/// # Examples
///
/// ```
/// use exarch_core::PartialOutcome;
/// use exarch_core::PartialWrites;
///
/// assert_eq!(
///     PartialOutcome::RolledBack.writes(),
///     PartialWrites::RolledBack
/// );
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PartialOutcome {
    /// The written files remain in the destination; the report counts them.
    Kept(ExtractionReport),
    /// Atomic extraction discarded the written files; no counters are
    /// meaningful.
    RolledBack,
    /// An in-memory extraction dropped what it collected; no counters are
    /// meaningful.
    Discarded,
}

impl PartialOutcome {
    /// The [`PartialWrites`] state matching this outcome.
    #[must_use]
    pub const fn writes(&self) -> PartialWrites {
        match self {
            Self::Kept(_) => PartialWrites::Kept,
            Self::RolledBack => PartialWrites::RolledBack,
            Self::Discarded => PartialWrites::Discarded,
        }
    }
}

/// Error data for FFI consumption.
///
/// `#[non_exhaustive]` and output-only: bindings read it, only
/// [`ArchiveError::into_ffi_message`] builds it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FfiErrorMessage {
    /// Error class and its class-specific payload.
    pub kind: FfiKind,

    /// Human-readable, redacted description.
    pub description: String,

    /// Set when the error came from a partially completed extraction.
    pub partial: Option<PartialOutcome>,

    /// The failure behind an unreadable creation source, so a binding can
    /// expose `errno`, `strerror` and `filename`.
    pub source_fault: Option<FfiSourceFault>,
}

/// What a binding needs of an unreadable creation source, redacted like the
/// rest of the message.
///
/// # Examples
///
/// ```
/// use exarch_core::ArchiveError;
///
/// let error = ArchiveError::SourceNotAccessible {
///     path: "src/a.txt".into(),
///     error: std::io::Error::from_raw_os_error(13),
/// };
/// let fault = error.into_ffi_message().source_fault.unwrap();
/// assert_eq!(fault.raw_os_error, Some(13));
/// assert!(fault.name.ends_with("a.txt"));
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FfiSourceFault {
    /// The OS error number, when the failure has one.
    pub raw_os_error: Option<i32>,

    /// The error text: the full `Display` in debug builds, the `ErrorKind`
    /// description in release builds.
    pub text: String,

    /// The source path as the shared policy redacts it: the file name only in
    /// release builds.
    pub name: String,
}

impl FfiErrorMessage {
    const fn new(kind: FfiKind, description: String) -> Self {
        Self {
            kind,
            description,
            partial: None,
            source_fault: None,
        }
    }
}

impl ArchiveError {
    /// Converts the error into the data every binding consumes.
    ///
    /// Path and I/O-error text is redacted per the shared policy in
    /// [`super::redaction`] — see [`Self::redacted_path`] and
    /// [`sanitize_io_error_for_error`]. A [`Self::PartialExtraction`] yields
    /// its source's message with [`FfiErrorMessage::partial`] set.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveError;
    /// use exarch_core::ErrorCode;
    /// use std::path::PathBuf;
    ///
    /// let error = ArchiveError::PathTraversal {
    ///     path: PathBuf::from("../../etc/passwd"),
    /// };
    ///
    /// let msg = error.into_ffi_message();
    /// assert_eq!(msg.kind.code(), ErrorCode::PathTraversal);
    /// // Archive-relative, attacker-authored path: never redacted (#462).
    /// assert!(msg.description.contains("../../etc/passwd"));
    /// ```
    #[must_use]
    pub fn into_ffi_message(self) -> FfiErrorMessage {
        if let Self::PartialExtraction(partial) = self {
            let (source, report, writes) = partial.into_parts();
            let mut msg = source.into_ffi_message();
            msg.partial = Some(match writes {
                PartialWrites::Kept => PartialOutcome::Kept(report),
                PartialWrites::RolledBack => PartialOutcome::RolledBack,
                PartialWrites::Discarded => PartialOutcome::Discarded,
            });
            return msg;
        }
        let mut msg = FfiErrorMessage::new(self.ffi_kind(), self.ffi_description());
        if let Self::SourceNotAccessible { error, .. } = &self {
            msg.source_fault = Some(FfiSourceFault {
                raw_os_error: error.raw_os_error(),
                text: sanitize_io_error_for_error(error),
                name: self.redacted_path().unwrap_or_default(),
            });
        }
        msg
    }

    /// The binding-facing class of this error, without consuming it.
    ///
    /// The only variant-to-[`FfiKind`] table: [`Self::error_code`] and
    /// [`Self::into_ffi_message`] derive from it. A
    /// [`Self::PartialExtraction`] reports its source's kind.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveError;
    /// use exarch_core::ErrorCode;
    /// use exarch_core::Malformation;
    ///
    /// let err = ArchiveError::from(Malformation::PackSizesOverflow);
    /// assert_eq!(err.ffi_kind().code(), ErrorCode::InvalidArchive);
    /// ```
    #[must_use]
    pub fn ffi_kind(&self) -> FfiKind {
        match self {
            Self::PathTraversal { .. } => FfiKind::PathTraversal,
            Self::SymlinkEscape { .. } => FfiKind::SymlinkEscape,
            Self::HardlinkEscape { .. } => FfiKind::HardlinkEscape,
            Self::ZipBomb(details) => FfiKind::ZipBomb {
                scope: details.scope(),
            },
            Self::ZipInconsistency(_) => FfiKind::ZipInconsistency,
            Self::QuotaExceeded { resource } => FfiKind::QuotaExceeded {
                kind: resource.kind(),
            },
            Self::SecurityViolation { kind } => FfiKind::SecurityViolation {
                relaxable_by: kind.relaxable_by(),
                sub_code: kind.sub_code(),
            },
            Self::InvalidArchive(m) => FfiKind::InvalidArchive {
                sub_code: m.sub_code(),
            },
            Self::TarAmbiguity(_) => FfiKind::InvalidArchive {
                sub_code: Some(InvalidArchiveSubCode::TarAmbiguity),
            },
            Self::TarTrailer(refusal) => {
                if refusal.is_policy_refusal() {
                    FfiKind::SecurityViolation {
                        relaxable_by: refusal.relaxable_by(),
                        sub_code: SecurityViolationSubCode::TarTrailer,
                    }
                } else {
                    FfiKind::InvalidArchive {
                        sub_code: Some(InvalidArchiveSubCode::TarTrailer),
                    }
                }
            }
            Self::Io(io_err) => FfiKind::Io(io_err.kind()),
            Self::InvalidPermissions { .. } => FfiKind::InvalidPermissions,
            Self::Cancelled => FfiKind::Cancelled,
            Self::OutputReservationLeft { error, .. } => FfiKind::Io(error.kind()),
            Self::ReplaceFailed(failure) => FfiKind::Io(failure.error.kind()),
            Self::DestinationOccupied { .. } => FfiKind::OutputExists,
            Self::SourceNotFound { .. } => FfiKind::SourceNotFound,
            Self::SourceNotAccessible { .. } => FfiKind::SourceNotAccessible,
            Self::OutputExists { .. } => FfiKind::OutputExists,
            Self::InvalidCompressionLevel { .. } => FfiKind::InvalidCompressionLevel,
            Self::UnknownFormat { .. } | Self::ReaderFormat(ReaderFormatError::Unrecognized) => {
                FfiKind::UnknownFormat
            }
            Self::InvalidConfiguration { setting, .. } => FfiKind::InvalidConfiguration {
                setting: Some(*setting),
            },
            Self::ReaderFormat(_) => FfiKind::InvalidConfiguration { setting: None },
            Self::PartialExtraction(partial) => partial.cause().ffi_kind(),
        }
    }

    /// The redacted, binding-facing description.
    fn ffi_description(&self) -> String {
        let path = self
            .redacted_path()
            .unwrap_or_else(|| "<unknown>".to_string());
        match self {
            Self::PathTraversal { .. } => format!("path traversal detected: {path}"),
            Self::SymlinkEscape { .. } => {
                format!("symlink target outside extraction directory: {path}")
            }
            Self::HardlinkEscape { .. } => {
                format!("hardlink target outside extraction directory: {path}")
            }
            Self::ZipBomb(_)
            | Self::ZipInconsistency(_)
            | Self::TarAmbiguity(_)
            | Self::TarTrailer(_)
            | Self::SecurityViolation { .. } => self.to_string(),
            Self::QuotaExceeded { resource } => resource.to_string(),
            Self::InvalidArchive(reason) => format!("invalid archive: {reason}"),
            Self::Io(io_err) => sanitize_io_error_for_error(io_err),
            Self::InvalidPermissions { mode, .. } => {
                format!("invalid permissions for {path}: {:#o}", mode.get())
            }
            Self::Cancelled => "operation cancelled".to_string(),
            Self::OutputReservationLeft { error, .. } => format!(
                "an empty reservation file remains at {path}: {}",
                sanitize_io_error_for_error(error)
            ),
            Self::ReplaceFailed(failure) => failure.redacted_description(),
            Self::DestinationOccupied { conflicts, .. } => format!(
                "destination {path} already holds {} of the paths to extract",
                conflicts.len()
            ),
            Self::SourceNotFound { .. } => format!("source path not found: {path}"),
            Self::SourceNotAccessible { error, .. } => {
                format!(
                    "source path is not accessible: {path}: {}",
                    sanitize_io_error_for_error(error)
                )
            }
            Self::OutputExists { .. } => format!("output file already exists: {path}"),
            Self::InvalidCompressionLevel { level } => {
                format!("invalid compression level {level}, must be 1-9")
            }
            Self::UnknownFormat { .. } => {
                format!("cannot determine archive format from: {path}")
            }
            Self::InvalidConfiguration { setting, problem } => format!(
                "invalid configuration: {}",
                super::config_error::message(*setting, problem)
            ),
            Self::ReaderFormat(reason) => reason.to_string(),
            Self::PartialExtraction(partial) => partial.cause().ffi_description(),
        }
    }

    /// Returns the stable [`ErrorCode`] of this error.
    ///
    /// Useful for matching on error types without full message formatting.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveError;
    /// use exarch_core::ErrorCode;
    /// use exarch_core::Violation;
    ///
    /// let err = ArchiveError::from(Violation::EncryptedArchive);
    /// assert_eq!(err.error_code(), ErrorCode::SecurityViolation);
    /// assert_eq!(err.error_code().as_str(), "SECURITY_VIOLATION");
    /// ```
    #[must_use]
    pub fn error_code(&self) -> ErrorCode {
        self.ffi_kind().code()
    }
}

#[cfg(test)]
mod tests {
    use super::super::config_error::ConfigProblem;
    use super::super::types::QuotaResource;
    use super::super::types::ZipBombDetails;
    use super::super::types::ZipBombScope;
    use super::super::violation::Violation;
    use super::*;
    use std::collections::HashSet;

    use crate::security::Compressed;
    use crate::security::Uncompressed;
    use std::assert_matches;
    use std::path::PathBuf;

    #[test]
    fn test_ffi_kind_accessors_expose_payload() {
        let kind = FfiKind::SecurityViolation {
            relaxable_by: Some(PolicySetting::Symlinks),
            sub_code: SecurityViolationSubCode::TarTrailer,
        };
        assert_eq!(kind.relaxable_by(), Some(PolicySetting::Symlinks));
        assert_eq!(
            kind.sub_code(),
            Some(SubCode::SecurityViolation(
                SecurityViolationSubCode::TarTrailer
            ))
        );
        let kind = FfiKind::InvalidArchive {
            sub_code: Some(InvalidArchiveSubCode::TarAmbiguity),
        };
        assert_eq!(kind.relaxable_by(), None);
        assert_eq!(kind.sub_code().map(SubCode::as_str), Some("TAR_AMBIGUITY"));
        assert_eq!(
            FfiKind::ZipBomb {
                scope: ZipBombScope::Entry
            }
            .sub_code()
            .map(SubCode::as_str),
            Some("ENTRY")
        );
    }

    /// Regression test for #462: `PathTraversal` carries an
    /// archive-relative, attacker-authored path and must never be redacted,
    /// unlike a genuinely host-derived path variant (see the test below).
    #[test]
    fn test_attacker_path_never_redacted() {
        let error = ArchiveError::PathTraversal {
            path: PathBuf::from("../../etc/passwd"),
        };
        let msg = error.into_ffi_message();
        assert!(msg.description.contains("../../etc/passwd"));
    }

    /// Regression test for #453: `SourceNotFound` carries a host filesystem
    /// path; in release builds it must be redacted to filename-only. This
    /// only exercises the release-build branch — the debug-build behavior
    /// is covered directly in `super::redaction`.
    #[test]
    #[cfg(not(debug_assertions))]
    fn test_host_path_redacted_in_release() {
        let error = ArchiveError::SourceNotFound {
            path: PathBuf::from("/srv/secret/app/x.txt"),
        };
        let msg = error.into_ffi_message();
        assert!(msg.description.contains("x.txt"));
        assert!(!msg.description.contains("/srv/secret"));
    }

    /// Regression test for #453: `Io` messages must not leak a host path
    /// embedded in the free-form message text in release builds.
    #[test]
    #[cfg(not(debug_assertions))]
    fn test_io_error_redacted_in_release() {
        let error = ArchiveError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "directory is not writable: /srv/secret/app/private-output",
        ));
        let msg = error.into_ffi_message();
        assert!(!msg.description.contains("/srv/secret"));
    }

    #[test]
    fn test_error_codes_match() {
        let test_cases = vec![
            (
                ArchiveError::PathTraversal {
                    path: PathBuf::from("test"),
                },
                ErrorCode::PathTraversal,
            ),
            (
                ArchiveError::SymlinkEscape {
                    path: PathBuf::from("test"),
                },
                ErrorCode::SymlinkEscape,
            ),
            (
                ArchiveError::ZipBomb(ZipBombDetails::new(
                    ZipBombScope::Entry,
                    Compressed(100),
                    Uncompressed(10000),
                )),
                ErrorCode::ZipBomb,
            ),
        ];

        for (error, expected_code) in test_cases {
            assert_eq!(error.error_code(), expected_code);
            assert_eq!(error.into_ffi_message().kind.code(), expected_code);
        }
    }

    fn one_error_per_variant() -> Vec<ArchiveError> {
        vec![
            ArchiveError::PathTraversal {
                path: PathBuf::from("test"),
            },
            ArchiveError::SymlinkEscape {
                path: PathBuf::from("test"),
            },
            ArchiveError::HardlinkEscape {
                path: PathBuf::from("test"),
            },
            ArchiveError::ZipBomb(ZipBombDetails::new(
                ZipBombScope::Entry,
                Compressed(100),
                Uncompressed(10000),
            )),
            ArchiveError::ZipInconsistency(
                super::super::zip_inconsistency::ZipInconsistency::OverlappingEntries,
            ),
            ArchiveError::QuotaExceeded {
                resource: QuotaResource::IntegerOverflow,
            },
            ArchiveError::from(Violation::EncryptedArchive),
            ArchiveError::unclassified("test"),
            ArchiveError::Io(std::io::Error::other("test")),
            ArchiveError::InvalidPermissions {
                path: PathBuf::from("test"),
                mode: crate::RawMode::new(0o777),
            },
            ArchiveError::SourceNotFound {
                path: PathBuf::from("test"),
            },
            ArchiveError::SourceNotAccessible {
                path: PathBuf::from("test"),
                error: std::io::Error::other("test"),
            },
            ArchiveError::OutputExists {
                path: PathBuf::from("test"),
            },
            ArchiveError::InvalidCompressionLevel {
                level: crate::RequestedLevel::Integer(10),
            },
            ArchiveError::UnknownFormat {
                path: PathBuf::from("test"),
            },
            ArchiveError::InvalidConfiguration {
                setting: ConfigSetting::OutputPath,
                problem: ConfigProblem::NotSet,
            },
        ]
    }

    #[test]
    fn test_all_error_variants_have_codes() {
        for error in one_error_per_variant() {
            let code = error.error_code();
            let msg = error.into_ffi_message();
            assert_eq!(msg.kind.code(), code);
            assert!(!msg.description.is_empty());
            assert!(msg.partial.is_none());
        }
    }

    #[test]
    fn test_kind_code_covers_error_code_all_exactly_once() {
        let mut seen: Vec<ErrorCode> = one_error_per_variant()
            .into_iter()
            .map(|e| e.into_ffi_message().kind.code())
            .collect();
        seen.sort_by_key(|c| c.as_str());
        let mut expected = ErrorCode::ALL.to_vec();
        expected.sort_by_key(|c| c.as_str());
        assert_eq!(seen, expected);
    }

    fn every_tar_ambiguity() -> Vec<super::super::tar_ambiguity::TarAmbiguity> {
        use super::super::tar_ambiguity::TarAmbiguity as A;
        use super::super::tar_ambiguity::TarExtensionKind as Ext;
        use super::super::tar_ambiguity::TarHeaderField as Field;
        use super::super::tar_ambiguity::TarNonRegularKind as NonRegular;
        use super::super::tar_ambiguity::TarPathKey as Key;
        let key = || "k".to_string();
        vec![
            A::MalformedRecord,
            A::EmptyKey,
            A::OversizedRecord { key: key() },
            A::DuplicateRecord { key: key() },
            A::UnsupportedRecord { key: key() },
            A::InvalidSize,
            A::GlobalOverride { key: key() },
            A::GlobalTooLarge { size: 2, limit: 1 },
            A::LocalBeforeGlobal,
            A::LongRecordBeforeGlobal,
            A::StackedLongRecord { key: Key::Path },
            A::StackedSizeRecord,
            A::UnrecognizedHeader { kind: Ext::Pax },
            A::SparseEntry,
            A::NonCanonicalNumber { field: Field::Size },
            A::PrefixWithoutUstar,
            A::ChecksumMismatch,
            A::DuplicateExtensionHeader { kind: Ext::Pax },
            A::WindowMismatch,
            A::NonZeroPadding,
            A::MalformedLongRecord {
                kind: Ext::LongName,
            },
            A::NonRegularPayload {
                kind: NonRegular::Directory,
                size: 1,
                path: "d".into(),
            },
            A::DirectoryNamedPayload {
                size: 1,
                path: "d/".into(),
            },
        ]
    }

    #[test]
    fn test_ffi_kind_sub_code_table() {
        use super::super::tar_trailer::TarTrailerRefusal as R;
        use super::super::tar_trailer::TrailerCorruption;

        let ambiguity = Some(InvalidArchiveSubCode::TarAmbiguity);
        let trailer = Some(InvalidArchiveSubCode::TarTrailer);
        let invalid = |sub_code| FfiKind::InvalidArchive { sub_code };

        for variant in every_tar_ambiguity() {
            let error = ArchiveError::TarAmbiguity(variant);
            assert_eq!(error.ffi_kind(), invalid(ambiguity), "{error:?}");
        }

        for refusal in [
            R::Truncated,
            R::Corrupt {
                cause: TrailerCorruption::Decoder,
                detail: "d".into(),
            },
            R::Corrupt {
                cause: TrailerCorruption::TrailingData,
                detail: "d".into(),
            },
        ] {
            let error = ArchiveError::TarTrailer(refusal);
            assert_eq!(error.ffi_kind(), invalid(trailer), "{error:?}");
        }
        assert_eq!(
            ArchiveError::TarTrailer(R::OverCap { cap: 1 }).ffi_kind(),
            FfiKind::SecurityViolation {
                relaxable_by: Some(PolicySetting::MaxTarMetadataBytes),
                sub_code: SecurityViolationSubCode::TarTrailer,
            }
        );

        assert_eq!(ArchiveError::unclassified("x").ffi_kind(), invalid(None));
        assert_eq!(
            ArchiveError::from(Violation::EncryptedArchive).ffi_kind(),
            FfiKind::SecurityViolation {
                relaxable_by: None,
                sub_code: SecurityViolationSubCode::Encrypted,
            }
        );
        let wrapped = ArchiveError::PartialExtraction(crate::Partial::new(
            ArchiveError::TarAmbiguity(super::super::tar_ambiguity::TarAmbiguity::SparseEntry),
            ExtractionReport::default(),
            PartialWrites::Kept,
        ));
        assert_eq!(wrapped.ffi_kind(), invalid(ambiguity));
    }

    #[test]
    fn test_partial_extraction_sets_partial() {
        let wrap = |writes| {
            ArchiveError::PartialExtraction(crate::Partial::new(
                ArchiveError::from(Violation::EncryptedArchive),
                ExtractionReport::default(),
                writes,
            ))
        };
        let kept = wrap(PartialWrites::Kept).into_ffi_message();
        assert_matches!(kept.partial, Some(PartialOutcome::Kept(_)));
        assert_eq!(kept.kind.code(), ErrorCode::SecurityViolation);
        let rolled = wrap(PartialWrites::RolledBack).into_ffi_message();
        assert_matches!(rolled.partial, Some(PartialOutcome::RolledBack));
        let discarded = wrap(PartialWrites::Discarded).into_ffi_message();
        assert_matches!(discarded.partial, Some(PartialOutcome::Discarded));
        assert_eq!(PartialOutcome::Discarded.writes(), PartialWrites::Discarded);
    }

    #[test]
    fn quota_and_zip_bomb_sub_codes_are_screaming_and_unique() {
        let quotas: Vec<_> = QuotaKind::ALL
            .iter()
            .map(|&kind| SubCode::Quota(kind).as_str())
            .collect();
        let scopes: Vec<_> = ZipBombScope::ALL
            .iter()
            .map(|&scope| SubCode::ZipBomb(scope).as_str())
            .collect();
        for set in [&quotas, &scopes] {
            let unique: HashSet<_> = set.iter().collect();
            assert_eq!(unique.len(), set.len(), "{set:?}");
            for code in set {
                assert!(
                    code.chars().all(|c| c.is_ascii_uppercase() || c == '_'),
                    "{code}"
                );
            }
        }
    }

    #[test]
    fn quota_and_zip_bomb_kinds_carry_their_sub_code() {
        let quota = ArchiveError::QuotaExceeded {
            resource: QuotaResource::SolidBlockMemory {
                scope: crate::SolidMemoryScope::Block,
                current: 2,
                max: 1,
            },
        };
        assert_eq!(
            quota.ffi_kind().sub_code(),
            Some(SubCode::Quota(QuotaKind::SolidBlockMemory))
        );
        assert_eq!(
            quota.ffi_kind().sub_code().map(SubCode::as_str),
            Some("SOLID_BLOCK_MEMORY")
        );
    }

    #[test]
    fn the_sub_code_constants_cover_every_kind_and_scope() {
        let quotas: Vec<_> = QuotaKind::ALL.iter().map(|&k| SubCode::Quota(k)).collect();
        assert_eq!(SubCode::QUOTA_ALL, quotas.as_slice());
        let scopes: Vec<_> = ZipBombScope::ALL
            .iter()
            .map(|&s| SubCode::ZipBomb(s))
            .collect();
        assert_eq!(SubCode::ZIP_BOMB_ALL, scopes.as_slice());
    }
}
