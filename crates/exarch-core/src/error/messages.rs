//! FFI error message formatting.
//!
//! The single source of binding-facing error data: a stable [`ErrorCode`], a
//! typed [`FfiKind`] with the payload each code carries, a redacted
//! description and the fate of partial output. Python, Node.js and the CLI
//! consume [`FfiErrorMessage`] instead of re-matching [`ArchiveError`].

use super::redaction::sanitize_io_error_for_error;
use super::types::ArchiveError;
use super::types::PartialWrites;
use super::types::PolicySetting;
use super::types::ReaderFormatError;
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
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub enum SecurityViolationSubCode {
        /// An over-cap tail after the TAR end-of-archive marker.
        TarTrailer => "TAR_TRAILER",
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
/// use std::assert_matches;
///
/// let msg = ArchiveError::violation("nope".into()).into_ffi_message();
/// assert_matches!(
///     msg.kind,
///     FfiKind::SecurityViolation {
///         relaxable_by: None,
///         sub_code: None,
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
    ZipBomb,
    /// ZIP structure is ambiguous or self-contradictory.
    ZipInconsistency,
    /// A quota was exceeded.
    QuotaExceeded,
    /// Denied by security policy.
    #[non_exhaustive]
    SecurityViolation {
        /// The `SecurityConfig` setting whose current value refused the
        /// entry; see [`ArchiveError::relaxable_by`].
        relaxable_by: Option<PolicySetting>,
        /// Finer classification, when the refusal has one.
        sub_code: Option<SecurityViolationSubCode>,
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
    InvalidConfiguration,
}

impl FfiKind {
    /// The stable [`ErrorCode`] of this class.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::PathTraversal => ErrorCode::PathTraversal,
            Self::SymlinkEscape => ErrorCode::SymlinkEscape,
            Self::HardlinkEscape => ErrorCode::HardlinkEscape,
            Self::ZipBomb => ErrorCode::ZipBomb,
            Self::ZipInconsistency => ErrorCode::ZipInconsistency,
            Self::QuotaExceeded => ErrorCode::QuotaExceeded,
            Self::SecurityViolation { .. } => ErrorCode::SecurityViolation,
            Self::InvalidArchive { .. } => ErrorCode::InvalidArchive,
            Self::Io(_) => ErrorCode::IoError,
            Self::InvalidPermissions => ErrorCode::InvalidPermissions,
            Self::SourceNotFound => ErrorCode::SourceNotFound,
            Self::SourceNotAccessible => ErrorCode::SourceNotAccessible,
            Self::OutputExists => ErrorCode::OutputExists,
            Self::InvalidCompressionLevel => ErrorCode::InvalidCompressionLevel,
            Self::UnknownFormat => ErrorCode::UnknownFormat,
            Self::InvalidConfiguration => ErrorCode::InvalidConfiguration,
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
}

impl FfiErrorMessage {
    const fn new(kind: FfiKind, description: String) -> Self {
        Self {
            kind,
            description,
            partial: None,
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
        if let Self::PartialExtraction {
            source,
            report,
            writes,
        } = self
        {
            let mut msg = source.into_ffi_message();
            msg.partial = Some(match writes {
                PartialWrites::Kept => PartialOutcome::Kept(report),
                PartialWrites::RolledBack => PartialOutcome::RolledBack,
                PartialWrites::Discarded => PartialOutcome::Discarded,
            });
            return msg;
        }
        FfiErrorMessage::new(self.ffi_kind(), self.ffi_description())
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
    ///
    /// let err = ArchiveError::InvalidArchive("bad".into());
    /// assert_eq!(err.ffi_kind().code(), ErrorCode::InvalidArchive);
    /// ```
    #[must_use]
    pub fn ffi_kind(&self) -> FfiKind {
        match self {
            Self::PathTraversal { .. } => FfiKind::PathTraversal,
            Self::SymlinkEscape { .. } => FfiKind::SymlinkEscape,
            Self::HardlinkEscape { .. } => FfiKind::HardlinkEscape,
            Self::ZipBomb(_) => FfiKind::ZipBomb,
            Self::ZipInconsistency(_) => FfiKind::ZipInconsistency,
            Self::QuotaExceeded { .. } => FfiKind::QuotaExceeded,
            Self::SecurityViolation { relaxable_by, .. } => FfiKind::SecurityViolation {
                relaxable_by: *relaxable_by,
                sub_code: None,
            },
            Self::InvalidArchive(_) => FfiKind::InvalidArchive { sub_code: None },
            Self::TarAmbiguity(_) => FfiKind::InvalidArchive {
                sub_code: Some(InvalidArchiveSubCode::TarAmbiguity),
            },
            Self::TarTrailer(refusal) => {
                if refusal.is_policy_refusal() {
                    FfiKind::SecurityViolation {
                        relaxable_by: refusal.relaxable_by(),
                        sub_code: Some(SecurityViolationSubCode::TarTrailer),
                    }
                } else {
                    FfiKind::InvalidArchive {
                        sub_code: Some(InvalidArchiveSubCode::TarTrailer),
                    }
                }
            }
            Self::Io(io_err) => FfiKind::Io(io_err.kind()),
            Self::InvalidPermissions { .. } => FfiKind::InvalidPermissions,
            Self::SourceNotFound { .. } => FfiKind::SourceNotFound,
            Self::SourceNotAccessible { .. } => FfiKind::SourceNotAccessible,
            Self::OutputExists { .. } => FfiKind::OutputExists,
            Self::InvalidCompressionLevel { .. } => FfiKind::InvalidCompressionLevel,
            Self::UnknownFormat { .. } | Self::ReaderFormat(ReaderFormatError::Unrecognized) => {
                FfiKind::UnknownFormat
            }
            Self::InvalidConfiguration { .. } | Self::ReaderFormat(_) => {
                FfiKind::InvalidConfiguration
            }
            Self::PartialExtraction { source, .. } => source.ffi_kind(),
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
            | Self::TarTrailer(_) => self.to_string(),
            Self::QuotaExceeded { resource } => resource.to_string(),
            Self::SecurityViolation { reason, .. } => {
                format!("operation denied by security policy: {reason}")
            }
            Self::InvalidArchive(reason) => format!("invalid archive: {reason}"),
            Self::Io(io_err) => sanitize_io_error_for_error(io_err),
            Self::InvalidPermissions { mode, .. } => {
                format!("invalid permissions for {path}: {mode:#o}")
            }
            Self::SourceNotFound { .. } => format!("source path not found: {path}"),
            Self::SourceNotAccessible { .. } => {
                format!("source path is not accessible: {path}")
            }
            Self::OutputExists { .. } => format!("output file already exists: {path}"),
            Self::InvalidCompressionLevel { level } => {
                format!("invalid compression level {level}, must be 1-9")
            }
            Self::UnknownFormat { .. } => {
                format!("cannot determine archive format from: {path}")
            }
            Self::InvalidConfiguration { reason } => format!("invalid configuration: {reason}"),
            Self::ReaderFormat(reason) => reason.to_string(),
            Self::PartialExtraction { source, .. } => source.ffi_description(),
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
    ///
    /// let err = ArchiveError::violation("nope".into());
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
    use super::super::types::QuotaResource;
    use super::super::types::ZipBombDetails;
    use super::super::types::ZipBombScope;
    use super::*;
    use std::assert_matches;
    use std::path::PathBuf;

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
                ArchiveError::ZipBomb(ZipBombDetails::new(ZipBombScope::Entry, 100, 10000)),
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
            ArchiveError::ZipBomb(ZipBombDetails::new(ZipBombScope::Entry, 100, 10000)),
            ArchiveError::ZipInconsistency(
                super::super::zip_inconsistency::ZipInconsistency::OverlappingEntries,
            ),
            ArchiveError::QuotaExceeded {
                resource: QuotaResource::IntegerOverflow,
            },
            ArchiveError::violation("test".into()),
            ArchiveError::InvalidArchive("test".into()),
            ArchiveError::Io(std::io::Error::other("test")),
            ArchiveError::InvalidPermissions {
                path: PathBuf::from("test"),
                mode: 0o777,
            },
            ArchiveError::SourceNotFound {
                path: PathBuf::from("test"),
            },
            ArchiveError::SourceNotAccessible {
                path: PathBuf::from("test"),
            },
            ArchiveError::OutputExists {
                path: PathBuf::from("test"),
            },
            ArchiveError::InvalidCompressionLevel { level: 10 },
            ArchiveError::UnknownFormat {
                path: PathBuf::from("test"),
            },
            ArchiveError::InvalidConfiguration {
                reason: "test".into(),
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
                sub_code: Some(SecurityViolationSubCode::TarTrailer),
            }
        );

        assert_eq!(
            ArchiveError::InvalidArchive("x".into()).ffi_kind(),
            invalid(None)
        );
        assert_eq!(
            ArchiveError::violation("x".into()).ffi_kind(),
            FfiKind::SecurityViolation {
                relaxable_by: None,
                sub_code: None,
            }
        );
        let wrapped = ArchiveError::PartialExtraction {
            source: Box::new(ArchiveError::TarAmbiguity(
                super::super::tar_ambiguity::TarAmbiguity::SparseEntry,
            )),
            report: ExtractionReport::default(),
            writes: PartialWrites::Kept,
        };
        assert_eq!(wrapped.ffi_kind(), invalid(ambiguity));
    }

    #[test]
    fn test_partial_extraction_sets_partial() {
        let wrap = |writes| ArchiveError::PartialExtraction {
            source: Box::new(ArchiveError::violation("x".into())),
            report: ExtractionReport::default(),
            writes,
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
}
