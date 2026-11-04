//! Typed refusals for the bytes after the end-of-archive marker of a
//! compressed TAR.

use super::types::PolicySetting;
use crate::closed_enum::closed_enum;
use crate::inspection::integrity::MIN_TRAILER_CAP;

closed_enum! {
    /// What is wrong with the compressed stream after the TAR
    /// end-of-archive marker.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::TrailerCorruption;
    ///
    /// assert_eq!(TrailerCorruption::Decoder.to_string(), "decoder error");
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum TrailerCorruption {
        /// Bytes that are neither another compressed member nor zero padding
        /// follow the last member. Raised by the gzip and bzip2 decoders only:
        /// trailing garbage after an xz or zstd stream is a decoder error.
        TrailingData => "trailing data after the last compressed member",
        /// The codec rejected the stream: a checksum mismatch, a corrupt
        /// block or a malformed member.
        Decoder => "decoder error",
    }
}

/// Why the bytes after the end-of-archive marker of a compressed TAR were
/// refused.
///
/// `detail` is the decoder's message, for display only: never compare it with
/// a real message.
///
/// # Examples
///
/// ```
/// use exarch_core::ArchiveError;
/// use exarch_core::TarTrailerRefusal;
///
/// let err = ArchiveError::TarTrailer(TarTrailerRefusal::Truncated);
/// assert!(err.to_string().contains("TAR end-of-archive marker"));
/// assert!(!err.is_security_violation());
///
/// let err = ArchiveError::TarTrailer(TarTrailerRefusal::OverCap { cap: 1 << 20 });
/// assert!(err.is_security_violation());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TarTrailerRefusal {
    /// More decoded bytes than `cap` follow the marker. Relaxable through
    /// `max_tar_metadata_bytes`.
    OverCap {
        /// The effective cap in bytes: `max_tar_metadata_bytes`, raised to the
        /// 1 MiB floor.
        cap: u64,
    },
    /// The stream after the marker is corrupt.
    Corrupt {
        /// What kind of corruption it is.
        cause: TrailerCorruption,
        /// The decoder's message, for display only.
        detail: String,
    },
    /// The stream ends inside a compressed member after the marker.
    Truncated,
}

impl TarTrailerRefusal {
    /// The setting that lifts this refusal, if one does.
    pub(crate) const fn relaxable_by(&self) -> Option<PolicySetting> {
        match self {
            Self::OverCap { .. } => Some(PolicySetting::MaxTarMetadataBytes),
            Self::Corrupt { .. } | Self::Truncated => None,
        }
    }

    /// The message without its `invalid archive` or `operation denied by
    /// security policy` prefix.
    pub(crate) fn reason(&self) -> String {
        const PREFIX: &str = "integrity check failed after the TAR end-of-archive marker";
        match self {
            Self::Corrupt { detail, .. } => format!("{PREFIX}: {detail}"),
            Self::Truncated => format!("{PREFIX}: the compressed stream is truncated"),
            Self::OverCap { cap } => over_cap_reason(*cap),
        }
    }

    /// Whether the stream was refused by policy rather than for being
    /// corrupt.
    pub(crate) const fn is_policy_refusal(&self) -> bool {
        match self {
            Self::OverCap { .. } => true,
            Self::Corrupt { .. } | Self::Truncated => false,
        }
    }
}

/// The refusal of an over-cap tail without the policy prefix.
pub(crate) fn over_cap_reason(cap: u64) -> String {
    format!(
        "more than {cap} bytes follow the TAR end-of-archive marker (at least \
         {MIN_TRAILER_CAP} bytes are always allowed)"
    )
}

impl std::fmt::Display for TarTrailerRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OverCap { .. } => {
                write!(f, "operation denied by security policy: {}", self.reason())
            }
            Self::Corrupt { .. } | Self::Truncated => {
                write!(f, "invalid archive: {}", self.reason())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names_the_marker_in_every_variant() {
        for refusal in [
            TarTrailerRefusal::OverCap { cap: 7 },
            TarTrailerRefusal::Corrupt {
                cause: TrailerCorruption::Decoder,
                detail: "checksum mismatch".into(),
            },
            TarTrailerRefusal::Truncated,
        ] {
            assert!(
                refusal.to_string().contains("TAR end-of-archive marker"),
                "{refusal:?}"
            );
        }
    }

    fn corrupt() -> TarTrailerRefusal {
        TarTrailerRefusal::Corrupt {
            cause: TrailerCorruption::TrailingData,
            detail: "x".into(),
        }
    }

    #[test]
    fn only_the_over_cap_refusal_is_a_relaxable_policy_violation() {
        use crate::ArchiveError;
        use crate::ErrorCode;
        use crate::FfiKind;
        use crate::InvalidArchiveSubCode;
        use crate::SecurityViolationSubCode;
        use crate::inspection::report::IssueCategory;
        use crate::inspection::report::IssueSeverity;
        use crate::inspection::report::VerificationIssue;

        let over = ArchiveError::TarTrailer(TarTrailerRefusal::OverCap { cap: 9 });
        assert!(over.is_security_violation() && over.is_recoverable());
        assert_eq!(
            over.relaxable_by(),
            Some(PolicySetting::MaxTarMetadataBytes)
        );
        assert_eq!(over.context(), None);
        assert_eq!(over.error_code(), ErrorCode::SecurityViolation);
        assert_eq!(
            over.into_ffi_message().kind,
            FfiKind::SecurityViolation {
                relaxable_by: Some(PolicySetting::MaxTarMetadataBytes),
                sub_code: SecurityViolationSubCode::TarTrailer,
            }
        );
        let issue = VerificationIssue::from_error(
            &ArchiveError::TarTrailer(TarTrailerRefusal::OverCap { cap: 9 }),
            None,
        );
        assert_eq!(issue.category, IssueCategory::SecurityPolicy);
        assert_eq!(issue.severity, IssueSeverity::High);

        for refusal in [corrupt(), TarTrailerRefusal::Truncated] {
            let error = ArchiveError::TarTrailer(refusal.clone());
            assert!(!error.is_security_violation() && !error.is_recoverable());
            assert_eq!(error.relaxable_by(), None);
            assert_eq!(error.context(), None);
            assert_eq!(error.error_code(), ErrorCode::InvalidArchive);
            assert_eq!(
                error.into_ffi_message().kind,
                FfiKind::InvalidArchive {
                    sub_code: Some(InvalidArchiveSubCode::TarTrailer)
                }
            );
            let issue = VerificationIssue::from_error(&ArchiveError::TarTrailer(refusal), None);
            assert_eq!(issue.category, IssueCategory::InvalidArchive);
            assert_eq!(issue.severity, IssueSeverity::High);
        }
    }

    #[test]
    fn a_partial_extraction_delegates_to_the_refusal() {
        use crate::ArchiveError;
        use crate::ExtractionReport;
        use crate::PartialWrites;

        let wrapped = ArchiveError::PartialExtraction(crate::Partial::new(
            ArchiveError::TarTrailer(TarTrailerRefusal::OverCap { cap: 1 }),
            ExtractionReport::default(),
            PartialWrites::Kept,
        ));
        assert!(wrapped.is_security_violation());
        assert_eq!(
            wrapped.relaxable_by(),
            Some(PolicySetting::MaxTarMetadataBytes)
        );
    }

    #[test]
    fn over_cap_names_the_effective_cap() {
        let text = TarTrailerRefusal::OverCap { cap: 4_194_304 }.to_string();
        assert!(text.contains("more than 4194304 bytes"), "{text}");
    }
}
