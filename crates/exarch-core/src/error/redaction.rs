//! Shared path and I/O-error redaction algorithms for FFI-facing error
//! messages.
//!
//! `exarch-python` and `exarch-node` both render [`ArchiveError`] into
//! host-language exceptions and must decide, per error variant, how much
//! path information to expose. Getting this wrong in either direction is a
//! problem: leaking a host filesystem path can disclose internal directory
//! structure to a user reading a release-build error message (see #453),
//! while over-redacting an archive-relative path that the *attacker*
//! already authored (e.g. a `PathTraversal` entry) destroys the defender's
//! ability to identify which archive entry triggered the violation without
//! actually hiding anything (see #462).
//!
//! This module owns the two redaction algorithms — [`sanitize_path_for_error`]
//! for genuinely host-derived paths and [`format_entry_path_for_error`] for
//! archive-relative, attacker-authored paths — plus
//! [`sanitize_io_error_for_error`] for I/O error messages (see #463, #464).
//! Both bindings call these algorithms directly, per variant, in their own
//! `convert_error`; [`ArchiveError::to_ffi_message`] uses them via
//! [`ArchiveError::redacted_path`]. The mapping from variant to algorithm is
//! therefore still applied independently in three places — here (via
//! `redacted_path`), in `exarch-python::convert_error`, and in
//! `exarch-node::convert_error` — only the two algorithms themselves are
//! single-sourced.

use std::path::Path;

use super::types::ArchiveError;

/// Formats a host-derived filesystem path for inclusion in an FFI error
/// message.
///
/// In debug builds, returns the full path for detailed diagnostics. In
/// release builds, returns only the filename to avoid leaking internal
/// directory structures to potential attackers.
///
/// Use this for variants whose path was derived from the host filesystem
/// (e.g. [`ArchiveError::SourceNotFound`]), not for archive-relative,
/// attacker-authored paths — see [`format_entry_path_for_error`] for those.
///
/// # Examples
///
/// ```
/// use exarch_core::sanitize_path_for_error;
/// use std::path::Path;
///
/// // Debug builds keep the full path; release builds keep only the
/// // filename — either way the filename itself is always present.
/// let redacted = sanitize_path_for_error(Path::new("/srv/secret/app/x.txt"));
/// assert!(redacted.ends_with("x.txt"));
/// ```
#[cfg(debug_assertions)]
#[must_use]
pub fn sanitize_path_for_error(path: &Path) -> String {
    path.display().to_string()
}

/// Formats a host-derived filesystem path for inclusion in an FFI error
/// message.
///
/// In debug builds, returns the full path for detailed diagnostics. In
/// release builds, returns only the filename to avoid leaking internal
/// directory structures to potential attackers.
///
/// Use this for variants whose path was derived from the host filesystem
/// (e.g. [`ArchiveError::SourceNotFound`]), not for archive-relative,
/// attacker-authored paths — see [`format_entry_path_for_error`] for those.
///
/// # Examples
///
/// ```
/// use exarch_core::sanitize_path_for_error;
/// use std::path::Path;
///
/// // Debug builds keep the full path; release builds keep only the
/// // filename — either way the filename itself is always present.
/// let redacted = sanitize_path_for_error(Path::new("/srv/secret/app/x.txt"));
/// assert!(redacted.ends_with("x.txt"));
/// ```
#[cfg(not(debug_assertions))]
#[must_use]
pub fn sanitize_path_for_error(path: &Path) -> String {
    path.file_name().map_or_else(
        || "<unknown>".to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

/// Formats an archive-relative, attacker-authored path for inclusion in an
/// FFI error message.
///
/// Unlike [`sanitize_path_for_error`], this never redacts: it always
/// returns the full path, in both debug and release builds. It exists for
/// variants like [`ArchiveError::PathTraversal`],
/// [`ArchiveError::SymlinkEscape`], and [`ArchiveError::HardlinkEscape`], whose
/// `path` is an entry path the attacker crafted inside the archive, not a host
/// filesystem path — see #462. The attacker already knows the path they
/// authored, so redacting it discloses nothing to them while destroying the
/// defender's ability to identify the offending entry in a redacted
/// release-build log.
///
/// # Examples
///
/// ```
/// use exarch_core::format_entry_path_for_error;
/// use std::path::Path;
///
/// let path = Path::new("../../etc/passwd");
/// assert_eq!(
///     format_entry_path_for_error(path),
///     path.display().to_string()
/// );
/// ```
#[must_use]
pub fn format_entry_path_for_error(path: &Path) -> String {
    path.display().to_string()
}

/// Sanitizes I/O error messages for FFI error reporting.
///
/// In debug builds, returns the full `Display` output (which may embed a
/// host path, e.g. from `DestDir`'s validation messages). In release
/// builds, returns only the [`std::io::ErrorKind`] description, since the
/// free-form message text has no structured path field to redact.
///
/// Exception: errors carrying an [`IoContext`](super::IoContext) — used at
/// `std::io::Error::other` call sites whose [`std::io::ErrorKind::Other`]
/// description would otherwise redact to the uninformative "other error"
/// (see #464) — surface [`IoContext::context`](super::IoContext::context) in
/// release builds instead. That is safe because `context` is always a
/// `&'static str` fixed at the call site, never built from path or archive
/// entry data.
///
/// # Examples
///
/// ```
/// use exarch_core::sanitize_io_error_for_error;
///
/// let err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
/// let msg = sanitize_io_error_for_error(&err);
/// assert!(!msg.is_empty());
/// ```
#[cfg(debug_assertions)]
#[must_use]
pub fn sanitize_io_error_for_error(e: &std::io::Error) -> String {
    e.to_string()
}

/// Sanitizes I/O error messages for FFI error reporting.
///
/// In debug builds, returns the full `Display` output (which may embed a
/// host path, e.g. from `DestDir`'s validation messages). In release
/// builds, returns only the [`std::io::ErrorKind`] description, since the
/// free-form message text has no structured path field to redact.
///
/// Exception: errors carrying an [`IoContext`](super::IoContext) — used at
/// `std::io::Error::other` call sites whose [`std::io::ErrorKind::Other`]
/// description would otherwise redact to the uninformative "other error"
/// (see #464) — surface [`IoContext::context`](super::IoContext::context) in
/// release builds instead. That is safe because `context` is always a
/// `&'static str` fixed at the call site, never built from path or archive
/// entry data.
///
/// # Examples
///
/// ```
/// use exarch_core::sanitize_io_error_for_error;
///
/// let err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
/// let msg = sanitize_io_error_for_error(&err);
/// assert!(!msg.is_empty());
/// ```
#[cfg(not(debug_assertions))]
#[must_use]
pub fn sanitize_io_error_for_error(e: &std::io::Error) -> String {
    e.get_ref()
        .and_then(|inner| inner.downcast_ref::<super::IoContext>())
        .map_or_else(|| e.kind().to_string(), |ctx| ctx.context.to_string())
}

impl ArchiveError {
    /// Formats this error's path field for an FFI-facing error message,
    /// applying the shared redaction policy, or returns `None` if this
    /// variant carries no path.
    ///
    /// Maps each [`ArchiveError`] variant to the correct redaction
    /// algorithm — [`format_entry_path_for_error`] (never redacted) for
    /// archive-relative, attacker-authored paths, or
    /// [`sanitize_path_for_error`] (redacted to filename-only in release
    /// builds) for genuinely host-derived paths (see #462). Used by
    /// [`Self::to_ffi_message`]. `exarch-python` and `exarch-node` apply
    /// this same variant-to-algorithm mapping independently in their own
    /// `convert_error` — calling [`format_entry_path_for_error`] and
    /// [`sanitize_path_for_error`] directly, per match arm, rather than
    /// through this method — so the mapping itself is duplicated across
    /// core, python, and node; only the two algorithms are single-sourced
    /// (see #463). `test_never_redacted_variants_keep_full_path` and
    /// `test_host_path_variants_follow_profile_policy` below guard this
    /// method's mapping; the bindings' own tests guard theirs.
    ///
    /// [`Self::InvalidPermissions`] carries an archive entry path (see
    /// `check_permissions` in `inspection::verify`), not a host path, so it
    /// is grouped with the never-redacted variants for the same reason as
    /// `PathTraversal`/`SymlinkEscape`/`HardlinkEscape`.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveError;
    /// use std::path::PathBuf;
    ///
    /// let err = ArchiveError::PathTraversal {
    ///     path: PathBuf::from("../../etc/passwd"),
    /// };
    /// assert_eq!(err.redacted_path().as_deref(), Some("../../etc/passwd"));
    ///
    /// let err = ArchiveError::InvalidCompressionLevel { level: 0 };
    /// assert_eq!(err.redacted_path(), None);
    /// ```
    #[must_use]
    pub fn redacted_path(&self) -> Option<String> {
        match self {
            Self::PathTraversal { path }
            | Self::SymlinkEscape { path }
            | Self::HardlinkEscape { path }
            | Self::InvalidPermissions { path, .. } => Some(format_entry_path_for_error(path)),

            Self::SourceNotFound { path }
            | Self::SourceNotAccessible { path }
            | Self::OutputExists { path }
            | Self::UnknownFormat { path } => Some(sanitize_path_for_error(path)),

            Self::PartialExtraction { source, .. } => source.redacted_path(),

            Self::Io(_)
            | Self::InvalidArchive(_)
            | Self::ZipBomb { .. }
            | Self::QuotaExceeded { .. }
            | Self::SecurityViolation { .. }
            | Self::InvalidCompressionLevel { .. }
            | Self::InvalidConfiguration { .. } => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ExtractionReport;
    use std::path::PathBuf;

    #[test]
    #[cfg(debug_assertions)]
    fn test_sanitize_path_for_error_keeps_full_path_in_debug() {
        let path = PathBuf::from("/srv/secret/app/x.txt");
        assert_eq!(sanitize_path_for_error(&path), "/srv/secret/app/x.txt");
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn test_sanitize_path_for_error_strips_directory_in_release() {
        let path = PathBuf::from("/srv/secret/app/x.txt");
        assert_eq!(sanitize_path_for_error(&path), "x.txt");
    }

    #[test]
    fn test_format_entry_path_for_error_never_redacts() {
        let path = PathBuf::from("../../etc/passwd");
        assert_eq!(format_entry_path_for_error(&path), "../../etc/passwd");
    }

    #[test]
    #[cfg(debug_assertions)]
    fn test_sanitize_io_error_for_error_keeps_message_in_debug() {
        let err = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "directory is not writable: /srv/secret/app/private-output",
        );
        assert_eq!(
            sanitize_io_error_for_error(&err),
            "directory is not writable: /srv/secret/app/private-output"
        );
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn test_sanitize_io_error_for_error_redacts_message_in_release() {
        let err = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "directory is not writable: /srv/secret/app/private-output",
        );
        let msg = sanitize_io_error_for_error(&err);
        assert!(!msg.contains("/srv/secret/app"));
        assert!(msg.contains("permission denied"));
    }

    /// Regression test for #464: `ErrorKind::Other` would otherwise redact to
    /// the uninformative "other error", so an `IoContext` payload surfaces its
    /// static `context` instead — without leaking the dynamic detail.
    #[test]
    #[cfg(not(debug_assertions))]
    fn test_sanitize_io_error_for_error_surfaces_io_context_in_release() {
        let err = std::io::Error::other(crate::IoContext::new(
            "failed to read entry metadata",
            "/srv/secret/app/x.txt: permission denied",
        ));
        let msg = sanitize_io_error_for_error(&err);
        assert_eq!(msg, "failed to read entry metadata");
    }

    #[test]
    #[cfg(debug_assertions)]
    fn test_sanitize_io_error_for_error_keeps_io_context_detail_in_debug() {
        let err = std::io::Error::other(crate::IoContext::new(
            "failed to read entry metadata",
            "/srv/secret/app/x.txt: permission denied",
        ));
        assert_eq!(
            sanitize_io_error_for_error(&err),
            "failed to read entry metadata: /srv/secret/app/x.txt: permission denied"
        );
    }

    /// Regression test for #462: every `ArchiveError` variant carrying an
    /// archive-relative, attacker-authored path must keep the full path in
    /// `redacted_path`, in both debug and release builds.
    #[test]
    fn test_never_redacted_variants_keep_full_path() {
        let attacker_path = PathBuf::from("../../etc/passwd");
        let never_redacted = [
            ArchiveError::PathTraversal {
                path: attacker_path.clone(),
            },
            ArchiveError::SymlinkEscape {
                path: attacker_path.clone(),
            },
            ArchiveError::HardlinkEscape {
                path: attacker_path.clone(),
            },
            ArchiveError::InvalidPermissions {
                path: attacker_path,
                mode: 0o777,
            },
        ];

        for err in never_redacted {
            assert_eq!(
                err.redacted_path().as_deref(),
                Some("../../etc/passwd"),
                "expected full path to survive redaction for {err:?}"
            );
        }
    }

    /// Regression test for #453/#462: every `ArchiveError` variant carrying
    /// a genuinely host-derived path is redacted to filename-only in
    /// release builds (and kept in full in debug builds).
    #[test]
    fn test_host_path_variants_follow_profile_policy() {
        let host_path = PathBuf::from("/srv/secret/app/x.txt");
        let host_derived = [
            ArchiveError::SourceNotFound {
                path: host_path.clone(),
            },
            ArchiveError::SourceNotAccessible {
                path: host_path.clone(),
            },
            ArchiveError::OutputExists {
                path: host_path.clone(),
            },
            ArchiveError::UnknownFormat { path: host_path },
        ];

        for err in host_derived {
            let redacted = err.redacted_path().expect("variant carries a path");
            assert!(
                redacted.ends_with("x.txt"),
                "expected filename to survive redaction for {err:?}, got {redacted:?}"
            );
            #[cfg(not(debug_assertions))]
            assert!(
                !redacted.contains("/srv/secret"),
                "expected host directory to be redacted for {err:?}, got {redacted:?}"
            );
        }
    }

    #[test]
    fn test_variants_without_path_return_none() {
        let no_path = [
            ArchiveError::ZipBomb {
                compressed: 100,
                uncompressed: 100_000,
                ratio: 1000.0,
            },
            ArchiveError::InvalidArchive("bad header".to_string()),
            ArchiveError::SecurityViolation {
                reason: "test".to_string(),
            },
            ArchiveError::InvalidCompressionLevel { level: 0 },
            ArchiveError::InvalidConfiguration {
                reason: "test".to_string(),
            },
            ArchiveError::Io(std::io::Error::other("test")),
        ];

        for err in no_path {
            assert_eq!(err.redacted_path(), None, "expected no path for {err:?}");
        }
    }

    /// Regression test for #251/#210: `PartialExtraction` must delegate to
    /// its `source`'s redaction policy rather than exposing a path itself.
    #[test]
    fn test_partial_extraction_delegates_to_source() {
        let err = ArchiveError::PartialExtraction {
            source: Box::new(ArchiveError::PathTraversal {
                path: PathBuf::from("../../etc/passwd"),
            }),
            report: ExtractionReport::new(),
        };
        assert_eq!(err.redacted_path().as_deref(), Some("../../etc/passwd"));
    }
}
