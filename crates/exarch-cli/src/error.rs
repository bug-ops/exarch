//! Error conversion utilities for CLI.
//!
//! Converts exarch-core's typed errors (thiserror) into user-friendly
//! contextual errors (anyhow) with actionable guidance.

use crate::output::terminal::TerminalPath;
use crate::output::terminal::TerminalText;
use anyhow::Result;
use exarch_core::ArchiveError;
use exarch_core::CompressionRatio;
use exarch_core::ExtractionReport;
use exarch_core::PartialWrites;
use exarch_core::ZipBombDetails;
use exarch_core::ZipBombScope;
use std::fmt;
use std::path::Path;

fn zip_bomb_hint(details: &ZipBombDetails) -> &'static str {
    match (details.ratio(), details.scope()) {
        (CompressionRatio::Unbounded, _) => {
            "The archive claims data from zero compressed bytes, so its size metadata is \
             inconsistent and no ratio limit admits it."
        }
        (CompressionRatio::Finite(_), ZipBombScope::SolidBlock) => {
            "Solid 7z blocks use a fixed 1000x limit that the CLI cannot change."
        }
        (CompressionRatio::Finite(_), _) => {
            "--max-compression-ratio allows higher ratios for ZIP and non-solid 7z if legitimate."
        }
    }
}

/// Sentinel error returned by `verify::execute` when `--strict` is active and
/// the archive has a `Warning`-status verification report. `main` maps this to
/// exit code 2 without printing an error message (the formatter already
/// reported the warning details to stdout/stderr before this is returned).
#[derive(Debug)]
pub struct StrictWarning;

impl fmt::Display for StrictWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Archive has warnings (--strict mode)")
    }
}

impl std::error::Error for StrictWarning {}

/// Sentinel error returned by `verify::execute` when the verification report
/// has `Fail` status.
///
/// The verification report itself (already emitted by the formatter, with
/// `data.status == "FAIL"` in JSON mode) fully describes the failure, so
/// `main` must not print a second error envelope for `--json` output — doing
/// so would emit two concatenated top-level JSON documents on stdout. For
/// human-readable output, `main` still prints this sentinel via
/// `format_error` and exits non-zero, matching prior behavior.
#[derive(Debug)]
pub struct VerificationFailed;

impl fmt::Display for VerificationFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Archive verification failed")
    }
}

impl std::error::Error for VerificationFailed {}

/// CLI-authored message layered over an optional [`ArchiveError`].
///
/// A distinct error type, not an anyhow `.context()` string, so the human
/// formatter can recognise it in the error chain and keep its line breaks
/// while escaping everything else. `Display` is the message alone; the wrapped
/// error is exposed as the `source`, so `{:#}` renders `message: error`.
#[derive(Debug)]
pub struct CliContext {
    text: String,
    source: Option<ArchiveError>,
}

impl CliContext {
    /// A message that wraps no underlying error.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            source: None,
        }
    }

    fn wrapping(text: String, source: ArchiveError) -> Self {
        Self {
            text,
            source: Some(source),
        }
    }
}

impl fmt::Display for CliContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl std::error::Error for CliContext {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

/// Carrier for partial-extraction progress embedded in the anyhow error chain.
///
/// `ArchiveError::PartialExtraction` uses `#[error("{source}")]` with
/// `#[source]`, so placing it directly in an anyhow chain causes the inner
/// error text to appear twice in `{:#}` output (once via Display, once via the
/// source chain).  This type carries the report without re-emitting the inner
/// error text in its own Display, keeping the anyhow chain clean. The
/// converted inner error is its `source`.
#[derive(Debug)]
pub struct PartialExtractionContext {
    pub(crate) report: ExtractionReport,
    pub(crate) writes: PartialWrites,
    inner: anyhow::Error,
}

impl fmt::Display for PartialExtractionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let r = &self.report;
        match self.writes {
            PartialWrites::Kept => {
                let items = r.files_extracted + r.directories_created + r.symlinks_created;
                write!(
                    f,
                    "WARNING: Extraction was stopped. {items} items ({} files, {} directories, {} symlinks) \
                     were written to disk before the error.",
                    r.files_extracted, r.directories_created, r.symlinks_created,
                )?;
                if r.files_skipped > 0 {
                    write!(f, "\nFiles skipped: {}", r.files_skipped)?;
                }
                if !r.warnings.is_empty() {
                    write!(f, "\nWarnings:")?;
                    for warning in &r.warnings {
                        write!(f, "\n  - {}", TerminalText::new(warning))?;
                    }
                }
                write!(
                    f,
                    "\nHINT: Inspect or remove the output directory before re-running."
                )
            }
            // The counts and warnings describe the discarded run, not the
            // destination.
            PartialWrites::RolledBack => f.write_str(
                "WARNING: Extraction was stopped. --atomic discarded the partial extraction; the \
                 destination was left unchanged.",
            ),
            // Forward-compat for a `PartialWrites` state added after this
            // match.
            _ => f.write_str("WARNING: Extraction was stopped."),
        }
    }
}

impl std::error::Error for PartialExtractionContext {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.inner.as_ref())
    }
}

/// Fixed literal prefixes `exarch-core` builds `SecurityViolation.reason`
/// strings from for the four categories the CLI's policy flags
/// (`--allow-symlinks`, `--allow-hardlinks`, `--allow-solid-archives`,
/// `--banned-component`) actually relax. Verified against the exact
/// construction call sites: `types/safe_symlink.rs`, `security/hardlink.rs`,
/// `formats/sevenz.rs`, and `types/safe_path.rs` / `types/safe_symlink.rs`
/// (banned components can appear either in the entry path itself or in a
/// symlink's target, hence two prefixes for that one category).
const RELAXABLE_VIOLATION_PREFIXES: &[&str] = &[
    "symlinks not allowed",
    "hardlinks not allowed",
    "solid 7z archives are not allowed",
    "banned path component:",
    "symlink target contains banned component:",
];

/// Returns `true` if `reason` names a `SecurityViolation` category one of the
/// CLI's policy flags can actually relax.
///
/// Matches with `starts_with`, anchored at the very beginning of `reason`:
/// each prefix above is the fixed literal text `exarch-core` writes before
/// any attacker-controlled data (an entry path, a component name, etc.), so
/// a forged archive cannot spoof this classification by choosing path
/// components that happen to contain one of these prefixes elsewhere in the
/// string — only a `reason` that genuinely originates from one of these
/// call sites starts with it.
fn is_relaxable_by_policy_flag(reason: &str) -> bool {
    RELAXABLE_VIOLATION_PREFIXES
        .iter()
        .any(|prefix| reason.starts_with(prefix))
}

fn quota_exceeded_context(
    resource: &exarch_core::QuotaResource,
    archive: TerminalPath<'_>,
) -> String {
    if matches!(resource, exarch_core::QuotaResource::DecoderMemory { .. }) {
        format!(
            "Decoder memory limit exceeded for '{archive}'\n\
             The archive declares a decompression dictionary larger than the allowed limit."
        )
    } else {
        format!(
            "Extraction limit exceeded for '{archive}'\n\
             HINT: Use --max-files, --max-total-size, or --max-file-size to increase limits."
        )
    }
}

/// Converts `ArchiveError` to user-friendly anyhow error with context.
///
/// The original `ArchiveError` is preserved as the source of a [`CliContext`]
/// so that callers can downcast via the anyhow chain (used by JSON error
/// output).
///
/// `allow_symlinks` suppresses the `--allow-symlinks` hint for `SymlinkEscape`
/// errors when the flag is already active — in that case the escape is a
/// genuine security violation, not a configuration issue.
///
/// A `PartialExtraction` keeps the `writes` outcome core recorded.
pub fn convert_extraction_error(
    err: ArchiveError,
    archive: &Path,
    allow_symlinks: bool,
) -> anyhow::Error {
    // Handle PartialExtraction before the borrow below.
    //
    // `PartialExtraction` is `#[error("{source}")]` with `#[source]`, so
    // placing it in an anyhow chain directly would cause the inner error text
    // to appear twice in `{:#}` output. Recursing gives the inner `source`
    // its own fully-formed, category-specific context (HINT included) first;
    // `PartialExtractionContext` is then layered on top as an additional
    // context frame, which — unlike `PartialExtraction` itself — never
    // re-displays the inner error text.
    //
    // This keeps issue #204's "inner error text appears exactly once in
    // `{:#}`" guarantee: no CLI-authored `context` string below interpolates
    // data the wrapped error's own Display already carries.
    if let ArchiveError::PartialExtraction {
        source,
        report,
        writes,
    } = err
    {
        let inner = convert_extraction_error(*source, archive, allow_symlinks);
        return anyhow::Error::new(PartialExtractionContext {
            report,
            writes,
            inner,
        });
    }

    let archive = TerminalPath::new(archive);
    let context = match &err {
        ArchiveError::PartialExtraction { .. } => unreachable!(),
        ArchiveError::PathTraversal { .. } => format!(
            "Security violation: Archive '{archive}' attempted path traversal\n\
             HINT: This archive may be malicious. Do not extract from untrusted sources."
        ),
        ArchiveError::ZipBomb(details) => format!(
            "Security violation: Archive '{archive}' appears to be a zip bomb\n\
             HINT: {}",
            zip_bomb_hint(details),
        ),
        ArchiveError::ZipInconsistency(_) => format!(
            "Security violation: ZIP archive '{archive}' is read differently by different tools\n\
             HINT: The archive may be crafted to show different content to different extractors. \
             Use --zip-consistency ignore only for archives from a trusted producer."
        ),
        ArchiveError::QuotaExceeded { resource } => quota_exceeded_context(resource, archive),
        ArchiveError::SymlinkEscape { .. } => {
            if allow_symlinks {
                format!("Symlink escape blocked in '{archive}'")
            } else {
                format!(
                    "Symlink rejected in '{archive}'\n\
                     HINT: Use --allow-symlinks to extract symlinks (only if trusted source)."
                )
            }
        }
        ArchiveError::HardlinkEscape { .. } => format!(
            "Hardlink rejected in '{archive}'\n\
             HINT: Use --allow-hardlinks to extract hardlinks (only if trusted source)."
        ),
        ArchiveError::Io(_) => format!("Failed to process '{archive}'"),
        ArchiveError::UnknownFormat { path } => format!(
            "Cannot determine archive format: {}\n\
             HINT: Supported formats: tar, tar.gz, tar.bz2, tar.xz, tar.zstd, zip",
            TerminalPath::new(path)
        ),
        ArchiveError::InvalidArchive(_) => format!(
            "Invalid archive '{archive}'\n\
             HINT: The archive may be corrupted or malformed."
        ),
        ArchiveError::InvalidConfiguration { reason } => format!(
            "Invalid configuration: {reason}\n\
             HINT: Check the flags you passed and their allowed value ranges.",
        ),
        ArchiveError::SourceNotFound { path } => format!(
            "Source path not found: {}\n\
             HINT: Verify the archive path exists and is readable.",
            TerminalPath::new(path),
        ),
        ArchiveError::SourceNotAccessible { path } => format!(
            "Source path is not accessible: {}\n\
             HINT: Check file permissions on the archive.",
            TerminalPath::new(path),
        ),
        ArchiveError::OutputExists { path } => format!(
            "Output path already exists: {}\n\
             HINT: Use --force to overwrite.",
            TerminalPath::new(path),
        ),
        ArchiveError::InvalidPermissions { mode, .. } => {
            format!("Invalid permissions {mode:#o}: blocked by security policy.")
        }
        ArchiveError::InvalidCompressionLevel { level } => {
            format!("Invalid compression level {level}: must be between 1 and 9.")
        }
        // `SecurityViolation.reason` is a free-form String with no structured
        // variant to distinguish its cause, and the CLI's four policy flags
        // only relax a handful of them (symlinks, hardlinks, solid archives,
        // banned components) — roughly a dozen others (GHSA-5j8q-wxg5-hj4r's
        // declared/decompressed size mismatch, encrypted/password-protected
        // entries, unsupported compression methods, oversized symlink
        // targets, disallowed TAR entry types, null bytes or empty/oversized
        // paths, etc.) cannot be relaxed by any flag at all. Rather than
        // special-casing the one known mismatch, classify by the fixed
        // literal prefix each relaxable category's reason is built from (see
        // `is_relaxable_by_policy_flag`) and give every non-matching reason a
        // HINT that does not point at a flag that cannot fix it.
        ArchiveError::SecurityViolation { reason } => {
            let hint = if is_relaxable_by_policy_flag(reason) {
                "If this archive is from a trusted source, relax the relevant policy flag \
                 (--allow-symlinks, --allow-hardlinks, --allow-solid-archives, \
                 --banned-component)."
            } else {
                "This archive was rejected by a security check that cannot be relaxed via any \
                 policy flag."
            };
            format!("Security violation while processing '{archive}'\nHINT: {hint}")
        }
        // Forward-compat: a variant added to ArchiveError after this match was
        // written. #[non_exhaustive] requires this arm to compile against a
        // newer exarch-core; there is no more specific context to add.
        _ => format!("Error while processing '{archive}'"),
    };
    anyhow::Error::new(CliContext::wrapping(context, err))
}

/// Adds context to a generic error about archive operations.
///
/// `allow_symlinks` is forwarded to [`convert_extraction_error`] to suppress
/// the `--allow-symlinks` hint when the flag is already active.
pub fn add_archive_context<T>(
    result: Result<T, ArchiveError>,
    archive: &Path,
    allow_symlinks: bool,
) -> anyhow::Result<T> {
    result.map_err(|e| convert_extraction_error(e, archive, allow_symlinks))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::path::PathBuf;

    #[test]
    fn test_convert_path_traversal_error() {
        let err = ArchiveError::PathTraversal {
            path: PathBuf::from("../../../etc/passwd"),
        };
        let converted = convert_extraction_error(err, Path::new("malicious.zip"), false);
        let msg = format!("{converted:?}");
        assert!(msg.contains("path traversal"));
        assert!(msg.contains("malicious.zip"));
        assert!(msg.contains("HINT"));
    }

    fn zip_bomb_message(scope: ZipBombScope, compressed: u64, uncompressed: u64) -> String {
        let err = ArchiveError::ZipBomb(ZipBombDetails::new(scope, compressed, uncompressed));
        let converted = convert_extraction_error(err, Path::new("bomb.zip"), false);
        format!("{converted:?}")
    }

    #[test]
    fn test_convert_zip_bomb_error() {
        let msg = zip_bomb_message(ZipBombScope::Entry, 1024, 1024 * 1024 * 150);
        assert!(msg.contains("zip bomb"));
        assert!(msg.contains("bomb.zip"));
        assert!(msg.contains("--max-compression-ratio"));
    }

    #[test]
    fn test_zip_bomb_solid_block_hint() {
        let msg = zip_bomb_message(ZipBombScope::SolidBlock, 1024, 1024 * 1024 * 150);
        assert!(msg.contains("fixed 1000x limit"));
        assert!(!msg.contains("--max-compression-ratio"));
    }

    #[test]
    fn test_zip_bomb_unbounded_hint() {
        let msg = zip_bomb_message(ZipBombScope::Entry, 0, 10);
        assert!(msg.contains("size metadata is inconsistent"));
        assert!(!msg.contains("--max-compression-ratio"));
    }

    #[test]
    fn test_path_traversal_path_appears_once() {
        let path = PathBuf::from("../../../etc/passwd");
        let err = ArchiveError::PathTraversal { path };
        let converted = convert_extraction_error(err, Path::new("archive.tar.gz"), false);
        let msg = format!("{converted:#}");
        assert_eq!(
            msg.matches("../../../etc/passwd").count(),
            1,
            "path should appear exactly once, got: {msg}"
        );
    }

    #[test]
    fn test_symlink_escape_path_appears_once() {
        let path = PathBuf::from("link/to/escape");
        let err = ArchiveError::SymlinkEscape { path };
        let converted = convert_extraction_error(err, Path::new("archive.tar.gz"), false);
        let msg = format!("{converted:#}");
        assert_eq!(
            msg.matches("link/to/escape").count(),
            1,
            "path should appear exactly once, got: {msg}"
        );
    }

    #[test]
    fn test_symlink_escape_hint_suppressed_when_flag_active() {
        let path = PathBuf::from("link/to/escape");
        let err = ArchiveError::SymlinkEscape { path };
        let converted = convert_extraction_error(err, Path::new("archive.tar.gz"), true);
        let msg = format!("{converted:#}");
        assert!(
            !msg.contains("--allow-symlinks"),
            "hint must be suppressed when --allow-symlinks is active, got: {msg}"
        );
    }

    #[test]
    fn test_symlink_escape_hint_shown_when_flag_inactive() {
        let path = PathBuf::from("link/to/escape");
        let err = ArchiveError::SymlinkEscape { path };
        let converted = convert_extraction_error(err, Path::new("archive.tar.gz"), false);
        let msg = format!("{converted:#}");
        assert!(
            msg.contains("--allow-symlinks"),
            "hint must be shown when --allow-symlinks is not active, got: {msg}"
        );
    }

    #[test]
    fn test_hardlink_escape_path_appears_once() {
        let path = PathBuf::from("hard/link/escape");
        let err = ArchiveError::HardlinkEscape { path };
        let converted = convert_extraction_error(err, Path::new("archive.tar.gz"), false);
        let msg = format!("{converted:#}");
        assert_eq!(
            msg.matches("hard/link/escape").count(),
            1,
            "path should appear exactly once, got: {msg}"
        );
    }

    #[test]
    fn test_convert_io_error() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let err = ArchiveError::Io(io_err);
        let converted = convert_extraction_error(err, Path::new("archive.tar.gz"), false);
        let msg = format!("{converted:?}");
        assert!(msg.contains("I/O error"));
    }

    // Regression test for issue #528: the `Io` arm's context must not
    // re-embed the wrapped `io::Error`'s own Display text, since anyhow's
    // `{:#}` rendering already appends the source error after the context.
    #[test]
    fn test_io_error_no_duplication() {
        let io_err = io::Error::new(
            io::ErrorKind::InvalidData,
            "Illegal byte sequence (os error 92)",
        );
        let err = ArchiveError::Io(io_err);
        let converted = convert_extraction_error(err, Path::new("nonutf8.tar"), false);
        let msg = format!("{converted:#}");
        assert_eq!(
            msg.matches("Illegal byte sequence (os error 92)").count(),
            1,
            "OS error text should appear exactly once, got: {msg}"
        );
        assert_eq!(
            msg.matches("I/O error").count(),
            1,
            "\"I/O error\" phrase should appear exactly once, got: {msg}"
        );
    }

    // Regression tests for issue #204: PartialExtraction wrapping
    // HardlinkEscape / SymlinkEscape must not repeat the inner error text
    // more than once.

    #[test]
    fn test_partial_hardlink_escape_inner_text_appears_once() {
        use exarch_core::ExtractionReport;
        use std::time::Duration;

        let inner = ArchiveError::HardlinkEscape {
            path: PathBuf::from("hardlink_escape_path"),
        };
        let report = ExtractionReport {
            files_extracted: 1,
            directories_created: 0,
            symlinks_created: 0,
            bytes_written: 0,
            duration: Duration::from_millis(0),
            files_skipped: 0,
            warnings: vec![],
        };
        let err = ArchiveError::PartialExtraction {
            source: Box::new(inner),
            report,
            writes: PartialWrites::Kept,
        };
        let converted = convert_extraction_error(err, Path::new("archive.tar.gz"), false);
        let msg = format!("{converted:#}");
        let occurrences = msg.matches("hardlink_escape_path").count();
        assert_eq!(
            occurrences, 1,
            "inner error path should appear exactly once, got: {msg}"
        );
    }

    // Regression tests for issue #295: four explicit arms must produce
    // actionable messages.

    #[test]
    fn test_output_exists_contains_path_and_hint() {
        let path = PathBuf::from("/tmp/output");
        let err = ArchiveError::OutputExists { path };
        let converted = convert_extraction_error(err, Path::new("archive.tar.gz"), false);
        let msg = format!("{converted:#}");
        assert!(msg.contains("/tmp/output"), "path missing: {msg}");
        assert!(msg.contains("--force"), "hint missing: {msg}");
    }

    #[test]
    fn test_invalid_permissions_contains_mode_and_path() {
        let path = PathBuf::from("evil/file");
        let err = ArchiveError::InvalidPermissions { path, mode: 0o4755 };
        let converted = convert_extraction_error(err, Path::new("archive.tar.gz"), false);
        let msg = format!("{converted:#}");
        assert!(msg.contains("evil/file"), "path missing: {msg}");
        assert!(
            msg.contains("security policy"),
            "policy text missing: {msg}"
        );
    }

    #[test]
    fn test_invalid_compression_level_contains_level() {
        let err = ArchiveError::InvalidCompressionLevel { level: 0 };
        let converted = convert_extraction_error(err, Path::new("archive.tar.gz"), false);
        let msg = format!("{converted:#}");
        assert!(msg.contains('0'), "level missing: {msg}");
        assert!(msg.contains("between 1 and 9"), "range hint missing: {msg}");
    }

    #[test]
    fn test_security_violation_reason_appears_exactly_once() {
        let err = ArchiveError::SecurityViolation {
            reason: "absolute path detected".to_string(),
        };
        let converted = convert_extraction_error(err, Path::new("archive.tar.gz"), false);
        let msg = format!("{converted:#}");
        assert_eq!(
            msg.matches("absolute path detected").count(),
            1,
            "reason should appear exactly once, got: {msg}"
        );
    }

    // Regression test for issue #520: the GHSA-5j8q-wxg5-hj4r forged-size
    // SecurityViolation must get its own accurate HINT, not the generic
    // policy-flag one, since none of those flags can fix a size mismatch.

    #[test]
    fn test_security_violation_forged_size_hint_omits_policy_flags() {
        let err = ArchiveError::SecurityViolation {
            reason: "decompressed size exceeded the declared uncompressed size of 50 bytes"
                .to_string(),
        };
        let converted = convert_extraction_error(err, Path::new("archive.zip"), false);
        let msg = format!("{converted:#}");
        assert!(
            msg.contains("cannot be relaxed via any policy flag"),
            "expected the size-mismatch-specific HINT, got: {msg}"
        );
        for flag in [
            "--allow-symlinks",
            "--allow-hardlinks",
            "--allow-solid-archives",
            "--banned-component",
        ] {
            assert!(
                !msg.contains(flag),
                "forged-size HINT must not mention {flag}, got: {msg}"
            );
        }
    }

    #[test]
    fn test_security_violation_hint_names_policy_flags() {
        // These assertions target text the CLI itself authors (the anyhow
        // context), not the wrapped `ArchiveError`'s own Display, so the test
        // fails if the HINT regresses to generic wording again.
        let err = ArchiveError::SecurityViolation {
            reason: "banned path component: .git".to_string(),
        };
        let converted = convert_extraction_error(err, Path::new("archive.tar.gz"), false);
        let msg = format!("{converted:#}");
        for flag in [
            "--allow-symlinks",
            "--allow-hardlinks",
            "--allow-solid-archives",
            "--banned-component",
        ] {
            assert!(msg.contains(flag), "HINT missing flag {flag}: {msg}");
        }
    }

    #[test]
    fn test_partial_symlink_escape_inner_text_appears_once() {
        use exarch_core::ExtractionReport;
        use std::time::Duration;

        let inner = ArchiveError::SymlinkEscape {
            path: PathBuf::from("symlink_escape_path"),
        };
        let report = ExtractionReport {
            files_extracted: 2,
            directories_created: 1,
            symlinks_created: 0,
            bytes_written: 100,
            duration: Duration::from_millis(0),
            files_skipped: 0,
            warnings: vec![],
        };
        let err = ArchiveError::PartialExtraction {
            source: Box::new(inner),
            report,
            writes: PartialWrites::Kept,
        };
        let converted = convert_extraction_error(err, Path::new("archive.tar.gz"), false);
        let msg = format!("{converted:#}");
        let occurrences = msg.matches("symlink_escape_path").count();
        assert_eq!(
            occurrences, 1,
            "inner error path should appear exactly once, got: {msg}"
        );
    }

    // Regression tests for issue #503: files_skipped/warnings must be shown in
    // the partial-extraction Display output when present, and hidden when
    // both are empty/zero (mirrors the #498-fix "shown when present" pattern).

    #[test]
    fn test_partial_display_shows_files_skipped_and_warnings_when_present() {
        use exarch_core::ExtractionReport;
        use std::time::Duration;

        let inner = ArchiveError::HardlinkEscape {
            path: PathBuf::from("hardlink_escape_path"),
        };
        let report = ExtractionReport {
            files_extracted: 1,
            directories_created: 0,
            symlinks_created: 0,
            bytes_written: 0,
            duration: Duration::from_millis(0),
            files_skipped: 2,
            warnings: vec!["skipped a broken symlink".to_string()],
        };
        let err = ArchiveError::PartialExtraction {
            source: Box::new(inner),
            report,
            writes: PartialWrites::Kept,
        };
        let converted = convert_extraction_error(err, Path::new("archive.tar.gz"), false);
        let msg = format!("{converted:#}");
        assert!(msg.contains("Files skipped: 2"), "got: {msg}");
        assert!(msg.contains("Warnings:"), "got: {msg}");
        assert!(msg.contains("skipped a broken symlink"), "got: {msg}");
    }

    // Regression test for issue #527: PartialExtraction must not discard the
    // category-specific HINT the wrapped source would otherwise get.

    #[test]
    fn test_partial_security_violation_keeps_hint_and_partial_progress_wording() {
        use exarch_core::ExtractionReport;
        use std::time::Duration;

        let inner = ArchiveError::SecurityViolation {
            reason: "symlinks not allowed by security policy".to_string(),
        };
        let report = ExtractionReport {
            files_extracted: 3,
            directories_created: 1,
            symlinks_created: 0,
            bytes_written: 42,
            duration: Duration::from_millis(0),
            files_skipped: 0,
            warnings: vec![],
        };
        let err = ArchiveError::PartialExtraction {
            source: Box::new(inner),
            report,
            writes: PartialWrites::Kept,
        };
        let converted = convert_extraction_error(err, Path::new("archive.tar.gz"), false);
        let msg = format!("{converted:#}");
        assert!(
            msg.contains("were written to disk before the error"),
            "partial-progress wording missing: {msg}"
        );
        assert!(
            msg.contains("--allow-symlinks"),
            "category-specific HINT missing: {msg}"
        );
        assert_eq!(
            msg.matches("symlinks not allowed by security policy")
                .count(),
            1,
            "inner error reason should appear exactly once, got: {msg}"
        );
    }

    #[test]
    fn test_partial_rolled_back_display_makes_no_written_claim() {
        use exarch_core::ExtractionReport;
        use std::time::Duration;

        let report = ExtractionReport {
            files_extracted: 1,
            directories_created: 0,
            symlinks_created: 0,
            bytes_written: 0,
            duration: Duration::from_millis(0),
            files_skipped: 0,
            warnings: vec![],
        };
        let err = ArchiveError::PartialExtraction {
            source: Box::new(ArchiveError::HardlinkEscape {
                path: PathBuf::from("hardlink_escape_path"),
            }),
            report,
            writes: PartialWrites::RolledBack,
        };
        let converted = convert_extraction_error(err, Path::new("archive.tar.gz"), false);
        let msg = format!("{converted:#}");
        assert!(!msg.contains("written to disk"), "got: {msg}");
        assert!(!msg.contains("Inspect or remove"), "got: {msg}");
        assert!(msg.contains("destination was left unchanged"), "got: {msg}");
        assert_eq!(msg.matches("hardlink_escape_path").count(), 1, "got: {msg}");
    }

    #[test]
    fn test_partial_rolled_back_display_omits_the_discarded_runs_skips_and_warnings() {
        use exarch_core::ExtractionReport;
        use std::time::Duration;

        let report = ExtractionReport {
            files_extracted: 1,
            directories_created: 0,
            symlinks_created: 0,
            bytes_written: 0,
            duration: Duration::from_millis(0),
            files_skipped: 3,
            warnings: vec!["skipped 3 entries".to_string()],
        };
        let err = ArchiveError::PartialExtraction {
            source: Box::new(ArchiveError::HardlinkEscape {
                path: PathBuf::from("hardlink_escape_path"),
            }),
            report,
            writes: PartialWrites::RolledBack,
        };
        let converted = convert_extraction_error(err, Path::new("archive.tar.gz"), false);
        let msg = format!("{converted:#}");
        assert!(!msg.contains("Files skipped"), "got: {msg}");
        assert!(!msg.contains("Warnings:"), "got: {msg}");
        assert!(!msg.contains("skipped 3 entries"), "got: {msg}");
        assert!(msg.contains("destination was left unchanged"), "got: {msg}");
    }

    #[test]
    fn test_partial_display_hides_files_skipped_and_warnings_when_empty() {
        use exarch_core::ExtractionReport;
        use std::time::Duration;

        let inner = ArchiveError::HardlinkEscape {
            path: PathBuf::from("hardlink_escape_path"),
        };
        let report = ExtractionReport {
            files_extracted: 1,
            directories_created: 0,
            symlinks_created: 0,
            bytes_written: 0,
            duration: Duration::from_millis(0),
            files_skipped: 0,
            warnings: vec![],
        };
        let err = ArchiveError::PartialExtraction {
            source: Box::new(inner),
            report,
            writes: PartialWrites::Kept,
        };
        let converted = convert_extraction_error(err, Path::new("archive.tar.gz"), false);
        let msg = format!("{converted:#}");
        assert!(!msg.contains("Files skipped"), "got: {msg}");
        assert!(!msg.contains("Warnings:"), "got: {msg}");
    }

    #[test]
    fn test_cli_context_keeps_archive_error_as_source() {
        let err = ArchiveError::PathTraversal {
            path: PathBuf::from("../x"),
        };
        let converted = convert_extraction_error(err, Path::new("a.tar"), false);
        assert!(converted.downcast_ref::<CliContext>().is_some());
        assert!(
            converted
                .chain()
                .any(|link| link.downcast_ref::<ArchiveError>().is_some())
        );
    }

    #[test]
    fn test_partial_context_is_chain_root_with_inner_source() {
        let err = ArchiveError::PartialExtraction {
            source: Box::new(ArchiveError::PathTraversal {
                path: PathBuf::from("../x"),
            }),
            report: ExtractionReport::default(),
            writes: PartialWrites::Kept,
        };
        let converted = convert_extraction_error(err, Path::new("a.tar"), false);
        assert!(
            converted
                .downcast_ref::<PartialExtractionContext>()
                .is_some()
        );
        let kinds: Vec<_> = converted
            .chain()
            .map(|link| {
                (
                    link.is::<PartialExtractionContext>(),
                    link.is::<CliContext>(),
                )
            })
            .collect();
        assert_eq!(kinds[0], (true, false));
        assert_eq!(kinds[1], (false, true));
    }

    #[test]
    fn test_invalid_archive_reason_appears_once() {
        let err = ArchiveError::InvalidArchive("distinctive-reason".to_string());
        let converted = convert_extraction_error(err, Path::new("a.tar"), false);
        let msg = format!("{converted:#}");
        assert_eq!(msg.matches("distinctive-reason").count(), 1, "got: {msg}");
    }

    #[test]
    fn test_partial_display_escapes_warnings() {
        let report = ExtractionReport {
            warnings: vec!["w\x1b[31m\nforged".to_string()],
            ..ExtractionReport::default()
        };
        let err = ArchiveError::PartialExtraction {
            source: Box::new(ArchiveError::PathTraversal {
                path: PathBuf::from("../x"),
            }),
            report,
            writes: PartialWrites::Kept,
        };
        let msg = format!(
            "{:#}",
            convert_extraction_error(err, Path::new("a.tar"), false)
        );
        assert!(!msg.contains('\x1b'), "got: {msg:?}");
        assert!(msg.contains("\\x1b[31m\\x0aforged"), "got: {msg:?}");
    }
}
