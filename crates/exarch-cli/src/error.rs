//! Error conversion utilities for CLI.
//!
//! Converts exarch-core's typed errors (thiserror) into user-friendly
//! contextual errors (anyhow) with actionable guidance.

use anyhow::Result;
use exarch_core::ArchiveError;
use exarch_core::ExtractionReport;
use std::fmt;
use std::path::Path;

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

/// Carrier for partial-extraction progress embedded in the anyhow error chain.
///
/// `ArchiveError::PartialExtraction` uses `#[error("{source}")]` with
/// `#[source]`, so placing it directly in an anyhow chain causes the inner
/// error text to appear twice in `{:#}` output (once via Display, once via the
/// source chain).  This type carries the report without re-emitting the inner
/// error text in its own Display, keeping the anyhow chain clean.
#[derive(Debug)]
pub struct PartialExtractionContext {
    pub(crate) report: ExtractionReport,
}

impl fmt::Display for PartialExtractionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let r = &self.report;
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
                write!(f, "\n  - {warning}")?;
            }
        }
        write!(
            f,
            "\nHINT: Inspect or remove the output directory before re-running."
        )
    }
}

impl std::error::Error for PartialExtractionContext {}

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

/// Converts `ArchiveError` to user-friendly anyhow error with context.
///
/// The original `ArchiveError` is preserved as the error source so that
/// callers can downcast via the anyhow chain (used by JSON error output).
///
/// `allow_symlinks` suppresses the `--allow-symlinks` hint for `SymlinkEscape`
/// errors when the flag is already active — in that case the escape is a
/// genuine security violation, not a configuration issue.
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
    // `{:#}`" guarantee intact for the variants whose CLI-authored `context`
    // string below does not itself re-embed the inner error's data —
    // `PathTraversal`, `SymlinkEscape`, `HardlinkEscape`, `SecurityViolation`,
    // `ZipBomb`, `QuotaExceeded` (the ones the regression tests below cover).
    // `InvalidArchive` builds its `context` string by interpolating the
    // inner data directly (`{reason}`), so its inner text was already
    // printed twice by this same recursion path on the *non-partial* path
    // before this change; wrapping it in `PartialExtraction` now reaches
    // that pre-existing duplication too, rather than introducing a new one
    // — partial and non-partial output are consistent with each other, not
    // newly broken. (`Io`'s context no longer re-embeds the inner error's
    // text either, since #528 — it is not an exception to the guarantee.)
    if let ArchiveError::PartialExtraction { source, report } = err {
        return convert_extraction_error(*source, archive, allow_symlinks)
            .context(PartialExtractionContext { report });
    }

    let context = match &err {
        ArchiveError::PartialExtraction { .. } => unreachable!(),
        ArchiveError::PathTraversal { .. } => format!(
            "Security violation: Archive '{}' attempted path traversal\n\
             HINT: This archive may be malicious. Do not extract from untrusted sources.",
            archive.display(),
        ),
        ArchiveError::ZipBomb { .. } => format!(
            "Security violation: Archive '{}' appears to be a zip bomb\n\
             HINT: Use --max-compression-ratio to allow higher ratios if legitimate.",
            archive.display(),
        ),
        ArchiveError::QuotaExceeded { .. } => format!(
            "Extraction limit exceeded for '{}'\n\
             HINT: Use --max-files, --max-total-size, or --max-file-size to increase limits.",
            archive.display(),
        ),
        ArchiveError::SymlinkEscape { .. } => {
            if allow_symlinks {
                format!("Symlink escape blocked in '{}'", archive.display())
            } else {
                format!(
                    "Symlink rejected in '{}'\n\
                     HINT: Use --allow-symlinks to extract symlinks (only if trusted source).",
                    archive.display(),
                )
            }
        }
        ArchiveError::HardlinkEscape { .. } => format!(
            "Hardlink rejected in '{}'\n\
             HINT: Use --allow-hardlinks to extract hardlinks (only if trusted source).",
            archive.display(),
        ),
        ArchiveError::Io(_) => format!("Failed to process '{}'", archive.display()),
        ArchiveError::UnknownFormat { path } => format!(
            "Cannot determine archive format: {}\n\
             HINT: Supported formats: tar, tar.gz, tar.bz2, tar.xz, tar.zstd, zip",
            path.display()
        ),
        ArchiveError::InvalidArchive(reason) => format!(
            "Invalid archive '{}': {}\n\
             HINT: The archive may be corrupted or malformed.",
            archive.display(),
            reason
        ),
        ArchiveError::InvalidConfiguration { reason } => format!(
            "Invalid configuration: {reason}\n\
             HINT: Check the flags you passed and their allowed value ranges.",
        ),
        ArchiveError::SourceNotFound { path } => format!(
            "Source path not found: {}\n\
             HINT: Verify the archive path exists and is readable.",
            path.display(),
        ),
        ArchiveError::SourceNotAccessible { path } => format!(
            "Source path is not accessible: {}\n\
             HINT: Check file permissions on the archive.",
            path.display(),
        ),
        ArchiveError::OutputExists { path } => format!(
            "Output path already exists: {}\n\
             HINT: Use --force to overwrite.",
            path.display(),
        ),
        ArchiveError::InvalidPermissions { path, mode } => format!(
            "Invalid permissions {mode:#o} for {}: blocked by security policy.",
            path.display(),
        ),
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
            format!(
                "Security violation while processing '{}'\nHINT: {hint}",
                archive.display(),
            )
        }
        // Forward-compat: a variant added to ArchiveError after this match was
        // written. #[non_exhaustive] requires this arm to compile against a
        // newer exarch-core; there is no more specific context to add.
        _ => format!("Error while processing '{}'", archive.display()),
    };
    anyhow::Error::from(err).context(context)
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

    #[test]
    fn test_convert_zip_bomb_error() {
        let err = ArchiveError::ZipBomb {
            compressed: 1024,
            uncompressed: 1024 * 1024 * 150,
            ratio: 150.0,
        };
        let converted = convert_extraction_error(err, Path::new("bomb.zip"), false);
        let msg = format!("{converted:?}");
        assert!(msg.contains("zip bomb"));
        assert!(msg.contains("bomb.zip"));
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

    // Regression tests for issue #204: PartialExtraction wrapping HardlinkEscape /
    // SymlinkEscape must not repeat the inner error text more than once.

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
        };
        let converted = convert_extraction_error(err, Path::new("archive.tar.gz"), false);
        let msg = format!("{converted:#}");
        let occurrences = msg.matches("hardlink_escape_path").count();
        assert_eq!(
            occurrences, 1,
            "inner error path should appear exactly once, got: {msg}"
        );
    }

    // Regression tests for issue #295: four explicit arms must produce actionable
    // messages.

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
        };
        let converted = convert_extraction_error(err, Path::new("archive.tar.gz"), false);
        let msg = format!("{converted:#}");
        assert!(!msg.contains("Files skipped"), "got: {msg}");
        assert!(!msg.contains("Warnings:"), "got: {msg}");
    }
}
