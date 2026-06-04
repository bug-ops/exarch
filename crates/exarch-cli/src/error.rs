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
             were written to disk before the error.\n\
             HINT: Inspect or remove the output directory before re-running.",
            r.files_extracted, r.directories_created, r.symlinks_created,
        )
    }
}

impl std::error::Error for PartialExtractionContext {}

/// Converts `ArchiveError` to user-friendly anyhow error with context.
///
/// The original `ArchiveError` is preserved as the error source so that
/// callers can downcast via the anyhow chain (used by JSON error output).
///
/// `allow_symlinks` suppresses the `--allow-symlinks` hint for `SymlinkEscape`
/// errors when the flag is already active — in that case the escape is a
/// genuine security violation, not a configuration issue.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn convert_extraction_error(
    err: ArchiveError,
    archive: &Path,
    allow_symlinks: bool,
) -> anyhow::Error {
    // Handle PartialExtraction before the borrow below.
    //
    // `PartialExtraction` is `#[error("{source}")]` with `#[source]`, so
    // placing it in an anyhow chain causes the inner error text to appear
    // twice in `{:#}` output.  Instead, we extract the inner error and wrap
    // it with `PartialExtractionContext`, which carries the partial report
    // without duplicating the inner Display text.
    if let ArchiveError::PartialExtraction { source, report } = err {
        return anyhow::Error::from(*source).context(PartialExtractionContext { report });
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
        ArchiveError::Io(io_err) => {
            format!(
                "I/O error while processing '{}': {}",
                archive.display(),
                io_err
            )
        }
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
        _ => format!("Error processing archive '{}'", archive.display()),
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
}
