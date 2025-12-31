//! Error conversion utilities for CLI.
//!
//! Converts exarch-core's typed errors (thiserror) into user-friendly
//! contextual errors (anyhow) with actionable guidance.

use anyhow::Result;
use anyhow::anyhow;
use exarch_core::ExtractionError;
use std::path::Path;

/// Converts `ExtractionError` to user-friendly anyhow error with context
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn convert_extraction_error(err: ExtractionError, archive: &Path) -> anyhow::Error {
    match err {
        ExtractionError::PathTraversal { path } => {
            anyhow!(
                "Security violation: Archive '{}' attempted path traversal with '{}'\n\
                 HINT: This archive may be malicious. Do not extract from untrusted sources.",
                archive.display(),
                path.display()
            )
        }
        ExtractionError::ZipBomb {
            compressed,
            uncompressed,
            ratio,
        } => {
            anyhow!(
                "Security violation: Archive '{}' appears to be a zip bomb\n\
                 Compression ratio: {}:1 ({}KB → {}MB)\n\
                 HINT: Use --max-compression-ratio to allow higher ratios if legitimate.",
                archive.display(),
                ratio as u64,
                compressed / 1024,
                uncompressed / 1024 / 1024
            )
        }
        ExtractionError::QuotaExceeded { resource } => {
            anyhow!(
                "Extraction limit exceeded for '{}': {}\n\
                 HINT: Use --max-files, --max-total-size, or --max-file-size to increase limits.",
                archive.display(),
                resource
            )
        }
        ExtractionError::SymlinkEscape { path } => {
            anyhow!(
                "Symlink rejected in '{}': {}\n\
                 HINT: Use --allow-symlinks to extract symlinks (only if trusted source).",
                archive.display(),
                path.display()
            )
        }
        ExtractionError::HardlinkEscape { path } => {
            anyhow!(
                "Hardlink rejected in '{}': {}\n\
                 HINT: Use --allow-hardlinks to extract hardlinks (only if trusted source).",
                archive.display(),
                path.display()
            )
        }
        ExtractionError::Io(io_err) => {
            anyhow!(
                "I/O error while processing '{}': {}",
                archive.display(),
                io_err
            )
        }
        ExtractionError::UnsupportedFormat => {
            anyhow!(
                "Archive format not supported: {}\n\
                 HINT: Supported formats: tar, tar.gz, tar.bz2, tar.xz, tar.zstd, zip",
                archive.display()
            )
        }
        ExtractionError::InvalidArchive(reason) => {
            anyhow!(
                "Invalid archive '{}': {}\n\
                 HINT: The archive may be corrupted or malformed.",
                archive.display(),
                reason
            )
        }
        _ => anyhow::Error::from(err)
            .context(format!("Error processing archive '{}'", archive.display())),
    }
}

/// Adds context to a generic error about archive operations
pub fn add_archive_context<T>(
    result: Result<T, ExtractionError>,
    archive: &Path,
) -> anyhow::Result<T> {
    result.map_err(|e| convert_extraction_error(e, archive))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::path::PathBuf;

    #[test]
    fn test_convert_path_traversal_error() {
        let err = ExtractionError::PathTraversal {
            path: PathBuf::from("../../../etc/passwd"),
        };
        let converted = convert_extraction_error(err, Path::new("malicious.zip"));
        let msg = format!("{converted:?}");
        assert!(msg.contains("path traversal"));
        assert!(msg.contains("malicious.zip"));
        assert!(msg.contains("HINT"));
    }

    #[test]
    fn test_convert_zip_bomb_error() {
        let err = ExtractionError::ZipBomb {
            compressed: 1024,
            uncompressed: 1024 * 1024 * 150,
            ratio: 150.0,
        };
        let converted = convert_extraction_error(err, Path::new("bomb.zip"));
        let msg = format!("{converted:?}");
        assert!(msg.contains("zip bomb"));
        assert!(msg.contains("150:1"));
    }

    #[test]
    fn test_convert_io_error() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let err = ExtractionError::Io(io_err);
        let converted = convert_extraction_error(err, Path::new("archive.tar.gz"));
        let msg = format!("{converted:?}");
        assert!(msg.contains("I/O error"));
    }
}
