//! Archive format detection.

use std::path::Path;

use crate::{ExtractionError, Result};

/// Supported archive formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveType {
    /// Tar archive (uncompressed).
    Tar,
    /// Gzip-compressed tar archive.
    TarGz,
    /// Bzip2-compressed tar archive.
    TarBz2,
    /// XZ-compressed tar archive.
    TarXz,
    /// ZIP archive.
    Zip,
}

/// Detects the archive type from a file path.
///
/// # Errors
///
/// Returns an error if the format cannot be determined.
pub fn detect_format(path: &Path) -> Result<ArchiveType> {
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .ok_or(ExtractionError::UnsupportedFormat)?;

    match extension {
        "tar" => Ok(ArchiveType::Tar),
        "gz" | "tgz" => {
            if let Some(stem) = path.file_stem() {
                if stem.to_string_lossy().ends_with(".tar") {
                    return Ok(ArchiveType::TarGz);
                }
            }
            Ok(ArchiveType::TarGz)
        }
        "bz2" | "tbz" | "tbz2" => Ok(ArchiveType::TarBz2),
        "xz" | "txz" => Ok(ArchiveType::TarXz),
        "zip" => Ok(ArchiveType::Zip),
        _ => Err(ExtractionError::UnsupportedFormat),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_detect_tar() {
        let path = PathBuf::from("archive.tar");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::Tar);
    }

    #[test]
    fn test_detect_tar_gz() {
        let path = PathBuf::from("archive.tar.gz");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::TarGz);

        let path2 = PathBuf::from("archive.tgz");
        assert_eq!(detect_format(&path2).unwrap(), ArchiveType::TarGz);
    }

    #[test]
    fn test_detect_zip() {
        let path = PathBuf::from("archive.zip");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::Zip);
    }

    #[test]
    fn test_detect_unsupported() {
        let path = PathBuf::from("archive.rar");
        assert!(matches!(
            detect_format(&path),
            Err(ExtractionError::UnsupportedFormat)
        ));
    }
}
