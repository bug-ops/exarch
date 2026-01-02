//! Archive format detection.

use std::path::Path;

use crate::ExtractionError;
use crate::Result;

/// 7z format magic bytes (signature).
///
/// 7z archives start with the signature: `37 7A BC AF 27 1C`
/// This is the string "7z" followed by format version bytes.
///
/// This constant is defined for future magic byte detection implementation.
#[allow(dead_code)]
const SEVENZ_MAGIC: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

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
    /// Zstd-compressed tar archive.
    TarZst,
    /// ZIP archive.
    Zip,
    /// 7z archive.
    SevenZ,
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

    let ext_lower = extension.to_ascii_lowercase();
    match ext_lower.as_str() {
        "tar" => Ok(ArchiveType::Tar),
        "gz" | "tgz" => {
            if let Some(stem) = path.file_stem()
                && stem.to_string_lossy().ends_with(".tar")
            {
                return Ok(ArchiveType::TarGz);
            }
            Ok(ArchiveType::TarGz)
        }
        "bz2" | "tbz" | "tbz2" => Ok(ArchiveType::TarBz2),
        "xz" | "txz" => Ok(ArchiveType::TarXz),
        "zst" | "tzst" => Ok(ArchiveType::TarZst),
        "zip" => Ok(ArchiveType::Zip),
        "7z" => Ok(ArchiveType::SevenZ),
        _ => Err(ExtractionError::UnsupportedFormat),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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
    fn test_detect_tar_bz2() {
        let path = PathBuf::from("archive.tar.bz2");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::TarBz2);

        let path2 = PathBuf::from("archive.tbz");
        assert_eq!(detect_format(&path2).unwrap(), ArchiveType::TarBz2);

        let path3 = PathBuf::from("archive.tbz2");
        assert_eq!(detect_format(&path3).unwrap(), ArchiveType::TarBz2);
    }

    #[test]
    fn test_detect_tar_xz() {
        let path = PathBuf::from("archive.tar.xz");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::TarXz);

        let path2 = PathBuf::from("archive.txz");
        assert_eq!(detect_format(&path2).unwrap(), ArchiveType::TarXz);
    }

    #[test]
    fn test_detect_tar_zst() {
        let path = PathBuf::from("archive.tar.zst");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::TarZst);

        let path2 = PathBuf::from("archive.tzst");
        assert_eq!(detect_format(&path2).unwrap(), ArchiveType::TarZst);
    }

    #[test]
    fn test_detect_zip() {
        let path = PathBuf::from("archive.zip");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::Zip);
    }

    #[test]
    fn test_detect_7z() {
        let path = PathBuf::from("archive.7z");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::SevenZ);
    }

    #[test]
    fn test_detect_7z_case_insensitive() {
        let path = PathBuf::from("ARCHIVE.7Z");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::SevenZ);

        let path2 = PathBuf::from("Archive.7Z");
        assert_eq!(detect_format(&path2).unwrap(), ArchiveType::SevenZ);
    }

    #[test]
    fn test_detect_unsupported() {
        let path = PathBuf::from("archive.rar");
        assert!(matches!(
            detect_format(&path),
            Err(ExtractionError::UnsupportedFormat)
        ));
    }

    #[test]
    fn test_archive_type_sevenz_equality() {
        assert_eq!(ArchiveType::SevenZ, ArchiveType::SevenZ);
        assert_ne!(ArchiveType::SevenZ, ArchiveType::Zip);
    }

    #[test]
    fn test_archive_type_sevenz_debug() {
        let format = ArchiveType::SevenZ;
        let debug_str = format!("{format:?}");
        assert_eq!(debug_str, "SevenZ");
    }
}
