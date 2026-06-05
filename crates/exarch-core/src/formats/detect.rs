//! Archive format detection.

use std::io::Read as _;
use std::path::Path;

use crate::ArchiveError;
use crate::Result;

/// Number of bytes to read for magic-byte detection.
///
/// TAR USTAR signature sits at offset 257 and is 5 bytes long, so we need
/// at least 262 bytes. All other signatures fit within the first 6 bytes.
const MAGIC_READ_LEN: usize = 262;

/// Magic byte signatures for each supported archive format.
///
/// Each entry is `(offset, signature, ArchiveType)`.
///
/// ZIP has three recognized openers: local-file header (`PK\x03\x04`), EOCD
/// (`PK\x05\x06` — valid empty ZIP), and split-archive marker (`PK\x07\x08`).
const MAGIC_SIGNATURES: &[(usize, &[u8], ArchiveType)] = &[
    (0, b"\x1f\x8b", ArchiveType::TarGz),
    (0, b"\x28\xb5\x2f\xfd", ArchiveType::TarZst),
    (0, b"\x42\x5a\x68", ArchiveType::TarBz2),
    (0, b"\x50\x4b\x03\x04", ArchiveType::Zip),
    (0, b"\x50\x4b\x05\x06", ArchiveType::Zip),
    (0, b"\x50\x4b\x07\x08", ArchiveType::Zip),
    (0, b"\x37\x7a\xbc\xaf\x27\x1c", ArchiveType::SevenZ),
    (0, b"\xfd\x37\x7a\x58\x5a\x00", ArchiveType::TarXz),
    (257, b"ustar", ArchiveType::Tar),
];

/// File extensions that wrap a ZIP container with extra structure.
///
/// Signing, manifests, and ordering rules sit on top of the ZIP bytes
/// for these formats. Extraction treats them as ZIP; creation is
/// rejected separately in `api::reject_zip_family_creation`. Kept as a
/// single source of truth so the two call sites don't drift.
pub const ZIP_FAMILY_ALIASES: &[&str] = &[
    "jar", "war", "ear", "nar", "nbm", "apk", "aab", "ipa", "appx", "msix", "whl", "vsix", "xpi",
    "epub",
];

/// Returns true if `ext` (case-insensitive) names a ZIP-family alias.
/// Plain `.zip` is deliberately *not* included - callers can test it
/// separately when they need to distinguish "bare ZIP" from "ZIP under
/// another name".
pub(crate) fn is_zip_family_alias(ext: &str) -> bool {
    let lower = ext.to_ascii_lowercase();
    ZIP_FAMILY_ALIASES.contains(&lower.as_str())
}

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

/// Detects the archive type from a file path using two-phase detection.
///
/// This function is for **reading** existing archives. For creating archives,
/// use `detect_format_from_extension` directly so that stale on-disk bytes
/// do not override the user's intended output format.
///
/// **Phase 1 — extension:** maps the file extension to an [`ArchiveType`] using
/// the same rules as before. `.gz` is only accepted when the stem ends with
/// `.tar` (e.g. `archive.tar.gz`); a bare `archive.gz` is not a recognised
/// extension.
///
/// **Phase 2 — magic bytes:** when extension detection fails (unrecognised or
/// missing extension), the function reads up to the first 262 bytes of the file
/// and matches against known magic-byte signatures. If the file is not readable
/// (does not exist, is a directory, I/O error), phase 2 is silently skipped and
/// [`ArchiveError::UnknownFormat`] is returned.
///
/// Additionally, if extension detection succeeds but magic-byte inspection
/// identifies a *different* known format, the magic-byte result takes
/// precedence. This covers the common case where a file was renamed or given
/// the wrong extension.
///
/// **Note on compression signatures:** magic-byte detection maps GZ, BZ2, XZ,
/// and Zstd signatures to their `Tar*` variants because those are the only
/// archive-level formats this library handles for those compression schemes.
/// A bare single-file gzip/bz2/xz/zstd stream (not wrapping a tar) will
/// succeed detection but fail at extraction with a tar-parse error. When the
/// file has an unrelated extension (e.g. `.dat`), magic-byte fallback still
/// returns the `Tar*` guess — callers should be aware that
/// compressed-but-not-tar streams will surface errors at decode time rather
/// than at detection.
///
/// # Errors
///
/// Returns [`ArchiveError::UnknownFormat`] when neither phase can determine the
/// format.
pub fn detect_format(path: &Path) -> Result<ArchiveType> {
    let ext_result = detect_format_from_extension(path);

    match ext_result {
        Ok(ext_type) => {
            // Extension matched. Read magic bytes to verify; if they point to
            // a different known format, trust the bytes over the name.
            if let Some(magic_type) = detect_format_from_magic(path)
                && magic_type != ext_type
            {
                return Ok(magic_type);
            }
            Ok(ext_type)
        }
        Err(_) => {
            // Extension gave no conclusive result — fall back to magic bytes.
            detect_format_from_magic(path).ok_or_else(|| ArchiveError::UnknownFormat {
                path: path.to_path_buf(),
            })
        }
    }
}

/// Extension-only detection used for archive **creation**.
///
/// Magic-byte inspection is intentionally skipped here: the output file may not
/// exist yet, or it may contain stale bytes from a previous run that must not
/// override the caller's chosen format.
pub(crate) fn detect_format_from_extension(path: &Path) -> Result<ArchiveType> {
    let extension =
        path.extension()
            .and_then(|e| e.to_str())
            .ok_or_else(|| ArchiveError::UnknownFormat {
                path: path.to_path_buf(),
            })?;

    let ext_lower = extension.to_ascii_lowercase();
    match ext_lower.as_str() {
        "tar" => Ok(ArchiveType::Tar),
        "tgz" => Ok(ArchiveType::TarGz),
        "gz" => {
            if let Some(stem) = path.file_stem()
                && stem.to_string_lossy().ends_with(".tar")
            {
                Ok(ArchiveType::TarGz)
            } else {
                Err(ArchiveError::UnknownFormat {
                    path: path.to_path_buf(),
                })
            }
        }
        "bz2" | "tbz" | "tbz2" => Ok(ArchiveType::TarBz2),
        "xz" | "txz" => Ok(ArchiveType::TarXz),
        "zst" | "tzst" => Ok(ArchiveType::TarZst),
        "zip" => Ok(ArchiveType::Zip),
        "7z" => Ok(ArchiveType::SevenZ),
        // JVM artifacts, app bundles, Python wheels, IDE/browser
        // extensions, EPUBs - all ZIP under the hood, so they extract
        // through the same path. See `ZIP_FAMILY_ALIASES` for the list.
        ext if is_zip_family_alias(ext) => Ok(ArchiveType::Zip),
        _ => Err(ArchiveError::UnknownFormat {
            path: path.to_path_buf(),
        }),
    }
}

/// Reads up to [`MAGIC_READ_LEN`] bytes from the beginning of `path` and
/// matches them against [`MAGIC_SIGNATURES`].
///
/// Uses a read loop to handle short reads (interrupted syscalls, FUSE mounts,
/// network filesystems) so the USTAR check at offset 257 is always reliable.
///
/// Returns `None` if the file cannot be read or no signature matches.
fn detect_format_from_magic(path: &Path) -> Option<ArchiveType> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = [0u8; MAGIC_READ_LEN];
    let mut filled = 0;

    // Loop until the buffer is full or we reach EOF.
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}

            Err(_) => return None,
        }
    }

    let header = &buf[..filled];

    for &(offset, sig, archive_type) in MAGIC_SIGNATURES {
        let end = offset.checked_add(sig.len())?;
        if header.len() >= end && &header[offset..end] == sig {
            return Some(archive_type);
        }
    }
    None
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
    fn test_detect_tar_gz_still_works() {
        let path = PathBuf::from("archive.tar.gz");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::TarGz);

        let path2 = PathBuf::from("archive.tgz");
        assert_eq!(detect_format(&path2).unwrap(), ArchiveType::TarGz);
    }

    #[test]
    fn test_detect_bare_gz_returns_unknown_format() {
        let path = PathBuf::from("archive.gz");
        assert!(matches!(
            detect_format(&path),
            Err(ArchiveError::UnknownFormat { .. })
        ));
    }

    #[test]
    fn test_detect_bare_gz_error_carries_path() {
        let path = PathBuf::from("archive.gz");
        let err = detect_format(&path).unwrap_err();
        assert!(matches!(
            err,
            ArchiveError::UnknownFormat { path: ref p } if p == &PathBuf::from("archive.gz")
        ));
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
    fn test_detect_zip_family_extensions() {
        // Each of these is a ZIP underneath and should resolve to
        // ArchiveType::Zip so the existing extractor picks it up. Upper-case
        // variants cover Windows-authored filenames. Driving off
        // ZIP_FAMILY_ALIASES keeps the test from drifting if the list changes.
        for ext in ZIP_FAMILY_ALIASES {
            let path = PathBuf::from(format!("archive.{ext}"));
            assert_eq!(
                detect_format(&path).unwrap(),
                ArchiveType::Zip,
                "{ext} should detect as ZIP",
            );

            let upper = PathBuf::from(format!("archive.{}", ext.to_ascii_uppercase()));
            assert_eq!(
                detect_format(&upper).unwrap(),
                ArchiveType::Zip,
                "{ext} uppercase should detect as ZIP",
            );
        }
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
    fn test_detect_unknown_format() {
        let path = PathBuf::from("archive.rar");
        assert!(matches!(
            detect_format(&path),
            Err(ArchiveError::UnknownFormat { .. })
        ));
    }

    #[test]
    fn test_detect_unknown_format_error_carries_path() {
        let path = PathBuf::from("archive.rar");
        let err = detect_format(&path).unwrap_err();
        assert!(matches!(
            err,
            ArchiveError::UnknownFormat { path: ref p } if p == &PathBuf::from("archive.rar")
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

    // --- magic-bytes tests ---

    fn write_magic_file(dir: &tempfile::TempDir, name: &str, header: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        // Pad to MAGIC_READ_LEN so TAR USTAR offset tests work.
        let mut data = vec![0u8; MAGIC_READ_LEN];
        let n = header.len().min(data.len());
        data[..n].copy_from_slice(&header[..n]);
        std::fs::write(&path, &data).unwrap();
        path
    }

    fn write_magic_file_at_offset(
        dir: &tempfile::TempDir,
        name: &str,
        offset: usize,
        sig: &[u8],
    ) -> PathBuf {
        let path = dir.path().join(name);
        let mut data = vec![0u8; MAGIC_READ_LEN];
        let end = offset + sig.len();
        if end <= data.len() {
            data[offset..end].copy_from_slice(sig);
        }
        std::fs::write(&path, &data).unwrap();
        path
    }

    #[test]
    fn test_magic_zip_no_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_magic_file(&dir, "data", b"\x50\x4b\x03\x04");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::Zip);
    }

    #[test]
    fn test_magic_gzip_no_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_magic_file(&dir, "data", b"\x1f\x8b\x00");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::TarGz);
    }

    #[test]
    fn test_magic_bz2_no_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_magic_file(&dir, "data", b"\x42\x5a\x68");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::TarBz2);
    }

    #[test]
    fn test_magic_xz_no_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_magic_file(&dir, "data", b"\xfd\x37\x7a\x58\x5a\x00");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::TarXz);
    }

    #[test]
    fn test_magic_zstd_no_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_magic_file(&dir, "data", b"\x28\xb5\x2f\xfd");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::TarZst);
    }

    #[test]
    fn test_magic_sevenz_no_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_magic_file(&dir, "data", b"\x37\x7a\xbc\xaf\x27\x1c");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::SevenZ);
    }

    #[test]
    fn test_magic_tar_ustar_no_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_magic_file_at_offset(&dir, "data", 257, b"ustar");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::Tar);
    }

    #[test]
    fn test_magic_wins_over_wrong_extension() {
        // File named .zip but contains gzip magic bytes.
        let dir = tempfile::tempdir().unwrap();
        let path = write_magic_file(&dir, "archive.zip", b"\x1f\x8b\x00");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::TarGz);
    }

    #[test]
    fn test_extension_wins_when_no_magic_mismatch() {
        // File named .zip whose first bytes are not a recognised signature —
        // extension result stands.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.zip");
        std::fs::write(&path, b"\x00\x00\x00\x00").unwrap();
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::Zip);
    }

    #[test]
    fn test_nonexistent_file_without_extension_returns_unknown() {
        let path = PathBuf::from("/nonexistent/path/to/archive");
        assert!(matches!(
            detect_format(&path),
            Err(ArchiveError::UnknownFormat { .. })
        ));
    }

    #[test]
    fn test_nonexistent_file_with_known_extension_uses_extension() {
        // For a nonexistent file the magic-read silently fails, so extension wins.
        let path = PathBuf::from("/nonexistent/archive.zip");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::Zip);
    }

    // S1: empty ZIP (EOCD magic) and split-archive marker must be detected.
    #[test]
    fn test_magic_empty_zip_eocd_no_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_magic_file(&dir, "empty", b"\x50\x4b\x05\x06");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::Zip);
    }

    #[test]
    fn test_magic_split_zip_no_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_magic_file(&dir, "split", b"\x50\x4b\x07\x08");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::Zip);
    }

    // S3: USTAR detection must work even when the file is exactly 262 bytes with
    // no extra padding — exercises the read loop for a file that is exactly at
    // the boundary and has no trailing zero padding beyond offset 262.
    #[test]
    fn test_magic_tar_ustar_exact_boundary_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("minimal.tar");
        // Write exactly 262 bytes: zeros everywhere except "ustar" at offset 257.
        let mut data = vec![0u8; MAGIC_READ_LEN];
        data[257..262].copy_from_slice(b"ustar");
        std::fs::write(&path, &data).unwrap();
        // Extension matches too — verify magic agrees.
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::Tar);
    }

    // S3: a file shorter than 262 bytes but with USTAR at offset 257 must still
    // be detected (file is 262 bytes minimum by construction, but 263 bytes with
    // one extra zero also works; test a file that is exactly the USTAR minimum).
    #[test]
    fn test_magic_tar_ustar_minimal_263_byte_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data");
        let mut data = vec![0u8; 263];
        data[257..262].copy_from_slice(b"ustar");
        std::fs::write(&path, &data).unwrap();
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::Tar);
    }
}
