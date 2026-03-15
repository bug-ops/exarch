//! Archive listing implementation.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;

use flate2::read::GzDecoder;

use crate::ExtractionError;
use crate::Result;
use crate::SecurityConfig;
use crate::error::QuotaResource;
use crate::formats::detect::ArchiveType;
use crate::formats::detect::detect_format;
use crate::inspection::manifest::ArchiveEntry;
use crate::inspection::manifest::ArchiveManifest;
use crate::inspection::manifest::ManifestEntryType;

/// Lists archive contents without extracting.
///
/// Returns a manifest containing metadata for all entries in the archive.
/// No files are written to disk during this operation.
///
/// # Arguments
///
/// * `archive_path` - Path to archive file
/// * `config` - Security configuration (quota limits apply)
///
/// # Errors
///
/// Returns error if:
/// - Archive file cannot be opened
/// - Archive format is unsupported or corrupted
/// - Quota limits exceeded (file count, total size)
///
/// # Examples
///
/// ```no_run
/// use exarch_core::SecurityConfig;
/// use exarch_core::list_archive;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = SecurityConfig::default();
/// let manifest = list_archive("archive.tar.gz", &config)?;
///
/// println!("Archive contains {} files", manifest.total_entries);
/// for entry in manifest.entries {
///     println!("{}: {} bytes", entry.path.display(), entry.size);
/// }
/// # Ok(())
/// # }
/// ```
pub fn list_archive<P: AsRef<Path>>(
    archive_path: P,
    config: &SecurityConfig,
) -> Result<ArchiveManifest> {
    let archive_path = archive_path.as_ref();
    let format = detect_format(archive_path)?;

    match format {
        ArchiveType::Tar => list_tar(archive_path, format, config),
        ArchiveType::TarGz => list_tar_gz(archive_path, format, config),
        ArchiveType::TarBz2 => list_tar_bz2(archive_path, format, config),
        ArchiveType::TarXz => list_tar_xz(archive_path, format, config),
        ArchiveType::TarZst => list_tar_zst(archive_path, format, config),
        ArchiveType::Zip => list_zip(archive_path, format, config),
        ArchiveType::SevenZ => Err(crate::ExtractionError::InvalidArchive(
            "7z archive listing not yet supported".into(),
        )),
    }
}

fn list_tar(
    archive_path: &Path,
    format: ArchiveType,
    config: &SecurityConfig,
) -> Result<ArchiveManifest> {
    let file = File::open(archive_path)?;
    let reader = BufReader::new(file);
    let archive = tar::Archive::new(reader);
    list_tar_entries(archive, format, config)
}

fn list_tar_gz(
    archive_path: &Path,
    format: ArchiveType,
    config: &SecurityConfig,
) -> Result<ArchiveManifest> {
    let file = File::open(archive_path)?;
    let reader = BufReader::new(file);
    let decoder = GzDecoder::new(reader);
    let archive = tar::Archive::new(decoder);
    list_tar_entries(archive, format, config)
}

fn list_tar_bz2(
    archive_path: &Path,
    format: ArchiveType,
    config: &SecurityConfig,
) -> Result<ArchiveManifest> {
    use bzip2::read::BzDecoder;

    let file = File::open(archive_path)?;
    let reader = BufReader::new(file);
    let decoder = BzDecoder::new(reader);
    let archive = tar::Archive::new(decoder);
    list_tar_entries(archive, format, config)
}

fn list_tar_xz(
    archive_path: &Path,
    format: ArchiveType,
    config: &SecurityConfig,
) -> Result<ArchiveManifest> {
    use xz2::read::XzDecoder;

    let file = File::open(archive_path)?;
    let reader = BufReader::new(file);
    let decoder = XzDecoder::new(reader);
    let archive = tar::Archive::new(decoder);
    list_tar_entries(archive, format, config)
}

fn list_tar_zst(
    archive_path: &Path,
    format: ArchiveType,
    config: &SecurityConfig,
) -> Result<ArchiveManifest> {
    use zstd::stream::read::Decoder as ZstdDecoder;

    let file = File::open(archive_path)?;
    let reader = BufReader::new(file);
    let decoder = ZstdDecoder::new(reader)?;
    let archive = tar::Archive::new(decoder);
    list_tar_entries(archive, format, config)
}

fn list_tar_entries<R: std::io::Read>(
    mut archive: tar::Archive<R>,
    format: ArchiveType,
    config: &SecurityConfig,
) -> Result<ArchiveManifest> {
    let mut manifest = ArchiveManifest::new(format);

    let entries = archive
        .entries()
        .map_err(|e| ExtractionError::InvalidArchive(format!("failed to read TAR entries: {e}")))?;

    for entry_result in entries {
        let entry = entry_result.map_err(|e| {
            ExtractionError::InvalidArchive(format!("failed to read TAR entry: {e}"))
        })?;

        // Skip TAR metadata entries (PAX headers, GNU long names/links)
        if is_tar_metadata_entry(&entry) {
            continue;
        }

        // Check file count quota
        if manifest.total_entries >= config.max_file_count {
            return Err(ExtractionError::QuotaExceeded {
                resource: QuotaResource::FileCount {
                    current: manifest.total_entries + 1,
                    max: config.max_file_count,
                },
            });
        }

        let path = entry
            .path()
            .map_err(|e| ExtractionError::InvalidArchive(format!("invalid path: {e}")))?
            .into_owned();

        let entry_type = convert_tar_entry_type(&entry)?;
        let size = entry.size();
        let mode = entry.header().mode().ok();
        let modified =
            entry.header().mtime().ok().and_then(|t| {
                SystemTime::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(t))
            });

        let (symlink_target, hardlink_target) = match entry.header().entry_type() {
            tar::EntryType::Symlink | tar::EntryType::Link => {
                let target = entry
                    .link_name()
                    .map_err(|e| {
                        ExtractionError::InvalidArchive(format!("invalid link target: {e}"))
                    })?
                    .map(std::borrow::Cow::into_owned);

                if entry.header().entry_type() == tar::EntryType::Symlink {
                    (target.clone(), None)
                } else {
                    (None, target.clone())
                }
            }
            _ => (None, None),
        };

        let archive_entry = ArchiveEntry {
            path,
            entry_type,
            size,
            compressed_size: None,
            mode,
            modified,
            symlink_target,
            hardlink_target,
        };

        // Check total size quota
        if manifest.total_size + archive_entry.size > config.max_total_size {
            return Err(ExtractionError::QuotaExceeded {
                resource: QuotaResource::TotalSize {
                    current: manifest.total_size + archive_entry.size,
                    max: config.max_total_size,
                },
            });
        }

        manifest.add_entry(archive_entry);
    }

    Ok(manifest)
}

fn list_zip(
    archive_path: &Path,
    format: ArchiveType,
    config: &SecurityConfig,
) -> Result<ArchiveManifest> {
    let file = File::open(archive_path)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| ExtractionError::InvalidArchive(format!("failed to open ZIP archive: {e}")))?;

    let mut manifest = ArchiveManifest::new(format);

    for i in 0..archive.len() {
        // Check file count quota
        if manifest.total_entries >= config.max_file_count {
            return Err(ExtractionError::QuotaExceeded {
                resource: QuotaResource::FileCount {
                    current: manifest.total_entries + 1,
                    max: config.max_file_count,
                },
            });
        }

        let entry = archive.by_index(i).map_err(|e| {
            if e.to_string().contains("Password required to decrypt file") {
                return ExtractionError::SecurityViolation {
                    reason: "archive is password-protected".into(),
                };
            }
            ExtractionError::InvalidArchive(format!("failed to read ZIP entry: {e}"))
        })?;

        if entry.encrypted() {
            return Err(ExtractionError::SecurityViolation {
                reason: "archive is password-protected".into(),
            });
        }

        let path = entry
            .enclosed_name()
            .ok_or_else(|| ExtractionError::PathTraversal {
                path: PathBuf::from(entry.name()),
            })?;
        let path = path.clone();

        let entry_type = convert_zip_entry_type(&entry);
        let size = entry.size();
        let compressed_size = Some(entry.compressed_size());
        // Strip file-type bits (S_IFREG, S_IFDIR, etc.) from external_attributes >> 16,
        // keeping only the permission bits so the display matches TAR output.
        let mode = entry.unix_mode().map(|m| m & 0o7777);
        #[allow(clippy::cast_sign_loss)]
        let modified = entry.last_modified().and_then(|dt| {
            time::PrimitiveDateTime::try_from(dt).ok().and_then(|t| {
                let timestamp = t.assume_utc().unix_timestamp().max(0) as u64;
                SystemTime::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(timestamp))
            })
        });

        let symlink_target = if entry_type == ManifestEntryType::Symlink {
            Some(path.clone())
        } else {
            None
        };

        let archive_entry = ArchiveEntry {
            path,
            entry_type,
            size,
            compressed_size,
            mode,
            modified,
            symlink_target,
            hardlink_target: None,
        };

        // Check total size quota
        if manifest.total_size + archive_entry.size > config.max_total_size {
            return Err(ExtractionError::QuotaExceeded {
                resource: QuotaResource::TotalSize {
                    current: manifest.total_size + archive_entry.size,
                    max: config.max_total_size,
                },
            });
        }

        manifest.add_entry(archive_entry);
    }

    Ok(manifest)
}

/// Returns `true` for TAR metadata entries that should be skipped.
fn is_tar_metadata_entry<R: std::io::Read>(entry: &tar::Entry<'_, R>) -> bool {
    matches!(
        entry.header().entry_type(),
        tar::EntryType::XHeader
            | tar::EntryType::XGlobalHeader
            | tar::EntryType::GNULongName
            | tar::EntryType::GNULongLink
    )
}

fn convert_tar_entry_type<R: std::io::Read>(
    entry: &tar::Entry<'_, R>,
) -> Result<ManifestEntryType> {
    match entry.header().entry_type() {
        tar::EntryType::Directory => Ok(ManifestEntryType::Directory),
        tar::EntryType::Symlink => Ok(ManifestEntryType::Symlink),
        tar::EntryType::Link => Ok(ManifestEntryType::Hardlink),
        tar::EntryType::Char | tar::EntryType::Block | tar::EntryType::Fifo => {
            Err(ExtractionError::InvalidArchive(
                "special files (char/block devices, FIFOs) are not supported".to_string(),
            ))
        }
        // Regular, Continuous, GNUSparse treated as files
        _ => Ok(ManifestEntryType::File),
    }
}

fn convert_zip_entry_type<R: std::io::Read + std::io::Seek>(
    entry: &zip::read::ZipFile<'_, R>,
) -> ManifestEntryType {
    if entry.is_dir() {
        ManifestEntryType::Directory
    } else if is_zip_symlink(entry) {
        ManifestEntryType::Symlink
    } else {
        ManifestEntryType::File
    }
}

fn is_zip_symlink<R: std::io::Read + std::io::Seek>(entry: &zip::read::ZipFile<'_, R>) -> bool {
    #[cfg(unix)]
    {
        if let Some(mode) = entry.unix_mode() {
            const S_IFLNK: u32 = 0o120_000;
            return (mode & S_IFLNK) == S_IFLNK;
        }
    }

    #[cfg(not(unix))]
    let _ = entry;

    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Writes a minimal single-file ZIP archive where `external_attributes`
    /// encodes a full Unix stat(2) mode (file-type bits + permission bits)
    /// in the high 16 bits, as produced by system `zip(1)`, Python's
    /// `zipfile`, and other Unix-aware tools.
    ///
    /// `unix_mode` is what `ZipFile::unix_mode()` should return (i.e.
    /// `external_attributes >> 16`). The zip crate's write API masks
    /// `unix_permissions` to 0o777, so we construct the binary ZIP
    /// structure directly to reproduce archives from external tools.
    /// Uses empty content (CRC32 = 0) to avoid a CRC32 dependency in tests.
    #[allow(clippy::cast_possible_truncation)]
    fn zip_with_raw_unix_mode(filename: &str, unix_mode: u32) -> Vec<u8> {
        let external_attributes = unix_mode << 16;
        let name_bytes = filename.as_bytes();
        let name_len = name_bytes.len() as u16;

        let mut buf: Vec<u8> = Vec::new();

        // Local file header (empty stored entry, CRC32 = 0)
        let local_offset = buf.len() as u32;
        buf.extend_from_slice(b"PK\x03\x04"); // signature
        buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
        buf.extend_from_slice(&0u16.to_le_bytes()); // general purpose flags
        buf.extend_from_slice(&0u16.to_le_bytes()); // compression method: stored
        buf.extend_from_slice(&0u16.to_le_bytes()); // last mod time
        buf.extend_from_slice(&0u16.to_le_bytes()); // last mod date
        buf.extend_from_slice(&0u32.to_le_bytes()); // CRC32
        buf.extend_from_slice(&0u32.to_le_bytes()); // compressed size
        buf.extend_from_slice(&0u32.to_le_bytes()); // uncompressed size
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // extra field length
        buf.extend_from_slice(name_bytes);
        // no content bytes

        // Central directory entry
        let central_offset = buf.len() as u32;
        buf.extend_from_slice(b"PK\x01\x02"); // signature
        buf.extend_from_slice(&0x031eu16.to_le_bytes()); // version made by: Unix (3) + spec 3.0
        buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
        buf.extend_from_slice(&0u16.to_le_bytes()); // flags
        buf.extend_from_slice(&0u16.to_le_bytes()); // compression
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
        buf.extend_from_slice(&0u32.to_le_bytes()); // CRC32
        buf.extend_from_slice(&0u32.to_le_bytes()); // compressed size
        buf.extend_from_slice(&0u32.to_le_bytes()); // uncompressed size
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // extra length
        buf.extend_from_slice(&0u16.to_le_bytes()); // comment length
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        buf.extend_from_slice(&0u16.to_le_bytes()); // internal file attributes
        buf.extend_from_slice(&external_attributes.to_le_bytes()); // external attributes
        buf.extend_from_slice(&local_offset.to_le_bytes()); // local header offset
        buf.extend_from_slice(name_bytes);

        // End of central directory record
        let central_size = (buf.len() as u32) - central_offset;
        buf.extend_from_slice(b"PK\x05\x06"); // signature
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk number
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk with central dir
        buf.extend_from_slice(&1u16.to_le_bytes()); // entries on this disk
        buf.extend_from_slice(&1u16.to_le_bytes()); // total entries
        buf.extend_from_slice(&central_size.to_le_bytes());
        buf.extend_from_slice(&central_offset.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // comment length
        buf
    }

    #[test]
    fn test_list_archive_empty_tar() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let builder = tar::Builder::new(Vec::new());
        let data = builder.into_inner().unwrap();
        temp_file.write_all(&data).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let manifest = list_archive(temp_file.path(), &config).unwrap();

        assert_eq!(manifest.total_entries, 0);
        assert_eq!(manifest.total_size, 0);
        assert_eq!(manifest.entries.len(), 0);
        assert_eq!(manifest.format, ArchiveType::Tar);
    }

    #[test]
    fn test_list_archive_tar_gz() {
        let mut temp_file = NamedTempFile::with_suffix(".tar.gz").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let data = b"test content";
        let mut header = tar::Header::new_gnu();
        header.set_path("file.txt").unwrap();
        header.set_size(data.len() as u64);
        header.set_cksum();
        builder.append(&header, &data[..]).unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let compressed = encoder.finish().unwrap();

        temp_file.write_all(&compressed).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let manifest = list_archive(temp_file.path(), &config).unwrap();

        assert_eq!(manifest.total_entries, 1);
        assert_eq!(manifest.format, ArchiveType::TarGz);
        assert_eq!(manifest.entries[0].path, PathBuf::from("file.txt"));
        assert_eq!(manifest.entries[0].entry_type, ManifestEntryType::File);
    }

    #[test]
    fn test_list_archive_zip() {
        let temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        let file = std::fs::File::create(temp_file.path()).unwrap();
        let mut zip = zip::ZipWriter::new(file);

        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("test.txt", options).unwrap();
        zip.write_all(b"test content").unwrap();
        zip.finish().unwrap();

        let config = SecurityConfig::default();
        let manifest = list_archive(temp_file.path(), &config).unwrap();

        assert_eq!(manifest.total_entries, 1);
        assert_eq!(manifest.format, ArchiveType::Zip);
        assert_eq!(manifest.entries[0].path, PathBuf::from("test.txt"));
        assert_eq!(manifest.entries[0].entry_type, ManifestEntryType::File);
    }

    #[test]
    fn test_list_archive_with_entries() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let file1_data = b"content1";
        let mut header1 = tar::Header::new_gnu();
        header1.set_path("dir/file1.txt").unwrap();
        header1.set_size(file1_data.len() as u64);
        header1.set_cksum();
        builder.append(&header1, &file1_data[..]).unwrap();

        let file2_data = b"content2";
        let mut header2 = tar::Header::new_gnu();
        header2.set_path("dir/file2.txt").unwrap();
        header2.set_size(file2_data.len() as u64);
        header2.set_cksum();
        builder.append(&header2, &file2_data[..]).unwrap();

        let data = builder.into_inner().unwrap();
        temp_file.write_all(&data).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let manifest = list_archive(temp_file.path(), &config).unwrap();

        assert_eq!(manifest.total_entries, 2);
        assert_eq!(manifest.total_size, 16);
        assert_eq!(manifest.entries.len(), 2);
        assert_eq!(manifest.entries[0].path, PathBuf::from("dir/file1.txt"));
        assert_eq!(manifest.entries[1].path, PathBuf::from("dir/file2.txt"));
    }

    #[test]
    fn test_list_archive_with_symlink() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_path("link").unwrap();
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("target.txt").unwrap();
        header.set_cksum();
        builder.append(&header, &[][..]).unwrap();

        let data = builder.into_inner().unwrap();
        temp_file.write_all(&data).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let manifest = list_archive(temp_file.path(), &config).unwrap();

        assert_eq!(manifest.total_entries, 1);
        assert_eq!(manifest.entries[0].entry_type, ManifestEntryType::Symlink);
        assert_eq!(
            manifest.entries[0].symlink_target,
            Some(PathBuf::from("target.txt"))
        );
    }

    #[test]
    fn test_list_archive_with_hardlink() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_path("link").unwrap();
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Link);
        header.set_link_name("original.txt").unwrap();
        header.set_cksum();
        builder.append(&header, &[][..]).unwrap();

        let data = builder.into_inner().unwrap();
        temp_file.write_all(&data).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let manifest = list_archive(temp_file.path(), &config).unwrap();

        assert_eq!(manifest.total_entries, 1);
        assert_eq!(manifest.entries[0].entry_type, ManifestEntryType::Hardlink);
        assert_eq!(
            manifest.entries[0].hardlink_target,
            Some(PathBuf::from("original.txt"))
        );
    }

    #[test]
    fn test_list_archive_quota_exceeded() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        // Create 2 entries
        let data = b"test data";
        let mut header = tar::Header::new_gnu();
        header.set_path("file1.txt").unwrap();
        header.set_size(data.len() as u64);
        header.set_cksum();
        builder.append(&header, &data[..]).unwrap();

        let mut header2 = tar::Header::new_gnu();
        header2.set_path("file2.txt").unwrap();
        header2.set_size(data.len() as u64);
        header2.set_cksum();
        builder.append(&header2, &data[..]).unwrap();

        let archive_data = builder.into_inner().unwrap();
        temp_file.write_all(&archive_data).unwrap();
        temp_file.flush().unwrap();

        // Set quota to 1 file
        let config = SecurityConfig {
            max_file_count: 1,
            ..Default::default()
        };

        let result = list_archive(temp_file.path(), &config);
        match result {
            Err(ExtractionError::QuotaExceeded {
                resource: QuotaResource::FileCount { current, max },
            }) => {
                assert_eq!(max, 1);
                assert_eq!(current, 2, "current must be max+1 (off-by-one fix)");
            }
            other => panic!("expected FileCount quota error, got {other:?}"),
        }
    }

    #[test]
    fn test_list_zip_quota_exceeded_file_count() {
        let temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        let file = std::fs::File::create(temp_file.path()).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("a.txt", options).unwrap();
        zip.start_file("b.txt", options).unwrap();
        zip.finish().unwrap();

        let config = SecurityConfig {
            max_file_count: 1,
            ..Default::default()
        };

        let result = list_archive(temp_file.path(), &config);
        match result {
            Err(ExtractionError::QuotaExceeded {
                resource: QuotaResource::FileCount { current, max },
            }) => {
                assert_eq!(max, 1);
                assert_eq!(current, 2, "current must be max+1 (off-by-one fix)");
            }
            other => panic!("expected FileCount quota error, got {other:?}"),
        }
    }

    #[test]
    fn test_zip_mode_strips_s_ifreg_bits() {
        // Archives from Unix tools store the full stat(2) mode in external_attributes.
        // 0o100644 = S_IFREG (0o100000) | 0o644. After listing, only 0o644 must remain.
        let zip_bytes = zip_with_raw_unix_mode("file.txt", 0o100_644);
        let mut temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        temp_file.write_all(&zip_bytes).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let manifest = list_archive(temp_file.path(), &config).unwrap();

        assert_eq!(manifest.total_entries, 1);
        assert_eq!(manifest.entries[0].mode, Some(0o644));
    }

    #[test]
    fn test_zip_mode_strips_s_ifdir_bits() {
        // 0o040755 = S_IFDIR (0o040000) | 0o755. After listing, only 0o755 must remain.
        let zip_bytes = zip_with_raw_unix_mode("mydir/", 0o040_755);
        let mut temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        temp_file.write_all(&zip_bytes).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let manifest = list_archive(temp_file.path(), &config).unwrap();

        assert_eq!(manifest.total_entries, 1);
        assert_eq!(manifest.entries[0].mode, Some(0o755));
    }

    #[test]
    fn test_zip_mode_permission_bits_unchanged() {
        // When no file-type bits are present, permission bits must be preserved as-is.
        let zip_bytes = zip_with_raw_unix_mode("file.txt", 0o644);
        let mut temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        temp_file.write_all(&zip_bytes).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let manifest = list_archive(temp_file.path(), &config).unwrap();

        assert_eq!(manifest.total_entries, 1);
        assert_eq!(manifest.entries[0].mode, Some(0o644));
    }

    #[test]
    fn test_list_zip_encrypted_returns_security_violation() {
        use std::io::Cursor;
        use zip::ZipWriter;
        use zip::unstable::write::FileOptionsExt;
        use zip::write::SimpleFileOptions;

        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default()
            .with_deprecated_encryption(b"password")
            .unwrap();
        writer.start_file("secret.txt", options).unwrap();
        writer.write_all(b"secret data").unwrap();
        let zip_data = writer.finish().unwrap().into_inner();

        let mut temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        temp_file.write_all(&zip_data).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let result = list_archive(temp_file.path(), &config);
        match result {
            Err(ExtractionError::SecurityViolation { reason }) => {
                assert!(
                    reason.contains("password-protected"),
                    "expected 'password-protected' in reason: {reason}"
                );
            }
            other => panic!("expected SecurityViolation, got: {other:?}"),
        }
    }

    #[test]
    fn test_tar_and_zip_mode_consistent() {
        // TAR and ZIP must both store only permission bits in ArchiveEntry.mode.
        let tar_file = NamedTempFile::with_suffix(".tar").unwrap();
        {
            let mut builder = tar::Builder::new(std::fs::File::create(tar_file.path()).unwrap());
            let data = b"content";
            let mut header = tar::Header::new_gnu();
            header.set_path("file.txt").unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, &data[..]).unwrap();
            builder.into_inner().unwrap();
        }

        // ZIP with full S_IFREG mode, as written by an external Unix tool.
        let zip_bytes = zip_with_raw_unix_mode("file.txt", 0o100_644);
        let zip_file = NamedTempFile::with_suffix(".zip").unwrap();
        {
            let mut f = std::fs::File::create(zip_file.path()).unwrap();
            f.write_all(&zip_bytes).unwrap();
        }

        let config = SecurityConfig::default();
        let tar_manifest = list_archive(tar_file.path(), &config).unwrap();
        let zip_manifest = list_archive(zip_file.path(), &config).unwrap();

        assert_eq!(tar_manifest.entries[0].mode, zip_manifest.entries[0].mode);
        assert_eq!(tar_manifest.entries[0].mode, Some(0o644));
    }
}
