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

        // Check file count quota
        if manifest.total_entries >= config.max_file_count {
            return Err(ExtractionError::QuotaExceeded {
                resource: QuotaResource::FileCount {
                    current: manifest.total_entries,
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
                    current: manifest.total_entries,
                    max: config.max_file_count,
                },
            });
        }

        let entry = archive.by_index(i).map_err(|e| {
            ExtractionError::InvalidArchive(format!("failed to read ZIP entry: {e}"))
        })?;

        let path = entry
            .enclosed_name()
            .ok_or_else(|| ExtractionError::PathTraversal {
                path: PathBuf::from(entry.name()),
            })?;
        let path = path.clone();

        let entry_type = convert_zip_entry_type(&entry);
        let size = entry.size();
        let compressed_size = Some(entry.compressed_size());
        let mode = entry.unix_mode();
        #[allow(deprecated, clippy::cast_sign_loss)]
        let modified = entry.last_modified().and_then(|dt| {
            dt.to_time().ok().and_then(|t| {
                let timestamp = t.unix_timestamp().max(0) as u64;
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
        // All other types (Regular, Continuous, GNULongName, etc.) treated as files
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
        assert!(matches!(
            result,
            Err(ExtractionError::QuotaExceeded {
                resource: QuotaResource::FileCount { .. },
            })
        ));
    }
}
