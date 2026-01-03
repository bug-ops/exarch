//! TAR archive format extraction.
//!
//! This module provides secure extraction of TAR archives with comprehensive
//! security validation. Supported formats:
//!
//! - **ustar** (POSIX.1-1988): Standard Unix tar format
//! - **pax** (POSIX.1-2001): Extended header format for long paths/metadata
//! - **gnu** (GNU tar): GNU extensions for sparse files and incremental backups
//!
//! # Format Detection
//!
//! The TAR format is auto-detected based on header magic bytes. No explicit
//! format selection is required.
//!
//! # Compression Support
//!
//! Transparent decompression is supported via:
//!
//! - **gzip** (.tar.gz, .tgz): Via `flate2` crate
//! - **bzip2** (.tar.bz2, .tbz2): Via `bzip2` crate
//! - **xz** (.tar.xz, .txz): Via `xz2` crate
//! - **zstd** (.tar.zst, .tzst): Via `zstd` crate
//!
//! # Security Features
//!
//! All entries are validated through the security layer:
//!
//! - Path traversal prevention (rejects `../`, absolute paths)
//! - Quota enforcement (file size, count, total size)
//! - Symlink escape detection (symlinks must point within extraction directory)
//! - Hardlink escape detection (hardlink targets must be within extraction
//!   directory)
//! - Permission sanitization (strips setuid/setgid bits)
//! - Device file rejection (char, block devices not supported)
//! - FIFO rejection (named pipes not supported)
//!
//! # Entry Type Support
//!
//! | Entry Type | Supported | Notes |
//! |------------|-----------|-------|
//! | Regular files | ✅ Yes | Full support with streaming |
//! | Directories | ✅ Yes | Created recursively |
//! | Symlinks | ✅ Yes | Unix only, requires `config.allowed.symlinks = true` |
//! | Hardlinks | ✅ Yes | Two-pass extraction, requires `config.allowed.hardlinks = true` |
//! | Char devices | ❌ No | Rejected with `UnsupportedFeature` error |
//! | Block devices | ❌ No | Rejected with `UnsupportedFeature` error |
//! | FIFOs | ❌ No | Rejected with `UnsupportedFeature` error |
//!
//! # Performance Characteristics
//!
//! - **Streaming**: Processes entries one at a time without buffering entire
//!   archive
//! - **Memory usage**: O(1) for archive processing, O(n) for hardlink tracking
//! - **Two-pass extraction**: Files/directories first, hardlinks second
//!
//! # Examples
//!
//! Basic extraction:
//!
//! ```no_run
//! use exarch_core::SecurityConfig;
//! use exarch_core::formats::TarArchive;
//! use exarch_core::formats::traits::ArchiveFormat;
//! use std::fs::File;
//! use std::path::Path;
//!
//! let file = File::open("archive.tar")?;
//! let mut archive = TarArchive::new(file);
//! let report = archive.extract(Path::new("/output"), &SecurityConfig::default())?;
//! println!("Extracted {} files", report.files_extracted);
//! # Ok::<(), exarch_core::ExtractionError>(())
//! ```
//!
//! Gzip-compressed TAR:
//!
//! ```no_run
//! use exarch_core::SecurityConfig;
//! use exarch_core::formats::TarArchive;
//! use exarch_core::formats::traits::ArchiveFormat;
//! use flate2::read::GzDecoder;
//! use std::fs::File;
//! use std::path::Path;
//!
//! let file = File::open("archive.tar.gz")?;
//! let decoder = GzDecoder::new(file);
//! let mut archive = TarArchive::new(decoder);
//! let report = archive.extract(Path::new("/output"), &SecurityConfig::default())?;
//! # Ok::<(), exarch_core::ExtractionError>(())
//! ```

use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::path::Path;
use std::time::Instant;

use smallvec::SmallVec;
use tar::Archive;

use crate::ExtractionError;
use crate::ExtractionReport;
use crate::Result;
use crate::SecurityConfig;
use crate::copy::CopyBuffer;
use crate::security::validator::EntryValidator;
use crate::security::validator::ValidatedEntry;
use crate::security::validator::ValidatedEntryType;
use crate::types::DestDir;
use crate::types::EntryType;
use crate::types::SafePath;

use super::common;
use super::traits::ArchiveFormat;

/// TAR archive handler with streaming extraction.
///
/// Supports ustar, pax, and gnu TAR formats with automatic detection.
/// The archive is processed in a streaming fashion to minimize memory usage.
///
/// # Type Parameters
///
/// - `R`: Reader type that must implement `Read`
///
/// # Examples
///
/// ```no_run
/// use exarch_core::SecurityConfig;
/// use exarch_core::formats::TarArchive;
/// use exarch_core::formats::traits::ArchiveFormat;
/// use std::fs::File;
/// use std::path::Path;
///
/// let file = File::open("archive.tar")?;
/// let mut archive = TarArchive::new(file);
/// let config = SecurityConfig::default();
/// let report = archive.extract(Path::new("/output"), &config)?;
/// # Ok::<(), exarch_core::ExtractionError>(())
/// ```
pub struct TarArchive<R: Read> {
    /// Underlying `tar::Archive` reader
    inner: Archive<R>,
}

impl<R: Read> TarArchive<R> {
    /// Creates a new TAR archive handler from a reader.
    ///
    /// The reader will be consumed during extraction. For file-based
    /// archives, wrap in `BufReader` for optimal performance.
    ///
    /// # Performance Notes
    ///
    /// - Input: Wrap file readers in `BufReader::new()` for 10x faster reads
    /// - Output: File writes use `BufWriter` internally for optimal throughput
    /// - Memory: O(1) for archive processing, O(n) for hardlink tracking
    /// - Typical throughput: 100-500 MB/s on modern SSDs
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use exarch_core::formats::TarArchive;
    /// use std::fs::File;
    /// use std::io::BufReader;
    ///
    /// let file = File::open("archive.tar")?;
    /// let reader = BufReader::new(file);
    /// let archive = TarArchive::new(reader);
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn new(reader: R) -> Self {
        Self {
            inner: Archive::new(reader),
        }
    }

    /// Processes a single TAR entry.
    fn process_entry(
        entry: tar::Entry<'_, R>,
        validator: &mut EntryValidator,
        dest: &DestDir,
        report: &mut ExtractionReport,
        copy_buffer: &mut CopyBuffer,
        dir_cache: &mut common::DirCache,
    ) -> Result<Option<HardlinkInfo>> {
        let path = entry
            .path()
            .map_err(|e| ExtractionError::InvalidArchive(format!("invalid path: {e}")))?
            .into_owned();

        let entry_type = TarEntryAdapter::to_entry_type(&entry)?;
        let size = TarEntryAdapter::get_uncompressed_size(&entry)?;
        let mode = entry.header().mode().ok();

        let validated = validator.validate_entry(&path, &entry_type, size, None, mode)?;

        match validated.entry_type {
            ValidatedEntryType::File => {
                Self::extract_file(entry, &validated, dest, report, copy_buffer, dir_cache)?;
                Ok(None)
            }

            ValidatedEntryType::Directory => {
                common::create_directory(&validated, dest, report, dir_cache)?;
                Ok(None)
            }

            ValidatedEntryType::Symlink(safe_symlink) => {
                common::create_symlink(&safe_symlink, dest, report, dir_cache)?;
                Ok(None)
            }

            ValidatedEntryType::Hardlink { target } => {
                // Two-pass: defer hardlink creation until target files exist
                Ok(Some(HardlinkInfo {
                    link_path: validated.safe_path,
                    target_path: target,
                }))
            }
        }
    }

    /// Extracts a regular file to disk.
    fn extract_file(
        mut entry: tar::Entry<'_, R>,
        validated: &ValidatedEntry,
        dest: &DestDir,
        report: &mut ExtractionReport,
        copy_buffer: &mut CopyBuffer,
        dir_cache: &mut common::DirCache,
    ) -> Result<()> {
        let size = entry.header().size().ok();
        common::extract_file_generic(
            &mut entry,
            validated,
            dest,
            report,
            size,
            copy_buffer,
            dir_cache,
        )
    }

    /// Creates a hardlink in the second pass.
    #[allow(unused_variables)]
    fn create_hardlink(
        info: &HardlinkInfo,
        dest: &DestDir,
        report: &mut ExtractionReport,
        dir_cache: &mut common::DirCache,
    ) -> Result<()> {
        #[cfg(unix)]
        {
            use std::fs::hard_link;

            let link_path = dest.join(&info.link_path);
            let target_path = dest.join(&info.target_path);

            if !target_path.exists() {
                return Err(ExtractionError::InvalidArchive(format!(
                    "hardlink target does not exist: {}",
                    info.target_path.as_path().display()
                )));
            }

            // Create parent directories using cache
            dir_cache.ensure_parent_dir(&link_path)?;

            hard_link(&target_path, &link_path)?;

            report.files_extracted += 1;

            Ok(())
        }

        #[cfg(not(unix))]
        {
            Err(ExtractionError::SecurityViolation {
                reason: "hardlinks are not supported on this platform".into(),
            })
        }
    }
}

impl<R: Read> ArchiveFormat for TarArchive<R> {
    fn extract(&mut self, output_dir: &Path, config: &SecurityConfig) -> Result<ExtractionReport> {
        let start = Instant::now();

        let dest = DestDir::new(output_dir.to_path_buf())?;

        let mut validator = EntryValidator::new(config, &dest);

        let mut report = ExtractionReport::new();

        let mut hardlinks: SmallVec<[HardlinkInfo; 8]> = SmallVec::new();

        let mut copy_buffer = CopyBuffer::new();

        let mut dir_cache = common::DirCache::new();

        let entries = self
            .inner
            .entries()
            .map_err(|e| ExtractionError::InvalidArchive(format!("failed to read entries: {e}")))?;

        for entry_result in entries {
            let entry = entry_result.map_err(|e| {
                ExtractionError::InvalidArchive(format!("failed to read entry: {e}"))
            })?;

            if let Some(hardlink_info) = Self::process_entry(
                entry,
                &mut validator,
                &dest,
                &mut report,
                &mut copy_buffer,
                &mut dir_cache,
            )? {
                hardlinks.push(hardlink_info);
            }
        }

        // Two-pass extraction: create hardlinks after all target files exist
        for hardlink_info in &hardlinks {
            Self::create_hardlink(hardlink_info, &dest, &mut report, &mut dir_cache)?;
        }

        report.duration = start.elapsed();

        Ok(report)
    }

    fn format_name(&self) -> &'static str {
        "tar"
    }
}

/// Information about a hardlink for deferred creation.
#[allow(dead_code)] // Fields used only on Unix
struct HardlinkInfo {
    link_path: SafePath,
    target_path: SafePath,
}

/// Adapter to convert `tar::Entry` to our `EntryType`.
struct TarEntryAdapter;

impl TarEntryAdapter {
    /// Converts `tar::EntryType` to our `EntryType` enum.
    fn to_entry_type<R: Read>(tar_entry: &tar::Entry<'_, R>) -> Result<EntryType> {
        use tar::EntryType as TarType;

        match tar_entry.header().entry_type() {
            TarType::Regular => Ok(EntryType::File),

            TarType::Directory => Ok(EntryType::Directory),

            TarType::Symlink => {
                let target = tar_entry
                    .link_name()
                    .map_err(|e| {
                        ExtractionError::InvalidArchive(format!("failed to read symlink name: {e}"))
                    })?
                    .ok_or_else(|| {
                        ExtractionError::InvalidArchive("symlink missing target".into())
                    })?
                    .into_owned();
                Ok(EntryType::Symlink { target })
            }

            TarType::Link => {
                let target = tar_entry
                    .link_name()
                    .map_err(|e| {
                        ExtractionError::InvalidArchive(format!(
                            "failed to read hardlink name: {e}"
                        ))
                    })?
                    .ok_or_else(|| {
                        ExtractionError::InvalidArchive("hardlink missing target".into())
                    })?
                    .into_owned();
                Ok(EntryType::Hardlink { target })
            }

            TarType::Char => Err(ExtractionError::SecurityViolation {
                reason: "character device entries not supported".into(),
            }),

            TarType::Block => Err(ExtractionError::SecurityViolation {
                reason: "block device entries not supported".into(),
            }),

            TarType::Fifo => Err(ExtractionError::SecurityViolation {
                reason: "FIFO entries not supported".into(),
            }),

            _ => Err(ExtractionError::SecurityViolation {
                reason: format!(
                    "unsupported entry type: {:?}",
                    tar_entry.header().entry_type()
                ),
            }),
        }
    }

    /// Gets uncompressed size from TAR header.
    fn get_uncompressed_size<R: Read>(tar_entry: &tar::Entry<'_, R>) -> Result<u64> {
        tar_entry.header().size().map_err(|e| {
            ExtractionError::InvalidArchive(format!("invalid size in TAR header: {e}"))
        })
    }
}

/// Opens a gzip-compressed TAR archive (.tar.gz).
///
/// The file is wrapped in `BufReader` for optimal performance.
///
/// # Errors
///
/// Returns an error if the file cannot be opened.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::SecurityConfig;
/// use exarch_core::formats::tar::open_tar_gz;
/// use exarch_core::formats::traits::ArchiveFormat;
/// use std::path::Path;
///
/// let mut archive = open_tar_gz("archive.tar.gz")?;
/// let config = SecurityConfig::default();
/// let report = archive.extract(Path::new("/output"), &config)?;
/// # Ok::<(), exarch_core::ExtractionError>(())
/// ```
pub fn open_tar_gz<P: AsRef<Path>>(
    path: P,
) -> Result<TarArchive<flate2::read::GzDecoder<BufReader<File>>>> {
    let file = File::open(path)?;
    let buffered = BufReader::new(file);
    let decoder = flate2::read::GzDecoder::new(buffered);
    Ok(TarArchive::new(decoder))
}

/// Opens a bzip2-compressed TAR archive (.tar.bz2).
///
/// The file is wrapped in `BufReader` for optimal performance.
///
/// # Errors
///
/// Returns an error if the file cannot be opened.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::SecurityConfig;
/// use exarch_core::formats::tar::open_tar_bz2;
/// use exarch_core::formats::traits::ArchiveFormat;
/// use std::path::Path;
///
/// let mut archive = open_tar_bz2("archive.tar.bz2")?;
/// let config = SecurityConfig::default();
/// let report = archive.extract(Path::new("/output"), &config)?;
/// # Ok::<(), exarch_core::ExtractionError>(())
/// ```
pub fn open_tar_bz2<P: AsRef<Path>>(
    path: P,
) -> Result<TarArchive<bzip2::read::BzDecoder<BufReader<File>>>> {
    let file = File::open(path)?;
    let buffered = BufReader::new(file);
    let decoder = bzip2::read::BzDecoder::new(buffered);
    Ok(TarArchive::new(decoder))
}

/// Opens an xz-compressed TAR archive (.tar.xz).
///
/// The file is wrapped in `BufReader` for optimal performance.
///
/// # Errors
///
/// Returns an error if the file cannot be opened.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::SecurityConfig;
/// use exarch_core::formats::tar::open_tar_xz;
/// use exarch_core::formats::traits::ArchiveFormat;
/// use std::path::Path;
///
/// let mut archive = open_tar_xz("archive.tar.xz")?;
/// let config = SecurityConfig::default();
/// let report = archive.extract(Path::new("/output"), &config)?;
/// # Ok::<(), exarch_core::ExtractionError>(())
/// ```
pub fn open_tar_xz<P: AsRef<Path>>(
    path: P,
) -> Result<TarArchive<xz2::read::XzDecoder<BufReader<File>>>> {
    let file = File::open(path)?;
    let buffered = BufReader::new(file);
    let decoder = xz2::read::XzDecoder::new(buffered);
    Ok(TarArchive::new(decoder))
}

/// Opens a zstd-compressed TAR archive (.tar.zst).
///
/// The file is wrapped in `BufReader` for optimal performance.
///
/// # Errors
///
/// Returns an error if the file cannot be opened or if decompression
/// initialization fails.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::SecurityConfig;
/// use exarch_core::formats::tar::open_tar_zst;
/// use exarch_core::formats::traits::ArchiveFormat;
/// use std::path::Path;
///
/// let mut archive = open_tar_zst("archive.tar.zst")?;
/// let config = SecurityConfig::default();
/// let report = archive.extract(Path::new("/output"), &config)?;
/// # Ok::<(), exarch_core::ExtractionError>(())
/// ```
pub fn open_tar_zst<P: AsRef<Path>>(
    path: P,
) -> Result<TarArchive<zstd::Decoder<'static, BufReader<File>>>> {
    let file = File::open(path)?;
    let buffered = BufReader::new(file);
    let decoder = zstd::Decoder::with_buffer(buffered)?;
    Ok(TarArchive::new(decoder))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::test_utils::create_test_tar;
    use std::io::Cursor;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_tar_archive_new() {
        let tar_data = create_test_tar(vec![]);
        let archive = TarArchive::new(Cursor::new(tar_data));
        assert_eq!(archive.format_name(), "tar");
    }

    #[test]
    fn test_extract_simple_file() {
        let tar_data = create_test_tar(vec![("file.txt", b"hello world")]);
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive.extract(temp.path(), &config).unwrap();

        assert_eq!(report.files_extracted, 1);
        assert_eq!(report.directories_created, 0);
        assert!(temp.path().join("file.txt").exists());
    }

    #[test]
    fn test_extract_nested_structure() {
        let mut builder = tar::Builder::new(Vec::new());

        // Add directories explicitly
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_cksum();
        builder
            .append_data(&mut header, "dir1/", &[] as &[u8])
            .unwrap();

        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_cksum();
        builder
            .append_data(&mut header, "dir1/dir2/", &[] as &[u8])
            .unwrap();

        // Add file
        let mut header = tar::Header::new_gnu();
        header.set_size(6);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "dir1/dir2/file.txt", &b"nested"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive.extract(temp.path(), &config).unwrap();

        assert_eq!(report.files_extracted, 1);
        assert_eq!(report.directories_created, 2);
        assert!(temp.path().join("dir1/dir2/file.txt").exists());
    }

    #[test]
    #[cfg(unix)]
    fn test_extract_symlink() {
        let mut builder = tar::Builder::new(Vec::new());

        // Add target file
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "target.txt", &b"data\n"[..])
            .unwrap();

        // Add symlink
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("target.txt").unwrap();
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "link.txt", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = true;

        let report = archive.extract(temp.path(), &config).unwrap();

        assert_eq!(report.files_extracted, 1);
        assert_eq!(report.symlinks_created, 1);
        assert!(temp.path().join("link.txt").exists());
    }

    #[test]
    #[cfg(unix)]
    fn test_extract_hardlink_two_pass() {
        let mut builder = tar::Builder::new(Vec::new());

        // Add hardlink BEFORE target (tests two-pass)
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_link_name("target.txt").unwrap();
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "hardlink.txt", &[] as &[u8])
            .unwrap();

        // Add target file
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "target.txt", &b"data\n"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;

        let report = archive.extract(temp.path(), &config).unwrap();

        assert_eq!(report.files_extracted, 2);
        assert!(temp.path().join("hardlink.txt").exists());
        assert!(temp.path().join("target.txt").exists());
    }

    #[test]
    fn test_quota_file_size_exceeded() {
        let tar_data = create_test_tar(vec![("large.bin", &vec![0u8; 1000])]);
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig {
            max_file_size: 100,
            ..Default::default()
        };

        let result = archive.extract(temp.path(), &config);

        assert!(result.is_err());
    }

    #[test]
    fn test_unsupported_entry_type_block_device() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Block);
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "dev/sda", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let result = archive.extract(temp.path(), &config);

        assert!(result.is_err());
    }

    #[test]
    fn test_unsupported_entry_type_char_device() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Char);
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "dev/tty", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let result = archive.extract(temp.path(), &config);

        assert!(result.is_err());
    }

    #[test]
    fn test_unsupported_entry_type_fifo() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Fifo);
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "fifo", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let result = archive.extract(temp.path(), &config);

        assert!(result.is_err());
    }

    #[test]
    fn test_extract_gzip_compressed() {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        // Create TAR archive
        let tar_data = create_test_tar(vec![("file.txt", b"compressed")]);

        // Compress with gzip
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let gz_data = encoder.finish().unwrap();

        // Extract
        let decoder = flate2::read::GzDecoder::new(Cursor::new(gz_data));
        let mut archive = TarArchive::new(decoder);

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive.extract(temp.path(), &config).unwrap();

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("file.txt").exists());
    }

    #[test]
    fn test_extract_bzip2_compressed() {
        use bzip2::Compression;
        use bzip2::write::BzEncoder;

        // Create TAR archive
        let tar_data = create_test_tar(vec![("file.txt", b"compressed")]);

        // Compress with bzip2
        let mut encoder = BzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let bz2_data = encoder.finish().unwrap();

        // Extract
        let decoder = bzip2::read::BzDecoder::new(Cursor::new(bz2_data));
        let mut archive = TarArchive::new(decoder);

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive.extract(temp.path(), &config).unwrap();

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("file.txt").exists());
    }

    #[test]
    fn test_extract_xz_compressed() {
        use xz2::write::XzEncoder;

        // Create TAR archive
        let tar_data = create_test_tar(vec![("file.txt", b"compressed")]);

        // Compress with xz
        let mut encoder = XzEncoder::new(Vec::new(), 6);
        encoder.write_all(&tar_data).unwrap();
        let xz_data = encoder.finish().unwrap();

        // Extract
        let decoder = xz2::read::XzDecoder::new(Cursor::new(xz_data));
        let mut archive = TarArchive::new(decoder);

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive.extract(temp.path(), &config).unwrap();

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("file.txt").exists());
    }

    #[test]
    fn test_extract_zstd_compressed() {
        // Create TAR archive
        let tar_data = create_test_tar(vec![("file.txt", b"compressed")]);

        // Compress with zstd
        let zst_data = zstd::encode_all(&tar_data[..], 3).unwrap();

        // Extract
        let decoder = zstd::Decoder::with_buffer(Cursor::new(zst_data)).unwrap();
        let mut archive = TarArchive::new(decoder);

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive.extract(temp.path(), &config).unwrap();

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("file.txt").exists());
    }

    #[test]
    fn test_empty_tar_archive() {
        let tar_data = create_test_tar(vec![]);
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive.extract(temp.path(), &config).unwrap();

        assert_eq!(report.files_extracted, 0);
        assert_eq!(report.directories_created, 0);
    }

    #[test]
    fn test_extract_empty_file() {
        let tar_data = create_test_tar(vec![("empty.txt", b"")]);
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive.extract(temp.path(), &config).unwrap();

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("empty.txt").exists());
        assert_eq!(
            std::fs::metadata(temp.path().join("empty.txt"))
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn test_extract_multiple_files() {
        let tar_data = create_test_tar(vec![
            ("file1.txt", b"content1"),
            ("file2.txt", b"content2"),
            ("file3.txt", b"content3"),
        ]);
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive.extract(temp.path(), &config).unwrap();

        assert_eq!(report.files_extracted, 3);
        assert!(temp.path().join("file1.txt").exists());
        assert!(temp.path().join("file2.txt").exists());
        assert!(temp.path().join("file3.txt").exists());
    }

    #[test]
    fn test_quota_file_count_exceeded() {
        let tar_data = create_test_tar(vec![
            ("file1.txt", b"a"),
            ("file2.txt", b"b"),
            ("file3.txt", b"c"),
        ]);
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig {
            max_file_count: 2,
            ..Default::default()
        };

        let result = archive.extract(temp.path(), &config);

        assert!(result.is_err());
    }

    #[test]
    fn test_quota_total_size_exceeded() {
        let tar_data = create_test_tar(vec![
            ("file1.txt", &vec![0u8; 500]),
            ("file2.txt", &vec![0u8; 600]),
        ]);
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig {
            max_total_size: 1000,
            ..Default::default()
        };

        let result = archive.extract(temp.path(), &config);

        assert!(result.is_err());
    }

    #[test]
    #[cfg(unix)]
    fn test_file_permissions_preserved() {
        use std::os::unix::fs::PermissionsExt;

        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, "script.sh", &b"#!/bin/sh"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive.extract(temp.path(), &config).unwrap();

        assert_eq!(report.files_extracted, 1);

        let metadata = std::fs::metadata(temp.path().join("script.sh")).unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o755);
    }

    #[test]
    #[cfg(unix)]
    fn test_permissions_sanitized_setuid_removed() {
        use std::os::unix::fs::PermissionsExt;

        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o4755); // setuid bit set
        header.set_cksum();
        builder
            .append_data(&mut header, "binary", &b"data"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive.extract(temp.path(), &config).unwrap();

        assert_eq!(report.files_extracted, 1);

        let metadata = std::fs::metadata(temp.path().join("binary")).unwrap();
        let permissions = metadata.permissions();
        // setuid bit should be stripped
        assert_eq!(permissions.mode() & 0o7777, 0o755);
    }

    #[test]
    fn test_bytes_written_tracking() {
        let tar_data = create_test_tar(vec![("file1.txt", b"12345"), ("file2.txt", b"67890")]);
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive.extract(temp.path(), &config).unwrap();

        assert_eq!(report.bytes_written, 10);
    }

    #[test]
    fn test_extract_directory_only() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_cksum();
        builder
            .append_data(&mut header, "mydir/", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive.extract(temp.path(), &config).unwrap();

        assert_eq!(report.files_extracted, 0);
        assert_eq!(report.directories_created, 1);
        assert!(temp.path().join("mydir").is_dir());
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_disabled_by_default() {
        let mut builder = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("target.txt").unwrap();
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "link.txt", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default(); // symlinks disabled by default

        let result = archive.extract(temp.path(), &config);

        assert!(result.is_err());
    }

    #[test]
    #[cfg(unix)]
    fn test_hardlink_disabled_by_default() {
        let mut builder = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_link_name("target.txt").unwrap();
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "hardlink.txt", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default(); // hardlinks disabled by default

        let result = archive.extract(temp.path(), &config);

        assert!(result.is_err());
    }

    #[test]
    fn test_extraction_duration_recorded() {
        let tar_data = create_test_tar(vec![("file.txt", b"test")]);
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive.extract(temp.path(), &config).unwrap();

        assert!(report.duration.as_nanos() > 0);
    }

    #[test]
    fn test_path_traversal_via_dotdot_rejected() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);

        // Manually set path with .. (bypassing tar crate validation)
        let path_bytes = b"subdir/../etc/passwd";
        let mut name_field = [0u8; 100];
        name_field[..path_bytes.len()].copy_from_slice(path_bytes);
        header.as_gnu_mut().unwrap().name = name_field;
        header.set_cksum();

        builder.append(&header, &b"evil\n"[..]).unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let result = archive.extract(temp.path(), &config);

        assert!(result.is_err());
        match result {
            Err(ExtractionError::PathTraversal { .. }) => {}
            _ => panic!("Expected PathTraversal error"),
        }
    }

    #[test]
    fn test_absolute_path_rejected() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);

        // Manually set absolute path (bypassing tar crate validation)
        let path_bytes = b"/etc/shadow";
        let mut name_field = [0u8; 100];
        name_field[..path_bytes.len()].copy_from_slice(path_bytes);
        header.as_gnu_mut().unwrap().name = name_field;
        header.set_cksum();

        builder.append(&header, &b"evil\n"[..]).unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let result = archive.extract(temp.path(), &config);

        assert!(result.is_err());
        match result {
            Err(ExtractionError::PathTraversal { .. }) => {}
            _ => panic!("Expected PathTraversal error for absolute path"),
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_escape_rejected() {
        let mut builder = tar::Builder::new(Vec::new());

        // Add directory first
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_cksum();
        builder
            .append_data(&mut header, "subdir/", &[] as &[u8])
            .unwrap();

        // Add symlink in subdir pointing outside extraction directory
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("../../etc/passwd").unwrap();
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "subdir/evil_link.txt", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = true;

        let result = archive.extract(temp.path(), &config);

        assert!(result.is_err());
        match result {
            Err(ExtractionError::SymlinkEscape { .. }) => {}
            other => panic!("Expected SymlinkEscape error for symlink escape, got: {other:?}"),
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_hardlink_target_missing_error() {
        let mut builder = tar::Builder::new(Vec::new());

        // Add hardlink without target file (should fail in second pass)
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_link_name("nonexistent.txt").unwrap();
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "hardlink.txt", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;

        let result = archive.extract(temp.path(), &config);

        assert!(result.is_err());
        match result {
            Err(ExtractionError::InvalidArchive(msg)) => {
                assert!(msg.contains("hardlink target does not exist"));
            }
            _ => panic!("Expected InvalidArchive error for missing hardlink target"),
        }
    }

    // OPT-H001: Test SmallVec stack allocation for hardlinks
    #[test]
    #[cfg(unix)]
    fn test_hardlink_collection_stack_allocation() {
        // Test with 7 hardlinks - should stay on stack (SmallVec<[T; 8]>)
        let mut builder = tar::Builder::new(Vec::new());

        // Add target file
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "target.txt", &b"data\n"[..])
            .unwrap();

        // Add 7 hardlinks (stays on stack)
        for i in 0..7 {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Link);
            header.set_link_name("target.txt").unwrap();
            header.set_size(0);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("link{i}.txt"), &[] as &[u8])
                .unwrap();
        }

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;

        let report = archive.extract(temp.path(), &config).unwrap();

        // 1 target file + 7 hardlinks = 8 files extracted
        assert_eq!(report.files_extracted, 8);
        for i in 0..7 {
            assert!(temp.path().join(format!("link{i}.txt")).exists());
        }
    }

    // OPT-H001: Test SmallVec heap spillover for hardlinks
    #[test]
    #[cfg(unix)]
    fn test_hardlink_collection_heap_spillover() {
        // Test with 20 hardlinks - should spill to heap
        let mut builder = tar::Builder::new(Vec::new());

        // Add target file
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "target.txt", &b"data\n"[..])
            .unwrap();

        // Add 20 hardlinks (spills to heap)
        for i in 0..20 {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Link);
            header.set_link_name("target.txt").unwrap();
            header.set_size(0);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("link{i}.txt"), &[] as &[u8])
                .unwrap();
        }

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;

        let report = archive.extract(temp.path(), &config).unwrap();

        // 1 target file + 20 hardlinks = 21 files extracted
        assert_eq!(report.files_extracted, 21);
        for i in 0..20 {
            assert!(temp.path().join(format!("link{i}.txt")).exists());
        }
    }

    // OPT-H001: Test SmallVec boundary at exactly 8 hardlinks
    #[test]
    #[cfg(unix)]
    fn test_hardlink_collection_boundary() {
        // Test with exactly 8 hardlinks - boundary case
        let mut builder = tar::Builder::new(Vec::new());

        // Add target file
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "target.txt", &b"data\n"[..])
            .unwrap();

        // Add exactly 8 hardlinks (boundary case)
        for i in 0..8 {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Link);
            header.set_link_name("target.txt").unwrap();
            header.set_size(0);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("link{i}.txt"), &[] as &[u8])
                .unwrap();
        }

        let tar_data = builder.into_inner().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;

        let report = archive.extract(temp.path(), &config).unwrap();

        // 1 target file + 8 hardlinks = 9 files extracted
        assert_eq!(report.files_extracted, 9);
        for i in 0..8 {
            assert!(temp.path().join(format!("link{i}.txt")).exists());
        }
    }
}
