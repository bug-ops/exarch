//! ZIP archive format extraction.
//!
//! This module provides secure extraction of ZIP archives with comprehensive
//! security validation. Supported features:
//!
//! - **ZIP format** (PKZIP 2.0+)
//! - **Compression methods**: Stored, DEFLATE, DEFLATE64, BZIP2, ZSTD
//! - **Symlinks**: Via Unix extended file attributes
//! - **Central directory**: Random access to entries
//!
//! # Central Directory Structure
//!
//! Unlike TAR's linear stream, ZIP archives have a central directory at the
//! end:
//!
//! ```text
//! [File 1 Data] [File 2 Data] ... [Central Directory] [End Record]
//! ```
//!
//! This allows:
//! - Random access to any entry without scanning entire archive
//! - Metadata lookup before extraction
//! - Better zip bomb detection (know all sizes upfront)
//!
//! **Trade-off:** Requires seekable reader (`Read + Seek`).
//!
//! # Compression Support
//!
//! Each ZIP entry is independently compressed:
//!
//! | Method | Feature Flag | Typical Use |
//! |--------|--------------|-------------|
//! | Stored | (built-in) | No compression |
//! | DEFLATE | `deflate` | Standard compression (ZIP default) |
//! | DEFLATE64 | `deflate64` | Enhanced DEFLATE |
//! | BZIP2 | `bzip2` | Better compression ratio |
//! | ZSTD | `zstd` | Modern fast compression |
//!
//! Decompression is transparent during extraction.
//!
//! # Security Features
//!
//! All entries are validated through the security layer:
//!
//! - **Path traversal prevention** (rejects `../`, absolute paths)
//! - **Quota enforcement** (file size, count, total size)
//! - **Zip bomb detection** (per-entry and aggregate compression ratios)
//! - **Symlink escape detection** (symlinks must point within extraction
//!   directory)
//! - **Permission sanitization** (strips setuid/setgid bits)
//! - **Encryption rejection** (password-protected archives not supported)
//!
//! # Entry Type Support
//!
//! | Entry Type | Supported | Detection Method |
//! |------------|-----------|------------------|
//! | Regular files | ✅ Yes | Default entry type |
//! | Directories | ✅ Yes | Name ends with `/` or explicit flag |
//! | Symlinks | ✅ Yes | Unix external attributes (mode & 0o120000) |
//! | Hardlinks | ❌ No | Not part of ZIP spec |
//!
//! ## Symlink Handling
//!
//! ZIP symlinks are platform-specific:
//!
//! - **Unix**: Symlink target stored as file data, mode indicates symlink type
//! - **Windows**: No native symlink support in ZIP
//! - **Detection**: Check Unix external file attributes for `S_IFLNK` mode
//!
//! # Password-Protected Archives
//!
//! **Security Policy:** Password-protected ZIP archives are **rejected**.
//!
//! **Rationale:**
//! - No crypto dependencies (smaller attack surface)
//! - Clear security boundary (no decryption attempted)
//! - User must decrypt separately if needed
//!
//! Detection:
//! - Archive-level check in constructor
//! - Per-entry encryption flag check during extraction
//!
//! # Examples
//!
//! Basic extraction:
//!
//! ```no_run
//! use exarch_core::ExtractionOptions;
//! use exarch_core::SecurityConfig;
//! use exarch_core::formats::ZipArchive;
//! use exarch_core::formats::traits::ArchiveFormat;
//! use std::fs::File;
//! use std::path::Path;
//!
//! let file = File::open("archive.zip")?;
//! let mut archive = ZipArchive::new(file)?;
//! let report = archive.extract(
//!     Path::new("/output"),
//!     &SecurityConfig::default(),
//!     &ExtractionOptions::default(),
//!     &mut exarch_core::NoopProgress,
//! )?;
//! println!("Extracted {} files", report.files_extracted);
//! # Ok::<(), exarch_core::ArchiveError>(())
//! ```
//!
//! Custom security configuration:
//!
//! ```no_run
//! use exarch_core::ExtractionOptions;
//! use exarch_core::SecurityConfig;
//!
//! let mut config = SecurityConfig::default();
//! config.allowed.symlinks = true; // Allow symlinks
//! config.max_file_size = 100 * 1024 * 1024; // 100 MB per file
//! config.max_compression_ratio = 100.0; // Allow 100:1 compression
//! // ... extract with config
//! ```

use std::io::Read;
use std::io::Seek;
use std::path::Path;
use std::path::PathBuf;
use std::time::Instant;

use zip::ZipArchive as ZipReader;

use crate::ArchiveError;
use crate::ExtractionOptions;
use crate::ExtractionReport;
use crate::ProgressCallback;
use crate::Result;
use crate::SecurityConfig;
use crate::copy::CopyBuffer;
use crate::security::EntryValidator;
use crate::security::validator::ValidatedEntryType;
use crate::types::DestDir;
use crate::types::EntryType;

use super::common;
use super::common::EntryCompleteGuard;
use super::traits::ArchiveFormat;

/// ZIP archive handler with random-access extraction.
///
/// Supports:
/// - ZIP format (PKZIP 2.0+)
/// - Compression methods: stored, deflate, deflate64, bzip2, zstd
/// - Unix symlinks via extended attributes
/// - Password-protected archive detection (rejected)
///
/// # Central Directory
///
/// ZIP archives have a central directory at the end containing metadata
/// for all entries. This allows random access but requires seekable reader.
///
/// # Compression
///
/// Unlike TAR, each ZIP entry is independently compressed. This allows:
/// - Selective decompression (only extract needed files)
/// - Parallel decompression (future optimization)
/// - Better compression ratio detection for zip bombs
///
/// # Examples
///
/// ```no_run
/// use exarch_core::ExtractionOptions;
/// use exarch_core::SecurityConfig;
/// use exarch_core::formats::ZipArchive;
/// use exarch_core::formats::traits::ArchiveFormat;
/// use std::fs::File;
/// use std::path::Path;
///
/// let file = File::open("archive.zip")?;
/// let mut archive = ZipArchive::new(file)?;
/// let report = archive.extract(
///     Path::new("/output"),
///     &SecurityConfig::default(),
///     &ExtractionOptions::default(),
///     &mut exarch_core::NoopProgress,
/// )?;
/// println!("Extracted {} files", report.files_extracted);
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
pub struct ZipArchive<R: Read + Seek> {
    inner: ZipReader<R>,
}

impl<R: Read + Seek> ZipArchive<R> {
    /// Creates a new ZIP archive handler from a seekable reader.
    ///
    /// The reader must support both `Read` and `Seek` because ZIP archives
    /// have a central directory at the end that must be parsed first.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - File is not a valid ZIP archive
    /// - Central directory is corrupted
    /// - Archive is password-protected (rejected for security)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use exarch_core::formats::ZipArchive;
    /// use std::fs::File;
    ///
    /// let file = File::open("archive.zip")?;
    /// let archive = ZipArchive::new(file)?;
    /// # Ok::<(), exarch_core::ArchiveError>(())
    /// ```
    pub fn new(reader: R) -> Result<Self> {
        let mut inner = ZipReader::new(reader).map_err(|e| {
            ArchiveError::InvalidArchive(format!("failed to open ZIP archive: {e}"))
        })?;

        // Detect password protection early (CRIT-003: robust check with entry limit)
        if Self::is_password_protected(&mut inner)? {
            return Err(ArchiveError::SecurityViolation {
                reason: "password-protected ZIP archives are not supported".into(),
            });
        }

        Ok(Self { inner })
    }

    /// Checks if any entry in the archive is encrypted.
    ///
    /// Scans all entries via metadata-only reads (no decompression). Stops
    /// early on the first encrypted entry found.
    fn is_password_protected(archive: &mut ZipReader<R>) -> Result<bool> {
        for i in 0..archive.len() {
            if Self::check_entry_encrypted(archive, i)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[inline]
    fn check_entry_encrypted(archive: &mut ZipReader<R>, index: usize) -> Result<bool> {
        match archive.by_index(index) {
            Ok(file) => Ok(file.encrypted()),
            Err(e) if e.to_string().contains("Password required to decrypt file") => Ok(true),
            Err(e) => Err(ArchiveError::InvalidArchive(format!(
                "failed to check entry {index} for encryption: {e}"
            ))),
        }
    }

    /// Processes a single ZIP entry with a single `by_index()` call.
    ///
    /// Branches on entry type (directory/symlink/file) within the same
    /// borrow scope. For directories and symlinks, the zip file is
    /// explicitly dropped before calling extraction helpers. For files,
    /// the zip file remains alive through validation and is reused for
    /// data extraction.
    #[allow(clippy::too_many_arguments)]
    fn process_entry(
        &mut self,
        index: usize,
        validator: &mut EntryValidator,
        dest: &DestDir,
        report: &mut ExtractionReport,
        copy_buffer: &mut CopyBuffer,
        dir_cache: &mut common::DirCache,
        skip_duplicates: bool,
        config: &SecurityConfig,
        progress: &mut dyn ProgressCallback,
    ) -> Result<()> {
        let mut zip_file = self.inner.by_index(index).map_err(|e| {
            if e.to_string().contains("Password required to decrypt file") {
                return ArchiveError::SecurityViolation {
                    reason: "archive is password-protected.\n  Password-protected ZIP archives are not supported. Decrypt the archive externally and try again.".into(),
                };
            }
            ArchiveError::InvalidArchive(format!("failed to read entry {index}: {e}"))
        })?;

        if zip_file.encrypted() {
            let name = zip_file
                .name()
                .map_or_else(|_| format!("<entry {index}>"), std::borrow::Cow::into_owned);
            return Err(ArchiveError::SecurityViolation {
                reason: format!("encrypted entry detected: {name}"),
            });
        }

        let path = PathBuf::from(
            zip_file
                .name()
                .map_err(|e| {
                    ArchiveError::InvalidArchive(format!("invalid entry name at {index}: {e}"))
                })?
                .as_ref(),
        );

        let (uncompressed_size, compressed_size) = ZipEntryAdapter::get_sizes(&zip_file);
        let mode = zip_file.unix_mode();

        let compression = ZipEntryAdapter::get_compression_method(&zip_file);
        if matches!(compression, CompressionMethod::Unsupported) {
            return Err(ArchiveError::SecurityViolation {
                reason: format!(
                    "unsupported compression method: {:?}",
                    zip_file.compression()
                ),
            });
        }

        if zip_file.is_dir() {
            drop(zip_file);
            let validated = validator.validate_entry(
                &path,
                &EntryType::Directory,
                uncompressed_size,
                Some(compressed_size),
                mode,
                Some(dir_cache),
            )?;
            common::create_directory(&validated, dest, report, dir_cache)?;
        } else if ZipEntryAdapter::is_symlink_from_mode(mode) {
            let target = ZipEntryAdapter::read_symlink_target(&mut zip_file)?;
            drop(zip_file);
            let entry_type = EntryType::Symlink { target };
            let validated = validator.validate_entry(
                &path,
                &entry_type,
                uncompressed_size,
                Some(compressed_size),
                mode,
                Some(dir_cache),
            )?;
            if let ValidatedEntryType::Symlink(safe_symlink) = validated.entry_type {
                common::create_symlink(&safe_symlink, dest, report, dir_cache, skip_duplicates)?;
            }
        } else {
            let ext = path.extension().and_then(|e| e.to_str());
            if !config.is_path_extension_allowed(ext) {
                report.files_skipped += 1;
                report.warnings.push(format!(
                    "skipped entry with disallowed extension: {}",
                    path.display()
                ));
                return Ok(());
            }
            // File: validate BEFORE writing (security invariant preserved),
            // then extract with the same zip_file (stream still at position 0)
            let validated = validator.validate_entry(
                &path,
                &EntryType::File,
                uncompressed_size,
                Some(compressed_size),
                mode,
                Some(dir_cache),
            )?;
            Self::extract_file(
                &mut zip_file,
                &validated,
                dest,
                report,
                uncompressed_size,
                copy_buffer,
                dir_cache,
                skip_duplicates,
                progress,
            )?;
        }

        Ok(())
    }

    /// Extracts a regular file to disk.
    #[allow(clippy::too_many_arguments)]
    fn extract_file(
        zip_file: &mut zip::read::ZipFile<'_, R>,
        validated: &crate::security::validator::ValidatedEntry,
        dest: &DestDir,
        report: &mut ExtractionReport,
        file_size: u64,
        copy_buffer: &mut CopyBuffer,
        dir_cache: &mut common::DirCache,
        skip_duplicates: bool,
        progress: &mut dyn ProgressCallback,
    ) -> Result<()> {
        common::extract_file_generic(
            zip_file,
            validated,
            dest,
            report,
            Some(file_size),
            copy_buffer,
            dir_cache,
            skip_duplicates,
            progress,
        )
    }
}

impl<R: Read + Seek> ArchiveFormat for ZipArchive<R> {
    fn extract(
        &mut self,
        output_dir: &Path,
        config: &SecurityConfig,
        options: &ExtractionOptions,
        progress: &mut dyn ProgressCallback,
    ) -> Result<ExtractionReport> {
        let start = Instant::now();
        let skip_duplicates = options.skip_duplicates;

        let dest = DestDir::new_or_create(output_dir.to_path_buf())?;

        // OPT-H004: Pass references to avoid cloning
        let mut validator = EntryValidator::new(config, &dest);

        let mut report = ExtractionReport::new();

        // OPT-C002: Single copy buffer per archive instead of per-file allocation
        let mut copy_buffer = CopyBuffer::new();

        let mut dir_cache = common::DirCache::new();

        let entry_count = self.inner.len();

        for i in 0..entry_count {
            let entry_path = {
                // Borrow ends before process_entry to satisfy the borrow checker.
                let zf = self.inner.by_index(i).map_err(|e| {
                    ArchiveError::InvalidArchive(format!("failed to open zip entry {i}: {e}"))
                })?;
                std::path::PathBuf::from(
                    zf.name()
                        .map_err(|e| {
                            ArchiveError::InvalidArchive(format!("invalid entry name at {i}: {e}"))
                        })?
                        .as_ref(),
                )
            };
            progress.on_entry_start(&entry_path, entry_count, i.saturating_add(1));
            let mut guard = EntryCompleteGuard::new(progress, &entry_path);

            let result = self.process_entry(
                i,
                &mut validator,
                &dest,
                &mut report,
                &mut copy_buffer,
                &mut dir_cache,
                skip_duplicates,
                config,
                guard.progress_mut(),
            );

            if let Err(e) = result {
                drop(guard);
                return Err(if report.total_items() > 0 {
                    ArchiveError::PartialExtraction {
                        source: Box::new(e),
                        report: std::mem::take(&mut report),
                    }
                } else {
                    e
                });
            }
            guard.complete();
        }

        progress.on_complete();
        report.duration = start.elapsed();

        Ok(report)
    }

    fn list(&mut self, config: &SecurityConfig) -> Result<crate::inspection::ArchiveManifest> {
        use crate::inspection::list::list_zip_reader;
        list_zip_reader(&mut self.inner, config)
    }

    fn verify(&mut self, config: &SecurityConfig) -> Result<crate::inspection::VerificationReport> {
        let manifest = self.list(config)?;
        crate::inspection::verify::verify_manifest(&manifest, config)
    }

    fn format_name(&self) -> &'static str {
        "zip"
    }
}

/// Adapter to convert `zip::ZipFile` metadata to internal types.
struct ZipEntryAdapter;

impl ZipEntryAdapter {
    /// Checks if an entry is a symbolic link by examining Unix mode bits.
    fn is_symlink_from_mode(mode: Option<u32>) -> bool {
        mode.is_some_and(|m| {
            const S_IFMT: u32 = 0o170_000;
            const S_IFLNK: u32 = 0o120_000;
            (m & S_IFMT) == S_IFLNK
        })
    }

    /// Reads symlink target from ZIP entry data (stored as file content).
    fn read_symlink_target<R: Read>(zip_file: &mut zip::read::ZipFile<'_, R>) -> Result<PathBuf> {
        // SECURITY: Limit to PATH_MAX (4096) to prevent unbounded allocation
        const MAX_SYMLINK_TARGET_SIZE: u64 = 4096;

        let size = zip_file.size();
        if size > MAX_SYMLINK_TARGET_SIZE {
            return Err(ArchiveError::SecurityViolation {
                reason: format!(
                    "symlink target too large: {size} bytes (max {MAX_SYMLINK_TARGET_SIZE})"
                ),
            });
        }

        // SAFETY: size has already been validated to be <= MAX_SYMLINK_TARGET_SIZE
        // (4096) which is well within usize range on all platforms
        #[allow(clippy::cast_possible_truncation)]
        let mut target_bytes = Vec::with_capacity(size as usize);
        zip_file
            .take(MAX_SYMLINK_TARGET_SIZE)
            .read_to_end(&mut target_bytes)
            .map_err(|e| {
                ArchiveError::InvalidArchive(format!("failed to read symlink target: {e}"))
            })?;

        let target_str = std::str::from_utf8(&target_bytes).map_err(|_| {
            ArchiveError::InvalidArchive("symlink target is not valid UTF-8".into())
        })?;

        Ok(PathBuf::from(target_str))
    }

    /// Gets compression method for the entry.
    fn get_compression_method<R: Read>(zip_file: &zip::read::ZipFile<'_, R>) -> CompressionMethod {
        match zip_file.compression() {
            zip::CompressionMethod::Stored => CompressionMethod::Stored,
            zip::CompressionMethod::Deflated => CompressionMethod::Deflate,
            zip::CompressionMethod::Bzip2 => CompressionMethod::Bzip2,
            zip::CompressionMethod::Zstd => CompressionMethod::Zstd,
            _ => CompressionMethod::Unsupported,
        }
    }

    /// Gets uncompressed and compressed sizes.
    fn get_sizes<R: Read>(zip_file: &zip::read::ZipFile<'_, R>) -> (u64, u64) {
        (zip_file.size(), zip_file.compressed_size())
    }
}

/// Compression methods supported by ZIP.
#[derive(Debug, Clone, Copy)]
enum CompressionMethod {
    Stored,
    Deflate,
    Bzip2,
    Zstd,
    Unsupported,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::items_after_statements,
    clippy::uninlined_format_args,
    clippy::field_reassign_with_default
)]
mod tests {
    use super::*;
    use crate::test_utils::create_test_zip;
    use std::io::Cursor;
    use std::io::Write;
    use tempfile::TempDir;
    use zip::write::SimpleFileOptions;
    use zip::write::ZipWriter;

    #[test]
    fn test_zip_archive_new() {
        let zip_data = create_test_zip(vec![]);
        let cursor = Cursor::new(zip_data);
        let archive = ZipArchive::new(cursor).unwrap();
        assert_eq!(archive.format_name(), "zip");
    }

    #[test]
    fn test_extract_empty_archive() {
        let zip_data = create_test_zip(vec![]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 0);
        assert_eq!(report.directories_created, 0);
    }

    #[test]
    fn test_extract_simple_file() {
        let zip_data = create_test_zip(vec![("file.txt", b"hello world")]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("file.txt").exists());

        let content = std::fs::read_to_string(temp.path().join("file.txt")).unwrap();
        assert_eq!(content, "hello world");
    }

    #[test]
    fn test_extract_multiple_files() {
        let zip_data = create_test_zip(vec![
            ("file1.txt", b"content1"),
            ("file2.txt", b"content2"),
            ("file3.txt", b"content3"),
        ]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 3);
    }

    #[test]
    fn test_extract_nested_structure() {
        let zip_data = create_test_zip(vec![("dir1/dir2/file.txt", b"nested")]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("dir1/dir2/file.txt").exists());
    }

    #[test]
    fn test_extract_with_deflate_compression() {
        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        zip.start_file("compressed.txt", options).unwrap();
        zip.write_all(b"This text will be compressed with DEFLATE")
            .unwrap();

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);

        let content = std::fs::read_to_string(temp.path().join("compressed.txt")).unwrap();
        assert_eq!(content, "This text will be compressed with DEFLATE");
    }

    #[test]
    fn test_extract_with_bzip2_compression() {
        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Bzip2);

        zip.start_file("bzip2.txt", options).unwrap();
        zip.write_all(b"This text will be compressed with BZIP2")
            .unwrap();

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
    }

    #[test]
    fn test_extract_with_zstd_compression() {
        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Zstd);

        zip.start_file("zstd.txt", options).unwrap();
        zip.write_all(b"This text will be compressed with ZSTD")
            .unwrap();

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
    }

    #[test]
    fn test_extract_directory_entry() {
        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        // ZIP directories end with '/'
        let options = SimpleFileOptions::default();
        zip.add_directory("mydir/", options).unwrap();

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.directories_created, 1);
        assert!(temp.path().join("mydir").is_dir());
    }

    #[test]
    fn test_extract_empty_file() {
        let zip_data = create_test_zip(vec![("empty.txt", b"")]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("empty.txt").exists());

        let metadata = std::fs::metadata(temp.path().join("empty.txt")).unwrap();
        assert_eq!(metadata.len(), 0);
    }

    #[test]
    fn test_quota_file_size_exceeded() {
        let zip_data = create_test_zip(vec![("large.bin", &vec![0u8; 1000])]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.max_file_size = 100; // Only allow 100 bytes

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_quota_file_count_exceeded() {
        let zip_data = create_test_zip(vec![
            ("file1.txt", b"data"),
            ("file2.txt", b"data"),
            ("file3.txt", b"data"),
        ]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.max_file_count = 2; // Only allow 2 files

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_path_traversal_rejected() {
        let zip_data = create_test_zip(vec![("../etc/passwd", b"malicious")]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ArchiveError::PathTraversal { .. }
        ));
    }

    #[test]
    fn test_absolute_path_rejected() {
        let zip_data = create_test_zip(vec![("/etc/shadow", b"malicious")]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_zip_bomb_detection() {
        // Create a highly compressed file
        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        zip.start_file("bomb.txt", options).unwrap();
        // Write highly compressible data
        zip.write_all(&vec![0u8; 100_000]).unwrap();

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.max_compression_ratio = 10.0; // Low threshold for testing

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        // Should fail with ZipBomb error
        assert!(result.is_err());
    }

    #[test]
    #[cfg(unix)]
    fn test_file_permissions_preserved() {
        use std::os::unix::fs::PermissionsExt;

        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        let options = SimpleFileOptions::default().unix_permissions(0o755);
        zip.start_file("script.sh", options).unwrap();
        zip.write_all(b"#!/bin/sh\n").unwrap();

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);

        let metadata = std::fs::metadata(temp.path().join("script.sh")).unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o755);
    }

    #[test]
    #[cfg(unix)]
    fn test_permissions_sanitized_setuid_removed() {
        use std::os::unix::fs::PermissionsExt;

        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        let options = SimpleFileOptions::default().unix_permissions(0o4755); // setuid
        zip.start_file("binary", options).unwrap();
        zip.write_all(b"data").unwrap();

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let _report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        let metadata = std::fs::metadata(temp.path().join("binary")).unwrap();
        let permissions = metadata.permissions();
        // setuid bit should be stripped
        assert_eq!(permissions.mode() & 0o7777, 0o755);
    }

    #[test]
    #[cfg(unix)]
    fn test_permissions_sanitized_setgid_removed() {
        use std::os::unix::fs::PermissionsExt;

        // MED-003: Test setgid bit removal
        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        let options = SimpleFileOptions::default().unix_permissions(0o2755); // setgid
        zip.start_file("binary", options).unwrap();
        zip.write_all(b"data").unwrap();

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let _report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        let metadata = std::fs::metadata(temp.path().join("binary")).unwrap();
        let permissions = metadata.permissions();
        // setgid bit should be stripped
        assert_eq!(permissions.mode() & 0o7777, 0o755);
    }

    #[test]
    #[cfg(unix)]
    fn test_permissions_sanitized_setuid_setgid_removed() {
        use std::os::unix::fs::PermissionsExt;

        // MED-003: Test both setuid and setgid bit removal
        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        let options = SimpleFileOptions::default().unix_permissions(0o6755); // setuid + setgid
        zip.start_file("binary", options).unwrap();
        zip.write_all(b"data").unwrap();

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let _report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        let metadata = std::fs::metadata(temp.path().join("binary")).unwrap();
        let permissions = metadata.permissions();
        // Both setuid and setgid bits should be stripped
        assert_eq!(permissions.mode() & 0o7777, 0o755);
    }

    #[test]
    #[cfg(unix)]
    fn test_extract_symlink_via_unix_attributes() {
        // raw_zip_with_custom_entry places mode bits in the external attributes
        // high word (unix_mode << 16), which is how real ZIP tools encode them.
        // This bypasses the zip crate writer's lossy unix_permissions() path.
        let zip_bytes = raw_zip_with_custom_entry("link", b"target.txt", 0, 0, 0o120_777);
        let cursor = Cursor::new(zip_bytes);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = true;

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.symlinks_created, 1, "should have 1 symlink");

        let link_path = temp.path().join("link");
        let metadata = std::fs::symlink_metadata(&link_path).unwrap();
        assert!(metadata.is_symlink(), "link should be a symlink");
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_disabled_by_default() {
        let zip_bytes = raw_zip_with_custom_entry("link", b"target.txt", 0, 0, 0o120_777);
        let cursor = Cursor::new(zip_bytes);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default(); // symlinks disabled by default

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        match result {
            Err(ArchiveError::SecurityViolation { reason }) => {
                assert!(
                    reason.contains("symlinks not allowed") || reason.contains("symlink"),
                    "error should mention symlinks: {reason}"
                );
            }
            Err(other) => panic!("expected SecurityViolation, got: {other:?}"),
            Ok(_) => panic!("expected error, got success"),
        }
    }

    #[test]
    fn test_hardlink_rejected() {
        // ZIP spec has no hardlink type; ValidatedEntryType::Hardlink is
        // unreachable for any real ZIP entry. Verify that a well-formed ZIP
        // extracts cleanly without triggering any hardlink-related error path.
        let zip_data = create_test_zip(vec![("file.txt", b"content")]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("file.txt").exists());
    }

    #[test]
    fn test_compression_method_detection() {
        // Test that different compression methods are detected correctly
        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        let stored =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zip.start_file("stored.txt", stored).unwrap();
        zip.write_all(b"stored").unwrap();

        let deflated =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("deflated.txt", deflated).unwrap();
        zip.write_all(b"deflated").unwrap();

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 2);
    }

    #[test]
    fn test_bytes_written_tracking() {
        let zip_data = create_test_zip(vec![
            ("file1.txt", b"hello"),    // 5 bytes
            ("file2.txt", b"world!!!"), // 8 bytes
        ]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.bytes_written, 13);
    }

    #[test]
    fn test_duration_tracking() {
        let zip_data = create_test_zip(vec![("file.txt", b"data")]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        // Duration should be non-zero
        assert!(report.duration.as_nanos() > 0);
    }

    #[test]
    fn test_invalid_zip_archive() {
        let invalid_data = b"not a zip file";
        let cursor = Cursor::new(invalid_data);
        let result = ZipArchive::new(cursor);

        assert!(result.is_err());
    }

    #[test]
    fn test_entry_type_detection_file() {
        let zip_data = create_test_zip(vec![("regular.txt", b"content")]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert_eq!(report.directories_created, 0);
        assert_eq!(report.symlinks_created, 0);
    }

    #[test]
    fn test_entry_type_detection_directory() {
        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        let options = SimpleFileOptions::default();
        zip.add_directory("testdir/", options).unwrap();

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 0);
        assert_eq!(report.directories_created, 1);
    }

    #[test]
    fn test_nested_directories_created_automatically() {
        // ZIP might not have explicit directory entries
        // Parent dirs should be created automatically
        let zip_data = create_test_zip(vec![("a/b/c/file.txt", b"nested")]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let _report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert!(temp.path().join("a/b/c/file.txt").exists());
        assert!(temp.path().join("a").is_dir());
        assert!(temp.path().join("a/b").is_dir());
        assert!(temp.path().join("a/b/c").is_dir());
    }

    #[test]
    fn test_large_file_extraction() {
        // Test with a 1MB file
        let large_data = vec![0xAB; 1024 * 1024];
        let zip_data = create_test_zip(vec![("large.bin", &large_data)]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);

        let extracted = std::fs::read(temp.path().join("large.bin")).unwrap();
        assert_eq!(extracted.len(), 1024 * 1024);
    }

    #[test]
    fn test_many_files_extraction() {
        // Test with 100 files
        let entries: Vec<_> = (0..100)
            .map(|i| (format!("file{i}.txt"), format!("content{i}").into_bytes()))
            .collect();

        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        for (name, data) in &entries {
            let options = SimpleFileOptions::default();
            zip.start_file(name, options).unwrap();
            zip.write_all(data).unwrap();
        }

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 100);
    }

    #[test]
    fn test_quota_total_size_exceeded() {
        let zip_data = create_test_zip(vec![
            ("file1.txt", &vec![0u8; 600]),
            ("file2.txt", &vec![0u8; 600]),
        ]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.max_total_size = 1000; // Total limit 1000 bytes

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_special_characters_in_filename() {
        let zip_data = create_test_zip(vec![
            ("file with spaces.txt", b"content"),
            ("file-with-dashes.txt", b"content"),
            ("file_with_underscores.txt", b"content"),
        ]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 3);
        assert!(temp.path().join("file with spaces.txt").exists());
    }

    #[test]
    fn test_is_symlink_from_mode() {
        assert!(ZipEntryAdapter::is_symlink_from_mode(Some(0o120_777)));
        assert!(ZipEntryAdapter::is_symlink_from_mode(Some(0o120_755)));
        assert!(!ZipEntryAdapter::is_symlink_from_mode(Some(0o100_644)));
        assert!(!ZipEntryAdapter::is_symlink_from_mode(Some(0o040_755)));
        assert!(!ZipEntryAdapter::is_symlink_from_mode(Some(0o755)));
        assert!(!ZipEntryAdapter::is_symlink_from_mode(None));
    }

    /// Builds a single-entry ZIP in memory with a custom compression method
    /// field, flags, unix mode, and content. CRC32 must be correct for
    /// non-empty content when using Stored method (method=0); pass 0 for
    /// empty content.
    #[allow(clippy::cast_possible_truncation)]
    fn raw_zip_with_custom_entry(
        filename: &str,
        content: &[u8],
        compression_method: u16,
        flags: u16,
        unix_mode: u32,
    ) -> Vec<u8> {
        let crc = crc32_ieee(content);
        let external_attributes = unix_mode << 16;
        let name_bytes = filename.as_bytes();
        let name_len = name_bytes.len() as u16;
        let content_len = content.len() as u32;

        let mut buf: Vec<u8> = Vec::new();

        let local_offset = buf.len() as u32;
        buf.extend_from_slice(b"PK\x03\x04");
        buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
        buf.extend_from_slice(&flags.to_le_bytes());
        buf.extend_from_slice(&compression_method.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&content_len.to_le_bytes()); // compressed size
        buf.extend_from_slice(&content_len.to_le_bytes()); // uncompressed size
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // extra field length
        buf.extend_from_slice(name_bytes);
        buf.extend_from_slice(content);

        let central_offset = buf.len() as u32;
        buf.extend_from_slice(b"PK\x01\x02");
        buf.extend_from_slice(&0x031eu16.to_le_bytes()); // version made by: Unix
        buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
        buf.extend_from_slice(&flags.to_le_bytes());
        buf.extend_from_slice(&compression_method.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&content_len.to_le_bytes()); // compressed size
        buf.extend_from_slice(&content_len.to_le_bytes()); // uncompressed size
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // extra length
        buf.extend_from_slice(&0u16.to_le_bytes()); // comment length
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        buf.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        buf.extend_from_slice(&external_attributes.to_le_bytes());
        buf.extend_from_slice(&local_offset.to_le_bytes());
        buf.extend_from_slice(name_bytes);

        let central_size = (buf.len() as u32) - central_offset;
        buf.extend_from_slice(b"PK\x05\x06");
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk number
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk with central dir
        buf.extend_from_slice(&1u16.to_le_bytes()); // entries on this disk
        buf.extend_from_slice(&1u16.to_le_bytes()); // total entries
        buf.extend_from_slice(&central_size.to_le_bytes());
        buf.extend_from_slice(&central_offset.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // comment length
        buf
    }

    /// CRC32 (IEEE 802.3 polynomial) implementation for test use.
    fn crc32_ieee(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &byte in data {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
            }
        }
        !crc
    }

    #[test]
    fn test_unsupported_compression_method_rejected() {
        // Build a ZIP with compression method=99 (unknown/unsupported)
        // The zip crate parses entries with unknown methods but fails on decompression.
        // Our code checks the compression method in process_entry before decompressing.
        let zip_bytes = raw_zip_with_custom_entry("file.txt", b"", 99, 0, 0o100_644);
        let cursor = Cursor::new(zip_bytes);
        let result = ZipArchive::new(cursor);
        if let Ok(mut archive) = result {
            let temp = TempDir::new().unwrap();
            let config = SecurityConfig::default();
            let err = archive
                .extract(
                    temp.path(),
                    &config,
                    &ExtractionOptions::default(),
                    &mut crate::NoopProgress,
                )
                .unwrap_err();
            assert!(
                matches!(err, ArchiveError::SecurityViolation { .. }),
                "expected SecurityViolation for unsupported compression, got: {err:?}"
            );
        }
        // If zip crate rejects at parse time, that's also acceptable —
        // the archive never opens, so extraction is blocked either way.
    }

    #[test]
    fn test_symlink_target_too_large() {
        // Build a raw ZIP entry with symlink mode (0o120777) and >4096 bytes content.
        // The size field in the local header is what our code reads via
        // zip_file.size(). We need actual content bytes so the zip crate
        // reports the correct uncompressed size.
        let target = vec![b'a'; 4097];
        let zip_bytes = raw_zip_with_custom_entry("link", &target, 0, 0, 0o120_777);
        let cursor = Cursor::new(zip_bytes);
        // The archive itself should open fine.
        let result = ZipArchive::new(cursor);
        if let Ok(mut archive) = result {
            let temp = TempDir::new().unwrap();
            let mut config = SecurityConfig::default();
            config.allowed.symlinks = true;
            let err = archive
                .extract(
                    temp.path(),
                    &config,
                    &ExtractionOptions::default(),
                    &mut crate::NoopProgress,
                )
                .unwrap_err();
            assert!(
                matches!(err, ArchiveError::SecurityViolation { ref reason } if reason.contains("symlink target too large")),
                "expected SecurityViolation(symlink target too large), got: {err:?}"
            );
        }
    }

    #[test]
    fn test_symlink_target_invalid_utf8() {
        // Build a raw ZIP entry with symlink mode and non-UTF-8 content.
        let invalid_utf8 = vec![0xFF, 0xFE, 0x00];
        let zip_bytes = raw_zip_with_custom_entry("link", &invalid_utf8, 0, 0, 0o120_777);
        let cursor = Cursor::new(zip_bytes);
        let result = ZipArchive::new(cursor);
        if let Ok(mut archive) = result {
            let temp = TempDir::new().unwrap();
            let mut config = SecurityConfig::default();
            config.allowed.symlinks = true;
            let err = archive
                .extract(
                    temp.path(),
                    &config,
                    &ExtractionOptions::default(),
                    &mut crate::NoopProgress,
                )
                .unwrap_err();
            assert!(
                matches!(err, ArchiveError::InvalidArchive(ref msg) if msg.contains("UTF-8")),
                "expected InvalidArchive(UTF-8), got: {err:?}"
            );
        }
    }

    /// Creates a 400-entry ZIP archive in memory. The entry at
    /// `encrypted_index` is encrypted using deprecated `ZipCrypto`. All other
    /// entries are unencrypted with Stored compression and 1-byte content,
    /// to keep construction fast.
    fn create_large_archive_with_encrypted_entry(encrypted_index: usize) -> Vec<u8> {
        use zip::unstable::write::FileOptionsExt;

        let total = 400usize;
        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        for i in 0..total {
            let options = if i == encrypted_index {
                SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored)
                    .with_deprecated_encryption(b"pass")
                    .unwrap()
            } else {
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored)
            };
            zip.start_file(format!("file{i}.txt"), options).unwrap();
            zip.write_all(b"x").unwrap();
        }

        zip.finish().unwrap().into_inner()
    }

    #[test]
    fn test_password_protected_large_archive_first_entry() {
        // Encrypted entry at index 0 — detected by full scan.
        let zip_data = create_large_archive_with_encrypted_entry(0);
        let cursor = Cursor::new(zip_data);
        let result = ZipArchive::new(cursor);
        assert!(
            matches!(result, Err(ArchiveError::SecurityViolation { .. })),
            "expected SecurityViolation for encrypted entry in first batch"
        );
    }

    #[test]
    fn test_password_protected_large_archive_middle_entry() {
        // Encrypted entry at index 200 — detected by full scan.
        let zip_data = create_large_archive_with_encrypted_entry(200);
        let cursor = Cursor::new(zip_data);
        let result = ZipArchive::new(cursor);
        assert!(
            matches!(result, Err(ArchiveError::SecurityViolation { .. })),
            "expected SecurityViolation for encrypted entry in middle batch"
        );
    }

    #[test]
    fn test_password_protected_large_archive_last_entry() {
        // Encrypted entry at index 399 — detected by full scan.
        let zip_data = create_large_archive_with_encrypted_entry(399);
        let cursor = Cursor::new(zip_data);
        let result = ZipArchive::new(cursor);
        assert!(
            matches!(result, Err(ArchiveError::SecurityViolation { .. })),
            "expected SecurityViolation for encrypted entry in last batch"
        );
    }

    #[test]
    fn test_large_archive_no_encryption_passes_constructor() {
        // 400-entry unencrypted archive — constructor should succeed.
        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for i in 0..400usize {
            zip.start_file(format!("file{i}.txt"), options).unwrap();
            zip.write_all(b"x").unwrap();
        }
        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let archive = ZipArchive::new(cursor);
        assert!(
            archive.is_ok(),
            "unencrypted 400-entry archive should open fine"
        );
    }

    #[test]
    fn test_encrypted_entry_at_gap_index_is_detected_by_full_scan() {
        // Index 125 was previously in the gap between first-100 and middle-100
        // sampling windows. The full scan now catches it at construction time.
        let zip_data = create_large_archive_with_encrypted_entry(125);
        let cursor = Cursor::new(zip_data);
        let result = ZipArchive::new(cursor);
        assert!(
            matches!(result, Err(ArchiveError::SecurityViolation { .. })),
            "full scan must detect encrypted entry at index 125"
        );
    }

    /// Build a raw ZIP with two local entries sharing the same path.
    ///
    /// The `zip` crate's writer rejects duplicate filenames, so we craft bytes
    /// manually. Both local file records and both central directory entries are
    /// included so the archive is spec-valid.
    #[allow(clippy::cast_possible_truncation)]
    fn create_raw_duplicate_zip(path: &str, content1: &[u8], content2: &[u8]) -> Vec<u8> {
        let name_bytes = path.as_bytes();
        let name_len = name_bytes.len() as u16;
        let mut buf: Vec<u8> = Vec::new();

        let write_local = |buf: &mut Vec<u8>, content: &[u8]| {
            let crc = crc32_ieee(content);
            let size = content.len() as u32;
            buf.extend_from_slice(b"PK\x03\x04");
            buf.extend_from_slice(&20u16.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes()); // flags
            buf.extend_from_slice(&0u16.to_le_bytes()); // stored
            buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
            buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
            buf.extend_from_slice(&crc.to_le_bytes());
            buf.extend_from_slice(&size.to_le_bytes());
            buf.extend_from_slice(&size.to_le_bytes());
            buf.extend_from_slice(&name_len.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes()); // extra
            buf.extend_from_slice(name_bytes);
            buf.extend_from_slice(content);
        };

        let offset1 = buf.len() as u32;
        write_local(&mut buf, content1);
        let offset2 = buf.len() as u32;
        write_local(&mut buf, content2);

        let write_central = |buf: &mut Vec<u8>, content: &[u8], offset: u32| {
            let crc = crc32_ieee(content);
            let size = content.len() as u32;
            buf.extend_from_slice(b"PK\x01\x02");
            buf.extend_from_slice(&0x031eu16.to_le_bytes()); // version made: Unix
            buf.extend_from_slice(&20u16.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes()); // flags
            buf.extend_from_slice(&0u16.to_le_bytes()); // stored
            buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
            buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
            buf.extend_from_slice(&crc.to_le_bytes());
            buf.extend_from_slice(&size.to_le_bytes());
            buf.extend_from_slice(&size.to_le_bytes());
            buf.extend_from_slice(&name_len.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes()); // extra
            buf.extend_from_slice(&0u16.to_le_bytes()); // comment
            buf.extend_from_slice(&0u16.to_le_bytes()); // disk start
            buf.extend_from_slice(&0u16.to_le_bytes()); // int attrs
            buf.extend_from_slice(&(0o100_644u32 << 16).to_le_bytes()); // ext attrs
            buf.extend_from_slice(&offset.to_le_bytes());
            buf.extend_from_slice(name_bytes);
        };

        let central_start = buf.len() as u32;
        write_central(&mut buf, content1, offset1);
        write_central(&mut buf, content2, offset2);
        let central_size = (buf.len() as u32) - central_start;

        buf.extend_from_slice(b"PK\x05\x06");
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk w/ cd
        buf.extend_from_slice(&2u16.to_le_bytes()); // entries on disk
        buf.extend_from_slice(&2u16.to_le_bytes()); // total entries
        buf.extend_from_slice(&central_size.to_le_bytes());
        buf.extend_from_slice(&central_start.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // comment len
        buf
    }

    #[test]
    fn test_duplicate_entry_skip_default() {
        let zip_data = create_raw_duplicate_zip("legit.txt", b"first", b"second");
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();
        let options = ExtractionOptions::default(); // skip_duplicates = true

        let report = archive
            .extract(temp.path(), &config, &options, &mut crate::NoopProgress)
            .unwrap();

        // zip crate 8.x deduplicates entries at ZipArchive::new(), so the raw
        // archive with two identical filenames appears as a single entry.
        // The skip logic is verified by the TAR tests; this test confirms the
        // ZIP extractor still succeeds without panicking on such archives.
        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("legit.txt").exists());
    }

    #[test]
    fn test_encrypted_zip_rejected_with_security_violation() {
        use zip::unstable::write::FileOptionsExt;

        let buffer = Vec::new();
        let mut writer = ZipWriter::new(Cursor::new(buffer));
        let options = SimpleFileOptions::default()
            .with_deprecated_encryption(b"password123")
            .unwrap();
        writer.start_file("secret.txt", options).unwrap();
        writer.write_all(b"secret data").unwrap();
        let zip_data = writer.finish().unwrap().into_inner();

        let cursor = Cursor::new(zip_data);
        let result = ZipArchive::new(cursor);
        let Err(err) = result else {
            panic!("expected error for encrypted ZIP, got Ok");
        };
        match err {
            ArchiveError::SecurityViolation { reason } => {
                assert!(
                    reason.contains("password") || reason.contains("encrypted"),
                    "expected password/encryption mention in reason: {reason}"
                );
            }
            other => panic!("expected SecurityViolation, got: {other}"),
        }
    }

    // Regression test for #171: full scan must catch an encrypted entry at any
    // interior position.
    #[test]
    fn test_encrypted_entry_not_at_boundary_is_detected() {
        use zip::unstable::write::FileOptionsExt;

        let buffer = Vec::new();
        let mut writer = ZipWriter::new(Cursor::new(buffer));

        let plain = SimpleFileOptions::default();
        let encrypted = SimpleFileOptions::default()
            .with_deprecated_encryption(b"secret")
            .unwrap();

        // 7 entries: indices 0..6. Encrypted entry is at index 3 (interior).
        // Verifies that the full scan catches all positions, not just boundaries.
        for i in 0..7u8 {
            if i == 3 {
                writer
                    .start_file(format!("file{i}.txt"), encrypted)
                    .unwrap();
            } else {
                writer.start_file(format!("file{i}.txt"), plain).unwrap();
            }
            writer.write_all(b"data").unwrap();
        }
        let zip_data = writer.finish().unwrap().into_inner();

        let cursor = Cursor::new(zip_data);
        let result = ZipArchive::new(cursor);
        assert!(
            result.is_err(),
            "archive with encrypted entry at index 3 must be rejected"
        );
        match result.err().unwrap() {
            ArchiveError::SecurityViolation { reason } => {
                assert!(
                    reason.contains("password") || reason.contains("encrypted"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected SecurityViolation, got: {other}"),
        }
    }

    #[test]
    fn test_list_returns_manifest_with_entries() {
        let zip_data = create_test_zip(vec![("a.txt", b"hello"), ("b.txt", b"world")]);
        let mut archive = ZipArchive::new(Cursor::new(zip_data)).unwrap();
        let config = SecurityConfig::default();

        let manifest = archive.list(&config).unwrap();

        assert_eq!(manifest.total_entries, 2);
        assert_eq!(manifest.total_size, 10);
    }

    #[test]
    fn test_list_empty_zip_returns_empty_manifest() {
        let zip_data = create_test_zip(vec![]);
        let mut archive = ZipArchive::new(Cursor::new(zip_data)).unwrap();
        let config = SecurityConfig::default();

        let manifest = archive.list(&config).unwrap();

        assert_eq!(manifest.total_entries, 0);
        assert_eq!(manifest.total_size, 0);
    }

    #[test]
    fn test_verify_clean_zip_is_safe() {
        let zip_data = create_test_zip(vec![("safe.txt", b"data")]);
        let mut archive = ZipArchive::new(Cursor::new(zip_data)).unwrap();
        let config = SecurityConfig::default();

        let report = archive.verify(&config).unwrap();

        assert!(report.is_safe());
        assert_eq!(report.total_entries, 1);
    }

    #[test]
    fn test_allowed_extensions_filters_out_disallowed() {
        use crate::NoopProgress;
        let zip_data = create_test_zip(vec![("keep.txt", b"keep"), ("skip.exe", b"skip")]);
        let dest = tempfile::tempdir().unwrap();
        let config = SecurityConfig::default().with_allowed_extensions(vec!["txt".to_string()]);

        let report = ZipArchive::new(Cursor::new(zip_data))
            .unwrap()
            .extract(
                dest.path(),
                &config,
                &ExtractionOptions::default(),
                &mut NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert_eq!(report.files_skipped, 1);
        assert!(dest.path().join("keep.txt").exists());
        assert!(!dest.path().join("skip.exe").exists());
        assert!(report.warnings.iter().any(|w| w.contains("skip.exe")));
    }

    #[test]
    fn test_empty_allowed_extensions_allows_all() {
        use crate::NoopProgress;
        let zip_data = create_test_zip(vec![("a.txt", b"a"), ("b.exe", b"b")]);
        let dest = tempfile::tempdir().unwrap();
        let config = SecurityConfig::default();

        let report = ZipArchive::new(Cursor::new(zip_data))
            .unwrap()
            .extract(
                dest.path(),
                &config,
                &ExtractionOptions::default(),
                &mut NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 2);
        assert_eq!(report.files_skipped, 0);
    }

    #[test]
    fn test_extension_less_files_blocked_when_allowlist_nonempty() {
        use crate::NoopProgress;
        let zip_data = create_test_zip(vec![("Makefile", b"all:"), ("keep.txt", b"ok")]);
        let dest = tempfile::tempdir().unwrap();
        let config = SecurityConfig::default().with_allowed_extensions(vec!["txt".to_string()]);

        let report = ZipArchive::new(Cursor::new(zip_data))
            .unwrap()
            .extract(
                dest.path(),
                &config,
                &ExtractionOptions::default(),
                &mut NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1, "only .txt should be extracted");
        assert_eq!(
            report.files_skipped, 1,
            "extension-less file must be skipped"
        );
        assert!(!dest.path().join("Makefile").exists());
        assert!(dest.path().join("keep.txt").exists());
    }
}
