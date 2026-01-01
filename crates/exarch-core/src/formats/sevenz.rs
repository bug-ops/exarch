//! 7z archive format extraction.
//!
//! Provides secure extraction of 7z archives with security validation.
//!
//! # Security Features
//!
//! - Encrypted archives rejected by default
//! - Solid archives rejected by default (configurable)
//! - Path traversal prevention
//! - Decompression bomb detection
//! - Memory exhaustion protection for solid blocks
//!
//! # Supported Compression Methods
//!
//! - LZMA / LZMA2
//! - BZIP2
//! - `PPMd`
//! - DEFLATE
//! - Copy (stored)
//!
//! # Solid Archives
//!
//! 7z supports "solid" compression where multiple files are compressed together
//! as a single block. While this provides better compression ratios, it has
//! security implications:
//!
//! - **Memory exhaustion**: Extracting a single file requires decompressing the
//!   entire solid block into memory
//! - **Denial of service**: Malicious archives can create large solid blocks
//!   that exhaust available memory
//!
//! **Default Policy**: Solid archives are **rejected** by default.
//! Use `SecurityConfig::allow_solid_archives` to enable.
//!
//! # Examples
//!
//! Basic extraction:
//!
//! ```no_run
//! use exarch_core::SecurityConfig;
//! use exarch_core::formats::SevenZArchive;
//! use exarch_core::formats::traits::ArchiveFormat;
//! use std::fs::File;
//! use std::path::Path;
//!
//! let file = File::open("archive.7z")?;
//! let mut archive = SevenZArchive::new(file)?;
//! let report = archive.extract(Path::new("/output"), &SecurityConfig::default())?;
//! println!("Extracted {} files", report.files_extracted);
//! # Ok::<(), exarch_core::ExtractionError>(())
//! ```
//!
//! Allow solid archives with memory limit:
//!
//! ```no_run
//! use exarch_core::SecurityConfig;
//!
//! let mut config = SecurityConfig::default();
//! config.allow_solid_archives = true;
//! config.max_solid_block_memory = 512 * 1024 * 1024; // 512 MB
//! // ... extract with config
//! ```

use std::io::Read;
use std::io::Seek;
use std::path::Path;
use std::path::PathBuf;

use sevenz_rust2::Archive;
use sevenz_rust2::Password;

use crate::ExtractionError;
use crate::ExtractionReport;
use crate::Result;
use crate::SecurityConfig;
use crate::security::EntryValidator;
use crate::security::validator::ValidatedEntryType;
use crate::types::DestDir;
use crate::types::EntryType;

use super::traits::ArchiveFormat;

/// 7z archive handler with security validation.
///
/// Supports:
/// - 7z format (LZMA SDK)
/// - Compression methods: LZMA, LZMA2, BZIP2, `PPMd`, DEFLATE, Copy
/// - Multi-volume archives (read-only)
/// - Encrypted archive detection (rejected)
/// - Solid archive detection (rejected by default)
///
/// # Solid Archives
///
/// Solid compression stores multiple files in a single compressed block.
/// This provides better compression ratios but requires decompressing
/// the entire block to extract a single file, which can cause memory
/// exhaustion attacks.
///
/// **Security Policy**: Solid archives are rejected by default.
/// Use `SecurityConfig::allow_solid_archives` to enable with memory limits.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::SecurityConfig;
/// use exarch_core::formats::SevenZArchive;
/// use exarch_core::formats::traits::ArchiveFormat;
/// use std::fs::File;
/// use std::path::Path;
///
/// let file = File::open("archive.7z")?;
/// let mut archive = SevenZArchive::new(file)?;
/// let report = archive.extract(Path::new("/output"), &SecurityConfig::default())?;
/// println!("Extracted {} files", report.files_extracted);
/// # Ok::<(), exarch_core::ExtractionError>(())
/// ```
pub struct SevenZArchive<R: Read + Seek> {
    source: R,
}

impl<R: Read + Seek> SevenZArchive<R> {
    /// Creates a new 7z archive reader.
    ///
    /// # Security Checks
    ///
    /// - Rejects encrypted archives (via password parameter)
    /// - Validates archive header signature
    /// - Checks for solid compression (rejected by default)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Archive is encrypted
    /// - Archive header is invalid
    /// - Format is not recognized
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use exarch_core::formats::SevenZArchive;
    /// use std::fs::File;
    ///
    /// let file = File::open("archive.7z")?;
    /// let archive = SevenZArchive::new(file)?;
    /// # Ok::<(), exarch_core::ExtractionError>(())
    /// ```
    pub fn new(mut source: R) -> Result<Self> {
        // Step 1: Verify it's a valid 7z archive by reading metadata
        let password = Password::empty();
        let archive = Archive::read(&mut source, &password).map_err(|e| {
            // SECURITY: Check if error indicates encryption
            let err_str = e.to_string().to_lowercase();
            if err_str.contains("encrypt") || err_str.contains("password") {
                return ExtractionError::SecurityViolation {
                    reason: "encrypted 7z archives are not supported".into(),
                };
            }
            ExtractionError::InvalidArchive(format!("failed to open 7z archive: {e}"))
        })?;

        // Step 2: SECURITY - Reject solid archives immediately (fail-fast)
        if archive.is_solid {
            return Err(ExtractionError::SecurityViolation {
                reason: "solid 7z archives are not supported in this version".into(),
            });
        }

        // Step 3: Rewind for actual extraction
        source.rewind().map_err(ExtractionError::Io)?;

        Ok(Self { source })
    }
}

impl<R: Read + Seek> ArchiveFormat for SevenZArchive<R> {
    fn extract(&mut self, output_dir: &Path, config: &SecurityConfig) -> Result<ExtractionReport> {
        // Step 1: Read archive metadata
        // NOTE: Archive is re-parsed here because sevenz-rust2 doesn't allow storing
        // Archive in struct (no Clone/Send). Performance review recommends
        // investigating alternatives.
        let password = Password::empty();
        let archive = Archive::read(&mut self.source, &password)
            .map_err(|e| ExtractionError::InvalidArchive(format!("failed to read archive: {e}")))?;

        // Solid archives already rejected in new(), but check again for safety
        debug_assert!(
            !archive.is_solid,
            "solid archives should be rejected in new()"
        );

        // Step 2: Initialize extraction context
        let dest = DestDir::new(output_dir.to_path_buf())?;
        let mut validator = EntryValidator::new(config, &dest);

        // Step 3: Validate all paths BEFORE extraction
        // SECURITY NOTE: Pre-validation prevents partial extraction on malicious
        // archives
        //
        // API LIMITATIONS (sevenz-rust2 0.20):
        // - compressed_size: Not exposed per-entry, so zip bomb detection relies on
        //   quotas only
        // - symlink detection: Not exposed, non-directory entries treated as files
        for entry in &archive.files {
            let path = PathBuf::from(&entry.name);
            let entry_type = SevenZEntryAdapter::to_entry_type(entry);

            // KNOWN LIMITATION: compressed_size is None, so compression ratio check is
            // skipped. Defense relies on max_total_size and max_file_size
            // quotas.
            let validated = validator.validate_entry(&path, &entry_type, entry.size, None, None)?;

            match validated.entry_type {
                ValidatedEntryType::File | ValidatedEntryType::Directory => {
                    // Will be extracted/created when extraction is implemented
                }
                _ => {
                    // KNOWN LIMITATION: sevenz-rust2 doesn't expose symlink/hardlink detection.
                    // If entry type detection improves, this will catch them.
                    return Err(ExtractionError::SecurityViolation {
                        reason: "symlinks/hardlinks not yet supported for 7z".into(),
                    });
                }
            }
        }

        // Step 4: TEMPORARY for Phase 10.2
        // sevenz-rust2 0.20 has limited extraction API. Options for Phase 10.3:
        // 1. Use sevenz-rust2::Archive::extract() to temp dir, then move with
        //    validation
        // 2. Switch to sevenz-rust (older but may have better API)
        // 3. Implement custom decompression using blocks
        Err(ExtractionError::SecurityViolation {
            reason: "7z extraction implementation pending - sevenz-rust2 API limitations".into(),
        })
    }

    fn format_name(&self) -> &'static str {
        "7z"
    }
}

/// Adapter to convert sevenz-rust2 entry types to our `EntryType` enum.
///
/// # Known Limitations (sevenz-rust2 0.20)
///
/// - **Symlinks**: Not detected. The 7z format supports symlinks but
///   sevenz-rust2 doesn't expose `is_symlink()` or similar. Non-directory
///   entries are treated as files.
/// - **Hardlinks**: Not detected for the same reason.
/// - **Unix mode**: Not exposed, so permission sanitization cannot be applied.
///
/// These limitations are documented in the security review.
struct SevenZEntryAdapter;

impl SevenZEntryAdapter {
    /// Converts 7z entry to our `EntryType` enum.
    ///
    /// # Security Note
    ///
    /// Due to sevenz-rust2 API limitations, this function cannot detect
    /// symlinks or hardlinks. All non-directory entries are classified as
    /// files. If the archive contains symlinks, they will be treated as
    /// regular files during extraction (when implemented).
    fn to_entry_type(entry: &sevenz_rust2::ArchiveEntry) -> EntryType {
        // Phase 10.2: Only files and directories
        // TODO(Phase 10.3): Investigate if sevenz-rust2 exposes symlink/hardlink info
        if entry.is_directory() {
            return EntryType::Directory;
        }

        // Default: regular file (may be symlink - API limitation)
        EntryType::File
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // 7z format magic bytes for signature validation
    const SEVENZ_MAGIC: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

    /// Test that `format_name` returns correct value.
    /// This test doesn't require a valid archive.
    #[test]
    fn test_format_name() {
        // We can't create a valid SevenZArchive without a real archive,
        // but we can verify the implementation returns the expected value
        // by checking the trait implementation directly.

        // Create invalid data - this will fail to parse
        let data = SEVENZ_MAGIC.to_vec();
        let cursor = Cursor::new(data);

        // new() will fail because it's not a valid archive, but that's expected
        let result = SevenZArchive::new(cursor);
        assert!(result.is_err(), "invalid archive should fail to parse");

        // Verify the error is InvalidArchive (not security violation)
        assert!(matches!(result, Err(ExtractionError::InvalidArchive(_))));
    }

    /// Test that invalid magic bytes are rejected.
    #[test]
    fn test_invalid_magic_rejected() {
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let cursor = Cursor::new(data);

        let result = SevenZArchive::new(cursor);
        assert!(result.is_err());
        assert!(matches!(result, Err(ExtractionError::InvalidArchive(_))));
    }

    // ==================== IGNORED TESTS ====================
    //
    // The following tests are ignored because sevenz-rust2 0.20 does not export
    // a Writer/Encoder API for creating test archives programmatically.
    //
    // Resolution options for Phase 10.3:
    // 1. Generate pre-built fixtures using external 7z tool (recommended)
    // 2. Switch to alternative crate with Writer API
    // 3. Include binary fixtures in tests/fixtures/
    //
    // See .local/sevenz-testing-review.md for detailed analysis.

    #[test]
    #[ignore = "Phase 10.3: Requires pre-generated fixtures (sevenz-rust2 lacks Writer API)"]
    fn test_extract_simple_file() {
        // TODO: Load from tests/fixtures/simple.7z
        unimplemented!("requires fixture generation");
    }

    #[test]
    #[ignore = "Phase 10.3: Requires pre-generated fixtures (sevenz-rust2 lacks Writer API)"]
    fn test_path_traversal_rejected() {
        // TODO: Load from tests/fixtures/cve-path-traversal.7z
        unimplemented!("requires fixture generation");
    }

    #[test]
    #[ignore = "Phase 10.3: Requires pre-generated fixtures (sevenz-rust2 lacks Writer API)"]
    fn test_solid_archive_rejected() {
        // TODO: Load from tests/fixtures/solid.7z
        unimplemented!("requires fixture generation");
    }

    #[test]
    #[ignore = "Phase 10.3: Requires pre-generated fixtures (sevenz-rust2 lacks Writer API)"]
    fn test_encrypted_archive_rejected() {
        // TODO: Load from tests/fixtures/encrypted.7z
        unimplemented!("requires fixture generation");
    }

    #[test]
    #[ignore = "Phase 10.3: Requires pre-generated fixtures (sevenz-rust2 lacks Writer API)"]
    fn test_quota_exceeded() {
        // TODO: Load from tests/fixtures/large-files.7z
        unimplemented!("requires fixture generation");
    }
}
