//! Common extraction utilities shared between archive formats.
//!
//! This module provides shared functionality for TAR and ZIP extractors
//! to avoid code duplication. It is an internal module not exposed in
//! the public API.
//!
//! # Functions
//!
//! - [`extract_file_generic`]: Generic file extraction with buffered I/O
//! - [`create_directory`]: Directory creation (idempotent)
//! - [`create_symlink`]: Symbolic link creation (Unix only)

use std::fs::File;
use std::fs::create_dir_all;
use std::io::BufWriter;
use std::io::Read;
use std::io::Write;

use crate::ExtractionError;
use crate::ExtractionReport;
use crate::Result;
use crate::copy::CopyBuffer;
use crate::copy::copy_with_buffer;
use crate::error::QuotaResource;
use crate::security::validator::ValidatedEntry;
use crate::types::DestDir;
use crate::types::SafeSymlink;

/// Generic file extraction implementation used by all format adapters.
///
/// This function consolidates file extraction logic to ensure consistent:
/// - Directory creation
/// - Buffered I/O (64KB buffer)
/// - Permission preservation (Unix only)
/// - Quota tracking with overflow protection
///
/// # Correctness
///
/// Quota is checked BEFORE writing to prevent partial files on overflow.
/// This fixes the inconsistency where TAR was checking AFTER write.
///
/// # Type Parameters
///
/// - `R`: Reader type that implements `Read`
///
/// # Arguments
///
/// * `reader` - Source data stream
/// * `validated` - Validated entry metadata (path, mode, etc.)
/// * `dest` - Destination directory
/// * `report` - Extraction statistics (updated)
/// * `expected_size` - Expected file size (if known) for quota pre-check
/// * `copy_buffer` - Reusable buffer for I/O operations
///
/// # Errors
///
/// Returns error if:
/// - Parent directory creation fails
/// - Quota would be exceeded (checked before write)
/// - File creation fails
/// - I/O error during copy
/// - Permission setting fails (Unix)
pub fn extract_file_generic<R: Read>(
    reader: &mut R,
    validated: &ValidatedEntry,
    dest: &DestDir,
    report: &mut ExtractionReport,
    expected_size: Option<u64>,
    copy_buffer: &mut CopyBuffer,
) -> Result<()> {
    let output_path = dest.join(&validated.safe_path);

    // Create parent directories if needed
    if let Some(parent) = output_path.parent() {
        create_dir_all(parent)?;
    }

    // CRITICAL: Check quota BEFORE writing (prevents partial files on overflow)
    if let Some(size) = expected_size {
        report
            .bytes_written
            .checked_add(size)
            .ok_or(ExtractionError::QuotaExceeded {
                resource: QuotaResource::IntegerOverflow,
            })?;
    }

    // Write file with buffered I/O
    let output_file = File::create(&output_path)?;
    let mut buffered_writer = BufWriter::with_capacity(64 * 1024, output_file);
    let bytes_written = copy_with_buffer(reader, &mut buffered_writer, copy_buffer)?;
    buffered_writer.flush()?;

    // Set permissions (Unix only)
    #[cfg(unix)]
    if let Some(mode) = validated.mode {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(&output_path, permissions)?;
    }
    // On non-Unix platforms, we silently skip permission setting because
    // file extraction can succeed without it (permissions are platform-specific).
    // This differs from symlink creation, which returns an error on non-Unix
    // platforms because symlinks are a fundamental feature that cannot be emulated.
    #[cfg(not(unix))]
    let _ = validated.mode; // Suppress unused field warning

    // Update statistics
    report.files_extracted += 1;
    // Use checked_add for safety, though the pre-check should prevent overflow
    // if expected_size was accurate
    report.bytes_written =
        report
            .bytes_written
            .checked_add(bytes_written)
            .ok_or(ExtractionError::QuotaExceeded {
                resource: QuotaResource::IntegerOverflow,
            })?;

    Ok(())
}

/// Creates a directory from a validated entry.
///
/// This is a shared helper used by both TAR and ZIP extractors.
///
/// # Idempotent Behavior
///
/// This function is idempotent - calling it multiple times for the same
/// directory has no effect. This is because `create_dir_all` silently
/// succeeds if the directory already exists, avoiding duplicate creation
/// errors during archive extraction.
///
/// # Quota Tracking
///
/// Directory creation increments the `directories_created` counter but
/// does NOT count toward the byte quota (`bytes_written`). Only regular
/// file data counts toward byte quotas.
///
/// # Errors
///
/// Returns an error if directory creation fails due to I/O errors.
pub fn create_directory(
    validated: &ValidatedEntry,
    dest: &DestDir,
    report: &mut ExtractionReport,
) -> Result<()> {
    let dir_path = dest.join(&validated.safe_path);

    // create_dir_all is idempotent - handles existing directories gracefully
    create_dir_all(&dir_path)?;

    report.directories_created += 1;

    Ok(())
}

/// Creates a symbolic link from a validated symlink entry.
///
/// This is a shared helper used by both TAR and ZIP extractors.
/// Parent directories are created automatically if needed.
///
/// # Platform Support
///
/// - **Unix**: Full symlink support via `std::os::unix::fs::symlink`
/// - **Other platforms**: Returns `SecurityViolation` error
///
/// # Error Behavior
///
/// If the symlink already exists, the function will fail with an I/O error.
/// Unlike `create_directory`, this function is NOT idempotent - it does not
/// overwrite existing symlinks or files at the target path.
///
/// # Errors
///
/// Returns an error if:
/// - Platform does not support symlinks
/// - Parent directory creation fails
/// - Symlink creation fails (including when target path already exists)
/// - A file or symlink already exists at the link path
#[allow(unused_variables)]
pub fn create_symlink(
    safe_symlink: &SafeSymlink,
    dest: &DestDir,
    report: &mut ExtractionReport,
) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let link_path = dest.join_path(safe_symlink.link_path());
        let target_path = safe_symlink.target_path();

        // Create parent directories
        if let Some(parent) = link_path.parent() {
            create_dir_all(parent)?;
        }

        // Create symlink
        symlink(target_path, &link_path)?;

        report.symlinks_created += 1;

        Ok(())
    }

    #[cfg(not(unix))]
    {
        Err(ExtractionError::SecurityViolation {
            reason: "symlinks are not supported on this platform".into(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::ExtractionError;
    use crate::ExtractionReport;
    use crate::SecurityConfig;
    use crate::copy::CopyBuffer;
    use crate::security::validator::ValidatedEntry;
    use crate::security::validator::ValidatedEntryType;
    use crate::types::SafePath;
    use std::io::Cursor;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_extract_file_generic_integer_overflow_check() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let mut report = ExtractionReport::default();
        let mut copy_buffer = CopyBuffer::new();

        // Set bytes_written to a value close to u64::MAX
        report.bytes_written = u64::MAX - 100;

        // Try to extract a file with size that would overflow
        let expected_size = Some(200u64); // This would overflow when added

        let config = SecurityConfig::default();
        let validated = ValidatedEntry {
            safe_path: SafePath::validate(&PathBuf::from("test.txt"), &dest, &config)
                .expect("path should be valid"),
            mode: Some(0o644),
            entry_type: ValidatedEntryType::File,
        };

        let mut reader = Cursor::new(b"test data");

        let result = extract_file_generic(
            &mut reader,
            &validated,
            &dest,
            &mut report,
            expected_size,
            &mut copy_buffer,
        );

        // Should return QuotaExceeded with IntegerOverflow
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ExtractionError::QuotaExceeded {
                resource: QuotaResource::IntegerOverflow
            }
        ));
    }
}
