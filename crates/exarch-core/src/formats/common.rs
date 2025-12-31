//! Common extraction utilities shared between archive formats.
//!
//! This module provides shared functionality for TAR and ZIP extractors
//! to avoid code duplication.

use std::fs::create_dir_all;

use crate::ExtractionReport;
use crate::Result;
use crate::security::validator::ValidatedEntry;
use crate::types::DestDir;
use crate::types::SafeSymlink;

/// Creates a directory from a validated entry.
///
/// This is a shared helper used by both TAR and ZIP extractors.
/// The function is idempotent - calling it multiple times for the
/// same directory has no effect.
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

    // create_dir_all is idempotent
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
/// # Errors
///
/// Returns an error if:
/// - Platform does not support symlinks
/// - Parent directory creation fails
/// - Symlink creation fails
#[allow(unused_variables)]
pub fn create_symlink(
    safe_symlink: &SafeSymlink,
    dest: &DestDir,
    report: &mut ExtractionReport,
) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let link_path = dest.as_path().join(safe_symlink.link_path());
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
