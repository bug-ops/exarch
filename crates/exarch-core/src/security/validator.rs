//! Entry validation orchestrator.
//!
//! This module provides the main `EntryValidator` type that coordinates all
//! security validations for archive entries.

use std::path::Path;

use crate::Result;
use crate::SecurityConfig;
use crate::security::hardlink::HardlinkTracker;
use crate::security::path::validate_path;
use crate::security::permissions::sanitize_permissions;
use crate::security::quota::QuotaTracker;
use crate::security::symlink::validate_symlink;
use crate::security::zipbomb::validate_compression_ratio;
use crate::types::DestDir;
use crate::types::EntryType;
use crate::types::SafePath;
use crate::types::SafeSymlink;

/// Result of entry validation.
///
/// Contains validated and sanitized entry information ready for extraction.
#[derive(Debug)]
pub struct ValidatedEntry {
    /// Validated path within destination directory
    pub safe_path: SafePath,

    /// Validated entry type
    pub entry_type: ValidatedEntryType,

    /// Sanitized file permissions (if applicable)
    pub mode: Option<u32>,
}

/// Validated entry type variants.
#[derive(Debug)]
pub enum ValidatedEntryType {
    /// Regular file
    File,

    /// Directory
    Directory,

    /// Validated symlink
    Symlink(SafeSymlink),

    /// Hardlink (validated in tracker, target path stored for two-pass)
    Hardlink {
        /// Target path (already validated)
        target: SafePath,
    },
}

/// Orchestrates security validation for archive entries.
///
/// This type maintains state across entry validations:
/// - Quota tracking (file count, total size)
/// - Compression ratio monitoring (zip bomb detection)
/// - Hardlink target tracking
///
/// # Lifecycle
///
/// 1. Create with `EntryValidator::new(&config, &dest)`
/// 2. For each entry, call `validate_entry()`
/// 3. After all entries processed, call `finish()` for final report
///
/// # Examples
///
/// ```no_run
/// use exarch_core::SecurityConfig;
/// use exarch_core::security::EntryValidator;
/// use exarch_core::types::DestDir;
/// use exarch_core::types::EntryType;
/// use std::path::Path;
/// use std::path::PathBuf;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dest = DestDir::new(PathBuf::from("/tmp"))?;
/// let config = SecurityConfig::default();
///
/// let mut validator = EntryValidator::new(&config, &dest);
///
/// // Validate a file entry
/// let entry = validator.validate_entry(
///     Path::new("foo/bar.txt"),
///     &EntryType::File,
///     1024,        // uncompressed size
///     Some(512),   // compressed size
///     Some(0o644), // mode
/// )?;
///
/// let report = validator.finish();
/// println!("Validated {} files", report.files_validated);
/// # Ok(())
/// # }
/// ```
/// OPT-H004: Validator uses references to avoid cloning config and dest.
/// This eliminates 1 clone per extraction (`SecurityConfig` + `DestDir`).
pub struct EntryValidator<'a> {
    config: &'a SecurityConfig,
    dest: &'a DestDir,
    quota_tracker: QuotaTracker,
    hardlink_tracker: HardlinkTracker,
}

impl<'a> EntryValidator<'a> {
    /// Creates a new entry validator with the given security configuration.
    #[must_use]
    pub fn new(config: &'a SecurityConfig, dest: &'a DestDir) -> Self {
        Self {
            config,
            dest,
            quota_tracker: QuotaTracker::new(),
            hardlink_tracker: HardlinkTracker::new(),
        }
    }

    /// Validates an archive entry.
    ///
    /// This method orchestrates all security validations:
    /// 1. Path validation (traversal, depth, banned components)
    /// 2. Quota checking (file size, count, total size)
    /// 3. Compression ratio validation (zip bomb detection)
    /// 4. Type-specific validation (symlink, hardlink, permissions)
    ///
    /// # Performance
    ///
    /// Typical execution time per entry:
    /// - Regular file (non-existing): ~1-2 μs
    /// - Regular file (existing): ~10-50 μs (canonicalization)
    /// - Symlink: ~10-50 μs (target resolution)
    /// - Hardlink: ~5-10 μs (tracking update)
    ///
    /// # Errors
    ///
    /// Returns an error if any validation fails. Common errors:
    /// - `ExtractionError::PathTraversal` - Path escapes destination
    /// - `ExtractionError::QuotaExceeded` - Size or count limits exceeded
    /// - `ExtractionError::ZipBomb` - Compression ratio too high
    /// - `ExtractionError::SymlinkEscape` - Symlink target escapes
    /// - `ExtractionError::HardlinkEscape` - Hardlink target escapes
    /// - `ExtractionError::InvalidPermissions` - Dangerous permissions
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use exarch_core::SecurityConfig;
    /// use exarch_core::security::EntryValidator;
    /// use exarch_core::types::DestDir;
    /// use exarch_core::types::EntryType;
    /// use std::path::Path;
    /// use std::path::PathBuf;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let dest = DestDir::new(PathBuf::from("/tmp"))?;
    /// let config = SecurityConfig::default();
    /// let mut validator = EntryValidator::new(&config, &dest);
    ///
    /// let entry = validator.validate_entry(
    ///     Path::new("file.txt"),
    ///     &EntryType::File,
    ///     1024,
    ///     None,
    ///     Some(0o644),
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn validate_entry(
        &mut self,
        path: &Path,
        entry_type: &EntryType,
        uncompressed_size: u64,
        compressed_size: Option<u64>,
        mode: Option<u32>,
    ) -> Result<ValidatedEntry> {
        let safe_path = validate_path(path, self.dest, self.config)?;

        if matches!(entry_type, EntryType::File) {
            self.quota_tracker
                .record_file(uncompressed_size, self.config)?;
        }

        if let Some(compressed) = compressed_size {
            validate_compression_ratio(compressed, uncompressed_size, self.config)?;
        }

        let (validated_type, sanitized_mode) = match entry_type {
            EntryType::File => {
                let sanitized = if let Some(m) = mode {
                    Some(sanitize_permissions(safe_path.as_path(), m, self.config)?)
                } else {
                    None
                };
                (ValidatedEntryType::File, sanitized)
            }

            EntryType::Directory => (ValidatedEntryType::Directory, None),

            EntryType::Symlink { target } => {
                let safe_symlink = validate_symlink(&safe_path, target, self.dest, self.config)?;
                (ValidatedEntryType::Symlink(safe_symlink), None)
            }

            EntryType::Hardlink { target } => {
                // Hardlink tracker validates: absolute paths, traversal, normalization, escapes
                self.hardlink_tracker.validate_hardlink(
                    &safe_path,
                    target,
                    self.dest,
                    self.config,
                )?;

                // SAFETY: validate_hardlink verified target is relative, normalized, within
                // dest
                let target_safe = SafePath::new_unchecked(target.clone());

                (
                    ValidatedEntryType::Hardlink {
                        target: target_safe,
                    },
                    None,
                )
            }
        };

        Ok(ValidatedEntry {
            safe_path,
            entry_type: validated_type,
            mode: sanitized_mode,
        })
    }

    /// Finishes validation and returns a summary report.
    ///
    /// This consumes the validator and returns statistics about the
    /// validation process.
    #[must_use]
    pub fn finish(self) -> ValidationReport {
        ValidationReport {
            files_validated: self.quota_tracker.files_extracted(),
            total_bytes: self.quota_tracker.bytes_written(),
            hardlinks_tracked: self.hardlink_tracker.count(),
        }
    }
}

/// Summary report of validation process.
#[derive(Debug)]
pub struct ValidationReport {
    /// Number of files validated
    pub files_validated: usize,

    /// Total bytes processed
    pub total_bytes: u64,

    /// Number of hardlinks tracked
    pub hardlinks_tracked: usize,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_entry_validator_new() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();
        let validator = EntryValidator::new(&config, &dest);
        let report = validator.finish();
        assert_eq!(report.files_validated, 0);
        assert_eq!(report.total_bytes, 0);
        assert_eq!(report.hardlinks_tracked, 0);
    }

    #[test]
    fn test_validate_file_entry() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();
        let mut validator = EntryValidator::new(&config, &dest);

        let result = validator.validate_entry(
            Path::new("file.txt"),
            &EntryType::File,
            1024,
            None,
            Some(0o644),
        );

        assert!(result.is_ok());
        let entry = result.unwrap();
        assert_eq!(entry.safe_path.as_path(), Path::new("file.txt"));
        assert!(matches!(entry.entry_type, ValidatedEntryType::File));
        assert_eq!(entry.mode, Some(0o644));
    }

    #[test]
    fn test_validate_directory_entry() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();
        let mut validator = EntryValidator::new(&config, &dest);

        let result =
            validator.validate_entry(Path::new("dir"), &EntryType::Directory, 0, None, None);

        assert!(result.is_ok());
        let entry = result.unwrap();
        assert!(matches!(entry.entry_type, ValidatedEntryType::Directory));
        assert!(entry.mode.is_none());
    }

    #[test]
    fn test_validate_path_traversal_rejected() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();
        let mut validator = EntryValidator::new(&config, &dest);

        let result = validator.validate_entry(
            Path::new("../etc/passwd"),
            &EntryType::File,
            1024,
            None,
            Some(0o644),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_quota_exceeded_file_size() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.max_file_size = 100;
        let mut validator = EntryValidator::new(&config, &dest);

        let result = validator.validate_entry(
            Path::new("large.txt"),
            &EntryType::File,
            1000,
            None,
            Some(0o644),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_quota_exceeded_file_count() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.max_file_count = 2;
        let mut validator = EntryValidator::new(&config, &dest);

        assert!(
            validator
                .validate_entry(
                    Path::new("file1.txt"),
                    &EntryType::File,
                    100,
                    None,
                    Some(0o644)
                )
                .is_ok()
        );
        assert!(
            validator
                .validate_entry(
                    Path::new("file2.txt"),
                    &EntryType::File,
                    100,
                    None,
                    Some(0o644)
                )
                .is_ok()
        );

        let result = validator.validate_entry(
            Path::new("file3.txt"),
            &EntryType::File,
            100,
            None,
            Some(0o644),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_zip_bomb_detected() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();
        let mut validator = EntryValidator::new(&config, &dest);

        let result = validator.validate_entry(
            Path::new("bomb.txt"),
            &EntryType::File,
            1_000_000,
            Some(100),
            Some(0o644),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_validation_report() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();
        let mut validator = EntryValidator::new(&config, &dest);

        validator
            .validate_entry(
                Path::new("file1.txt"),
                &EntryType::File,
                1024,
                None,
                Some(0o644),
            )
            .unwrap();

        validator
            .validate_entry(
                Path::new("file2.txt"),
                &EntryType::File,
                2048,
                None,
                Some(0o644),
            )
            .unwrap();

        let report = validator.finish();
        assert_eq!(report.files_validated, 2);
        assert_eq!(report.total_bytes, 1024 + 2048);
    }

    #[test]
    fn test_sanitize_permissions_setuid() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();
        let mut validator = EntryValidator::new(&config, &dest);

        let result = validator.validate_entry(
            Path::new("file.txt"),
            &EntryType::File,
            1024,
            None,
            Some(0o4755),
        );

        assert!(result.is_ok());
        let entry = result.unwrap();
        assert_eq!(entry.mode, Some(0o755)); // setuid stripped
    }

    #[test]
    fn test_symlink_validation() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = true;
        let mut validator = EntryValidator::new(&config, &dest);

        let result = validator.validate_entry(
            Path::new("link"),
            &EntryType::Symlink {
                target: PathBuf::from("target.txt"),
            },
            0,
            None,
            None,
        );

        assert!(result.is_ok());
        let entry = result.unwrap();
        assert!(matches!(entry.entry_type, ValidatedEntryType::Symlink(_)));
    }

    #[test]
    fn test_hardlink_validation() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        let mut validator = EntryValidator::new(&config, &dest);

        let result = validator.validate_entry(
            Path::new("link"),
            &EntryType::Hardlink {
                target: PathBuf::from("target.txt"),
            },
            0,
            None,
            None,
        );

        assert!(result.is_ok());
        let entry = result.unwrap();
        assert!(matches!(
            entry.entry_type,
            ValidatedEntryType::Hardlink { .. }
        ));
    }

    #[test]
    fn test_multiple_entries_with_report() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        let mut validator = EntryValidator::new(&config, &dest);

        // Validate multiple entry types
        validator
            .validate_entry(
                Path::new("file1.txt"),
                &EntryType::File,
                1024,
                None,
                Some(0o644),
            )
            .unwrap();

        validator
            .validate_entry(Path::new("dir"), &EntryType::Directory, 0, None, None)
            .unwrap();

        validator
            .validate_entry(
                Path::new("hardlink"),
                &EntryType::Hardlink {
                    target: PathBuf::from("file1.txt"),
                },
                0,
                None,
                None,
            )
            .unwrap();

        let report = validator.finish();
        assert_eq!(report.files_validated, 1); // Only files counted
        assert_eq!(report.total_bytes, 1024);
        assert_eq!(report.hardlinks_tracked, 1);
    }

    // M-TEST-1: Empty directory handling
    #[test]
    fn test_empty_directory_validation() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();
        let mut validator = EntryValidator::new(&config, &dest);

        // Empty directory should be valid
        let result = validator.validate_entry(
            Path::new("empty_dir/"),
            &EntryType::Directory,
            0,
            None,
            None,
        );

        assert!(result.is_ok(), "empty directory should be valid");
        let entry = result.unwrap();
        assert!(
            matches!(entry.entry_type, ValidatedEntryType::Directory),
            "should be directory type"
        );
        assert!(entry.mode.is_none(), "directory should not have mode set");
    }

    #[test]
    fn test_nested_empty_directories() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default();
        let mut validator = EntryValidator::new(&config, &dest);

        // Multiple nested empty directories
        let dirs = ["a/", "a/b/", "a/b/c/"];
        for dir in &dirs {
            let result =
                validator.validate_entry(Path::new(dir), &EntryType::Directory, 0, None, None);
            assert!(result.is_ok(), "nested directory {dir} should be valid");
        }

        let report = validator.finish();
        assert_eq!(
            report.files_validated, 0,
            "directories are not counted as files"
        );
    }

    // OPT-H004: Test validator uses references (no cloning)
    #[test]
    fn test_validator_uses_references() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let config = SecurityConfig::default();

        // Create validator with references
        let validator = EntryValidator::new(&config, &dest);

        // Verify config and dest are still accessible (not moved)
        assert_eq!(
            config.max_file_size,
            SecurityConfig::default().max_file_size
        );
        // Note: dest.as_path() may be canonicalized on macOS (/var vs /private/var)
        // Just verify dest is still accessible
        let _ = dest.as_path();

        // Validator can still be used
        drop(validator);
    }

    // OPT-H004: Test multiple validators can share same config
    #[test]
    fn test_multiple_validators_share_config() {
        let temp1 = TempDir::new().unwrap();
        let temp2 = TempDir::new().unwrap();
        let dest1 = DestDir::new(temp1.path().to_path_buf()).unwrap();
        let dest2 = DestDir::new(temp2.path().to_path_buf()).unwrap();
        let config = SecurityConfig::default();

        // Create two validators sharing the same config reference
        let mut validator1 = EntryValidator::new(&config, &dest1);
        let mut validator2 = EntryValidator::new(&config, &dest2);

        // Both validators work independently
        let result1 = validator1.validate_entry(
            Path::new("file1.txt"),
            &EntryType::File,
            1024,
            None,
            Some(0o644),
        );
        assert!(result1.is_ok());

        let result2 = validator2.validate_entry(
            Path::new("file2.txt"),
            &EntryType::File,
            2048,
            None,
            Some(0o644),
        );
        assert!(result2.is_ok());

        // Config is still accessible
        assert_eq!(
            config.max_file_size,
            SecurityConfig::default().max_file_size
        );
    }
}
