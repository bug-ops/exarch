//! Entry validation orchestrator.
//!
//! This module provides the main `EntryValidator` type that coordinates all
//! security validations for archive entries.

use std::path::Path;

use crate::Result;
use crate::SecurityConfig;
use crate::config::Validated;
use crate::formats::common::DirCache;
use crate::security::context::ValidationContext;
use crate::security::hardlink::HardlinkTracker;
use crate::security::permissions::SanitizedMode;
use crate::security::permissions::sanitize_permissions;
use crate::security::quota::QuotaPermit;
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
///
/// # Security Properties
///
/// - Can ONLY be constructed through [`EntryValidator::validate_entry`]
/// - Fields are private; accessed through getters, so a `ValidatedEntry` cannot
///   be hand-assembled from unvalidated parts anywhere else in the crate
#[derive(Debug)]
pub struct ValidatedEntry {
    safe_path: SafePath,
    entry_type: ValidatedEntryType,
    mode: Option<SanitizedMode>,
}

impl ValidatedEntry {
    /// Constructs a `ValidatedEntry` from its already-validated parts.
    ///
    /// `pub(crate)` rather than fully private so that unit tests elsewhere in
    /// this crate (`formats::common`) can build fixtures without weakening
    /// the sealing against external construction.
    pub(crate) fn new(
        safe_path: SafePath,
        entry_type: ValidatedEntryType,
        mode: Option<SanitizedMode>,
    ) -> Self {
        Self {
            safe_path,
            entry_type,
            mode,
        }
    }

    /// Returns the validated path within the destination directory.
    #[inline]
    #[must_use]
    pub fn safe_path(&self) -> &SafePath {
        &self.safe_path
    }

    /// Returns the validated entry type.
    #[inline]
    #[must_use]
    pub fn entry_type(&self) -> &ValidatedEntryType {
        &self.entry_type
    }

    /// Returns the sanitized file permissions, if applicable.
    #[inline]
    #[must_use]
    pub fn mode(&self) -> Option<SanitizedMode> {
        self.mode
    }

    /// Consumes the entry, returning its validated parts by value.
    ///
    /// `entry_type()` only lends a shared reference, which is enough to
    /// observe a `QuotaPermit` but not to move it out of the `File` variant
    /// — `QuotaPermit` is neither `Clone` nor `Copy` by design, so ownership
    /// can only be obtained by consuming the `ValidatedEntry` that holds it.
    /// Write paths that need to thread the permit by value into a helper
    /// (mirroring `formats::common::copy_file_content_with_permit`'s guarantee)
    /// call this instead of `entry_type()`.
    #[inline]
    #[must_use]
    pub(crate) fn into_parts(self) -> (SafePath, ValidatedEntryType, Option<SanitizedMode>) {
        (self.safe_path, self.entry_type, self.mode)
    }
}

/// Validated entry type variants.
///
/// This enum alone does not carry the sealing guarantee — the external seal
/// comes from [`ValidatedEntry`]: its constructor is `pub(crate)`, so
/// nothing outside this crate can assemble a `ValidatedEntry` at all,
/// regardless of how its `ValidatedEntryType` field was produced. Within
/// that guarantee, several variants add a second, crate-internal layer for
/// their own payloads:
///
/// - The `Symlink` and `Hardlink` variants wrap [`SafeSymlink`] and
///   [`SafePath`], which are independently sealed and can only be produced by
///   their own validation routines, so even crate-internal code cannot forge a
///   "validated" symlink/hardlink target.
/// - The `File` variant wraps [`QuotaPermit`], whose only producer is
///   [`QuotaTracker::reserve`]: a `File` variant cannot be built without a
///   quota reservation having actually succeeded. This is crate-internal
///   discipline, not an external-construction barrier — enum variant fields are
///   as visible as the enum itself, so `ValidatedEntryType::File(todo!())`
///   compiles from outside this crate too; it just can never *run*, since
///   nothing outside this crate can produce a genuine `QuotaPermit`.
///
/// `#[non_exhaustive]` so a future variant is not a breaking change for
/// downstream matches — [`ValidatedEntry::entry_type`] is the only way
/// external code observes this type, and even that always sees output from
/// [`EntryValidator::validate_entry`].
#[derive(Debug)]
#[non_exhaustive]
pub enum ValidatedEntryType {
    /// Regular file, carrying proof that its size was reserved against a
    /// [`QuotaTracker`] before this entry was validated.
    File(QuotaPermit),

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
/// - Symlink-seen flag (for canonicalize optimization)
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
/// let config = SecurityConfig::default().validate()?;
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
///     None,        // dir_cache
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
    config: &'a SecurityConfig<Validated>,
    dest: &'a DestDir,
    quota_tracker: QuotaTracker,
    hardlink_tracker: HardlinkTracker,
    symlink_seen: bool,
}

impl<'a> EntryValidator<'a> {
    /// Creates a new entry validator with the given security configuration.
    #[must_use]
    pub fn new(config: &'a SecurityConfig<Validated>, dest: &'a DestDir) -> Self {
        Self {
            config,
            dest,
            quota_tracker: QuotaTracker::new(),
            hardlink_tracker: HardlinkTracker::new(),
            symlink_seen: false,
        }
    }

    /// Validates an archive entry.
    ///
    /// This method orchestrates all security validations:
    /// 1. Path validation (traversal, depth, banned components)
    /// 2. Quota checking (file size, count, total size) — `EntryType::File`
    ///    only
    /// 3. Compression ratio validation (zip bomb detection)
    /// 4. Type-specific validation (symlink, hardlink, permissions)
    ///
    /// When `dir_cache` is provided, path validation can skip expensive
    /// `canonicalize()` syscalls for parents that were created by us.
    ///
    /// # Errors
    ///
    /// Returns an error if any validation fails. Common errors:
    /// - `ArchiveError::PathTraversal` - Path escapes destination
    /// - `ArchiveError::QuotaExceeded` - Size or count limits exceeded
    /// - `ArchiveError::ZipBomb` - Compression ratio too high
    /// - `ArchiveError::SymlinkEscape` - Symlink target escapes
    /// - `ArchiveError::HardlinkEscape` - Hardlink target escapes
    /// - `ArchiveError::InvalidPermissions` - Dangerous permissions
    #[inline]
    pub fn validate_entry(
        &mut self,
        path: &Path,
        entry_type: &EntryType,
        uncompressed_size: u64,
        compressed_size: Option<u64>,
        mode: Option<u32>,
        dir_cache: Option<&DirCache>,
    ) -> Result<ValidatedEntry> {
        let safe_path = self.validate_entry_path(path, dir_cache)?;

        let (validated_type, sanitized_mode) = match entry_type {
            EntryType::File => {
                let permit = self.quota_tracker.reserve(uncompressed_size, self.config)?;
                self.check_ratio(compressed_size, uncompressed_size)?;
                let sanitized = mode.map(|m| sanitize_permissions(m, self.config));
                (ValidatedEntryType::File(permit), sanitized)
            }

            EntryType::Directory => {
                self.check_ratio(compressed_size, uncompressed_size)?;
                (ValidatedEntryType::Directory, None)
            }

            EntryType::Symlink { target } => {
                self.check_ratio(compressed_size, uncompressed_size)?;
                let safe_symlink = validate_symlink(&safe_path, target, self.dest, self.config)?;
                self.symlink_seen = true;
                (ValidatedEntryType::Symlink(safe_symlink), None)
            }

            EntryType::Hardlink { target } => {
                self.check_ratio(compressed_size, uncompressed_size)?;

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

        Ok(ValidatedEntry::new(
            safe_path,
            validated_type,
            sanitized_mode,
        ))
    }

    /// Validates only the path portion of an entry — traversal, absolute-path,
    /// depth, and symlink-escape-adjacent checks — without reserving quota or
    /// applying type-specific validation (symlink/hardlink target checks,
    /// permission sanitization).
    ///
    /// Split out of [`validate_entry`](Self::validate_entry), which calls
    /// this for its own path-validation step so the two never diverge.
    /// Callers that must resolve an entry's destination path *before*
    /// deciding whether to reserve quota — 7z's duplicate-skip check (issue
    /// #478), which needs the path to check for a pre-existing file at the
    /// destination — use this together with
    /// [`reserve_file`](Self::reserve_file) instead of `validate_entry`, so
    /// a skipped entry never reserves quota it will not use.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::PathTraversal`](crate::ArchiveError::PathTraversal)
    /// or another path-validation error if `path` fails validation.
    pub(crate) fn validate_entry_path(
        &self,
        path: &Path,
        dir_cache: Option<&DirCache>,
    ) -> Result<SafePath> {
        let mut ctx = ValidationContext::new(self.config.allowed.symlinks);
        if let Some(cache) = dir_cache {
            ctx = ctx.with_dir_cache(cache);
        }
        if self.symlink_seen {
            ctx.mark_symlink_seen();
        }

        SafePath::validate_with_context(path, self.dest, self.config, &ctx)
    }

    /// Reserves quota capacity for a regular file's byte count, independent
    /// of path validation.
    ///
    /// Mirrors [`reserve_hardlink`](Self::reserve_hardlink), which exists for
    /// the same reason on the hardlink path: reserving quota unconditionally
    /// inside `validate_entry` and only checking for a duplicate afterward
    /// would permanently consume the entry's quota allotment on the skip
    /// path, since [`QuotaPermit`] has no `Drop` impl to release it. Used by
    /// 7z's extraction callback together with
    /// [`validate_entry_path`](Self::validate_entry_path) (issue #478).
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::QuotaExceeded`](crate::ArchiveError::QuotaExceeded)
    /// if recording `size` bytes would exceed `max_file_size`,
    /// `max_file_count`, or `max_total_size`.
    pub(crate) fn reserve_file(&mut self, size: u64) -> Result<QuotaPermit> {
        self.quota_tracker.reserve(size, self.config)
    }

    /// Validates the compression ratio (zip bomb detection) when a
    /// compressed size is known.
    ///
    /// Extracted so [`validate_entry`](Self::validate_entry) can call it at
    /// the exact ordering position each entry type requires relative to its
    /// other checks, without duplicating the `if let Some(compressed) = ...`
    /// pattern at every call site.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::ZipBomb`] if the compression ratio exceeds the
    /// configured limit.
    #[inline]
    fn check_ratio(&self, compressed_size: Option<u64>, uncompressed_size: u64) -> Result<()> {
        if let Some(compressed) = compressed_size {
            validate_compression_ratio(compressed, uncompressed_size, self.config)?;
        }
        Ok(())
    }

    /// Reserves quota capacity for a hardlink's copied byte count against the
    /// shared quota tracker, returning a capability token that proves the
    /// reservation succeeded.
    ///
    /// Hardlinks are validated for path/target escape during the first pass
    /// (`validate_entry`), but their size is only known once the target file
    /// exists on disk, in the second pass. This routes that size through the
    /// same `QuotaTracker` used for regular files, so `max_file_size`,
    /// `max_file_count`, and `max_total_size` are enforced uniformly
    /// regardless of entry type.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::QuotaExceeded`] if recording this hardlink
    /// would exceed `max_file_size`, `max_file_count`, or `max_total_size`.
    pub(crate) fn reserve_hardlink(&mut self, size: u64) -> Result<QuotaPermit> {
        self.quota_tracker.reserve(size, self.config)
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
    use std::assert_matches;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_entry_validator_new() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default().validate().expect("valid config");
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
        let config = SecurityConfig::default().validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);

        let result = validator.validate_entry(
            Path::new("file.txt"),
            &EntryType::File,
            1024,
            None,
            Some(0o644),
            None,
        );

        assert!(result.is_ok());
        let entry = result.unwrap();
        assert_eq!(entry.safe_path.as_path(), Path::new("file.txt"));
        assert_matches!(entry.entry_type, ValidatedEntryType::File(_));
        assert_eq!(entry.mode.map(SanitizedMode::as_u32), Some(0o644));
    }

    #[test]
    fn test_validate_directory_entry() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default().validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);

        let result =
            validator.validate_entry(Path::new("dir"), &EntryType::Directory, 0, None, None, None);

        assert!(result.is_ok());
        let entry = result.unwrap();
        assert_matches!(entry.entry_type, ValidatedEntryType::Directory);
        assert!(entry.mode.is_none());
    }

    #[test]
    fn test_validate_path_traversal_rejected() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default().validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);

        let result = validator.validate_entry(
            Path::new("../etc/passwd"),
            &EntryType::File,
            1024,
            None,
            Some(0o644),
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_quota_exceeded_file_size() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.max_file_size = 100;
        let config = config.validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);

        let result = validator.validate_entry(
            Path::new("large.txt"),
            &EntryType::File,
            1000,
            None,
            Some(0o644),
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_quota_exceeded_file_count() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.max_file_count = 2;
        let config = config.validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);

        assert!(
            validator
                .validate_entry(
                    Path::new("file1.txt"),
                    &EntryType::File,
                    100,
                    None,
                    Some(0o644),
                    None,
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
                    Some(0o644),
                    None,
                )
                .is_ok()
        );

        let result = validator.validate_entry(
            Path::new("file3.txt"),
            &EntryType::File,
            100,
            None,
            Some(0o644),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_zip_bomb_detected() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default().validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);

        let result = validator.validate_entry(
            Path::new("bomb.txt"),
            &EntryType::File,
            1_000_000,
            Some(100),
            Some(0o644),
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_validation_report() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default().validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);

        validator
            .validate_entry(
                Path::new("file1.txt"),
                &EntryType::File,
                1024,
                None,
                Some(0o644),
                None,
            )
            .unwrap();

        validator
            .validate_entry(
                Path::new("file2.txt"),
                &EntryType::File,
                2048,
                None,
                Some(0o644),
                None,
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
        let config = SecurityConfig::default().validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);

        let result = validator.validate_entry(
            Path::new("file.txt"),
            &EntryType::File,
            1024,
            None,
            Some(0o4755),
            None,
        );

        assert!(result.is_ok());
        let entry = result.unwrap();
        assert_eq!(entry.mode.map(SanitizedMode::as_u32), Some(0o755)); // setuid stripped
    }

    #[test]
    fn test_symlink_validation() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = true;
        let config = config.validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);

        let result = validator.validate_entry(
            Path::new("link"),
            &EntryType::Symlink {
                target: PathBuf::from("target.txt"),
            },
            0,
            None,
            None,
            None,
        );

        assert!(result.is_ok());
        let entry = result.unwrap();
        assert_matches!(entry.entry_type, ValidatedEntryType::Symlink(_));
        assert!(validator.symlink_seen);
    }

    #[test]
    fn test_hardlink_validation() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        let config = config.validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);

        let result = validator.validate_entry(
            Path::new("link"),
            &EntryType::Hardlink {
                target: PathBuf::from("target.txt"),
            },
            0,
            None,
            None,
            None,
        );

        assert!(result.is_ok());
        let entry = result.unwrap();
        assert_matches!(entry.entry_type, ValidatedEntryType::Hardlink { .. });
    }

    #[test]
    fn test_multiple_entries_with_report() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        let config = config.validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);

        // Validate multiple entry types
        validator
            .validate_entry(
                Path::new("file1.txt"),
                &EntryType::File,
                1024,
                None,
                Some(0o644),
                None,
            )
            .unwrap();

        validator
            .validate_entry(Path::new("dir"), &EntryType::Directory, 0, None, None, None)
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
        let config = SecurityConfig::default().validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);

        // Empty directory should be valid
        let result = validator.validate_entry(
            Path::new("empty_dir/"),
            &EntryType::Directory,
            0,
            None,
            None,
            None,
        );

        assert!(result.is_ok(), "empty directory should be valid");
        let entry = result.unwrap();
        assert_matches!(
            entry.entry_type,
            ValidatedEntryType::Directory,
            "should be directory type"
        );
        assert!(entry.mode.is_none(), "directory should not have mode set");
    }

    #[test]
    fn test_nested_empty_directories() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default().validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);

        // Multiple nested empty directories
        let dirs = ["a/", "a/b/", "a/b/c/"];
        for dir in &dirs {
            let result = validator.validate_entry(
                Path::new(dir),
                &EntryType::Directory,
                0,
                None,
                None,
                None,
            );
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
        let config = SecurityConfig::default().validate().expect("valid config");

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
        let config = SecurityConfig::default().validate().expect("valid config");

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
            None,
        );
        assert!(result1.is_ok());

        let result2 = validator2.validate_entry(
            Path::new("file2.txt"),
            &EntryType::File,
            2048,
            None,
            Some(0o644),
            None,
        );
        assert!(result2.is_ok());

        // Config is still accessible
        assert_eq!(
            config.max_file_size,
            SecurityConfig::default().max_file_size
        );
    }

    #[test]
    fn test_validate_entry_with_dir_cache() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default().validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);

        let sub = dest.as_path().join("subdir");
        let mut dir_cache = DirCache::new();
        dir_cache.ensure_dir(&sub).expect("should create dir");

        let result = validator.validate_entry(
            Path::new("subdir/file.txt"),
            &EntryType::File,
            100,
            None,
            Some(0o644),
            Some(&dir_cache),
        );
        assert!(
            result.is_ok(),
            "entry with dir_cache should validate: {result:?}"
        );
    }

    #[test]
    fn test_symlink_seen_flag_propagates() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = true;
        let config = config.validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);

        assert!(!validator.symlink_seen);

        // Validate a symlink entry
        validator
            .validate_entry(
                Path::new("link"),
                &EntryType::Symlink {
                    target: PathBuf::from("target.txt"),
                },
                0,
                None,
                None,
                None,
            )
            .unwrap();

        assert!(validator.symlink_seen);
    }

    // Issue #426: hardlink quota bypass regression tests.

    #[test]
    fn test_reserve_hardlink_exceeding_max_file_size_rejected() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.max_file_size = 100;
        let config = config.validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);

        // A single hardlink whose on-disk target size alone exceeds
        // max_file_size must be rejected, exactly like an oversized regular
        // file would be.
        let result = validator.reserve_hardlink(1_000);

        assert_matches!(
            result,
            Err(crate::ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::FileSize { .. }
            }),
            "hardlink exceeding max_file_size must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn test_reserve_hardlink_shares_quota_tracker_with_files() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        config.max_total_size = 250;
        let config = config.validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);

        // A regular file consumes part of the shared total-size budget...
        validator
            .validate_entry(
                Path::new("file1.txt"),
                &EntryType::File,
                100,
                None,
                Some(0o644),
                None,
            )
            .unwrap();

        // ...and a hardlink recorded afterwards must be charged against the
        // same tracker, not a separate/untracked counter.
        assert!(validator.reserve_hardlink(100).is_ok());

        let result = validator.reserve_hardlink(100);
        assert_matches!(
            result,
            Err(crate::ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::TotalSize { .. }
            }),
            "hardlink bytes must accumulate on the same tracker as file bytes \
             (200 already recorded + 100 more exceeds the 250 budget), got: {result:?}"
        );
    }

    #[test]
    fn test_reserve_hardlink_exceeding_max_file_count() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.max_file_count = 2;
        let config = config.validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);

        assert!(validator.reserve_hardlink(1).is_ok());
        assert!(validator.reserve_hardlink(1).is_ok());

        let result = validator.reserve_hardlink(1);
        assert_matches!(
            result,
            Err(crate::ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::FileCount { .. }
            }),
            "hardlink count alone exceeding max_file_count must be rejected, got: {result:?}"
        );
    }
}
