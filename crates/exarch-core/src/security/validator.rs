//! Entry validation orchestrator.
//!
//! This module provides the main `EntryValidator` type that coordinates all
//! security validations for archive entries.

use std::path::Path;

use crate::ArchiveError;
use crate::Result;
use crate::SecurityConfig;
use crate::config::Validated;
use crate::formats::common::DirCache;
use crate::security::context::ValidationContext;
use crate::security::hardlink::HardlinkTracker;
use crate::security::hardlink::require_hardlinks_allowed;
use crate::security::permissions::SanitizedMode;
use crate::security::permissions::sanitize_permissions;
use crate::security::quota::EntryCount;
use crate::security::quota::QuotaPermit;
use crate::security::quota::QuotaTracker;
use crate::security::symlink::validate_symlink;
use crate::security::zipbomb::validate_compression_ratio;
use crate::types::DestDir;
use crate::types::EntryType;
use crate::types::SafePath;
use crate::types::SafeSymlink;
use crate::types::safe_path::EMPTY_PATH_REASON;
use crate::types::safe_symlink::require_symlinks_allowed;

/// Whether an archive entry is a directory, as the root-entry rule sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeKind {
    /// The entry is a directory (or stands for one, like ZIP's empty root
    /// file).
    Directory,
    /// Any other entry: file, symlink, hardlink.
    NonDirectory,
}

impl NodeKind {
    /// Converts a format's directory flag at the boundary, so the rule itself
    /// never takes a bare `bool`.
    pub(crate) const fn directory_if(is_directory: bool) -> Self {
        if is_directory {
            Self::Directory
        } else {
            Self::NonDirectory
        }
    }
}

/// An archive entry name, split into the archive root and everything else.
///
/// The root (`.`, `./`) names the destination itself, so it must not be taken
/// for an ordinary path: handlers have to match on the variant. `P` is the
/// path as carried at that stage (`&Path` for a raw name, `SafePath` once
/// validated).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryPath<P> {
    /// The destination itself (`.`, `./`).
    Root(P),
    /// Any path below the destination.
    Child(P),
}

impl<'a> EntryPath<&'a Path> {
    /// Classifies a raw entry name; the single definition of "root" for names
    /// not yet validated.
    pub(crate) fn of(path: &'a Path) -> Self {
        if path == Path::new(".") {
            Self::Root(path)
        } else {
            Self::Child(path)
        }
    }
}

impl<P> EntryPath<P> {
    /// Whether this is the root; for tests and callers that only need to know
    /// that, not to act on the path.
    pub(crate) const fn is_root(&self) -> bool {
        matches!(self, Self::Root(_))
    }

    /// The path, for callers that treat the root like any directory.
    pub(crate) fn into_inner(self) -> P {
        match self {
            Self::Root(path) | Self::Child(path) => path,
        }
    }

    /// Rejects a root entry that is not a directory.
    ///
    /// A file, symlink or hardlink standing for the root would be written
    /// onto, or remove, the destination. Shared by entry validation and
    /// listing so `extract`, `list` and `verify` agree.
    pub(crate) fn require_directory_root(self, kind: NodeKind) -> Result<Self> {
        if self.is_root() && kind == NodeKind::NonDirectory {
            return Err(ArchiveError::violation(
                "archive root entry '.' must be a directory".into(),
            ));
        }
        Ok(self)
    }
}

/// Rejects a root entry that is not a directory, for the TAR extractor, which
/// checks the raw name before its extension filter.
pub(crate) fn check_root_entry_is_directory(path: &Path, kind: NodeKind) -> Result<()> {
    EntryPath::of(path).require_directory_root(kind).map(drop)
}

/// Rejects an empty entry name, so listing fails on the name that extraction
/// and `verify` refuse, instead of joining it onto the destination directory.
pub(crate) fn require_non_empty_name(path: &Path) -> Result<()> {
    if path.is_empty() {
        return Err(ArchiveError::violation(EMPTY_PATH_REASON.into()));
    }
    Ok(())
}

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
    #[non_exhaustive]
    Hardlink {
        /// Target path (already validated)
        target: SafePath,
        /// Proof the hardlink was counted against `max_file_count` in the
        /// first pass; the second pass spends it to charge the copied bytes.
        counted: EntryCount,
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
    /// 2. Quota checking (file size, count, total size) — files and symlinks; a
    ///    hardlink is counted here and charged its bytes in the second pass.
    ///    Directories are not counted
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
    /// - `ArchiveError::SecurityViolation` - Root entry (`.`) that is not a
    ///   directory. This is a backstop for formats that reach here without an
    ///   earlier check; TAR checks first, in `process_entry`, so the root is
    ///   rejected before the extension filter can skip it.
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
        let kind = NodeKind::directory_if(matches!(entry_type, EntryType::Directory));
        let safe_path = self
            .validate_entry_path(path, kind, dir_cache)?
            .into_inner();

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
                require_symlinks_allowed(self.config)?;
                self.reserve_symlink(uncompressed_size)?;
                let safe_symlink = validate_symlink(&safe_path, target, self.dest, self.config)?;
                self.symlink_seen = true;
                (ValidatedEntryType::Symlink(safe_symlink), None)
            }

            EntryType::Hardlink { target } => {
                self.check_ratio(compressed_size, uncompressed_size)?;
                require_hardlinks_allowed(self.config)?;
                let counted = self.quota_tracker.reserve_count(self.config)?;

                // Hardlink tracker validates: absolute paths, traversal,
                // normalization, escapes
                self.hardlink_tracker.validate_hardlink(
                    &safe_path,
                    target,
                    self.dest,
                    self.config,
                )?;

                // SAFETY: validate_hardlink verified target is relative,
                // normalized, within dest
                let target_safe = SafePath::new_unchecked(target.clone());

                (
                    ValidatedEntryType::Hardlink {
                        target: target_safe,
                        counted,
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
    /// or another path-validation error if `path` fails validation, and
    /// [`ArchiveError::SecurityViolation`](crate::ArchiveError::SecurityViolation)
    /// for a root entry (`.`) whose `kind` is not a directory.
    pub(crate) fn validate_entry_path(
        &self,
        path: &Path,
        kind: NodeKind,
        dir_cache: Option<&DirCache>,
    ) -> Result<EntryPath<SafePath>> {
        let entry_path = EntryPath::of(path).require_directory_root(kind)?;
        let mut ctx = ValidationContext::new(self.config.allowed.symlinks);
        if let Some(cache) = dir_cache {
            ctx = ctx.with_dir_cache(cache);
        }
        if self.symlink_seen {
            ctx.mark_symlink_seen();
        }

        let validate = |path| SafePath::validate_with_context(path, self.dest, self.config, &ctx);
        match entry_path {
            EntryPath::Root(path) => validate(path).map(EntryPath::Root),
            EntryPath::Child(path) => validate(path).map(EntryPath::Child),
        }
    }

    /// Reserves quota capacity for a regular file's byte count, independent
    /// of path validation.
    ///
    /// Mirrors [`charge_hardlink`](Self::charge_hardlink), which exists for
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
    pub(crate) fn check_ratio(
        &self,
        compressed_size: Option<u64>,
        uncompressed_size: u64,
    ) -> Result<()> {
        if let Some(compressed) = compressed_size {
            validate_compression_ratio(compressed, uncompressed_size, self.config)?;
        }
        Ok(())
    }

    /// Reserves quota capacity for a symlink, charging its stored size the way
    /// `list` and `verify` do.
    ///
    /// Counts the symlink against `max_file_count` so a link flood is bounded
    /// like a file flood. The permit is discarded: no writer consumes one for a
    /// link.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::QuotaExceeded`] if recording the link would
    /// exceed `max_file_size`, `max_file_count`, or `max_total_size`.
    pub(crate) fn reserve_symlink(&mut self, size: u64) -> Result<()> {
        self.quota_tracker.reserve(size, self.config).map(drop)
    }

    /// Charges a hardlink's copied byte count against the shared quota tracker,
    /// returning a capability token that proves the charge succeeded.
    ///
    /// The hardlink was already counted against `max_file_count` in the first
    /// pass (`validate_entry`), which is what `counted` proves; its size is
    /// only known once the target file exists on disk, in the second pass. This
    /// routes that size through the same `QuotaTracker` used for regular files,
    /// so `max_file_size` and `max_total_size` are enforced uniformly
    /// regardless of entry type, without counting the entry twice.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::QuotaExceeded`] if the copy would exceed
    /// `max_file_size` or `max_total_size`.
    pub(crate) fn charge_hardlink(
        &mut self,
        counted: EntryCount,
        size: u64,
    ) -> Result<QuotaPermit> {
        self.quota_tracker.charge(counted, size, self.config)
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
    /// Number of entries counted against `max_file_count`: files, symlinks and
    /// hardlinks (directories are not counted)
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
    fn test_entry_path_of_splits_root_from_child() {
        for root in [".", "./", "./."] {
            assert!(EntryPath::of(Path::new(root)).is_root(), "{root:?}");
        }
        assert_eq!(
            EntryPath::of(Path::new("a/b")),
            EntryPath::Child(Path::new("a/b"))
        );
    }

    #[test]
    fn test_root_requires_directory() {
        let root = EntryPath::of(Path::new("."));
        assert!(root.require_directory_root(NodeKind::Directory).is_ok());
        assert_matches!(
            root.require_directory_root(NodeKind::NonDirectory),
            Err(ArchiveError::SecurityViolation { .. })
        );
        let child = EntryPath::of(Path::new("a"));
        assert!(child.require_directory_root(NodeKind::NonDirectory).is_ok());
    }

    #[test]
    fn test_validate_entry_path_returns_root_for_directory_and_rejects_file() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
        let config = SecurityConfig::default().validate().expect("valid config");
        let validator = EntryValidator::new(&config, &dest);

        let root = validator
            .validate_entry_path(Path::new("."), NodeKind::Directory, None)
            .expect("root directory");
        assert!(root.is_root());
        assert_matches!(
            validator.validate_entry_path(Path::new("."), NodeKind::NonDirectory, None),
            Err(ArchiveError::SecurityViolation { .. })
        );
        let child = validator
            .validate_entry_path(Path::new("a.txt"), NodeKind::NonDirectory, None)
            .expect("child");
        assert!(!child.is_root());
    }

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
        assert_eq!(report.files_validated, 2); // File and hardlink; directories are not counted
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
        // Note: dest.as_path() may be canonicalized on macOS (/var vs
        // /private/var) Just verify dest is still accessible
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

    fn validate_hardlink_entry(
        validator: &mut EntryValidator<'_>,
        name: &str,
    ) -> crate::Result<EntryCount> {
        let entry = validator.validate_entry(
            Path::new(name),
            &EntryType::Hardlink {
                target: PathBuf::from("target.txt"),
            },
            0,
            None,
            None,
            None,
        )?;
        match entry.into_parts() {
            (_, ValidatedEntryType::Hardlink { counted, .. }, _) => Ok(counted),
            other => panic!("expected a hardlink, got {other:?}"),
        }
    }

    fn validate_symlink_entry(
        validator: &mut EntryValidator<'_>,
        name: &str,
    ) -> crate::Result<ValidatedEntry> {
        validator.validate_entry(
            Path::new(name),
            &EntryType::Symlink {
                target: PathBuf::from("target.txt"),
            },
            0,
            None,
            None,
            None,
        )
    }

    #[test]
    fn test_charge_hardlink_exceeding_max_file_size_rejected() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        config.max_file_size = 100;
        let config = config.validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);

        let counted = validate_hardlink_entry(&mut validator, "link").unwrap();
        let result = validator.charge_hardlink(counted, 1_000);

        assert_matches!(
            result,
            Err(crate::ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::FileSize { .. }
            }),
            "hardlink exceeding max_file_size must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn test_charge_hardlink_shares_quota_tracker_with_files() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        config.max_total_size = 250;
        let config = config.validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);

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

        let first = validate_hardlink_entry(&mut validator, "link1").unwrap();
        let second = validate_hardlink_entry(&mut validator, "link2").unwrap();
        assert!(validator.charge_hardlink(first, 100).is_ok());

        let result = validator.charge_hardlink(second, 100);
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
    fn test_hardlink_counted_once_in_pass_one() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;
        config.max_file_count = 2;
        let config = config.validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);

        let first = validate_hardlink_entry(&mut validator, "link1").unwrap();
        let second = validate_hardlink_entry(&mut validator, "link2").unwrap();

        let result = validate_hardlink_entry(&mut validator, "link3");
        assert_matches!(
            result,
            Err(crate::ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::FileCount { .. }
            }),
            "the third hardlink must exceed max_file_count in pass one, got: {result:?}"
        );

        assert!(validator.charge_hardlink(first, 1).is_ok());
        assert!(validator.charge_hardlink(second, 1).is_ok());
        assert_eq!(validator.finish().files_validated, 3);
    }

    #[test]
    fn test_symlink_exceeding_max_file_count_rejected() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = true;
        config.max_file_count = 2;
        let config = config.validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);

        assert!(validate_symlink_entry(&mut validator, "l1").is_ok());
        assert!(validate_symlink_entry(&mut validator, "l2").is_ok());

        let result = validate_symlink_entry(&mut validator, "l3");
        assert_matches!(
            result,
            Err(crate::ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::FileCount { .. }
            }),
            "symlinks must count against max_file_count, got: {result:?}"
        );
    }

    #[test]
    fn test_symlink_policy_error_wins_over_file_count() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.max_file_count = 1;
        let config = config.validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);
        validator
            .validate_entry(Path::new("f"), &EntryType::File, 1, None, None, None)
            .unwrap();

        let result = validate_symlink_entry(&mut validator, "l1");
        assert_matches!(
            result,
            Err(crate::ArchiveError::SecurityViolation { ref reason, .. })
                if reason == "symlinks not allowed",
            "got: {result:?}"
        );
    }

    #[test]
    fn test_hardlink_policy_error_wins_over_file_count() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.max_file_count = 1;
        let config = config.validate().expect("valid config");
        let mut validator = EntryValidator::new(&config, &dest);
        validator
            .validate_entry(Path::new("f"), &EntryType::File, 1, None, None, None)
            .unwrap();

        let result = validate_hardlink_entry(&mut validator, "l1");
        assert_matches!(
            result,
            Err(crate::ArchiveError::SecurityViolation { ref reason, .. })
                if reason == "hardlinks not allowed",
            "got: {result:?}"
        );
    }
}
