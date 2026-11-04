//! Entry validation orchestrator.
//!
//! This module provides the main `EntryValidator` type that coordinates all
//! security validations for archive entries.

use std::path::Path;

use crate::ArchiveError;
use crate::Result;
use crate::SecurityConfig;
use crate::Violation;
use crate::formats::common::check_entry_name_limits;
use crate::formats::common::is_extension_allowed;
use crate::security::admitted::EntrySize;
use crate::security::admitted::PendingFile;
use crate::security::admitted::ValidatedFile;
use crate::security::admitted::ValidatedHardlink;
use crate::security::admitted::ValidatedSymlink;
use crate::security::context::ValidationContext;
use crate::security::fs_view::FsView;
use crate::security::fs_view::HostFs;
use crate::security::hardlink::HardlinkTarget;
use crate::security::hardlink::HardlinkTracker;
use crate::security::hardlink::require_hardlinks_allowed;
use crate::security::permissions::RawMode;
use crate::security::permissions::SanitizedMode;
use crate::security::quota::EntryCount;
use crate::security::quota::QuotaPermit;
use crate::security::quota::QuotaTracker;
use crate::types::DestDir;
use crate::types::EntryType;
use crate::types::SafePath;
use crate::types::SafeSymlink;
use crate::types::safe_path::ParentCheck;
use crate::types::safe_path::Resolved;
use crate::types::safe_symlink::require_symlinks_allowed;

/// Refuses an entry name `view`'s path model cannot hold, so `extract` agrees
/// with `list` and `verify` on an overlong path.
fn check_name_limits<V: FsView, P: ParentCheck>(
    view: &V,
    path: &SafePath<P>,
    regular_file: bool,
    config: &SecurityConfig,
) -> Result<()> {
    check_entry_name_limits(view.path_model(), path.as_path(), regular_file, config)
        .map_err(ArchiveError::Io)
}

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
            return Err(Violation::RootEntryNotDirectory.into());
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
        return Err(Violation::EmptyPath.into());
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
///   [`HardlinkTarget`], which are independently sealed and can only be
///   produced by their own validation routines, so even crate-internal code
///   cannot forge a "validated" symlink/hardlink target.
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
        target: HardlinkTarget,
        /// Proof the hardlink was counted against `max_file_count` in the
        /// first pass; the second pass spends it to charge the copied bytes.
        counted: EntryCount,
    },
}

/// What path validation and the extension allowlist decide about a file, before
/// any quota is charged.
pub(crate) enum FileScreen<P: ParentCheck = Resolved> {
    /// The file is to be extracted once its quota is reserved.
    Pending(PendingFile<P>),
    /// The extension allowlist excludes the file; extraction skips it.
    DisallowedExtension,
}

/// The validation state and rules shared by every extraction target: quota,
/// hardlink and symlink tracking plus the per-entry checks.
///
/// It holds neither a root nor a view. Both are passed per call, tied by
/// [`FsView::Root`], so a target can mutate its view between validations and a
/// root can never be paired with the wrong view.
pub(crate) struct ValidatorCore<'a> {
    config: &'a SecurityConfig,
    quota_tracker: QuotaTracker,
    hardlink_tracker: HardlinkTracker,
    symlink_seen: bool,
}

impl<'a> ValidatorCore<'a> {
    pub(crate) fn new(config: &'a SecurityConfig) -> Self {
        Self {
            config,
            quota_tracker: QuotaTracker::new(),
            hardlink_tracker: HardlinkTracker::new(),
            symlink_seen: false,
        }
    }

    /// A context reflecting the symlinks seen so far; build a fresh one for
    /// every entry.
    pub(crate) fn context<'r, V: FsView>(&self) -> ValidationContext<'r, V> {
        let mut ctx = ValidationContext::new(self.config.allowed.symlinks.is_allowed());
        if self.symlink_seen {
            ctx.mark_symlink_seen();
        }
        ctx
    }

    /// See [`EntryValidator::validate_entry`].
    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors the public validate_entry plus the root, view and context"
    )]
    pub(crate) fn validate_entry_in<V: FsView>(
        &mut self,
        path: &Path,
        entry_type: &EntryType,
        size: EntrySize,
        mode: Option<RawMode>,
        root: &V::Root,
        view: &V,
        ctx: &ValidationContext<'_, V>,
    ) -> Result<ValidatedEntry> {
        match entry_type {
            EntryType::File => {
                let file = self.validate_file_in(path, size, mode, root, view, ctx)?;
                let (safe_path, permit, mode) = file.into_parts();
                Ok(ValidatedEntry::new(
                    safe_path,
                    ValidatedEntryType::File(permit),
                    mode,
                ))
            }
            EntryType::Directory => {
                let safe_path = self.validate_directory_in(path, size, root, view, ctx)?;
                Ok(ValidatedEntry::new(
                    safe_path,
                    ValidatedEntryType::Directory,
                    None,
                ))
            }
            EntryType::Symlink { target } => {
                let symlink = self.validate_symlink_in(path, target, size, root, view, ctx)?;
                Ok(ValidatedEntry::new(
                    symlink.link,
                    ValidatedEntryType::Symlink(symlink.symlink),
                    None,
                ))
            }
            EntryType::Hardlink { target } => {
                let link = self.validate_hardlink_in(path, target, size, root, view, ctx)?;
                Ok(ValidatedEntry::new(
                    link.link,
                    ValidatedEntryType::Hardlink {
                        target: link.target,
                        counted: link.counted,
                    },
                    None,
                ))
            }
        }
    }

    /// Validates a regular file: path, quota reservation, ratio and mode.
    pub(crate) fn validate_file_in<V: FsView, P: ParentCheck>(
        &mut self,
        path: &Path,
        size: EntrySize,
        mode: Option<RawMode>,
        root: &V::Root,
        view: &V,
        ctx: &ValidationContext<'_, V, P>,
    ) -> Result<ValidatedFile<P>> {
        let pending = self.pending_file_in(path, size, mode, root, view, ctx)?;
        check_name_limits(view, pending.path(), true, self.config)?;
        self.admit_file(pending)
    }

    /// Validates a file's path, then applies the extension allowlist, ahead of
    /// any quota.
    ///
    /// The path comes first, so a disallowed entry named `../x.bin` is
    /// refused rather than skipped. This is the one place the allowlist rule
    /// is applied to extraction.
    pub(crate) fn screen_file_path_in<V: FsView, P: ParentCheck>(
        &self,
        path: &Path,
        size: EntrySize,
        mode: Option<RawMode>,
        root: &V::Root,
        view: &V,
        ctx: &ValidationContext<'_, V, P>,
    ) -> Result<FileScreen<P>> {
        let pending = self.pending_file_in(path, size, mode, root, view, ctx)?;
        if is_extension_allowed(path, self.config) {
            check_name_limits(view, pending.path(), true, self.config)?;
            Ok(FileScreen::Pending(pending))
        } else {
            Ok(FileScreen::DisallowedExtension)
        }
    }

    /// Reserves the quota of a screened file, checks its ratio and sanitizes
    /// its mode.
    pub(crate) fn admit_file<P: ParentCheck>(
        &mut self,
        pending: PendingFile<P>,
    ) -> Result<ValidatedFile<P>> {
        pending.admit(&mut self.quota_tracker, self.config)
    }

    fn pending_file_in<V: FsView, P: ParentCheck>(
        &self,
        path: &Path,
        size: EntrySize,
        mode: Option<RawMode>,
        root: &V::Root,
        view: &V,
        ctx: &ValidationContext<'_, V, P>,
    ) -> Result<PendingFile<P>> {
        let safe_path = self
            .validate_entry_path_in(path, NodeKind::NonDirectory, root, view, ctx)?
            .into_inner();
        Ok(PendingFile::new(safe_path, size, mode))
    }

    /// Validates a directory entry: path and ratio.
    pub(crate) fn validate_directory_in<V: FsView, P: ParentCheck>(
        &self,
        path: &Path,
        size: EntrySize,
        root: &V::Root,
        view: &V,
        ctx: &ValidationContext<'_, V, P>,
    ) -> Result<SafePath<P>> {
        let safe_path = self
            .validate_entry_path_in(path, NodeKind::Directory, root, view, ctx)?
            .into_inner();
        check_name_limits(view, &safe_path, false, self.config)?;
        size.check_ratio(self.config)?;
        Ok(safe_path)
    }

    /// Validates a symlink entry: path, ratio, policy, quota and target.
    pub(crate) fn validate_symlink_in<V: FsView, P: ParentCheck>(
        &mut self,
        path: &Path,
        target: &Path,
        size: EntrySize,
        root: &V::Root,
        view: &V,
        ctx: &ValidationContext<'_, V, P>,
    ) -> Result<ValidatedSymlink<P>> {
        let safe_path = self
            .validate_entry_path_in(path, NodeKind::NonDirectory, root, view, ctx)?
            .into_inner();
        check_name_limits(view, &safe_path, false, self.config)?;
        size.check_ratio(self.config)?;
        require_symlinks_allowed(self.config)?;
        self.reserve_symlink(size.uncompressed.0)?;
        let symlink = SafeSymlink::validate_in(&safe_path, target, root, self.config, view)?;
        self.symlink_seen = true;
        Ok(ValidatedSymlink {
            link: safe_path,
            symlink,
        })
    }

    /// Validates a hardlink entry: path, ratio, policy, count and target.
    pub(crate) fn validate_hardlink_in<V: FsView, P: ParentCheck>(
        &mut self,
        path: &Path,
        target: &Path,
        size: EntrySize,
        root: &V::Root,
        view: &V,
        ctx: &ValidationContext<'_, V, P>,
    ) -> Result<ValidatedHardlink<P>> {
        let safe_path = self
            .validate_entry_path_in(path, NodeKind::NonDirectory, root, view, ctx)?
            .into_inner();
        check_name_limits(view, &safe_path, false, self.config)?;
        size.check_ratio(self.config)?;
        require_hardlinks_allowed(self.config)?;
        let counted = self.quota_tracker.reserve_count(self.config)?;

        let target = self.hardlink_tracker.validate_hardlink_in(
            &safe_path,
            target,
            root,
            self.config,
            view,
        )?;

        Ok(ValidatedHardlink {
            link: safe_path,
            target,
            counted,
        })
    }

    /// See [`EntryValidator::validate_entry_path`].
    pub(crate) fn validate_entry_path_in<V: FsView, P: ParentCheck>(
        &self,
        path: &Path,
        kind: NodeKind,
        root: &V::Root,
        view: &V,
        ctx: &ValidationContext<'_, V, P>,
    ) -> Result<EntryPath<SafePath<P>>> {
        let entry_path = EntryPath::of(path).require_directory_root(kind)?;
        let validate =
            |path| SafePath::validate_with_context_in(path, root, self.config, ctx, view);
        match entry_path {
            EntryPath::Root(path) => validate(path).map(EntryPath::Root),
            EntryPath::Child(path) => validate(path).map(EntryPath::Child),
        }
    }

    pub(crate) fn reserve_file(&mut self, size: u64) -> Result<QuotaPermit> {
        self.quota_tracker.reserve(size, self.config)
    }

    pub(crate) fn reserve_symlink(&mut self, size: u64) -> Result<()> {
        self.quota_tracker.reserve(size, self.config).map(drop)
    }

    pub(crate) fn charge_hardlink(
        &mut self,
        counted: EntryCount,
        size: u64,
    ) -> Result<QuotaPermit> {
        self.quota_tracker.charge(counted, size, self.config)
    }

    pub(crate) fn finish(self) -> ValidationReport {
        ValidationReport {
            files_validated: self.quota_tracker.files_extracted(),
            total_bytes: self.quota_tracker.bytes_written(),
            hardlinks_tracked: self.hardlink_tracker.count(),
        }
    }
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
/// use exarch_core::security::Compressed;
/// use exarch_core::security::EntrySize;
/// use exarch_core::security::EntryValidator;
/// use exarch_core::security::RawMode;
/// use exarch_core::security::Uncompressed;
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
///     EntrySize::new(Uncompressed(1024), Some(Compressed(512))),
///     Some(RawMode::new(0o644)),
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
    core: ValidatorCore<'a>,
    dest: &'a DestDir,
}

impl<'a> EntryValidator<'a> {
    /// Creates a new entry validator with the given security configuration.
    #[must_use]
    pub fn new(config: &'a SecurityConfig, dest: &'a DestDir) -> Self {
        Self {
            core: ValidatorCore::new(config),
            dest,
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
        size: EntrySize,
        mode: Option<RawMode>,
    ) -> Result<ValidatedEntry> {
        let ctx = self.core.context::<HostFs>();
        self.core
            .validate_entry_in(path, entry_type, size, mode, self.dest, &HostFs, &ctx)
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
    #[cfg(test)]
    pub(crate) fn charge_hardlink(
        &mut self,
        counted: EntryCount,
        size: u64,
    ) -> Result<QuotaPermit> {
        self.core.charge_hardlink(counted, size)
    }

    /// Finishes validation and returns a summary report.
    ///
    /// This consumes the validator and returns statistics about the
    /// validation process.
    #[must_use]
    pub fn finish(self) -> ValidationReport {
        self.core.finish()
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
    use crate::security::Compressed;
    use crate::security::Uncompressed;
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
            Err(crate::ArchiveError::SecurityViolation { .. })
        );
        let child = EntryPath::of(Path::new("a"));
        assert!(child.require_directory_root(NodeKind::NonDirectory).is_ok());
    }

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
            EntrySize::new(Uncompressed(1024), None),
            Some(RawMode::new(0o644)),
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
        let config = SecurityConfig::default();
        let mut validator = EntryValidator::new(&config, &dest);

        let result = validator.validate_entry(
            Path::new("dir"),
            &EntryType::Directory,
            EntrySize::new(Uncompressed(0), None),
            None,
        );

        assert!(result.is_ok());
        let entry = result.unwrap();
        assert_matches!(entry.entry_type, ValidatedEntryType::Directory);
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
            EntrySize::new(Uncompressed(1024), None),
            Some(RawMode::new(0o644)),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_quota_exceeded_file_size() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.max_file_size = crate::Limit::Bounded(crate::non_zero!(100));
        let mut validator = EntryValidator::new(&config, &dest);

        let result = validator.validate_entry(
            Path::new("large.txt"),
            &EntryType::File,
            EntrySize::new(Uncompressed(1000), None),
            Some(RawMode::new(0o644)),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_quota_exceeded_file_count() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.max_file_count = crate::Limit::Bounded(crate::non_zero!(2));
        let mut validator = EntryValidator::new(&config, &dest);

        assert!(
            validator
                .validate_entry(
                    Path::new("file1.txt"),
                    &EntryType::File,
                    EntrySize::new(Uncompressed(100), None),
                    Some(RawMode::new(0o644))
                )
                .is_ok()
        );
        assert!(
            validator
                .validate_entry(
                    Path::new("file2.txt"),
                    &EntryType::File,
                    EntrySize::new(Uncompressed(100), None),
                    Some(RawMode::new(0o644))
                )
                .is_ok()
        );

        let result = validator.validate_entry(
            Path::new("file3.txt"),
            &EntryType::File,
            EntrySize::new(Uncompressed(100), None),
            Some(RawMode::new(0o644)),
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
            EntrySize::new(Uncompressed(1_000_000), Some(Compressed(100))),
            Some(RawMode::new(0o644)),
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
                EntrySize::new(Uncompressed(1024), None),
                Some(RawMode::new(0o644)),
            )
            .unwrap();

        validator
            .validate_entry(
                Path::new("file2.txt"),
                &EntryType::File,
                EntrySize::new(Uncompressed(2048), None),
                Some(RawMode::new(0o644)),
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
            EntrySize::new(Uncompressed(1024), None),
            Some(RawMode::new(0o4755)),
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
        config.allowed.symlinks = crate::Admit::Allow;
        let mut validator = EntryValidator::new(&config, &dest);

        let result = validator.validate_entry(
            Path::new("link"),
            &EntryType::Symlink {
                target: PathBuf::from("target.txt"),
            },
            EntrySize::new(Uncompressed(0), None),
            None,
        );

        assert!(result.is_ok());
        let entry = result.unwrap();
        assert_matches!(entry.entry_type, ValidatedEntryType::Symlink(_));
        assert!(validator.core.symlink_seen);
    }

    #[test]
    fn test_hardlink_validation() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;
        let mut validator = EntryValidator::new(&config, &dest);

        let result = validator.validate_entry(
            Path::new("link"),
            &EntryType::Hardlink {
                target: PathBuf::from("target.txt"),
            },
            EntrySize::new(Uncompressed(0), None),
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
        config.allowed.hardlinks = crate::Admit::Allow;
        let mut validator = EntryValidator::new(&config, &dest);

        // Validate multiple entry types
        validator
            .validate_entry(
                Path::new("file1.txt"),
                &EntryType::File,
                EntrySize::new(Uncompressed(1024), None),
                Some(RawMode::new(0o644)),
            )
            .unwrap();

        validator
            .validate_entry(
                Path::new("dir"),
                &EntryType::Directory,
                EntrySize::new(Uncompressed(0), None),
                None,
            )
            .unwrap();

        validator
            .validate_entry(
                Path::new("hardlink"),
                &EntryType::Hardlink {
                    target: PathBuf::from("file1.txt"),
                },
                EntrySize::new(Uncompressed(0), None),
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
        let config = SecurityConfig::default();
        let mut validator = EntryValidator::new(&config, &dest);

        // Empty directory should be valid
        let result = validator.validate_entry(
            Path::new("empty_dir/"),
            &EntryType::Directory,
            EntrySize::new(Uncompressed(0), None),
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
        let config = SecurityConfig::default();
        let mut validator = EntryValidator::new(&config, &dest);

        // Multiple nested empty directories
        let dirs = ["a/", "a/b/", "a/b/c/"];
        for dir in &dirs {
            let result = validator.validate_entry(
                Path::new(dir),
                &EntryType::Directory,
                EntrySize::new(Uncompressed(0), None),
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
        let config = SecurityConfig::default();

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
        let config = SecurityConfig::default();

        // Create two validators sharing the same config reference
        let mut validator1 = EntryValidator::new(&config, &dest1);
        let mut validator2 = EntryValidator::new(&config, &dest2);

        // Both validators work independently
        let result1 = validator1.validate_entry(
            Path::new("file1.txt"),
            &EntryType::File,
            EntrySize::new(Uncompressed(1024), None),
            Some(RawMode::new(0o644)),
        );
        assert!(result1.is_ok());

        let result2 = validator2.validate_entry(
            Path::new("file2.txt"),
            &EntryType::File,
            EntrySize::new(Uncompressed(2048), None),
            Some(RawMode::new(0o644)),
        );
        assert!(result2.is_ok());

        // Config is still accessible
        assert_eq!(
            config.max_file_size,
            SecurityConfig::default().max_file_size
        );
    }

    #[test]
    fn test_symlink_seen_flag_propagates() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = crate::Admit::Allow;
        let mut validator = EntryValidator::new(&config, &dest);

        assert!(!validator.core.symlink_seen);

        // Validate a symlink entry
        validator
            .validate_entry(
                Path::new("link"),
                &EntryType::Symlink {
                    target: PathBuf::from("target.txt"),
                },
                EntrySize::new(Uncompressed(0), None),
                None,
            )
            .unwrap();

        assert!(validator.core.symlink_seen);
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
            EntrySize::new(Uncompressed(0), None),
            None,
        )?;
        match entry.entry_type {
            ValidatedEntryType::Hardlink { counted, .. } => Ok(counted),
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
            EntrySize::new(Uncompressed(0), None),
            None,
        )
    }

    #[test]
    fn test_charge_hardlink_exceeding_max_file_size_rejected() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;
        config.max_file_size = crate::Limit::Bounded(crate::non_zero!(100));
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
        config.allowed.hardlinks = crate::Admit::Allow;
        config.max_total_size = crate::Limit::Bounded(crate::non_zero!(250));
        let mut validator = EntryValidator::new(&config, &dest);

        validator
            .validate_entry(
                Path::new("file1.txt"),
                &EntryType::File,
                EntrySize::new(Uncompressed(100), None),
                Some(RawMode::new(0o644)),
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
        config.allowed.hardlinks = crate::Admit::Allow;
        config.max_file_count = crate::Limit::Bounded(crate::non_zero!(2));
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
        config.allowed.symlinks = crate::Admit::Allow;
        config.max_file_count = crate::Limit::Bounded(crate::non_zero!(2));
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
        config.max_file_count = crate::Limit::Bounded(crate::non_zero!(1));
        let mut validator = EntryValidator::new(&config, &dest);
        validator
            .validate_entry(
                Path::new("f"),
                &EntryType::File,
                EntrySize::new(Uncompressed(1), None),
                None,
            )
            .unwrap();

        let result = validate_symlink_entry(&mut validator, "l1");
        assert_matches!(
            result,
            Err(crate::ArchiveError::SecurityViolation { ref kind })
                if kind.to_string() == "symlinks not allowed",
            "got: {result:?}"
        );
    }

    #[test]
    fn test_hardlink_policy_error_wins_over_file_count() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let mut config = SecurityConfig::default();
        config.max_file_count = crate::Limit::Bounded(crate::non_zero!(1));
        let mut validator = EntryValidator::new(&config, &dest);
        validator
            .validate_entry(
                Path::new("f"),
                &EntryType::File,
                EntrySize::new(Uncompressed(1), None),
                None,
            )
            .unwrap();

        let result = validate_hardlink_entry(&mut validator, "l1");
        assert_matches!(
            result,
            Err(crate::ArchiveError::SecurityViolation { ref kind })
                if kind.to_string() == "hardlinks not allowed",
            "got: {result:?}"
        );
    }
}
