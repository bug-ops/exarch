//! Entry validation core.
//!
//! [`ValidatorCore`] coordinates every security validation for archive
//! entries: path, quota, compression ratio, link policy and target. Each
//! extraction target (the host directory, a sink, a listing) drives it and
//! receives one proof token per entry kind from [`crate::security::admitted`].

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
use crate::security::hardlink::HardlinkTracker;
use crate::security::hardlink::require_hardlinks_allowed;
use crate::security::permissions::RawMode;
use crate::security::quota::EntryCount;
use crate::security::quota::QuotaPermit;
use crate::security::quota::QuotaTracker;
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
pub enum NodeKind {
    /// The entry is a directory (or stands for one, like ZIP's empty root
    /// file).
    Directory,
    /// Any other entry: file, symlink, hardlink.
    NonDirectory,
}

impl NodeKind {
    /// Converts a format's directory flag at the boundary, so the rule itself
    /// never takes a bare `bool`.
    pub const fn directory_if(is_directory: bool) -> Self {
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
pub enum EntryPath<P> {
    /// The destination itself (`.`, `./`).
    Root(P),
    /// Any path below the destination.
    Child(P),
}

impl<'a> EntryPath<&'a Path> {
    /// Classifies a raw entry name; the single definition of "root" for names
    /// not yet validated.
    pub fn of(path: &'a Path) -> Self {
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
    pub const fn is_root(&self) -> bool {
        matches!(self, Self::Root(_))
    }

    /// The path, for callers that treat the root like any directory.
    pub fn into_inner(self) -> P {
        match self {
            Self::Root(path) | Self::Child(path) => path,
        }
    }

    /// Rejects a root entry that is not a directory.
    ///
    /// A file, symlink or hardlink standing for the root would be written
    /// onto, or remove, the destination. Shared by entry validation and
    /// listing so `extract`, `list` and `verify` agree.
    pub fn require_directory_root(self, kind: NodeKind) -> Result<Self> {
        if self.is_root() && kind == NodeKind::NonDirectory {
            return Err(Violation::RootEntryNotDirectory.into());
        }
        Ok(self)
    }
}

/// Rejects a root entry that is not a directory, for the TAR extractor, which
/// checks the raw name before its extension filter.
pub fn check_root_entry_is_directory(path: &Path, kind: NodeKind) -> Result<()> {
    EntryPath::of(path).require_directory_root(kind).map(drop)
}

/// Rejects an empty entry name, so listing fails on the name that extraction
/// and `verify` refuse, instead of joining it onto the destination directory.
pub fn require_non_empty_name(path: &Path) -> Result<()> {
    if path.is_empty() {
        return Err(Violation::EmptyPath.into());
    }
    Ok(())
}

/// What path validation and the extension allowlist decide about a file, before
/// any quota is charged.
pub enum FileScreen<P: ParentCheck = Resolved> {
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
pub struct ValidatorCore<'a> {
    config: &'a SecurityConfig,
    quota_tracker: QuotaTracker,
    hardlink_tracker: HardlinkTracker,
    symlink_seen: bool,
}

impl<'a> ValidatorCore<'a> {
    pub fn new(config: &'a SecurityConfig) -> Self {
        Self {
            config,
            quota_tracker: QuotaTracker::new(),
            hardlink_tracker: HardlinkTracker::new(),
            symlink_seen: false,
        }
    }

    /// A context reflecting the symlinks seen so far; build a fresh one for
    /// every entry.
    pub fn context<'r, V: FsView>(&self) -> ValidationContext<'r, V> {
        let mut ctx = ValidationContext::new(self.config.allowed.symlinks.is_allowed());
        if self.symlink_seen {
            ctx.mark_symlink_seen();
        }
        ctx
    }

    /// Validates a regular file: path, quota reservation, ratio and mode.
    #[cfg(test)]
    pub fn validate_file_in<V: FsView, P: ParentCheck>(
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
    pub fn screen_file_path_in<V: FsView, P: ParentCheck>(
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
    pub fn admit_file<P: ParentCheck>(
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
    pub fn validate_directory_in<V: FsView, P: ParentCheck>(
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
    pub fn validate_symlink_in<V: FsView, P: ParentCheck>(
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
        self.reserve_symlink(size.uncompressed().0)?;
        let symlink = SafeSymlink::validate_in(&safe_path, target, root, self.config, view)?;
        self.symlink_seen = true;
        Ok(ValidatedSymlink { symlink })
    }

    /// Validates a hardlink entry: path, ratio, policy, count and target.
    pub fn validate_hardlink_in<V: FsView, P: ParentCheck>(
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

    /// Validates an entry's path, which must be a directory if it names the
    /// archive root.
    pub fn validate_entry_path_in<V: FsView, P: ParentCheck>(
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

    pub fn reserve_file(&mut self, size: u64) -> Result<QuotaPermit> {
        self.quota_tracker.reserve(size, self.config)
    }

    pub fn reserve_symlink(&mut self, size: u64) -> Result<()> {
        self.quota_tracker.reserve(size, self.config).map(drop)
    }

    pub fn charge_hardlink(&mut self, counted: EntryCount, size: u64) -> Result<QuotaPermit> {
        self.quota_tracker.charge(counted, size, self.config)
    }
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
    use crate::security::fs_view::HostFs;
    use crate::security::permissions::SanitizedMode;
    use crate::types::DestDir;
    use std::assert_matches;
    use tempfile::TempDir;

    /// A core with a real destination, answering one call per entry kind.
    struct Harness<'a> {
        core: ValidatorCore<'a>,
        dest: DestDir,
        _temp: TempDir,
    }

    impl<'a> Harness<'a> {
        fn new(config: &'a SecurityConfig) -> Self {
            let temp = TempDir::new().expect("failed to create temp dir");
            let dest = DestDir::new(temp.path().to_path_buf()).expect("failed to create dest");
            Self {
                core: ValidatorCore::new(config),
                dest,
                _temp: temp,
            }
        }

        fn file(
            &mut self,
            path: &str,
            size: EntrySize,
            mode: Option<u32>,
        ) -> Result<ValidatedFile> {
            let ctx = self.core.context::<HostFs>();
            self.core.validate_file_in(
                Path::new(path),
                size,
                mode.map(RawMode::new),
                &self.dest,
                &HostFs,
                &ctx,
            )
        }

        fn plain_file(&mut self, path: &str, bytes: u64) -> Result<ValidatedFile> {
            self.file(path, sizes(bytes), Some(0o644))
        }

        fn directory(&self, path: &str) -> Result<SafePath> {
            let ctx = self.core.context::<HostFs>();
            self.core
                .validate_directory_in(Path::new(path), sizes(0), &self.dest, &HostFs, &ctx)
        }

        fn symlink(&mut self, path: &str) -> Result<ValidatedSymlink> {
            let ctx = self.core.context::<HostFs>();
            self.core.validate_symlink_in(
                Path::new(path),
                Path::new("target.txt"),
                sizes(0),
                &self.dest,
                &HostFs,
                &ctx,
            )
        }

        fn hardlink(&mut self, path: &str) -> Result<ValidatedHardlink> {
            let ctx = self.core.context::<HostFs>();
            self.core.validate_hardlink_in(
                Path::new(path),
                Path::new("target.txt"),
                sizes(0),
                &self.dest,
                &HostFs,
                &ctx,
            )
        }
    }

    fn sizes(uncompressed: u64) -> EntrySize {
        EntrySize::new(Uncompressed(uncompressed), None)
    }

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
    fn test_validate_file_entry() {
        let config = SecurityConfig::default();
        let mut harness = Harness::new(&config);

        let (path, _permit, mode) = harness.plain_file("file.txt", 1024).unwrap().into_parts();

        assert_eq!(path.as_path(), Path::new("file.txt"));
        assert_eq!(mode.map(SanitizedMode::as_u32), Some(0o644));
    }

    #[test]
    fn test_validate_directory_entry() {
        let config = SecurityConfig::default();
        let harness = Harness::new(&config);

        let path = harness.directory("dir").unwrap();

        assert_eq!(path.as_path(), Path::new("dir"));
    }

    #[test]
    fn test_validate_path_traversal_rejected() {
        let config = SecurityConfig::default();
        let mut harness = Harness::new(&config);

        assert_matches!(
            harness.plain_file("../etc/passwd", 1024),
            Err(ArchiveError::PathTraversal { .. })
        );
    }

    #[test]
    fn test_quota_exceeded_file_size() {
        let mut config = SecurityConfig::default();
        config.max_file_size = crate::Limit::Bounded(crate::non_zero!(100));
        let mut harness = Harness::new(&config);

        assert_matches!(
            harness.plain_file("large.txt", 1000),
            Err(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::FileSize { .. }
            })
        );
    }

    #[test]
    fn test_quota_exceeded_file_count() {
        let mut config = SecurityConfig::default();
        config.max_file_count = crate::Limit::Bounded(crate::non_zero!(2));
        let mut harness = Harness::new(&config);

        assert!(harness.plain_file("file1.txt", 100).is_ok());
        assert!(harness.plain_file("file2.txt", 100).is_ok());
        assert_matches!(
            harness.plain_file("file3.txt", 100),
            Err(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::FileCount { .. }
            })
        );
    }

    #[test]
    fn test_zip_bomb_detected() {
        let config = SecurityConfig::default();
        let mut harness = Harness::new(&config);

        let result = harness.file(
            "bomb.txt",
            EntrySize::new(Uncompressed(1_000_000), Some(Compressed(100))),
            Some(0o644),
        );

        assert_matches!(result, Err(ArchiveError::ZipBomb(_)));
    }

    #[test]
    fn test_sanitize_permissions_setuid() {
        let config = SecurityConfig::default();
        let mut harness = Harness::new(&config);

        let (_, _, mode) = harness
            .file("file.txt", sizes(1024), Some(0o4755))
            .unwrap()
            .into_parts();

        assert_eq!(mode.map(SanitizedMode::as_u32), Some(0o755));
    }

    #[test]
    fn test_symlink_validation_marks_the_context() {
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = crate::Admit::Allow;
        let mut harness = Harness::new(&config);
        assert!(!harness.core.symlink_seen);

        let validated = harness.symlink("link").unwrap();

        assert_eq!(validated.symlink.link().as_path(), Path::new("link"));
        assert_eq!(validated.symlink.target_path(), Path::new("target.txt"));
        assert!(harness.core.symlink_seen);
    }

    #[test]
    fn test_hardlink_validation() {
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;
        let mut harness = Harness::new(&config);

        let validated = harness.hardlink("link").unwrap();

        assert_eq!(validated.link.as_path(), Path::new("link"));
        assert_eq!(validated.target.as_path(), Path::new("target.txt"));
    }

    #[test]
    fn test_nested_empty_directories() {
        let config = SecurityConfig::default();
        let harness = Harness::new(&config);

        for dir in ["a/", "a/b/", "a/b/c/", "empty_dir/"] {
            assert!(harness.directory(dir).is_ok(), "{dir}");
        }
    }

    // Issue #426: hardlink quota bypass regression tests.

    #[test]
    fn test_charge_hardlink_exceeding_max_file_size_rejected() {
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;
        config.max_file_size = crate::Limit::Bounded(crate::non_zero!(100));
        let mut harness = Harness::new(&config);

        let counted = harness.hardlink("link").unwrap().counted;
        let result = harness.core.charge_hardlink(counted, 1_000);

        assert_matches!(
            result,
            Err(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::FileSize { .. }
            }),
            "hardlink exceeding max_file_size must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn test_charge_hardlink_shares_quota_tracker_with_files() {
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;
        config.max_total_size = crate::Limit::Bounded(crate::non_zero!(250));
        let mut harness = Harness::new(&config);

        harness.plain_file("file1.txt", 100).unwrap();
        let first = harness.hardlink("link1").unwrap().counted;
        let second = harness.hardlink("link2").unwrap().counted;
        assert!(harness.core.charge_hardlink(first, 100).is_ok());

        let result = harness.core.charge_hardlink(second, 100);
        assert_matches!(
            result,
            Err(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::TotalSize { .. }
            }),
            "hardlink bytes must accumulate on the same tracker as file bytes \
             (200 already recorded + 100 more exceeds the 250 budget), got: {result:?}"
        );
    }

    #[test]
    fn test_hardlink_counted_once_in_pass_one() {
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;
        config.max_file_count = crate::Limit::Bounded(crate::non_zero!(2));
        let mut harness = Harness::new(&config);

        let first = harness.hardlink("link1").unwrap().counted;
        let second = harness.hardlink("link2").unwrap().counted;

        let result = harness.hardlink("link3");
        assert_matches!(
            result,
            Err(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::FileCount { .. }
            }),
            "the third hardlink must exceed max_file_count in pass one, got: {result:?}"
        );

        assert!(harness.core.charge_hardlink(first, 1).is_ok());
        assert!(harness.core.charge_hardlink(second, 1).is_ok());
    }

    #[test]
    fn test_symlink_exceeding_max_file_count_rejected() {
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = crate::Admit::Allow;
        config.max_file_count = crate::Limit::Bounded(crate::non_zero!(2));
        let mut harness = Harness::new(&config);

        assert!(harness.symlink("l1").is_ok());
        assert!(harness.symlink("l2").is_ok());

        let result = harness.symlink("l3");
        assert_matches!(
            result,
            Err(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::FileCount { .. }
            }),
            "symlinks must count against max_file_count, got: {result:?}"
        );
    }

    #[test]
    fn test_symlink_policy_error_wins_over_file_count() {
        let mut config = SecurityConfig::default();
        config.max_file_count = crate::Limit::Bounded(crate::non_zero!(1));
        let mut harness = Harness::new(&config);
        harness.file("f", sizes(1), None).unwrap();

        let result = harness.symlink("l1");
        assert_matches!(
            result,
            Err(ArchiveError::SecurityViolation { ref kind })
                if kind.to_string() == "symlinks not allowed",
            "got: {result:?}"
        );
    }

    #[test]
    fn test_hardlink_policy_error_wins_over_file_count() {
        let mut config = SecurityConfig::default();
        config.max_file_count = crate::Limit::Bounded(crate::non_zero!(1));
        let mut harness = Harness::new(&config);
        harness.file("f", sizes(1), None).unwrap();

        let result = harness.hardlink("l1");
        assert_matches!(
            result,
            Err(ArchiveError::SecurityViolation { ref kind })
                if kind.to_string() == "hardlinks not allowed",
            "got: {result:?}"
        );
    }
}
