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
use crate::SkipKind;
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
use crate::security::fs_view::LinkKind;
use crate::security::hardlink::HardlinkTracker;
use crate::security::hardlink::require_hardlinks_allowed;
use crate::security::permissions::RawMode;
use crate::security::quota::EntryCount;
use crate::security::quota::QuotaPermit;
use crate::security::quota::QuotaTracker;
use crate::selection::Decision;
use crate::selection::EntryShape;
use crate::selection::IncludeHits;
use crate::selection::LandingClaims;
use crate::selection::Placement;
use crate::selection::SelectionRun;
use crate::types::SafePath;
use crate::types::SafeSymlink;
use crate::types::safe_path::ParentCheck;
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

/// What the entry gate decides about an entry before any quota is charged:
/// extract it, or leave it out for a stated reason.
///
/// The reason is [`SkipKind::NotSelected`] or [`SkipKind::StrippedAway`] from
/// the selection, or [`SkipKind::ExtensionNotAllowed`] from the allowlist.
#[derive(Debug)]
pub(crate) enum Gated<T> {
    /// The entry is extracted; `T` is what its validation produced.
    Admit(T),
    /// The entry is skipped and counted under this kind.
    Skip(SkipKind),
}

impl<T> Gated<T> {
    /// The admitted value; panics when the entry was skipped.
    #[cfg(test)]
    pub(crate) fn into_admitted(self) -> T {
        match self {
            Self::Admit(value) => value,
            Self::Skip(kind) => panic!("the entry was skipped: {kind:?}"),
        }
    }

    /// Applies `f` to an admitted entry.
    pub(crate) fn map<U>(self, f: impl FnOnce(T) -> U) -> Gated<U> {
        match self {
            Self::Admit(value) => Gated::Admit(f(value)),
            Self::Skip(kind) => Gated::Skip(kind),
        }
    }
}

/// Applies the entry selection to a name that passed path validation: patterns
/// first, then the rewrite, and validates a rewritten name again as a landing.
///
/// This is the one place a rewritten name becomes a [`SafePath`]; `extract`,
/// `list`, `verify` and every sink reach it, so they agree on every landing.
/// `hits` records which include patterns matched, for the end-of-scan check.
///
/// # Errors
///
/// Returns the validation error of the rewritten name, or the refusal a
/// rewrite raises.
pub(crate) fn route_validated<V: FsView, P: ParentCheck>(
    run: SelectionRun<'_>,
    original: SafePath<P>,
    shape: EntryShape,
    root: &V::Root,
    config: &SecurityConfig,
    ctx: &ValidationContext<'_, V, P>,
    view: &V,
) -> Result<Gated<SafePath<P>>> {
    if run.selection.is_default() {
        return Ok(Gated::Admit(original));
    }
    match run.decide(original.as_path(), shape)? {
        Decision::Skip(kind) => Ok(Gated::Skip(kind)),
        Decision::Extract(Placement::Unchanged) => Ok(Gated::Admit(original)),
        Decision::Extract(Placement::Rewritten(rewritten)) => {
            SafePath::validate_rewritten_in(&rewritten, root, config, ctx, view).map(Gated::Admit)
        }
    }
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
    include_hits: IncludeHits,
    claims: LandingClaims,
}

impl<'a> ValidatorCore<'a> {
    pub(crate) fn new(config: &'a SecurityConfig) -> Self {
        Self {
            config,
            quota_tracker: QuotaTracker::new(),
            hardlink_tracker: HardlinkTracker::new(),
            symlink_seen: false,
            include_hits: IncludeHits::of(&config.selection),
            claims: LandingClaims::default(),
        }
    }

    /// Refuses a hardlink whose target landing several entries map to.
    ///
    /// Called when the link is materialized, after every entry was seen.
    ///
    /// # Errors
    ///
    /// Returns [`Violation::HardlinkTargetAmbiguous`].
    pub(crate) fn require_unambiguous_target(&self, link: &Path, target: &Path) -> Result<()> {
        self.claims.require_unambiguous(link, target)
    }

    /// Settles what only the whole scan decides: an include pattern that no
    /// entry matched.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::UnmatchedInclude`] naming every unmatched
    /// pattern.
    pub(crate) fn finish_selection(&self) -> Result<()> {
        self.include_hits
            .require_all_matched(&self.config.selection)
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

    /// Validates a regular file: path, selection, quota reservation, ratio and
    /// mode.
    #[cfg(test)]
    pub(crate) fn validate_file_in<V: FsView, P: ParentCheck>(
        &mut self,
        path: &Path,
        size: EntrySize,
        mode: Option<RawMode>,
        root: &V::Root,
        view: &V,
        ctx: &ValidationContext<'_, V, P>,
    ) -> Result<Gated<ValidatedFile<P>>> {
        match self.screen_file_path_in(path, size, mode, root, view, ctx)? {
            Gated::Admit(pending) => self.admit_file(pending).map(Gated::Admit),
            Gated::Skip(kind) => Ok(Gated::Skip(kind)),
        }
    }

    /// Validates a file's path, applies the selection and rewrite, then the
    /// extension allowlist, ahead of any quota.
    ///
    /// The original path comes first, so an unselected or disallowed entry
    /// named `../x.bin` is refused rather than skipped. This is the one place
    /// the allowlist rule is applied to extraction.
    pub(crate) fn screen_file_path_in<V: FsView, P: ParentCheck>(
        &mut self,
        path: &Path,
        size: EntrySize,
        mode: Option<RawMode>,
        root: &V::Root,
        view: &V,
        ctx: &ValidationContext<'_, V, P>,
    ) -> Result<Gated<PendingFile<P>>> {
        let safe_path = match self.route_entry_in(path, EntryShape::File, root, view, ctx)? {
            Gated::Admit(entry) => entry.into_inner(),
            Gated::Skip(kind) => return Ok(Gated::Skip(kind)),
        };
        if !is_extension_allowed(safe_path.as_path(), self.config) {
            self.charge_skipped()?;
            return Ok(Gated::Skip(SkipKind::ExtensionNotAllowed));
        }
        check_name_limits(view, &safe_path, true, self.config)?;
        self.claims
            .claim(&self.config.selection, safe_path.as_path());
        Ok(Gated::Admit(PendingFile::new(safe_path, size, mode)))
    }

    /// Reserves the quota of a screened file, checks its ratio and sanitizes
    /// its mode.
    pub(crate) fn admit_file<P: ParentCheck>(
        &mut self,
        pending: PendingFile<P>,
    ) -> Result<ValidatedFile<P>> {
        pending.admit(&mut self.quota_tracker, self.config)
    }

    /// Validates a directory entry: path, selection and ratio.
    pub(crate) fn validate_directory_in<V: FsView, P: ParentCheck>(
        &mut self,
        path: &Path,
        size: EntrySize,
        root: &V::Root,
        view: &V,
        ctx: &ValidationContext<'_, V, P>,
    ) -> Result<Gated<SafePath<P>>> {
        let safe_path = match self.route_entry_in(path, EntryShape::Directory, root, view, ctx)? {
            Gated::Admit(entry) => entry.into_inner(),
            Gated::Skip(kind) => return Ok(Gated::Skip(kind)),
        };
        check_name_limits(view, &safe_path, false, self.config)?;
        size.check_ratio(self.config)?;
        Ok(Gated::Admit(safe_path))
    }

    /// Validates a symlink entry: path, selection, ratio, policy, quota and
    /// target.
    ///
    /// The target text is never rewritten: it is validated at the rewritten
    /// landing as the archive recorded it.
    pub(crate) fn validate_symlink_in<V: FsView, P: ParentCheck>(
        &mut self,
        path: &Path,
        target: &Path,
        size: EntrySize,
        root: &V::Root,
        view: &V,
        ctx: &ValidationContext<'_, V, P>,
    ) -> Result<Gated<ValidatedSymlink<P>>> {
        let shape = EntryShape::Link(LinkKind::Symlink);
        let safe_path = match self.route_entry_in(path, shape, root, view, ctx)? {
            Gated::Admit(entry) => entry.into_inner(),
            Gated::Skip(kind) => return Ok(Gated::Skip(kind)),
        };
        check_name_limits(view, &safe_path, false, self.config)?;
        size.check_ratio(self.config)?;
        require_symlinks_allowed(self.config)?;
        self.reserve_symlink(size.uncompressed().0)?;
        let symlink = SafeSymlink::validate_in(&safe_path, target, root, self.config, view)?;
        self.symlink_seen = true;
        Ok(Gated::Admit(ValidatedSymlink { symlink }))
    }

    /// Validates a hardlink entry: path, selection, ratio, policy, count and
    /// target.
    ///
    /// The target is an archive path, so it goes through the selection and
    /// rewrite as entry names do; a target the extraction does not write
    /// refuses the link.
    pub(crate) fn validate_hardlink_in<V: FsView, P: ParentCheck>(
        &mut self,
        path: &Path,
        target: &Path,
        size: EntrySize,
        root: &V::Root,
        view: &V,
        ctx: &ValidationContext<'_, V, P>,
    ) -> Result<Gated<ValidatedHardlink<P>>> {
        let shape = EntryShape::Link(LinkKind::Hardlink);
        let safe_path = match self.route_entry_in(path, shape, root, view, ctx)? {
            Gated::Admit(entry) => entry.into_inner(),
            Gated::Skip(kind) => return Ok(Gated::Skip(kind)),
        };
        check_name_limits(view, &safe_path, false, self.config)?;
        size.check_ratio(self.config)?;
        require_hardlinks_allowed(self.config)?;
        let target = self.config.selection.mapped_link_target(
            path,
            target,
            self.config.allowed.absolute_paths,
        )?;
        let counted = self.quota_tracker.reserve_count(self.config)?;

        let target = self.hardlink_tracker.validate_hardlink_in(
            &safe_path,
            &target,
            root,
            self.config,
            view,
        )?;

        Ok(Gated::Admit(ValidatedHardlink {
            link: safe_path,
            target,
            counted,
        }))
    }

    /// Validates an entry's path as the archive names it, then applies the
    /// selection: the entry is skipped, or admitted at its landing.
    ///
    /// The landing is the validated path itself, or, when the selection
    /// rewrites paths, the rewritten path validated again.
    ///
    /// Every entry counts once against `max_file_count`: a skipped entry and
    /// an admitted directory are charged here, files and links by their own
    /// reservation.
    ///
    /// # Errors
    ///
    /// Returns the validation error of the path, or
    /// [`Violation::FileCountExceeded`](crate::error::Violation) when the
    /// count is exceeded.
    pub(crate) fn route_entry_in<V: FsView, P: ParentCheck>(
        &mut self,
        path: &Path,
        shape: EntryShape,
        root: &V::Root,
        view: &V,
        ctx: &ValidationContext<'_, V, P>,
    ) -> Result<Gated<EntryPath<SafePath<P>>>> {
        let original = self
            .validate_entry_path_in(path, shape.node_kind(), root, view, ctx)?
            .into_inner();
        let run = SelectionRun {
            selection: &self.config.selection,
            hits: Some(&self.include_hits),
        };
        let routed = route_validated(run, original, shape, root, self.config, ctx, view)?;
        let charged = match (&routed, shape) {
            (Gated::Skip(_), _) | (Gated::Admit(_), EntryShape::Directory) => true,
            (Gated::Admit(_), _) => false,
        };
        if charged {
            self.charge_skipped()?;
        }
        Ok(routed.map(|landing| {
            if landing.as_path().is_empty() {
                EntryPath::Root(landing)
            } else {
                EntryPath::Child(landing)
            }
        }))
    }

    /// Validates an entry's path, which must be a directory if it names the
    /// archive root.
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

    /// Charges an entry the extraction skips after validation, such as a
    /// duplicate, to `max_file_count`.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::QuotaExceeded`] when the count is exceeded.
    pub(crate) fn charge_skipped(&mut self) -> Result<()> {
        self.quota_tracker.reserve_count(self.config).map(drop)
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

    trait Admitted<T> {
        fn admitted(self) -> Result<T>;
    }

    impl<T> Admitted<T> for Result<Gated<T>> {
        fn admitted(self) -> Result<T> {
            self.map(Gated::into_admitted)
        }
    }

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
            self.core
                .validate_file_in(
                    Path::new(path),
                    size,
                    mode.map(RawMode::new),
                    &self.dest,
                    &HostFs,
                    &ctx,
                )
                .admitted()
        }

        fn plain_file(&mut self, path: &str, bytes: u64) -> Result<ValidatedFile> {
            self.file(path, sizes(bytes), Some(0o644))
        }

        fn directory(&mut self, path: &str) -> Result<SafePath> {
            let ctx = self.core.context::<HostFs>();
            self.core
                .validate_directory_in(Path::new(path), sizes(0), &self.dest, &HostFs, &ctx)
                .admitted()
        }

        fn symlink(&mut self, path: &str) -> Result<ValidatedSymlink> {
            let ctx = self.core.context::<HostFs>();
            self.core
                .validate_symlink_in(
                    Path::new(path),
                    Path::new("target.txt"),
                    sizes(0),
                    &self.dest,
                    &HostFs,
                    &ctx,
                )
                .admitted()
        }

        fn hardlink(&mut self, path: &str) -> Result<ValidatedHardlink> {
            let ctx = self.core.context::<HostFs>();
            self.core
                .validate_hardlink_in(
                    Path::new(path),
                    Path::new("target.txt"),
                    sizes(0),
                    &self.dest,
                    &HostFs,
                    &ctx,
                )
                .admitted()
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
        let mut harness = Harness::new(&config);

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
        let mut harness = Harness::new(&config);

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
