//! Which archive entries an extraction takes, and where they land.
//!
//! An [`EntrySelection`] holds include patterns, exclude patterns and a
//! [`PathRewrite`]. It lives in [`SecurityConfig`](crate::SecurityConfig), so
//! `extract`, `list`, `verify` and every sink read one value and cannot
//! disagree about what an extraction would write.
//!
//! The decision for one entry is made by [`EntrySelection::decide`], on a name
//! that already passed path validation, in a fixed order: patterns match the
//! normalized archive path first, then the rewrite removes leading components.
//! A rewritten name exists only as a [`Rewritten`], which can be turned into a
//! landing path solely by validating it again as a
//! [`SafePath`](crate::types::SafePath), so a stripped name never reaches a
//! writer unchecked.

use std::borrow::Cow;
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::HashSet;
use std::num::NonZeroU64;
use std::num::NonZeroUsize;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use crate::Admit;
use crate::ArchiveError;
use crate::ConfigProblem;
use crate::ConfigSetting;
use crate::Result;
use crate::SkipKind;
use crate::Violation;
use crate::pattern::EntryPattern;
use crate::pattern::PatternList;
use crate::pattern::normalized;
use crate::security::fs_view::LinkKind;
use crate::security::validator::NodeKind;

/// How many leading path components extraction drops from every entry.
///
/// Never zero (no rewriting is [`PathRewrite::Keep`], not `0`) and never above
/// the destination's maximum path depth, so a value that could not leave
/// anything of a valid path is refused when it is built.
///
/// The bound is checked only in [`StripComponents::new`], against the depth
/// passed then. Lowering
/// [`SecurityConfig::max_path_depth`](crate::SecurityConfig::max_path_depth)
/// afterwards does not re-check an existing value (a count above the new depth
/// strips every entry away), so build the count after the depth is final.
///
/// # Examples
///
/// ```
/// use exarch_core::SecurityConfig;
/// use exarch_core::StripComponents;
/// use exarch_core::non_zero;
///
/// let max_depth = non_zero!(32);
/// let strip = StripComponents::new(non_zero!(1), max_depth)?;
/// assert_eq!(strip.get().get(), 1);
/// assert!(StripComponents::new(non_zero!(33), max_depth).is_err());
///
/// // Lowering the depth later leaves the count as it was built.
/// let config = SecurityConfig::default().with_max_path_depth(non_zero!(2));
/// assert_eq!(strip.get().get(), 1);
/// assert!(StripComponents::new(non_zero!(3), config.max_path_depth).is_err());
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StripComponents(NonZeroUsize);

impl StripComponents {
    /// Builds a count of at most `max_path_depth`.
    ///
    /// A front end holding a signed or floating-point number turns it into a
    /// [`NonZeroU64`] with [`positive_from_i128`](crate::positive_from_i128) or
    /// [`positive_from_f64`](crate::positive_from_f64) naming
    /// [`ConfigSetting::StripComponents`], then calls this.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidConfiguration`] naming
    /// [`ConfigSetting::StripComponents`] with [`ConfigProblem::TooLarge`] when
    /// `count` exceeds `max_path_depth`.
    pub fn new(count: NonZeroU64, max_path_depth: NonZeroUsize) -> Result<Self> {
        usize::try_from(count.get())
            .ok()
            .filter(|count| *count <= max_path_depth.get())
            .and_then(NonZeroUsize::new)
            .map(Self)
            .ok_or_else(|| ArchiveError::InvalidConfiguration {
                setting: ConfigSetting::StripComponents,
                problem: ConfigProblem::TooLarge {
                    max: u64::try_from(max_path_depth.get()).unwrap_or(u64::MAX),
                },
            })
    }

    /// The number of components dropped.
    #[must_use]
    pub const fn get(self) -> NonZeroUsize {
        self.0
    }
}

/// How a validated archive path becomes the path an entry lands at.
///
/// # Examples
///
/// ```
/// use exarch_core::PathRewrite;
///
/// assert_eq!(PathRewrite::default(), PathRewrite::Keep);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum PathRewrite {
    /// The entry lands at its own normalized path.
    #[default]
    Keep,
    /// The leading components are removed. An entry with no component left is
    /// skipped as [`SkipKind::StrippedAway`].
    ///
    /// Entries that collide after stripping follow the
    /// [`ExistingFiles`](crate::ExistingFiles) policy. A hardlink whose target
    /// path is the landing of several colliding entries is refused as
    /// [`Violation::HardlinkTargetAmbiguous`], because it cannot say which one
    /// it means; a symlink is a path and resolves to whichever entry won.
    Strip(StripComponents),
    /// Every regular file lands in the destination root under its final
    /// component. Directory entries are skipped as
    /// [`SkipKind::StrippedAway`]; a symlink or hardlink entry is refused,
    /// because its target was written for the original layout.
    ///
    /// Files that share a final name collide under the destination's
    /// [`ExistingFiles`](crate::ExistingFiles) policy and are reported as
    /// [`SkipKind::Duplicate`], so use
    /// [`ExistingFiles::Refuse`](crate::ExistingFiles::Refuse) where a silent
    /// first-wins is not wanted.
    Flatten,
}

/// The entries of an archive an extraction takes, and how their paths are
/// rewritten.
///
/// An entry is selected when it matches at least one include pattern (or there
/// are none) and no exclude pattern; an exclude pattern always wins. Patterns
/// match the entry's normalized archive path before any stripping, compare raw
/// bytes and are case-sensitive on every host. A match selects the entry and
/// everything below it.
///
/// The default selects every entry and keeps every path.
///
/// # Examples
///
/// ```
/// use exarch_core::EntrySelection;
/// use exarch_core::SecurityConfig;
///
/// let config = SecurityConfig::default()
///     .try_add_include("src")?
///     .try_add_exclude("src/generated")?;
/// assert!(!config.selection.is_default());
/// assert_eq!(
///     EntrySelection::default(),
///     SecurityConfig::default().selection
/// );
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EntrySelection {
    include: PatternList,
    exclude: PatternList,
    rewrite: PathRewrite,
}

impl EntrySelection {
    /// Whether this selection leaves an extraction as if it had none.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty() && self.rewrite == PathRewrite::Keep
    }

    /// The include patterns; empty selects every entry.
    #[must_use]
    pub fn include(&self) -> &[EntryPattern] {
        self.include.as_slice()
    }

    /// The exclude patterns.
    #[must_use]
    pub fn exclude(&self) -> &[EntryPattern] {
        self.exclude.as_slice()
    }

    /// How selected entries are rewritten.
    #[must_use]
    pub const fn rewrite(&self) -> PathRewrite {
        self.rewrite
    }

    /// Adds an include pattern.
    #[must_use]
    pub fn with_include(mut self, pattern: EntryPattern) -> Self {
        self.include = std::mem::take(&mut self.include).pushed(pattern);
        self
    }

    /// Adds an exclude pattern.
    #[must_use]
    pub fn with_exclude(mut self, pattern: EntryPattern) -> Self {
        self.exclude = std::mem::take(&mut self.exclude).pushed(pattern);
        self
    }

    /// Sets how selected entries are rewritten.
    #[must_use]
    pub const fn with_rewrite(mut self, rewrite: PathRewrite) -> Self {
        self.rewrite = rewrite;
        self
    }

    /// Sets or clears the strip, leaving a flatten as it is.
    ///
    /// `None` removes a strip but keeps a flatten, so a front end can apply
    /// its strip and flatten options independently, in either order.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::EntrySelection;
    /// use exarch_core::PathRewrite;
    ///
    /// let selection = EntrySelection::default()
    ///     .with_flatten(true)
    ///     .with_strip(None);
    /// assert_eq!(selection.rewrite(), PathRewrite::Flatten);
    /// ```
    #[must_use]
    pub const fn with_strip(mut self, strip: Option<StripComponents>) -> Self {
        self.rewrite = match (strip, self.rewrite) {
            (Some(strip), _) => PathRewrite::Strip(strip),
            (None, PathRewrite::Flatten) => PathRewrite::Flatten,
            (None, _) => PathRewrite::Keep,
        };
        self
    }

    /// Sets or clears the flatten, leaving a strip as it is.
    ///
    /// `false` removes a flatten but keeps a strip.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::EntrySelection;
    /// use exarch_core::PathRewrite;
    ///
    /// let selection = EntrySelection::default()
    ///     .with_flatten(true)
    ///     .with_flatten(false);
    /// assert_eq!(selection.rewrite(), PathRewrite::Keep);
    /// ```
    #[must_use]
    pub const fn with_flatten(mut self, flatten: bool) -> Self {
        self.rewrite = match (flatten, self.rewrite) {
            (true, _) => PathRewrite::Flatten,
            (false, PathRewrite::Flatten) => PathRewrite::Keep,
            (false, rewrite) => rewrite,
        };
        self
    }

    /// Replaces the include patterns; the rewrite is kept.
    #[must_use]
    pub fn with_include_list(mut self, patterns: Vec<EntryPattern>) -> Self {
        self.include = patterns.into();
        self
    }

    /// Replaces the exclude patterns; the rewrite is kept.
    #[must_use]
    pub fn with_exclude_list(mut self, patterns: Vec<EntryPattern>) -> Self {
        self.exclude = patterns.into();
        self
    }

    /// Decides what happens to an entry whose name `original` already passed
    /// path validation (so it holds only normal components).
    ///
    /// Include patterns that match are recorded in `hits`, even when an
    /// exclude pattern then drops the entry, so only a pattern that matches no
    /// scanned entry at all is reported as unmatched.
    ///
    /// # Errors
    ///
    /// Returns [`Violation::LinkUnderFlatten`] for a selected link entry under
    /// [`PathRewrite::Flatten`].
    pub(crate) fn decide(
        &self,
        original: &Path,
        shape: EntryShape,
        hits: Option<&IncludeHits>,
    ) -> Result<Decision> {
        let normalized = normalized(original);
        let path = normalized.as_deref();
        if !self.record_includes(path, hits) || self.exclude.any_match(path) {
            return Ok(Decision::Skip(SkipKind::NotSelected));
        }
        Ok(match (self.rewrite, shape) {
            (PathRewrite::Keep, _) => Decision::Extract(Placement::Unchanged),
            (PathRewrite::Strip(strip), _) => {
                let kept: PathBuf = original.components().skip(strip.get().get()).collect();
                Decision::rewritten(kept)
            }
            (PathRewrite::Flatten, EntryShape::File) => {
                Decision::rewritten(original.file_name().map_or_default(PathBuf::from))
            }
            (PathRewrite::Flatten, EntryShape::Directory) => Decision::Skip(SkipKind::StrippedAway),
            (PathRewrite::Flatten, EntryShape::Link(kind)) => {
                return Err(Violation::LinkUnderFlatten {
                    kind,
                    name: crate::path_text(original).into(),
                }
                .into());
            }
        })
    }

    /// Where a listed entry lands lexically, or `None` when the selection
    /// leaves it out.
    ///
    /// For the passes that run before or beside validation (name limits, quota
    /// charges), which only need the landing's shape. The default selection
    /// returns `raw` untouched.
    pub(crate) fn lexical_landing<'a>(
        &self,
        raw: &'a Path,
        kind: NodeKind,
    ) -> Option<Cow<'a, Path>> {
        if self.is_default() {
            return Some(Cow::Borrowed(raw));
        }
        let normal: PathBuf = raw
            .components()
            .filter(|component| matches!(component, Component::Normal(_)))
            .collect();
        let shape = match kind {
            NodeKind::Directory => EntryShape::Directory,
            NodeKind::NonDirectory => EntryShape::File,
        };
        match self.decide(&normal, shape, None) {
            Ok(Decision::Extract(Placement::Unchanged)) | Err(_) => Some(Cow::Owned(normal)),
            Ok(Decision::Extract(Placement::Rewritten(rewritten))) => Some(Cow::Owned(rewritten.0)),
            Ok(Decision::Skip(_)) => None,
        }
    }

    /// Records which include patterns match `path` and tells whether the entry
    /// is included: some pattern matched, or there is none.
    fn record_includes(&self, path: Option<&[u8]>, hits: Option<&IncludeHits>) -> bool {
        if self.include.is_empty() {
            return true;
        }
        let Some(hits) = hits else {
            return self.include.any_match(path);
        };
        let mut included = false;
        hits.with_scratch(|scratch| {
            self.include.matching(path, scratch, |index| {
                included = true;
                hits.record(index);
            });
        });
        included
    }

    /// Fails when an include pattern matches none of the listed entries.
    ///
    /// For `list`, which has no extraction to record hits as it goes.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::UnmatchedInclude`] naming every unmatched
    /// pattern.
    pub(crate) fn require_includes_matched<'a>(
        &self,
        entries: impl IntoIterator<Item = &'a Path>,
    ) -> Result<()> {
        if self.include.is_empty() {
            return Ok(());
        }
        let hits = IncludeHits::of(self);
        for raw in entries {
            let normal: PathBuf = raw
                .components()
                .filter(|component| matches!(component, Component::Normal(_)))
                .collect();
            self.record_includes(normalized(&normal).as_deref(), Some(&hits));
        }
        hits.require_all_matched(self)
    }

    /// The hardlink target to validate for the link entry `link`, mapped as an
    /// entry name is, or the refusal for a target the extraction does not
    /// write.
    ///
    /// # Errors
    ///
    /// Returns [`Violation::HardlinkTargetNotExtracted`] for a target that is
    /// not selected or is stripped away, and the refusal of
    /// [`Self::map_link_target`] otherwise.
    pub(crate) fn mapped_link_target<'t>(
        &self,
        link: &Path,
        target: &'t Path,
        absolute: Admit,
    ) -> Result<Cow<'t, Path>> {
        match self.map_link_target(target, absolute)? {
            TargetMapping::Unchanged => Ok(Cow::Borrowed(target)),
            TargetMapping::Mapped(mapped) => Ok(Cow::Owned(mapped)),
            TargetMapping::NotExtracted => Err(target_not_extracted(link, target)),
        }
    }

    /// Maps the target of a hardlink, an archive path, as the entry names are
    /// mapped, without recording include hits.
    ///
    /// Where `absolute` admits absolute paths, a root or drive prefix is
    /// dropped, as it is from an entry name, so the target lands where the
    /// entry of that name does and is selected and rewritten with it. Elsewhere
    /// the root is kept and the validator refuses the target as it does without
    /// a selection. A target with no normal component is returned unchanged for
    /// its own validation to refuse with the same typed error.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::PathTraversal`] for a target holding `..`, which
    /// cannot be matched against patterns or stripped lexically.
    pub(crate) fn map_link_target(&self, target: &Path, absolute: Admit) -> Result<TargetMapping> {
        if self.is_default() {
            return Ok(TargetMapping::Unchanged);
        }
        let mut root = PathBuf::new();
        let mut normalized = PathBuf::new();
        for component in target.components() {
            match component {
                Component::Normal(name) => normalized.push(name),
                Component::ParentDir => {
                    return Err(ArchiveError::PathTraversal {
                        path: target.to_path_buf(),
                    });
                }
                Component::RootDir | Component::Prefix(_) if !absolute.is_allowed() => {
                    root.push(component.as_os_str());
                }
                Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
            }
        }
        if normalized.is_empty() {
            return Ok(TargetMapping::Unchanged);
        }
        Ok(match self.decide(&normalized, EntryShape::File, None)? {
            // A refused absolute target is refused by the validator whatever
            // the selection says; reporting it as not extracted would blame
            // the selection for a refusal that including it would not lift.
            Decision::Skip(_) if !root.is_empty() => TargetMapping::Unchanged,
            Decision::Skip(_) => TargetMapping::NotExtracted,
            Decision::Extract(Placement::Unchanged) => TargetMapping::Mapped(root.join(normalized)),
            Decision::Extract(Placement::Rewritten(rewritten)) => {
                TargetMapping::Mapped(root.join(rewritten.0))
            }
        })
    }
}

/// A selection together with the record of include patterns that matched,
/// for one pass over an archive's entries.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SelectionRun<'a> {
    /// The selection applied to every entry.
    pub selection: &'a EntrySelection,
    /// Where include matches are recorded; `None` for a pass that must not
    /// count again entries that were already counted.
    pub hits: Option<&'a IncludeHits>,
}

impl SelectionRun<'_> {
    /// Decides one entry; see [`EntrySelection::decide`].
    pub(crate) fn decide(&self, original: &Path, shape: EntryShape) -> Result<Decision> {
        self.selection.decide(original, shape, self.hits)
    }
}

/// What kind of entry a name belongs to, for rewrites that treat kinds
/// differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryShape {
    /// A directory entry.
    Directory,
    /// A regular file.
    File,
    /// A symlink or hardlink.
    Link(LinkKind),
}

impl EntryShape {
    /// How the entry-root rule sees this kind.
    pub(crate) const fn node_kind(self) -> NodeKind {
        match self {
            Self::Directory => NodeKind::Directory,
            Self::File | Self::Link(_) => NodeKind::NonDirectory,
        }
    }
}

/// The outcome of [`EntrySelection::decide`].
#[derive(Debug)]
pub(crate) enum Decision {
    /// The entry is extracted at `Placement`.
    Extract(Placement),
    /// The entry is left out.
    Skip(SkipKind),
}

impl Decision {
    /// An entry that lands at `kept`, or is stripped away when nothing is left.
    fn rewritten(kept: PathBuf) -> Self {
        if kept.is_empty() {
            Self::Skip(SkipKind::StrippedAway)
        } else {
            Self::Extract(Placement::Rewritten(Rewritten(kept)))
        }
    }
}

/// Where a selected entry lands.
#[derive(Debug)]
pub(crate) enum Placement {
    /// At its own validated path.
    Unchanged,
    /// At a rewritten path that still has to be validated.
    Rewritten(Rewritten),
}

/// A path produced by a rewrite, not yet validated as a landing.
///
/// Only [`EntrySelection::decide`] builds one, and the only use of it is
/// [`SafePath::validate_rewritten_in`](crate::types::SafePath), so a stripped
/// name cannot be written without passing validation again.
#[derive(Debug)]
pub(crate) struct Rewritten(PathBuf);

impl Rewritten {
    /// The rewritten path, for validation.
    pub(crate) fn as_path(&self) -> &Path {
        &self.0
    }
}

/// What the selection makes of a hardlink target.
#[derive(Debug)]
pub(crate) enum TargetMapping {
    /// Validate the target as it is.
    Unchanged,
    /// Validate this destination-relative path instead.
    Mapped(PathBuf),
    /// The target entry is not extracted: it is not selected or stripped away.
    NotExtracted,
}

/// Which include patterns matched at least one scanned entry.
#[derive(Debug)]
pub(crate) struct IncludeHits {
    matched: Box<[Cell<bool>]>,
    /// The glob matches of the entry being tested, reused across entries.
    scratch: RefCell<Vec<usize>>,
}

impl IncludeHits {
    /// A record with one slot per include pattern of `selection`.
    pub(crate) fn of(selection: &EntrySelection) -> Self {
        Self {
            matched: selection
                .include()
                .iter()
                .map(|_| Cell::new(false))
                .collect(),
            scratch: RefCell::default(),
        }
    }

    /// Runs `body` with the reusable match buffer. A nested call finds it
    /// empty and allocates its own, so the buffer is never shared.
    fn with_scratch(&self, body: impl FnOnce(&mut Vec<usize>)) {
        let mut scratch = self.scratch.take();
        body(&mut scratch);
        self.scratch.replace(scratch);
    }

    fn record(&self, index: usize) {
        if let Some(slot) = self.matched.get(index) {
            slot.set(true);
        }
    }

    /// Fails with the patterns that matched no entry, if any.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::UnmatchedInclude`] naming every such pattern.
    pub(crate) fn require_all_matched(&self, selection: &EntrySelection) -> Result<()> {
        let unmatched: Box<[EntryPattern]> = selection
            .include()
            .iter()
            .zip(self.matched.iter())
            .filter(|(_, hit)| !hit.get())
            .map(|(pattern, _)| pattern.clone())
            .collect();
        unmatched.is_empty().ok_or(ArchiveError::UnmatchedInclude {
            patterns: unmatched,
        })
    }
}

/// The landings of the regular files a rewriting selection admitted, and which
/// of them more than one entry maps to.
///
/// Stripping or flattening can make two entries land on one path, and only one
/// of them wins. A hardlink names its target by archive path, so it cannot say
/// which of the colliding entries it means; [`Self::require_unambiguous`]
/// refuses it instead of copying the winner's bytes. Nothing is recorded
/// under [`PathRewrite::Keep`], so a plain extraction pays nothing.
#[derive(Debug, Default)]
pub(crate) struct LandingClaims {
    seen: RefCell<HashSet<PathBuf>>,
    ambiguous: RefCell<HashSet<PathBuf>>,
}

impl LandingClaims {
    /// Records that a file entry lands at `landing`.
    pub(crate) fn claim(&self, selection: &EntrySelection, landing: &Path) {
        if selection.rewrite == PathRewrite::Keep {
            return;
        }
        let mut seen = self.seen.borrow_mut();
        if !seen.insert(landing.to_path_buf()) {
            self.ambiguous.borrow_mut().insert(landing.to_path_buf());
        }
    }

    /// Fails when several entries map to `target`, the landing a hardlink
    /// refers to.
    ///
    /// # Errors
    ///
    /// Returns [`Violation::HardlinkTargetAmbiguous`].
    pub(crate) fn require_unambiguous(&self, link: &Path, target: &Path) -> Result<()> {
        if self.ambiguous.borrow().contains(target) {
            return Err(Violation::HardlinkTargetAmbiguous {
                link: crate::path_text(link).into(),
                target: crate::path_text(target).into(),
            }
            .into());
        }
        Ok(())
    }
}

/// The hardlink refusal for a target that is not extracted.
fn target_not_extracted(link: &Path, target: &Path) -> ArchiveError {
    Violation::HardlinkTargetNotExtracted {
        link: crate::path_text(link).into(),
        target: crate::path_text(target).into(),
    }
    .into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::assert_matches;

    use super::*;
    use crate::non_zero;

    fn pattern(text: &str) -> EntryPattern {
        EntryPattern::parse_for(ConfigSetting::EntryInclude, text).unwrap()
    }

    fn decide(selection: &EntrySelection, path: &str) -> Decision {
        selection
            .decide(Path::new(path), EntryShape::File, None)
            .unwrap()
    }

    fn skipped(decision: &Decision) -> Option<SkipKind> {
        match decision {
            Decision::Skip(kind) => Some(*kind),
            Decision::Extract(_) => None,
        }
    }

    fn landing(decision: Decision) -> Option<PathBuf> {
        match decision {
            Decision::Extract(Placement::Rewritten(rewritten)) => Some(rewritten.0),
            _ => None,
        }
    }

    #[test]
    fn default_selects_everything_unchanged() {
        let selection = EntrySelection::default();
        assert!(selection.is_default());
        assert_matches!(
            decide(&selection, "a/b"),
            Decision::Extract(Placement::Unchanged)
        );
    }

    #[test]
    fn include_selects_a_subtree_and_nothing_else() {
        let selection = EntrySelection::default().with_include(pattern("a/b"));
        assert!(skipped(&decide(&selection, "a/b/c.txt")).is_none());
        assert!(skipped(&decide(&selection, "a/b")).is_none());
        assert_eq!(
            skipped(&decide(&selection, "a/d.txt")),
            Some(SkipKind::NotSelected)
        );
    }

    #[test]
    fn exclude_always_wins_over_include() {
        let selection = EntrySelection::default()
            .with_include(pattern("src"))
            .with_exclude(pattern("src/generated"));
        assert!(skipped(&decide(&selection, "src/main.rs")).is_none());
        assert_eq!(
            skipped(&decide(&selection, "src/generated/x.rs")),
            Some(SkipKind::NotSelected)
        );
    }

    #[test]
    fn bare_name_matches_a_component_at_any_depth() {
        let selection = EntrySelection::default().with_exclude(pattern("docs"));
        assert!(skipped(&decide(&selection, "top/docs/a")).is_some());
        assert!(skipped(&decide(&selection, "top/doc/a")).is_none());
    }

    #[test]
    fn matching_is_case_sensitive() {
        let selection = EntrySelection::default().with_include(pattern("README"));
        assert!(skipped(&decide(&selection, "readme")).is_some());
        assert!(skipped(&decide(&selection, "README")).is_none());
    }

    #[test]
    fn strip_removes_leading_components_and_skips_what_runs_out() {
        let strip = StripComponents::new(non_zero!(1), non_zero!(32)).unwrap();
        let selection = EntrySelection::default().with_rewrite(PathRewrite::Strip(strip));
        assert_eq!(
            landing(decide(&selection, "top/src/main.rs")),
            Some(PathBuf::from("src/main.rs"))
        );
        for exhausted in ["top", "README"] {
            assert_eq!(
                skipped(&decide(&selection, exhausted)),
                Some(SkipKind::StrippedAway)
            );
        }
        assert_eq!(
            skipped(&decide(&selection, "")),
            Some(SkipKind::StrippedAway)
        );
    }

    #[test]
    fn selection_matches_before_stripping() {
        let strip = StripComponents::new(non_zero!(1), non_zero!(32)).unwrap();
        let selection = EntrySelection::default()
            .with_include(pattern("top/src"))
            .with_rewrite(PathRewrite::Strip(strip));
        assert_eq!(
            landing(decide(&selection, "top/src/a")),
            Some(PathBuf::from("src/a"))
        );
        assert_eq!(
            skipped(&decide(&selection, "src/a")),
            Some(SkipKind::NotSelected)
        );
    }

    #[test]
    fn strip_and_flatten_builders_set_one_rewrite_without_disturbing_the_other() {
        let strip = StripComponents::new(non_zero!(1), non_zero!(32)).unwrap();
        let stripped = EntrySelection::default().with_strip(Some(strip));
        let flattened = EntrySelection::default().with_flatten(true);

        assert_eq!(stripped.rewrite(), PathRewrite::Strip(strip));
        assert_eq!(flattened.rewrite(), PathRewrite::Flatten);
        assert_eq!(
            flattened.clone().with_strip(None).rewrite(),
            PathRewrite::Flatten
        );
        assert_eq!(
            stripped.clone().with_flatten(false).rewrite(),
            PathRewrite::Strip(strip)
        );
        assert_eq!(stripped.with_strip(None).rewrite(), PathRewrite::Keep);
        assert_eq!(flattened.with_flatten(false).rewrite(), PathRewrite::Keep);
    }

    #[test]
    fn the_list_builders_replace_a_list_and_keep_the_rewrite() {
        let strip = StripComponents::new(non_zero!(1), non_zero!(32)).unwrap();
        let selection = EntrySelection::default()
            .with_include(pattern("old"))
            .with_exclude(pattern("old"))
            .with_rewrite(PathRewrite::Strip(strip))
            .with_include_list(vec![pattern("a"), pattern("b")])
            .with_exclude_list(Vec::new());

        assert_eq!(selection.include(), [pattern("a"), pattern("b")]);
        assert!(selection.exclude().is_empty());
        assert_eq!(selection.rewrite(), PathRewrite::Strip(strip));
    }

    #[test]
    fn strip_count_is_bounded_by_the_path_depth() {
        assert!(StripComponents::new(non_zero!(32), non_zero!(32)).is_ok());
        let refused = StripComponents::new(non_zero!(33), non_zero!(32));
        assert_matches!(
            refused,
            Err(ArchiveError::InvalidConfiguration {
                setting: ConfigSetting::StripComponents,
                problem: ConfigProblem::TooLarge { max: 32 },
            })
        );
    }

    #[test]
    fn include_hits_report_every_pattern_that_matched_nothing() {
        let selection = EntrySelection::default()
            .with_include(pattern("a"))
            .with_include(pattern("b"))
            .with_exclude(pattern("a"));
        let hits = IncludeHits::of(&selection);
        selection
            .decide(Path::new("a"), EntryShape::File, Some(&hits))
            .unwrap();
        let Err(ArchiveError::UnmatchedInclude { patterns }) = hits.require_all_matched(&selection)
        else {
            panic!("pattern b matched nothing");
        };
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].to_string(), "b");
    }

    #[test]
    fn a_nested_scratch_use_gets_its_own_empty_buffer() {
        let hits = IncludeHits::of(&EntrySelection::default());
        hits.with_scratch(|outer| {
            outer.push(1);
            hits.with_scratch(|inner| {
                assert!(inner.is_empty());
                inner.push(2);
            });
            assert_eq!(outer.as_slice(), [1]);
        });
    }

    #[test]
    fn link_target_maps_through_the_same_rules() {
        let strip = StripComponents::new(non_zero!(1), non_zero!(32)).unwrap();
        let selection = EntrySelection::default()
            .with_exclude(pattern("hidden"))
            .with_rewrite(PathRewrite::Strip(strip));
        assert_matches!(
            selection.map_link_target(Path::new("./top/orig"), Admit::Refuse).unwrap(),
            TargetMapping::Mapped(path) if path == Path::new("orig")
        );
        assert_matches!(
            selection
                .map_link_target(Path::new("top"), Admit::Refuse)
                .unwrap(),
            TargetMapping::NotExtracted
        );
        assert_matches!(
            selection
                .map_link_target(Path::new("top/hidden/x"), Admit::Refuse)
                .unwrap(),
            TargetMapping::NotExtracted
        );
        assert_matches!(
            selection.map_link_target(Path::new("top/../x"), Admit::Refuse),
            Err(ArchiveError::PathTraversal { .. })
        );
        assert_matches!(
            selection
                .map_link_target(Path::new("/abs"), Admit::Refuse)
                .unwrap(),
            TargetMapping::Unchanged,
            "a refused absolute target stays for the validator to refuse"
        );
        assert_matches!(
            selection
                .map_link_target(Path::new("/abs"), Admit::Allow)
                .unwrap(),
            TargetMapping::NotExtracted
        );
        assert_matches!(
            selection
                .map_link_target(Path::new("/"), Admit::Refuse)
                .unwrap(),
            TargetMapping::Unchanged
        );
    }

    #[test]
    fn absolute_link_target_is_relocated_only_where_absolute_paths_are_admitted() {
        let strip = StripComponents::new(non_zero!(1), non_zero!(32)).unwrap();
        let selection = EntrySelection::default()
            .with_include(pattern("top"))
            .with_rewrite(PathRewrite::Strip(strip));
        assert_matches!(
            selection.map_link_target(Path::new("/top/orig"), Admit::Allow).unwrap(),
            TargetMapping::Mapped(path) if path == Path::new("orig")
        );
        assert_matches!(
            selection
                .map_link_target(Path::new("/other/orig"), Admit::Allow)
                .unwrap(),
            TargetMapping::NotExtracted
        );
        assert_matches!(
            selection.map_link_target(Path::new("/top/../x"), Admit::Allow),
            Err(ArchiveError::PathTraversal { .. })
        );
        assert_matches!(
            selection.map_link_target(Path::new("/top/orig"), Admit::Refuse).unwrap(),
            TargetMapping::Mapped(path) if path == Path::new("/orig")
        );
    }
}
