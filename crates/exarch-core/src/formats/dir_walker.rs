//! Parent-directory creation that never walks through a link it did not vet.
//!
//! The walk starts at the destination's pinned directory handle and descends
//! one component at a time with a handle-relative, no-follow open (`openat`
//! with `O_NOFOLLOW` on Unix, `NtCreateFile` on Windows), creating missing
//! components with `mkdirat` or its Windows equivalent. Every step operates on
//! the handle the previous step returned, so a link swapped in for an already
//! vetted component cannot redirect what follows, and nothing is remembered
//! between entries.
//! The returned [`VettedDir`] is the handle the caller writes through.
//!
//! The walk holds at most two handles: the current directory and the one being
//! opened.
//!
//! # Failure handling
//!
//! A failed open is classified by `fstatat(NOFOLLOW)`, not by `errno`, because
//! platforms disagree on what a directory open of a symlink reports. A missing
//! component is created and opened once more; a second failure, or any
//! failure whose probe finds nothing to blame, returns the original I/O error
//! so an attacker who removes and re-creates entries cannot make the walk
//! retry forever.

#[cfg(unix)]
use std::collections::VecDeque;
#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use crate::ArchiveError;
use crate::Result;
use crate::SecurityConfig;
use crate::Violation;
use crate::formats::pinned_dir::Leaf;
use crate::formats::pinned_dir::PinnedRoot;
use crate::formats::pinned_dir::VettedDir;
#[cfg(not(unix))]
use crate::security::fs_view::HostFs;
#[cfg(not(unix))]
use crate::security::fs_view::LinkClass;
#[cfg(unix)]
use crate::security::fs_view::MAX_SYMLINK_HOPS;
use crate::security::fs_view::Occupant;
use crate::security::fs_view::ParentBlocker;
use crate::security::fs_view::PathModel;
#[cfg(not(unix))]
use crate::security::fs_view::classify_link;
use crate::security::fs_view::joined;
use crate::security::fs_view::name_too_long;
use crate::security::fs_view::projected_landing_within_limits;
use crate::types::SafePath;
use crate::types::safe_path::ParentCheck;

/// A directory handle that is either the pinned destination root, borrowed, or
/// a handle the walk opened below it.
///
/// An entry directly in the destination needs no new descriptor: the root
/// handle is already pinned, so lending it saves an `openat` and a `close` per
/// top-level entry.
#[derive(Debug)]
pub enum DirRef<'r> {
    /// The destination's pinned root handle, lent by the [`PinnedRoot`].
    Root(&'r VettedDir),
    /// A handle the walk opened below the root, owned by the caller.
    Opened(VettedDir),
}

impl DirRef<'_> {
    /// Returns an owned handle, reopening the root when this one is borrowed,
    /// for callers that keep the directory beyond the borrow of the root.
    pub(crate) fn into_owned(self) -> Result<VettedDir> {
        match self {
            Self::Root(root) => Ok(root.reopen()?),
            Self::Opened(dir) => Ok(dir),
        }
    }
}

impl std::ops::Deref for DirRef<'_> {
    type Target = VettedDir;

    fn deref(&self) -> &VettedDir {
        match self {
            Self::Root(root) => root,
            Self::Opened(dir) => dir,
        }
    }
}

/// What an existing symlink among the parent components may be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkPolicy {
    /// Any symlink component is refused.
    Refuse,
    /// A symlink component is accepted only if it resolves to a directory
    /// inside the destination.
    ContainedOnly,
}

impl LinkPolicy {
    fn of(config: &SecurityConfig) -> Self {
        if config.allowed.symlinks.is_allowed() {
            Self::ContainedOnly
        } else {
            Self::Refuse
        }
    }
}

/// What a walk does with a component that does not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Missing {
    Create,
    Fail,
}

/// Which symlink rule a walk applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Links {
    /// The walker's configured [`LinkPolicy`].
    Policy,
    /// Any symlink is a blocker; used to re-walk a path that was already
    /// resolved to a symlink-free form.
    Strict,
}

/// One opened component, with the symlink-free location it resolved to when
/// the component was a symlink.
struct Hop<'r> {
    dir: DirRef<'r>,
    resolved: Option<PathBuf>,
}

impl Hop<'_> {
    fn plain(dir: VettedDir) -> Self {
        Self {
            dir: DirRef::Opened(dir),
            resolved: None,
        }
    }
}

/// Creates and vets the directories that archive entries are written into.
#[derive(Debug, Clone, Copy)]
pub struct DirWalker {
    links: LinkPolicy,
}

impl DirWalker {
    /// Builds a walker that applies the symlink policy of `config`.
    pub fn new(config: &SecurityConfig) -> Self {
        Self {
            links: LinkPolicy::of(config),
        }
    }

    /// Creates `dest/rel` and every missing ancestor, vetting each component,
    /// and returns a handle on the directory.
    ///
    /// # Errors
    ///
    /// Returns `SecurityViolation` for a symlink component the policy refuses
    /// or one that dangles or does not resolve to a directory, `SymlinkEscape`
    /// for one that leaves `dest`, `PathTraversal` for a non-relative `rel`,
    /// and an I/O error when a component is a file or cannot be created. A
    /// blocking component is reported against `rel` with the same text and
    /// category as `verify`.
    pub(crate) fn ensure_dir<'r, P: ParentCheck>(
        self,
        root: &'r PinnedRoot,
        rel: &SafePath<P>,
    ) -> Result<DirRef<'r>> {
        let rel = rel.as_path();
        self.descend(root, rel, rel, Missing::Create, Links::Policy)
    }

    /// Creates the parent directory of `dest/rel` like [`Self::ensure_dir`]
    /// and returns it with the name of the entry inside it.
    ///
    /// # Errors
    ///
    /// Same as [`Self::ensure_dir`], plus `PathTraversal` when `rel` does not
    /// end in a normal name.
    pub(crate) fn ensure_parent<'r, 'p, P: ParentCheck>(
        self,
        root: &'r PinnedRoot,
        rel: &'p SafePath<P>,
    ) -> Result<(DirRef<'r>, Leaf<'p>)> {
        let rel = rel.as_path();
        let (parent, leaf) = Leaf::split(rel)?;
        let dir = self.descend(root, parent, rel, Missing::Create, Links::Policy)?;
        Ok((dir, leaf))
    }

    /// Opens the parent directory of `dest/rel` without creating anything.
    ///
    /// # Errors
    ///
    /// Same as [`Self::ensure_parent`]; a missing component is an I/O error of
    /// kind `NotFound`.
    pub(crate) fn open_parent<'r, 'p>(
        self,
        root: &'r PinnedRoot,
        rel: &'p Path,
    ) -> Result<(DirRef<'r>, Leaf<'p>)> {
        let (parent, leaf) = Leaf::split(rel)?;
        let dir = self.descend(root, parent, rel, Missing::Fail, Links::Policy)?;
        Ok((dir, leaf))
    }

    /// Like [`Self::open_parent`], but any symlink on the way is refused. For
    /// a path that was resolved through symlinks and is expected to be free of
    /// them.
    ///
    /// # Errors
    ///
    /// Same as [`Self::open_parent`].
    pub(crate) fn open_resolved_parent<'r, 'p>(
        self,
        root: &'r PinnedRoot,
        rel: &'p Path,
    ) -> Result<(DirRef<'r>, Leaf<'p>)> {
        let (parent, leaf) = Leaf::split(rel)?;
        let dir = self.descend(root, parent, rel, Missing::Fail, Links::Strict)?;
        Ok((dir, leaf))
    }

    fn descend<'r>(
        self,
        root: &'r PinnedRoot,
        dir: &Path,
        entry: &Path,
        missing: Missing,
        links: Links,
    ) -> Result<DirRef<'r>> {
        let (dir_ref, landing) = self.walk(root, dir, entry, missing, links)?;
        if let Some(landing) = landing {
            let tail = entry.strip_prefix(dir).unwrap_or_else(|_| Path::new(""));
            projected_landing_within_limits(PathModel::Host, &landing, tail)?;
        }
        Ok(dir_ref)
    }

    /// Walks `dir` and also returns where the walk ended, relative to the
    /// destination, when a symlink on the way redirected it.
    fn walk<'r>(
        self,
        root: &'r PinnedRoot,
        dir: &Path,
        entry: &Path,
        missing: Missing,
        links: Links,
    ) -> Result<(DirRef<'r>, Option<PathBuf>)> {
        let mut walked = PathBuf::new();
        let mut landing: Option<PathBuf> = None;
        let mut current: Option<DirRef<'r>> = None;
        let tail = entry.strip_prefix(dir).unwrap_or_else(|_| Path::new(""));
        let mut components = dir.components();
        while let Some(component) = components.next() {
            let Some(leaf) = Leaf::from_component(component) else {
                if matches!(component, std::path::Component::CurDir) {
                    continue;
                }
                return Err(ArchiveError::PathTraversal {
                    path: dir.to_path_buf(),
                });
            };
            walked.push(leaf.as_os_str());
            let parent = current.as_deref().unwrap_or_else(|| root.dir());
            let here = landing
                .as_deref()
                .unwrap_or_else(|| walked.parent().unwrap_or_else(|| Path::new("")));
            let site = LinkSite { parent, leaf, here };
            let hop = self.step(root, &site, &walked, entry, missing, links)?;
            let redirected = hop.resolved.is_some();
            match (hop.resolved, landing.as_mut()) {
                (Some(resolved), _) => landing = Some(resolved),
                (None, Some(landing)) => landing.push(leaf.as_os_str()),
                (None, None) => {}
            }
            if let (true, Some(landing)) = (redirected, landing.as_deref()) {
                Self::ensure_fits(&hop.dir, landing, components.as_path(), tail)?;
            }
            current = Some(hop.dir);
        }
        Ok((current.unwrap_or_else(|| DirRef::Root(root.dir())), landing))
    }

    /// Refuses, before anything is created below a symlink target, a landing
    /// that no later component can bring under the host path limit.
    ///
    /// The rest of the path may still cross another symlink, which resets the
    /// landing; only when it provably ends here is the projected length final.
    fn ensure_fits(at: &VettedDir, landing: &Path, rest: &Path, tail: &Path) -> Result<()> {
        let projected = joined(landing, rest);
        if projected_landing_within_limits(PathModel::Host, &projected, tail).is_ok()
            || !Self::ends_here(at, rest)
        {
            return Ok(());
        }
        Err(ArchiveError::Io(name_too_long()))
    }

    /// Whether `rest` below `at` holds no symlink, file or unreadable entry, so
    /// no later component can change where the walk lands.
    fn ends_here(at: &VettedDir, rest: &Path) -> bool {
        let mut opened: Option<VettedDir> = None;
        for component in rest.components() {
            let Some(leaf) = Leaf::from_component(component) else {
                continue;
            };
            let parent = opened.as_ref().unwrap_or(at);
            match parent.probe(leaf) {
                Ok(None) => return true,
                Ok(Some(Occupant::Directory)) => match parent.open_dir(leaf) {
                    Ok(next) => opened = Some(next),
                    Err(_) => return false,
                },
                Ok(Some(_)) | Err(_) => return false,
            }
        }
        true
    }

    fn step<'r>(
        self,
        root: &'r PinnedRoot,
        site: &LinkSite<'_>,
        walked: &Path,
        entry: &Path,
        missing: Missing,
        links: Links,
    ) -> Result<Hop<'r>> {
        let LinkSite { parent, leaf, .. } = *site;
        let mut err = match parent.open_dir(leaf) {
            Ok(dir) => return Ok(Hop::plain(dir)),
            Err(e) => e,
        };
        if err.kind() == std::io::ErrorKind::NotFound && missing == Missing::Create {
            match parent.make_dir(leaf) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
            err = match parent.open_dir(leaf) {
                Ok(dir) => return Ok(Hop::plain(dir)),
                Err(e) => e,
            };
        }
        match parent.probe(leaf) {
            Ok(Some(Occupant::Symlink)) => self.follow(root, site, walked, entry, links),
            Ok(Some(Occupant::File)) => Err(ParentBlocker::File.error(entry, walked)),
            Ok(Some(Occupant::Directory) | None) | Err(_) => Err(err.into()),
        }
    }

    /// Resolves the symlink component `walked` under the active rule.
    ///
    /// The link is resolved even under `Refuse`, to tell a link no policy
    /// admits from one `--allow-symlinks` would; resolving can trigger an
    /// automount lookup.
    fn follow<'r>(
        self,
        root: &'r PinnedRoot,
        site: &LinkSite<'_>,
        walked: &Path,
        entry: &Path,
        links: Links,
    ) -> Result<Hop<'r>> {
        if links == Links::Strict {
            return Err(ParentBlocker::Symlink.error(entry, walked));
        }
        match (Followed::of(root, site, walked), self.links) {
            (Followed::Blocked(blocker), _) => Err(blocker.error(entry, walked)),
            (Followed::Inside(_), LinkPolicy::Refuse) => {
                Err(ArchiveError::from(Violation::SymlinkComponent {
                    walked: walked.display().to_string().into(),
                }))
            }
            (Followed::Inside(inside), LinkPolicy::ContainedOnly) => {
                let (dir, _) = self.walk(root, &inside, entry, Missing::Fail, Links::Strict)?;
                Ok(Hop {
                    dir,
                    resolved: Some(inside),
                })
            }
        }
    }
}

/// Where a symlink component sits: the handle of the directory that holds it,
/// its name, and that directory's symlink-free position below the destination.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(
    not(unix),
    expect(dead_code, reason = "only the Unix resolver reads the link site")
)]
struct LinkSite<'a> {
    parent: &'a VettedDir,
    leaf: Leaf<'a>,
    here: &'a Path,
}

/// What a pre-existing symlink among the parent components turns out to be.
#[derive(Debug, PartialEq, Eq)]
enum Followed {
    /// A directory inside the destination, at this symlink-free path relative
    /// to it.
    Inside(PathBuf),
    /// Nothing may be written through the link.
    Blocked(ParentBlocker),
}

#[cfg(unix)]
impl Followed {
    /// Resolves the link hop by hop with `readlinkat` and `openat` on the
    /// handles the walk holds, so the verdict never depends on how long the
    /// destination's own absolute path is.
    fn of(root: &PinnedRoot, site: &LinkSite<'_>, _walked: &Path) -> Self {
        match HandleResolution::resolve(root, site) {
            Ok(inside) => Self::Inside(inside),
            Err(blocker) => Self::Blocked(blocker),
        }
    }
}

#[cfg(not(unix))]
impl Followed {
    /// Resolves the link by its absolute path: there is no pinned
    /// `readlinkat` on this platform.
    // TODO(#895-followup: Windows/WASI handle-relative walk, canonical_within):
    // realpath makes acceptance depend on the destination's absolute length
    // there.
    fn of(root: &PinnedRoot, _site: &LinkSite<'_>, walked: &Path) -> Self {
        let dest = root.dest();
        match classify_link(&HostFs, &dest.as_path().join(walked), dest) {
            LinkClass::InsideDir(resolved) => Self::Inside(
                resolved
                    .strip_prefix(dest.as_path())
                    .unwrap_or(&resolved)
                    .to_path_buf(),
            ),
            LinkClass::Blocked(blocker) => Self::Blocked(blocker),
        }
    }
}

/// One component still to resolve below the current directory.
#[cfg(unix)]
enum Pending {
    Parent,
    Name(OsString),
}

/// Resolves a symlink the way the kernel would, but one handle-relative step at
/// a time, tracking the symlink-free position it reaches below the root.
///
/// Every file-system operation is relative to a handle the walk already holds
/// (`readlinkat`, `fstatat` with no-follow, `openat` with `O_NOFOLLOW`), so a
/// swap of an already-vetted component cannot redirect it, and no absolute path
/// is ever formed. Anything the resolution cannot prove stays inside the
/// destination fails closed:
///
/// - a `..` above the root is an escape;
/// - an absolute target is mapped only through the destination's canonical root
///   or the root as the caller wrote it (`/var/x` for `/private/var/x`); any
///   other spelling of the same place (a bind mount, another alias) is an
///   escape, where `realpath` used to accept it;
/// - more than [`MAX_SYMLINK_HOPS`] links, a dangling link or a non-directory
///   result blocks the walk.
///
/// The handles of the directories entered are kept on a stack, so a `..` costs
/// one pop; only a `..` that leaves the directory the resolution started in
/// re-opens the ancestors from the root, once.
#[cfg(unix)]
struct HandleResolution<'r> {
    root: &'r PinnedRoot,
    position: PathBuf,
    dir: VettedDir,
    parents: Vec<VettedDir>,
    hops: usize,
    pending: VecDeque<Pending>,
}

#[cfg(unix)]
impl<'r> HandleResolution<'r> {
    fn resolve(
        root: &'r PinnedRoot,
        site: &LinkSite<'_>,
    ) -> std::result::Result<PathBuf, ParentBlocker> {
        let mut state = Self {
            root,
            position: site.here.to_path_buf(),
            dir: site.parent.reopen().map_err(|_| ParentBlocker::Symlink)?,
            parents: Vec::new(),
            hops: 0,
            pending: VecDeque::new(),
        };
        state.follow_link(site.leaf)?;
        while let Some(next) = state.pending.pop_front() {
            match next {
                Pending::Parent => state.ascend()?,
                Pending::Name(name) => state.enter(&name)?,
            }
        }
        Ok(state.position)
    }

    /// Reads the symlink `name` in the current directory and queues its target.
    fn follow_link(&mut self, name: Leaf<'_>) -> std::result::Result<(), ParentBlocker> {
        self.hops += 1;
        if self.hops > MAX_SYMLINK_HOPS {
            return Err(ParentBlocker::Symlink);
        }
        let target = self
            .dir
            .read_link(name)
            .map_err(|_| ParentBlocker::Symlink)?;
        let relative = if target.is_absolute() {
            let dest = self.root.dest();
            let inside = target
                .strip_prefix(dest.as_path())
                .or_else(|_| target.strip_prefix(dest.written()))
                .map_err(|_| ParentBlocker::Escape)?
                .to_path_buf();
            self.position.clear();
            self.parents.clear();
            self.dir = self
                .root
                .dir()
                .reopen()
                .map_err(|_| ParentBlocker::Symlink)?;
            inside
        } else {
            target
        };
        let mut steps = Vec::new();
        for component in relative.components() {
            match component {
                Component::Normal(part) => steps.push(Pending::Name(part.to_os_string())),
                Component::ParentDir => steps.push(Pending::Parent),
                Component::CurDir => {}
                Component::RootDir | Component::Prefix(_) => return Err(ParentBlocker::Escape),
            }
        }
        for step in steps.into_iter().rev() {
            self.pending.push_front(step);
        }
        Ok(())
    }

    /// Moves into `name`, following it when it is itself a symlink.
    fn enter(&mut self, name: &OsString) -> std::result::Result<(), ParentBlocker> {
        let Some(leaf) = Leaf::from_component(Component::Normal(name)) else {
            return Err(ParentBlocker::Symlink);
        };
        if matches!(self.pending.front(), Some(Pending::Parent)) {
            // `name/..` returns to the directory it started in once `name` is
            // known to be a real directory, so it is neither opened nor left.
            return match self.dir.probe(leaf) {
                Ok(Some(Occupant::Directory)) => {
                    self.pending.pop_front();
                    Ok(())
                }
                Ok(Some(Occupant::Symlink)) => self.follow_link(leaf),
                Ok(Some(Occupant::File) | None) | Err(_) => Err(ParentBlocker::Symlink),
            };
        }
        match self.dir.open_dir(leaf) {
            Ok(next) => {
                self.parents.push(std::mem::replace(&mut self.dir, next));
                self.position.push(name);
                Ok(())
            }
            Err(_) => match self.dir.probe(leaf) {
                Ok(Some(Occupant::Symlink)) => self.follow_link(leaf),
                Ok(Some(Occupant::Directory | Occupant::File) | None) | Err(_) => {
                    Err(ParentBlocker::Symlink)
                }
            },
        }
    }

    /// Moves to the parent directory; above the root is an escape.
    fn ascend(&mut self) -> std::result::Result<(), ParentBlocker> {
        if !self.position.pop() {
            return Err(ParentBlocker::Escape);
        }
        if let Some(parent) = self.parents.pop() {
            self.dir = parent;
            return Ok(());
        }
        let mut dir = self
            .root
            .dir()
            .reopen()
            .map_err(|_| ParentBlocker::Symlink)?;
        for component in self.position.components() {
            let Some(leaf) = Leaf::from_component(component) else {
                return Err(ParentBlocker::Symlink);
            };
            let next = dir.open_dir(leaf).map_err(|_| ParentBlocker::Symlink)?;
            self.parents.push(std::mem::replace(&mut dir, next));
        }
        self.dir = dir;
        Ok(())
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::PolicySetting;
    use crate::security::fs_view::MAX_PATH_LEN;
    use crate::types::DestDir;
    use crate::types::safe_path::Resolved;
    use std::assert_matches;
    use std::fs;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    fn walker(allow_symlinks: bool) -> DirWalker {
        let config = SecurityConfig::default().with_allow_symlinks(allow_symlinks);
        DirWalker::new(&config)
    }

    fn sp(path: &str) -> SafePath {
        SafePath::<Resolved>::for_test(path)
    }

    fn dest_with_outside() -> (TempDir, PinnedRoot, PathBuf) {
        let root = TempDir::new().unwrap();
        let dest = root.path().join("dest");
        let outside = root.path().join("outside");
        fs::create_dir(&dest).unwrap();
        fs::create_dir(&outside).unwrap();
        (
            root,
            PinnedRoot::open(DestDir::new(dest).unwrap()).unwrap(),
            outside.canonicalize().unwrap(),
        )
    }

    #[test]
    fn creates_missing_components_and_is_idempotent() {
        let (_root, dest, _) = dest_with_outside();
        let walker = walker(false);

        walker.ensure_dir(&dest, &sp("a/b/c")).unwrap();
        walker.ensure_dir(&dest, &sp("a/b/c")).unwrap();
        walker.ensure_parent(&dest, &sp("a/b/c/f.txt")).unwrap();

        assert!(dest.dest().as_path().join("a/b/c").is_dir());
    }

    #[test]
    fn parent_of_a_top_level_name_is_the_destination() {
        let (_root, dest, _) = dest_with_outside();
        let rel = sp("f.txt");
        let (dir, leaf) = walker(false).ensure_parent(&dest, &rel).unwrap();

        dir.create_new(leaf, None).unwrap();

        assert!(dest.dest().as_path().join("f.txt").is_file());
    }

    #[test]
    fn top_level_parent_borrows_the_root_and_nested_parent_opens_one() {
        let (_root, dest, _) = dest_with_outside();
        let walker = walker(false);

        let (top, _) = walker.ensure_parent(&dest, &sp("f.txt")).unwrap();
        let (nested, _) = walker.ensure_parent(&dest, &sp("d/f.txt")).unwrap();

        assert_matches!(top, DirRef::Root(_));
        assert_matches!(nested, DirRef::Opened(_));
    }

    #[test]
    fn borrowed_root_stays_pinned_when_the_destination_path_is_swapped() {
        let (root, dest, outside) = dest_with_outside();
        let rel = sp("f.txt");
        let (dir, leaf) = walker(false).ensure_parent(&dest, &rel).unwrap();
        assert_matches!(dir, DirRef::Root(_));

        let moved = root.path().join("moved");
        fs::rename(dest.dest().as_path(), &moved).unwrap();
        symlink(&outside, dest.dest().as_path()).unwrap();
        dir.create_new(leaf, None).unwrap();

        assert!(moved.join("f.txt").is_file());
        assert!(!outside.join("f.txt").exists());
    }

    #[test]
    fn planted_symlink_is_refused_with_the_borrowed_root() {
        let (_root, dest, outside) = dest_with_outside();
        symlink(&outside, dest.dest().as_path().join("planted")).unwrap();

        let err = walker(true)
            .ensure_parent(&dest, &sp("planted/f.txt"))
            .map(|_| ())
            .unwrap_err();

        assert_matches!(err, ArchiveError::SymlinkEscape { .. }, "{err}");
        assert!(!outside.join("f.txt").exists());
    }

    #[test]
    fn into_owned_gives_a_usable_handle_for_both_variants() {
        let (_root, dest, _) = dest_with_outside();
        let walker = walker(false);

        let (top_rel, nested_rel) = (sp("top.txt"), sp("d/n.txt"));
        let (top, top_leaf) = walker.ensure_parent(&dest, &top_rel).unwrap();
        let (nested, nested_leaf) = walker.ensure_parent(&dest, &nested_rel).unwrap();
        let top = top.into_owned().unwrap();
        let nested = nested.into_owned().unwrap();
        top.create_new(top_leaf, None).unwrap();
        nested.create_new(nested_leaf, None).unwrap();

        assert!(dest.dest().as_path().join("top.txt").is_file());
        assert!(dest.dest().as_path().join("d/n.txt").is_file());
    }

    #[test]
    fn open_parent_does_not_create_and_reports_not_found() {
        let (_root, dest, _) = dest_with_outside();

        let err = walker(false)
            .open_parent(&dest, sp("missing/f").as_path())
            .unwrap_err();

        assert_matches!(&err, ArchiveError::Io(e) if e.kind() == std::io::ErrorKind::NotFound);
        assert!(!dest.dest().as_path().join("missing").exists());
    }

    #[test]
    fn refuses_a_symlink_component_without_creating_below_it() {
        let (_root, dest, outside) = dest_with_outside();
        symlink(&outside, dest.dest().as_path().join("redirect")).unwrap();

        let err = walker(false)
            .ensure_dir(&dest, &sp("redirect/sub"))
            .unwrap_err();

        assert_matches!(err, ArchiveError::SymlinkEscape { .. }, "{err}");
        assert!(!outside.join("sub").exists());
    }

    #[test]
    fn refuse_policy_offers_the_flag_only_for_a_link_it_would_admit() {
        let (_root, dest, outside) = dest_with_outside();
        let base = dest.dest().as_path().to_path_buf();
        fs::create_dir(base.join("real")).unwrap();
        symlink("real", base.join("alias")).unwrap();
        symlink("missing", base.join("dangling")).unwrap();
        fs::write(base.join("f"), b"x").unwrap();
        symlink("f", base.join("tofile")).unwrap();
        symlink(&outside, base.join("away")).unwrap();

        let relaxable = |rel: &str| {
            walker(false)
                .ensure_dir(&dest, &sp(rel))
                .unwrap_err()
                .relaxable_by()
        };

        assert_eq!(relaxable("alias/x"), Some(PolicySetting::Symlinks));
        assert_eq!(relaxable("dangling/x"), None);
        assert_eq!(relaxable("tofile/x"), None);
        assert_eq!(relaxable("away/x"), None);
    }

    #[test]
    fn refuses_a_symlink_to_a_file_component() {
        let (_root, dest, outside) = dest_with_outside();
        fs::write(outside.join("f"), b"x").unwrap();
        symlink(outside.join("f"), dest.dest().as_path().join("link")).unwrap();

        assert!(walker(false).ensure_dir(&dest, &sp("link/x")).is_err());
    }

    #[test]
    fn contained_policy_refuses_an_escaping_symlink() {
        let (_root, dest, outside) = dest_with_outside();
        symlink(&outside, dest.dest().as_path().join("redirect")).unwrap();

        let err = walker(true)
            .ensure_dir(&dest, &sp("redirect/sub"))
            .unwrap_err();

        assert_matches!(err, ArchiveError::SymlinkEscape { .. }, "{err}");
        assert!(!outside.join("sub").exists());
    }

    #[test]
    fn contained_policy_accepts_a_link_to_a_directory_inside_dest() {
        let (_root, dest, _) = dest_with_outside();
        fs::create_dir(dest.dest().as_path().join("real")).unwrap();
        symlink("real", dest.dest().as_path().join("alias")).unwrap();

        walker(true).ensure_dir(&dest, &sp("alias/sub")).unwrap();

        assert!(dest.dest().as_path().join("real/sub").is_dir());
    }

    #[test]
    fn an_absolute_target_through_the_canonical_root_is_accepted() {
        let (_root, dest, _) = dest_with_outside();
        let base = dest.dest().as_path().to_path_buf();
        fs::create_dir(base.join("real")).unwrap();
        symlink(base.join("real"), base.join("alias")).unwrap();

        walker(true).ensure_dir(&dest, &sp("alias/sub")).unwrap();

        assert!(base.join("real/sub").is_dir());
    }

    // `/var/...` written by the caller versus `/private/var/...` canonical: an
    // absolute target spelled through the written root is accepted.
    #[test]
    fn an_absolute_target_spelled_through_the_written_root_is_accepted() {
        let temp = TempDir::new().unwrap();
        let real_root = temp.path().join("dest");
        fs::create_dir(&real_root).unwrap();
        let written = temp.path().join("written_alias");
        symlink(&real_root, &written).unwrap();
        let dest = PinnedRoot::open(DestDir::new(&written).unwrap()).unwrap();
        assert_ne!(dest.dest().as_path(), dest.dest().written());
        fs::create_dir(real_root.join("real")).unwrap();
        symlink(written.join("real"), real_root.join("alias")).unwrap();

        walker(true).ensure_dir(&dest, &sp("alias/sub")).unwrap();

        assert!(real_root.join("real/sub").is_dir());
    }

    // The absolute spelling is mapped only through the canonical or the written
    // root; another spelling of the same place is refused where `realpath`
    // accepted it.
    #[test]
    fn an_absolute_target_spelled_through_another_alias_of_the_root_is_refused() {
        let (root, dest, _) = dest_with_outside();
        let base = dest.dest().as_path().to_path_buf();
        fs::create_dir(base.join("real")).unwrap();
        let alias_of_root = root.path().join("alias_of_dest");
        symlink(&base, &alias_of_root).unwrap();
        symlink(alias_of_root.join("real"), base.join("alias")).unwrap();

        let err = walker(true)
            .ensure_dir(&dest, &sp("alias/sub"))
            .unwrap_err();

        assert_matches!(err, ArchiveError::SymlinkEscape { .. }, "{err}");
        assert!(!base.join("real/sub").exists());
    }

    #[test]
    fn a_target_that_leaves_the_root_and_reenters_it_is_refused() {
        let (_root, dest, _) = dest_with_outside();
        let base = dest.dest().as_path().to_path_buf();
        fs::create_dir(base.join("real")).unwrap();
        symlink("../dest/real", base.join("up")).unwrap();

        let err = walker(true).ensure_dir(&dest, &sp("up/sub")).unwrap_err();

        assert_matches!(err, ArchiveError::SymlinkEscape { .. }, "{err}");
        assert!(!base.join("real/sub").exists());
    }

    #[test]
    fn a_link_to_the_parent_directory_resolves_to_it() {
        let (_root, dest, _) = dest_with_outside();
        let base = dest.dest().as_path().to_path_buf();
        fs::create_dir(base.join("x")).unwrap();
        symlink("..", base.join("x/up")).unwrap();

        walker(true).ensure_dir(&dest, &sp("x/up/y")).unwrap();

        assert!(base.join("y").is_dir());
    }

    /// A link at the bottom of a deep directory whose target climbs the whole
    /// way back up, crossed by many entries: each crossing is one handle pop
    /// per `..`, not a re-walk from the root.
    fn deep_climbing_link(depth: usize) -> (TempDir, PinnedRoot, String) {
        let (root, dest, _) = dest_with_outside();
        let base = dest.dest().as_path().to_path_buf();
        let deep = vec!["a"; depth].join("/");
        walker(false).ensure_dir(&dest, &sp(&deep)).unwrap();
        fs::create_dir(base.join("x")).unwrap();
        let climb = vec![".."; depth].join("/");
        symlink(format!("{climb}/x"), base.join(&deep).join("l")).unwrap();
        (root, dest, format!("{deep}/l"))
    }

    #[test]
    fn a_link_climbing_out_of_a_deep_directory_resolves_to_the_root_level_target() {
        let (_root, dest, link) = deep_climbing_link(30);

        walker(true)
            .ensure_dir(&dest, &sp(&format!("{link}/sub")))
            .unwrap();

        assert!(dest.dest().as_path().join("x/sub").is_dir());
    }

    #[test]
    fn crossing_a_deep_climbing_link_many_times_keeps_each_hop_cheap() {
        let (_root, dest, link) = deep_climbing_link(30);
        let started = std::time::Instant::now();

        for i in 0..2000 {
            walker(true)
                .ensure_dir(&dest, &sp(&format!("{link}/d{i}")))
                .unwrap();
        }

        assert!(
            started.elapsed() < std::time::Duration::from_secs(60),
            "2000 crossings took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn name_then_parent_returns_only_through_a_real_directory() {
        let (_root, dest, _) = dest_with_outside();
        let base = dest.dest().as_path().to_path_buf();
        fs::create_dir_all(base.join("a/b")).unwrap();
        fs::create_dir(base.join("real")).unwrap();
        fs::write(base.join("file"), b"x").unwrap();
        symlink("a/b", base.join("s")).unwrap();
        symlink("real/../real", base.join("plain")).unwrap();
        symlink("s/..", base.join("through_link")).unwrap();
        symlink("file/..", base.join("through_file")).unwrap();
        symlink("missing/..", base.join("through_missing")).unwrap();

        walker(true).ensure_dir(&dest, &sp("plain/x")).unwrap();
        assert!(base.join("real/x").is_dir());
        // `s/..` is the parent of the link's target (`a`), not of the link.
        walker(true)
            .ensure_dir(&dest, &sp("through_link/y"))
            .unwrap();
        assert!(base.join("a/y").is_dir());
        assert!(!base.join("y").exists());
        assert!(
            walker(true)
                .ensure_dir(&dest, &sp("through_file/z"))
                .is_err()
        );
        assert!(
            walker(true)
                .ensure_dir(&dest, &sp("through_missing/z"))
                .is_err()
        );
    }

    // The shape of the perf fixture, scaled down: a chain of links whose
    // targets each go down a nested directory, back up, and on to the previous
    // link.
    #[test]
    fn a_chain_of_down_and_up_links_resolves_and_stays_cheap() {
        let (_root, dest, _) = dest_with_outside();
        let base = dest.dest().as_path().to_path_buf();
        let nested = vec!["d"; 15].join("/");
        walker(false).ensure_dir(&dest, &sp(&nested)).unwrap();
        fs::create_dir(base.join("end")).unwrap();
        let wiggle = format!("{nested}/{}", vec![".."; 15].join("/"));
        symlink("end", base.join("l0")).unwrap();
        for i in 1..=10 {
            symlink(format!("{wiggle}/l{}", i - 1), base.join(format!("l{i}"))).unwrap();
        }
        let started = std::time::Instant::now();

        for i in 0..300 {
            walker(true)
                .ensure_dir(&dest, &sp(&format!("l10/e{i}")))
                .unwrap();
        }

        assert!(base.join("end/e299").is_dir());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_loop_of_links_is_refused_and_creates_nothing() {
        let (_root, dest, _) = dest_with_outside();
        let base = dest.dest().as_path().to_path_buf();
        symlink("b", base.join("a")).unwrap();
        symlink("a", base.join("b")).unwrap();

        assert!(walker(true).ensure_dir(&dest, &sp("a/x")).is_err());
        assert_eq!(fs::read_dir(&base).unwrap().count(), 2);
    }

    #[test]
    fn the_hop_limit_is_exact_and_shared_with_the_virtual_tree() {
        use crate::security::fs_view::MAX_SYMLINK_HOPS;

        for (hops, accepted) in [(MAX_SYMLINK_HOPS, true), (MAX_SYMLINK_HOPS + 1, false)] {
            let (_root, dest, _) = dest_with_outside();
            let base = dest.dest().as_path().to_path_buf();
            fs::create_dir(base.join("real")).unwrap();
            for i in 1..hops {
                symlink(format!("l{}", i + 1), base.join(format!("l{i}"))).unwrap();
            }
            symlink("real", base.join(format!("l{hops}"))).unwrap();

            let result = walker(true).ensure_dir(&dest, &sp("l1/x"));

            assert_eq!(result.is_ok(), accepted, "{hops} hops");
        }
    }

    fn name_of_len(len: usize) -> String {
        let mut name = String::new();
        while name.len() < len {
            if !name.is_empty() {
                name.push('/');
            }
            let room = len - name.len();
            name.push_str(&"n".repeat(room.min(200)));
        }
        assert_eq!(name.len(), len);
        name
    }

    /// Builds `dest/d -> chain` and returns a relative entry `d/<rest>` whose
    /// landing is `landing_len` bytes long. The chain is sized from the
    /// destination so the link itself resolves on every platform.
    fn long_landing(dest: &PinnedRoot, landing_len: usize) -> SafePath {
        let base = dest.dest().as_path();
        let chain_len = MAX_PATH_LEN - base.as_os_str().len() - 64;
        let chain = name_of_len(chain_len);
        walker(false).ensure_dir(dest, &sp(&chain)).unwrap();
        symlink(&chain, base.join("d")).unwrap();
        let rest = name_of_len(landing_len - chain_len - 1);
        sp(&format!("d/{rest}/f"))
    }

    #[test]
    fn contained_policy_accepts_a_landing_exactly_at_the_path_limit() {
        let (_root, dest, _) = dest_with_outside();
        let landing_len = MAX_PATH_LEN - "/f".len();
        let rel = long_landing(&dest, landing_len);

        walker(true).ensure_parent(&dest, &rel).unwrap();
    }

    #[test]
    fn contained_policy_refuses_a_landing_one_byte_over_the_path_limit() {
        let (_root, dest, _) = dest_with_outside();
        let landing_len = MAX_PATH_LEN - "/f".len() + 1;
        let rel = long_landing(&dest, landing_len);

        let err = walker(true)
            .ensure_parent(&dest, &rel)
            .map(|_| ())
            .unwrap_err();

        assert_matches!(&err, ArchiveError::Io(e) if e.kind() == std::io::ErrorKind::InvalidFilename, "{err}");
        assert_eq!(
            fs::read_dir(dest.dest().as_path().join("d"))
                .unwrap()
                .count(),
            0,
            "nothing is created below the link target"
        );
    }

    #[test]
    fn contained_policy_judges_the_final_landing_not_the_first_hop() {
        let (_root, dest, _) = dest_with_outside();
        let base = dest.dest().as_path().to_path_buf();
        let chain = name_of_len(MAX_PATH_LEN - base.as_os_str().len() - 64);
        walker(false).ensure_dir(&dest, &sp(&chain)).unwrap();
        fs::create_dir(base.join("short")).unwrap();
        symlink(&chain, base.join("d")).unwrap();
        symlink(base.join("short"), base.join(&chain).join("x")).unwrap();

        walker(true).ensure_parent(&dest, &sp("d/x/f")).unwrap();
    }

    #[test]
    fn contained_policy_refuses_a_dangling_symlink() {
        let (_root, dest, _) = dest_with_outside();
        symlink("missing", dest.dest().as_path().join("dangling")).unwrap();

        assert!(walker(true).ensure_dir(&dest, &sp("dangling/x")).is_err());
    }

    #[test]
    fn refuses_a_regular_file_component() {
        let (_root, dest, _) = dest_with_outside();
        fs::write(dest.dest().as_path().join("f"), b"x").unwrap();

        let err = walker(false).ensure_dir(&dest, &sp("f/x")).unwrap_err();

        assert_matches!(err, ArchiveError::Io(_), "{err}");
    }

    #[test]
    fn refuses_non_relative_paths() {
        let (_root, dest, _) = dest_with_outside();
        for bad in ["../x", "/abs", "a/../../x"] {
            let err = walker(false).ensure_dir(&dest, &sp(bad)).unwrap_err();
            assert_matches!(err, ArchiveError::PathTraversal { .. }, "{bad}: {err}");
        }
    }

    #[test]
    fn a_swap_after_a_successful_walk_is_caught_by_the_next_one() {
        let (_root, dest, outside) = dest_with_outside();
        let walker = walker(false);
        walker.ensure_dir(&dest, &sp("d")).unwrap();

        fs::remove_dir(dest.dest().as_path().join("d")).unwrap();
        symlink(&outside, dest.dest().as_path().join("d")).unwrap();

        assert!(walker.ensure_parent(&dest, &sp("d/f")).is_err());
    }

    #[test]
    fn a_swap_after_a_walk_does_not_redirect_writes_through_the_returned_handle() {
        let (_root, dest, outside) = dest_with_outside();
        let base = dest.dest().as_path().to_path_buf();
        let rel = sp("a/b/f");
        let (dir, leaf) = walker(false).ensure_parent(&dest, &rel).unwrap();

        fs::rename(base.join("a"), base.join("a_moved")).unwrap();
        symlink(&outside, base.join("a")).unwrap();
        dir.create_new(leaf, None).unwrap();

        assert!(base.join("a_moved/b/f").is_file());
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    }

    #[test]
    fn components_swapped_while_walking_never_write_outside() {
        use std::sync::atomic::AtomicBool;
        use std::sync::atomic::Ordering;

        let (_root, dest, outside) = dest_with_outside();
        let base = dest.dest().as_path().to_path_buf();
        let stop = AtomicBool::new(false);
        let walker = walker(false);

        std::thread::scope(|scope| {
            scope.spawn(|| {
                while !stop.load(Ordering::Relaxed) {
                    let moved = base.join("d_moved");
                    if fs::rename(base.join("d"), &moved).is_ok() {
                        let _ = symlink(&outside, base.join("d"));
                        let _ = fs::remove_file(base.join("d"));
                        let _ = fs::rename(&moved, base.join("d"));
                    }
                }
            });
            for i in 0..200 {
                let rel = sp(&format!("d/sub/f{i}"));
                if let Ok((dir, leaf)) = walker.ensure_parent(&dest, &rel) {
                    let _ = dir.create_new(leaf, None);
                }
            }
            stop.store(true, Ordering::Relaxed);
        });

        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    }
}
