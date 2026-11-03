//! Parent-directory creation that never walks through a link it did not vet.
//!
//! The walk starts at the destination's pinned directory handle and descends
//! one component at a time with `openat(NOFOLLOW)`, creating missing
//! components with `mkdirat`. Every step operates on the handle the previous
//! step returned, so a symlink swapped in for an already vetted component
//! cannot redirect what follows, and nothing is remembered between entries.
//! The returned [`VettedDir`] is the handle the caller writes through.
//!
//! The walk holds at most two descriptors: the current directory and the one
//! being opened.
//!
//! # Failure handling
//!
//! A failed open is classified by `fstatat(NOFOLLOW)`, not by `errno`, because
//! platforms disagree on what a directory open of a symlink reports. A missing
//! component is created and opened once more; a second failure, or any
//! failure whose probe finds nothing to blame, returns the original I/O error
//! so an attacker who removes and re-creates entries cannot make the walk
//! retry forever.

use std::path::Path;
use std::path::PathBuf;

use crate::ArchiveError;
use crate::PolicySetting;
use crate::Result;
use crate::SecurityConfig;
use crate::config::Validated;
use crate::formats::pinned_dir::Leaf;
use crate::formats::pinned_dir::PinnedRoot;
use crate::formats::pinned_dir::VettedDir;
use crate::security::fs_view::HostFs;
use crate::security::fs_view::LinkClass;
use crate::security::fs_view::Occupant;
use crate::security::fs_view::ParentBlocker;
use crate::security::fs_view::classify_link;
use crate::types::SafePath;

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
    fn of(config: &SecurityConfig<Validated>) -> Self {
        if config.allowed.symlinks {
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

/// Creates and vets the directories that archive entries are written into.
#[derive(Debug, Clone, Copy)]
pub struct DirWalker {
    links: LinkPolicy,
}

impl DirWalker {
    /// Builds a walker that applies the symlink policy of `config`.
    pub fn new(config: &SecurityConfig<Validated>) -> Self {
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
    pub(crate) fn ensure_dir<'r>(self, root: &'r PinnedRoot, rel: &SafePath) -> Result<DirRef<'r>> {
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
    pub(crate) fn ensure_parent<'r, 'p>(
        self,
        root: &'r PinnedRoot,
        rel: &'p SafePath,
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
        rel: &'p SafePath,
    ) -> Result<(DirRef<'r>, Leaf<'p>)> {
        let rel = rel.as_path();
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
        let mut walked = PathBuf::new();
        let mut current: Option<DirRef<'r>> = None;
        for component in dir.components() {
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
            let next = self.step(root, parent, leaf, &walked, entry, missing, links)?;
            current = Some(next);
        }
        Ok(current.unwrap_or_else(|| DirRef::Root(root.dir())))
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the walk state is threaded through unchanged; a parameter struct adds indirection"
    )]
    fn step<'r>(
        self,
        root: &'r PinnedRoot,
        parent: &VettedDir,
        leaf: Leaf<'_>,
        walked: &Path,
        entry: &Path,
        missing: Missing,
        links: Links,
    ) -> Result<DirRef<'r>> {
        let mut err = match parent.open_dir(leaf) {
            Ok(dir) => return Ok(DirRef::Opened(dir)),
            Err(e) => e,
        };
        if err.kind() == std::io::ErrorKind::NotFound && missing == Missing::Create {
            match parent.make_dir(leaf) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
            err = match parent.open_dir(leaf) {
                Ok(dir) => return Ok(DirRef::Opened(dir)),
                Err(e) => e,
            };
        }
        match parent.probe(leaf) {
            Ok(Some(Occupant::Symlink)) => self.follow(root, walked, entry, links),
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
        walked: &Path,
        entry: &Path,
        links: Links,
    ) -> Result<DirRef<'r>> {
        if links == Links::Strict {
            return Err(ParentBlocker::Symlink.error(entry, walked));
        }
        let dest = root.dest();
        match (
            classify_link(&HostFs, &dest.as_path().join(walked), dest),
            self.links,
        ) {
            (LinkClass::Blocked(blocker), _) => Err(blocker.error(entry, walked)),
            (LinkClass::InsideDir(_), LinkPolicy::Refuse) => {
                Err(ArchiveError::relaxable_violation(
                    PolicySetting::Symlinks,
                    format!("path component is a symlink: {}", walked.display()),
                ))
            }
            (LinkClass::InsideDir(resolved), LinkPolicy::ContainedOnly) => {
                let inside = resolved.strip_prefix(dest.as_path()).unwrap_or(&resolved);
                self.descend(root, inside, entry, Missing::Fail, Links::Strict)
            }
        }
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::types::DestDir;
    use std::assert_matches;
    use std::fs;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    fn walker(allow_symlinks: bool) -> DirWalker {
        let config = SecurityConfig::default()
            .with_allow_symlinks(allow_symlinks)
            .validate()
            .unwrap();
        DirWalker::new(&config)
    }

    fn sp(path: &str) -> SafePath {
        SafePath::new_unchecked(PathBuf::from(path))
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
            .open_parent(&dest, &sp("missing/f"))
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
