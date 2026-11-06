//! Handle-relative resolution of symlink targets.
//!
//! A [`LinkCursor`] resolves a link target the way the kernel would, one
//! component at a time, while holding the directory handle of the position it
//! has reached. Every file-system operation is relative to a handle already
//! held (`readlinkat`, `fstatat` with no-follow, `openat` with `O_NOFOLLOW`),
//! so the result does not depend on later changes to path names, and no
//! absolute path is ever formed: the verdict does not depend on how long the
//! destination's own absolute path is.
//!
//! The cursor serves two callers:
//!
//! - the directory walker follows a pre-existing symlink among the parents of
//!   an entry ([`LinkCursor::at_site`]); the link must resolve to a directory,
//!   and the cursor's final handle is the directory the walk continues in;
//! - link validation resolves the target of a link about to be created
//!   ([`LinkCursor::for_target`]); the target may name things that do not exist
//!   yet, which the cursor tracks lexically from the first missing component
//!   on.
//!
//! Anything the resolution cannot prove stays inside the destination is
//! refused:
//!
//! - a `..` above the root is an escape;
//! - an absolute target is mapped only through the destination's canonical root
//!   or the root as the caller wrote it (`/var/x` for `/private/var/x`); any
//!   other spelling of the same place (a bind mount, another alias) is an
//!   escape;
//! - more than [`MAX_SYMLINK_HOPS`] links, or a link that dangles or runs
//!   through a file, is unresolvable.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::io;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use crate::ArchiveError;
use crate::formats::pinned_dir::Leaf;
use crate::formats::pinned_dir::PinnedRoot;
use crate::formats::pinned_dir::VettedDir;
use crate::security::fs_view::LinkBase;
use crate::security::fs_view::MAX_SYMLINK_HOPS;
use crate::security::fs_view::Occupant;
use crate::security::fs_view::ParentBlocker;

/// The most ancestor handles a cursor keeps open at once, so a deep path
/// costs a bounded number of descriptors.
const MAX_HELD_DIRS: usize = 32;

/// Why a cursor refused to resolve a target.
#[derive(Debug)]
pub(crate) enum Refusal {
    /// The path leaves the destination, or maps through a spelling of it the
    /// cursor does not trust.
    Escape,
    /// A link dangles, loops, runs through a file, or could not be inspected.
    Unresolvable,
    /// A name past the host's limits.
    NameTooLong(io::Error),
    /// The host ran out of descriptors or memory; says nothing about the path.
    Resource(io::Error),
}

impl Refusal {
    /// The blocker the directory walker reports for this refusal.
    pub(crate) const fn blocker(&self) -> ParentBlocker {
        match self {
            Self::Escape => ParentBlocker::Escape,
            Self::Unresolvable | Self::NameTooLong(_) | Self::Resource(_) => ParentBlocker::Symlink,
        }
    }

    /// The I/O error this refusal stands for when it is not a verdict on the
    /// path, or the refusal itself when it is.
    ///
    /// # Errors
    ///
    /// Returns `self` for a verdict on the path.
    pub(crate) fn into_failure(self) -> std::result::Result<ArchiveError, Self> {
        match self {
            Self::NameTooLong(error) | Self::Resource(error) => Ok(ArchiveError::Io(error)),
            other => Err(other),
        }
    }

    /// The error link validation reports for `link`.
    pub(crate) fn into_error(self, link: &Path) -> ArchiveError {
        self.into_failure()
            .unwrap_or_else(|_| ArchiveError::SymlinkEscape {
                path: link.to_path_buf(),
            })
    }

    fn of_probe(error: &io::Error) -> Self {
        let exhausted = rustix::io::Errno::from_io_error(error).is_some_and(|errno| {
            [
                rustix::io::Errno::MFILE,
                rustix::io::Errno::NFILE,
                rustix::io::Errno::NOMEM,
            ]
            .contains(&errno)
        });
        if exhausted || error.kind() == io::ErrorKind::OutOfMemory {
            Self::Resource(io::Error::new(error.kind(), error.to_string()))
        } else if error.kind() == io::ErrorKind::InvalidFilename {
            Self::NameTooLong(io::Error::from(io::ErrorKind::InvalidFilename))
        } else {
            Self::Unresolvable
        }
    }
}

type Resolution<T> = std::result::Result<T, Refusal>;

/// One component still to resolve below the current directory.
enum Step {
    Parent,
    Name(OsString),
    /// The expansion of a followed link is complete.
    LinkEnd,
}

/// What a cursor accepts for components that do not exist.
enum Existence {
    /// Every component must exist and the result must be a directory.
    Required,
    /// Missing components are tracked lexically; `start` is the link's
    /// directory, relative to the root, which a `..` may always leave.
    LexicalTail { start: PathBuf },
}

/// A handle-holding resolver for symlink targets.
///
/// The handles of the nearest directories entered are kept in a window of at
/// most [`MAX_HELD_DIRS`], so a `..` costs one pop and the number of open
/// descriptors does not grow with the depth of the path. A `..` that leaves
/// the window only moves the position; the ancestors are re-opened from the
/// root, keeping the last window, only when a later component needs a handle,
/// so a run of `..` that ends at the root opens nothing.
pub(crate) struct LinkCursor<'r> {
    root: &'r PinnedRoot,
    /// The handle of `position`, or `None` until it is re-opened.
    dir: Option<VettedDir>,
    /// Handles of the ancestors of `position`, nearest last.
    parents: VecDeque<VettedDir>,
    held_cap: usize,
    peak_held: usize,
    /// The symlink-free, existing part of the position, relative to the root.
    position: PathBuf,
    /// Names below the deepest existing directory, never looked up.
    tail: Vec<OsString>,
    hops: usize,
    active_links: usize,
    pending: VecDeque<Step>,
    existence: Existence,
}

impl<'r> LinkCursor<'r> {
    /// Starts at the symlink `leaf` inside `parent`, which sits at `here`
    /// below the root, and resolves it to the directory it names.
    ///
    /// # Errors
    ///
    /// Returns a [`Refusal`] when the link dangles, loops, does not name a
    /// directory or leaves the destination.
    pub(crate) fn at_site(
        root: &'r PinnedRoot,
        parent: &VettedDir,
        here: &Path,
        leaf: Leaf<'_>,
    ) -> Resolution<(PathBuf, VettedDir)> {
        Self::at_site_capped(root, parent, here, leaf, MAX_HELD_DIRS)
            .map(|(position, dir, _)| (position, dir))
    }

    /// [`Self::at_site`] holding at most `held_cap` ancestor handles; also
    /// returns the most handles held at once.
    fn at_site_capped(
        root: &'r PinnedRoot,
        parent: &VettedDir,
        here: &Path,
        leaf: Leaf<'_>,
        held_cap: usize,
    ) -> Resolution<(PathBuf, VettedDir, usize)> {
        let mut cursor = Self::new(
            root,
            parent.reopen().map_err(|e| Refusal::of_probe(&e))?,
            here.to_path_buf(),
            Existence::Required,
            held_cap,
        );
        cursor.follow_link(leaf)?;
        cursor.run()?;
        cursor.dir()?;
        let dir = cursor.dir.ok_or(Refusal::Unresolvable)?;
        Ok((cursor.position, dir, cursor.peak_held))
    }

    fn new(
        root: &'r PinnedRoot,
        dir: VettedDir,
        position: PathBuf,
        existence: Existence,
        held_cap: usize,
    ) -> Self {
        Self {
            root,
            dir: Some(dir),
            parents: VecDeque::new(),
            held_cap,
            peak_held: 1,
            position,
            tail: Vec::new(),
            hops: 0,
            active_links: 0,
            pending: VecDeque::new(),
            existence,
        }
    }

    /// Resolves `target`, the target of a link at `link`, where `base` says
    /// what the target is relative to. The parents of `link` are vetted on the
    /// way for [`LinkBase::LinkDirectory`]: an existing symlink there is
    /// refused, not followed, and the first missing one starts the lexical
    /// tail. Returns the resolved position relative to the root.
    ///
    /// # Errors
    ///
    /// Returns a [`Refusal`] when the target leaves the destination, runs
    /// through a link that dangles or loops, or names something the host
    /// cannot look up.
    pub(crate) fn for_target(
        root: &'r PinnedRoot,
        link: &Path,
        base: LinkBase,
        target: &Path,
    ) -> Resolution<PathBuf> {
        Self::for_target_capped(root, link, base, target, MAX_HELD_DIRS)
            .map(|(resolved, _)| resolved)
    }

    /// [`Self::for_target`] holding at most `held_cap` ancestor handles; also
    /// returns the most handles held at once.
    fn for_target_capped(
        root: &'r PinnedRoot,
        link: &Path,
        base: LinkBase,
        target: &Path,
        held_cap: usize,
    ) -> Resolution<(PathBuf, usize)> {
        let start = match base {
            LinkBase::LinkDirectory => link.parent().unwrap_or_else(|| Path::new("")),
            LinkBase::Destination => Path::new(""),
        };
        let mut cursor = Self::new(
            root,
            root.dir().reopen().map_err(|e| Refusal::of_probe(&e))?,
            PathBuf::new(),
            Existence::LexicalTail {
                start: start.to_path_buf(),
            },
            held_cap,
        );
        cursor.enter_start(start)?;
        cursor.queue(target)?;
        cursor.run()?;
        Ok((cursor.lexical_position(), cursor.peak_held))
    }

    fn lexical_position(&self) -> PathBuf {
        self.tail
            .iter()
            .fold(self.position.clone(), |path, name| path.join(name))
    }

    /// Walks the directory the link sits in, refusing a symlink on the way.
    fn enter_start(&mut self, start: &Path) -> Resolution<()> {
        for component in start.components() {
            let Component::Normal(name) = component else {
                continue;
            };
            if !self.tail.is_empty() {
                self.tail.push(name.to_os_string());
                continue;
            }
            let leaf = Self::leaf(name)?;
            if let Ok(next) = self.dir()?.open_dir(leaf) {
                self.push_dir(name, next);
                continue;
            }
            match self.probe(leaf)? {
                Some(Occupant::Directory) => self.descend(name, leaf)?,
                Some(Occupant::Symlink) => return Err(Refusal::Escape),
                Some(Occupant::File) | None => self.tail.push(name.to_os_string()),
            }
        }
        Ok(())
    }

    /// The handle of the current position, re-opened from the root when a
    /// `..` has moved past the handles in the window. Only the nearest
    /// ancestors are kept; the others are closed as the walk passes them.
    fn dir(&mut self) -> Resolution<&VettedDir> {
        if self.dir.is_none() {
            let mut dir = self
                .root
                .dir()
                .reopen()
                .map_err(|e| Refusal::of_probe(&e))?;
            self.parents.clear();
            let position = self.position.clone();
            for component in position.components() {
                let leaf = Leaf::from_component(component).ok_or(Refusal::Unresolvable)?;
                let next = dir.open_dir(leaf).map_err(|e| Refusal::of_probe(&e))?;
                let ancestor = std::mem::replace(&mut dir, next);
                self.keep_ancestor(ancestor);
            }
            self.dir = Some(dir);
            self.note_held();
        }
        self.dir.as_ref().ok_or(Refusal::Unresolvable)
    }

    fn probe(&mut self, leaf: Leaf<'_>) -> Resolution<Option<Occupant>> {
        self.dir()?.probe(leaf).map_err(|e| Refusal::of_probe(&e))
    }

    fn leaf(name: &std::ffi::OsStr) -> Resolution<Leaf<'_>> {
        Leaf::from_component(Component::Normal(name)).ok_or(Refusal::Unresolvable)
    }

    fn descend(&mut self, name: &std::ffi::OsStr, leaf: Leaf<'_>) -> Resolution<()> {
        let next = self
            .dir()?
            .open_dir(leaf)
            .map_err(|e| Refusal::of_probe(&e))?;
        self.push_dir(name, next);
        Ok(())
    }

    fn push_dir(&mut self, name: &std::ffi::OsStr, next: VettedDir) {
        if let Some(current) = self.dir.replace(next) {
            self.keep_ancestor(current);
        }
        self.position.push(name);
        self.note_held();
    }

    /// Adds `ancestor` to the window, closing the farthest one when it is full.
    fn keep_ancestor(&mut self, ancestor: VettedDir) {
        if self.parents.len() >= self.held_cap {
            self.parents.pop_front();
        }
        self.parents.push_back(ancestor);
    }

    fn note_held(&mut self) {
        self.peak_held = self.peak_held.max(self.parents.len() + 1);
    }

    fn run(&mut self) -> Resolution<()> {
        while let Some(step) = self.pending.pop_front() {
            match step {
                Step::Parent => self.ascend()?,
                Step::Name(name) => self.enter(&name)?,
                Step::LinkEnd => {
                    self.active_links -= 1;
                    if self.active_links == 0 {
                        self.hops = 0;
                    }
                }
            }
        }
        Ok(())
    }

    /// Queues the components of `path` in front of the pending ones.
    fn queue(&mut self, path: &Path) -> Resolution<()> {
        let mut steps = Vec::new();
        for component in path.components() {
            match component {
                Component::Normal(part) => steps.push(Step::Name(part.to_os_string())),
                Component::ParentDir => steps.push(Step::Parent),
                Component::CurDir => {}
                Component::RootDir | Component::Prefix(_) => return Err(Refusal::Escape),
            }
        }
        for step in steps.into_iter().rev() {
            self.pending.push_front(step);
        }
        Ok(())
    }

    /// Reads the symlink `name` in the current directory and queues its target.
    fn follow_link(&mut self, name: Leaf<'_>) -> Resolution<()> {
        self.hops += 1;
        if self.hops > MAX_SYMLINK_HOPS {
            return Err(Refusal::Unresolvable);
        }
        let target = self
            .dir()?
            .read_link(name)
            .map_err(|e| Refusal::of_probe(&e))?;
        let relative = if target.is_absolute() {
            let dest = self.root.dest();
            let stripped = target.strip_prefix(dest.as_path());
            #[cfg(unix)]
            let stripped = stripped.or_else(|_| target.strip_prefix(dest.written()));
            let inside = stripped.map_err(|_| Refusal::Escape)?.to_path_buf();
            self.position.clear();
            self.parents.clear();
            self.dir = None;
            inside
        } else {
            target
        };
        self.pending.push_front(Step::LinkEnd);
        self.active_links += 1;
        let mut steps = std::mem::take(&mut self.pending);
        self.queue(&relative)?;
        self.pending.append(&mut steps);
        Ok(())
    }

    /// Moves into `name`, following it when it is itself a symlink.
    fn enter(&mut self, name: &OsString) -> Resolution<()> {
        if !self.tail.is_empty() {
            self.tail.push(name.clone());
            return Ok(());
        }
        let leaf = Self::leaf(name)?;
        if matches!(self.pending.front(), Some(Step::Parent)) {
            // `name/..` returns to where it started once `name` is known to be
            // a real directory, so it is neither opened nor left.
            let occupant = self.probe(leaf)?;
            if occupant == Some(Occupant::Directory) {
                self.pending.pop_front();
                return Ok(());
            }
            return self.settle(name, leaf, occupant);
        }
        // Opening first settles the common case, a real directory, in one
        // call; only a failed open is classified with a probe.
        if let Ok(next) = self.dir()?.open_dir(leaf) {
            self.push_dir(name, next);
            return Ok(());
        }
        let occupant = self.probe(leaf)?;
        self.settle(name, leaf, occupant)
    }

    /// Continues past `name`, which is `occupant` in the current directory.
    fn settle(
        &mut self,
        name: &OsString,
        leaf: Leaf<'_>,
        occupant: Option<Occupant>,
    ) -> Resolution<()> {
        match occupant {
            Some(Occupant::Directory) => self.descend(name, leaf),
            Some(Occupant::Symlink) => self.follow_link(leaf),
            Some(Occupant::File) if self.may_end_on_file() => {
                self.tail.push(name.clone());
                Ok(())
            }
            None if self.may_be_missing() => {
                self.tail.push(name.clone());
                Ok(())
            }
            Some(Occupant::File) | None => Err(Refusal::Unresolvable),
        }
    }

    /// Whether the cursor accepts a missing component here: only a link target
    /// being validated, and not inside a link that has to exist.
    const fn may_be_missing(&self) -> bool {
        matches!(self.existence, Existence::LexicalTail { .. }) && self.active_links == 0
    }

    /// Whether a file at this component is acceptable: it must not be crossed
    /// by a followed link, which has to name an existing path.
    fn may_end_on_file(&self) -> bool {
        matches!(self.existence, Existence::LexicalTail { .. })
            && (self.active_links == 0 || matches!(self.pending.front(), Some(Step::LinkEnd)))
    }

    /// Moves to the parent directory; above the root is an escape.
    fn ascend(&mut self) -> Resolution<()> {
        if !self.tail.is_empty() {
            let Existence::LexicalTail { start } = &self.existence else {
                return Err(Refusal::Unresolvable);
            };
            if !start.starts_with(self.lexical_position()) {
                return Err(Refusal::Escape);
            }
            self.tail.pop();
            return Ok(());
        }
        if !self.position.pop() {
            return Err(Refusal::Escape);
        }
        self.dir = self.parents.pop_back();
        Ok(())
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::assert_matches;
    use std::ffi::OsStr;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    struct Tree {
        _temp: TempDir,
        root: PinnedRoot,
        path: PathBuf,
    }

    fn fixture(dirs: &[&str], files: &[&str], links: &[(&str, &str)]) -> Tree {
        let temp = TempDir::new().unwrap();
        let path = temp.path().canonicalize().unwrap();
        for dir in dirs {
            std::fs::create_dir_all(path.join(dir)).unwrap();
        }
        for file in files {
            std::fs::write(path.join(file), b"x").unwrap();
        }
        for (name, target) in links {
            symlink(target, path.join(name)).unwrap();
        }
        let root = PinnedRoot::open_for_test(&path).unwrap();
        Tree {
            _temp: temp,
            root,
            path,
        }
    }

    fn resolve(tree: &Tree, link: &str, target: &str) -> Resolution<PathBuf> {
        LinkCursor::for_target(
            &tree.root,
            Path::new(link),
            LinkBase::LinkDirectory,
            Path::new(target),
        )
    }

    fn open(tree: &Tree, rel: &str) -> VettedDir {
        let mut dir = tree.root.dir().reopen().unwrap();
        for part in Path::new(rel).components() {
            let leaf = Leaf::from_component(part).unwrap();
            dir = dir.open_dir(leaf).unwrap();
        }
        dir
    }

    fn leaf(name: &str) -> Leaf<'_> {
        Leaf::from_component(Component::Normal(OsStr::new(name))).unwrap()
    }

    #[test]
    fn a_failed_probe_is_classified_by_what_it_says_about_the_host() {
        let kind = |kind: io::ErrorKind| Refusal::of_probe(&io::Error::from(kind));
        assert_matches!(
            kind(io::ErrorKind::InvalidFilename),
            Refusal::NameTooLong(_)
        );
        assert_matches!(kind(io::ErrorKind::PermissionDenied), Refusal::Unresolvable);
        assert_matches!(kind(io::ErrorKind::Other), Refusal::Unresolvable);
        for errno in [libc::EMFILE, libc::ENFILE, libc::ENOMEM] {
            let refusal = Refusal::of_probe(&io::Error::from_raw_os_error(errno));
            assert_matches!(refusal, Refusal::Resource(_), "{errno}");
            assert_matches!(
                refusal.into_error(Path::new("l")),
                ArchiveError::Io(_),
                "{errno}"
            );
        }
        assert_matches!(
            Refusal::Unresolvable.into_error(Path::new("l")),
            ArchiveError::SymlinkEscape { .. }
        );
    }

    #[test]
    fn a_target_may_leave_the_parents_of_its_own_link() {
        let existing = fixture(&["a/b"], &[], &[]);
        assert_eq!(
            resolve(&existing, "a/b/l", "../../x").unwrap(),
            Path::new("x")
        );
        assert_matches!(
            resolve(&existing, "a/b/l", "../../../x"),
            Err(Refusal::Escape)
        );

        let missing = fixture(&[], &[], &[]);
        assert_eq!(
            resolve(&missing, "m/n/l", "../../x").unwrap(),
            Path::new("x")
        );
        assert_matches!(
            resolve(&missing, "m/n/l", "../../../x"),
            Err(Refusal::Escape)
        );
    }

    #[test]
    fn a_symlink_among_the_parents_of_the_link_is_refused_not_followed() {
        let tree = fixture(&["d"], &[], &[("s", "d")]);
        assert_matches!(resolve(&tree, "s/l", "x"), Err(Refusal::Escape));
    }

    #[test]
    fn the_lexical_tail_follows_the_names_it_never_looked_up() {
        let tree = fixture(&[], &["f"], &[("dangling", "missing")]);
        assert_eq!(resolve(&tree, "l", "f/x").unwrap(), Path::new("f/x"));
        assert_eq!(resolve(&tree, "l", "new/x").unwrap(), Path::new("new/x"));
        assert_matches!(resolve(&tree, "l", "new/../x"), Err(Refusal::Escape));
        assert_matches!(resolve(&tree, "l", "f/.."), Err(Refusal::Escape));
        assert_matches!(
            resolve(&tree, "l", "dangling/x"),
            Err(Refusal::Unresolvable)
        );
    }

    #[test]
    fn a_name_past_the_host_limit_is_a_length_refusal() {
        let tree = fixture(&[], &[], &[]);
        let long = "a".repeat(300);
        assert_matches!(
            resolve(&tree, "l", &format!("{long}/x")),
            Err(Refusal::NameTooLong(_))
        );
    }

    #[test]
    fn a_dotdot_past_a_followed_link_reopens_the_ancestors() {
        let tree = fixture(&["p/q/r", "p/s"], &[], &[("p/q/r/l", "../../s")]);
        let parent = open(&tree, "p/q/r");

        let (position, dir) =
            LinkCursor::at_site(&tree.root, &parent, Path::new("p/q/r"), leaf("l")).unwrap();

        assert_eq!(position, Path::new("p/s"));
        assert_eq!(dir.probe(leaf("missing")).unwrap(), None);
    }

    #[test]
    fn the_walker_form_needs_every_component_to_exist_and_end_on_a_directory() {
        let tree = fixture(
            &["d"],
            &["f"],
            &[("to_dir", "d"), ("to_file", "f"), ("to_missing", "nope/x")],
        );
        let at = |name: &str| {
            LinkCursor::at_site(&tree.root, tree.root.dir(), Path::new(""), leaf(name))
                .map(|(position, _)| position)
        };
        assert_eq!(at("to_dir").unwrap(), Path::new("d"));
        assert_matches!(at("to_file"), Err(Refusal::Unresolvable));
        assert_matches!(at("to_missing"), Err(Refusal::Unresolvable));
    }

    #[test]
    fn held_handles_stay_within_the_cap_however_deep_the_path() {
        const DEPTH: usize = 100;
        let deep = vec!["d"; DEPTH].join("/");
        let tree = fixture(&[&deep], &[], &[]);
        let link = format!("{deep}/l");
        let up = format!("{}x", "../".repeat(DEPTH));

        let (capped, peak) = LinkCursor::for_target_capped(
            &tree.root,
            Path::new(&link),
            LinkBase::LinkDirectory,
            Path::new(&up),
            4,
        )
        .unwrap();
        let (uncapped, wide) = LinkCursor::for_target_capped(
            &tree.root,
            Path::new(&link),
            LinkBase::LinkDirectory,
            Path::new(&up),
            usize::MAX,
        )
        .unwrap();

        assert_eq!(capped, Path::new("x"));
        assert_eq!(capped, uncapped);
        assert!(peak <= 5, "{peak}");
        assert!(wide > DEPTH / 2, "{wide}");
    }

    #[test]
    fn the_default_window_bounds_a_path_deeper_than_the_descriptor_limit() {
        const DEPTH: usize = 300;
        let deep = vec!["d"; DEPTH].join("/");
        let tree = fixture(&[&deep], &[], &[]);

        let (resolved, peak) = LinkCursor::for_target_capped(
            &tree.root,
            Path::new(&format!("{deep}/l")),
            LinkBase::LinkDirectory,
            Path::new("x"),
            MAX_HELD_DIRS,
        )
        .unwrap();

        assert_eq!(resolved, Path::new(&format!("{deep}/x")));
        assert!(peak <= MAX_HELD_DIRS + 1, "{peak}");
    }

    #[test]
    fn reopening_from_the_root_keeps_only_the_window() {
        const DEPTH: usize = 100;
        let deep = vec!["d"; DEPTH].join("/");
        let up = "../".repeat(DEPTH - 40);
        let tree = fixture(&[&deep], &[], &[]);
        symlink(&up, tree.path.join(&deep).join("l")).unwrap();
        let parent = open(&tree, &deep);

        let (position, _, peak) =
            LinkCursor::at_site_capped(&tree.root, &parent, Path::new(&deep), leaf("l"), 4)
                .unwrap();

        assert_eq!(position, Path::new(&vec!["d"; 40].join("/")));
        assert!(peak <= 5, "{peak}");
    }

    #[test]
    fn the_hop_budget_is_per_link_not_per_resolution() {
        let chain = MAX_SYMLINK_HOPS / 2 + 2;
        let mut links: Vec<(String, String)> = Vec::new();
        for index in 0..chain {
            let next = |prefix: &str, last: &str| {
                if index + 1 < chain {
                    format!("{prefix}{}", index + 1)
                } else {
                    last.to_owned()
                }
            };
            links.push((format!("a{index}"), next("a", "D1")));
            links.push((format!("D1/b{index}"), next("b", "../D2")));
        }
        let refs: Vec<(&str, &str)> = links
            .iter()
            .map(|(n, t)| (n.as_str(), t.as_str()))
            .collect();
        let tree = fixture(&["D1", "D2"], &[], &refs);

        assert_eq!(resolve(&tree, "l", "a0/b0/x").unwrap(), Path::new("D2/x"));

        let long: Vec<(String, String)> = (0..=MAX_SYMLINK_HOPS)
            .map(|index| {
                let target = if index == MAX_SYMLINK_HOPS {
                    "D1".to_owned()
                } else {
                    format!("c{}", index + 1)
                };
                (format!("c{index}"), target)
            })
            .collect();
        let refs: Vec<(&str, &str)> = long.iter().map(|(n, t)| (n.as_str(), t.as_str())).collect();
        let tree = fixture(&["D1"], &[], &refs);
        assert_matches!(resolve(&tree, "l", "c0/x"), Err(Refusal::Unresolvable));
    }
}
