//! Removing what a staging directory holds through its descriptor.
//!
//! The staging directory is entered once, through the descriptor the run
//! verified, and every level below it is opened relative to its parent without
//! following a symlink. No step resolves the staging directory's name, so the
//! removal reaches nothing but that directory's own tree.
//!
//! The walk is iterative and holds descriptors only for the root, the
//! [`DESCRIPTOR_WINDOW`] most recent levels and at most [`CHECKPOINTS`] older
//! ones spaced evenly (the spacing doubles as the tree deepens), so a tree of
//! any depth is removed without exhausting the open-file limit. A level that
//! holds no descriptor is re-opened by name from the nearest one that does when
//! the walk climbs back to it; those extra opens come to about depth^2/1000
//! in total, which is negligible next to the tree's own syscalls.

use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs::File;
use std::io;

use rustix::fs::AtFlags;
use rustix::fs::FileType;
use rustix::fs::Stat;
use rustix::io::Errno;

use super::dir::list_entries;
use crate::formats::file_identity::IdentityKey;
use crate::formats::pinned_dir::open_directory_at;

/// The deepest levels, which keep their descriptor open.
const DESCRIPTOR_WINDOW: usize = 16;

/// Older levels, spaced evenly, that keep their descriptor open.
const CHECKPOINTS: usize = 32;

/// The distance between two checkpoints until the tree outgrows them.
const INITIAL_SPACING: usize = DESCRIPTOR_WINDOW;

/// A directory of the tree being removed: its name in the level above, the
/// identity it was first opened with, what is still to be removed in it, and
/// its descriptor while it holds one.
struct Level {
    name: OsString,
    identity: IdentityKey,
    pending: Vec<OsString>,
    dir: Option<File>,
}

/// What a [`Visit`] decides about a directory it has just been shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Enter {
    /// List the directory and visit what it holds.
    Descend,
    /// Leave the directory, and everything in it, in place.
    Keep,
}

/// The names of the directories between the root and a visited entry, the
/// root itself excluded.
pub(super) struct Trail<'a> {
    #[cfg_attr(
        not(target_os = "macos"),
        expect(dead_code, reason = "only the macOS sweep reads the trail")
    )]
    levels: &'a [Level],
}

impl Trail<'_> {
    /// The names, outermost first.
    #[cfg(target_os = "macos")]
    pub(super) fn to_vec(&self) -> Vec<OsString> {
        self.levels.iter().map(|level| level.name.clone()).collect()
    }
}

/// What a walk does at the directories and entries it reaches. The walk
/// itself unlinks every directory it has emptied.
pub(super) trait Visit {
    /// Called with a directory opened below the root, before it is listed.
    fn enter(&mut self, dir: &File) -> Enter;

    /// Called for an entry of `dir` that is not a directory.
    fn leaf(&mut self, dir: &File, name: &OsStr, stat: &Stat, trail: Trail<'_>) -> Outcome;
}

/// Whether an entry handed to [`Visit::leaf`] is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Outcome {
    Removed,
    Kept,
}

#[cfg(target_os = "macos")]
impl Outcome {
    /// `Removed` when `removed` holds.
    pub(super) const fn of(removed: bool) -> Self {
        if removed { Self::Removed } else { Self::Kept }
    }
}

/// Unlinks every entry that is not a directory, keeping the first failure.
#[derive(Default)]
struct Plain {
    error: Option<io::Error>,
}

impl Visit for Plain {
    fn enter(&mut self, _dir: &File) -> Enter {
        Enter::Descend
    }

    fn leaf(&mut self, dir: &File, name: &OsStr, _stat: &Stat, _trail: Trail<'_>) -> Outcome {
        match rustix::fs::unlinkat(dir, name, AtFlags::empty()) {
            Ok(()) => Outcome::Removed,
            Err(e) => {
                self.error.get_or_insert_with(|| e.into());
                Outcome::Kept
            }
        }
    }
}

/// The levels from the root down to the directory being emptied.
struct Walk {
    levels: Vec<Level>,
    spacing: usize,
}

fn not_found() -> io::Error {
    io::ErrorKind::NotFound.into()
}

fn identity_of(dir: &File) -> io::Result<IdentityKey> {
    IdentityKey::of_stat(&rustix::fs::fstat(dir)?)
}

impl Walk {
    fn new(root: &File) -> io::Result<Self> {
        let root = Level {
            name: OsString::new(),
            identity: identity_of(root)?,
            pending: list_entries(root)?,
            dir: Some(root.try_clone()?),
        };
        Ok(Self {
            levels: vec![root],
            spacing: INITIAL_SPACING,
        })
    }

    fn level_mut(&mut self, index: usize) -> io::Result<&mut Level> {
        self.levels.get_mut(index).ok_or_else(not_found)
    }

    /// Descends into the directory `name` of the deepest level, whose
    /// descriptor the caller holds as `parent`, unless `visit` keeps it.
    fn descend(
        &mut self,
        parent: &File,
        name: &OsStr,
        visit: &mut impl Visit,
    ) -> io::Result<Enter> {
        let child = open_directory_at(parent, name)?;
        if visit.enter(&child) == Enter::Keep {
            return Ok(Enter::Keep);
        }
        let pending = list_entries(&child)?;
        self.levels.push(Level {
            name: name.to_os_string(),
            identity: identity_of(&child)?,
            pending,
            dir: Some(child),
        });
        self.release_below_window();
        Ok(Enter::Descend)
    }

    /// Closes the descriptors of the levels that left the window and are not
    /// checkpoints, doubling the spacing first when the checkpoints would
    /// exceed [`CHECKPOINTS`].
    fn release_below_window(&mut self) {
        let len = self.levels.len();
        let Some(outside) = len.checked_sub(DESCRIPTOR_WINDOW.saturating_add(1)) else {
            return;
        };
        let mut spacing_changed = false;
        while len
            .checked_div(self.spacing)
            .is_some_and(|held| held > CHECKPOINTS)
        {
            self.spacing = self.spacing.saturating_mul(2);
            spacing_changed = true;
        }
        let first = if spacing_changed { 1 } else { outside.max(1) };
        let spacing = self.spacing;
        for (index, level) in self
            .levels
            .iter_mut()
            .enumerate()
            .take(outside.saturating_add(1))
        {
            if index >= first && !index.is_multiple_of(spacing) {
                level.dir = None;
            }
        }
    }

    /// The descriptor of the level at `index`, re-opened level by level from
    /// the nearest one that still holds its own when it was evicted.
    fn dir_at(&mut self, index: usize) -> io::Result<&File> {
        if self.level_mut(index)?.dir.is_none() {
            self.reopen(index)?;
        }
        self.level_mut(index)?.dir.as_ref().ok_or_else(not_found)
    }

    /// The descriptor of the level at `index` together with the names of the
    /// levels from the root down to it.
    fn view(&mut self, index: usize) -> io::Result<(&File, Trail<'_>)> {
        self.dir_at(index)?;
        let dir = self
            .levels
            .get(index)
            .and_then(|level| level.dir.as_ref())
            .ok_or_else(not_found)?;
        let levels = self.levels.get(1..=index).unwrap_or_default();
        Ok((dir, Trail { levels }))
    }

    fn reopen(&mut self, index: usize) -> io::Result<()> {
        let base = (0..index)
            .rev()
            .find(|i| self.levels.get(*i).is_some_and(|level| level.dir.is_some()))
            .ok_or_else(not_found)?;
        let mut cursor = self
            .levels
            .get(base)
            .and_then(|level| level.dir.as_ref())
            .ok_or_else(not_found)?
            .try_clone()?;
        for at in base.saturating_add(1)..=index {
            let level = self.level_mut(at)?;
            let next = open_directory_at(&cursor, &level.name)?;
            if identity_of(&next)? != level.identity {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "a staged directory was replaced during removal",
                ));
            }
            if at == index {
                level.dir = Some(next);
                break;
            }
            if at.saturating_add(DESCRIPTOR_WINDOW) > index {
                level.dir = Some(next.try_clone()?);
            }
            cursor = next;
        }
        Ok(())
    }
}

/// Unlinks everything below `dir` it may. Says whether nothing was left.
///
/// A directory the removal cannot open, list or empty and an entry it cannot
/// unlink are left in place. Symlinks are unlinked, never followed.
pub(super) fn remove_children(dir: &File) -> bool {
    walk(dir, &mut Plain::default())
}

/// [`remove_children`] that reports why something was left: the first
/// failure the walk met.
pub(super) fn remove_children_checked(dir: &File) -> io::Result<()> {
    let mut plain = Plain::default();
    let walked = walk_checked(dir, &mut plain);
    plain.error.map_or(walked, Err)
}

/// Visits everything below `dir` depth first, unlinking each directory once
/// `visit` has dealt with what it held. Says whether nothing was left.
pub(super) fn walk(dir: &File, visit: &mut impl Visit) -> bool {
    walk_checked(dir, visit).is_ok()
}

/// [`walk`] reporting the first failure.
fn walk_checked(dir: &File, visit: &mut impl Visit) -> io::Result<()> {
    let mut walk = Walk::new(dir)?;
    let mut first = Ok(());
    while let Some(top) = walk.levels.len().checked_sub(1) {
        let step = match walk.levels.last_mut().and_then(|level| level.pending.pop()) {
            Some(name) => visit_entry(&mut walk, top, &name, visit),
            None => close_level(&mut walk, top),
        };
        if first.is_ok() {
            first = step;
        }
    }
    first
}

fn kept() -> io::Error {
    io::Error::other("an entry was kept")
}

/// Hands the entry `name` of the level `top` to `visit`, or descends into it
/// when it is a directory. Succeeds when the entry is gone or will be once the
/// level it opens is closed.
fn visit_entry(
    walk: &mut Walk,
    top: usize,
    name: &OsStr,
    visit: &mut impl Visit,
) -> io::Result<()> {
    let (dir, trail) = match walk.view(top) {
        Ok(view) => view,
        Err(e) => {
            if let Some(level) = walk.levels.last_mut() {
                level.pending.clear();
            }
            return Err(e);
        }
    };
    let stat = match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(Errno::NOENT) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return match visit.leaf(dir, name, &stat, trail) {
            Outcome::Removed => Ok(()),
            Outcome::Kept => Err(kept()),
        };
    }
    let parent = dir.try_clone()?;
    match walk.descend(&parent, name, visit)? {
        Enter::Descend => Ok(()),
        Enter::Keep => Err(kept()),
    }
}

/// Removes the emptied level `top` from the one above it. The root, which is
/// the last level, is left to the caller.
fn close_level(walk: &mut Walk, top: usize) -> io::Result<()> {
    let level = walk.levels.pop().ok_or_else(not_found)?;
    let Some(parent) = top.checked_sub(1) else {
        return Ok(());
    };
    drop(level.dir);
    let dir = walk.dir_at(parent)?;
    Ok(rustix::fs::unlinkat(dir, &level.name, AtFlags::REMOVEDIR)?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::os::unix::fs::symlink;

    use rustix::fs::Mode;
    use rustix::fs::OFlags;
    use tempfile::TempDir;

    use super::*;

    /// Builds `levels` nested directories named `d` below `root` one
    /// descriptor at a time, so the path may exceed `PATH_MAX`, and puts a file
    /// in each.
    fn deep_tree(root: &File, levels: usize) {
        let mut cursor = root.try_clone().unwrap();
        for _ in 0..levels {
            rustix::fs::mkdirat(&cursor, "d", Mode::from_raw_mode(0o700)).unwrap();
            cursor = open_directory_at(&cursor, OsStr::new("d")).unwrap();
            rustix::fs::openat(
                &cursor,
                "f",
                OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .unwrap();
        }
    }

    fn is_empty(dir: &File) -> bool {
        list_entries(dir).unwrap().is_empty()
    }

    #[test]
    fn a_tree_deeper_than_the_descriptor_window_is_removed_whole() {
        for levels in [1, DESCRIPTOR_WINDOW, DESCRIPTOR_WINDOW + 1, 100, 600] {
            let temp = TempDir::new().unwrap();
            let root = File::open(temp.path()).unwrap();
            deep_tree(&root, levels);

            assert!(remove_children(&root), "{levels} levels");

            assert!(is_empty(&root), "{levels} levels");
        }
    }

    const BUDGET_CHILD: &str = "EXARCH_REMOVE_BUDGET_CHILD";

    /// Runs the budget check in a child process: the lowered open-file limit
    /// is process-wide and never restored, so no other test sees it.
    #[test]
    fn a_deep_tree_is_removed_within_a_small_descriptor_budget() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "staging::remove::tests::descriptor_budget_child"])
            .env(BUDGET_CHILD, "1")
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "{stdout}");
        assert!(
            stdout.contains("1 passed"),
            "the child did not run: {stdout}"
        );
    }

    #[test]
    fn descriptor_budget_child() {
        if std::env::var_os(BUDGET_CHILD).is_none() {
            return;
        }
        let temp = TempDir::new().unwrap();
        let root = File::open(temp.path()).unwrap();
        deep_tree(&root, 600);
        let saved = rustix::process::getrlimit(rustix::process::Resource::Nofile);
        let soft = u64::try_from(DESCRIPTOR_WINDOW + CHECKPOINTS + 40).unwrap_or(u64::MAX);
        let lowered = rustix::process::Rlimit {
            current: Some(soft),
            maximum: saved.maximum,
        };
        rustix::process::setrlimit(rustix::process::Resource::Nofile, lowered).unwrap();

        assert!(remove_children(&root));

        assert!(is_empty(&root));
    }

    #[test]
    fn a_level_replaced_before_it_is_reopened_is_refused() {
        let temp = TempDir::new().unwrap();
        let root = File::open(temp.path()).unwrap();
        deep_tree(&root, 3);
        let mut walk = Walk::new(&root).unwrap();
        for _ in 0..3 {
            let parent = walk
                .levels
                .last()
                .and_then(|l| l.dir.as_ref())
                .unwrap()
                .try_clone()
                .unwrap();
            walk.descend(&parent, OsStr::new("d"), &mut Plain::default())
                .unwrap();
        }
        for level in walk.levels.iter_mut().skip(1) {
            level.dir = None;
        }
        assert!(walk.dir_at(3).is_ok());
        for level in walk.levels.iter_mut().skip(1) {
            level.dir = None;
        }
        std::fs::rename(temp.path().join("d"), temp.path().join("moved")).unwrap();
        std::fs::create_dir_all(temp.path().join("d/d/d")).unwrap();

        let reopened = walk.dir_at(3);

        assert_eq!(reopened.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_wide_and_deep_tree_is_removed_whole() {
        let temp = TempDir::new().unwrap();
        let root = File::open(temp.path()).unwrap();
        for branch in ["a", "b", "c"] {
            std::fs::create_dir(temp.path().join(branch)).unwrap();
            std::fs::write(temp.path().join(branch).join("file"), b"x").unwrap();
            let sub = File::open(temp.path().join(branch)).unwrap();
            deep_tree(&sub, DESCRIPTOR_WINDOW * 3);
        }
        std::fs::write(temp.path().join("top"), b"x").unwrap();

        assert!(remove_children(&root));

        assert!(is_empty(&root));
    }

    #[test]
    fn symlinks_are_unlinked_and_never_followed() {
        let outside = TempDir::new().unwrap();
        std::fs::write(outside.path().join("keep"), b"x").unwrap();
        let temp = TempDir::new().unwrap();
        let root = File::open(temp.path()).unwrap();
        deep_tree(&root, DESCRIPTOR_WINDOW + 5);
        symlink(outside.path(), temp.path().join("to_dir")).unwrap();
        symlink(outside.path().join("keep"), temp.path().join("to_file")).unwrap();
        symlink("missing", temp.path().join("dangling")).unwrap();

        assert!(remove_children(&root));

        assert!(is_empty(&root));
        assert!(outside.path().join("keep").exists());
    }

    #[test]
    fn an_unlistable_directory_is_reported_and_kept() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let root = File::open(temp.path()).unwrap();
        let locked = temp.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::write(temp.path().join("gone"), b"x").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let listable = std::fs::read_dir(&locked).is_ok();

        let removed = remove_children(&root);

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        if !listable {
            assert!(!removed);
            assert!(locked.exists());
        }
        assert!(!temp.path().join("gone").exists());
    }
}
