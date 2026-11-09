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
    /// descriptor the caller holds as `parent`.
    fn descend(&mut self, parent: &File, name: &OsStr) -> io::Result<()> {
        let child = open_directory_at(parent, name)?;
        let pending = list_entries(&child)?;
        self.levels.push(Level {
            name: name.to_os_string(),
            identity: identity_of(&child)?,
            pending,
            dir: Some(child),
        });
        self.release_below_window();
        Ok(())
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
    let Ok(mut walk) = Walk::new(dir) else {
        return false;
    };
    let mut removed = true;
    while let Some(top) = walk.levels.len().checked_sub(1) {
        match walk.levels.last_mut().and_then(|level| level.pending.pop()) {
            Some(name) => removed &= remove_entry(&mut walk, top, &name),
            None => removed &= close_level(&mut walk, top),
        }
    }
    removed
}

/// Removes the entry `name` of the level `top`, or descends into it when it
/// is a directory. Says whether the entry is gone or will be once the level it
/// opens is closed.
fn remove_entry(walk: &mut Walk, top: usize, name: &OsStr) -> bool {
    let Ok(dir) = walk.dir_at(top) else {
        if let Some(level) = walk.levels.last_mut() {
            level.pending.clear();
        }
        return false;
    };
    let stat = match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(Errno::NOENT) => return true,
        Err(_) => return false,
    };
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return rustix::fs::unlinkat(dir, name, AtFlags::empty()).is_ok();
    }
    let Ok(parent) = dir.try_clone() else {
        return false;
    };
    walk.descend(&parent, name).is_ok()
}

/// Removes the emptied level `top` from the one above it. The root, which is
/// the last level, is left to the caller.
fn close_level(walk: &mut Walk, top: usize) -> bool {
    let Some(level) = walk.levels.pop() else {
        return false;
    };
    let Some(parent) = top.checked_sub(1) else {
        return true;
    };
    drop(level.dir);
    walk.dir_at(parent)
        .is_ok_and(|dir| rustix::fs::unlinkat(dir, &level.name, AtFlags::REMOVEDIR).is_ok())
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
            walk.descend(&parent, OsStr::new("d")).unwrap();
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
