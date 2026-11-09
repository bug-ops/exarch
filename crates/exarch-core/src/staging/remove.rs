//! Removing what a staging directory holds through its descriptor.
//!
//! The staging directory is entered once, through the descriptor the run
//! verified, and every level below it is opened relative to its parent without
//! following a symlink. No step resolves the staging directory's name, so the
//! removal reaches nothing but that directory's own tree.

use std::ffi::OsStr;
use std::fs::File;

use rustix::fs::AtFlags;
use rustix::fs::FileType;
use rustix::io::Errno;

use super::dir::list_entries;
use crate::formats::pinned_dir::open_directory_at;

/// Directory levels the removal descends, each holding one descriptor.
pub(super) const MAX_DEPTH: usize = 64;

/// Unlinks everything below `dir` it may. Says whether nothing was left.
///
/// A directory the removal cannot open, list or empty, an entry it cannot
/// unlink and a tree deeper than [`MAX_DEPTH`] are left in place.
pub(super) fn remove_children(dir: &File) -> bool {
    remove_below(dir, 0)
}

fn remove_below(dir: &File, depth: usize) -> bool {
    let Ok(names) = list_entries(dir) else {
        return false;
    };
    let mut removed = true;
    for name in &names {
        removed &= remove_entry(dir, name, depth);
    }
    removed
}

fn remove_entry(dir: &File, name: &OsStr, depth: usize) -> bool {
    let stat = match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(Errno::NOENT) => return true,
        Err(_) => return false,
    };
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return rustix::fs::unlinkat(dir, name, AtFlags::empty()).is_ok();
    }
    if depth >= MAX_DEPTH {
        return false;
    }
    let Ok(child) = open_directory_at(dir, name) else {
        return false;
    };
    remove_below(&child, depth.saturating_add(1))
        && rustix::fs::unlinkat(dir, name, AtFlags::REMOVEDIR).is_ok()
}
