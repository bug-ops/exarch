//! Removing what a rolled-back staging directory still holds on macOS.
//!
//! Every entry staged under an inheritable `deny delete` entry of the parent
//! inherits it, and the kernel then refuses to unlink the entry, so a plain
//! recursive removal leaves the staging directory behind. The sweep clears the
//! inherited entries of the run's own staged children and unlinks them.
//!
//! Nothing here acts on an entry by name except the unlink itself: an entry is
//! opened without following a symlink, its owner, link count and ACL are read
//! from the descriptor, and only then is the ACL cleared through that
//! descriptor. The sweep runs only with the [`OwnContents`] proof, and clears
//! only an entry whose identity the run's ledger holds: an entry the run did
//! not create is never cleared, whatever its owner and ACL look like.
//!
//! An entry with other links is the run's own only when every one of its
//! names is inside the staging directory: the sweep counts the names it walks
//! past per inode, and clears the inode only when its link count equals that
//! count, so a link from outside the stage (or from a place the sweep could
//! not see) keeps the entry and its ACL in place. An entry that belongs to
//! another user or carries an entry that was not inherited is left in place
//! too. Every failure skips the entry: the rollback reports what survived.
//!
//! The tree is walked by the bounded-descriptor walk the plain removal uses,
//! so a tree of any depth is swept.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs::File;

use rustix::fs::AtFlags;
use rustix::fs::FileType;
use rustix::fs::Mode;
use rustix::fs::OFlags;
use rustix::fs::Stat;
use rustix::io::Errno;

use super::acl;
use super::dir::OwnContents;
use super::dir::VerifiedStage;
use super::remove::Enter;
use super::remove::Outcome;
use super::remove::Trail;
use super::remove::Visit;
use super::remove::walk;
use crate::formats::file_identity::IdentityKey;
use crate::formats::pinned_dir::open_directory_at;
use crate::formats::run_record::RunRecord;

/// The names inside the stage the sweep walked past and could not unlink,
/// for the entries that have several links.
#[derive(Default)]
struct Links {
    /// How many names of each inode are still in the stage.
    surviving: HashMap<IdentityKey, usize>,
    /// The paths below the stage of the names that were opened and found to
    /// have several links.
    deferred: HashMap<IdentityKey, Vec<Vec<OsString>>>,
}

impl Links {
    fn survives(&mut self, key: Option<IdentityKey>) {
        if let Some(key) = key {
            let count = self.surviving.entry(key).or_default();
            *count = count.saturating_add(1);
        }
    }

    fn defer(&mut self, key: Option<IdentityKey>, trail: &Trail<'_>, name: &OsStr) {
        let Some(key) = key else {
            return;
        };
        self.survives(Some(key));
        let mut at = trail.to_vec();
        at.push(name.to_os_string());
        self.deferred.entry(key).or_default().push(at);
    }

    /// Unlinks the names of every inode whose links are all inside the stage
    /// and whose ACL the sweep may clear. Says whether any name was removed.
    fn resolve(&self, root: &File, ledger: &RunRecord) -> bool {
        let mut removed = false;
        for (key, names) in &self.deferred {
            if self.surviving.get(key) == Some(&names.len()) {
                removed |= remove_group(root, *key, names, ledger);
            }
        }
        removed
    }
}

/// Unlinks every name in `names`, which are all the names the inode `key`
/// has, after clearing its inherited ACL entries.
///
/// Every name is opened again first and must still be a non-directory with
/// that identity and a link count equal to `names.len()`; nothing is cleared
/// or unlinked unless all of them are.
fn remove_group(
    root: &File,
    key: IdentityKey,
    names: &[Vec<OsString>],
    ledger: &RunRecord,
) -> bool {
    let mut opened = Vec::with_capacity(names.len());
    for at in names {
        let Some((parent, name)) = open_parent(root, at) else {
            return false;
        };
        let Ok(file) = open_leaf(&parent, name) else {
            return false;
        };
        let matches = rustix::fs::fstat(&file).is_ok_and(|stat| {
            FileType::from_raw_mode(stat.st_mode) != FileType::Directory
                && IdentityKey::of_stat(&stat).is_ok_and(|opened| opened == key)
                && usize::from(stat.st_nlink) == names.len()
        });
        if !matches {
            return false;
        }
        opened.push((parent, name, file));
    }
    let Some((_, _, first)) = opened.first() else {
        return false;
    };
    if !cleared_own_entry(first, ledger) {
        return false;
    }
    for (parent, name, _) in &opened {
        let _ = rustix::fs::unlinkat(parent, *name, AtFlags::empty());
    }
    true
}

/// The directory holding the entry at `at` below `root`, opened through each
/// level without following a symlink, and the entry's name.
fn open_parent<'a>(root: &File, at: &'a [OsString]) -> Option<(File, &'a OsStr)> {
    let (name, directories) = at.split_last()?;
    let mut current = root.try_clone().ok()?;
    for directory in directories {
        current = open_directory_at(&current, directory).ok()?;
    }
    Some((current, name.as_os_str()))
}

/// Unlinks everything it may under `stage`, clearing the inherited ACL
/// entries that stand in the way of the entries `ledger` says the run made.
pub(super) fn sweep(stage: &VerifiedStage, _own: &OwnContents, ledger: &RunRecord) {
    let root = stage.as_file();
    let _ = acl::CopiedAcl::clear(root);
    let mut sweep = Sweep::new(ledger);
    walk(root, &mut sweep);
    if sweep.links.resolve(root, ledger) {
        // The directories that held those names can go now.
        walk(root, &mut Sweep::new(ledger));
    }
}

/// The walk's visitor: enters only the directories the run made and clears
/// their ACL, and unlinks the entries whose ACL the run may clear.
struct Sweep<'a> {
    links: Links,
    ledger: &'a RunRecord,
}

impl Visit for Sweep<'_> {
    fn enter(&mut self, dir: &File) -> Enter {
        if cleared_own_entry(dir, self.ledger) {
            Enter::Descend
        } else {
            Enter::Keep
        }
    }

    fn leaf(&mut self, dir: &File, name: &OsStr, stat: &Stat, trail: Trail<'_>) -> Outcome {
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Symlink => {
                Outcome::of(rustix::fs::unlinkat(dir, name, AtFlags::empty()).is_ok())
            }
            _ => self.sweep_leaf(dir, name, stat, &trail),
        }
    }
}

impl<'a> Sweep<'a> {
    fn new(ledger: &'a RunRecord) -> Self {
        Self {
            links: Links::default(),
            ledger,
        }
    }

    fn sweep_leaf(&mut self, dir: &File, name: &OsStr, stat: &Stat, trail: &Trail<'_>) -> Outcome {
        match rustix::fs::unlinkat(dir, name, AtFlags::empty()) {
            Err(Errno::ACCESS | Errno::PERM) => {}
            Ok(()) => return Outcome::Removed,
            Err(_) => return Outcome::Kept,
        }
        let key = IdentityKey::of_stat(stat).ok();
        let Some((file, opened)) = open_leaf(dir, name)
            .ok()
            .and_then(|file| rustix::fs::fstat(&file).ok().map(|opened| (file, opened)))
        else {
            self.links.survives(key);
            return Outcome::Kept;
        };
        if FileType::from_raw_mode(opened.st_mode) == FileType::Directory {
            self.links.survives(key);
            Outcome::Kept
        } else if opened.st_nlink == 1 {
            Outcome::of(
                cleared_own_entry(&file, self.ledger)
                    && rustix::fs::unlinkat(dir, name, AtFlags::empty()).is_ok(),
            )
        } else {
            self.links
                .defer(IdentityKey::of_stat(&opened).ok(), trail, name);
            Outcome::Kept
        }
    }
}

/// Clears the ACL of `file` when the run created it, the caller owns it and
/// every entry in the ACL was inherited, so nothing the owner set on purpose
/// and nothing the run did not create is touched.
fn cleared_own_entry(file: &File, ledger: &RunRecord) -> bool {
    rustix::fs::fstat(file).is_ok_and(|stat| {
        is_owned_by_caller(&stat)
            && IdentityKey::of_stat(&stat).is_ok_and(|key| ledger.created_with(key))
    }) && acl::only_inherited_entries(file)
        && acl::CopiedAcl::clear(file).is_ok()
}

fn is_owned_by_caller(stat: &Stat) -> bool {
    stat.st_uid == rustix::process::geteuid().as_raw()
}

/// Opens a file that is not a directory without reading, writing or blocking
/// on it: read access first, and write access for an entry whose ACL denies
/// the read (a `deny read` entry or a mode without it).
fn open_leaf(dir: &File, name: &OsStr) -> rustix::io::Result<File> {
    let base = OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    rustix::fs::openat(dir, name, base | OFlags::RDONLY, Mode::empty())
        .or_else(|error| match error {
            Errno::ACCESS => rustix::fs::openat(dir, name, base | OFlags::WRONLY, Mode::empty()),
            other => Err(other),
        })
        .map(File::from)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;
    use std::path::Path;
    use std::path::PathBuf;

    use crate::formats::pinned_dir::Gid;
    use crate::formats::pinned_dir::Uid;

    use tempfile::TempDir;

    use super::super::adopt::Adoption;
    use super::super::adopt::Claim;
    use super::super::dir::Seed;
    use super::super::dir::StagingDir;
    use super::super::test_acl::AclCleanup;
    use super::super::test_acl::aces_of;
    use super::super::test_acl::add_ace;
    use super::super::test_acl::clear_acl;
    use super::IdentityKey;
    use super::RunRecord;
    use super::remove_group;
    use crate::formats::file_identity::FileIdentity;
    use crate::formats::pinned_dir::VettedDir;
    use crate::formats::run_record::Recording;

    const DENY_DELETE: &str = "everyone deny delete,file_inherit,directory_inherit";

    /// A parent whose children inherit a `deny delete` entry, pinned.
    fn denying_parent(temp: &TempDir) -> (VettedDir, PathBuf) {
        let parent = temp.path().canonicalize().unwrap().join("parent");
        std::fs::create_dir(&parent).unwrap();
        add_ace(&parent, DENY_DELETE);
        (VettedDir::open_path(&parent).unwrap(), parent)
    }

    /// Records everything now in the stage as made by the run, as the
    /// extraction would have.
    fn record_tree(staging: &StagingDir<'_>) {
        fn walk(ledger: &RunRecord, dir: &std::path::Path) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                let stat = rustix::fs::lstat(&path).unwrap();
                ledger.insert_identity_for_test(FileIdentity::Known(
                    IdentityKey::of_stat(&stat).unwrap(),
                ));
                if path.is_dir() && !path.is_symlink() {
                    walk(ledger, &path);
                }
            }
        }
        walk(staging.ledger(), staging.path());
    }

    fn is_root() -> bool {
        rustix::process::geteuid().is_root()
    }

    #[test]
    fn the_runs_own_entries_that_inherited_a_delete_deny_are_swept() {
        let temp = TempDir::new().unwrap();
        let _cleanup = AclCleanup(temp.path());
        let (pin, parent) = denying_parent(&temp);
        let staging = StagingDir::create(&pin, &parent, Seed::Absent).unwrap();
        let root = staging.path().to_path_buf();
        std::fs::create_dir_all(root.join("d/e")).unwrap();
        std::fs::write(root.join("d/e/f"), b"x").unwrap();
        std::fs::write(root.join("w"), b"x").unwrap();
        std::fs::set_permissions(root.join("w"), std::fs::Permissions::from_mode(0o200)).unwrap();
        symlink("w", root.join("l")).unwrap();
        assert!(!aces_of(&root.join("d/e/f")).is_empty());
        record_tree(&staging);

        assert!(staging.discard().is_none());

        assert!(!root.exists());
    }

    fn names(paths: &[&str]) -> Vec<Vec<std::ffi::OsString>> {
        paths.iter().map(|path| vec![(*path).into()]).collect()
    }

    fn key_of(path: &std::path::Path) -> IdentityKey {
        let stat = rustix::fs::stat(path).unwrap();
        IdentityKey::of_stat(&stat).unwrap()
    }

    fn ledger_of(path: &std::path::Path) -> RunRecord {
        let ledger = RunRecord::new(Recording::Ledger);
        ledger.insert_identity_for_test(FileIdentity::Known(key_of(path)));
        ledger
    }

    #[test]
    fn a_group_whose_names_all_match_is_unlinked() {
        let temp = TempDir::new().unwrap();
        std::fs::write(temp.path().join("a"), b"x").unwrap();
        std::fs::hard_link(temp.path().join("a"), temp.path().join("b")).unwrap();
        let root = std::fs::File::open(temp.path()).unwrap();

        let removed = remove_group(
            &root,
            key_of(&temp.path().join("a")),
            &names(&["a", "b"]),
            &ledger_of(&temp.path().join("a")),
        );

        assert!(removed);
        assert!(!temp.path().join("a").exists() && !temp.path().join("b").exists());
    }

    #[test]
    fn a_name_swapped_to_another_inode_keeps_the_whole_group() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path();
        std::fs::write(dir.join("a"), b"x").unwrap();
        std::fs::hard_link(dir.join("a"), dir.join("b")).unwrap();
        let key = key_of(&dir.join("a"));
        std::fs::remove_file(dir.join("b")).unwrap();
        std::fs::write(dir.join("b"), b"y").unwrap();
        std::fs::hard_link(dir.join("b"), dir.join("b_extra")).unwrap();
        std::fs::hard_link(dir.join("a"), dir.join("a_extra")).unwrap();
        let root = std::fs::File::open(dir).unwrap();

        let removed = remove_group(&root, key, &names(&["a", "b"]), &ledger_of(&dir.join("a")));

        assert!(!removed);
        assert!(dir.join("a").exists() && dir.join("b").exists());
    }

    #[test]
    fn a_tree_of_any_depth_is_swept() {
        for levels in [65, 200] {
            let temp = TempDir::new().unwrap();
            let _cleanup = AclCleanup(temp.path());
            let (pin, parent) = denying_parent(&temp);
            let staging = StagingDir::create(&pin, &parent, Seed::Absent).unwrap();
            let mut deepest = staging.path().to_path_buf();
            for _ in 0..levels {
                deepest.push("d");
            }
            std::fs::create_dir_all(&deepest).unwrap();
            std::fs::write(deepest.join("f"), b"x").unwrap();
            record_tree(&staging);
            assert!(!aces_of(&deepest).is_empty(), "{levels} levels");
            assert!(!aces_of(&deepest.join("f")).is_empty(), "{levels} levels");
            let root = std::fs::File::open(staging.path()).unwrap();
            assert!(
                !super::super::remove::remove_children(&root),
                "{levels} levels: the plain removal must fail so only the sweep can succeed"
            );
            assert!(deepest.join("f").exists(), "{levels} levels");

            assert!(staging.discard().is_none(), "{levels} levels");
        }
    }

    fn adopt_for_test(staging: &mut StagingDir<'_>, parent: &Path, mode: u32) {
        let own = std::fs::metadata(parent).unwrap();
        let _adopted = staging
            .adopt(Adoption::for_test(
                mode,
                Uid::of(&own),
                Gid::of(&own),
                Claim::Full,
            ))
            .unwrap();
    }

    /// A stage with one recorded file, adopted with `mode`.
    fn adopted_stage<'p>(pin: &'p VettedDir, parent: &Path, mode: u32) -> StagingDir<'p> {
        let mut staging = StagingDir::create(pin, parent, Seed::Absent).unwrap();
        std::fs::write(staging.path().join("f"), b"x").unwrap();
        record_tree(&staging);
        adopt_for_test(&mut staging, parent, mode);
        staging
    }

    #[test]
    fn a_rollback_after_a_closed_adoption_still_sweeps() {
        let temp = TempDir::new().unwrap();
        let _cleanup = AclCleanup(temp.path());
        let (pin, parent) = denying_parent(&temp);
        let staging = adopted_stage(&pin, &parent, 0o755);

        assert!(staging.own.is_some());
        assert!(staging.discard().is_none());
    }

    #[test]
    fn a_rollback_after_an_adoption_that_opens_the_root_keeps_the_stage() {
        for mode in [0o775, 0o757] {
            let temp = TempDir::new().unwrap();
            let _cleanup = AclCleanup(temp.path());
            let (pin, parent) = denying_parent(&temp);
            let staging = adopted_stage(&pin, &parent, mode);
            let root = staging.path().to_path_buf();

            assert!(staging.own.is_none(), "{mode:o}");
            assert!(staging.discard().is_some(), "{mode:o}");
            assert!(root.exists(), "{mode:o}");
        }
    }

    #[test]
    fn an_entry_planted_after_adoption_stays_as_the_leftover() {
        let temp = TempDir::new().unwrap();
        let _cleanup = AclCleanup(temp.path());
        let (pin, parent) = denying_parent(&temp);
        let mut staging = StagingDir::create(&pin, &parent, Seed::Absent).unwrap();
        let root = staging.path().to_path_buf();
        std::fs::create_dir(root.join("sub")).unwrap();
        std::fs::set_permissions(root.join("sub"), std::fs::Permissions::from_mode(0o777)).unwrap();
        record_tree(&staging);
        adopt_for_test(&mut staging, &parent, 0o755);
        std::fs::write(root.join("sub/planted"), b"x").unwrap();
        assert!(staging.own.is_some());

        let leftover = staging.discard().unwrap();

        assert_eq!(leftover.path, root);
        assert!(root.join("sub/planted").exists());
    }

    #[test]
    fn a_link_from_outside_keeps_its_acl_after_adoption() {
        let temp = TempDir::new().unwrap();
        let _cleanup = AclCleanup(temp.path());
        let (pin, parent) = denying_parent(&temp);
        let mut staging = StagingDir::create(&pin, &parent, Seed::Absent).unwrap();
        let root = staging.path().to_path_buf();
        std::fs::create_dir(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/first"), b"x").unwrap();
        record_tree(&staging);
        adopt_for_test(&mut staging, &parent, 0o755);
        let outside = temp.path().canonicalize().unwrap().join("outside");
        std::fs::hard_link(root.join("sub/first"), &outside).unwrap();
        let held = aces_of(&outside);
        assert_eq!(held.len(), 1, "{held:?}");

        assert!(staging.discard().is_some());

        assert!(root.join("sub/first").exists());
        assert_eq!(aces_of(&outside), held);
    }

    #[test]
    fn the_proof_is_dropped_unless_the_root_is_closed_to_others() {
        let temp = TempDir::new().unwrap();
        let _cleanup = AclCleanup(temp.path());
        let (pin, parent) = denying_parent(&temp);
        let mut staging = StagingDir::create(&pin, &parent, Seed::Absent).unwrap();
        let root = staging.path().to_path_buf();
        let proof = |staging: &mut StagingDir<'_>| {
            let own = staging.own.take();
            staging.keep_own_after_adoption(own);
            staging.own.is_some()
        };
        assert!(proof(&mut staging));

        add_ace(
            &root,
            "everyone allow list,file_inherit,directory_inherit,only_inherit",
        );
        assert!(proof(&mut staging));

        add_ace(&root, "everyone allow list");
        assert!(!proof(&mut staging));
    }

    #[test]
    fn an_entry_nobody_may_open_stays_a_named_leftover() {
        if is_root() {
            return;
        }
        let temp = TempDir::new().unwrap();
        let _cleanup = AclCleanup(temp.path());
        let (pin, parent) = denying_parent(&temp);
        let staging = StagingDir::create(&pin, &parent, Seed::Absent).unwrap();
        let root = staging.path().to_path_buf();
        std::fs::write(root.join("z"), b"x").unwrap();
        std::fs::set_permissions(root.join("z"), std::fs::Permissions::from_mode(0o000)).unwrap();

        let leftover = staging.discard().unwrap();

        assert_eq!(leftover.path, root);
        assert!(root.join("z").exists());
    }

    #[test]
    fn hard_links_created_inside_the_stage_are_swept() {
        let temp = TempDir::new().unwrap();
        let _cleanup = AclCleanup(temp.path());
        let (pin, parent) = denying_parent(&temp);
        let staging = StagingDir::create(&pin, &parent, Seed::Absent).unwrap();
        let root = staging.path().to_path_buf();
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::write(root.join("first"), b"x").unwrap();
        std::fs::hard_link(root.join("first"), root.join("a/second")).unwrap();
        std::fs::hard_link(root.join("first"), root.join("a/b/third")).unwrap();
        record_tree(&staging);

        assert!(staging.discard().is_none());

        assert!(!root.exists());
    }

    #[test]
    fn a_link_from_outside_keeps_the_in_stage_names_of_the_same_inode() {
        let temp = TempDir::new().unwrap();
        let _cleanup = AclCleanup(temp.path());
        let (pin, parent) = denying_parent(&temp);
        let staging = StagingDir::create(&pin, &parent, Seed::Absent).unwrap();
        let root = staging.path().to_path_buf();
        std::fs::write(root.join("first"), b"x").unwrap();
        std::fs::hard_link(root.join("first"), root.join("second")).unwrap();
        let outside = temp.path().canonicalize().unwrap().join("outside");
        std::fs::hard_link(root.join("first"), &outside).unwrap();
        let held = aces_of(&outside);
        assert_eq!(held.len(), 1, "{held:?}");

        assert!(staging.discard().is_some());

        assert!(root.join("first").exists() && root.join("second").exists());
        assert_eq!(aces_of(&outside), held);
    }

    #[test]
    fn an_entry_with_an_explicit_deny_is_never_cleared() {
        let temp = TempDir::new().unwrap();
        let _cleanup = AclCleanup(temp.path());
        let (pin, parent) = denying_parent(&temp);
        let staging = StagingDir::create(&pin, &parent, Seed::Absent).unwrap();
        let root = staging.path().to_path_buf();
        std::fs::write(root.join("kept"), b"x").unwrap();
        add_ace(&root.join("kept"), "everyone deny delete");
        let before = aces_of(&root.join("kept"));
        assert_eq!(before.len(), 2, "{before:?}");

        assert!(staging.discard().is_some());

        assert_eq!(aces_of(&root.join("kept")), before);
    }

    #[test]
    fn a_hard_link_to_an_object_outside_the_stage_is_left_and_its_acl_kept() {
        let temp = TempDir::new().unwrap();
        let _cleanup = AclCleanup(temp.path());
        let (pin, parent) = denying_parent(&temp);
        let outside = temp.path().canonicalize().unwrap().join("outside");
        std::fs::create_dir(&outside).unwrap();
        add_ace(&outside, DENY_DELETE);
        let victim = outside.join("victim");
        std::fs::write(&victim, b"x").unwrap();
        let held = aces_of(&victim);
        assert_eq!(held.len(), 1, "{held:?}");
        assert!(held[0].contains("inherited"), "{held:?}");
        let staging = StagingDir::create(&pin, &parent, Seed::Absent).unwrap();
        let root = staging.path().to_path_buf();
        std::fs::create_dir(root.join("sub")).unwrap();
        std::fs::hard_link(&victim, root.join("sub/link")).unwrap();

        assert!(staging.discard().is_some());

        assert!(root.join("sub/link").exists());
        assert_eq!(aces_of(&victim), held);
    }

    #[test]
    fn an_entry_the_run_did_not_create_keeps_its_acl_and_is_reported() {
        let temp = TempDir::new().unwrap();
        let _cleanup = AclCleanup(temp.path());
        let (pin, parent) = denying_parent(&temp);
        let outside = temp.path().canonicalize().unwrap().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let moved = outside.join("moved");
        std::fs::create_dir(&moved).unwrap();
        add_ace(&moved, "everyone deny delete,file_inherit");
        let kept = moved.join("kept");
        std::fs::write(&kept, b"x").unwrap();
        clear_acl(&moved);
        let held = aces_of(&kept);
        assert_eq!(held.len(), 1, "{held:?}");
        let staging = StagingDir::create(&pin, &parent, Seed::Absent).unwrap();
        let root = staging.path().to_path_buf();
        std::fs::write(root.join("own"), b"x").unwrap();
        record_tree(&staging);
        std::fs::rename(&moved, root.join("moved")).unwrap();

        let leftover = staging.discard().unwrap();

        assert_eq!(leftover.path, root);
        assert!(!root.join("own").exists());
        assert!(root.join("moved/kept").exists());
        assert_eq!(aces_of(&root.join("moved/kept")), held);
    }

    #[test]
    fn a_saturated_ledger_sweeps_nothing() {
        let temp = TempDir::new().unwrap();
        let _cleanup = AclCleanup(temp.path());
        let (pin, parent) = denying_parent(&temp);
        let staging = StagingDir::create(&pin, &parent, Seed::Absent).unwrap();
        let root = staging.path().to_path_buf();
        std::fs::create_dir(root.join("d")).unwrap();
        std::fs::write(root.join("d/f"), b"x").unwrap();
        record_tree(&staging);
        staging.ledger().saturate();

        assert!(staging.discard().is_some());

        assert!(root.join("d/f").exists());
    }
}
