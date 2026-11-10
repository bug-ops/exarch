//! The destination pre-check of a listed archive.
//!
//! [`check`] walks the landings a listing says extraction creates, in the
//! order it creates them, through the same [`DirWalker`] that the write phase
//! uses. Every parent is opened handle-relatively with the walker's symlink
//! policy, so a symlink among the parents is refused with the very error
//! extraction gives, and a failure to inspect a path is reported as the I/O
//! error it is, never as a symlink refusal. A landing that holds a symlink is
//! refused with the error the write phase gives ([`replaces_symlink`]), and one
//! that holds a directory is a `DestinationOccupied` conflict, the class
//! [`kept_occupant_refusal`] gives it there. A file at a directory landing is
//! the one occupant the write phase still reports as an untyped I/O error.

use std::path::Path;
use std::path::PathBuf;

use crate::ArchiveError;
use crate::DestinationCheck;
use crate::Result;
use crate::SecurityConfig;
use crate::formats::common::check_directory_occupant;
use crate::formats::dir_walker::DirRef;
use crate::formats::dir_walker::DirWalker;
use crate::formats::file_identity::FileIdentity;
use crate::formats::file_identity::IdentityCheck;
use crate::formats::occupant::replaces_symlink;
use crate::formats::pinned_dir::Leaf;
use crate::formats::pinned_dir::LeafBuf;
use crate::formats::pinned_dir::PinnedRoot;
use crate::formats::pinned_dir::VettedDir;
use crate::inspection::ArchiveManifest;
use crate::inspection::Landing;
use crate::inspection::LandingKind;
use crate::inspection::LinkTarget;
use crate::inspection::ManifestEntryKind;
use crate::security::fs_view::Occupant;
use crate::types::DestDir;

/// What a landing finds at its path.
enum Occupancy {
    /// Nothing is there, or what is there is acceptable.
    Free,
    /// Something is there that the write phase refuses to replace.
    Conflict,
}

/// Opens `dest` for probing, or `None` when it does not exist: nothing can
/// conflict with an archive that has no destination yet.
fn open_destination(dest: &Path) -> Result<Option<PinnedRoot>> {
    match DestDir::new(dest) {
        Ok(dest_dir) => PinnedRoot::open(dest_dir).map(Some),
        Err(ArchiveError::DestinationNotAccessible { error, .. })
            if error.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// The parent a landing was last opened under, kept for the next landing.
///
/// A parent is kept only when every component down to it is a plain
/// directory (a strict, symlink-refusing walk reaches it) and the volume
/// reports a file identity. It is reused only while the entry that names it is
/// still the same inode in the directory that held it, so a replaced
/// directory or a symlink swapped in sends the next landing through a fresh
/// walk, which gives the walker's own verdict. A path with a symlink in any
/// ancestor, a missing parent, or a volume without file ids is never kept, so
/// the walker's redirect handling and projected-length check still run for
/// every landing below it.
///
/// Ancestors above the entry that names the parent are not re-read: the
/// handles pin them, so a reuse answers for the tree as pinned, the same
/// snapshot the walk that filled the cache saw.
///
/// A landing that finds neither a reusable parent nor a remembered unkeepable
/// one is a miss and pays for a probe. A hit resets the run of misses; a miss
/// whose parent lies below the previous one (a sorted archive entering a new
/// directory chain) is not counted; after [`MISS_LIMIT`] counted misses in a
/// row the cache steps aside for the rest of the check, so an archive that
/// interleaves directories costs what the plain walk costs. An archive that
/// lists a directory's entries together misses once per directory and never
/// reaches the limit unless it holds a run of unrelated directories of one or
/// two entries, where reuse saves almost nothing.
struct ParentCache<'r> {
    slot: Slot<'r>,
    misses: u8,
    #[cfg(test)]
    reuses: usize,
}

/// Consecutive misses after which [`ParentCache`] stops probing.
const MISS_LIMIT: u8 = 4;

enum Slot<'r> {
    Empty,
    Kept(CachedParent<'r>),
    /// The parent at this path cannot be kept; its landings walk afresh.
    Unkept(PathBuf),
    /// The cache is off for the rest of the check; every landing walks afresh.
    Bypass,
}

#[cfg(test)]
impl std::fmt::Debug for Slot<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Empty => "Empty",
            Self::Kept(_) => "Kept",
            Self::Unkept(_) => "Unkept",
            Self::Bypass => "Bypass",
        })
    }
}

struct CachedParent<'r> {
    dir_rel: PathBuf,
    holder: DirRef<'r>,
    name: LeafBuf,
    identity: FileIdentity,
    dir: VettedDir,
}

/// What a strict walk to a parent found.
enum Probed<'r> {
    Kept(CachedParent<'r>),
    /// The parent was opened but cannot be kept.
    Opened(VettedDir),
    /// The strict walk did not end in an opened directory; the policy walk
    /// decides.
    Unresolved,
}

/// A landing's parent directory, from the cache or from a fresh walk.
enum Parent<'c, 'r> {
    Cached(&'c VettedDir),
    Fresh(DirRef<'r>),
}

impl std::ops::Deref for Parent<'_, '_> {
    type Target = VettedDir;

    fn deref(&self) -> &VettedDir {
        match self {
            Self::Cached(dir) => dir,
            Self::Fresh(dir) => dir,
        }
    }
}

/// Whether a directory with this identity may be reused: an unknown identity
/// cannot show that the directory was replaced.
const fn is_keepable(identity: FileIdentity) -> bool {
    matches!(identity, FileIdentity::Known(_))
}

impl<'r> ParentCache<'r> {
    const fn new() -> Self {
        Self {
            slot: Slot::Empty,
            misses: 0,
            #[cfg(test)]
            reuses: 0,
        }
    }

    /// Whether `dir_rel` lies below the parent the previous landing used: a
    /// sorted archive walks into a new directory chain this way, one miss per
    /// level, and that is not a sign of interleaved directories.
    fn descends_into(&self, dir_rel: &Path) -> bool {
        match &self.slot {
            Slot::Kept(cached) => dir_rel.starts_with(&cached.dir_rel),
            Slot::Unkept(path) => dir_rel.starts_with(path),
            Slot::Empty | Slot::Bypass => false,
        }
    }

    /// Opens the parent of `rel` as [`DirWalker::open_parent`] does, reusing
    /// the previous landing's parent when it is provably unchanged. An
    /// unkeepable parent costs one walk, as without the cache.
    fn open<'c, 'p>(
        &'c mut self,
        walker: DirWalker,
        root: &'r PinnedRoot,
        rel: &'p Path,
    ) -> Result<(Parent<'c, 'r>, Leaf<'p>)> {
        let (dir_rel, leaf) = Leaf::split(rel)?;
        if dir_rel.is_empty() {
            let (dir, leaf) = walker.open_parent(root, rel)?;
            return Ok((Parent::Fresh(dir), leaf));
        }
        match &self.slot {
            Slot::Bypass => {}
            Slot::Kept(cached) if cached.holds(dir_rel) => {
                self.misses = 0;
                #[cfg(test)]
                {
                    self.reuses += 1;
                }
            }
            Slot::Unkept(path) if path == dir_rel => self.misses = 0,
            _ if self.misses >= MISS_LIMIT => self.slot = Slot::Bypass,
            _ => {
                if !self.descends_into(dir_rel) {
                    self.misses = self.misses.saturating_add(1);
                }
                match CachedParent::probe(walker, root, dir_rel) {
                    Probed::Kept(cached) => self.slot = Slot::Kept(cached),
                    Probed::Opened(dir) => {
                        self.slot = Slot::Unkept(dir_rel.to_path_buf());
                        return Ok((Parent::Fresh(DirRef::Opened(dir)), leaf));
                    }
                    Probed::Unresolved => self.slot = Slot::Unkept(dir_rel.to_path_buf()),
                }
            }
        }
        if let Slot::Kept(cached) = &self.slot {
            return Ok((Parent::Cached(&cached.dir), leaf));
        }
        let (dir, leaf) = walker.open_parent(root, rel)?;
        Ok((Parent::Fresh(dir), leaf))
    }
}

impl<'r> CachedParent<'r> {
    fn holds(&self, dir_rel: &Path) -> bool {
        self.dir_rel == dir_rel
            && self
                .holder
                .identity(self.name.as_leaf())
                .ok()
                .flatten()
                .is_some_and(|now| now.check(self.identity) == IdentityCheck::Same)
    }

    fn probe(walker: DirWalker, root: &'r PinnedRoot, dir_rel: &Path) -> Probed<'r> {
        let Ok((holder, leaf)) = walker.open_resolved_parent(root, dir_rel) else {
            return Probed::Unresolved;
        };
        let Ok(Some(status)) = holder.status(leaf) else {
            return Probed::Unresolved;
        };
        let Ok(dir) = holder.open_dir(leaf) else {
            return Probed::Unresolved;
        };
        let Some(name) = LeafBuf::of(dir_rel).filter(|_| is_keepable(status.identity)) else {
            return Probed::Opened(dir);
        };
        match holder.identity(leaf) {
            Ok(Some(after)) if after.check(status.identity) == IdentityCheck::Same => {
                Probed::Kept(Self {
                    dir_rel: dir_rel.to_path_buf(),
                    holder,
                    name,
                    identity: status.identity,
                    dir,
                })
            }
            _ => Probed::Unresolved,
        }
    }
}

/// What a landing puts at its path.
enum Arrival<'a> {
    Directory,
    File,
    Symlink(&'a LinkTarget),
    Hardlink,
}

impl<'a> Arrival<'a> {
    fn of(kind: LandingKind<'a>) -> Self {
        match kind {
            LandingKind::ImplicitParent => Self::Directory,
            LandingKind::Entry(entry) => match &entry.kind {
                ManifestEntryKind::Directory => Self::Directory,
                ManifestEntryKind::File { .. } => Self::File,
                ManifestEntryKind::Symlink { target } => Self::Symlink(target),
                ManifestEntryKind::Hardlink { .. } => Self::Hardlink,
            },
        }
    }
}

/// Refuses, before anything is written, a destination the write phase would
/// refuse.
///
/// # Errors
///
/// `DestinationOccupied` naming every occupied landing, in path-component
/// order; the typed symlink
/// refusal the write phase gives for a link among the parents or at a
/// landing; or the I/O error of a path that could not be inspected.
pub(super) fn check(
    manifest: &ArchiveManifest,
    config: &SecurityConfig,
    dest: &Path,
    check: DestinationCheck,
) -> Result<()> {
    let Some(root) = open_destination(dest)? else {
        return Ok(());
    };
    let walker = DirWalker::new(config);
    let mut parents = ParentCache::new();
    let mut conflicts: Vec<PathBuf> = Vec::new();
    for landing in manifest.landings(config) {
        let rel = landing.path().as_path();
        if rel.is_empty() {
            continue;
        }
        match inspect(walker, &root, &mut parents, &landing, check) {
            Ok(Occupancy::Free) => {}
            Ok(Occupancy::Conflict) => conflicts.push(rel.to_path_buf()),
            Err(ArchiveError::Io(error)) if is_below_a_conflict(&error, &conflicts) => {}
            Err(error) => return Err(error),
        }
    }
    conflicts.sort();
    conflicts.dedup();
    conflicts
        .is_empty()
        .ok_or_else(|| ArchiveError::DestinationOccupied {
            destination: Some(dest.to_path_buf()),
            conflicts: conflicts.into_boxed_slice(),
            by: crate::OccupiedBy::Existing,
        })
}

/// Whether an I/O failure only says that the path is absent or sits below a
/// conflict already reported at one of its ancestors.
fn is_below_a_conflict(error: &std::io::Error, conflicts: &[PathBuf]) -> bool {
    match error.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidFilename => true,
        std::io::ErrorKind::NotADirectory => !conflicts.is_empty(),
        _ => false,
    }
}

/// Looks at the landing's path through its pinned parent.
fn inspect<'r>(
    walker: DirWalker,
    root: &'r PinnedRoot,
    parents: &mut ParentCache<'r>,
    landing: &Landing<'_>,
    check: DestinationCheck,
) -> Result<Occupancy> {
    let rel = landing.path().as_path();
    let arrival = Arrival::of(landing.kind());
    let (parent, leaf) = parents.open(walker, root, rel)?;
    let Some(occupant) = parent.probe(leaf)? else {
        return Ok(Occupancy::Free);
    };
    let refuse_symlink = || Err(replaces_symlink(rel));
    let replaceable = check == DestinationCheck::Replaceable;
    match (&arrival, occupant) {
        (Arrival::Directory, Occupant::Directory) => Ok(Occupancy::Free),
        (Arrival::Directory, Occupant::Symlink) => vet_symlinked_directory(walker, root, landing),
        (Arrival::File | Arrival::Symlink(_), Occupant::File) if replaceable => Ok(Occupancy::Free),
        (_, Occupant::Directory | Occupant::File) => Ok(Occupancy::Conflict),
        (Arrival::Symlink(target), Occupant::Symlink) if replaceable => match target {
            LinkTarget::Recorded(recorded) if parent.read_link(leaf)? == *recorded => {
                Ok(Occupancy::Free)
            }
            _ => refuse_symlink(),
        },
        (_, Occupant::Symlink) => refuse_symlink(),
    }
}

/// The write phase's verdict on a symlink at a directory landing: an entry
/// goes through the occupant check, an implied parent through the walk.
fn vet_symlinked_directory(
    walker: DirWalker,
    root: &PinnedRoot,
    landing: &Landing<'_>,
) -> Result<Occupancy> {
    let rel = landing.path().as_path();
    if matches!(landing.kind(), LandingKind::Entry(_)) {
        check_directory_occupant(&root.dest().probe(rel), rel, root.dest())?;
    }
    walker.vet_dir(root, rel)?;
    Ok(Occupancy::Free)
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::assert_matches;

    use super::*;
    use crate::ArchiveEntry;
    use crate::ArchiveType;
    use crate::Violation;

    fn replaceable_over_a_symlink(target: LinkTarget) -> Result<()> {
        let mut manifest = ArchiveManifest::new(ArchiveType::SevenZ);
        manifest
            .add_entry(ArchiveEntry::new(
                "x".into(),
                ManifestEntryKind::Symlink { target },
            ))
            .unwrap();
        let dest = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("anything", dest.path().join("x")).unwrap();
        let config = SecurityConfig::default().with_allow_symlinks(true);
        check(
            &manifest,
            &config,
            dest.path(),
            DestinationCheck::Replaceable,
        )
    }

    #[test]
    fn an_unread_symlink_target_is_not_provably_replaceable() {
        assert_matches!(
            replaceable_over_a_symlink(LinkTarget::Unread),
            Err(ArchiveError::SecurityViolation {
                kind: Violation::ReplacesSymlink { .. },
                ..
            })
        );
    }

    #[test]
    fn a_recorded_equal_target_is_replaceable() {
        replaceable_over_a_symlink(LinkTarget::Recorded("anything".into())).unwrap();
    }

    #[test]
    fn a_recorded_different_target_is_refused_as_a_symlink() {
        assert_matches!(
            replaceable_over_a_symlink(LinkTarget::Recorded("other".into())),
            Err(ArchiveError::SecurityViolation {
                kind: Violation::ReplacesSymlink { .. },
                ..
            })
        );
    }

    fn parent_probe<'r>(
        cache: &mut ParentCache<'r>,
        config: &SecurityConfig,
        root: &'r PinnedRoot,
        rel: &str,
    ) -> Result<Option<Occupant>> {
        let (parent, leaf) = cache.open(DirWalker::new(config), root, Path::new(rel))?;
        Ok(parent.probe(leaf)?)
    }

    fn cached_slot(cache: &ParentCache<'_>) -> bool {
        matches!(cache.slot, Slot::Kept(_))
    }

    #[test]
    fn consecutive_landings_share_one_parent() {
        let dest = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dest.path().join("a/b")).unwrap();
        std::fs::write(dest.path().join("a/b/f"), b"x").unwrap();
        let root = open_destination(dest.path()).unwrap().unwrap();
        let config = SecurityConfig::default();
        let mut cache = ParentCache::new();

        assert_eq!(
            parent_probe(&mut cache, &config, &root, "a/b/f").unwrap(),
            Some(Occupant::File)
        );
        assert!(cached_slot(&cache));
        assert_eq!(cache.reuses, 0);
        assert_eq!(
            parent_probe(&mut cache, &config, &root, "a/b/g").unwrap(),
            None
        );
        assert_eq!(cache.reuses, 1);
    }

    #[test]
    fn a_parent_below_a_symlinked_ancestor_is_never_kept() {
        let dest = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dest.path().join("real/sub")).unwrap();
        std::fs::write(dest.path().join("real/sub/f"), b"x").unwrap();
        std::os::unix::fs::symlink("real", dest.path().join("alias")).unwrap();
        let root = open_destination(dest.path()).unwrap().unwrap();
        let config = SecurityConfig::default().with_allow_symlinks(true);
        let mut cache = ParentCache::new();

        assert_eq!(
            parent_probe(&mut cache, &config, &root, "alias/sub/f").unwrap(),
            Some(Occupant::File)
        );
        assert_eq!(
            parent_probe(&mut cache, &config, &root, "alias/sub/g").unwrap(),
            None
        );

        assert!(!cached_slot(&cache));
        assert_eq!(cache.reuses, 0);
    }

    #[test]
    fn a_retargeted_ancestor_symlink_is_followed_anew() {
        let dest = tempfile::tempdir().unwrap();
        for dir in ["one", "two"] {
            std::fs::create_dir_all(dest.path().join(dir).join("sub")).unwrap();
        }
        std::fs::write(dest.path().join("two/sub/g"), b"x").unwrap();
        std::os::unix::fs::symlink("one", dest.path().join("alias")).unwrap();
        let root = open_destination(dest.path()).unwrap().unwrap();
        let config = SecurityConfig::default().with_allow_symlinks(true);
        let mut cache = ParentCache::new();
        assert_eq!(
            parent_probe(&mut cache, &config, &root, "alias/sub/g").unwrap(),
            None
        );

        std::fs::remove_file(dest.path().join("alias")).unwrap();
        std::os::unix::fs::symlink("two", dest.path().join("alias")).unwrap();

        assert_eq!(
            parent_probe(&mut cache, &config, &root, "alias/sub/g").unwrap(),
            Some(Occupant::File)
        );
    }

    #[test]
    fn a_directory_replaced_between_landings_is_walked_again() {
        let dest = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dest.path().join("a/b")).unwrap();
        let root = open_destination(dest.path()).unwrap().unwrap();
        let config = SecurityConfig::default();
        let mut cache = ParentCache::new();
        assert_eq!(
            parent_probe(&mut cache, &config, &root, "a/b/f").unwrap(),
            None
        );

        std::fs::rename(dest.path().join("a/b"), dest.path().join("a/old")).unwrap();
        std::fs::create_dir(dest.path().join("a/b")).unwrap();
        std::fs::write(dest.path().join("a/b/f"), b"new").unwrap();

        assert_eq!(
            parent_probe(&mut cache, &config, &root, "a/b/f").unwrap(),
            Some(Occupant::File)
        );
    }

    #[test]
    fn a_symlink_swapped_in_between_landings_is_refused() {
        let dest = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("f"), b"x").unwrap();
        std::fs::create_dir_all(dest.path().join("a/b")).unwrap();
        let root = open_destination(dest.path()).unwrap().unwrap();
        let config = SecurityConfig::default();
        let mut cache = ParentCache::new();
        parent_probe(&mut cache, &config, &root, "a/b/f").unwrap();

        std::fs::remove_dir(dest.path().join("a/b")).unwrap();
        std::os::unix::fs::symlink(outside.path(), dest.path().join("a/b")).unwrap();

        assert_matches!(
            parent_probe(&mut cache, &config, &root, "a/b/f"),
            Err(ArchiveError::SymlinkEscape { .. })
        );
        assert!(!cached_slot(&cache));
    }

    #[test]
    fn a_parent_behind_a_symlink_is_never_kept() {
        let dest = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dest.path().join("real")).unwrap();
        std::os::unix::fs::symlink("real", dest.path().join("alias")).unwrap();
        let root = open_destination(dest.path()).unwrap().unwrap();
        let config = SecurityConfig::default().with_allow_symlinks(true);
        let mut cache = ParentCache::new();

        parent_probe(&mut cache, &config, &root, "alias/f").unwrap();

        assert!(!cached_slot(&cache));
    }

    #[test]
    fn a_different_parent_replaces_the_kept_one() {
        let dest = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dest.path().join("a/x")).unwrap();
        std::fs::create_dir_all(dest.path().join("a/y")).unwrap();
        std::fs::write(dest.path().join("a/y/f"), b"x").unwrap();
        let root = open_destination(dest.path()).unwrap().unwrap();
        let config = SecurityConfig::default();
        let mut cache = ParentCache::new();

        assert_eq!(
            parent_probe(&mut cache, &config, &root, "a/x/f").unwrap(),
            None
        );
        assert_eq!(
            parent_probe(&mut cache, &config, &root, "a/y/f").unwrap(),
            Some(Occupant::File)
        );
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod throttle_tests {
    use std::assert_matches;

    use super::*;

    fn populated() -> tempfile::TempDir {
        let dest = tempfile::tempdir().unwrap();
        for dir in ["a/x", "b/x"] {
            std::fs::create_dir_all(dest.path().join(dir)).unwrap();
        }
        std::fs::write(dest.path().join("a/x/f"), b"x").unwrap();
        dest
    }

    fn plain_probe(config: &SecurityConfig, root: &PinnedRoot, rel: &str) -> Option<Occupant> {
        let (parent, leaf) = DirWalker::new(config)
            .open_parent(root, Path::new(rel))
            .unwrap();
        parent.probe(leaf).unwrap()
    }

    fn cached_probe<'r>(
        cache: &mut ParentCache<'r>,
        config: &SecurityConfig,
        root: &'r PinnedRoot,
        rel: &str,
    ) -> Option<Occupant> {
        let (parent, leaf) = cache
            .open(DirWalker::new(config), root, Path::new(rel))
            .unwrap();
        parent.probe(leaf).unwrap()
    }

    #[test]
    fn interleaved_directories_bypass_the_cache_with_the_plain_verdicts() {
        let dest = populated();
        let root = open_destination(dest.path()).unwrap().unwrap();
        let config = SecurityConfig::default();
        let mut cache = ParentCache::new();

        for _ in 0..6 {
            for rel in ["a/x/f", "b/x/f"] {
                assert_eq!(
                    cached_probe(&mut cache, &config, &root, rel),
                    plain_probe(&config, &root, rel),
                    "{rel}"
                );
            }
        }

        assert_matches!(cache.slot, Slot::Bypass);
        assert_eq!(cache.reuses, 0);
    }

    #[test]
    fn a_sorted_archive_never_bypasses_the_cache() {
        let dest = populated();
        let root = open_destination(dest.path()).unwrap().unwrap();
        let config = SecurityConfig::default();
        let mut cache = ParentCache::new();

        for rel in ["a/x/f"; 5].into_iter().chain(["b/x/f"; 5]) {
            assert_eq!(
                cached_probe(&mut cache, &config, &root, rel),
                plain_probe(&config, &root, rel)
            );
        }

        assert_matches!(cache.slot, Slot::Kept(_));
        assert_eq!(cache.reuses, 8);
        assert_eq!(cache.misses, 0);
    }

    #[test]
    fn a_sorted_archive_entering_a_deep_chain_never_bypasses_the_cache() {
        let dest = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dest.path().join("a/b/c/d/e/f/g")).unwrap();
        let root = open_destination(dest.path()).unwrap().unwrap();
        let config = SecurityConfig::default();
        let mut cache = ParentCache::new();

        for rel in [
            "a",
            "a/b",
            "a/b/c",
            "a/b/c/d",
            "a/b/c/d/e",
            "a/b/c/d/e/f",
            "a/b/c/d/e/f/g",
            "a/b/c/d/e/f/g/x",
            "a/b/c/d/e/f/g/y",
        ] {
            assert_eq!(
                cached_probe(&mut cache, &config, &root, rel),
                plain_probe(&config, &root, rel)
            );
        }

        assert_matches!(cache.slot, Slot::Kept(_));
        assert_eq!(cache.reuses, 1);
    }

    #[test]
    fn a_hit_resets_the_run_of_misses() {
        let dest = populated();
        let root = open_destination(dest.path()).unwrap().unwrap();
        let config = SecurityConfig::default();
        let mut cache = ParentCache::new();

        for rel in ["a/x/f", "b/x/f", "a/x/f", "a/x/g", "b/x/f", "a/x/f"] {
            cached_probe(&mut cache, &config, &root, rel);
        }

        assert!(!matches!(cache.slot, Slot::Bypass));
    }
}

#[cfg(test)]
mod keepable_tests {
    use super::*;
    use crate::formats::file_identity::IdentityKey;

    #[test]
    fn only_a_known_identity_may_be_kept() {
        assert!(!is_keepable(FileIdentity::Unknown));
        assert!(is_keepable(FileIdentity::Known(IdentityKey {
            dev: 1,
            ino: 2
        })));
    }
}
