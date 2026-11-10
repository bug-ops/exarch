//! Which landings the current run created itself.
//!
//! Under [`ExistingFiles::Refuse`] an occupied landing is refused, except when
//! the run made the occupant and it is a file or a symlink: a second archive
//! entry for the same path is a duplicate and is skipped, as under
//! [`ExistingFiles::Skip`]. A directory the run made is never a duplicate, but
//! the record keeps it too, so a refusal can say that the archive itself made
//! the occupant. The record tells an entry the run made from one it did not. It
//! is kept per run, by the pinned destination; files are recorded under
//! `Refuse` and `Overwrite`, never under `Skip`, directories always.
//!
//! A staged run keeps a [`Recording::Ledger`] instead: every entry the run
//! creates is recorded whatever `ExistingFiles` says, and the ledger outlives
//! the extraction, so a rollback can tell what the run made from what it did
//! not make.
//!
//! A landing is keyed by file identity (device and file index of the entry
//! itself, never of a symlink's target), which is exact on a case-insensitive
//! host and needs no path folding. Where the volume gives no identity the key
//! is the landing path as the archive spelled it, so a duplicate that differs
//! only in case is refused: the record fails closed. A failed identity lookup
//! records nothing. [`ArchiveManifest::dispositions_on`] can model the path
//! basis when its caller passes [`VolumeIdentity::LandingPaths`]; the CLI and
//! both bindings probe the destination volume for it, and a `list` without a
//! destination assumes file identities.
//!
//! [`ArchiveManifest::dispositions_on`]: crate::ArchiveManifest::dispositions_on
//! [`VolumeIdentity::LandingPaths`]: crate::VolumeIdentity::LandingPaths
//!
//! The record is bounded by [`RECORD_CAP`]. Past it nothing more is recorded
//! and every occupant counts as not created by this run, so the run fails
//! closed.
//!
//! # Races
//!
//! The record can be wrong when another process replaces a file this run made
//! (an identity that matches a file it did not make, or no longer matches one
//! it did). A wrong answer only turns a refusal into a skip or a skip into a
//! refusal. Neither writes: every occupant site routes `Refuse` to "refuse" or
//! "skip" and never to an overwrite, and the creates themselves stay `O_EXCL`.
//!
//! Identities are reused: once a created file is deleted, the filesystem may
//! hand its (device, inode) to the next file. A foreign file that takes over
//! the freed identity of a created one is skipped as a duplicate, never
//! overwritten.

use std::cell::RefCell;
use std::collections::HashSet;
use std::fs::File;
use std::path::Path;
use std::path::PathBuf;

use super::file_identity::FileIdentity;
use super::file_identity::IdentityKey;
use super::pinned_dir::Leaf;
use super::pinned_dir::VettedDir;
use crate::ExistingFiles;

/// The most landings a run records (4 Mi keys).
const RECORD_CAP: usize = 4 * 1024 * 1024;

/// How a landing is recorded: by identity, or by path where the volume gives
/// none (FAT, exFAT, and Windows volumes without `FileIdInfo`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum LandingKey {
    Identity(IdentityKey),
    Path(PathBuf),
}

fn key_for(identity: FileIdentity, rel: &Path) -> LandingKey {
    #[cfg(test)]
    if key_basis::current() == key_basis::KeyBasis::Path {
        return LandingKey::Path(rel.to_path_buf());
    }
    identity
        .key()
        .map_or_else(|| LandingKey::Path(rel.to_path_buf()), LandingKey::Identity)
}

/// A test-only switch that makes this thread key every landing by its spelled
/// path, as a volume without file identities does.
#[cfg(test)]
pub(crate) mod key_basis {
    use std::cell::Cell;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum KeyBasis {
        Identity,
        Path,
    }

    thread_local! {
        static BASIS: Cell<KeyBasis> = const { Cell::new(KeyBasis::Identity) };
    }

    pub(super) fn current() -> KeyBasis {
        BASIS.with(Cell::get)
    }

    /// Runs `body` with this thread keying landings by `basis`.
    pub(crate) fn with<T>(basis: KeyBasis, body: impl FnOnce() -> T) -> T {
        struct Restore(KeyBasis);
        impl Drop for Restore {
            fn drop(&mut self) {
                BASIS.with(|cell| cell.set(self.0));
            }
        }
        let _restore = Restore(BASIS.with(|cell| cell.replace(basis)));
        body()
    }
}

/// The key of the occupant of `leaf`, `None` when it is absent or the lookup
/// fails, so the landing is not recorded and a later duplicate is refused.
fn key_of(dir: &VettedDir, leaf: Leaf<'_>, rel: &Path) -> Option<LandingKey> {
    let identity = dir.identity(leaf).ok().flatten()?;
    Some(key_for(identity, rel))
}

#[derive(Debug, Default)]
struct Created {
    keys: HashSet<LandingKey>,
    saturated: bool,
}

/// What a [`RunRecord`] keeps.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Recording {
    /// Files created under `ExistingFiles::Refuse` (the duplicate check) and
    /// `Overwrite` (the maker named by a refused hardlink), never under `Skip`.
    #[default]
    Duplicates,
    /// Every entry the run creates, under any `ExistingFiles`.
    Ledger,
}

impl Recording {
    const fn records(self, existing_files: ExistingFiles) -> bool {
        match self {
            Self::Ledger => true,
            Self::Duplicates => !matches!(existing_files, ExistingFiles::Skip),
        }
    }
}

/// The landings a run created, consulted when one is found occupied.
#[derive(Debug, Default)]
pub(crate) struct RunRecord {
    recording: Recording,
    created: RefCell<Created>,
}

impl RunRecord {
    /// An empty record that keeps what `recording` says.
    pub(crate) fn new(recording: Recording) -> Self {
        Self {
            recording,
            created: RefCell::default(),
        }
    }

    /// Records that the run just created `leaf` in `dir`, if `existing_files`
    /// needs the record.
    ///
    /// A key that cannot be read is not recorded, so a later duplicate is
    /// refused.
    pub(crate) fn note(
        &self,
        existing_files: ExistingFiles,
        dir: &VettedDir,
        leaf: Leaf<'_>,
        rel: &Path,
    ) {
        if self.recording.records(existing_files) {
            self.insert(key_of(dir, leaf, rel));
        }
    }

    /// Records that the run just created the directory `leaf` in `dir`.
    ///
    /// A duplicate check never skips a directory, but a refusal asks whether
    /// the run made the occupant, so directories are recorded under every
    /// [`Recording`].
    pub(crate) fn note_directory(&self, dir: &VettedDir, leaf: Leaf<'_>, rel: &Path) {
        self.insert(key_of(dir, leaf, rel));
    }

    /// Like [`note`](Self::note) for the file `leaf` the run just created and
    /// still holds open: keyed by its handle, so no lookup by name unless the
    /// handle gives no identity, which the lookup by name then classifies.
    pub(crate) fn note_file(
        &self,
        existing_files: ExistingFiles,
        file: &File,
        dir: &VettedDir,
        leaf: Leaf<'_>,
        rel: &Path,
    ) {
        if !self.recording.records(existing_files) {
            return;
        }
        match FileIdentity::of_file(file) {
            FileIdentity::Unknown => self.insert(key_of(dir, leaf, rel)),
            known @ FileIdentity::Known(_) => self.insert(Some(key_for(known, rel))),
        }
    }

    fn insert(&self, key: Option<LandingKey>) {
        let Some(key) = key else {
            return;
        };
        let mut created = self.created.borrow_mut();
        if created.keys.len() >= RECORD_CAP {
            created.saturated = true;
        } else {
            created.keys.insert(key);
        }
    }

    /// Whether the occupant of `leaf` in `dir` is a landing this run created.
    ///
    /// `false` when the key cannot be read or the record is saturated.
    pub(crate) fn created_here(&self, dir: &VettedDir, leaf: Leaf<'_>, rel: &Path) -> bool {
        let created = self.created.borrow();
        !created.saturated && key_of(dir, leaf, rel).is_some_and(|key| created.keys.contains(&key))
    }

    /// Whether the run created an entry with this identity.
    ///
    /// `false` for a saturated record, and for an entry recorded by path
    /// because its volume gave no identity: neither can vouch for an entry.
    #[cfg(any(target_os = "macos", all(unix, test)))]
    pub(crate) fn created_with(&self, key: IdentityKey) -> bool {
        let created = self.created.borrow();
        !created.saturated && created.keys.contains(&LandingKey::Identity(key))
    }

    #[cfg(all(test, unix))]
    pub(crate) fn insert_identity_for_test(&self, identity: super::file_identity::FileIdentity) {
        if let Some(key) = identity.key() {
            self.created
                .borrow_mut()
                .keys
                .insert(LandingKey::Identity(key));
        }
    }

    #[cfg(all(test, unix))]
    pub(crate) fn saturate(&self) {
        self.created.borrow_mut().saturated = true;
    }
}

#[cfg(test)]
mod key_tests {
    use std::assert_matches;

    use super::LandingKey;
    use super::RunRecord;
    use super::key_for;
    use crate::formats::file_identity::FileIdentity;

    #[test]
    fn an_unknown_identity_is_keyed_by_the_path_as_spelled() {
        let record = RunRecord::default();
        record.insert(Some(key_for(FileIdentity::Unknown, "dir/a".as_ref())));

        let created = |rel: &str| {
            record
                .created
                .borrow()
                .keys
                .contains(&key_for(FileIdentity::Unknown, rel.as_ref()))
        };
        assert!(created("dir/a"));
        assert!(!created("dir/A"));
        assert_matches!(
            key_for(FileIdentity::Unknown, "x".as_ref()),
            LandingKey::Path(_)
        );
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::RunRecord;
    use crate::ExistingFiles;
    use crate::formats::pinned_dir::support::leaf;
    use crate::formats::pinned_dir::support::pinned_at;

    #[test]
    fn skip_records_nothing_and_only_what_it_recorded_counts_as_created() {
        let temp = tempfile::tempdir().unwrap();
        let dir = pinned_at(temp.path());
        std::fs::write(temp.path().join("made"), b"x").unwrap();
        std::fs::write(temp.path().join("foreign"), b"y").unwrap();
        let record = RunRecord::default();

        record.note(ExistingFiles::Skip, &dir, leaf("made"), "made".as_ref());
        assert!(!record.created_here(&dir, leaf("made"), "made".as_ref()));

        let overwriting = RunRecord::default();
        overwriting.note(
            ExistingFiles::Overwrite,
            &dir,
            leaf("made"),
            "made".as_ref(),
        );
        assert!(overwriting.created_here(&dir, leaf("made"), "made".as_ref()));

        record.note(ExistingFiles::Refuse, &dir, leaf("made"), "made".as_ref());
        assert!(record.created_here(&dir, leaf("made"), "made".as_ref()));
        assert!(!record.created_here(&dir, leaf("foreign"), "foreign".as_ref()));
        assert!(!record.created_here(&dir, leaf("absent"), "absent".as_ref()));
    }

    #[test]
    fn a_file_noted_by_its_handle_counts_as_created_except_under_skip() {
        let temp = tempfile::tempdir().unwrap();
        let dir = pinned_at(temp.path());
        let made = std::fs::File::create(temp.path().join("made")).unwrap();
        std::fs::write(temp.path().join("foreign"), b"y").unwrap();
        let record = RunRecord::default();

        record.note_file(
            ExistingFiles::Skip,
            &made,
            &dir,
            leaf("made"),
            "made".as_ref(),
        );
        assert!(!record.created_here(&dir, leaf("made"), "made".as_ref()));

        record.note_file(
            ExistingFiles::Refuse,
            &made,
            &dir,
            leaf("made"),
            "made".as_ref(),
        );
        assert!(record.created_here(&dir, leaf("made"), "made".as_ref()));
        assert!(!record.created_here(&dir, leaf("foreign"), "foreign".as_ref()));
    }

    #[test]
    fn a_saturated_record_treats_every_occupant_as_foreign() {
        let temp = tempfile::tempdir().unwrap();
        let dir = pinned_at(temp.path());
        std::fs::write(temp.path().join("made"), b"x").unwrap();
        let record = RunRecord::default();
        record.note(ExistingFiles::Refuse, &dir, leaf("made"), "made".as_ref());

        record.saturate();

        assert!(!record.created_here(&dir, leaf("made"), "made".as_ref()));
    }

    #[test]
    fn a_symlink_is_keyed_by_itself_not_by_its_target() {
        let temp = tempfile::tempdir().unwrap();
        let dir = pinned_at(temp.path());
        std::fs::write(temp.path().join("target"), b"x").unwrap();
        std::os::unix::fs::symlink("target", temp.path().join("link")).unwrap();
        let record = RunRecord::default();
        record.note(ExistingFiles::Refuse, &dir, leaf("link"), "link".as_ref());

        assert!(record.created_here(&dir, leaf("link"), "link".as_ref()));
        assert!(!record.created_here(&dir, leaf("target"), "target".as_ref()));
    }

    #[test]
    fn a_ledger_records_whatever_existing_files_says_and_a_duplicate_record_never_skip() {
        let temp = tempfile::tempdir().unwrap();
        let dir = pinned_at(temp.path());
        std::fs::write(temp.path().join("made"), b"x").unwrap();
        std::fs::create_dir(temp.path().join("sub")).unwrap();
        let key = |name: &str| {
            let stat = rustix::fs::stat(temp.path().join(name)).unwrap();
            crate::formats::file_identity::IdentityKey::of_stat(&stat).unwrap()
        };
        let duplicates = RunRecord::default();
        let ledger = RunRecord::new(super::Recording::Ledger);

        for record in [&duplicates, &ledger] {
            record.note(ExistingFiles::Skip, &dir, leaf("made"), "made".as_ref());
            record.note_directory(&dir, leaf("sub"), "sub".as_ref());
        }

        assert!(!duplicates.created_with(key("made")));
        assert!(duplicates.created_with(key("sub")));
        assert!(ledger.created_with(key("made")));
        assert!(ledger.created_with(key("sub")));
    }

    #[test]
    fn a_saturated_ledger_vouches_for_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let dir = pinned_at(temp.path());
        std::fs::write(temp.path().join("made"), b"x").unwrap();
        let stat = rustix::fs::stat(temp.path().join("made")).unwrap();
        let key = crate::formats::file_identity::IdentityKey::of_stat(&stat).unwrap();
        let ledger = RunRecord::new(super::Recording::Ledger);
        ledger.note(ExistingFiles::Skip, &dir, leaf("made"), "made".as_ref());
        assert!(ledger.created_with(key));

        ledger.saturate();

        assert!(!ledger.created_with(key));
    }
}
