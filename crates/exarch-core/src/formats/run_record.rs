//! Which landings the current run created itself.
//!
//! Under [`ExistingFiles::Refuse`] an occupied landing is refused, except when
//! the run made the occupant: a second archive entry for the same path is a
//! duplicate and is skipped, as under [`ExistingFiles::Skip`]. The record tells
//! the two apart. It is kept per run, by the pinned destination, and is filled
//! only under `Refuse`.
//!
//! A landing is keyed by file identity (device and inode of the entry itself,
//! never of a symlink's target), which is exact on a case-insensitive host and
//! needs no path folding. Where the platform gives no identity (Windows) the
//! key is the landing path as the archive spelled it, so a duplicate that
//! differs only in case is refused: the record fails closed.
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

use std::cell::RefCell;
use std::collections::HashSet;
use std::path::Path;

use super::pinned_dir::Leaf;
use super::pinned_dir::VettedDir;
use crate::ExistingFiles;

/// The most landings a run records (4 Mi, 64 MiB of identity keys).
const RECORD_CAP: usize = 4 * 1024 * 1024;

#[cfg(any(unix, target_os = "wasi"))]
type LandingKey = (u64, u64);
#[cfg(not(any(unix, target_os = "wasi")))]
type LandingKey = std::path::PathBuf;

#[cfg(any(unix, target_os = "wasi"))]
fn key_of(dir: &VettedDir, leaf: Leaf<'_>, _rel: &Path) -> Option<LandingKey> {
    dir.identity(leaf).ok().flatten()
}

#[cfg(not(any(unix, target_os = "wasi")))]
fn key_of(_dir: &VettedDir, _leaf: Leaf<'_>, rel: &Path) -> Option<LandingKey> {
    Some(rel.to_path_buf())
}

#[derive(Debug, Default)]
struct Created {
    keys: HashSet<LandingKey>,
    saturated: bool,
}

/// The landings a run created, consulted when one is found occupied.
#[derive(Debug, Default)]
pub struct RunRecord(RefCell<Created>);

impl RunRecord {
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
        match existing_files {
            ExistingFiles::Refuse => {}
            ExistingFiles::Skip | ExistingFiles::Overwrite => return,
        }
        let Some(key) = key_of(dir, leaf, rel) else {
            return;
        };
        let mut created = self.0.borrow_mut();
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
        let created = self.0.borrow();
        !created.saturated && key_of(dir, leaf, rel).is_some_and(|key| created.keys.contains(&key))
    }

    #[cfg(all(test, unix))]
    pub(crate) fn saturate(&self) {
        self.0.borrow_mut().saturated = true;
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
    fn only_refuse_records_and_only_what_it_recorded_counts_as_created() {
        let temp = tempfile::tempdir().unwrap();
        let dir = pinned_at(temp.path());
        std::fs::write(temp.path().join("made"), b"x").unwrap();
        std::fs::write(temp.path().join("foreign"), b"y").unwrap();
        let record = RunRecord::default();

        for ignored in [ExistingFiles::Skip, ExistingFiles::Overwrite] {
            record.note(ignored, &dir, leaf("made"), "made".as_ref());
        }
        assert!(!record.created_here(&dir, leaf("made"), "made".as_ref()));

        record.note(ExistingFiles::Refuse, &dir, leaf("made"), "made".as_ref());
        assert!(record.created_here(&dir, leaf("made"), "made".as_ref()));
        assert!(!record.created_here(&dir, leaf("foreign"), "foreign".as_ref()));
        assert!(!record.created_here(&dir, leaf("absent"), "absent".as_ref()));
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
}
