//! Which landings the current run created itself.
//!
//! Under [`ExistingFiles::Refuse`] an occupied
//! landing is refused, except when the run made the occupant and it is a file
//! or a symlink: a second archive entry for the same path is a duplicate and is
//! skipped, as under [`ExistingFiles::Skip`]. A
//! directory the run made is never a duplicate, but the record keeps it too, so
//! a refusal can say that the archive itself made the occupant. The record
//! tells an entry the run made from one it did not. It is kept per run, by the
//! pinned destination, and every entry the run creates is recorded whatever
//! `ExistingFiles` says, up to the run's [`RecordBudget`].
//!
//! A staged run's record outlives the extraction, so a rollback can tell what
//! the run made from what it did not make.
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
//! [`RunRecord::maker`] is the tri-state form an opt-in refusal of repeated
//! paths reads: a saturated or lossy record, a failed identity lookup and a
//! path spelling the record does not hold are all [`Maker::Unknown`], never
//! "not made here".
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

/// The most landings a [`RecordBudget::Diagnostic`] run records.
///
/// Under [`ExistingFiles::Skip`] the record is consulted only to attribute a
/// refusal, never to decide a duplicate, so a large archive does not pay for
/// it: attribution is exact for the first 16 Ki landings of a run and
/// `existing` (maker unknown) afterwards.
const DIAGNOSTIC_RECORD_CAP: usize = 16 * 1024;

/// The most bytes of spellings a run remembers as its own (see
/// [`RunRecord::note_spelling`]), counting [`SPELLING_OVERHEAD`] per entry;
/// past it nothing is added and the parent is listed again, which stays
/// correct.
#[cfg(any(windows, test))]
const SPELLING_BYTES: usize = 4 * 1024 * 1024;

/// What one remembered spelling costs besides its path bytes.
#[cfg(any(windows, test))]
const SPELLING_OVERHEAD: usize = 64;

/// The spellings a run remembers, under a byte budget.
#[cfg(any(windows, test))]
#[derive(Debug, Default)]
struct Spellings {
    paths: HashSet<PathBuf>,
    bytes: usize,
}

/// How much a [`RunRecord`] keeps before it saturates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordBudget {
    /// Up to [`RECORD_CAP`] landings.
    Full,
    /// Up to [`DIAGNOSTIC_RECORD_CAP`] landings.
    Diagnostic,
}

impl RecordBudget {
    const fn cap(self) -> usize {
        match self {
            Self::Full => RECORD_CAP,
            Self::Diagnostic => DIAGNOSTIC_RECORD_CAP,
        }
    }
}

impl ExistingFiles {
    /// The budget of the record of an in-place run under this policy.
    pub(crate) const fn record_budget(self) -> RecordBudget {
        match self {
            Self::Skip => RecordBudget::Diagnostic,
            Self::Refuse | Self::Overwrite => RecordBudget::Full,
        }
    }
}

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
        let _restore =
            std::mem::DropGuard::new(BASIS.with(|cell| cell.replace(basis)), |previous| {
                BASIS.with(|cell| cell.set(previous));
            });
        body()
    }
}

/// The key of the occupant of `leaf`, `None` when it is absent or the lookup
/// fails, so the landing is not recorded and a later duplicate is refused.
fn key_of(dir: &VettedDir, leaf: Leaf<'_>, rel: &Path) -> Option<LandingKey> {
    let identity = dir.identity(leaf).ok().flatten()?;
    Some(key_for(identity, rel))
}

/// How much of what the run created the record still holds.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Completeness {
    #[default]
    Complete,
    /// A landing the run created could not be keyed, so the record may be
    /// missing an entry it made.
    Lossy,
    /// The budget was reached; absorbing, nothing more is recorded.
    Saturated,
}

impl Completeness {
    const fn lossy(self) -> Self {
        match self {
            Self::Complete => Self::Lossy,
            other => other,
        }
    }
}

#[derive(Debug, Default)]
struct Created {
    keys: HashSet<LandingKey>,
    completeness: Completeness,
}

/// Who made the occupant of a landing, as far as the record can prove.
///
/// Refusing a repeat is fail-closed: only [`Maker::Run`] is a repeat and only
/// [`Maker::Foreign`] is left to the existing-files policy; everything the
/// record cannot decide is [`Maker::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Maker {
    /// The record holds the occupant's key.
    Run,
    /// The key is readable, the record is complete and does not hold it, or
    /// nothing occupies the landing.
    Foreign,
    /// The record is saturated or lossy, the key cannot be read, or it is a
    /// path spelling the record does not hold.
    Unknown,
}

/// The landings a run created, consulted when one is found occupied.
#[derive(Debug)]
pub(crate) struct RunRecord {
    budget: RecordBudget,
    created: RefCell<Created>,
    /// Paths, exactly as spelled, whose last name is known to be stored as
    /// spelled.
    #[cfg(any(windows, test))]
    spellings: RefCell<Spellings>,
}

impl RunRecord {
    /// An empty record that saturates at `budget`.
    pub(crate) fn new(budget: RecordBudget) -> Self {
        Self {
            budget,
            created: RefCell::default(),
            #[cfg(any(windows, test))]
            spellings: RefCell::default(),
        }
    }

    /// Remembers that the last name of `rel` is stored exactly as spelled: the
    /// run created it under that spelling, or the parent listed it. The match
    /// is on the spelling, not on the entry, so another spelling of the same
    /// entry is never a hit.
    #[cfg(any(windows, test))]
    pub(crate) fn note_spelling(&self, rel: &Path) {
        let mut spellings = self.spellings.borrow_mut();
        let cost = rel.as_os_str().len().saturating_add(SPELLING_OVERHEAD);
        if spellings.bytes.saturating_add(cost) <= SPELLING_BYTES
            && spellings.paths.insert(rel.to_path_buf())
        {
            spellings.bytes = spellings.bytes.saturating_add(cost);
        }
    }

    /// Whether [`note_spelling`](Self::note_spelling) holds exactly `rel`.
    #[cfg(any(windows, test))]
    pub(crate) fn knows_spelling(&self, rel: &Path) -> bool {
        self.spellings.borrow().paths.contains(rel)
    }

    /// Remembers the 8.3-shaped name the run just created as `leaf` at `rel`.
    #[cfg_attr(
        not(windows),
        expect(
            unused_variables,
            clippy::unused_self,
            reason = "only Windows judges short-name spellings"
        )
    )]
    fn note_created_spelling(&self, leaf: Leaf<'_>, rel: &Path) {
        #[cfg(windows)]
        if super::short_name::ShortNameShape::of(leaf.as_os_str()).is_some() {
            self.note_spelling(rel);
        }
    }

    /// Records that the run just created `leaf` in `dir`.
    ///
    /// A key that cannot be read is not recorded, so a later duplicate is
    /// refused.
    ///
    /// A directory is recorded the same way: a duplicate check never skips
    /// one, but a refusal asks whether the run made the occupant.
    pub(crate) fn note(&self, dir: &VettedDir, leaf: Leaf<'_>, rel: &Path) {
        self.note_created_spelling(leaf, rel);
        if !self.is_saturated() {
            self.insert(key_of(dir, leaf, rel));
        }
    }

    /// Like [`note`](Self::note) for the file `leaf` the run just created and
    /// still holds open: keyed by its handle, so no lookup by name unless the
    /// handle gives no identity, which the lookup by name then classifies.
    pub(crate) fn note_file(&self, file: &File, dir: &VettedDir, leaf: Leaf<'_>, rel: &Path) {
        self.note_created_spelling(leaf, rel);
        if self.is_saturated() {
            return;
        }
        match FileIdentity::of_file(file) {
            FileIdentity::Unknown => self.insert(key_of(dir, leaf, rel)),
            known @ FileIdentity::Known(_) => self.insert(Some(key_for(known, rel))),
        }
    }

    fn is_saturated(&self) -> bool {
        self.created.borrow().completeness == Completeness::Saturated
    }

    /// Keeps `key`; reaching the budget saturates the record, so every occupant
    /// counts as foreign (a refusal then says `existing`) and nothing more is
    /// recorded.
    fn insert(&self, key: Option<LandingKey>) {
        let mut created = self.created.borrow_mut();
        let Some(key) = key else {
            created.completeness = created.completeness.lossy();
            return;
        };
        if created.keys.len() >= self.budget.cap() {
            created.completeness = Completeness::Saturated;
        } else {
            created.keys.insert(key);
        }
    }

    /// Whether the occupant of `leaf` in `dir` is a landing this run created.
    ///
    /// `false` when the key cannot be read or the record is saturated.
    pub(crate) fn created_here(&self, dir: &VettedDir, leaf: Leaf<'_>, rel: &Path) -> bool {
        self.maker(dir, leaf, rel) == Maker::Run
    }

    /// Who made the occupant of `leaf` in `dir`.
    ///
    /// The tri-state form of [`created_here`](Self::created_here) that an
    /// opt-in refusal of repeats needs: a record that cannot vouch either way
    /// answers [`Maker::Unknown`] instead of "not made here". `Maker::Run` is
    /// true exactly when `created_here` is.
    pub(crate) fn maker(&self, dir: &VettedDir, leaf: Leaf<'_>, rel: &Path) -> Maker {
        let created = self.created.borrow();
        if created.completeness == Completeness::Saturated {
            return Maker::Unknown;
        }
        // A held key proves the run made the occupant even in a lossy record,
        // so `Run` is exactly `created_here`; lossiness only withdraws
        // "foreign".
        match dir.identity(leaf) {
            Err(_) => Maker::Unknown,
            Ok(None) => Maker::Foreign,
            Ok(Some(identity)) => match key_for(identity, rel) {
                key if created.keys.contains(&key) => Maker::Run,
                _ if created.completeness == Completeness::Lossy => Maker::Unknown,
                LandingKey::Identity(_) => Maker::Foreign,
                LandingKey::Path(_) => Maker::Unknown,
            },
        }
    }

    /// Whether the run created an entry with this identity.
    ///
    /// `false` for a saturated record, and for an entry recorded by path
    /// because its volume gave no identity: neither can vouch for an entry.
    #[cfg(any(target_os = "macos", all(unix, test)))]
    pub(crate) fn created_with(&self, key: IdentityKey) -> bool {
        let created = self.created.borrow();
        created.completeness != Completeness::Saturated
            && created.keys.contains(&LandingKey::Identity(key))
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
        self.created.borrow_mut().completeness = Completeness::Saturated;
    }
}

#[cfg(test)]
mod key_tests {
    use std::assert_matches;

    use super::RecordBudget;

    use super::LandingKey;
    use super::RunRecord;
    use super::key_for;
    use crate::formats::file_identity::FileIdentity;

    #[test]
    fn an_unknown_identity_is_keyed_by_the_path_as_spelled() {
        let record = RunRecord::new(RecordBudget::Full);
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

#[cfg(test)]
mod completeness_tests {
    use super::Completeness;
    use super::RecordBudget;
    use super::RunRecord;

    #[test]
    fn lossy_only_degrades_a_complete_record_and_saturation_absorbs() {
        assert_eq!(Completeness::Complete.lossy(), Completeness::Lossy);
        assert_eq!(Completeness::Lossy.lossy(), Completeness::Lossy);
        assert_eq!(Completeness::Saturated.lossy(), Completeness::Saturated);
    }

    #[test]
    fn an_unkeyed_landing_makes_the_record_lossy_and_never_undoes_saturation() {
        let record = RunRecord::new(RecordBudget::Full);
        assert_eq!(record.created.borrow().completeness, Completeness::Complete);

        record.insert(None);
        assert_eq!(record.created.borrow().completeness, Completeness::Lossy);

        record.created.borrow_mut().completeness = Completeness::Saturated;
        record.insert(None);
        assert_eq!(
            record.created.borrow().completeness,
            Completeness::Saturated
        );
    }
}

#[cfg(all(test, unix))]
#[expect(clippy::unwrap_used, reason = "tests assert by panicking")]
mod tests {
    use super::Maker;
    use super::RecordBudget;
    use super::RunRecord;
    use super::key_basis;
    use crate::formats::pinned_dir::support::leaf;
    use crate::formats::pinned_dir::support::pinned_at;
    use std::path::Path;

    fn made_and_foreign() -> (tempfile::TempDir, crate::formats::pinned_dir::VettedDir) {
        let temp = tempfile::tempdir().unwrap();
        let dir = pinned_at(temp.path());
        std::fs::write(temp.path().join("made"), b"x").unwrap();
        std::fs::write(temp.path().join("foreign"), b"y").unwrap();
        (temp, dir)
    }

    #[test]
    fn maker_tells_the_run_from_a_foreign_occupant_and_an_absent_one() {
        let (_temp, dir) = made_and_foreign();
        let record = RunRecord::new(RecordBudget::Full);
        record.note(&dir, leaf("made"), "made".as_ref());

        assert_eq!(
            record.maker(&dir, leaf("made"), "made".as_ref()),
            Maker::Run
        );
        assert_eq!(
            record.maker(&dir, leaf("foreign"), "foreign".as_ref()),
            Maker::Foreign
        );
        assert_eq!(
            record.maker(&dir, leaf("absent"), "absent".as_ref()),
            Maker::Foreign
        );
    }

    #[test]
    fn a_saturated_record_cannot_vouch_either_way() {
        let (_temp, dir) = made_and_foreign();
        let record = RunRecord::new(RecordBudget::Full);
        record.note(&dir, leaf("made"), "made".as_ref());

        record.saturate();

        for name in ["made", "foreign"] {
            assert_eq!(
                record.maker(&dir, leaf(name), name.as_ref()),
                Maker::Unknown,
                "{name}"
            );
        }
    }

    #[test]
    fn a_record_that_filled_its_budget_saturates_into_unknown() {
        let (_temp, dir) = made_and_foreign();
        let record = RunRecord::new(RecordBudget::Diagnostic);
        let filler = |index: usize| Some(super::LandingKey::Path(format!("p{index}").into()));
        for index in 0..=super::DIAGNOSTIC_RECORD_CAP {
            record.insert(filler(index));
        }

        assert_eq!(
            record.maker(&dir, leaf("foreign"), "foreign".as_ref()),
            Maker::Unknown
        );
    }

    #[test]
    fn a_key_that_could_not_be_read_when_noted_makes_the_record_lossy() {
        let (_temp, dir) = made_and_foreign();
        let record = RunRecord::new(RecordBudget::Full);
        record.note(&dir, leaf("made"), "made".as_ref());

        record.note(&dir, leaf("absent"), "absent".as_ref());

        assert_eq!(
            record.maker(&dir, leaf("made"), "made".as_ref()),
            Maker::Run
        );
        assert_eq!(
            record.maker(&dir, leaf("foreign"), "foreign".as_ref()),
            Maker::Unknown,
            "a lossy record cannot call an unseen occupant foreign"
        );
    }

    #[test]
    fn run_is_exactly_created_here_whatever_the_state_of_the_record() {
        let (_temp, dir) = made_and_foreign();
        let lossy = RunRecord::new(RecordBudget::Full);
        lossy.note(&dir, leaf("made"), "made".as_ref());
        lossy.note(&dir, leaf("absent"), "absent".as_ref());
        let saturated = RunRecord::new(RecordBudget::Full);
        saturated.note(&dir, leaf("made"), "made".as_ref());
        saturated.saturate();
        let too_long = "x".repeat(300);

        for record in [&lossy, &saturated] {
            for name in ["made", "foreign", "absent", too_long.as_str()] {
                assert_eq!(
                    record.maker(&dir, leaf(name), name.as_ref()) == Maker::Run,
                    record.created_here(&dir, leaf(name), name.as_ref()),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn a_failed_identity_lookup_is_unknown_not_foreign() {
        let (_temp, dir) = made_and_foreign();
        let record = RunRecord::new(RecordBudget::Full);
        let too_long = "x".repeat(300);

        assert_eq!(
            record.maker(&dir, leaf(&too_long), too_long.as_ref()),
            Maker::Unknown
        );
    }

    #[test]
    fn a_path_keyed_record_knows_its_spelling_and_nothing_else() {
        let (_temp, dir) = made_and_foreign();
        let record = RunRecord::new(RecordBudget::Full);

        key_basis::with(key_basis::KeyBasis::Path, || {
            record.note(&dir, leaf("made"), "made".as_ref());

            assert_eq!(
                record.maker(&dir, leaf("made"), "made".as_ref()),
                Maker::Run
            );
            assert_eq!(
                record.maker(&dir, leaf("made"), "MADE".as_ref()),
                Maker::Unknown
            );
            assert_eq!(
                record.maker(&dir, leaf("foreign"), "foreign".as_ref()),
                Maker::Unknown
            );
        });
    }

    #[test]
    fn only_what_was_noted_counts_as_created() {
        let temp = tempfile::tempdir().unwrap();
        let dir = pinned_at(temp.path());
        std::fs::write(temp.path().join("made"), b"x").unwrap();
        std::fs::write(temp.path().join("foreign"), b"y").unwrap();
        let record = RunRecord::new(RecordBudget::Full);

        record.note(&dir, leaf("made"), "made".as_ref());

        assert!(record.created_here(&dir, leaf("made"), "made".as_ref()));
        assert!(!record.created_here(&dir, leaf("foreign"), "foreign".as_ref()));
        assert!(!record.created_here(&dir, leaf("absent"), "absent".as_ref()));
    }

    #[test]
    fn a_file_noted_by_its_handle_counts_as_created() {
        let temp = tempfile::tempdir().unwrap();
        let dir = pinned_at(temp.path());
        let made = std::fs::File::create(temp.path().join("made")).unwrap();
        std::fs::write(temp.path().join("foreign"), b"y").unwrap();
        let record = RunRecord::new(RecordBudget::Full);

        record.note_file(&made, &dir, leaf("made"), "made".as_ref());

        assert!(record.created_here(&dir, leaf("made"), "made".as_ref()));
        assert!(!record.created_here(&dir, leaf("foreign"), "foreign".as_ref()));
    }

    #[test]
    fn a_saturated_record_treats_every_occupant_as_foreign() {
        let temp = tempfile::tempdir().unwrap();
        let dir = pinned_at(temp.path());
        std::fs::write(temp.path().join("made"), b"x").unwrap();
        let record = RunRecord::new(RecordBudget::Full);
        record.note(&dir, leaf("made"), "made".as_ref());

        record.saturate();

        assert!(!record.created_here(&dir, leaf("made"), "made".as_ref()));
    }

    #[test]
    fn a_symlink_is_keyed_by_itself_not_by_its_target() {
        let temp = tempfile::tempdir().unwrap();
        let dir = pinned_at(temp.path());
        std::fs::write(temp.path().join("target"), b"x").unwrap();
        std::os::unix::fs::symlink("target", temp.path().join("link")).unwrap();
        let record = RunRecord::new(RecordBudget::Full);
        record.note(&dir, leaf("link"), "link".as_ref());

        assert!(record.created_here(&dir, leaf("link"), "link".as_ref()));
        assert!(!record.created_here(&dir, leaf("target"), "target".as_ref()));
    }

    #[test]
    fn files_and_directories_are_both_recorded_by_identity() {
        let temp = tempfile::tempdir().unwrap();
        let dir = pinned_at(temp.path());
        std::fs::write(temp.path().join("made"), b"x").unwrap();
        std::fs::create_dir(temp.path().join("sub")).unwrap();
        let key = |name: &str| {
            let stat = rustix::fs::stat(temp.path().join(name)).unwrap();
            crate::formats::file_identity::IdentityKey::of_stat(&stat).unwrap()
        };
        let record = RunRecord::new(RecordBudget::Full);

        record.note(&dir, leaf("made"), "made".as_ref());
        record.note(&dir, leaf("sub"), "sub".as_ref());

        assert!(record.created_with(key("made")));
        assert!(record.created_with(key("sub")));
    }

    #[test]
    fn a_saturated_record_vouches_for_no_identity() {
        let temp = tempfile::tempdir().unwrap();
        let dir = pinned_at(temp.path());
        std::fs::write(temp.path().join("made"), b"x").unwrap();
        let stat = rustix::fs::stat(temp.path().join("made")).unwrap();
        let key = crate::formats::file_identity::IdentityKey::of_stat(&stat).unwrap();
        let record = RunRecord::new(RecordBudget::Full);
        record.note(&dir, leaf("made"), "made".as_ref());
        assert!(record.created_with(key));

        record.saturate();

        assert!(!record.created_with(key));
    }

    #[test]
    fn a_diagnostic_record_keeps_exactly_its_cap_and_saturates_on_the_next_landing() {
        let temp = tempfile::tempdir().unwrap();
        let dir = pinned_at(temp.path());
        std::fs::write(temp.path().join("first"), b"x").unwrap();
        let diagnostic = RunRecord::new(RecordBudget::Diagnostic);
        let full = RunRecord::new(RecordBudget::Full);
        diagnostic.note(&dir, leaf("first"), "first".as_ref());
        full.note(&dir, leaf("first"), "first".as_ref());
        let filler = |index: usize| Some(super::LandingKey::Path(format!("p{index}").into()));
        assert_eq!(super::DIAGNOSTIC_RECORD_CAP, 16384);

        for index in 1..super::DIAGNOSTIC_RECORD_CAP {
            diagnostic.insert(filler(index));
        }
        assert!(diagnostic.created_here(&dir, leaf("first"), "first".as_ref()));

        diagnostic.insert(filler(super::DIAGNOSTIC_RECORD_CAP));
        for index in 1..=super::DIAGNOSTIC_RECORD_CAP {
            full.insert(filler(index));
        }

        assert!(!diagnostic.created_here(&dir, leaf("first"), "first".as_ref()));
        assert!(full.created_here(&dir, leaf("first"), "first".as_ref()));
    }

    #[test]
    fn skip_is_diagnostic_and_the_other_policies_are_full() {
        use crate::ExistingFiles;
        assert_eq!(
            ExistingFiles::Skip.record_budget(),
            RecordBudget::Diagnostic
        );
        assert_eq!(ExistingFiles::Refuse.record_budget(), RecordBudget::Full);
        assert_eq!(ExistingFiles::Overwrite.record_budget(), RecordBudget::Full);
    }

    #[test]
    fn a_remembered_spelling_matches_only_that_exact_spelling() {
        let record = RunRecord::new(RecordBudget::Full);
        record.note_spelling(Path::new("d/ABCDEF~1"));

        assert!(record.knows_spelling(Path::new("d/ABCDEF~1")));
        assert!(!record.knows_spelling(Path::new("d/abcdef~1")));
        assert!(!record.knows_spelling(Path::new("d/LONGNA~1")));
        assert!(!record.knows_spelling(Path::new("ABCDEF~1")));
    }

    #[test]
    fn remembered_spellings_do_not_depend_on_the_record_budget() {
        let record = RunRecord::new(RecordBudget::Diagnostic);
        let path = |index: usize| std::path::PathBuf::from(format!("d/X~{index}"));
        let count = super::DIAGNOSTIC_RECORD_CAP + 10;
        for index in 0..count {
            record.note_spelling(&path(index));
        }

        assert!(record.knows_spelling(&path(0)));
        assert!(record.knows_spelling(&path(count - 1)));
    }

    #[test]
    fn remembered_spellings_stay_within_the_byte_budget_whatever_the_key_length() {
        let record = RunRecord::new(RecordBudget::Full);
        let long = "c".repeat(200);
        let path = |index: usize| std::path::PathBuf::from(format!("{long}/{long}/X~{index}"));
        for index in 0..100_000 {
            record.note_spelling(&path(index));
        }

        let spellings = record.spellings.borrow();
        assert!(spellings.bytes <= super::SPELLING_BYTES);
        let stored: usize = spellings
            .paths
            .iter()
            .map(|p| p.as_os_str().len() + super::SPELLING_OVERHEAD)
            .sum();
        assert_eq!(stored, spellings.bytes);
        assert!(
            spellings.paths.len() < 100_000,
            "the budget, not the count, stopped it"
        );
        drop(spellings);
        assert!(record.knows_spelling(&path(0)));
        assert!(
            !record.knows_spelling(&path(99_999)),
            "past the budget the parent is listed again"
        );
    }
}
