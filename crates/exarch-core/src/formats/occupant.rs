//! What extraction does with a path that is already occupied.
//!
//! One decision point for every site that meets an occupant: the policy maps
//! to [`OccupantAction`], and the only way to obtain the permission to replace
//! is [`ExistingFiles::on_occupant`] under
//! [`ExistingFiles::Overwrite`]. A site that destroys an occupant takes a
//! [`ReplacePermit`], so a missed `Refuse` arm cannot reach an overwrite.
//!
//! [`is_run_duplicate`] is the one rule for which occupants a run may skip as
//! duplicates under `Refuse`. Extraction on the host, the in-memory sink and
//! the `list` model ([`ArchiveManifest::dispositions`]) all apply it, so they
//! cannot disagree about an archive that names a path twice.
//!
//! [`ArchiveManifest::dispositions`]: crate::ArchiveManifest::dispositions

use std::path::Path;

use crate::ArchiveError;
use crate::ExistingFiles;
use crate::ManifestEntryType;
use crate::OccupiedBy;
use crate::RepeatedPaths;
use crate::Result;
use crate::SinkOptions;
use crate::Violation;
use crate::formats::pinned_dir::PinnedRoot;
use crate::formats::run_record::Maker;
use crate::formats::run_record::RecordBudget;
use crate::security::fs_view::LinkKind;
use crate::security::fs_view::Occupant;
use crate::security::fs_view::normalized_display;
use crate::selection::EntryShape;

/// The two policies that decide an occupied landing, taken together.
///
/// The run record must outlive the existing-files policy alone: refusing a
/// repeat needs to know what the run made, so an opt-in
/// [`RepeatedPaths::Refuse`] keeps the full record under every
/// [`ExistingFiles`] mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OccupantPolicy {
    existing: ExistingFiles,
    repeats: RepeatedPaths,
}

impl OccupantPolicy {
    /// The policy of a check made before any entry of a run exists.
    pub(crate) const PRE_EXISTING: Self = Self::new(ExistingFiles::Skip, RepeatedPaths::KeepFirst);

    /// The product of `existing` and `repeats`.
    pub(crate) const fn new(existing: ExistingFiles, repeats: RepeatedPaths) -> Self {
        Self { existing, repeats }
    }

    /// The policies of a run that carries `options`.
    pub(crate) const fn of(options: SinkOptions) -> Self {
        Self::new(options.existing_files, options.repeats)
    }

    /// The repeated-paths policy of this product.
    pub(crate) const fn repeats(self) -> RepeatedPaths {
        self.repeats
    }

    /// The budget of the record of an in-place run under this policy.
    pub(crate) const fn record_budget(self) -> RecordBudget {
        match self.repeats {
            RepeatedPaths::Refuse => RecordBudget::Full,
            RepeatedPaths::KeepFirst => self.existing.record_budget(),
        }
    }

    /// Decides an occupied path: the repeat rule first, then the
    /// [`ExistingFiles`] policy for what it leaves.
    ///
    /// # Errors
    ///
    /// The refusals of [`RepeatedPaths::refuse_repeat`] and
    /// [`ExistingFiles::on_occupant`], and the I/O error of `occupant`.
    pub(crate) fn on_occupant(
        self,
        arriving: EntryShape,
        rel: &Path,
        occupant: impl FnOnce() -> std::io::Result<Option<Occupant>>,
        maker: impl FnOnce() -> Maker,
        site: OccupiedSite<'_>,
    ) -> Result<OccupantAction> {
        if self.repeats == RepeatedPaths::KeepFirst {
            return self.existing.on_occupant(
                arriving,
                rel,
                occupant,
                || maker() == Maker::Run,
                site,
            );
        }
        let found = occupant()?;
        if let Some(found) = found {
            self.repeats
                .refuse_repeat(arriving, rel, found, maker, site)?;
        }
        // The maker was foreign or the occupant is gone, never the run.
        self.existing
            .on_occupant(arriving, rel, || Ok(found), || false, site)
    }
}

impl RepeatedPaths {
    /// Refuses an entry `arriving` over the occupant `found` of `rel` when
    /// repeated paths are refused and the run made it or cannot show that it
    /// did not; any other occupant, and every occupant under
    /// [`RepeatedPaths::KeepFirst`], is left to the caller.
    ///
    /// A directory entry over a directory is no repeat. `maker` runs only
    /// under [`RepeatedPaths::Refuse`].
    ///
    /// # Errors
    ///
    /// [`Violation::RepeatedPath`] for an occupant the run made, and the
    /// refusal of `site` that names an existing occupant when the maker is
    /// unknown, under every [`ExistingFiles`] mode.
    pub(crate) fn refuse_repeat(
        self,
        arriving: EntryShape,
        rel: &Path,
        found: Occupant,
        maker: impl FnOnce() -> Maker,
        site: OccupiedSite<'_>,
    ) -> Result<()> {
        if self == Self::KeepFirst {
            return Ok(());
        }
        match maker() {
            Maker::Run if arriving == EntryShape::Directory && found == Occupant::Directory => {
                Ok(())
            }
            Maker::Run => Err(repeated_path(rel, found, arriving)),
            Maker::Unknown => Err(site.refuse(rel, Some(found), OccupiedBy::Existing)),
            Maker::Foreign => Ok(()),
        }
    }
}

/// The kind of manifest entry an occupant of the destination was made as.
const fn occupant_type(occupant: Occupant) -> ManifestEntryType {
    match occupant {
        Occupant::File => ManifestEntryType::File,
        Occupant::Directory => ManifestEntryType::Directory,
        Occupant::Symlink => ManifestEntryType::Symlink,
    }
}

/// The kind of manifest entry an arriving entry is.
pub(crate) const fn shape_type(shape: EntryShape) -> ManifestEntryType {
    match shape {
        EntryShape::Directory => ManifestEntryType::Directory,
        EntryShape::File => ManifestEntryType::File,
        EntryShape::Link(LinkKind::Symlink) => ManifestEntryType::Symlink,
        EntryShape::Link(LinkKind::Hardlink) => ManifestEntryType::Hardlink,
    }
}

/// The refusal of the entry `later` at `rel`, which an earlier entry of the
/// run, held by `earlier`, already made.
///
/// Shared by extraction, the in-memory sink, `list` and `verify`.
pub(crate) fn repeated_path(rel: &Path, earlier: Occupant, later: EntryShape) -> ArchiveError {
    repeated_path_between(rel, occupant_type(earlier), shape_type(later))
}

/// The one constructor of [`Violation::RepeatedPath`], for callers that know
/// the kinds of both copies already.
pub(crate) fn repeated_path_between(
    rel: &Path,
    earlier: ManifestEntryType,
    later: ManifestEntryType,
) -> ArchiveError {
    Violation::RepeatedPath {
        path: normalized_display(rel).into(),
        earlier,
        later,
    }
    .into()
}

/// Where an occupied-path refusal is raised: on a host destination, which the
/// refusal names, or with none (the in-memory sink and the `list` model).
///
/// The site is data, so the refusal is always a
/// [`ArchiveError::DestinationOccupied`] and always carries the maker the
/// caller decided.
#[derive(Debug, Clone, Copy)]
pub(crate) enum OccupiedSite<'a> {
    /// A run on the host destination of this root.
    Host(&'a PinnedRoot),
    /// A run with no host destination.
    Detached,
}

impl OccupiedSite<'_> {
    /// The refusal of the path `rel`, which holds `occupant` made by `by`.
    ///
    /// The one constructor of [`ArchiveError::DestinationOccupied`]; every
    /// site that decides what to do with an occupant must route `Refuse` here
    /// and never into an overwrite branch, since a missed arm would replace a
    /// file the caller asked to keep.
    pub(crate) fn refuse(
        self,
        rel: &Path,
        occupant: Option<Occupant>,
        by: OccupiedBy,
    ) -> ArchiveError {
        ArchiveError::DestinationOccupied {
            destination: match self {
                Self::Host(root) => Some(root.destination().to_path_buf()),
                Self::Detached => None,
            },
            conflicts: crate::OccupiedPaths::one(crate::OccupiedPath::at(rel, occupant)),
            by,
        }
    }
}

/// Proof that the overwrite policy allows destroying an occupant.
///
/// Neither `Clone` nor `Copy`, and constructible only by
/// [`ExistingFiles::on_occupant`], so each replacement consumes its own
/// decision.
#[derive(Debug)]
pub(crate) struct ReplacePermit(());

impl ReplacePermit {
    #[cfg(test)]
    pub(crate) const fn for_test() -> Self {
        Self(())
    }
}

/// What to do with an occupied path.
#[derive(Debug)]
pub(crate) enum OccupantAction {
    /// Leave the occupant in place and count a skip.
    Skip,
    /// Replace the occupant; the permit proves the policy allows it.
    Replace(ReplacePermit),
}

/// Whether `arriving`, finding `occupant` at its path, is a duplicate of an
/// earlier entry that a run under [`ExistingFiles::Refuse`] skips.
///
/// Only a file or a link over a file or a symlink: those are the entries a
/// repeated name replaces. A directory occupant is never a duplicate of a
/// non-directory, whoever created it, so the run refuses instead of hiding a
/// member behind a directory.
pub(crate) const fn is_run_duplicate(arriving: EntryShape, occupant: Occupant) -> bool {
    matches!(
        (arriving, occupant),
        (
            EntryShape::File | EntryShape::Link(_),
            Occupant::File | Occupant::Symlink
        )
    )
}

impl ExistingFiles {
    /// Decides what to do with an occupied path.
    ///
    /// Under [`Refuse`](Self::Refuse) the occupant is skipped only when
    /// `occupant` finds one that [`is_run_duplicate`] of `arriving` and
    /// `created_here` confirms the run made it; any other outcome, including
    /// an occupant that has vanished since the create failed, is refused with
    /// the refusal of `rel` at `site`, which then says whether the run made the
    /// occupant ([`OccupiedBy`]). The caller never retries the create.
    /// `occupant` runs only under `Refuse`, `created_here` after it and only
    /// for an occupant that exists.
    ///
    /// # Errors
    ///
    /// The refusal of `site`, and the I/O error of `occupant`.
    fn on_occupant(
        self,
        arriving: EntryShape,
        rel: &Path,
        occupant: impl FnOnce() -> std::io::Result<Option<Occupant>>,
        created_here: impl FnOnce() -> bool,
        site: OccupiedSite<'_>,
    ) -> Result<OccupantAction> {
        match self {
            Self::Skip => Ok(OccupantAction::Skip),
            Self::Refuse => refuse_unless_duplicate(arriving, rel, occupant()?, created_here, site)
                .map(|RunDuplicate(())| OccupantAction::Skip),
            Self::Overwrite => Ok(OccupantAction::Replace(ReplacePermit(()))),
        }
    }
}

/// Proof that an occupant is a repeat of an entry the run made, which a run
/// under [`ExistingFiles::Refuse`] skips.
#[derive(Debug)]
pub(crate) struct RunDuplicate(());

/// Who made the entry that `found` reports at a path: the run itself when
/// `created_here` confirms it, otherwise an entry that was there before, or
/// whose maker is unknown.
///
/// The one rule for [`OccupiedBy`]; `created_here` runs only for an occupant
/// that exists.
pub(crate) fn occupied_by(
    found: Option<Occupant>,
    created_here: impl FnOnce() -> bool,
) -> OccupiedBy {
    if found.is_some() && created_here() {
        OccupiedBy::Archive
    } else {
        OccupiedBy::Existing
    }
}

/// The `Refuse` rule for one occupied path: a [`RunDuplicate`] when
/// `occupant` is one that [`is_run_duplicate`] of `arriving` and `created_here`
/// confirms the run made it, otherwise the refusal of `rel` at `site`, saying
/// who made the occupant ([`OccupiedBy`]).
///
/// `created_here` runs only for an occupant that exists.
///
/// # Errors
///
/// The refusal of `site`.
pub(crate) fn refuse_unless_duplicate(
    arriving: EntryShape,
    rel: &Path,
    occupant: Option<Occupant>,
    created_here: impl FnOnce() -> bool,
    site: OccupiedSite<'_>,
) -> Result<RunDuplicate> {
    let by = occupied_by(occupant, created_here);
    match occupant {
        Some(found) if by == OccupiedBy::Archive && is_run_duplicate(arriving, found) => {
            Ok(RunDuplicate(()))
        }
        _ => Err(site.refuse(rel, occupant, by)),
    }
}

/// The occupants a write does not replace, even under
/// [`ExistingFiles::Overwrite`]: a file is replaced, so it cannot reach
/// [`kept_occupant_refusal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeptOccupant {
    /// A directory, which only a directory entry may share.
    Directory,
    /// A symlink, which a file entry does not replace.
    Symlink,
}

impl KeptOccupant {
    /// The occupant this kept occupant is.
    pub(crate) const fn occupant(self) -> Occupant {
        match self {
            Self::Directory => Occupant::Directory,
            Self::Symlink => Occupant::Symlink,
        }
    }

    /// The kept occupant `occupant` is, or `None` for a file.
    pub(crate) const fn of(occupant: Occupant) -> Option<Self> {
        match occupant {
            Occupant::Directory => Some(Self::Directory),
            Occupant::Symlink => Some(Self::Symlink),
            Occupant::File => None,
        }
    }
}

/// The security refusal of a path that holds a symlink no write replaces,
/// naming the entry `rel` and who made the symlink.
///
/// The one constructor of [`Violation::ReplacesSymlink`] for an occupant, so
/// the write phase, the in-memory sink and the destination pre-check read
/// alike.
pub(crate) fn replaces_symlink(rel: &Path, by: OccupiedBy) -> ArchiveError {
    Violation::ReplacesSymlink {
        rel: normalized_display(rel).into(),
        by,
    }
    .into()
}

/// The typed refusal of a path whose occupant no write replaces: a symlink
/// gives [`replaces_symlink`], a directory the refusal of `site`, both with
/// the maker ([`OccupiedBy`]) `created_here` decides.
///
/// Shared by the write phase, the in-memory sink and the destination
/// pre-check, so they report one error class for one occupant.
pub(crate) fn kept_occupant_refusal(
    kept: KeptOccupant,
    rel: &Path,
    created_here: impl FnOnce() -> bool,
    site: OccupiedSite<'_>,
) -> ArchiveError {
    let occupant = kept.occupant();
    let by = occupied_by(Some(occupant), created_here);
    match kept {
        KeptOccupant::Symlink => replaces_symlink(rel, by),
        KeptOccupant::Directory => site.refuse(rel, Some(occupant), by),
    }
}

/// The refusal of an entry `arriving` over an occupant of the in-memory tree,
/// which holds only what the run itself delivered, or `None` when the
/// conflict is of another kind.
///
/// Shared by the sink and the `list` model so a directory over a file or a
/// symlink, and a non-directory over a directory, read alike on both. Always
/// made by the archive ([`OccupiedBy::Archive`]) and without a destination.
pub(crate) fn tree_occupant_refusal(
    arriving: EntryShape,
    occupant: Occupant,
    rel: &Path,
) -> Option<ArchiveError> {
    let by = OccupiedBy::Archive;
    let arriving_directory = arriving == EntryShape::Directory;
    match occupant {
        Occupant::Symlink if arriving_directory => Some(replaces_symlink(rel, by)),
        Occupant::File if arriving_directory => {
            Some(OccupiedSite::Detached.refuse(rel, Some(occupant), by))
        }
        Occupant::Directory if !arriving_directory => {
            Some(OccupiedSite::Detached.refuse(rel, Some(occupant), by))
        }
        Occupant::File | Occupant::Symlink | Occupant::Directory => None,
    }
}

/// The refusal of a hardlink entry whose path is occupied under
/// [`ExistingFiles::Overwrite`].
///
/// A hardlink never replaces an occupant. A file gives the typed
/// [`ArchiveError::DestinationOccupied`] of `site`, naming the maker
/// `created_here` decides; a directory or symlink gives the same
/// [`kept_occupant_refusal`] a file or symlink entry gets there. An occupant
/// that vanished since the create failed counts as an existing file. The
/// permit proves the policy was `Overwrite`.
pub(crate) fn refuse_hardlink_replace(
    _permit: ReplacePermit,
    found: Option<Occupant>,
    rel: &Path,
    created_here: impl FnOnce() -> bool,
    site: OccupiedSite<'_>,
) -> ArchiveError {
    match found.and_then(KeptOccupant::of) {
        Some(kept) => kept_occupant_refusal(kept, rel, created_here, site),
        None => site.refuse(rel, found, occupied_by(found, created_here)),
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;
    use std::cell::Cell;
    use std::path::Path;

    use super::KeptOccupant;
    use super::OccupantAction;
    use super::OccupantPolicy;
    use super::ReplacePermit;
    use super::is_run_duplicate;
    use super::kept_occupant_refusal;
    use super::refuse_hardlink_replace;
    use crate::ArchiveError;
    use crate::ExistingFiles;
    use crate::OccupiedBy;
    use crate::RepeatedPaths;
    use crate::formats::run_record::RecordBudget;
    use crate::security::fs_view::LinkKind;
    use crate::security::fs_view::Occupant;
    use crate::selection::EntryShape;

    #[test]
    fn refuse_repeats_keep_the_full_record_under_every_existing_files_mode() {
        for existing in [
            ExistingFiles::Skip,
            ExistingFiles::Refuse,
            ExistingFiles::Overwrite,
        ] {
            assert_eq!(
                OccupantPolicy::new(existing, RepeatedPaths::Refuse).record_budget(),
                RecordBudget::Full,
                "{existing:?}"
            );
            assert_eq!(
                OccupantPolicy::new(existing, RepeatedPaths::KeepFirst).record_budget(),
                existing.record_budget(),
                "{existing:?}"
            );
        }
    }

    use super::OccupiedSite;
    use crate::Violation;
    use crate::formats::run_record::Maker;

    const MODES: [ExistingFiles; 3] = [
        ExistingFiles::Skip,
        ExistingFiles::Refuse,
        ExistingFiles::Overwrite,
    ];

    fn decide(
        existing: ExistingFiles,
        repeats: RepeatedPaths,
        arriving: EntryShape,
        found: Occupant,
        maker: Maker,
    ) -> Result<OccupantAction, ArchiveError> {
        OccupantPolicy::new(existing, repeats).on_occupant(
            arriving,
            Path::new("x"),
            || Ok(Some(found)),
            || maker,
            OccupiedSite::Detached,
        )
    }

    #[test]
    fn refused_repeats_refuse_an_occupant_of_the_run_under_every_mode() {
        for existing in MODES {
            for found in [Occupant::File, Occupant::Symlink, Occupant::Directory] {
                let outcome = decide(existing, RepeatedPaths::Refuse, FILE, found, Maker::Run);

                assert_matches!(
                    outcome,
                    Err(ArchiveError::SecurityViolation {
                        kind: Violation::RepeatedPath { .. },
                        ..
                    }),
                    "{existing:?} {found:?}"
                );
            }
        }
    }

    #[test]
    fn refused_repeats_fail_closed_when_the_maker_is_unknown_under_every_mode() {
        for existing in MODES {
            let outcome = decide(
                existing,
                RepeatedPaths::Refuse,
                FILE,
                Occupant::File,
                Maker::Unknown,
            );

            assert_matches!(
                outcome,
                Err(ArchiveError::DestinationOccupied {
                    by: OccupiedBy::Existing,
                    ..
                }),
                "{existing:?}"
            );
        }
    }

    #[test]
    fn refused_repeats_leave_a_foreign_occupant_to_the_existing_files_policy() {
        let foreign = |existing| {
            decide(
                existing,
                RepeatedPaths::Refuse,
                FILE,
                Occupant::File,
                Maker::Foreign,
            )
        };

        assert_matches!(foreign(ExistingFiles::Skip), Ok(OccupantAction::Skip));
        assert_matches!(
            foreign(ExistingFiles::Overwrite),
            Ok(OccupantAction::Replace(_))
        );
        assert_matches!(
            foreign(ExistingFiles::Refuse),
            Err(ArchiveError::DestinationOccupied {
                by: OccupiedBy::Existing,
                ..
            })
        );
    }

    #[test]
    fn a_directory_over_a_directory_of_the_run_is_no_repeat() {
        let policy = OccupantPolicy::new(ExistingFiles::Skip, RepeatedPaths::Refuse);
        let check = |arriving, found| {
            policy
                .repeats()
                .refuse_repeat(arriving, x(), found, || Maker::Run, DETACHED)
        };

        assert!(check(EntryShape::Directory, Occupant::Directory).is_ok());
        assert!(check(EntryShape::Directory, Occupant::File).is_err());
        assert!(check(EntryShape::Directory, Occupant::Symlink).is_err());
        assert!(check(FILE, Occupant::Directory).is_err());
    }

    #[test]
    fn kept_repeats_ignore_the_maker_and_decide_as_existing_files_does() {
        for existing in MODES {
            for maker in [Maker::Run, Maker::Foreign, Maker::Unknown] {
                let kept = decide(
                    existing,
                    RepeatedPaths::KeepFirst,
                    FILE,
                    Occupant::File,
                    maker,
                );
                let direct = existing.on_occupant(
                    FILE,
                    x(),
                    || Ok(Some(Occupant::File)),
                    || maker == Maker::Run,
                    DETACHED,
                );

                assert_eq!(
                    std::mem::discriminant(&kept.map_err(|e| e.to_string())),
                    std::mem::discriminant(&direct.map_err(|e| e.to_string())),
                    "{existing:?} {maker:?}"
                );
            }
        }
    }

    #[test]
    fn refused_repeats_name_both_kinds_and_the_path() {
        let outcome = decide(
            ExistingFiles::Skip,
            RepeatedPaths::Refuse,
            EntryShape::Link(LinkKind::Hardlink),
            Occupant::Symlink,
            Maker::Run,
        );

        assert_matches!(
            outcome,
            Err(ArchiveError::SecurityViolation {
                kind: Violation::RepeatedPath { path, earlier, later },
                ..
            }) if &*path == "x"
                && earlier == crate::ManifestEntryType::Symlink
                && later == crate::ManifestEntryType::Hardlink
        );
    }

    const FILE: EntryShape = EntryShape::File;
    const DETACHED: OccupiedSite<'static> = OccupiedSite::Detached;

    fn x() -> &'static Path {
        Path::new("x")
    }

    #[test]
    fn skip_and_overwrite_never_consult_the_occupant_or_the_run_record() {
        let asked = Cell::new(false);
        let occupant = || {
            asked.set(true);
            Ok(Some(Occupant::File))
        };
        let created_here = || {
            asked.set(true);
            true
        };

        let skip = ExistingFiles::Skip.on_occupant(FILE, x(), occupant, created_here, DETACHED);
        let overwrite =
            ExistingFiles::Overwrite.on_occupant(FILE, x(), occupant, created_here, DETACHED);

        assert_matches!(skip, Ok(OccupantAction::Skip));
        assert_matches!(overwrite, Ok(OccupantAction::Replace(_)));
        assert!(!asked.get());
    }

    #[test]
    fn refuse_skips_a_duplicate_of_the_run_and_refuses_a_foreign_occupant() {
        let found = || Ok(Some(Occupant::File));

        let duplicate = ExistingFiles::Refuse.on_occupant(FILE, x(), found, || true, DETACHED);
        let foreign = ExistingFiles::Refuse.on_occupant(FILE, x(), found, || false, DETACHED);

        assert_matches!(duplicate, Ok(OccupantAction::Skip));
        assert_matches!(foreign, Err(ArchiveError::DestinationOccupied { .. }));
    }

    #[test]
    fn refuse_refuses_a_run_directory_whatever_the_record_says() {
        for made_here in [true, false] {
            let outcome = ExistingFiles::Refuse.on_occupant(
                FILE,
                x(),
                || Ok(Some(Occupant::Directory)),
                || made_here,
                DETACHED,
            );

            assert_matches!(outcome, Err(ArchiveError::DestinationOccupied { .. }));
        }
    }

    #[test]
    fn refuse_refuses_a_vanished_occupant_and_propagates_a_probe_error() {
        let vanished = ExistingFiles::Refuse.on_occupant(FILE, x(), || Ok(None), || true, DETACHED);
        let failed = ExistingFiles::Refuse.on_occupant(
            FILE,
            x(),
            || Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            || true,
            DETACHED,
        );

        assert_matches!(vanished, Err(ArchiveError::DestinationOccupied { .. }));
        assert_matches!(failed, Err(ArchiveError::Io(_)));
    }

    #[test]
    fn a_refusal_says_whether_the_run_made_the_occupant() {
        let by = |outcome: Result<OccupantAction, ArchiveError>| {
            let Err(ArchiveError::DestinationOccupied { by, .. }) = outcome else {
                panic!("expected a refusal: {outcome:?}");
            };
            by
        };
        let dir = || Ok(Some(Occupant::Directory));

        let made = ExistingFiles::Refuse.on_occupant(FILE, x(), dir, || true, DETACHED);
        let foreign = ExistingFiles::Refuse.on_occupant(FILE, x(), dir, || false, DETACHED);
        let vanished = ExistingFiles::Refuse.on_occupant(FILE, x(), || Ok(None), || true, DETACHED);

        assert_eq!(by(made), OccupiedBy::Archive);
        assert_eq!(by(foreign), OccupiedBy::Existing);
        assert_eq!(by(vanished), OccupiedBy::Existing);
    }

    #[test]
    fn a_kept_directory_is_a_typed_conflict_and_a_kept_symlink_a_violation() {
        let made =
            kept_occupant_refusal(KeptOccupant::Directory, Path::new("d"), || true, DETACHED);
        let foreign =
            kept_occupant_refusal(KeptOccupant::Directory, Path::new("d"), || false, DETACHED);
        let link =
            kept_occupant_refusal(KeptOccupant::Symlink, Path::new("a//l"), || true, DETACHED);

        assert_matches!(
            made,
            ArchiveError::DestinationOccupied {
                by: OccupiedBy::Archive,
                ..
            }
        );
        assert_matches!(
            foreign,
            ArchiveError::DestinationOccupied {
                by: OccupiedBy::Existing,
                ..
            }
        );
        assert_matches!(
            link,
            ArchiveError::SecurityViolation {
                kind: crate::Violation::ReplacesSymlink { rel, .. },
                ..
            } if &*rel == "a/l"
        );
    }

    #[test]
    fn a_hardlink_over_a_kept_occupant_gets_the_kept_refusal() {
        let refusal = |found| {
            refuse_hardlink_replace(
                ReplacePermit::for_test(),
                found,
                Path::new("h"),
                || true,
                DETACHED,
            )
        };

        assert_matches!(
            refusal(Some(Occupant::Directory)),
            ArchiveError::DestinationOccupied {
                by: OccupiedBy::Archive,
                ..
            }
        );
        assert_matches!(
            refusal(Some(Occupant::Symlink)),
            ArchiveError::SecurityViolation { .. }
        );
        assert_matches!(
            refusal(Some(Occupant::File)),
            ArchiveError::DestinationOccupied {
                by: OccupiedBy::Archive,
                ..
            }
        );
        assert_matches!(
            refusal(None),
            ArchiveError::DestinationOccupied {
                by: OccupiedBy::Existing,
                ..
            }
        );
    }

    #[test]
    fn the_tree_refuses_a_directory_over_a_file_or_symlink_and_a_file_over_a_directory() {
        use super::tree_occupant_refusal;

        let refuse = |arriving, occupant| tree_occupant_refusal(arriving, occupant, Path::new("p"));

        assert_matches!(
            refuse(EntryShape::Directory, Occupant::File),
            Some(ArchiveError::DestinationOccupied { by: OccupiedBy::Archive, conflicts, .. })
                if conflicts.iter().map(|c| c.occupant).eq([Some(Occupant::File)])
        );
        assert_matches!(
            refuse(FILE, Occupant::Directory),
            Some(ArchiveError::DestinationOccupied { by: OccupiedBy::Archive, conflicts, .. })
                if conflicts.iter().map(|c| c.occupant).eq([Some(Occupant::Directory)])
        );
        assert_matches!(
            refuse(EntryShape::Directory, Occupant::Symlink),
            Some(ArchiveError::SecurityViolation {
                kind: crate::Violation::ReplacesSymlink {
                    by: OccupiedBy::Archive,
                    ..
                }
            })
        );
        assert_matches!(refuse(EntryShape::Directory, Occupant::Directory), None);
        assert_matches!(refuse(FILE, Occupant::File), None);
    }

    #[test]
    fn only_a_file_or_link_over_a_file_or_symlink_is_a_duplicate() {
        let shapes = [
            (EntryShape::Directory, false, false),
            (EntryShape::File, true, true),
            (EntryShape::Link(LinkKind::Symlink), true, true),
            (EntryShape::Link(LinkKind::Hardlink), true, true),
        ];
        for (shape, over_file, over_symlink) in shapes {
            assert_eq!(
                is_run_duplicate(shape, Occupant::File),
                over_file,
                "{shape:?}"
            );
            assert_eq!(
                is_run_duplicate(shape, Occupant::Symlink),
                over_symlink,
                "{shape:?}"
            );
            assert!(!is_run_duplicate(shape, Occupant::Directory), "{shape:?}");
        }
    }
}
