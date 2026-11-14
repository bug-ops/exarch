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
use crate::OccupiedBy;
use crate::Result;
use crate::Violation;
use crate::security::fs_view::Occupant;
use crate::security::fs_view::normalized_display;
use crate::selection::EntryShape;

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
    /// the error `refusal` builds, which then says whether the run made the
    /// occupant ([`OccupiedBy`]). The caller never retries the create.
    /// `occupant` runs only under `Refuse`, `created_here` after it and only
    /// for an occupant that exists.
    ///
    /// # Errors
    ///
    /// The error built by `refusal`, and the I/O error of `occupant`.
    pub(crate) fn on_occupant(
        self,
        arriving: EntryShape,
        occupant: impl FnOnce() -> std::io::Result<Option<Occupant>>,
        created_here: impl FnOnce() -> bool,
        refusal: impl FnOnce(Option<Occupant>) -> ArchiveError,
    ) -> Result<OccupantAction> {
        match self {
            Self::Skip => Ok(OccupantAction::Skip),
            Self::Refuse => refuse_unless_duplicate(arriving, occupant()?, created_here, refusal)
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
/// confirms the run made it, otherwise the error `refusal` builds, saying who
/// made the occupant ([`OccupiedBy`]).
///
/// `created_here` runs only for an occupant that exists.
///
/// # Errors
///
/// The error built by `refusal`.
pub(crate) fn refuse_unless_duplicate(
    arriving: EntryShape,
    occupant: Option<Occupant>,
    created_here: impl FnOnce() -> bool,
    refusal: impl FnOnce(Option<Occupant>) -> ArchiveError,
) -> Result<RunDuplicate> {
    let by = occupied_by(occupant, created_here);
    match occupant {
        Some(found) if by == OccupiedBy::Archive && is_run_duplicate(arriving, found) => {
            Ok(RunDuplicate(()))
        }
        _ => Err(refusal(occupant).occupied_by(by)),
    }
}

/// The occupants a write does not replace, even under
/// [`ExistingFiles::Overwrite`]: a file is replaced, so it cannot reach
/// [`kept_occupant_refusal`]. The one exception is a 7z extraction on a
/// Windows host, which replaces a symlink like a regular file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeptOccupant {
    /// A directory, which only a directory entry may share.
    Directory,
    /// A symlink, which a file entry does not replace (see the type doc for 7z
    /// on Windows).
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
/// gives [`replaces_symlink`], a directory the [`ArchiveError`] built by
/// `occupied` from the occupant, both with the maker ([`OccupiedBy`])
/// `created_here` decides.
///
/// Shared by the write phase, the in-memory sink and the destination
/// pre-check, so they report one error class for one occupant.
pub(crate) fn kept_occupant_refusal(
    kept: KeptOccupant,
    rel: &Path,
    created_here: impl FnOnce() -> bool,
    occupied: impl FnOnce(Option<Occupant>) -> ArchiveError,
) -> ArchiveError {
    let occupant = kept.occupant();
    let by = occupied_by(Some(occupant), created_here);
    match kept {
        KeptOccupant::Symlink => replaces_symlink(rel, by),
        KeptOccupant::Directory => occupied(Some(occupant)).occupied_by(by),
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
        Occupant::File if arriving_directory => Some(
            crate::formats::common::occupied_without_destination(rel, Some(occupant))
                .occupied_by(by),
        ),
        Occupant::Directory if !arriving_directory => Some(
            crate::formats::common::occupied_without_destination(rel, Some(occupant))
                .occupied_by(by),
        ),
        Occupant::File | Occupant::Symlink | Occupant::Directory => None,
    }
}

/// The refusal of a hardlink entry whose path is occupied under
/// [`ExistingFiles::Overwrite`].
///
/// A hardlink never replaces an occupant. A file gives the typed
/// [`ArchiveError::DestinationOccupied`] built by `occupied`, naming the maker
/// `created_here` decides; a directory or symlink gives the same
/// [`kept_occupant_refusal`] a file or symlink entry gets there. An occupant
/// that vanished since the create failed counts as an existing file. The
/// permit proves the policy was `Overwrite`.
pub(crate) fn refuse_hardlink_replace(
    _permit: ReplacePermit,
    found: Option<Occupant>,
    rel: &Path,
    created_here: impl FnOnce() -> bool,
    occupied: impl FnOnce(Option<Occupant>) -> ArchiveError,
) -> ArchiveError {
    match found.and_then(KeptOccupant::of) {
        Some(kept) => kept_occupant_refusal(kept, rel, created_here, occupied),
        None => occupied(found).occupied_by(occupied_by(found, created_here)),
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;
    use std::cell::Cell;
    use std::path::Path;

    use super::KeptOccupant;
    use super::OccupantAction;
    use super::ReplacePermit;
    use super::is_run_duplicate;
    use super::kept_occupant_refusal;
    use super::refuse_hardlink_replace;
    use crate::ArchiveError;
    use crate::ExistingFiles;
    use crate::OccupiedBy;
    use crate::security::fs_view::LinkKind;
    use crate::security::fs_view::Occupant;
    use crate::selection::EntryShape;

    fn refusal(_found: Option<Occupant>) -> ArchiveError {
        ArchiveError::Cancelled
    }

    const FILE: EntryShape = EntryShape::File;

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

        let skip = ExistingFiles::Skip.on_occupant(FILE, occupant, created_here, refusal);
        let overwrite = ExistingFiles::Overwrite.on_occupant(FILE, occupant, created_here, refusal);

        assert_matches!(skip, Ok(OccupantAction::Skip));
        assert_matches!(overwrite, Ok(OccupantAction::Replace(_)));
        assert!(!asked.get());
    }

    #[test]
    fn refuse_skips_a_duplicate_of_the_run_and_refuses_a_foreign_occupant() {
        let found = || Ok(Some(Occupant::File));

        let duplicate = ExistingFiles::Refuse.on_occupant(FILE, found, || true, refusal);
        let foreign = ExistingFiles::Refuse.on_occupant(FILE, found, || false, refusal);

        assert_matches!(duplicate, Ok(OccupantAction::Skip));
        assert_matches!(foreign, Err(ArchiveError::Cancelled));
    }

    #[test]
    fn refuse_refuses_a_run_directory_whatever_the_record_says() {
        for made_here in [true, false] {
            let outcome = ExistingFiles::Refuse.on_occupant(
                FILE,
                || Ok(Some(Occupant::Directory)),
                || made_here,
                refusal,
            );

            assert_matches!(outcome, Err(ArchiveError::Cancelled));
        }
    }

    #[test]
    fn refuse_refuses_a_vanished_occupant_and_propagates_a_probe_error() {
        let vanished = ExistingFiles::Refuse.on_occupant(FILE, || Ok(None), || true, refusal);
        let failed = ExistingFiles::Refuse.on_occupant(
            FILE,
            || Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            || true,
            refusal,
        );

        assert_matches!(vanished, Err(ArchiveError::Cancelled));
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
        let occupied =
            |found| crate::formats::common::occupied_without_destination(Path::new("x"), found);
        let dir = || Ok(Some(Occupant::Directory));

        let made = ExistingFiles::Refuse.on_occupant(FILE, dir, || true, occupied);
        let foreign = ExistingFiles::Refuse.on_occupant(FILE, dir, || false, occupied);
        let vanished = ExistingFiles::Refuse.on_occupant(FILE, || Ok(None), || true, occupied);

        assert_eq!(by(made), OccupiedBy::Archive);
        assert_eq!(by(foreign), OccupiedBy::Existing);
        assert_eq!(by(vanished), OccupiedBy::Existing);
    }

    #[test]
    fn a_kept_directory_is_a_typed_conflict_and_a_kept_symlink_a_violation() {
        let occupied =
            |found| crate::formats::common::occupied_without_destination(Path::new("d"), found);

        let made =
            kept_occupant_refusal(KeptOccupant::Directory, Path::new("d"), || true, occupied);
        let foreign =
            kept_occupant_refusal(KeptOccupant::Directory, Path::new("d"), || false, occupied);
        let link =
            kept_occupant_refusal(KeptOccupant::Symlink, Path::new("a//l"), || true, occupied);

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
                |found| crate::formats::common::occupied_without_destination(Path::new("h"), found),
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
                if conflicts[0].occupant == Some(Occupant::File)
        );
        assert_matches!(
            refuse(FILE, Occupant::Directory),
            Some(ArchiveError::DestinationOccupied { by: OccupiedBy::Archive, conflicts, .. })
                if conflicts[0].occupant == Some(Occupant::Directory)
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
