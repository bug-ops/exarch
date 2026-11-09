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

use crate::ArchiveError;
use crate::ExistingFiles;
use crate::OccupiedBy;
use crate::Result;
use crate::security::fs_view::Occupant;
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
        refusal: impl FnOnce() -> ArchiveError,
    ) -> Result<OccupantAction> {
        match self {
            Self::Skip => Ok(OccupantAction::Skip),
            Self::Refuse => {
                let found = occupant()?;
                let made_here = found.is_some() && created_here();
                match found {
                    Some(found) if made_here && is_run_duplicate(arriving, found) => {
                        Ok(OccupantAction::Skip)
                    }
                    _ => Err(refusal().occupied_by(if made_here {
                        OccupiedBy::Archive
                    } else {
                        OccupiedBy::Existing
                    })),
                }
            }
            Self::Overwrite => Ok(OccupantAction::Replace(ReplacePermit(()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;
    use std::cell::Cell;
    use std::path::Path;

    use super::OccupantAction;
    use super::is_run_duplicate;
    use crate::ArchiveError;
    use crate::ExistingFiles;
    use crate::OccupiedBy;
    use crate::security::fs_view::LinkKind;
    use crate::security::fs_view::Occupant;
    use crate::selection::EntryShape;

    fn refusal() -> ArchiveError {
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
            || crate::formats::common::destination_occupied(Path::new("d"), Path::new("x"));
        let dir = || Ok(Some(Occupant::Directory));

        let made = ExistingFiles::Refuse.on_occupant(FILE, dir, || true, occupied);
        let foreign = ExistingFiles::Refuse.on_occupant(FILE, dir, || false, occupied);
        let vanished = ExistingFiles::Refuse.on_occupant(FILE, || Ok(None), || true, occupied);

        assert_eq!(by(made), OccupiedBy::Archive);
        assert_eq!(by(foreign), OccupiedBy::Existing);
        assert_eq!(by(vanished), OccupiedBy::Existing);
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
