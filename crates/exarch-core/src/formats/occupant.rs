//! What extraction does with a path that is already occupied.
//!
//! One decision point for every site that meets an occupant: the policy maps
//! to [`OccupantAction`], and the only way to obtain the permission to replace
//! is [`ExistingFiles::on_occupant`] under
//! [`ExistingFiles::Overwrite`]. A site that destroys an occupant takes a
//! [`ReplacePermit`], so a missed `Refuse` arm cannot reach an overwrite.

use crate::ArchiveError;
use crate::ExistingFiles;
use crate::Result;

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

impl ExistingFiles {
    /// Decides what to do with an occupied path.
    ///
    /// `created_here` is asked only under [`Refuse`](Self::Refuse), where an
    /// occupant the run itself created is a duplicate and is skipped; any other
    /// occupant is refused with the error `refusal` builds. Neither closure
    /// runs under the other policies.
    ///
    /// # Errors
    ///
    /// The error built by `refusal`, under [`Refuse`](Self::Refuse) for an
    /// occupant the run did not create.
    pub(crate) fn on_occupant(
        self,
        created_here: impl FnOnce() -> bool,
        refusal: impl FnOnce() -> ArchiveError,
    ) -> Result<OccupantAction> {
        match self {
            Self::Skip => Ok(OccupantAction::Skip),
            Self::Refuse if created_here() => Ok(OccupantAction::Skip),
            Self::Refuse => Err(refusal()),
            Self::Overwrite => Ok(OccupantAction::Replace(ReplacePermit(()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;
    use std::cell::Cell;

    use super::OccupantAction;
    use super::ReplacePermit;
    use crate::ArchiveError;
    use crate::ExistingFiles;

    fn refusal() -> ArchiveError {
        ArchiveError::Cancelled
    }

    #[test]
    fn skip_and_overwrite_never_consult_the_run_record() {
        let asked = Cell::new(false);
        let created_here = || {
            asked.set(true);
            true
        };

        let skip = ExistingFiles::Skip.on_occupant(created_here, refusal);
        let overwrite = ExistingFiles::Overwrite.on_occupant(created_here, refusal);

        assert_matches!(skip, Ok(OccupantAction::Skip));
        assert_matches!(overwrite, Ok(OccupantAction::Replace(_)));
        assert!(!asked.get());
    }

    #[test]
    fn refuse_skips_a_duplicate_of_the_run_and_refuses_a_foreign_occupant() {
        let duplicate = ExistingFiles::Refuse.on_occupant(|| true, refusal);
        let foreign = ExistingFiles::Refuse.on_occupant(|| false, refusal);

        assert_matches!(duplicate, Ok(OccupantAction::Skip));
        assert_matches!(foreign, Err(ArchiveError::Cancelled));
    }

    #[test]
    fn the_test_permit_is_a_replace_permit() {
        let permit = ReplacePermit::for_test();

        assert_matches!(OccupantAction::Replace(permit), OccupantAction::Replace(_));
    }
}
