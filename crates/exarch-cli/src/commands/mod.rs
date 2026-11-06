//! Command implementations.

pub mod completion;
pub mod create;
pub mod extract;
pub mod list;
pub mod verify;

/// How a command that ran to completion ended.
///
/// A successful run that nevertheless has a non-zero status is an outcome,
/// not an error: the exit status is chosen by one exhaustive match in `main`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing to report beyond the command's own output.
    Ok,
    /// The verification report has `Fail` status.
    VerifyFailed,
    /// `verify --strict` found a warning.
    StrictWarning,
}

/// Why a command failed.
///
/// A core failure is kept apart from the CLI's own errors so `main` can give
/// it the archive name and the hints of the operation exactly once; an
/// `anyhow` error already carries the context its producer chose.
#[derive(Debug)]
pub enum CommandError {
    /// An error returned by `exarch-core`, not yet given CLI context.
    Core(ArchiveError),
    /// An error the CLI built or already contextualized.
    Other(anyhow::Error),
}

impl From<ArchiveError> for CommandError {
    fn from(err: ArchiveError) -> Self {
        Self::Core(err)
    }
}

impl From<anyhow::Error> for CommandError {
    fn from(err: anyhow::Error) -> Self {
        Self::Other(err)
    }
}

impl CommandError {
    /// The error `main` reports for `operation` on `archive`.
    pub fn contextualize(self, operation: Operation, archive: &Path) -> anyhow::Error {
        match self {
            Self::Core(err) => convert_error(operation, err, archive),
            Self::Other(err) => err,
        }
    }
}

/// What a command returns.
pub type CommandResult = Result<Outcome, CommandError>;

use crate::error::convert_error;
use crate::operation::Operation;
use exarch_core::ArchiveError;
use std::path::Path;
