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

use crate::cli::PolicyFlags;
use crate::error::convert_error;
use crate::operation::Operation;
use exarch_core::ArchiveError;
use exarch_core::ConfigSetting;
use exarch_core::SecurityConfig;
use exarch_core::non_zero_usize;
use std::path::Path;

/// The configuration `flags` describe on top of `base`: limits, link policy,
/// ZIP policy, decode lookahead and the path-depth limit, then the selection,
/// which core checks against that depth.
///
/// # Errors
///
/// `InvalidConfiguration` naming the setting of the flag core refuses.
pub fn security_config(
    flags: &impl PolicyFlags,
    base: SecurityConfig,
) -> Result<SecurityConfig, ArchiveError> {
    let mut config = flags.limits().apply(base)?;
    if let Some(links) = flags.links() {
        config = links.apply(config);
    }
    config = flags.zip().apply(config);
    if let Some(parallel) = flags.parallel() {
        config = parallel.apply(config)?;
    }
    if let Some(depth) = flags.max_path_depth() {
        config = config.with_max_path_depth(non_zero_usize(ConfigSetting::MaxPathDepth, depth)?);
    }
    flags.selection().apply(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use crate::cli::Commands;
    use clap::Parser as _;

    fn extract_flags(extra: &[&str]) -> crate::cli::ExtractArgs {
        let words = ["exarch", "extract", "a.tar"]
            .into_iter()
            .chain(extra.iter().copied());
        let Commands::Extract(args) = Cli::parse_from(words).command else {
            panic!("expected extract command");
        };
        args
    }

    #[test]
    fn the_selection_is_checked_against_the_path_depth_flag() {
        let over_depth = security_config(
            &extract_flags(&["--strip-components", "5", "--max-path-depth", "3"]),
            SecurityConfig::default(),
        );
        assert!(
            over_depth.is_err(),
            "strip above the depth limit is refused"
        );
        let within_depth = security_config(
            &extract_flags(&["--strip-components", "5", "--max-path-depth", "9"]),
            SecurityConfig::default(),
        );
        assert!(within_depth.is_ok(), "{within_depth:?}");
    }
}
