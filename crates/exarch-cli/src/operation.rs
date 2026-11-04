//! The CLI's operations and the long flags each one accepts.
//!
//! Hints name flags, and a flag only exists on some subcommands. Keeping both
//! as closed enums lets a test walk the real clap command and fail when a hint
//! points at an option the subcommand does not have.

use serde::Serialize;

/// A command that runs against an archive and can fail with an archive error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Extract,
    Create,
    List,
    Verify,
}

impl Operation {
    #[cfg(test)]
    pub const ALL: [Self; 4] = [Self::Extract, Self::Create, Self::List, Self::Verify];

    /// The subcommand name, as typed on the command line.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Extract => "extract",
            Self::Create => "create",
            Self::List => "list",
            Self::Verify => "verify",
        }
    }

    /// Whether this operation's subcommand declares `flag`.
    ///
    /// Checked against the clap definition by
    /// `every_flag_matches_its_subcommand`.
    pub const fn accepts(self, flag: Flag) -> bool {
        match flag {
            Flag::AllowSymlinks | Flag::AllowHardlinks => {
                matches!(self, Self::Extract | Self::Verify)
            }
            Flag::AllowSolidArchives
            | Flag::ZipConsistency
            | Flag::MaxFiles
            | Flag::MaxTotalSize
            | Flag::MaxCompressionRatio => {
                matches!(self, Self::Extract | Self::List | Self::Verify)
            }
            Flag::MaxFileSize => true,
            Flag::BannedComponent | Flag::MaxPathDepth => matches!(self, Self::Extract),
            Flag::Force => matches!(self, Self::Extract | Self::Create),
        }
    }
}

/// A long flag a hint may tell the user to pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flag {
    AllowSymlinks,
    AllowHardlinks,
    AllowSolidArchives,
    BannedComponent,
    Force,
    MaxCompressionRatio,
    MaxFiles,
    MaxFileSize,
    MaxPathDepth,
    MaxTotalSize,
    ZipConsistency,
}

impl Flag {
    #[cfg(test)]
    pub const ALL: [Self; 11] = [
        Self::AllowSymlinks,
        Self::AllowHardlinks,
        Self::AllowSolidArchives,
        Self::BannedComponent,
        Self::Force,
        Self::MaxCompressionRatio,
        Self::MaxFiles,
        Self::MaxFileSize,
        Self::MaxPathDepth,
        Self::MaxTotalSize,
        Self::ZipConsistency,
    ];

    /// The flag as typed, with its leading dashes.
    pub const fn long(self) -> &'static str {
        match self {
            Self::AllowSymlinks => "--allow-symlinks",
            Self::AllowHardlinks => "--allow-hardlinks",
            Self::AllowSolidArchives => "--allow-solid-archives",
            Self::BannedComponent => "--banned-component",
            Self::Force => "--force",
            Self::MaxCompressionRatio => "--max-compression-ratio",
            Self::MaxFiles => "--max-files",
            Self::MaxFileSize => "--max-file-size",
            Self::MaxPathDepth => "--max-path-depth",
            Self::MaxTotalSize => "--max-total-size",
            Self::ZipConsistency => "--zip-consistency",
        }
    }

    /// The flag's name without the dashes, as clap reports it.
    #[cfg(test)]
    pub fn id(self) -> &'static str {
        self.long().trim_start_matches("--")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn every_flag_matches_its_subcommand() {
        let command = crate::cli::Cli::command();
        for operation in Operation::ALL {
            let sub = command
                .find_subcommand(operation.name())
                .unwrap_or_else(|| panic!("no subcommand {}", operation.name()));
            for flag in Flag::ALL {
                let declared = sub
                    .get_arguments()
                    .any(|arg| arg.get_long() == Some(flag.id()));
                assert_eq!(
                    declared,
                    operation.accepts(flag),
                    "{} on {}",
                    flag.long(),
                    operation.name()
                );
            }
        }
    }

    #[test]
    fn operation_serializes_as_its_subcommand_name() {
        for operation in Operation::ALL {
            let value = serde_json::to_value(operation).unwrap_or_default();
            assert_eq!(value, operation.name());
        }
    }
}
