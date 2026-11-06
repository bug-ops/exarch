//! The CLI's operations and the long flags each one accepts.
//!
//! Hints name flags, and a flag only exists on some subcommands. Keeping both
//! as closed enums lets a test walk the real clap command and fail when a hint
//! points at an option the subcommand does not have.

use serde::Serialize;

/// Declares a fieldless enum together with its text table and its `ALL` list
/// from one variant list, so a variant cannot be left out of either.
macro_rules! closed_list {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident => $text_fn:ident {
            $($(#[$vmeta:meta])* $variant:ident => $text:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis enum $name {
            $($(#[$vmeta])* $variant),+
        }

        impl $name {
            /// Every variant, in declaration order.
            #[cfg(test)]
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The variant's text.
            pub const fn $text_fn(self) -> &'static str {
                match self {
                    $(Self::$variant => $text),+
                }
            }
        }
    };
}

closed_list! {
    /// A command that runs against an archive and can fail with an archive
    /// error.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "snake_case")]
    pub enum Operation => name {
        Extract => "extract",
        Create => "create",
        List => "list",
        Verify => "verify",
    }
}

impl Operation {
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
            Flag::Exclude | Flag::MaxFileSize => true,
            Flag::Include | Flag::StripComponents | Flag::Flatten => {
                matches!(self, Self::Extract | Self::List | Self::Verify)
            }
            Flag::AllowedExtensions | Flag::Atomic | Flag::BannedComponent | Flag::MaxPathDepth => {
                matches!(self, Self::Extract)
            }
            Flag::Force => matches!(self, Self::Extract | Self::Create),
        }
    }
}

closed_list! {
    /// A long flag a hint may tell the user to pass.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Flag => long {
        AllowSymlinks => "--allow-symlinks",
        AllowHardlinks => "--allow-hardlinks",
        AllowSolidArchives => "--allow-solid-archives",
        AllowedExtensions => "--allowed-extensions",
        Atomic => "--atomic",
        BannedComponent => "--banned-component",
        Exclude => "--exclude",
        Flatten => "--flatten",
        Force => "--force",
        Include => "--include",
        MaxCompressionRatio => "--max-compression-ratio",
        MaxFiles => "--max-files",
        MaxFileSize => "--max-file-size",
        MaxPathDepth => "--max-path-depth",
        MaxTotalSize => "--max-total-size",
        StripComponents => "--strip-components",
        ZipConsistency => "--zip-consistency",
    }
}

impl Flag {
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
        for &operation in Operation::ALL {
            let sub = command
                .find_subcommand(operation.name())
                .unwrap_or_else(|| panic!("no subcommand {}", operation.name()));
            for &flag in Flag::ALL {
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
        for &operation in Operation::ALL {
            let value = serde_json::to_value(operation).unwrap_or_default();
            assert_eq!(value, operation.name());
        }
    }
}
