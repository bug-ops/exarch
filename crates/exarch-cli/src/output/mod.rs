//! Output formatting module.

mod formatter;
mod human;
mod json;

pub use formatter::OutputFormatter;

use human::HumanFormatter;
use json::JsonFormatter;

/// Output verbosity level for human-readable formatters.
///
/// Replaces the CLI's `--verbose`/`--quiet` flags — two independent
/// booleans — with a single value, so formatter constructors can no longer
/// be handed the nonsensical `verbose: true, quiet: true` combination.
///
/// # Examples
///
/// ```no_run
/// use exarch_cli::output::Verbosity;
///
/// let level = Verbosity::from_flags(true, false);
/// assert_eq!(level, Verbosity::Verbose);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verbosity {
    /// Suppress all non-error output.
    Quiet,
    /// Default output level.
    Normal,
    /// Emit additional diagnostic detail.
    Verbose,
}

impl Verbosity {
    /// Derives a [`Verbosity`] from the CLI's `--verbose`/`--quiet` flags.
    ///
    /// `quiet` wins if both are set. This tie-break is real, reachable
    /// behavior, not dead code: `clap`'s `conflicts_with` on `--quiet` only
    /// rejects the pair when both flags land in the same `ArgMatches` level
    /// (e.g. `exarch list --verbose --quiet`). A global `--verbose` paired
    /// with a subcommand-level `--quiet` — or the reverse, e.g. `exarch
    /// --verbose extract archive.tar.gz out --quiet` — bypasses that check
    /// entirely, so both fields can genuinely be `true` at once.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use exarch_cli::output::Verbosity;
    ///
    /// assert_eq!(Verbosity::from_flags(false, false), Verbosity::Normal);
    /// assert_eq!(Verbosity::from_flags(false, true), Verbosity::Quiet);
    /// ```
    #[must_use]
    pub fn from_flags(verbose: bool, quiet: bool) -> Self {
        if quiet {
            Self::Quiet
        } else if verbose {
            Self::Verbose
        } else {
            Self::Normal
        }
    }
}

impl From<&crate::cli::Cli> for Verbosity {
    fn from(cli: &crate::cli::Cli) -> Self {
        Self::from_flags(cli.verbose, cli.quiet)
    }
}

/// Creates an output formatter based on CLI flags
pub fn create_formatter(json: bool, verbosity: Verbosity) -> Box<dyn OutputFormatter> {
    if json {
        Box::new(JsonFormatter::stdout())
    } else {
        Box::new(HumanFormatter::new(verbosity))
    }
}

/// Converts a byte count into a human-readable string using binary
/// (1024-based) units, tiered from bytes up to terabytes.
pub fn humanize_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.1} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::Verbosity;
    use super::humanize_bytes;
    use clap::Parser;

    #[test]
    fn from_flags_neither_set_is_normal() {
        assert_eq!(Verbosity::from_flags(false, false), Verbosity::Normal);
    }

    #[test]
    fn from_flags_verbose_only_is_verbose() {
        assert_eq!(Verbosity::from_flags(true, false), Verbosity::Verbose);
    }

    #[test]
    fn from_flags_quiet_only_is_quiet() {
        assert_eq!(Verbosity::from_flags(false, true), Verbosity::Quiet);
    }

    #[test]
    fn from_flags_both_set_resolves_to_quiet() {
        // Reachable in practice, not just a defensive default: `clap`'s
        // `conflicts_with` only rejects `--verbose`/`--quiet` when both land
        // in the same `ArgMatches` level, so a split-level combination (e.g.
        // `exarch --verbose extract ... --quiet`) parses successfully with
        // both bools `true`. `from_flags` must resolve that deterministically.
        assert_eq!(Verbosity::from_flags(true, true), Verbosity::Quiet);
    }

    #[test]
    fn from_cli_resolves_split_level_verbose_quiet_deterministically() {
        // Regression for the split-level bypass: a global `--verbose`
        // combined with a subcommand-level `--quiet` is not rejected by
        // clap's `conflicts_with` (only same-level pairs are), so both
        // `cli.verbose` and `cli.quiet` end up `true` here.
        let cli = crate::cli::Cli::parse_from([
            "exarch",
            "--verbose",
            "extract",
            "archive.tar.gz",
            "--quiet",
        ]);
        assert!(cli.verbose && cli.quiet, "both flags must parse as true");
        assert_eq!(Verbosity::from(&cli), Verbosity::Quiet);
    }

    #[test]
    fn test_humanize_bytes_bytes() {
        assert_eq!(humanize_bytes(0), "0 B");
        assert_eq!(humanize_bytes(512), "512 B");
        assert_eq!(humanize_bytes(1023), "1023 B");
    }

    #[test]
    fn test_humanize_bytes_kilobytes() {
        assert_eq!(humanize_bytes(1024), "1.0 KB");
        assert_eq!(humanize_bytes(1536), "1.5 KB");
        assert_eq!(humanize_bytes(2048), "2.0 KB");
    }

    #[test]
    fn test_humanize_bytes_megabytes() {
        assert_eq!(humanize_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(humanize_bytes(1536 * 1024), "1.5 MB");
        assert_eq!(humanize_bytes(2 * 1024 * 1024), "2.0 MB");
    }

    #[test]
    fn test_humanize_bytes_gigabytes() {
        assert_eq!(humanize_bytes(1024 * 1024 * 1024), "1.0 GB");
        assert_eq!(humanize_bytes(1536 * 1024 * 1024), "1.5 GB");
        assert_eq!(humanize_bytes(2 * 1024 * 1024 * 1024), "2.0 GB");
    }

    #[test]
    fn test_humanize_bytes_terabytes() {
        assert_eq!(humanize_bytes(1024_u64.pow(4)), "1.0 TB");
    }

    #[test]
    fn test_humanize_bytes_edge_cases() {
        // u64::MAX = 18446744073709551615 bytes = 16777216.0 TB (TB = 1024^4)
        assert_eq!(humanize_bytes(u64::MAX), "16777216.0 TB");
    }
}
