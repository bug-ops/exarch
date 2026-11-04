//! Exarch CLI - Command-line utility for secure archive extraction and
//! creation.

mod cli;
mod commands;
mod error;
mod operation;
mod output;
mod progress;
#[cfg(test)]
mod test_support;

use clap::Parser;
use commands::CommandResult;
use commands::Outcome;
use operation::Operation;
use output::OutputFormatter;
use output::OutputMode;
use std::path::Path;
use std::process::ExitCode;

/// The process exit status, one value per documented meaning.
///
/// Code 2 is clap's usage-error status and is deliberately not used here, so a
/// script can tell "your flags are wrong" from "the archive has warnings".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum ExitStatus {
    Success = 0,
    Failure = 1,
    StrictWarning = 3,
}

impl From<ExitStatus> for ExitCode {
    fn from(status: ExitStatus) -> Self {
        Self::from(status as u8)
    }
}

/// A command that failed, with the operation the formatter reports it under.
struct Failure {
    operation: Operation,
    error: anyhow::Error,
}

/// Runs `command`, giving a failure the archive name and hints of its
/// operation.
fn attempt(
    operation: Operation,
    archive: &Path,
    result: CommandResult,
) -> Result<Outcome, Failure> {
    result.map_err(|error| Failure {
        operation,
        error: error.contextualize(operation, archive),
    })
}

fn run(
    cli: &cli::Cli,
    mode: OutputMode,
    formatter: &mut dyn OutputFormatter,
) -> Result<Outcome, Failure> {
    match &cli.command {
        cli::Commands::Extract(args) => attempt(
            Operation::Extract,
            &args.archive,
            commands::extract::execute(args, formatter, mode),
        ),
        cli::Commands::Create(args) => attempt(
            Operation::Create,
            &args.output,
            commands::create::execute(args, formatter, mode),
        ),
        cli::Commands::List(args) => attempt(
            Operation::List,
            &args.archive,
            commands::list::execute(args, formatter),
        ),
        cli::Commands::Verify(args) => attempt(
            Operation::Verify,
            &args.archive,
            commands::verify::execute(args, formatter),
        ),
        cli::Commands::Completion(args) => {
            commands::completion::execute(args.shell);
            Ok(Outcome::Ok)
        }
    }
}

fn main() -> ExitCode {
    let cli = cli::Cli::parse();
    let mode = OutputMode::from(&cli);
    let mut formatter = output::create_formatter(mode);

    let status = match run(&cli, mode, formatter.as_mut()) {
        Ok(Outcome::Ok) => ExitStatus::Success,
        Ok(Outcome::VerifyFailed) => {
            formatter.format_verification_failed();
            ExitStatus::Failure
        }
        Ok(Outcome::StrictWarning) => ExitStatus::StrictWarning,
        Err(failure) => {
            formatter.format_error(failure.operation, &failure.error);
            ExitStatus::Failure
        }
    };
    status.into()
}

#[cfg(test)]
mod tests {
    use super::ExitStatus;

    #[test]
    fn strict_warning_does_not_share_clap_usage_error_code() {
        const CLAP_USAGE_ERROR: u8 = 2;
        for status in [
            ExitStatus::Success,
            ExitStatus::Failure,
            ExitStatus::StrictWarning,
        ] {
            assert_ne!(status as u8, CLAP_USAGE_ERROR, "{status:?}");
        }
        assert_eq!(ExitStatus::StrictWarning as u8, 3);
    }
}
