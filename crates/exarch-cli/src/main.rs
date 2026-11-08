//! Exarch CLI - Command-line utility for secure archive extraction and
//! creation.

mod cli;
mod commands;
mod error;
mod exit;
mod interrupt;
mod operation;
mod output;
mod progress;
#[cfg(test)]
mod test_support;

use clap::Parser;
use commands::CommandResult;
use commands::Outcome;
use exit::ExitStatus;
use operation::Operation;
use output::OutputFormatter;
use output::OutputMode;
use std::io::Write as _;
use std::path::Path;
use std::process::ExitCode;

/// A command that failed, with the operation the formatter reports it under;
/// `None` for a command that has no JSON envelope (`completion`).
struct Failure {
    operation: Option<Operation>,
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
        operation: Some(operation),
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
            commands::completion::execute(args.shell, &mut std::io::stdout())
                .map(|()| Outcome::Ok)
                .map_err(|error| Failure {
                    operation: None,
                    error: anyhow::Error::new(error).context("failed to write the completions"),
                })
        }
    }
}

/// The status of a failed command: a cancelled run that a stop request caused
/// reports that request, everything else is a plain failure.
fn failure_status(error: &anyhow::Error) -> ExitStatus {
    interrupt::requested()
        .filter(|_| error::is_cancelled(error))
        .map_or(ExitStatus::Failure, ExitStatus::from)
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
            match failure.operation {
                Some(operation) => formatter.format_error(operation, &failure.error),
                // A closed stderr must not turn the failure into a panic.
                None => {
                    let _ = writeln!(std::io::stderr(), "Error: {:#}", failure.error);
                }
            }
            failure_status(&failure.error)
        }
    };
    if matches!(status, ExitStatus::Interrupted | ExitStatus::Terminated) {
        drop(formatter);
        let _ = std::io::stdout().flush();
        interrupt::finish_by_signal();
    }
    status.into()
}
