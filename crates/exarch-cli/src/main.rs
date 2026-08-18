//! Exarch CLI - Command-line utility for secure archive extraction and
//! creation.

mod cli;
mod commands;
mod error;
mod output;
mod progress;

use clap::Parser;
use error::StrictWarning;
use error::VerificationFailed;
use output::OutputFormatter;
use output::Verbosity;
use std::process;

fn run(
    cli: &cli::Cli,
    verbosity: Verbosity,
    formatter: &mut dyn OutputFormatter,
) -> (anyhow::Result<()>, &'static str) {
    match &cli.command {
        cli::Commands::Extract(args) => (
            commands::extract::execute(args, formatter, verbosity),
            "extract",
        ),
        cli::Commands::Create(args) => (
            commands::create::execute(args, formatter, verbosity),
            "create",
        ),
        cli::Commands::List(args) => (commands::list::execute(args, formatter), "list"),
        cli::Commands::Verify(args) => (commands::verify::execute(args, formatter), "verify"),
        cli::Commands::Completion(args) => {
            commands::completion::execute(args.shell);
            (Ok(()), "completion")
        }
    }
}

fn main() {
    let cli = cli::Cli::parse();
    let verbosity = Verbosity::from(&cli);
    let mut formatter = output::create_formatter(cli.json, verbosity);

    let (result, operation) = run(&cli, verbosity, formatter.as_mut());
    if let Err(err) = result {
        if err.is::<StrictWarning>() {
            process::exit(2);
        }
        // The verification report (already emitted by the formatter) fully
        // describes a Fail status. In --json mode, printing a second error
        // envelope here would produce two concatenated top-level JSON
        // documents on stdout, so it's skipped; human-readable output still
        // gets the error message on stderr.
        if err.is::<VerificationFailed>() {
            if !cli.json {
                formatter.format_error(operation, &err);
            }
            process::exit(1);
        }
        formatter.format_error(operation, &err);
        process::exit(1);
    }
}
