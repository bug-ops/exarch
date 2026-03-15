//! Exarch CLI - Command-line utility for secure archive extraction and
//! creation.

mod cli;
mod commands;
mod error;
mod output;
mod progress;

use clap::Parser;
use output::OutputFormatter;
use std::process;

fn run(cli: &cli::Cli, formatter: &dyn OutputFormatter) -> (anyhow::Result<()>, &'static str) {
    match &cli.command {
        cli::Commands::Extract(args) => (commands::extract::execute(args, formatter), "extract"),
        cli::Commands::Create(args) => (
            commands::create::execute(args, formatter, cli.quiet),
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
    let formatter = output::create_formatter(cli.json, cli.verbose, cli.quiet);

    let (result, operation) = run(&cli, &*formatter);
    if let Err(err) = result {
        formatter.format_error(operation, &err);
        process::exit(1);
    }
}
