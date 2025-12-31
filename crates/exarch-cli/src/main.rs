//! Exarch CLI - Command-line utility for secure archive extraction and
//! creation.

mod cli;
mod commands;
mod error;
mod output;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let cli = cli::Cli::parse();

    let formatter = output::create_formatter(cli.json, cli.verbose, cli.quiet);

    match &cli.command {
        cli::Commands::Extract(args) => commands::extract::execute(args, &*formatter),
        cli::Commands::Create(args) => commands::create::execute(args, &*formatter, cli.quiet),
        cli::Commands::List(args) => commands::list::execute(args, &*formatter),
        cli::Commands::Verify(args) => commands::verify::execute(args, &*formatter),
    }
}
