//! Create command implementation.

use crate::cli::CreateArgs;
use crate::output::OutputFormatter;
use anyhow::Context;
use anyhow::Result;
use exarch_core::CreationConfig;
use exarch_core::create_archive;

pub fn execute(args: &CreateArgs, formatter: &dyn OutputFormatter, quiet: bool) -> Result<()> {
    // Check if output exists
    if args.output.exists() && !args.force {
        anyhow::bail!(
            "Output file already exists: {}. Use --force to overwrite",
            args.output.display()
        );
    }

    // Remove existing file if --force
    if args.output.exists() && args.force {
        std::fs::remove_file(&args.output).with_context(|| {
            format!("Failed to remove existing file: {}", args.output.display())
        })?;
    }

    // Build config
    let mut config = CreationConfig {
        follow_symlinks: args.follow_symlinks,
        include_hidden: args.include_hidden,
        compression_level: args.compression_level,
        strip_prefix: args.strip_prefix.clone(),
        ..Default::default()
    };

    // Add user exclude patterns to defaults
    config.exclude_patterns.extend(args.exclude.iter().cloned());

    // Create archive
    let report = create_archive(&args.output, &args.sources, &config)
        .with_context(|| format!("Failed to create archive: {}", args.output.display()))?;

    if !quiet {
        formatter.format_creation_result(&args.output, &report)?;
    }

    Ok(())
}
