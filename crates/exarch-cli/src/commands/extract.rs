//! Extract command implementation.

use crate::cli::ExtractArgs;
use crate::error::add_archive_context;
use crate::output::OutputFormatter;
use anyhow::Context;
use anyhow::Result;
use exarch_core::SecurityConfig;
use exarch_core::config::AllowedFeatures;
use exarch_core::extract_archive;
use std::env;

pub fn execute(args: &ExtractArgs, formatter: &dyn OutputFormatter) -> Result<()> {
    let output_dir = match &args.output_dir {
        Some(dir) => dir.clone(),
        None => env::current_dir().context("failed to get current directory")?,
    };

    let config = SecurityConfig {
        max_file_count: args.max_files,
        max_total_size: args.max_total_size.unwrap_or(500 * 1024 * 1024),
        max_file_size: args.max_file_size.unwrap_or(50 * 1024 * 1024),
        max_compression_ratio: f64::from(args.max_compression_ratio),
        allowed: AllowedFeatures {
            symlinks: args.allow_symlinks,
            hardlinks: args.allow_hardlinks,
            absolute_paths: false,
            world_writable: false,
        },
        preserve_permissions: args.preserve_permissions,
        ..Default::default()
    };

    let report = add_archive_context(
        extract_archive(&args.archive, &output_dir, &config),
        &args.archive,
    )?;

    formatter.format_extraction_result(&report)?;

    Ok(())
}
