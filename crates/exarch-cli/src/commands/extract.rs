//! Extract command implementation.

use crate::cli::ExtractArgs;
use crate::error::add_archive_context;
use crate::output::OutputFormatter;
use crate::progress::CliProgress;
use anyhow::Context;
use anyhow::Result;
use exarch_core::ExtractionOptions;
use exarch_core::ManifestEntryType;
use exarch_core::NoopProgress;
use exarch_core::SecurityConfig;
use exarch_core::config::AllowedFeatures;
use exarch_core::extract_archive_full;
use exarch_core::list_archive;
use std::env;

pub fn execute(args: &ExtractArgs, formatter: &dyn OutputFormatter) -> Result<()> {
    let output_dir = match &args.output_dir {
        Some(dir) => dir.clone(),
        None => env::current_dir().context("failed to get current directory")?,
    };

    if !args.force && !args.atomic {
        let manifest = list_archive(
            &args.archive,
            &SecurityConfig {
                allow_solid_archives: args.allow_solid_archives,
                ..Default::default()
            },
        )
        .with_context(|| format!("failed to list archive: {}", args.archive.display()))?;

        let conflicts: Vec<_> = manifest
            .entries
            .iter()
            .filter(|e| e.entry_type == ManifestEntryType::File)
            .map(|e| output_dir.join(&e.path))
            .filter(|p| p.exists())
            .collect();

        if !conflicts.is_empty() {
            let list = conflicts
                .iter()
                .map(|p| format!("  {}", p.display()))
                .collect::<Vec<_>>()
                .join("\n");
            anyhow::bail!("destination files already exist (use --force to overwrite):\n{list}");
        }
    }

    let config = SecurityConfig {
        max_file_count: args.max_files,
        max_total_size: args.max_total_size.unwrap_or(500 * 1024 * 1024),
        max_file_size: args.max_file_size.unwrap_or(50 * 1024 * 1024),
        max_compression_ratio: f64::from(args.max_compression_ratio),
        allowed: AllowedFeatures {
            symlinks: args.allow_symlinks,
            hardlinks: args.allow_hardlinks,
            absolute_paths: false,
            world_writable: args.allow_world_writable,
        },
        preserve_permissions: args.preserve_permissions,
        allow_solid_archives: args.allow_solid_archives,
        ..Default::default()
    };

    let options = ExtractionOptions {
        atomic: args.atomic,
    };

    // When --atomic + --force: remove existing destination after successful
    // extraction (handled inside extract_atomic via rename semantics) but we
    // must pre-remove if it exists so rename can succeed (on most platforms
    // rename over an existing non-empty dir fails).
    if args.atomic && args.force && output_dir.exists() {
        std::fs::remove_dir_all(&output_dir)
            .with_context(|| format!("failed to remove existing dir: {}", output_dir.display()))?;
    }

    // Use progress bar if TTY is detected (not quiet, not JSON, is terminal)
    let report = if CliProgress::should_show() {
        let mut progress = CliProgress::new(100, "Extracting");
        add_archive_context(
            extract_archive_full(&args.archive, &output_dir, &config, &options, &mut progress),
            &args.archive,
        )?
    } else {
        let mut noop = NoopProgress;
        add_archive_context(
            extract_archive_full(&args.archive, &output_dir, &config, &options, &mut noop),
            &args.archive,
        )?
    };

    formatter.format_extraction_result(&report)?;

    Ok(())
}
