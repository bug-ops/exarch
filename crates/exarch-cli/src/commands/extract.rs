//! Extract command implementation.

use crate::cli::ExtractArgs;
use crate::error::add_archive_context;
use crate::output::OutputFormatter;
use crate::progress::CliProgress;
use crate::progress::VerboseProgress;
use anyhow::Context;
use anyhow::Result;
use exarch_core::ExtractionOptions;
use exarch_core::ExtractionReport;
use exarch_core::ManifestEntryType;
use exarch_core::NoopProgress;
use exarch_core::ProgressCallback;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive_with_options_and_progress;
use exarch_core::list_archive;
use std::env;
use std::path::Path;

fn run_extraction(
    archive: &Path,
    output_dir: &Path,
    config: &SecurityConfig,
    options: &ExtractionOptions,
    progress: &mut dyn ProgressCallback,
    allow_symlinks: bool,
) -> Result<ExtractionReport> {
    add_archive_context(
        extract_archive_with_options_and_progress(archive, output_dir, config, options, progress),
        archive,
        allow_symlinks,
    )
}

/// Expands a list of extension tokens that may contain comma-separated values
/// into individual lowercase extension strings without leading dots.
fn parse_extensions(raw: &[String]) -> Vec<String> {
    raw.iter()
        .flat_map(|s| s.split(','))
        .map(|ext| ext.trim().trim_start_matches('.').to_lowercase())
        .filter(|ext| !ext.is_empty())
        .collect()
}

pub fn execute(
    args: &ExtractArgs,
    formatter: &dyn OutputFormatter,
    verbose: bool,
    quiet: bool,
) -> Result<()> {
    let output_dir = match &args.output_dir {
        Some(dir) => dir.clone(),
        None => env::current_dir().context("failed to get current directory")?,
    };

    let allowed_extensions = parse_extensions(&args.allowed_extensions);

    let config = SecurityConfig::default()
        .with_max_file_count(args.max_files)
        .with_max_total_size(args.max_total_size.unwrap_or(500 * 1024 * 1024))
        .with_max_file_size(args.max_file_size.unwrap_or(50 * 1024 * 1024))
        .with_max_compression_ratio(f64::from(args.max_compression_ratio))
        .with_max_path_depth(args.max_path_depth)
        .with_allow_symlinks(args.allow_symlinks)
        .with_allow_hardlinks(args.allow_hardlinks)
        .with_allow_absolute_paths(args.allow_absolute_paths)
        .with_allow_world_writable(args.allow_world_writable)
        .with_preserve_permissions(args.preserve_permissions)
        .with_allow_solid_archives(args.allow_solid_archives)
        .with_allowed_extensions(allowed_extensions);

    let config = if args.banned_components.is_empty() {
        config
    } else {
        config.with_banned_path_components(args.banned_components.clone())
    };

    // list_config shares quota params with config but uses safe defaults for
    // security flags — listing must not be blocked by allow_symlinks etc.
    let list_config = SecurityConfig::default()
        .with_max_file_count(config.max_file_count)
        .with_max_total_size(config.max_total_size)
        .with_max_file_size(config.max_file_size)
        .with_max_compression_ratio(config.max_compression_ratio)
        .with_allow_solid_archives(config.allow_solid_archives);

    // Always list the archive: needed for conflict detection and for obtaining
    // the real entry count that drives the progress bar.
    let manifest = list_archive(&args.archive, &list_config)
        .with_context(|| format!("failed to list archive: {}", args.archive.display()))?;

    if !args.force && !args.atomic {
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

    let entry_count = if config.allowed_extensions.is_empty() {
        manifest.entries.len()
    } else {
        manifest
            .entries
            .iter()
            .filter(|e| e.entry_type == ManifestEntryType::File)
            .filter(|e| {
                let ext = e.path.extension().and_then(|s| s.to_str());
                config.is_path_extension_allowed(ext)
            })
            .count()
    };

    let options = ExtractionOptions::default()
        .with_atomic(args.atomic)
        .with_skip_duplicates(!args.force);

    // When --atomic + --force: remove existing destination after successful
    // extraction (handled inside extract_atomic via rename semantics) but we
    // must pre-remove if it exists so rename can succeed (on most platforms
    // rename over an existing non-empty dir fails).
    if args.atomic && args.force && output_dir.exists() {
        std::fs::remove_dir_all(&output_dir)
            .with_context(|| format!("failed to remove existing dir: {}", output_dir.display()))?;
    }

    let mut progress: Box<dyn ProgressCallback> = if verbose {
        Box::new(VerboseProgress::new())
    } else if !quiet && CliProgress::should_show() {
        Box::new(CliProgress::new(entry_count, "Extracting"))
    } else {
        Box::new(NoopProgress)
    };

    let report = run_extraction(
        &args.archive,
        &output_dir,
        &config,
        &options,
        progress.as_mut(),
        args.allow_symlinks,
    )?;

    formatter.format_extraction_result(&report)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_extensions_comma_split() {
        let raw = vec!["zip,tar,gz".to_string()];
        assert_eq!(parse_extensions(&raw), vec!["zip", "tar", "gz"]);
    }

    #[test]
    fn parse_extensions_strips_leading_dot() {
        let raw = vec![".zip".to_string(), ".TAR".to_string()];
        assert_eq!(parse_extensions(&raw), vec!["zip", "tar"]);
    }

    #[test]
    fn parse_extensions_trims_whitespace() {
        let raw = vec![" zip , tar ".to_string()];
        assert_eq!(parse_extensions(&raw), vec!["zip", "tar"]);
    }

    #[test]
    fn parse_extensions_lowercases() {
        let raw = vec!["ZIP".to_string(), "TAR.GZ".to_string()];
        assert_eq!(parse_extensions(&raw), vec!["zip", "tar.gz"]);
    }

    #[test]
    fn parse_extensions_empty_input() {
        assert_eq!(parse_extensions(&[]), Vec::<String>::new());
    }

    #[test]
    fn parse_extensions_filters_empty_tokens() {
        let raw = vec!["zip,,tar".to_string()];
        assert_eq!(parse_extensions(&raw), vec!["zip", "tar"]);
    }

    #[test]
    fn parse_extensions_mixed_repeatable_and_comma() {
        let raw = vec!["zip,tar".to_string(), ".GZ".to_string()];
        assert_eq!(parse_extensions(&raw), vec!["zip", "tar", "gz"]);
    }
}
