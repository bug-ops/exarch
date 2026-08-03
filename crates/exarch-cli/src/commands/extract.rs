//! Extract command implementation.

use crate::cli::ExtractArgs;
use crate::commands::apply_size_limits;
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

/// Extracts into a fresh temp directory next to `output_dir`, then swaps it
/// into place over the pre-existing `output_dir`.
///
/// Used only for `--atomic --force` when `output_dir` already exists. Core's
/// own atomic path (`ExtractionOptions::atomic`) never replaces an existing
/// directory, so this performs the replacement itself, strictly after
/// extraction has already succeeded: the original destination is moved aside
/// to a backup path, the extracted content is moved into place, and only
/// then is the backup removed. If moving the extracted content into place
/// fails, the backup is moved back so the original destination is restored.
fn run_atomic_force_extraction(
    archive: &Path,
    output_dir: &Path,
    config: &SecurityConfig,
    options: &ExtractionOptions,
    progress: &mut dyn ProgressCallback,
    allow_symlinks: bool,
) -> Result<ExtractionReport> {
    let canonical_output = output_dir
        .canonicalize()
        .with_context(|| format!("failed to resolve destination: {}", output_dir.display()))?;
    let parent = canonical_output
        .parent()
        .with_context(|| format!("destination has no parent: {}", output_dir.display()))?;

    let temp_dir = tempfile::tempdir_in(parent)
        .with_context(|| format!("failed to create temp directory in {}", parent.display()))?;

    let report = run_extraction(
        archive,
        temp_dir.path(),
        config,
        options,
        progress,
        allow_symlinks,
    )?;

    // Extraction succeeded. Reserve a unique, currently-vacant sibling path
    // for the backup: renaming onto an existing path (even an empty
    // directory) is unsupported on Windows, so the reserved path must be
    // freed before use.
    let backup_dir = tempfile::tempdir_in(parent)
        .with_context(|| format!("failed to reserve backup path in {}", parent.display()))?;
    let backup_path = backup_dir.keep();
    std::fs::remove_dir(&backup_path)
        .with_context(|| format!("failed to free backup path: {}", backup_path.display()))?;

    std::fs::rename(&canonical_output, &backup_path).with_context(|| {
        format!(
            "failed to move existing destination {} aside before replacing it",
            canonical_output.display()
        )
    })?;

    let temp_path = temp_dir.keep();
    if let Err(e) = std::fs::rename(&temp_path, &canonical_output) {
        // Restore the original destination; the new extraction is discarded.
        // The restore's own outcome must be checked, not assumed: claiming
        // "restored" when the rename-back itself failed would tell the user
        // their data is safe while it actually sits at an unprinted temp path.
        let restore_result = std::fs::rename(&backup_path, &canonical_output);
        let _ = std::fs::remove_dir_all(&temp_path);
        return Err(e).with_context(|| match restore_result {
            Ok(()) => format!(
                "failed to move extracted content into {}; original destination restored",
                canonical_output.display()
            ),
            Err(restore_err) => format!(
                "failed to move extracted content into {}; the original destination could NOT \
                 be restored ({restore_err}) — its original contents are preserved at {} and \
                 must be recovered manually",
                canonical_output.display(),
                backup_path.display()
            ),
        });
    }

    let _ = std::fs::remove_dir_all(&backup_path);

    Ok(report)
}

/// Determines whether `--atomic --force` must replace a pre-existing
/// `output_dir` via [`run_atomic_force_extraction`].
///
/// Gated on `is_dir()`, not `exists()`: a pre-existing non-directory
/// destination (a regular file, a symlink to one, etc.) must never be
/// silently replaced by the swap — that would reproduce the exact data-loss
/// class #519 was filed for, just on a different destination type. Returns
/// an error instead of proceeding when that happens.
fn resolve_atomic_force_replace(args: &ExtractArgs, output_dir: &Path) -> Result<bool> {
    if !(args.atomic && args.force && output_dir.exists()) {
        return Ok(false);
    }
    if !output_dir.is_dir() {
        anyhow::bail!(
            "cannot use --atomic --force: destination {} already exists and is not a directory",
            output_dir.display()
        );
    }
    Ok(true)
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

/// Maximum number of conflicting destination paths listed individually in
/// the pre-flight conflict error before the remainder is collapsed into a
/// single "... and N more" summary line.
const MAX_LISTED_CONFLICTS: usize = 10;

/// Builds the pre-flight destination-conflict error message for `conflicts`.
///
/// Caps the number of individually listed paths at [`MAX_LISTED_CONFLICTS`]
/// so an archive with many same-named pre-existing files (up to
/// `max_file_count`, 10000 by default) cannot flood stderr with one line per
/// conflict. `conflicts` is sorted before truncation so "first N shown" is a
/// deterministic, reproducible subset rather than whatever order the archive
/// manifest happened to yield.
fn conflict_error_message(conflicts: &[std::path::PathBuf]) -> String {
    let count = conflicts.len();
    let noun = if count == 1 { "file" } else { "files" };
    let verb = if count == 1 { "exists" } else { "exist" };

    let mut sorted: Vec<&std::path::PathBuf> = conflicts.iter().collect();
    sorted.sort();

    let list = sorted
        .into_iter()
        .take(MAX_LISTED_CONFLICTS)
        .map(|p| format!("  {}", p.display()))
        .collect::<Vec<_>>()
        .join("\n");

    let remaining = count.saturating_sub(MAX_LISTED_CONFLICTS);
    if remaining == 0 {
        format!("{count} destination {noun} already {verb} (use --force to overwrite):\n{list}")
    } else {
        format!(
            "{count} destination {noun} already {verb} (use --force to overwrite); \
             first {MAX_LISTED_CONFLICTS} shown:\n{list}\n  ... and {remaining} more"
        )
    }
}

/// Drops empty entries from raw `--banned-component` values.
///
/// `SecurityConfig::validate()` rejects empty entries, but an empty value is
/// the documented idiom for disabling the default ban list (see the
/// `--banned-component` clap help), so it must never reach `validate()`.
/// The caller keeps checking `args.banned_components.is_empty()` on the raw,
/// unfiltered values to decide whether to override the default ban list at
/// all; this only strips empties out of the values passed once that
/// decision is made.
fn filter_banned_components(raw: &[String]) -> Vec<String> {
    raw.iter().filter(|c| !c.is_empty()).cloned().collect()
}

pub fn execute(
    args: &ExtractArgs,
    formatter: &mut dyn OutputFormatter,
    verbose: bool,
    quiet: bool,
) -> Result<()> {
    let output_dir = match &args.output_dir {
        Some(dir) => dir.clone(),
        None => env::current_dir().context("failed to get current directory")?,
    };

    let allowed_extensions = parse_extensions(&args.allowed_extensions);

    let config = apply_size_limits(
        SecurityConfig::default().with_max_file_count(args.max_files),
        args.max_total_size,
        args.max_file_size,
    )
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
        config.with_banned_path_components(filter_banned_components(&args.banned_components))
    };

    // list_config shares quota and path-filtering params with config but uses
    // safe defaults for flags that only apply during extraction (symlinks,
    // hardlinks, world-writable, permissions). allow_absolute_paths,
    // max_path_depth, and banned_path_components are propagated so listing
    // rejects paths that extraction would also reject on traversal grounds.
    let list_config = SecurityConfig::default()
        .with_max_file_count(config.max_file_count)
        .with_max_total_size(config.max_total_size)
        .with_max_file_size(config.max_file_size)
        .with_max_compression_ratio(config.max_compression_ratio)
        .with_allow_solid_archives(config.allow_solid_archives)
        .with_allow_absolute_paths(config.allowed.absolute_paths)
        .with_max_path_depth(config.max_path_depth)
        .with_banned_path_components(config.banned_path_components.clone());

    // Always list the archive: needed for conflict detection and for obtaining
    // the real entry count that drives the progress bar.
    let manifest = list_archive(&args.archive, &list_config)
        .with_context(|| format!("failed to list archive: {}", args.archive.display()))?;

    if !args.force && !args.atomic {
        let conflicts: Vec<_> = manifest
            .entries
            .iter()
            .filter(|e| e.entry_type == ManifestEntryType::File)
            .map(|e| {
                let relative = if args.allow_absolute_paths && e.path.is_absolute() {
                    e.path.strip_prefix("/").unwrap_or(&e.path)
                } else {
                    &e.path
                };
                output_dir.join(relative)
            })
            .filter(|p| p.exists())
            .collect();

        if !conflicts.is_empty() {
            anyhow::bail!(conflict_error_message(&conflicts));
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

    // --atomic + --force over a pre-existing destination needs a swap that
    // core's `extract_atomic` doesn't perform itself (it refuses to replace
    // an existing directory, by design, so a pre-existing destination is
    // never touched if extraction fails). The CLI performs that swap only
    // after extraction has already fully succeeded; see
    // `run_atomic_force_extraction`.
    let atomic_force_replace = resolve_atomic_force_replace(args, &output_dir)?;

    let options = ExtractionOptions::default()
        .with_atomic(args.atomic && !atomic_force_replace)
        .with_skip_duplicates(!args.force);

    let mut progress: Box<dyn ProgressCallback> = if verbose {
        Box::new(VerboseProgress::new())
    } else if !quiet && CliProgress::should_show() {
        Box::new(CliProgress::new(entry_count, "Extracting"))
    } else {
        Box::new(NoopProgress)
    };

    let report = if atomic_force_replace {
        run_atomic_force_extraction(
            &args.archive,
            &output_dir,
            &config,
            &options,
            progress.as_mut(),
            args.allow_symlinks,
        )?
    } else {
        run_extraction(
            &args.archive,
            &output_dir,
            &config,
            &options,
            progress.as_mut(),
            args.allow_symlinks,
        )?
    };

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

    #[test]
    fn filter_banned_components_drops_empty_entries() {
        let raw = vec![String::new()];
        assert_eq!(filter_banned_components(&raw), Vec::<String>::new());
    }

    #[test]
    fn filter_banned_components_keeps_non_empty_entries() {
        let raw = vec![".git".to_string(), String::new(), ".ssh".to_string()];
        assert_eq!(filter_banned_components(&raw), vec![".git", ".ssh"]);
    }

    #[test]
    fn conflict_error_message_singular() {
        let conflicts = vec![std::path::PathBuf::from("a.txt")];
        let msg = conflict_error_message(&conflicts);
        assert!(msg.starts_with("1 destination file already exists"));
        assert!(msg.contains("a.txt"));
        assert!(!msg.contains("more"));
    }

    #[test]
    fn conflict_error_message_under_cap_lists_all_without_truncation_note() {
        let conflicts: Vec<_> = (0..5)
            .map(|i| std::path::PathBuf::from(format!("f{i}.txt")))
            .collect();
        let msg = conflict_error_message(&conflicts);
        assert!(msg.starts_with("5 destination files already exist"));
        for i in 0..5 {
            assert!(msg.contains(&format!("f{i}.txt")));
        }
        assert!(!msg.contains("more"));
        assert!(!msg.contains("first"));
    }

    #[test]
    fn conflict_error_message_at_cap_lists_all_without_truncation_note() {
        let conflicts: Vec<_> = (0..MAX_LISTED_CONFLICTS)
            .map(|i| std::path::PathBuf::from(format!("f{i}.txt")))
            .collect();
        let msg = conflict_error_message(&conflicts);
        assert!(msg.starts_with("10 destination files already exist"));
        for i in 0..MAX_LISTED_CONFLICTS {
            assert!(msg.contains(&format!("f{i}.txt")));
        }
        assert!(!msg.contains("more"));
        assert!(!msg.contains("first"));
    }

    #[test]
    fn conflict_error_message_over_cap_truncates_and_summarizes() {
        // Zero-padded so lexicographic (PathBuf::Ord) sort matches numeric
        // order, and reverse-inserted to prove the shown subset is the
        // sorted-first-10, not an insertion-order-first-10.
        let conflicts: Vec<_> = (0..25)
            .rev()
            .map(|i| std::path::PathBuf::from(format!("f{i:02}.txt")))
            .collect();
        let msg = conflict_error_message(&conflicts);
        assert!(msg.starts_with("25 destination files already exist"));
        assert!(msg.contains("first 10 shown"));
        for i in 0..10 {
            assert!(msg.contains(&format!("f{i:02}.txt")));
        }
        for i in 10..25 {
            assert!(!msg.contains(&format!("f{i:02}.txt")));
        }
        assert!(msg.contains("... and 15 more"));
    }

    #[test]
    fn conflict_error_message_lists_shown_entries_in_sorted_order() {
        let conflicts: Vec<_> = ["c.txt", "a.txt", "b.txt"]
            .iter()
            .map(std::path::PathBuf::from)
            .collect();
        let msg = conflict_error_message(&conflicts);
        let find = |needle: &str| {
            msg.find(needle)
                .unwrap_or_else(|| panic!("{needle} missing from: {msg}"))
        };
        assert!(
            find("a.txt") < find("b.txt") && find("b.txt") < find("c.txt"),
            "shown paths must be listed in sorted order regardless of input order: {msg}"
        );
    }

    #[test]
    fn conflict_error_message_is_deterministic_across_input_permutations() {
        let ascending: Vec<_> = (0..15)
            .map(|i| std::path::PathBuf::from(format!("f{i:02}.txt")))
            .collect();
        let mut reversed = ascending.clone();
        reversed.reverse();

        assert_eq!(
            conflict_error_message(&ascending),
            conflict_error_message(&reversed),
            "the message must not depend on the order conflicts were discovered in"
        );
    }
}
