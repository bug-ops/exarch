//! Extract command implementation.

use crate::cli::ExtractArgs;
use crate::commands::apply_size_limits;
use crate::commands::atomic_swap::DestEntryKind;
use crate::commands::atomic_swap::PinnedDir;
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
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io;
use std::path::Path;
use std::path::PathBuf;

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

/// Everything [`run_atomic_force_extraction`] needs, resolved and pinned by
/// [`resolve_atomic_force_replace`] before extraction starts.
struct AtomicForceTarget {
    /// The destination's parent, pinned by an open file descriptor.
    pin: PinnedDir,
    /// The destination's final path component, resolved via
    /// [`Path::file_name`] — never a raw path fragment. See the invariant
    /// note at its point of derivation in [`resolve_atomic_force_replace`].
    dest_name: OsString,
    /// The `(dev, ino)` identity `entry_status` reported for `dest_name`
    /// when it confirmed the destination was a directory, carried forward
    /// rather than re-derived so the kind/identity pair snapshotted here is
    /// the one [`verify_destination_unchanged`] rechecks against.
    dest_id: (u64, u64),
    /// The pinned parent's canonical path, for temp/backup directory
    /// creation and error messages.
    parent_display: PathBuf,
    /// The destination's display path, for error messages.
    dest_display: PathBuf,
}

/// Extracts into a fresh temp directory next to the destination, then swaps
/// it into place over the pre-existing destination.
///
/// Used only for `--atomic --force` when the destination already exists.
/// Core's own atomic path (`ExtractionOptions::atomic`) never replaces an
/// existing directory, so this performs the replacement itself, strictly
/// after extraction has already succeeded: the original destination is
/// moved aside to a backup path, the extracted content is moved into place,
/// and only then is the backup removed. If moving the extracted content
/// into place fails, the backup is moved back so the original destination
/// is restored.
///
/// On Unix, `target.pin` pins the destination's parent directory by an open
/// file descriptor and every rename/remove below is resolved relative to
/// that descriptor rather than by path, closing the TOCTOU window where an
/// *intermediate* path component is replaced with a symlink mid-swap (issue
/// #526). A dev/ino identity recheck immediately before the destructive
/// swap (see [`verify_destination_unchanged`]) additionally narrows — it
/// does not close — the remaining window around the *final* component
/// itself: the fd-pin cannot cover a change to the entry it was opened for,
/// and the recheck is itself a check-then-use relative to the rename that
/// follows it, just one shrunk from extraction-duration to two syscalls
/// wide.
fn run_atomic_force_extraction(
    archive: &Path,
    target: AtomicForceTarget,
    config: &SecurityConfig,
    options: &ExtractionOptions,
    progress: &mut dyn ProgressCallback,
    allow_symlinks: bool,
) -> Result<ExtractionReport> {
    let AtomicForceTarget {
        pin,
        dest_name,
        dest_id,
        parent_display,
        dest_display,
    } = target;

    // Path-based: `tempfile` has no fd-relative constructor. If `parent`
    // were redirected between the pin above and here, every fd-relative
    // call below fails closed with `ENOENT` before anything destructive
    // happens, so this does not reopen the window `PinnedDir` closes.
    let temp_dir = tempfile::tempdir_in(&parent_display).with_context(|| {
        format!(
            "failed to create temp directory in {}",
            parent_display.display()
        )
    })?;
    // Derived now, before any destructive operation below, so that a
    // (practically unreachable, `tempfile` always yields a named path)
    // `file_name()` failure can never surface *after* the destination has
    // already been moved aside with no way to name the replacement.
    let temp_name = temp_dir
        .path()
        .file_name()
        .map(OsStr::to_os_string)
        .with_context(|| format!("temp path has no file name: {}", temp_dir.path().display()))?;

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
    //
    // Path-based for the same reason as the temp dir above.
    let backup_dir = tempfile::tempdir_in(&parent_display).with_context(|| {
        format!(
            "failed to reserve backup path in {}",
            parent_display.display()
        )
    })?;
    let backup_path = backup_dir.keep();
    let backup_name = backup_path
        .file_name()
        .with_context(|| format!("backup path has no file name: {}", backup_path.display()))?;
    pin.remove_dir(backup_name)
        .with_context(|| format!("failed to free backup path: {}", backup_path.display()))?;

    verify_destination_unchanged(&pin, &dest_name, dest_id, &dest_display)?;

    pin.rename(&dest_name, backup_name).with_context(|| {
        format!(
            "failed to move existing destination {} aside before replacing it",
            dest_display.display()
        )
    })?;

    let temp_path = temp_dir.keep();
    if let Err(e) = pin.rename(&temp_name, &dest_name) {
        // Restore the original destination; the new extraction is discarded.
        // The restore's own outcome must be checked, not assumed: claiming
        // "restored" when the rename-back itself failed would tell the user
        // their data is safe while it actually sits at an unprinted temp path.
        let restore_result = pin.rename(backup_name, &dest_name);
        // Path-based, but safe: std's Unix `remove_dir_all` has been
        // `O_NOFOLLOW`-rooted and fd-recursive since the CVE-2022-21658
        // hardening, so it cannot be tricked into descending a planted
        // symlink; a redirected `parent` at worst removes an
        // attacker-planted directory at the redirected location.
        let _ = std::fs::remove_dir_all(&temp_path);
        return Err(e).with_context(|| match restore_result {
            Ok(()) => format!(
                "failed to move extracted content into {}; original destination restored",
                dest_display.display()
            ),
            Err(restore_err) => format!(
                "failed to move extracted content into {}; the original destination could NOT \
                 be restored ({restore_err}) — its original contents are preserved at {} and \
                 must be recovered manually",
                dest_display.display(),
                backup_path.display()
            ),
        });
    }

    // Path-based, same CVE-2022-21658 rationale as above.
    let _ = std::fs::remove_dir_all(&backup_path);

    Ok(report)
}

/// Aborts with a distinct, actionable error if `pin`'s entry `name` no
/// longer identifies `expected`, or is no longer a directory at all.
///
/// Called by [`run_atomic_force_extraction`] immediately before the
/// destructive first swap rename. `display` is used only to build the error
/// message (it is expected to be the same path `name` was resolved from).
fn verify_destination_unchanged(
    pin: &PinnedDir,
    name: &OsStr,
    expected: (u64, u64),
    display: &Path,
) -> Result<()> {
    let (kind, current) = pin.entry_status(name).with_context(|| {
        format!(
            "failed to inspect destination before swap: {}",
            display.display()
        )
    })?;
    if kind != DestEntryKind::Directory || current != expected {
        anyhow::bail!(
            "destination changed on disk during extraction; refusing to swap: {}",
            display.display()
        );
    }
    Ok(())
}

/// Determines whether `--atomic --force` must replace the destination via
/// [`run_atomic_force_extraction`], resolving and pinning everything the
/// swap will need.
///
/// Returns `Ok(None)` whenever nothing can pre-exist at the destination
/// (nothing to swap, so the caller falls through to core's own atomic
/// extraction), and `Ok(Some(_))` only once the destination has been
/// confirmed to be a real, on-disk directory reachable through the pinned
/// parent.
///
/// A pre-existing non-directory destination (a regular file, a symlink to
/// one, etc.) is rejected with an error rather than silently replaced —
/// that would reproduce the exact data-loss class #519 was filed for, just
/// on a different destination type. This is a deliberate asymmetry: the
/// same condition on a non-final path *component* (a parent that turns out
/// to be a regular file, or is simply absent) only routes to `Ok(None)`,
/// because there the object in question isn't the thing that would be
/// destroyed — it only tells us there is nothing to destroy.
///
/// On Unix this now requires read permission on the destination's parent
/// directory for *every* `--atomic --force` invocation, including when the
/// destination does not yet exist — the pin below is unconditional, unlike
/// the old `exists()`-gated flow (see `PinnedDir::open`'s doc comment).
fn resolve_atomic_force_replace(
    args: &ExtractArgs,
    output_dir: &Path,
) -> Result<Option<AtomicForceTarget>> {
    if !(args.atomic && args.force) {
        return Ok(None);
    }

    // `dest_name` must stay `file_name()`-derived: `file_name()` strips a
    // trailing separator, and a trailing separator makes even
    // `SYMLINK_NOFOLLOW` resolve through the symlink (`"link/"` -> target).
    let (parent_path, dest_name): (PathBuf, OsString) = match output_dir.file_name() {
        Some(name) => {
            // `parent()` is `None` only for the root or an empty path, both
            // of which have no `file_name()` either — this branch is only
            // reached when `file_name()` was `Some`, so `parent()` here is
            // always `Some`, possibly empty (`Path::new("dest").parent()`
            // is `Some("")`).
            let parent = match output_dir.parent() {
                Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
                _ => PathBuf::from("."),
            };
            (parent, name.to_os_string())
        }
        // `output_dir` is/ends in `.`, `..`, or `/`: there is no
        // `file_name()`-derivable final component to take by path, so
        // resolve the whole thing through `canonicalize()` instead and take
        // its (already slash-free) `file_name()`.
        None => match output_dir.canonicalize() {
            Ok(canonical) => {
                let parent = canonical
                    .parent()
                    .with_context(|| {
                        format!("destination has no parent: {}", output_dir.display())
                    })?
                    .to_path_buf();
                let dest_name = canonical
                    .file_name()
                    .with_context(|| {
                        format!("destination has no file name: {}", output_dir.display())
                    })?
                    .to_os_string();
                (parent, dest_name)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("failed to resolve destination: {}", output_dir.display())
                });
            }
        },
    };

    let canonical_parent = match parent_path.canonicalize() {
        Ok(c) => c,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(None);
        }
        Err(e) => {
            return Err(e).with_context(|| {
                format!(
                    "failed to resolve destination parent: {}",
                    parent_path.display()
                )
            });
        }
    };

    // Every error here is a hard failure, never a silent `Ok(None)`: step 3
    // above already established that `canonical_parent` exists, so any
    // failure opening it now means either it changed underneath us or
    // permissions are wrong — both must fail closed rather than falling
    // through to the unprotected path. Note this is a strictly broader
    // permission requirement than the old path-based flow: it now applies
    // even when nothing pre-exists at the destination, since the `exists()`
    // gate that used to skip straight to `Ok(None)`/`Ok(false)` is gone.
    let pin = PinnedDir::open(&canonical_parent).with_context(|| {
        format!(
            "failed to pin destination parent: {}",
            canonical_parent.display()
        )
    })?;

    let dest_display = canonical_parent.join(&dest_name);
    let (kind, dest_id) = match pin.entry_status(&dest_name) {
        Ok(status) => status,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e).with_context(|| {
                format!("failed to inspect destination: {}", dest_display.display())
            });
        }
    };

    match kind {
        DestEntryKind::Directory => {}
        DestEntryKind::Symlink => anyhow::bail!(
            "cannot use --atomic --force: destination {} is a symlink; pass the resolved \
             target path instead",
            dest_display.display()
        ),
        DestEntryKind::Other => anyhow::bail!(
            "cannot use --atomic --force: destination {} already exists and is not a directory",
            dest_display.display()
        ),
    }

    Ok(Some(AtomicForceTarget {
        pin,
        dest_name,
        dest_id,
        parent_display: canonical_parent,
        dest_display,
    }))
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
    let atomic_force_target = resolve_atomic_force_replace(args, &output_dir)?;

    let options = ExtractionOptions::default()
        .with_atomic(args.atomic && atomic_force_target.is_none())
        .with_skip_duplicates(!args.force);

    let mut progress: Box<dyn ProgressCallback> = if verbose {
        Box::new(VerboseProgress::new())
    } else if !quiet && CliProgress::should_show() {
        Box::new(CliProgress::new(entry_count, "Extracting"))
    } else {
        Box::new(NoopProgress)
    };

    let report = if let Some(target) = atomic_force_target {
        run_atomic_force_extraction(
            &args.archive,
            target,
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

    /// Regression test for critic finding S2: the identity-mismatch abort
    /// branch in [`run_atomic_force_extraction`] previously had zero test
    /// coverage — only the OS-level property it relies on
    /// (`PinnedDir::entry_status` differing for different inodes) was
    /// tested, not this code's use of it. Exercises both outcomes of
    /// [`verify_destination_unchanged`] directly: unchanged passes, and a
    /// destination swapped for a freshly created replacement with the same
    /// name is rejected with the distinct "refusing to swap" message.
    #[test]
    #[cfg(unix)]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn verify_destination_unchanged_detects_a_swapped_destination() {
        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).expect("create parent");
        let dest = parent.join("dest");
        std::fs::create_dir(&dest).expect("create dest");

        let pin = PinnedDir::open(&parent).expect("pin parent");
        let dest_name = OsStr::new("dest");
        let (_, expected) = pin.entry_status(dest_name).expect("snapshot identity");

        verify_destination_unchanged(&pin, dest_name, expected, &dest)
            .expect("unchanged destination must pass verification");

        std::fs::rename(&dest, parent.join("dest.old")).expect("move dest aside");
        std::fs::create_dir(&dest).expect("create replacement dest");

        let err = verify_destination_unchanged(&pin, dest_name, expected, &dest)
            .expect_err("swapped destination must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("destination changed on disk during extraction; refusing to swap"),
            "error must carry the distinct refusing-to-swap message, got: {msg}"
        );
    }

    /// Regression test for the v3 spec's `verify_destination_unchanged`
    /// change: the identity check alone is not enough once the entry can be
    /// swapped for a *same-inode-impossible* but differently-kinded
    /// replacement — specifically, the destination being replaced with a
    /// symlink must be rejected by the explicit `DestEntryKind::Directory`
    /// assertion, not just by an identity mismatch (which a real attacker
    /// cannot control precisely enough to rely on alone).
    #[test]
    #[cfg(unix)]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn verify_destination_unchanged_detects_destination_replaced_with_symlink() {
        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).expect("create parent");
        let dest = parent.join("dest");
        std::fs::create_dir(&dest).expect("create dest");
        let decoy = root.path().join("decoy");
        std::fs::create_dir(&decoy).expect("create decoy");

        let pin = PinnedDir::open(&parent).expect("pin parent");
        let dest_name = OsStr::new("dest");
        let (_, expected) = pin.entry_status(dest_name).expect("snapshot identity");

        std::fs::remove_dir(&dest).expect("remove dest");
        std::os::unix::fs::symlink(&decoy, &dest).expect("plant symlink over dest");

        let err = verify_destination_unchanged(&pin, dest_name, expected, &dest)
            .expect_err("destination replaced with a symlink must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("destination changed on disk during extraction; refusing to swap"),
            "error must carry the distinct refusing-to-swap message, got: {msg}"
        );
    }

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
