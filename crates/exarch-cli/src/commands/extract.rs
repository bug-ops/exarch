//! Extract command implementation.

use crate::cli::BannedComponentsArg;
use crate::cli::DecodeReuseArg;
use crate::cli::ExtractArgs;
use crate::cli::ListToken;
use crate::commands::CommandResult;
use crate::commands::Outcome;
use crate::commands::atomic_swap;
use crate::commands::atomic_swap::DestEntryKind;
use crate::commands::atomic_swap::EntryName;
use crate::commands::atomic_swap::FileIdentity;
use crate::commands::atomic_swap::IdentityCheck;
use crate::commands::atomic_swap::PinnedDir;
use crate::error::CliContext;
use crate::error::Message;
use crate::error::add_archive_context;
use crate::error::convert_error;
use crate::operation::Flag;
use crate::operation::Operation;
use crate::output::OutputFormatter;
use crate::output::OutputMode;
use crate::progress::BarLength;
use crate::progress::progress_for;
use anyhow::Context;
use anyhow::Result;
use exarch_core::ArchiveEntry;
use exarch_core::ArchiveError;
use exarch_core::ArchiveManifest;
use exarch_core::ConfigSetting;
use exarch_core::DecodeReuse;
use exarch_core::Extension;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::ExtractionReport;
use exarch_core::ExtractionWarning;
use exarch_core::LandingKind;
use exarch_core::ListOptions;
use exarch_core::ListRequest;
use exarch_core::ListedArchive;
use exarch_core::ListedExtractOptions;
use exarch_core::ManifestEntryKind;
use exarch_core::PathComponentName;
use exarch_core::ProgressCallback;
use exarch_core::SecurityConfig;
use exarch_core::StoredTargets;
use exarch_core::Violation;
use exarch_core::formats::detect::ArchiveType;
use exarch_core::formats::detect::detect_format;
use exarch_core::non_zero_usize;
use exarch_core::path_text;
use std::cell::Cell;
use std::env;
use std::io;
use std::path::Path;
use std::path::PathBuf;

/// Where [`run_extraction`] writes, which decides what a stopped run leaves.
#[derive(Clone, Copy)]
enum Staging {
    /// Straight into the destination (or core's own atomic staging).
    Direct,
    /// Into a staging directory the CLI discards on failure.
    Discarded,
}

/// What [`run_extraction`] reads the archive from.
enum Source {
    /// The archive file, decoded as extraction reads it.
    Archive,
    /// An archive already listed, which may hold its decoded stream.
    Listed(ListedArchive),
}

fn run_extraction(
    archive: &Path,
    source: Source,
    output_dir: &Path,
    config: &SecurityConfig,
    options: &ExtractionOptions,
    progress: &mut dyn ProgressCallback,
    staging: Staging,
) -> Result<ExtractionReport> {
    let result = match source {
        Source::Archive => ExtractRequest::new(config)
            .with_options(options.clone())
            .with_progress(progress)
            .extract(archive, output_dir),
        Source::Listed(listed) => {
            let listed_options = ListedExtractOptions::default()
                .with_atomic(options.atomic)
                .with_skip_duplicates(options.skip_duplicates);
            listed.extract(output_dir, &listed_options, progress)
        }
    }
    .map_err(|err| match staging {
        Staging::Direct => err,
        Staging::Discarded => err.rolled_back(),
    });
    add_archive_context(Operation::Extract, result, archive)
}

/// Everything [`run_atomic_force_extraction`] needs, resolved and pinned by
/// [`resolve_atomic_force_replace`] before extraction starts.
struct AtomicForceTarget {
    /// The destination's parent, pinned by an open file descriptor.
    pin: PinnedDir,
    /// The destination's final path component, a single-component
    /// [`EntryName`] so no pinned operation can leave the pinned directory.
    dest_name: EntryName,
    /// The [`FileIdentity`] `entry_status` reported for `dest_name`
    /// when it confirmed the destination was a directory, carried forward
    /// rather than re-derived so the kind/identity pair snapshotted here is
    /// the one [`verify_destination_unchanged`] rechecks against.
    dest_id: FileIdentity,
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
    source: Source,
    target: AtomicForceTarget,
    config: &SecurityConfig,
    options: &ExtractionOptions,
    progress: &mut dyn ProgressCallback,
) -> Result<ExtractionReport> {
    let restore_failure = RestoreSlot::new(None);
    extract_and_swap(
        archive,
        source,
        target,
        config,
        options,
        progress,
        &restore_failure,
    )
    .map_err(|err| match restore_failure.take() {
        Some(failure) => err.context(failure.describe()),
        None => err,
    })
}

fn extract_and_swap(
    archive: &Path,
    source: Source,
    target: AtomicForceTarget,
    config: &SecurityConfig,
    options: &ExtractionOptions,
    progress: &mut dyn ProgressCallback,
    restore_failure: &RestoreSlot,
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
    // name failure can never surface *after* the destination has already
    // been moved aside with no way to name the replacement.
    let temp_name = EntryName::of(temp_dir.path()).with_context(|| {
        format!(
            "temp path has no usable file name: {}",
            temp_dir.path().display()
        )
    })?;
    // Captured fd-relative through `pin` rather than by re-resolving a path:
    // a `canonicalize`-based check here would be a no-op for the same
    // structural reason it was pre-#535 (`parent_display` is already fully
    // resolved), so it could never detect the parent redirect issue #530 is
    // about. This identity is what every disclosure check below confirms
    // against - "is *our* directory still present under `temp_name`", not
    // just "is something present under that name".
    let (_, temp_id) = pin.entry_status(&temp_name).with_context(|| {
        format!(
            "failed to inspect newly created temp directory: {}",
            parent_display.join(&temp_name).display()
        )
    })?;

    let temp_ref = TempOrphanRef {
        pin: &pin,
        name: &temp_name,
        id: temp_id,
        parent_display: &parent_display,
    };

    let mut report = run_extraction(
        archive,
        source,
        temp_dir.path(),
        config,
        options,
        progress,
        Staging::Discarded,
    )
    .with_context(|| temp_ref.disclose("extraction interrupted"))?;

    let displaced = DisplacedDestination::displace(
        &temp_ref,
        &dest_name,
        dest_id,
        &dest_display,
        restore_failure,
    )?;

    if let Err(e) = pin.rename(&temp_name, &dest_name) {
        // The restore's own outcome must be checked, not assumed: claiming
        // "restored" when the rename-back itself failed would tell the user
        // their data is safe while it actually sits at an unprinted temp path.
        let backup_path = displaced.backup_path().to_path_buf();
        let restore_result = displaced.restore();
        return Err(e).with_context(|| {
            describe_final_swap_failure(&temp_ref, &dest_display, &backup_path, restore_result)
        });
    }

    displaced.discard(&mut report);

    Ok(report)
}

/// Why a displaced destination could not be put back by
/// [`DisplacedDestination`]'s drop, and where its content then is.
#[derive(Debug)]
struct RestoreFailure {
    error: io::Error,
    backup_path: PathBuf,
}

impl RestoreFailure {
    fn describe(&self) -> String {
        format!(
            "the original destination could NOT be restored ({}) - its original contents are \
             preserved at {} and must be recovered manually",
            self.error,
            self.backup_path.display()
        )
    }
}

/// Where a dropped [`DisplacedDestination`] records a failed restore, for the
/// command to report.
type RestoreSlot = Cell<Option<RestoreFailure>>;

/// The pre-existing destination, moved aside to a backup name until the swap
/// completes.
///
/// A guard: dropping it while armed (an early `?`, a panic) renames the
/// backup back to the destination name, best effort, and records a failure in
/// the caller's [`RestoreSlot`]. [`restore`](Self::restore) and
/// [`discard`](Self::discard) consume it and disarm the drop.
#[must_use = "dropping a displaced destination restores it"]
struct DisplacedDestination<'a> {
    pin: &'a PinnedDir,
    dest_name: &'a EntryName,
    backup_name: EntryName,
    backup_path: PathBuf,
    backup_id: Option<FileIdentity>,
    failure: &'a RestoreSlot,
    armed: bool,
}

impl<'a> DisplacedDestination<'a> {
    /// Reserves a unique, currently-vacant sibling path in
    /// `temp.parent_display` to hold the pre-existing destination, then
    /// renames it there, returning the guard once the original destination is
    /// confirmed safely at that name.
    ///
    /// Renaming onto an existing path (even an empty directory) is
    /// unsupported on Windows, so the reserved path is freed (removed) again
    /// immediately after creation, before the destination is renamed onto it.
    /// Every error before the rename also runs [`disclose_if_orphaned`] on
    /// the temp directory identified by `temp`, since the extraction that
    /// landed there has already succeeded by the time this is called.
    fn displace(
        temp: &TempOrphanRef<'a>,
        dest_name: &'a EntryName,
        dest_id: FileIdentity,
        dest_display: &Path,
        failure: &'a RestoreSlot,
    ) -> Result<Self> {
        let backup_dir = tempfile::tempdir_in(temp.parent_display).with_context(|| {
            temp.disclose(&format!(
                "failed to reserve backup path in {}",
                temp.parent_display.display()
            ))
        })?;
        let backup_path = backup_dir.keep();
        let backup_name = EntryName::of(&backup_path).with_context(|| {
            temp.disclose(&format!(
                "backup path has no usable file name: {}",
                backup_path.display()
            ))
        })?;
        temp.pin.remove_dir(&backup_name).with_context(|| {
            temp.disclose(&format!(
                "failed to free backup path: {}",
                backup_path.display()
            ))
        })?;

        verify_destination_unchanged(temp.pin, dest_name, dest_id, dest_display).with_context(
            || temp.disclose("extraction already completed; destination changed underneath it"),
        )?;

        temp.pin.rename(dest_name, &backup_name).with_context(|| {
            temp.disclose(&format!(
                "failed to move existing destination {} aside before replacing it",
                dest_display.display()
            ))
        })?;
        // Captured right after the destination genuinely landed at
        // `backup_name` (before this rename it was `backup_dir`'s empty
        // placeholder, whose identity is irrelevant): the same fd-relative
        // pattern as `temp_id`, used so a failure to remove this backup after
        // a successful swap can be disclosed instead of silently discarded.
        //
        // Best-effort, not `?`: the destination has already been renamed to
        // `backup_name`, past the point of an easy return. A failure to
        // *inspect* the backup must never abort an otherwise-successful swap;
        // `discard` simply skips its warning if the identity was never
        // captured, the same "don't claim without confirmation" principle
        // `survival_clause`'s mismatch arm applies.
        let backup_id = temp.pin.entry_status(&backup_name).ok().map(|(_, id)| id);

        Ok(Self {
            pin: temp.pin,
            dest_name,
            backup_name,
            backup_path,
            backup_id,
            failure,
            armed: true,
        })
    }

    fn backup_path(&self) -> &Path {
        &self.backup_path
    }

    /// Renames the backup back to the destination name and disarms the guard.
    fn restore(mut self) -> io::Result<()> {
        self.armed = false;
        self.pin.rename(&self.backup_name, self.dest_name)
    }

    /// Removes the backup after a successful swap and disarms the guard; if
    /// removal fails and the entry at the backup name still identifies as the
    /// backup, records a warning on `report` instead of silently discarding
    /// the failure. Path-based, but safe for the same CVE-2022-21658
    /// (`O_NOFOLLOW`-rooted, fd-recursive `remove_dir_all`) reason as every
    /// other best-effort removal in this module.
    ///
    /// With no captured backup identity there is nothing to confirm the
    /// removal missed against, so this declines to warn rather than claiming a
    /// match it cannot verify.
    fn discard(mut self, report: &mut ExtractionReport) {
        self.armed = false;
        let Err(cleanup_err) = std::fs::remove_dir_all(&self.backup_path) else {
            return;
        };
        let Some(backup_id) = self.backup_id else {
            return;
        };
        let Ok((_, observed)) = self.pin.entry_status(&self.backup_name) else {
            return;
        };
        let identity_unverified = match observed.check(backup_id) {
            IdentityCheck::Same => false,
            IdentityCheck::Unknown => true,
            IdentityCheck::Different => return,
        };
        report.add_warning(ExtractionWarning::BackupCleanupFailed {
            path: self.backup_path.clone(),
            identity_unverified,
            error: cleanup_err.to_string(),
        });
    }
}

impl Drop for DisplacedDestination<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Err(error) = self.pin.rename(&self.backup_name, self.dest_name) {
            self.failure.set(Some(RestoreFailure {
                error,
                backup_path: self.backup_path.clone(),
            }));
        }
    }
}

/// Returns a disclosure clause naming where surviving content can be found,
/// or `None` if nothing under `name` still identifies as `expected_id` (i.e.
/// it was genuinely removed, or something unrelated now occupies the name).
/// Where identity is unverifiable, an entry present under `name` is disclosed
/// with a caveat rather than silently assumed to be ours or not.
///
/// When content survives, the disclosed path is resolved fresh from an
/// fd opened on the surviving entry itself ([`PinnedDir::open_entry`] +
/// [`atomic_swap::current_path`]), not by joining `name` onto
/// `parent_display`: `entry_status` confirming survival only proves the
/// content still exists *somewhere* linked from the pinned parent — it does
/// not prove `parent_display` (a plain, possibly stale display string) still
/// resolves there. Live-verified (issue #530 round 3): a redirect that
/// stays in place through this check makes `parent_display.join(name)`
/// resolve into the *decoy*, not the real content, even though the identity
/// check correctly confirms the real content survives. Falls back to the
/// logical path, with a caveat, only if fd-to-path resolution is
/// unavailable (non-Linux, non-macOS) or itself fails.
fn survival_clause(
    pin: &PinnedDir,
    name: &EntryName,
    expected_id: FileIdentity,
    parent_display: &Path,
) -> Option<String> {
    match pin.entry_status(name) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Ok((_, observed)) => match observed.check(expected_id) {
            IdentityCheck::Same => Some(surviving_content_clause(
                pin,
                name,
                expected_id,
                parent_display,
            )),
            IdentityCheck::Unknown => Some(format!(
                "an entry remains at {} whose identity could not be verified on this platform; \
                 it may be partial content from this run",
                parent_display.join(name).display()
            )),
            // Something else now occupies the name (a decoy left by a
            // redirect, or an unrelated benign reuse) — it is not ours to
            // claim, so no disclosure is made for it either.
            IdentityCheck::Different => None,
        },
        Err(e) => Some(format!(
            "whether partial content survived cleanup could not be determined ({e})"
        )),
    }
}

/// Builds the disclosure for content confirmed to survive under `name`,
/// resolving its real path from an fd on the entry itself.
fn surviving_content_clause(
    pin: &PinnedDir,
    name: &EntryName,
    expected_id: FileIdentity,
    parent_display: &Path,
) -> String {
    let real_path = pin
        .open_entry(name)
        .ok()
        .and_then(|fd| atomic_swap::current_path(&fd));
    real_path.map_or_else(
        || unresolved_survival_message(expected_id, parent_display, name),
        |path| {
            format!(
                "partial content survived cleanup and remains at {}",
                path.display()
            )
        },
    )
}

/// Builds the disclosure message for confirmed-surviving content whose
/// current path could not be resolved — `PinnedDir::open_entry` or
/// [`atomic_swap::current_path`] failed or (on platforms other than Linux
/// and macOS) isn't implemented. Deliberately does not say *why*: a genuine
/// runtime failure (`/proc` unmounted, `getpath` erroring) is not a
/// "platform limitation", so this only states the fact that resolution
/// failed, not a claimed cause (S2, review of #530 round 4).
///
/// A [`FileIdentity::Known`] identity gives an operator a `find`-based
/// fallback. [`FileIdentity::Unknown`] has nothing to print and no portable
/// by-inode lookup exists, so that message stays plain.
fn unresolved_survival_message(
    expected_id: FileIdentity,
    parent_display: &Path,
    name: &EntryName,
) -> String {
    match expected_id {
        FileIdentity::Known { dev, ino } => format!(
            "partial content survived cleanup (device {dev}, inode {ino}); its current path \
             could not be resolved — {} may no longer lead there if the containing directory has \
             itself been redirected, in which case locate it via `find <volume-root> -xdev -inum \
             {ino}`",
            parent_display.join(name).display()
        ),
        FileIdentity::Unknown => format!(
            "partial content survived cleanup at an unresolvable path; {} may no longer lead \
             there if the containing directory has itself been redirected",
            parent_display.join(name).display()
        ),
    }
}

/// Best-effort removes the directory `name` (resolved by joining
/// `parent_display`, the same *logical* path every other path-based
/// operation in [`run_atomic_force_extraction`] uses), then appends
/// [`survival_clause`]'s disclosure to `base_message` if it is still
/// present under `name` afterward, identified by `expected_id` — the
/// [`FileIdentity`] `pin.entry_status` reported when this directory was
/// created (fd-relative, so unaffected by a later redirect).
///
/// In the ordinary case this removal succeeds: `parent_display` was never
/// redirected, so it names the same directory `expected_id` identifies,
/// removing it leaves nothing under `name`, and no clause is appended —
/// matching pre-#530 behavior of silent, automatic cleanup on an ordinary
/// failure (unconditional disclosure was tried and reverted: it leaves a
/// partial-extraction directory behind on every failure, not just the race
/// this issue is about). In the #530 race, `parent_display` was redirected
/// mid-extraction: this removal, still path-based, can target a decoy at
/// the redirected location instead of the real directory — but the
/// `pin.entry_status` check afterward is fd-relative to the *pinned*
/// parent, immune to that same redirect, so it still correctly reports the
/// real directory's survival.
///
/// This detects and discloses survival of *this specific, identity-checked
/// directory* — it cannot discover content written to a *different*,
/// redirect-created decoy directory if the redirect happens mid-extraction
/// and is reverted before this check runs: `exarch-core`'s own per-entry
/// writes during extraction are path-based and re-resolve on every entry,
/// which is out of scope for this fix to make fd-relative (see the original
/// issue). That narrower case remains a genuine, undisclosed orphan — the
/// same class of accepted residual this module already documents elsewhere
/// (e.g. [`verify_destination_unchanged`]'s doc comment, and the non-Unix
/// `entry_status`'s [`FileIdentity::Unknown`], which survival disclosure
/// reports with a caveat instead of a verified match).
fn disclose_if_orphaned(
    pin: &PinnedDir,
    name: &EntryName,
    expected_id: FileIdentity,
    parent_display: &Path,
    base_message: &str,
) -> String {
    let _ = std::fs::remove_dir_all(parent_display.join(name));
    survival_clause(pin, name, expected_id, parent_display).map_or_else(
        || base_message.to_string(),
        |clause| format!("{base_message}; {clause}"),
    )
}

/// The temp directory's `pin`/`name`/`id`/`parent_display` identifiers,
/// bundled once so [`run_atomic_force_extraction`] and the functions it
/// calls can thread them to every [`disclose_if_orphaned`] call site without
/// repeating the same four parameters at each one. Performs no cleanup
/// itself — it only carries the identity `disclose` checks a cleanup
/// against.
struct TempOrphanRef<'a> {
    pin: &'a PinnedDir,
    name: &'a EntryName,
    id: FileIdentity,
    parent_display: &'a Path,
}

impl TempOrphanRef<'_> {
    /// Forwards to [`disclose_if_orphaned`] with this reference's identity.
    fn disclose(&self, base_message: &str) -> String {
        disclose_if_orphaned(
            self.pin,
            self.name,
            self.id,
            self.parent_display,
            base_message,
        )
    }
}

/// Builds the context message for the final swap-rename failure branch of
/// [`run_atomic_force_extraction`].
///
/// Reports, in order: whether the original destination could be restored
/// from `backup_path`, and (via [`disclose_if_orphaned`]) whether the
/// discarded extracted content identified by `temp`'s id is still present
/// under `temp`'s name — disclosed rather than assumed cleaned up, since a
/// failed or misdirected removal leaves that content as exactly the kind of
/// orphan issue #530 was filed for.
fn describe_final_swap_failure(
    temp: &TempOrphanRef<'_>,
    dest_display: &Path,
    backup_path: &Path,
    restore_result: io::Result<()>,
) -> String {
    let restored = match restore_result {
        Ok(()) => format!(
            "failed to move extracted content into {}; original destination restored",
            dest_display.display()
        ),
        Err(restore_err) => format!(
            "failed to move extracted content into {}; the original destination could NOT be \
             restored ({restore_err}) — its original contents are preserved at {} and must be \
             recovered manually",
            dest_display.display(),
            backup_path.display()
        ),
    };
    temp.disclose(&restored)
}

/// Aborts with a distinct, actionable error if `pin`'s entry `name` is
/// known to differ from `expected`, or is no longer a directory at all. An
/// unverifiable identity ([`IdentityCheck::Unknown`]) is not a mismatch.
///
/// Called by [`run_atomic_force_extraction`] immediately before the
/// destructive first swap rename. `display` is used only to build the error
/// message (it is expected to be the same path `name` was resolved from).
fn verify_destination_unchanged(
    pin: &PinnedDir,
    name: &EntryName,
    expected: FileIdentity,
    display: &Path,
) -> Result<()> {
    let (kind, current) = pin.entry_status(name).with_context(|| {
        format!(
            "failed to inspect destination before swap: {}",
            display.display()
        )
    })?;
    // `Unknown` (no stable identity on this platform) proceeds on the kind
    // check alone: there is nothing to compare, and refusing would make
    // `--atomic --force` unusable there.
    let identity_changed = current.check(expected) == IdentityCheck::Different;
    if kind != DestEntryKind::Directory || identity_changed {
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
    mode: WriteMode,
    output_dir: &Path,
) -> Result<Option<AtomicForceTarget>> {
    if mode != WriteMode::AtomicReplace {
        return Ok(None);
    }

    // `dest_name` must stay `file_name()`-derived: `file_name()` strips a
    // trailing separator, and a trailing separator makes even
    // `SYMLINK_NOFOLLOW` resolve through the symlink (`"link/"` -> target).
    let (parent_path, dest_name): (PathBuf, EntryName) = match EntryName::of(output_dir) {
        Some(name) => {
            // `parent()` is `None` only for the root or an empty path, both
            // of which have no `file_name()` either — this branch is only
            // reached when `file_name()` was `Some`, so `parent()` here is
            // always `Some`, possibly empty (`Path::new("dest").parent()`
            // is `Some("")`).
            let parent = match output_dir.parent() {
                Some(p) if !p.is_empty() => p.to_path_buf(),
                _ => PathBuf::from("."),
            };
            (parent, name)
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
                let dest_name = EntryName::of(&canonical).with_context(|| {
                    format!("destination has no file name: {}", output_dir.display())
                })?;
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
            "cannot use {atomic} {force}: destination {} is a symlink; pass the resolved \
             target path instead",
            dest_display.display(),
            atomic = Flag::Atomic.long(),
            force = Flag::Force.long(),
        ),
        DestEntryKind::Other => anyhow::bail!(
            "cannot use {atomic} {force}: destination {} already exists and is not a directory",
            dest_display.display(),
            atomic = Flag::Atomic.long(),
            force = Flag::Force.long(),
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

/// Parses the `--allowed-extensions` items into [`Extension`]s: blank items
/// are dropped and the rest are parsed by the core constructor.
///
/// # Errors
///
/// Returns the core refusal, naming the offending item, for an entry that
/// can never match (for example `tar.gz` or `a/b`), and an error when values
/// were given but hold no extension at all (an empty list would allow every
/// extension).
fn parse_extensions(tokens: &[ListToken]) -> Result<Vec<Extension>> {
    let parsed = items(tokens)
        .map(|ext| {
            Extension::try_from(ext).with_context(|| {
                format!("invalid {} value {ext:?}", Flag::AllowedExtensions.long())
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if parsed.is_empty() && !tokens.is_empty() {
        anyhow::bail!("{} names no extension", Flag::AllowedExtensions.long());
    }
    Ok(parsed)
}

fn items(tokens: &[ListToken]) -> impl Iterator<Item = &str> {
    tokens.iter().filter_map(|token| match token {
        ListToken::Item(item) => Some(item.as_str()),
        ListToken::Empty | ListToken::Blank => None,
    })
}

/// Maximum number of conflicting destination paths listed individually in
/// the pre-flight conflict error before the remainder is collapsed into a
/// single "... and N more" summary line.
const MAX_LISTED_CONFLICTS: usize = 10;

/// Builds the pre-flight destination-conflict message for `conflicts`.
///
/// Caps the number of individually listed paths at [`MAX_LISTED_CONFLICTS`]
/// so an archive with many same-named pre-existing files (up to
/// `max_file_count`, 10000 by default) cannot flood stderr with one line per
/// conflict. `conflicts` is sorted before truncation so "first N shown" is a
/// deterministic, reproducible subset rather than whatever order the archive
/// manifest happened to yield.
fn conflict_message(conflicts: &[PathBuf], mode: WriteMode) -> Message {
    let count = conflicts.len();
    let noun = if count == 1 { "file" } else { "files" };
    let verb = if count == 1 { "exists" } else { "exist" };
    let force = Flag::Force.long();

    let mut sorted: Vec<&PathBuf> = conflicts.iter().collect();
    sorted.sort();

    let remaining = count.saturating_sub(MAX_LISTED_CONFLICTS);
    let advice = if mode == WriteMode::Force {
        format!("{force} cannot replace it with a directory")
    } else {
        format!("use {force} to overwrite")
    };
    let mut message = if remaining == 0 {
        Message::default().text(format!(
            "{count} destination {noun} already {verb} ({advice}):"
        ))
    } else {
        Message::default().text(format!(
            "{count} destination {noun} already {verb} ({advice}); first \
             {MAX_LISTED_CONFLICTS} shown:"
        ))
    };
    for path in sorted.into_iter().take(MAX_LISTED_CONFLICTS) {
        message = message.lit("\n  ").path(path);
    }
    if remaining > 0 {
        message = message
            .lit("\n  ... and ")
            .text(remaining.to_string())
            .lit(" more");
    }
    message
}

fn conflict_error(conflicts: &[PathBuf], mode: WriteMode) -> anyhow::Error {
    anyhow::Error::new(CliContext::new(
        conflict_message(conflicts, mode).into_parts(),
    ))
}

/// The ban list `--banned-component` asks for: `None` keeps the default list.
///
/// A lone empty value (`--banned-component ""`) is the documented idiom for
/// disabling the default ban list. Any other list must name a component, so a
/// typo such as `,` can never switch the bans off.
///
/// # Errors
///
/// Returns the core refusal, naming the offending value, for a component that
/// can never equal a single path component (for example `a/b` or `..`), and
/// an error for a list that names no component other than a lone `""`.
fn banned_components(tokens: &[ListToken]) -> Result<Option<Vec<PathComponentName>>> {
    match BannedComponentsArg::of(tokens) {
        BannedComponentsArg::Default => Ok(None),
        BannedComponentsArg::Replace(tokens) if tokens == [ListToken::Empty] => {
            Ok(Some(Vec::new()))
        }
        BannedComponentsArg::Replace(tokens) => {
            let components = items(&tokens)
                .map(|component| {
                    PathComponentName::try_from(component).with_context(|| {
                        format!(
                            "invalid {} value {component:?}",
                            Flag::BannedComponent.long()
                        )
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            if components.is_empty() {
                anyhow::bail!("{} names no component", Flag::BannedComponent.long());
            }
            Ok(Some(components))
        }
    }
}

/// Lists the archive before extraction: for conflict detection and the entry
/// count that drives the progress bar. Neither needs link targets, and
/// extraction reads them itself, so the listing leaves 7z targets undecoded.
///
/// Header-known 7z link targets (empty or oversized) are still checked here,
/// as `list` does whatever the link policy, so such a target fails with its own
/// error before extraction can say that symlinks are not allowed.
///
/// Every failure keeps the category message and hint extraction would give the
/// same error, since that is the error the user has to act on.
fn list_for_extract(
    archive: &Path,
    config: &SecurityConfig,
    reuse: DecodeReuse,
) -> Result<ListedArchive> {
    let options = ListOptions::default().with_stored_targets(StoredTargets::Skip);
    ListRequest::new(config)
        .with_options(options)
        .for_extraction(archive, reuse)
        .map_err(|err| convert_error(Operation::Extract, err, archive))
}

/// Whether nothing can exist at `output_dir` yet and its parent is an existing
/// directory.
///
/// Such a destination has no conflicts to look for and no pre-existing content
/// a failed run could damage, so a TAR extraction skips the list pass (a full
/// second decode of a compressed stream) and runs atomically instead: a
/// refusal leaves nothing behind and creates no parent directory. An empty
/// parent (`out/`) means the current directory.
fn is_fresh_destination(output_dir: &Path) -> bool {
    let absent = matches!(
        output_dir.symlink_metadata(),
        Err(ref e) if e.kind() == io::ErrorKind::NotFound
    );
    let parent = match output_dir.parent() {
        Some(p) if !p.is_empty() => p,
        _ => Path::new("."),
    };
    absent && parent.is_dir()
}

/// Whether `archive` is a TAR stream, the only family whose list pass costs a
/// second decode; ZIP and 7z list from their headers, and their list pass also
/// carries header-level diagnostics that extraction reports differently.
fn is_tar_archive(archive: &Path) -> bool {
    detect_format(archive).is_ok_and(ArchiveType::is_tar)
}

/// Whether extraction will write `entry` as a file: a file whose extension the
/// allowlist admits is written, any other is skipped.
fn is_extracted_file(entry: &ArchiveEntry, config: &SecurityConfig) -> bool {
    matches!(entry.kind, ManifestEntryKind::File { .. })
        && config.is_extension_allowed(entry.path.extension().and_then(|s| s.to_str()))
}

/// Number of entries the progress bar counts: every listed entry, or only the
/// files with an allowed extension when an extension filter is active.
fn listed_entry_count(manifest: &ArchiveManifest, config: &SecurityConfig) -> usize {
    if config.allowed_extensions.is_empty() {
        manifest.entries().len()
    } else {
        manifest
            .entries()
            .iter()
            .filter(|e| matches!(e.kind, ManifestEntryKind::File { .. }))
            .filter(|e| is_extracted_file(e, config))
            .count()
    }
}

/// The configuration the size, count, depth and ratio flags describe; a value
/// core refuses is returned as `InvalidConfiguration` naming the flag's
/// setting.
fn limited_config(args: &ExtractArgs) -> Result<SecurityConfig, ArchiveError> {
    let config = args.parallel.apply(
        args.zip.apply(
            args.links
                .apply(args.limits.apply(SecurityConfig::default())?),
        ),
    )?;
    match args.max_path_depth {
        Some(depth) => {
            Ok(config.with_max_path_depth(non_zero_usize(ConfigSetting::MaxPathDepth, depth)?))
        }
        None => Ok(config),
    }
}

/// How `--force` and `--atomic` combine, resolved once from the arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriteMode {
    /// Neither flag: existing files are conflicts and are refused up front.
    Safe,
    /// `--force`: existing files are overwritten in place.
    Force,
    /// `--atomic`: extraction is staged and renamed into place on success.
    Atomic,
    /// Both: staged, and swapped over an existing destination directory.
    AtomicReplace,
}

impl WriteMode {
    const fn of(args: &ExtractArgs) -> Self {
        match (args.force, args.atomic) {
            (false, false) => Self::Safe,
            (true, false) => Self::Force,
            (false, true) => Self::Atomic,
            (true, true) => Self::AtomicReplace,
        }
    }

    const fn overwrites(self) -> bool {
        matches!(self, Self::Force | Self::AtomicReplace)
    }

    const fn stages(self) -> bool {
        matches!(self, Self::Atomic | Self::AtomicReplace)
    }
}

/// Proof that the destination was checked for files the archive would
/// overwrite, or that the mode makes the check moot.
struct ConflictsChecked(());

impl ConflictsChecked {
    /// Refuses, before anything is written, a destination that cannot hold the
    /// archive.
    ///
    /// The core says every path extraction creates, the implied parent
    /// directories included, in the order it creates them, resolving absolute
    /// and Windows-prefixed names, `.` components and paths through earlier
    /// links as extraction does. Each landing is probed with
    /// `symlink_metadata`, so a conflict is reported at the path that holds
    /// it: a file at an implied parent is named there, not at the entry below
    /// it.
    ///
    /// In [`WriteMode::Safe`] anything at the landing of a file, link or
    /// hardlink conflicts, and so does a non-directory at the landing of a
    /// directory. In [`WriteMode::Force`] files are replaced by files, but a
    /// non-directory can never be replaced by a directory, so only landings
    /// that must be directories are checked. Staged modes write nothing into
    /// the destination until the end and are not checked.
    ///
    /// A symlink at a landing is not turned into a generic conflict: the
    /// refusal is the library's own typed one (an escaping link is a
    /// `SymlinkEscape`, a link that does not lead to a directory is refused
    /// like extraction does), and a link to a directory inside the destination
    /// is left to extraction, which accepts it under `--allow-symlinks` or
    /// refuses with that hint.
    ///
    /// # Errors
    ///
    /// The refusal, or a failure to inspect a landing other than its absence.
    fn check(
        mode: WriteMode,
        manifest: &ArchiveManifest,
        config: &SecurityConfig,
        output_dir: &Path,
        archive: &Path,
    ) -> Result<Self> {
        if !matches!(mode, WriteMode::Safe | WriteMode::Force) {
            return Ok(Self(()));
        }
        let root = output_dir.canonicalize().ok();
        let mut conflicts = Vec::new();
        for landing in manifest.landings(config) {
            let must_be_directory = matches!(
                landing.kind(),
                LandingKind::ImplicitParent
                    | LandingKind::Entry(ArchiveEntry {
                        kind: ManifestEntryKind::Directory,
                        ..
                    })
            );
            if mode == WriteMode::Force && !must_be_directory {
                continue;
            }
            let target = output_dir.join(landing.path().as_path());
            let occupant = match target.symlink_metadata() {
                Ok(occupant) => occupant,
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                // Below a conflict already reported at an ancestor.
                Err(err) if err.kind() == io::ErrorKind::NotADirectory && !conflicts.is_empty() => {
                    continue;
                }
                Err(err) => {
                    return Err(err)
                        .with_context(|| format!("failed to inspect {}", path_text(&target)));
                }
            };
            if occupant.file_type().is_symlink() {
                if let Some(refusal) = symlink_refusal(
                    landing.path().as_path(),
                    &target,
                    must_be_directory,
                    root.as_deref(),
                ) {
                    return Err(convert_error(Operation::Extract, refusal, archive));
                }
            } else if !(must_be_directory && occupant.is_dir()) {
                conflicts.push(target);
            }
        }

        if conflicts.is_empty() {
            Ok(Self(()))
        } else {
            Err(conflict_error(&conflicts, mode))
        }
    }
}

/// The library's refusal for a symlink at a landing, or `None` when the link
/// leads to a directory inside `root` and the landing must be a directory:
/// whether extraction may write through it is extraction's call.
fn symlink_refusal(
    rel: &Path,
    target: &Path,
    must_be_directory: bool,
    root: Option<&Path>,
) -> Option<ArchiveError> {
    let resolved = target.canonicalize().ok();
    let inside_root = resolved
        .as_deref()
        .zip(root)
        .is_some_and(|(resolved, root)| resolved.starts_with(root));
    if !must_be_directory {
        return Some(ArchiveError::from(Violation::ReplacesSymlink {
            rel: path_text(rel).into(),
        }));
    }
    match resolved {
        Some(resolved) if inside_root && resolved.is_dir() => None,
        Some(_) if !inside_root => Some(ArchiveError::SymlinkEscape {
            path: rel.to_path_buf(),
        }),
        _ => Some(ArchiveError::from(Violation::SymlinkParent {
            entry: path_text(rel).into(),
            parent: path_text(rel).into(),
        })),
    }
}

/// How an extraction runs, decided once from the write mode and the
/// destination; each variant fixes its own [`ExtractionOptions`], so core's
/// atomic staging cannot disagree with the CLI's own swap.
enum ExtractPlan {
    /// One streaming pass over the archive, staged by core.
    Stream { options: ExtractionOptions },
    /// Extraction from a listing, with the destination checked for conflicts.
    Listed {
        listed: ListedArchive,
        options: ExtractionOptions,
    },
    /// Extraction into a temp directory, then a swap over the existing
    /// destination; core staging is off.
    Replace {
        target: AtomicForceTarget,
        source: Source,
        options: ExtractionOptions,
    },
}

impl ExtractPlan {
    fn listed(
        listed: ListedArchive,
        options: ExtractionOptions,
        _conflicts: ConflictsChecked,
    ) -> Self {
        Self::Listed { listed, options }
    }

    fn manifest(&self) -> Option<&ArchiveManifest> {
        match self {
            Self::Listed { listed, .. }
            | Self::Replace {
                source: Source::Listed(listed),
                ..
            } => Some(listed.manifest()),
            Self::Stream { .. }
            | Self::Replace {
                source: Source::Archive,
                ..
            } => None,
        }
    }

    fn run(
        self,
        archive: &Path,
        output_dir: &Path,
        config: &SecurityConfig,
        progress: &mut dyn ProgressCallback,
    ) -> Result<ExtractionReport> {
        match self {
            Self::Stream { options } => run_extraction(
                archive,
                Source::Archive,
                output_dir,
                config,
                &options,
                progress,
                Staging::Direct,
            ),
            Self::Listed { listed, options } => run_extraction(
                archive,
                Source::Listed(listed),
                output_dir,
                config,
                &options,
                progress,
                Staging::Direct,
            ),
            Self::Replace {
                target,
                source,
                options,
            } => run_atomic_force_extraction(archive, source, target, config, &options, progress),
        }
    }
}

fn plan_extraction(
    args: &ExtractArgs,
    mode: WriteMode,
    output_dir: &Path,
    config: &SecurityConfig,
) -> Result<ExtractPlan> {
    let reuse = DecodeReuseArg::resolve(args.decode_reuse);

    // Under `--atomic` the list pass would only size the progress bar: no
    // conflict check runs and the staged extraction refuses on its own.
    let single_pass =
        is_tar_archive(&args.archive) && (mode.stages() || is_fresh_destination(output_dir));
    let listing = if single_pass {
        None
    } else {
        let listed = list_for_extract(&args.archive, config, reuse)?;
        let conflicts =
            ConflictsChecked::check(mode, listed.manifest(), config, output_dir, &args.archive)?;
        Some((listed, conflicts))
    };

    // --atomic + --force over a pre-existing destination needs a swap that
    // core's `extract_atomic` doesn't perform itself (it refuses to replace
    // an existing directory, by design, so a pre-existing destination is
    // never touched if extraction fails). The CLI performs that swap only
    // after extraction has already fully succeeded; see
    // `run_atomic_force_extraction`.
    let target = resolve_atomic_force_replace(mode, output_dir)?;

    let options = |atomic: bool| {
        ExtractionOptions::default()
            .with_atomic(atomic)
            .with_skip_duplicates(!mode.overwrites())
            .with_decode_reuse(reuse)
    };
    Ok(match (target, listing) {
        (Some(target), listing) => ExtractPlan::Replace {
            target,
            source: listing.map_or(Source::Archive, |(listed, _)| Source::Listed(listed)),
            options: options(false),
        },
        (None, Some((listed, conflicts))) => {
            ExtractPlan::listed(listed, options(mode.stages()), conflicts)
        }
        (None, None) => ExtractPlan::Stream {
            options: options(true),
        },
    })
}

pub fn execute(
    args: &ExtractArgs,
    formatter: &mut dyn OutputFormatter,
    mode: OutputMode,
) -> CommandResult {
    let output_dir = match &args.output_dir {
        Some(dir) => dir.clone(),
        None => env::current_dir().context("failed to get current directory")?,
    };

    let allowed_extensions = parse_extensions(&args.allowed_extensions)?;

    let config = limited_config(args)?
        .with_allow_absolute_paths(args.allow_absolute_paths)
        .with_allow_world_writable(args.allow_world_writable)
        .with_preserve_permissions(args.preserve_permissions)
        .with_allowed_extensions(allowed_extensions);

    let config = match banned_components(&args.banned_components)? {
        Some(components) => config.with_banned_path_components(components),
        None => config,
    };

    let plan = plan_extraction(args, WriteMode::of(args), &output_dir, &config)?;
    let length = plan.manifest().map_or(BarLength::Discover, |manifest| {
        BarLength::Known(listed_entry_count(manifest, &config))
    });
    let mut progress = progress_for(mode, length, Operation::Extract);
    let report = plan.run(&args.archive, &output_dir, &config, progress.as_mut())?;

    formatter.format_extraction_result(&report)?;

    Ok(Outcome::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(unix)]
    #[allow(clippy::expect_used)]
    fn entry(name: &str) -> EntryName {
        EntryName::of(Path::new(name)).expect("single component")
    }

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
        let dest_name = &entry("dest");
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
        let dest_name = &entry("dest");
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

    /// An unverifiable expected identity (the non-Unix case) is the explicit
    /// "proceed on the kind check alone" arm: a directory passes, but a
    /// symlink is still refused.
    #[test]
    #[cfg(unix)]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn verify_destination_unchanged_with_unknown_identity_relies_on_kind_only() {
        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).expect("create parent");
        let dest = parent.join("dest");
        std::fs::create_dir(&dest).expect("create dest");
        let decoy = root.path().join("decoy");
        std::fs::create_dir(&decoy).expect("create decoy");

        let pin = PinnedDir::open(&parent).expect("pin parent");
        let dest_name = &entry("dest");

        verify_destination_unchanged(&pin, dest_name, FileIdentity::Unknown, &dest)
            .expect("a directory with unverifiable identity must pass on kind alone");

        std::fs::remove_dir(&dest).expect("remove dest");
        std::os::unix::fs::symlink(&decoy, &dest).expect("plant symlink over dest");

        verify_destination_unchanged(&pin, dest_name, FileIdentity::Unknown, &dest)
            .expect_err("a symlink must be refused even when identity is unknown");
    }

    /// With an unverifiable expected identity, an entry still present under
    /// the name is disclosed with a caveat, not claimed as verified and not
    /// silently dropped.
    #[test]
    #[cfg(unix)]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn survival_clause_with_unknown_identity_discloses_with_caveat() {
        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).expect("create parent");
        let name = &entry("temp_dir");
        std::fs::create_dir(parent.join(name)).expect("create temp dir");

        let pin = PinnedDir::open(&parent).expect("pin parent");
        let clause = survival_clause(&pin, name, FileIdentity::Unknown, &parent)
            .expect("an entry that cannot be ruled out must be disclosed");
        assert!(
            clause.contains("identity could not be verified"),
            "caveat expected, got: {clause}"
        );
    }

    /// Regression test for issue #530: the ordinary case, where cleanup
    /// genuinely succeeds, must disclose nothing — asserted directly against
    /// [`disclose_if_orphaned`] rather than a live redirect race, which
    /// [`survival_clause`]'s `Ok((_, id)) if id == expected_id` branch makes
    /// unnecessary for deterministic coverage of this behavior.
    #[test]
    #[cfg(unix)]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn disclose_if_orphaned_ordinary_cleanup_discloses_nothing() {
        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).expect("create parent");
        let name = &entry("temp_dir");
        std::fs::create_dir(parent.join(name)).expect("create temp dir");

        let pin = PinnedDir::open(&parent).expect("pin parent");
        let (_, id) = pin.entry_status(name).expect("snapshot identity");

        let msg = disclose_if_orphaned(&pin, name, id, &parent, "extraction interrupted");

        assert_eq!(
            msg, "extraction interrupted",
            "successful cleanup must not disclose a path: {msg}"
        );
        assert!(
            !parent.join(name).exists(),
            "the directory must actually be gone, not just unclaimed"
        );
    }

    /// Regression test for issue #530: content that survives the best-effort
    /// cleanup attempt (here, forced by making the directory's own
    /// permissions block removing its content — analogous in effect, though
    /// not in cause, to a `remove_dir_all` that missed the real directory
    /// under a parent redirect) must be disclosed, and the disclosed path
    /// must genuinely still contain the surviving content.
    #[test]
    #[cfg(unix)]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn disclose_if_orphaned_discloses_surviving_content_with_matching_identity() {
        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).expect("create parent");
        let name = &entry("temp_dir");
        let target = parent.join(name);
        std::fs::create_dir(&target).expect("create temp dir");
        std::fs::write(target.join("payload.txt"), b"partial content").expect("write payload");
        // Entry removal needs write permission on the *containing* directory,
        // not the entry itself — this blocks `remove_dir_all` from removing
        // `payload.txt`, which leaves `target` itself non-empty and thus
        // un-`rmdir`-able too.
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o555))
            .expect("restrict temp dir permissions");

        let pin = PinnedDir::open(&parent).expect("pin parent");
        let (_, id) = pin.entry_status(name).expect("snapshot identity");

        let msg = disclose_if_orphaned(&pin, name, id, &parent, "extraction interrupted");

        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
            .expect("restore temp dir permissions");

        if !target.join("payload.txt").exists() {
            // DAC permission checks don't apply to root, so the restriction
            // above did nothing and cleanup genuinely succeeded — same
            // root-skip reasoning as
            // `parent_without_read_permission_is_rejected`
            // in `atomic_swap.rs`.
            eprintln!(
                "skipping: permission-restricted removal unexpectedly succeeded (running as \
                 root?)"
            );
            return;
        }

        assert!(
            msg.contains("partial content survived cleanup and remains at"),
            "surviving content must be disclosed: {msg}"
        );
        assert!(
            msg.contains(&target.display().to_string()),
            "disclosed message must name the surviving path: {msg}"
        );
    }

    /// Regression test for issue #530: an entry that now occupies `name` but
    /// is *not* the directory `disclose_if_orphaned` was checking on (a
    /// decoy left by a redirect, or an unrelated benign reuse of the name)
    /// must never be claimed as surviving orphaned content — that would
    /// misdirect an operator at data this code has no actual claim over.
    #[test]
    #[cfg(unix)]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn disclose_if_orphaned_does_not_disclose_on_identity_mismatch() {
        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).expect("create parent");
        let name = &entry("temp_dir");
        let target = parent.join(name);
        std::fs::create_dir(&target).expect("create original temp dir");

        let pin = PinnedDir::open(&parent).expect("pin parent");
        let (_, original_id) = pin.entry_status(name).expect("snapshot original identity");

        // Replace the original with a different directory under the same
        // name — created under a *different* name first, while the
        // original (at `name`) is still alive, then `rename()`d over it.
        // This guarantees the allocator hands out a genuinely distinct
        // inode, not just "whatever's currently free": a delete-then-recreate
        // sequence would instead depend on the filesystem not reusing the
        // just-freed inode number, which APFS happens not to do but ext4
        // readily does — flipping this test to a false identity match on
        // Linux CI (reviewer finding, #530). `rename()` onto an existing,
        // empty directory atomically replaces the dentry, so the surviving
        // inode under `name` is deterministically the replacement's on every
        // platform. Protected from `disclose_if_orphaned`'s own cleanup
        // attempt the same way the previous test protects its target, so the
        // mismatch is actually observed rather than removed before the check
        // runs.
        let replacement = parent.join("replacement_dir");
        std::fs::create_dir(&replacement)
            .expect("create replacement temp dir under a different name");
        std::fs::write(replacement.join("decoy.txt"), b"not ours").expect("write decoy content");
        std::fs::rename(&replacement, &target).expect("rename replacement over the original name");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o555))
            .expect("restrict replacement dir permissions");

        let msg = disclose_if_orphaned(&pin, name, original_id, &parent, "extraction interrupted");

        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
            .expect("restore replacement dir permissions");

        if !target.join("decoy.txt").exists() {
            eprintln!(
                "skipping: permission-restricted removal unexpectedly succeeded (running as \
                 root?)"
            );
            return;
        }

        assert_eq!(
            msg, "extraction interrupted",
            "content under a mismatched identity must not be claimed as our own orphaned data: \
             {msg}"
        );
    }

    /// Regression test for issue #530, round 3: statically simulates the
    /// exact parent-redirect scenario the developer live-verified with a
    /// real, timing-sensitive race (see the round-3 developer handoff) —
    /// deterministically, since the redirect only needs to happen *between*
    /// identity capture and disclosure, not concurrently with anything.
    /// Proves `disclose_if_orphaned` discloses the survivor's real, current
    /// location — resolved via [`survival_clause`]'s `open_entry` +
    /// [`atomic_swap::current_path`] — rather than the decoy sitting at the
    /// redirected logical path, or nothing at all. This is the specific gap
    /// the existing
    /// `disclose_if_orphaned_discloses_surviving_content_with_matching_identity`
    /// test cannot catch: without a redirect, the logical path and the real
    /// path are identical, so that test would pass even if disclosure fell
    /// back to the (wrong, in a real redirect) logical path.
    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn disclose_if_orphaned_discloses_real_path_through_a_redirected_parent() {
        let root = tempfile::tempdir().expect("tempdir");
        let real_parent = root.path().join("real_parent");
        std::fs::create_dir(&real_parent).expect("create real parent");
        let name = &entry("temp_dir");
        let target = real_parent.join(name);
        std::fs::create_dir(&target).expect("create temp dir");
        std::fs::write(target.join("payload.txt"), b"partial content").expect("write payload");

        let pin = PinnedDir::open(&real_parent).expect("pin real parent");
        let (_, id) = pin.entry_status(name).expect("snapshot identity");

        // Redirect `real_parent`'s logical path: move the real directory
        // aside and put a symlink to an empty decoy in its place. `pin`,
        // already opened before this, keeps identifying the real, now-moved
        // directory by fd; `real_parent` (passed below as `parent_display`)
        // no longer resolves there by path.
        let decoy = root.path().join("decoy");
        std::fs::create_dir(&decoy).expect("create decoy");
        let moved_real_parent = root.path().join("real_parent_moved");
        std::fs::rename(&real_parent, &moved_real_parent).expect("move real parent aside");
        std::os::unix::fs::symlink(&decoy, &real_parent).expect("plant symlink at old path");

        let msg = disclose_if_orphaned(&pin, name, id, &real_parent, "extraction interrupted");

        let real_content = moved_real_parent.join(name);
        assert!(
            msg.contains("partial content survived cleanup and remains at"),
            "content must be disclosed as surviving: {msg}"
        );
        assert!(
            msg.contains(&real_content.display().to_string()),
            "disclosed path must be the real, moved location, not the decoy or the stale \
             logical path: {msg}"
        );
        assert!(
            !msg.contains(&decoy.display().to_string()),
            "disclosed path must never point into the decoy: {msg}"
        );
        assert!(
            real_content.join("payload.txt").exists(),
            "the disclosed real directory must genuinely still contain the surviving content"
        );
    }

    /// The items clap would produce for the given raw flag values.
    fn tokens(raw: &[&str]) -> Vec<ListToken> {
        raw.iter()
            .flat_map(|value| value.split(','))
            .map(|item| {
                if item.is_empty() {
                    ListToken::Empty
                } else if item.trim().is_empty() {
                    ListToken::Blank
                } else {
                    ListToken::Item(item.trim().to_owned())
                }
            })
            .collect()
    }

    #[allow(clippy::unwrap_used)]
    fn extension_names(raw: &[&str]) -> Vec<String> {
        parse_extensions(&tokens(raw))
            .unwrap()
            .iter()
            .map(|e| e.as_str().to_owned())
            .collect()
    }

    #[test]
    fn parse_extensions_comma_split() {
        assert_eq!(extension_names(&["zip,tar,gz"]), vec!["zip", "tar", "gz"]);
    }

    #[test]
    fn parse_extensions_strips_leading_dot() {
        assert_eq!(extension_names(&[".zip", ".TAR"]), vec!["zip", "tar"]);
    }

    #[test]
    fn parse_extensions_trims_whitespace() {
        assert_eq!(
            extension_names(&[" zip , tar ", " gz"]),
            vec!["zip", "tar", "gz"]
        );
    }

    #[test]
    fn parse_extensions_lowercases() {
        assert_eq!(extension_names(&["ZIP", "Txt"]), vec!["zip", "txt"]);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn parse_extensions_refuses_an_inner_dot() {
        for raw in ["tar.gz", "A.TXT", "a/b"] {
            let err = parse_extensions(&tokens(&[raw])).unwrap_err();
            assert!(format!("{err:#}").contains(raw), "{err:#}");
        }
    }

    #[test]
    fn parse_extensions_empty_input() {
        assert!(extension_names(&[]).is_empty());
    }

    #[test]
    fn parse_extensions_refuses_values_without_any_extension() {
        for raw in [",", " ", ""] {
            assert!(parse_extensions(&tokens(&[raw])).is_err(), "{raw:?}");
        }
    }

    #[test]
    fn parse_extensions_filters_empty_tokens() {
        assert_eq!(extension_names(&["zip,,tar, ,"]), vec!["zip", "tar"]);
    }

    #[test]
    fn parse_extensions_mixed_repeatable_and_comma() {
        assert_eq!(
            extension_names(&["zip,tar", ".GZ"]),
            vec!["zip", "tar", "gz"]
        );
    }

    #[allow(clippy::unwrap_used)]
    fn banned_names(raw: &[&str]) -> Option<Vec<String>> {
        banned_components(&tokens(raw))
            .unwrap()
            .map(|c| c.iter().map(|n| n.as_str().to_owned()).collect())
    }

    #[test]
    fn banned_components_absent_keeps_the_default_list() {
        assert_eq!(banned_names(&[]), None);
    }

    #[test]
    fn banned_components_lone_empty_value_disables_the_list() {
        assert_eq!(banned_names(&[""]), Some(Vec::new()));
    }

    #[test]
    fn banned_components_keep_non_empty_entries() {
        assert_eq!(
            banned_names(&[".git", "", ".ssh"]),
            Some(vec![".git".to_owned(), ".ssh".to_owned()])
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn banned_components_refuse_a_separator() {
        for raw in ["a/b", ".."] {
            let err = banned_components(&tokens(&[raw])).unwrap_err();
            assert!(format!("{err:#}").contains("--banned-component"), "{err:#}");
        }
    }

    #[test]
    fn banned_components_refuse_a_list_without_any_component() {
        for raw in [",", " ", " , "] {
            assert!(banned_components(&tokens(&[raw])).is_err(), "{raw:?}");
        }
    }

    #[test]
    fn banned_components_split_on_commas_and_trim() {
        assert_eq!(
            banned_names(&[".git, .ssh ,,.env"]),
            Some(vec![
                ".git".to_owned(),
                ".ssh".to_owned(),
                ".env".to_owned()
            ])
        );
    }

    #[test]
    fn conflict_error_message_escapes_hostile_paths() {
        let conflicts = vec![PathBuf::from("a\x1b[2J\nforged")];
        let msg = conflict_error_message(&conflicts);
        assert!(msg.ends_with("  a\\x1b[2J\\x0aforged"), "{msg:?}");
    }

    #[test]
    fn conflict_error_message_singular() {
        let conflicts = vec![PathBuf::from("a.txt")];
        let msg = conflict_error_message(&conflicts);
        assert!(msg.starts_with("1 destination file already exists"));
        assert!(msg.contains("a.txt"));
        assert!(!msg.contains("more"));
    }

    #[test]
    fn conflict_error_message_under_cap_lists_all_without_truncation_note() {
        let conflicts: Vec<_> = (0..5).map(|i| PathBuf::from(format!("f{i}.txt"))).collect();
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
            .map(|i| PathBuf::from(format!("f{i}.txt")))
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
            .map(|i| PathBuf::from(format!("f{i:02}.txt")))
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
            .map(PathBuf::from)
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
            .map(|i| PathBuf::from(format!("f{i:02}.txt")))
            .collect();
        let mut reversed = ascending.clone();
        reversed.reverse();

        assert_eq!(
            conflict_error_message(&ascending),
            conflict_error_message(&reversed),
            "the message must not depend on the order conflicts were discovered in"
        );
    }

    fn conflict_error_message(conflicts: &[PathBuf]) -> String {
        crate::error::terminal(&conflict_message(conflicts, WriteMode::Safe).into_parts())
    }

    #[test]
    fn write_mode_is_resolved_from_both_flags() {
        let mode = |force, atomic| {
            let mut args = extract_args();
            args.force = force;
            args.atomic = atomic;
            WriteMode::of(&args)
        };
        assert_eq!(mode(false, false), WriteMode::Safe);
        assert_eq!(mode(true, false), WriteMode::Force);
        assert_eq!(mode(false, true), WriteMode::Atomic);
        assert_eq!(mode(true, true), WriteMode::AtomicReplace);
        assert!(WriteMode::Force.overwrites() && !WriteMode::Force.stages());
        assert!(WriteMode::Atomic.stages() && !WriteMode::Atomic.overwrites());
    }

    fn extract_args() -> ExtractArgs {
        use clap::Parser as _;
        let crate::cli::Commands::Extract(args) =
            crate::cli::Cli::parse_from(["exarch", "extract", "a.tar"]).command
        else {
            panic!("expected extract command");
        };
        args
    }

    /// A destination displaced into a backup, in a parent holding the temp
    /// directory the extracted content would have been staged in.
    #[cfg(unix)]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn displaced_setup() -> (tempfile::TempDir, PathBuf, EntryName, EntryName) {
        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).expect("create parent");
        std::fs::create_dir(parent.join("dest")).expect("create dest");
        std::fs::write(parent.join("dest").join("keep.txt"), b"original").expect("write");
        std::fs::create_dir(parent.join("temp")).expect("create temp");
        (root, parent, entry("dest"), entry("temp"))
    }

    /// An early `?` between displacing the destination and swapping the new
    /// content in must put the original destination back.
    #[test]
    #[cfg(unix)]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn dropping_a_displaced_destination_restores_it() {
        let (_root, parent, dest_name, temp_name) = displaced_setup();
        let pin = PinnedDir::open(&parent).expect("pin parent");
        let (_, dest_id) = pin.entry_status(&dest_name).expect("dest identity");
        let (_, temp_id) = pin.entry_status(&temp_name).expect("temp identity");
        let temp_ref = TempOrphanRef {
            pin: &pin,
            name: &temp_name,
            id: temp_id,
            parent_display: &parent,
        };
        let slot = RestoreSlot::new(None);

        let swap = || -> Result<()> {
            let _displaced = DisplacedDestination::displace(
                &temp_ref,
                &dest_name,
                dest_id,
                &parent.join("dest"),
                &slot,
            )?;
            assert!(
                !parent.join("dest").exists(),
                "destination must be displaced"
            );
            anyhow::bail!("step between displace and swap failed");
        };
        swap().expect_err("the step fails");

        assert_eq!(
            std::fs::read(parent.join("dest").join("keep.txt")).expect("restored content"),
            b"original"
        );
        assert!(slot.take().is_none(), "a clean restore records no failure");
    }

    #[test]
    #[cfg(unix)]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn restore_and_discard_disarm_the_drop_guard() {
        let (_root, parent, dest_name, temp_name) = displaced_setup();
        let pin = PinnedDir::open(&parent).expect("pin parent");
        let (_, dest_id) = pin.entry_status(&dest_name).expect("dest identity");
        let (_, temp_id) = pin.entry_status(&temp_name).expect("temp identity");
        let temp_ref = TempOrphanRef {
            pin: &pin,
            name: &temp_name,
            id: temp_id,
            parent_display: &parent,
        };
        let slot = RestoreSlot::new(None);

        let displaced = DisplacedDestination::displace(
            &temp_ref,
            &dest_name,
            dest_id,
            &parent.join("dest"),
            &slot,
        )
        .expect("displace");
        pin.rename(&temp_name, &dest_name)
            .expect("swap new content in");
        let mut report = ExtractionReport::default();
        displaced.discard(&mut report);

        assert!(parent.join("dest").exists(), "the swapped-in content stays");
        assert!(
            !parent.join("dest").join("keep.txt").exists(),
            "the discarded drop must not restore the old destination over the new"
        );
        assert!(slot.take().is_none());
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    }

    #[test]
    #[cfg(unix)]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn a_failed_drop_restore_is_recorded_for_the_command() {
        let (_root, parent, dest_name, temp_name) = displaced_setup();
        let pin = PinnedDir::open(&parent).expect("pin parent");
        let (_, dest_id) = pin.entry_status(&dest_name).expect("dest identity");
        let (_, temp_id) = pin.entry_status(&temp_name).expect("temp identity");
        let temp_ref = TempOrphanRef {
            pin: &pin,
            name: &temp_name,
            id: temp_id,
            parent_display: &parent,
        };
        let slot = RestoreSlot::new(None);

        let displaced = DisplacedDestination::displace(
            &temp_ref,
            &dest_name,
            dest_id,
            &parent.join("dest"),
            &slot,
        )
        .expect("displace");
        // Something else took the destination name, so the rename-back fails
        // onto a non-empty directory.
        std::fs::create_dir(parent.join("dest")).expect("occupy destination name");
        std::fs::write(parent.join("dest").join("squatter"), b"x").expect("write");
        drop(displaced);

        let failure = slot.take().expect("the failed restore is recorded");
        assert!(failure.describe().contains("could NOT be restored"));
        assert!(failure.backup_path.join("keep.txt").exists());
    }
}
