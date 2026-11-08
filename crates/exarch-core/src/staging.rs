//! Staged extraction: the output is built next to the destination and only
//! published once the whole archive extracted.
//!
//! [`Staging::Atomic`] renames the staging directory into a destination that is
//! absent or an empty directory. [`Staging::AtomicReplace`] additionally swaps
//! the staging directory over a destination that already holds content (see
//! [`replace`]). Both build the output in a private sibling directory of the
//! destination, so the final rename never crosses a filesystem, and both poll
//! [`ProgressCallback::is_cancelled`] once more before anything is published.
//!
//! Inside the staging directory nothing but this run's own files can exist, so
//! [`ExistingFiles::Skip`] is raised to [`ExistingFiles::Refuse`]: in-archive
//! duplicates are still skipped through the run record, but a file planted in
//! the staging directory is refused instead of being kept and published.

mod acl;
mod adopt;
mod dir;
mod replace;

use std::io;
use std::path::Path;
use std::path::PathBuf;

use crate::ArchiveError;
use crate::ConfigProblem;
use crate::ConfigSetting;
use crate::EntrySelection;
use crate::ExistingFiles;
use crate::ExtractionOptions;
use crate::ExtractionReport;
use crate::IoContext;
use crate::NarrowingReason;
use crate::ProgressCallback;
use crate::Result;
use crate::Staging;
use crate::StagingLeftover;
use crate::destination_state::parent_or_cwd;
use crate::formats::pinned_dir::LeafBuf;
use crate::formats::pinned_dir::VettedDir;
use crate::report::Narrowed;
use crate::security::fs_view::Occupant;
use adopt::Adoption;
use dir::StagingDir;

/// The extraction a staging mode wraps: it writes into the directory it is
/// given, under the options it is given, reporting to the progress it is given.
pub(crate) trait StagedRun:
    FnOnce(&Path, &ExtractionOptions, &mut dyn ProgressCallback) -> Result<ExtractionReport>
{
}

impl<F> StagedRun for F where
    F: FnOnce(&Path, &ExtractionOptions, &mut dyn ProgressCallback) -> Result<ExtractionReport>
{
}

/// Runs `extract` into `output_dir`, or into a staging directory that replaces
/// or fills `output_dir` on success, as `options.staging` asks.
///
/// `archive` is the archive file when the extraction reads one; a replace
/// refuses a destination that contains it. A replace also refuses any
/// `selection` but the default one, because the swap would delete everything
/// in the destination that the selected subset does not contain.
///
/// # Errors
///
/// The extraction's own error, rolled back under a staging mode, or a typed
/// refusal or failure of the staging itself.
pub(crate) fn extract_staged(
    output_dir: &Path,
    options: &ExtractionOptions,
    selection: &EntrySelection,
    archive: Option<&Path>,
    progress: &mut dyn ProgressCallback,
    extract: impl StagedRun,
) -> Result<ExtractionReport> {
    if options.staging == Staging::AtomicReplace && !selection.is_default() {
        return Err(ArchiveError::InvalidConfiguration {
            setting: ConfigSetting::EntrySelection,
            problem: ConfigProblem::NotSupported,
        });
    }
    match options.staging {
        Staging::InPlace => extract(output_dir, options, progress),
        Staging::Atomic => extract_atomic(output_dir, options, progress, extract),
        Staging::AtomicReplace => match replace::resolve(output_dir, archive)? {
            Some(target) => replace::run(target, options, progress, extract),
            None => extract_atomic(output_dir, options, progress, extract),
        },
    }
}

/// The options a staging directory is extracted under.
fn staged_options(options: &ExtractionOptions) -> ExtractionOptions {
    let existing_files = match options.existing_files {
        ExistingFiles::Skip => ExistingFiles::Refuse,
        kept @ (ExistingFiles::Overwrite | ExistingFiles::Refuse) => kept,
    };
    options.clone().with_existing_files(existing_files)
}

/// Where [`Staging::Atomic`] publishes: the destination's name inside its
/// pinned parent, which is also where its staging directory is created.
struct AtomicDestination {
    name: LeafBuf,
    parent: PathBuf,
    pin: VettedDir,
    existed: bool,
}

impl AtomicDestination {
    /// Resolves `output_dir`, refusing one the final rename cannot fill.
    ///
    /// An existing destination is canonicalized, and both the staging
    /// directory's parent and the rename target come from that one path, so a
    /// symlinked `output_dir` is renamed onto its target and the staging
    /// directory is on the target's filesystem. For a destination that is
    /// absent the parent is created and canonicalized.
    #[expect(
        clippy::disallowed_methods,
        reason = "creates the parent of a destination that is only opened after the rename"
    )]
    fn resolve(output_dir: &Path) -> Result<Self> {
        let refuse = |problem| ArchiveError::InvalidConfiguration {
            setting: ConfigSetting::OutputPath,
            problem,
        };
        let (parent, name, existed) = if output_dir.exists() {
            let canonical = output_dir.canonicalize().map_err(ArchiveError::Io)?;
            if !canonical.is_dir() {
                return Err(refuse(ConfigProblem::NotADirectory));
            }
            if !is_empty_dir(&canonical)? {
                return Err(ArchiveError::OutputExists {
                    path: output_dir.to_path_buf(),
                });
            }
            let name = LeafBuf::of(&canonical).ok_or_else(|| refuse(ConfigProblem::NoParent))?;
            let parent = canonical
                .parent()
                .ok_or_else(|| refuse(ConfigProblem::NoParent))?
                .to_path_buf();
            (parent, name, true)
        } else {
            if output_dir
                .symlink_metadata()
                .is_ok_and(|metadata| metadata.is_symlink())
            {
                return Err(refuse(ConfigProblem::IsSymlink));
            }
            let name = LeafBuf::of(output_dir).ok_or_else(|| refuse(ConfigProblem::NoParent))?;
            let parent = parent_or_cwd(output_dir);
            std::fs::create_dir_all(parent).map_err(ArchiveError::Io)?;
            let parent = parent.canonicalize().map_err(ArchiveError::Io)?;
            (parent, name, false)
        };
        let pin = VettedDir::open_path(&parent).map_err(|e| {
            ArchiveError::Io(io_context(
                &e,
                "failed to pin the destination parent",
                &parent,
            ))
        })?;
        Ok(Self {
            name,
            parent,
            pin,
            existed,
        })
    }
}

fn is_empty_dir(dir: &Path) -> Result<bool> {
    let mut entries = std::fs::read_dir(dir).map_err(ArchiveError::Io)?;
    entries
        .next()
        .transpose()
        .map(|first| first.is_none())
        .map_err(ArchiveError::Io)
}

/// Wraps `error` with a static `context` and the `path` it concerns.
fn io_context(error: &io::Error, context: &'static str, path: &Path) -> io::Error {
    io::Error::new(
        error.kind(),
        IoContext::new(context, format!("{}: {error}", crate::path_text(path))),
    )
}

/// The error of an extraction that was cancelled after it finished, once
/// nothing was published; `leftover` is the staging directory that survived
/// its removal.
fn cancelled_after(report: ExtractionReport, leftover: Option<StagingLeftover>) -> ArchiveError {
    ArchiveError::partial_or(report, ArchiveError::Cancelled).rolled_back_with(leftover)
}

/// Removes the ACL a fresh staging directory inherited from `parent`, or
/// discards the directory and fails.
fn clear_inherited_acl<'p>(staging: StagingDir<'p>, parent: &Path) -> Result<StagingDir<'p>> {
    match staging.clear_inherited_acl() {
        Ok(()) => Ok(staging),
        Err(e) => {
            let error = ArchiveError::Io(io_context(
                &e,
                "failed to clear the access control list the staging directory inherited",
                parent,
            ));
            Err(error.rolled_back_with(staging.discard()))
        }
    }
}

/// The narrowing of a root whose destination vanished before its mode could
/// be read.
fn destination_vanished() -> Narrowed {
    let mut narrowed = Narrowed::none();
    narrowed.push(NarrowingReason::DestinationVanished);
    narrowed
}

fn extract_atomic(
    output_dir: &Path,
    options: &ExtractionOptions,
    progress: &mut dyn ProgressCallback,
    extract: impl StagedRun,
) -> Result<ExtractionReport> {
    let destination = AtomicDestination::resolve(output_dir)?;
    let mut staging = StagingDir::create(&destination.pin, &destination.parent)?;
    if destination.existed {
        staging = clear_inherited_acl(staging, &destination.parent)?;
    }

    // An absent destination has no mode to keep: the one a new directory gets
    // under the umask is read now, before any archive content is written. It is
    // also read for an existing one, as the fallback should that destination
    // vanish before the publish; only for an absent one is a failure fatal.
    let fresh_mode = match staging.probe_umask() {
        Ok(adoption) => Some(adoption),
        Err(_) if destination.existed => None,
        Err(e) => {
            let error = ArchiveError::Io(io_context(
                &e,
                "failed to probe the umask",
                &destination.parent,
            ));
            return Err(error.rolled_back_with(staging.discard()));
        }
    };

    let mut report = match extract(staging.path(), &staged_options(options), progress) {
        Ok(report) => report,
        Err(e) => return Err(e.rolled_back_with(staging.discard())),
    };
    if progress.is_cancelled() {
        return Err(cancelled_after(report, staging.discard()));
    }
    let published = adoption_for(&destination, fresh_mode, output_dir).and_then(|adoption| {
        publish_adopted(
            &mut staging,
            &destination,
            adoption,
            output_dir,
            &mut report,
        )
    });
    match published {
        Ok(()) => Ok(report),
        Err(error) => Err(error.rolled_back_with(staging.discard())),
    }
}

/// What the published root takes from the destination as it is now: its mode,
/// owner and ACL when it still is a directory, else `fresh_mode`.
fn adoption_for(
    destination: &AtomicDestination,
    fresh_mode: Option<Adoption>,
    output_dir: &Path,
) -> Result<Option<Adoption>> {
    let existing = destination
        .pin
        .status(destination.name.as_leaf())
        .map_err(ArchiveError::Io)?
        .filter(|status| status.occupant == Occupant::Directory);
    let Some(status) = existing else {
        return Ok(fresh_mode);
    };
    let acl = acl::read_destination(
        &destination.pin,
        destination.name.as_leaf(),
        &destination.parent,
        status.identity,
    )
    .map_err(|e| {
        ArchiveError::Io(io_context(
            &e,
            "failed to read the destination's access control list",
            output_dir,
        ))
    })?;
    Ok(Some(Adoption::of_empty_destination(&status, acl)))
}

/// Gives the staging directory the permissions in `adoption` and renames it
/// onto the destination, recording on `report` every way the root ended up
/// with less access than the destination. No `adoption` means the destination
/// vanished with no mode left to read: the root keeps its private mode.
///
/// Both happen only now so every earlier failure leaves the staging directory
/// private; a failure here leaves the caller to discard it.
fn publish_adopted(
    staging: &mut StagingDir<'_>,
    destination: &AtomicDestination,
    adoption: Option<Adoption>,
    output_dir: &Path,
    report: &mut ExtractionReport,
) -> Result<()> {
    match adoption {
        Some(adoption) => {
            let narrowed = staging.adopt(adoption).map_err(|e| {
                ArchiveError::Io(io_context(
                    &e,
                    "failed to give the extracted content the destination's permissions",
                    output_dir,
                ))
            })?;
            report.record_narrowing(narrowed);
        }
        None => report.record_narrowing(destination_vanished()),
    }
    staging
        .publish(&destination.name)
        .map_err(|e| match e.kind() {
            io::ErrorKind::AlreadyExists | io::ErrorKind::DirectoryNotEmpty => {
                ArchiveError::OutputExists {
                    path: output_dir.to_path_buf(),
                }
            }
            _ => ArchiveError::Io(io_context(
                &e,
                "failed to rename temp dir into place",
                output_dir,
            )),
        })
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
