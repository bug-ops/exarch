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
mod hold;
#[cfg(unix)]
mod remove;
mod replace;
#[cfg(target_os = "macos")]
mod sweep;
#[cfg(all(test, target_os = "macos"))]
#[allow(clippy::unwrap_used)]
mod test_acl;

use std::ffi::OsString;
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
use crate::formats::output_root::OutputRoot;
use crate::formats::pinned_dir::LeafBuf;
use crate::formats::pinned_dir::VettedDir;
use crate::report::Narrowed;
use crate::security::fs_view::Occupant;
use adopt::Adoption;
use dir::Seed;
use dir::StagingDir;
use hold::Destination;
use hold::DestinationHold;

/// The name prefix of every staging entry (a staging directory, or the
/// temporary file of a staged archive) created next to a destination.
///
/// # Examples
///
/// ```
/// assert!(exarch_core::STAGING_PREFIX.starts_with('.'));
/// assert!(exarch_core::BACKUP_PREFIX.starts_with(exarch_core::STAGING_PREFIX));
/// ```
pub const STAGING_PREFIX: &str = ".exarch-";

/// The name prefix of the backup an atomic replace renames the previous
/// destination to; it extends [`STAGING_PREFIX`].
pub const BACKUP_PREFIX: &str = ".exarch-backup-";

/// What a staged output is, which fixes how its destination is resolved.
///
/// # Examples
///
/// ```
/// use exarch_core::StagedOutputKind;
///
/// assert_ne!(StagedOutputKind::Directory, StagedOutputKind::File);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StagedOutputKind {
    /// An extraction destination directory (atomic or replace staging).
    Directory,
    /// A created archive file.
    File,
}

/// Where the staging entries of one output live, and the path a backup is
/// renamed back to.
///
/// Built only by [`staging_place`], so the parent is always an absolute,
/// canonical directory.
///
/// # Examples
///
/// ```
/// use exarch_core::StagedOutputKind;
/// use exarch_core::staging_place;
///
/// let dir = tempfile::tempdir()?;
/// let place = staging_place(&dir.path().join("out"), StagedOutputKind::Directory)?;
/// assert_eq!(place.target().file_name(), Some("out".as_ref()));
/// assert_eq!(place.target().parent(), Some(place.parent()));
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingPlace {
    parent: PathBuf,
    name: OsString,
}

impl StagingPlace {
    /// The directory that holds the staging and backup entries.
    #[must_use]
    pub fn parent(&self) -> &Path {
        &self.parent
    }

    /// The path of the output itself inside [`parent`](Self::parent): where a
    /// backup is renamed back to.
    #[must_use]
    pub fn target(&self) -> PathBuf {
        self.parent.join(&self.name)
    }
}

/// Resolves where the staging entries of `output` are created, by the rule the
/// staging code of `kind` uses.
///
/// A [`Directory`](StagedOutputKind::Directory) that exists is canonicalized
/// and split into parent and name; one that is absent takes its name from
/// `output` and its parent from the canonical parent. A
/// [`File`](StagedOutputKind::File) always takes the canonical parent and the
/// name of `output`. Nothing is created.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidInput`] when the output has no name (a root, or a
/// path ending in `..`); otherwise the error of canonicalizing, for example
/// `NotFound` when the parent does not exist yet.
///
/// # Examples
///
/// ```
/// use exarch_core::StagedOutputKind;
/// use exarch_core::staging_place;
///
/// let dir = tempfile::tempdir()?;
/// let output = dir.path().join("out");
/// let place = staging_place(&output, StagedOutputKind::File)?;
/// assert_eq!(place.target(), dir.path().canonicalize()?.join("out"));
/// assert!(staging_place(std::path::Path::new("/"), StagedOutputKind::Directory).is_err());
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn staging_place(output: &Path, kind: StagedOutputKind) -> io::Result<StagingPlace> {
    let no_name = || io::Error::new(io::ErrorKind::InvalidInput, "the output has no name");
    if kind == StagedOutputKind::Directory && output.exists() {
        let canonical = output.canonicalize()?;
        let name = canonical.file_name().ok_or_else(no_name)?.to_os_string();
        let parent = canonical.parent().ok_or_else(no_name)?.to_path_buf();
        return Ok(StagingPlace { parent, name });
    }
    let name = output.file_name().ok_or_else(no_name)?.to_os_string();
    let parent = parent_or_cwd(output).canonicalize()?;
    Ok(StagingPlace { parent, name })
}

/// The extraction a staging mode wraps: it writes into the directory it is
/// given, under the options it is given, reporting to the progress it is given.
pub(crate) trait StagedRun:
    FnOnce(OutputRoot<'_>, &ExtractionOptions, &mut dyn ProgressCallback) -> Result<ExtractionReport>
{
}

impl<F> StagedRun for F where
    F: FnOnce(
        OutputRoot<'_>,
        &ExtractionOptions,
        &mut dyn ProgressCallback,
    ) -> Result<ExtractionReport>
{
}

/// Runs `extract` into the directory `staging` pinned, under the options a
/// staging directory is extracted under.
///
/// # Errors
///
/// The extraction's own error, or the I/O error of pinning the directory. The
/// staging directory is left for the caller to discard.
fn extract_in(
    staging: &StagingDir<'_>,
    options: &ExtractionOptions,
    progress: &mut dyn ProgressCallback,
    extract: impl StagedRun,
) -> Result<ExtractionReport> {
    let output = staging.output().map_err(|e| {
        ArchiveError::Io(io_context(
            &e,
            "failed to pin the staging directory",
            staging.path(),
        ))
    })?;
    extract((&output).into(), &staged_options(options), progress)
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
        Staging::InPlace => extract(output_dir.into(), options, progress),
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
        let (parent, name) = if output_dir.exists() {
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
            (parent, name)
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
            (parent, name)
        };
        let pin = VettedDir::open_path(&parent).map_err(|e| {
            ArchiveError::Io(io_context(
                &e,
                "failed to pin the destination parent",
                &parent,
            ))
        })?;
        Ok(Self { name, parent, pin })
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

/// The narrowing of a root whose destination vanished before its mode could
/// be read, with the reason its children could not inherit from it, if any.
fn destination_vanished(withheld: Option<NarrowingReason>) -> Narrowed {
    let mut narrowed = Narrowed::none();
    narrowed.push(NarrowingReason::DestinationVanished);
    if let Some(reason) = withheld {
        narrowed.push(reason);
    }
    narrowed
}

/// How the staging directory for `destination` is prepared: as for an empty
/// directory to fill when one is there, else as for an absent destination.
///
/// An absent destination has no mode to keep: the one a new directory gets
/// under the umask is read at creation, before any archive content is
/// written. It is also read for an existing one, as the fallback should that
/// destination vanish before the publish.
///
/// An existing directory is also returned as the hold that keeps its inode
/// from being reissued; the caller keeps it until the run is over.
fn atomic_seed(
    destination: &AtomicDestination,
    output_dir: &Path,
) -> Result<(Seed, Option<DestinationHold>)> {
    let found = Destination::open(&destination.pin, destination.name.as_leaf())
        .map_err(ArchiveError::Io)?;
    let Destination::Directory { status, hold } = found else {
        return Ok((Seed::Absent, None));
    };
    let inheritance = acl::read_inheritance(
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
    Ok((Seed::FillEmpty(status.identity, inheritance), hold))
}

fn extract_atomic(
    output_dir: &Path,
    options: &ExtractionOptions,
    progress: &mut dyn ProgressCallback,
    extract: impl StagedRun,
) -> Result<ExtractionReport> {
    let destination = AtomicDestination::resolve(output_dir)?;
    let (seed, _hold) = atomic_seed(&destination, output_dir)?;
    let mut staging = StagingDir::create(&destination.pin, &destination.parent, seed)?;

    let mut report = match extract_in(&staging, options, progress, extract) {
        Ok(report) => report,
        Err(e) => return Err(e.rolled_back_with(staging.discard())),
    };
    if progress.is_cancelled() {
        return Err(cancelled_after(report, staging.discard()));
    }
    let fresh = staging.take_fresh();
    let published = adoption_for(&destination, fresh, output_dir).and_then(|adoption| {
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

/// Gives the staging directory the permissions in `adoption`, renames it onto
/// the destination and then finishes the root with the destination's ACL,
/// recording on `report` every way the root ended up with less access than
/// the destination. No `adoption` means the destination vanished with no mode
/// left to read: the root keeps its private mode.
///
/// The ACL waits for the rename because one that denies deleting the root
/// would stop it. Everything before the rename leaves the staging directory
/// private; a failure up to and including the rename leaves the caller to
/// discard it.
fn publish_adopted(
    staging: &mut StagingDir<'_>,
    destination: &AtomicDestination,
    adoption: Option<Adoption>,
    output_dir: &Path,
    report: &mut ExtractionReport,
) -> Result<()> {
    let adopted = if let Some(adoption) = adoption {
        let root = staging.adopt(adoption).map_err(|e| {
            ArchiveError::Io(io_context(
                &e,
                "failed to give the extracted content the destination's permissions",
                output_dir,
            ))
        })?;
        Some(root)
    } else {
        let withheld = staging.vanished_reason().map_err(|e| {
            ArchiveError::Io(io_context(
                &e,
                "failed to clear the access control list of the staging directory",
                output_dir,
            ))
        })?;
        report.record_narrowing(destination_vanished(withheld));
        None
    };
    let mut published = staging
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
        })?;
    report.record_narrowing(published.take_narrowing());
    if let Some(root) = adopted {
        report.record_narrowing(root.finish(published));
    }
    Ok(())
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod parent_tests;
#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
#[cfg(all(test, windows))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod windows_tests;
