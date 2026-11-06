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

mod parent;
mod replace;

use std::io;
use std::path::Path;
use std::path::PathBuf;

use tempfile::TempDir;

use crate::ArchiveError;
use crate::ConfigProblem;
use crate::ConfigSetting;
use crate::EntrySelection;
use crate::ExistingFiles;
use crate::ExtractionOptions;
use crate::ExtractionReport;
use crate::IoContext;
use crate::ProgressCallback;
use crate::Result;
use crate::Staging;

/// The extraction a staging mode wraps: it writes into the directory it is
/// given, under the options it is given, reporting to the progress it is given.
pub trait StagedRun:
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
pub fn extract_staged(
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

/// Where [`Staging::Atomic`] publishes, and the directory its staging
/// directory is created in.
struct AtomicDestination {
    path: PathBuf,
    parent: PathBuf,
}

impl AtomicDestination {
    /// Resolves `output_dir`, refusing one the final rename cannot fill.
    ///
    /// An existing destination is canonicalized, and both the staging
    /// directory's parent and the rename target come from that one path, so a
    /// symlinked `output_dir` is renamed onto its target and the staging
    /// directory is on the target's filesystem. A destination that is absent
    /// is used as given.
    fn resolve(output_dir: &Path) -> Result<Self> {
        let refuse = |problem| ArchiveError::InvalidConfiguration {
            setting: ConfigSetting::OutputPath,
            problem,
        };
        let path = if output_dir.exists() {
            let canonical = output_dir.canonicalize().map_err(ArchiveError::Io)?;
            if !canonical.is_dir() {
                return Err(refuse(ConfigProblem::NotADirectory));
            }
            if !is_empty_dir(&canonical)? {
                return Err(ArchiveError::OutputExists {
                    path: output_dir.to_path_buf(),
                });
            }
            canonical
        } else {
            if output_dir
                .symlink_metadata()
                .is_ok_and(|metadata| metadata.is_symlink())
            {
                return Err(refuse(ConfigProblem::IsSymlink));
            }
            output_dir.to_path_buf()
        };
        let parent = path
            .parent()
            .ok_or_else(|| refuse(ConfigProblem::NoParent))?
            .to_path_buf();
        Ok(Self { path, parent })
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

/// Creates the private staging directory next to the destination.
#[expect(
    clippy::disallowed_methods,
    reason = "creates the parent of a destination that is only opened after the rename"
)]
fn create_staging_dir(parent: &Path) -> Result<TempDir> {
    std::fs::create_dir_all(parent).map_err(ArchiveError::Io)?;
    tempfile::Builder::new()
        .prefix(".exarch-")
        .tempdir_in(parent)
        .map_err(|e| ArchiveError::Io(io_context(&e, "failed to create temp directory", parent)))
}

/// Wraps `error` with a static `context` and the `path` it concerns.
fn io_context(error: &io::Error, context: &'static str, path: &Path) -> io::Error {
    io::Error::new(
        error.kind(),
        IoContext::new(context, format!("{}: {error}", path.display())),
    )
}

/// The error of an extraction that was cancelled after it finished, once
/// nothing was published.
fn cancelled_after(report: ExtractionReport) -> ArchiveError {
    ArchiveError::partial_or(report, ArchiveError::Cancelled).rolled_back()
}

fn extract_atomic(
    output_dir: &Path,
    options: &ExtractionOptions,
    progress: &mut dyn ProgressCallback,
    extract: impl StagedRun,
) -> Result<ExtractionReport> {
    let destination = AtomicDestination::resolve(output_dir)?;
    let staging = create_staging_dir(&destination.parent)?;

    let report = extract(staging.path(), &staged_options(options), progress)
        .map_err(ArchiveError::rolled_back)?;
    if progress.is_cancelled() {
        return Err(cancelled_after(report));
    }
    publish(staging, &destination.path, output_dir)?;
    Ok(report)
}

/// Renames the staging directory onto the destination, removing it if that
/// fails.
#[expect(
    clippy::disallowed_methods,
    reason = "publishes the staging directory with one rename; it is not a write into the destination"
)]
fn publish(staging: TempDir, destination: &Path, output_dir: &Path) -> Result<()> {
    let staged = staging.keep();
    std::fs::rename(&staged, destination).map_err(|e| {
        let _ = std::fs::remove_dir_all(&staged);
        match e.kind() {
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
        }
    })
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
