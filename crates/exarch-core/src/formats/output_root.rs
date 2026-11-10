//! Where an extraction writes.
//!
//! An in-place run is told a directory by path and opens it itself. A staged
//! run is handed the staging directory it created: on Unix the descriptor it
//! verified, so the extraction never resolves the staging name again, and the
//! ledger of what the run creates, which the rollback reads after the
//! extraction ended.

use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

use super::run_record::RunRecord;
use crate::mark::MarkRun;

/// A staging directory an extraction writes into, with the record of what it
/// creates there.
///
/// Made only by the staging layer, from the directory it created and verified.
#[derive(Debug)]
pub(crate) struct StagedOutput {
    path: PathBuf,
    #[cfg(unix)]
    root: std::fs::File,
    ledger: Rc<RunRecord>,
}

impl StagedOutput {
    /// The staging directory behind `root`, logically at `path`.
    #[cfg(unix)]
    pub(crate) const fn new(path: PathBuf, root: std::fs::File, ledger: Rc<RunRecord>) -> Self {
        Self { path, root, ledger }
    }

    /// The staging directory at `path`, which has no descriptor to pin.
    #[cfg(not(unix))]
    pub(crate) const fn new(path: PathBuf, ledger: Rc<RunRecord>) -> Self {
        Self { path, ledger }
    }

    /// The staging directory's logical path.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// The descriptor of the staging directory itself.
    #[cfg(unix)]
    pub(crate) const fn root(&self) -> &std::fs::File {
        &self.root
    }

    /// What the run creates in the directory is recorded here.
    pub(crate) fn ledger(&self) -> Rc<RunRecord> {
        Rc::clone(&self.ledger)
    }
}

/// Where an extraction writes: a directory named by path or a staging
/// directory.
#[derive(Debug, Clone, Copy)]
pub(super) enum Place<'a> {
    /// A directory named by path, created if absent and opened by the run.
    Path(&'a Path),
    /// A staging directory pinned by the staging layer.
    Staged(&'a StagedOutput),
}

/// The directory an extraction writes into, with the mark the files it
/// creates are to carry.
#[derive(Debug, Clone, Copy)]
pub(crate) struct OutputRoot<'a> {
    place: Place<'a>,
    mark: Option<&'a Rc<MarkRun>>,
}

impl<'a> OutputRoot<'a> {
    const fn at(place: Place<'a>) -> Self {
        Self { place, mark: None }
    }

    /// The same directory, whose files carry the mark of `mark`; `None` marks
    /// nothing.
    pub(crate) const fn with_mark(self, mark: Option<&'a Rc<MarkRun>>) -> Self {
        Self { mark, ..self }
    }

    pub(super) const fn place(&self) -> Place<'a> {
        self.place
    }

    pub(super) fn mark(&self) -> Option<Rc<MarkRun>> {
        self.mark.map(Rc::clone)
    }
}

impl<'a> From<&'a Path> for OutputRoot<'a> {
    fn from(path: &'a Path) -> Self {
        Self::at(Place::Path(path))
    }
}

impl<'a> From<&'a PathBuf> for OutputRoot<'a> {
    fn from(path: &'a PathBuf) -> Self {
        Self::at(Place::Path(path))
    }
}

impl<'a> From<&'a StagedOutput> for OutputRoot<'a> {
    fn from(staged: &'a StagedOutput) -> Self {
        Self::at(Place::Staged(staged))
    }
}
