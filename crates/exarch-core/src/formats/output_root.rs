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

/// The directory an extraction writes into.
#[derive(Debug, Clone, Copy)]
pub(crate) enum OutputRoot<'a> {
    /// A directory named by path, created if absent and opened by the run.
    Path(&'a Path),
    /// A staging directory pinned by the staging layer.
    Staged(&'a StagedOutput),
}

impl<'a> From<&'a Path> for OutputRoot<'a> {
    fn from(path: &'a Path) -> Self {
        Self::Path(path)
    }
}

impl<'a> From<&'a PathBuf> for OutputRoot<'a> {
    fn from(path: &'a PathBuf) -> Self {
        Self::Path(path)
    }
}

impl<'a> From<&'a StagedOutput> for OutputRoot<'a> {
    fn from(staged: &'a StagedOutput) -> Self {
        Self::Staged(staged)
    }
}
