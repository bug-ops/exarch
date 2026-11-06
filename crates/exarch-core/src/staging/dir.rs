//! The private staging directory an atomic extraction builds its output in.
//!
//! A [`StagingDir`] is created next to the destination through a pinned
//! descriptor of the destination's parent, readable and writable by the owner
//! only, so nothing extracted into it is visible to other local users before
//! the run publishes it. It is an armed guard: dropping it (an early `?` or an
//! unwind) removes the directory, and [`discard`](StagingDir::discard) removes
//! it explicitly and reports what survived.

use std::io;
use std::path::Path;
use std::path::PathBuf;

use super::io_context;
use crate::ArchiveError;
use crate::Result;
use crate::StagingLeftover;
use crate::formats::file_identity::FileIdentity;
use crate::formats::file_identity::IdentityCheck;
use crate::formats::pinned_dir::LeafBuf;
use crate::formats::pinned_dir::VettedDir;

const PREFIX: &str = ".exarch-";
const CREATE_ATTEMPTS: usize = 16;

/// A staging directory inside the pinned directory `parent`.
#[must_use = "dropping a staging directory removes it"]
pub(super) struct StagingDir<'p> {
    pub(super) parent: &'p VettedDir,
    pub(super) name: LeafBuf,
    path: PathBuf,
    pub(super) id: FileIdentity,
    armed: bool,
    #[cfg(unix)]
    pub(super) adopted: Option<std::fs::File>,
}

impl<'p> StagingDir<'p> {
    /// Creates a fresh `0700` staging directory in `parent`, whose logical
    /// path is `parent_path`.
    ///
    /// # Errors
    ///
    /// An I/O error when no unused name could be created.
    pub(super) fn create(parent: &'p VettedDir, parent_path: &Path) -> Result<Self> {
        let failure = |error: &io::Error| {
            ArchiveError::Io(io_context(
                error,
                "failed to create temp directory",
                parent_path,
            ))
        };
        for _ in 0..CREATE_ATTEMPTS {
            let name = LeafBuf::random(PREFIX);
            match parent.make_private_dir(name.as_leaf()) {
                Ok(()) => return Self::claim(parent, parent_path, name).map_err(|e| failure(&e)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(failure(&e)),
            }
        }
        Err(failure(&io::Error::from(io::ErrorKind::AlreadyExists)))
    }

    /// Records the identity of the directory just created as `name`; a
    /// failure removes it through the armed guard.
    fn claim(parent: &'p VettedDir, parent_path: &Path, name: LeafBuf) -> io::Result<Self> {
        let path = parent_path.join(&name);
        let mut staging = Self {
            parent,
            name,
            path,
            id: FileIdentity::Unknown,
            armed: true,
            #[cfg(unix)]
            adopted: None,
        };
        staging.id = parent
            .status(staging.name.as_leaf())?
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
            .identity;
        Ok(staging)
    }

    /// The staging directory's logical path.
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Renames the staging directory to `destination` within its parent, and
    /// disarms the guard on success. On failure the directory stays and is
    /// still guarded.
    ///
    /// # Errors
    ///
    /// The rename's I/O error.
    pub(super) fn publish(&mut self, destination: &LeafBuf) -> io::Result<()> {
        self.parent
            .rename_dir_within(self.name.as_leaf(), destination.as_leaf())?;
        self.armed = false;
        Ok(())
    }

    /// Removes the staging directory and says what survived the removal.
    ///
    /// The removal goes by the logical path, which a redirect of the parent
    /// could point at a decoy; the survival check is relative to the pinned
    /// parent and so still sees the real directory, and names it from a
    /// descriptor on the entry itself.
    pub(super) fn discard(mut self) -> Option<StagingLeftover> {
        self.armed = false;
        self.remove_tree();
        match self.parent.status(self.name.as_leaf()) {
            Ok(None) => None,
            Ok(Some(observed)) if observed.identity.check(self.id) == IdentityCheck::Different => {
                None
            }
            Ok(Some(_)) | Err(_) => Some(StagingLeftover::new(
                self.parent
                    .entry_path(self.name.as_leaf())
                    .unwrap_or_else(|| self.path.clone()),
            )),
        }
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "removes the private staging directory; std's removal does not follow symlinks"
    )]
    fn remove_tree(&self) {
        self.reset_private();
        // The survival check in `discard` reports a removal that failed.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

impl Drop for StagingDir<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.remove_tree();
        }
    }
}
