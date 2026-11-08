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

#[cfg(unix)]
use super::acl;
#[cfg(unix)]
use super::acl::AclPlan;
use super::acl::Inheritance;
#[cfg(unix)]
use super::acl::ParentAcl;
use super::adopt::Adoption;
use super::io_context;
use crate::ArchiveError;
#[cfg(unix)]
use crate::NarrowingReason;
use crate::Result;
use crate::StagingLeftover;
use crate::formats::file_identity::FileIdentity;
use crate::formats::file_identity::IdentityCheck;
use crate::formats::pinned_dir::LeafBuf;
use crate::formats::pinned_dir::VettedDir;

const PREFIX: &str = ".exarch-";
const CREATE_ATTEMPTS: usize = 16;

/// What a new staging directory is made to resemble, which fixes the order of
/// the steps that prepare it (create, clear, probe, seed).
///
/// The inheritance is written only after the umask probe: a probe directory
/// made under it could inherit a deny entry and become impossible to remove.
#[cfg_attr(
    not(unix),
    allow(
        dead_code,
        reason = "only Unix hosts seed a staging directory with the destination's inheritance"
    )
)]
pub(super) enum Seed {
    /// No destination exists. Where the parent's inherited entries can be
    /// listed (macOS) they are captured, cleared, and re-seeded as entries for
    /// children only, so the directory is private while it is filled;
    /// elsewhere the parent's default ACL stays, as the mode's group bits mask
    /// it. The umask is probed either way (a failure is fatal).
    Absent,
    /// An empty destination that is filled in place of: the parent's
    /// inheritance is cleared, the umask probed (a failure is tolerated) and
    /// the destination's inheritance seeded.
    FillEmpty(FileIdentity, Inheritance),
    /// A destination that is replaced: as [`FillEmpty`](Self::FillEmpty)
    /// without the probe.
    Replace(FileIdentity, Inheritance),
}

/// Where the children of a staging directory got their inherited entries, and
/// so whether the published root may be wider than `0700`.
#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
pub(super) enum Inherited {
    /// From the parent, as a directory made at the destination's path would.
    Parent,
    /// From the destination with this identity, which had nothing to seed.
    Destination(FileIdentity),
    /// From the destination with this identity, whose inheritable entries
    /// were written onto the staging directory at creation.
    Seeded(FileIdentity),
    /// From nowhere: the destination's inheritance could not be carried over.
    Withheld(NarrowingReason),
}

#[cfg(unix)]
impl Inherited {
    /// The reason the published root must stay private, if there is one.
    ///
    /// `observed` is the identity of the destination being adopted, when
    /// there still is one. Children that inherited from a destination that is
    /// not the one being adopted would sit under a root with other access.
    /// An identity the volume cannot provide is not a mismatch.
    ///
    /// A destination that is gone (`observed` is `None`) leaves a seeded
    /// staging directory holding entries of a destination that no longer
    /// dictates anything: it stays private, with those entries removed. One
    /// with nothing seeded may keep the mode a new directory gets.
    pub(super) fn withholds(self, observed: Option<FileIdentity>) -> Option<NarrowingReason> {
        let changed = |seeded: FileIdentity| {
            observed
                .filter(|observed| observed.check(seeded) == IdentityCheck::Different)
                .map(|_| NarrowingReason::DestinationChanged)
        };
        match self {
            Self::Parent => None,
            Self::Withheld(reason) => Some(reason),
            Self::Destination(seeded) => changed(seeded),
            Self::Seeded(seeded) => match observed {
                Some(_) => changed(seeded),
                None => Some(NarrowingReason::DestinationVanished),
            },
        }
    }
}

/// Proof that the staging directory was renamed to its destination.
///
/// Only [`StagingDir::publish`] makes one, so what must happen to the root
/// after the rename cannot be done before it.
#[derive(Debug)]
pub(super) struct Published(());

/// Whose inheritance a staging directory is seeded with.
#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
enum SeedSource {
    /// The parent's, as a directory made at the destination's path gets it.
    Parent,
    /// The destination with this identity.
    Destination(FileIdentity),
}

/// A staging directory inside the pinned directory `parent`.
#[must_use = "dropping a staging directory removes it"]
pub(super) struct StagingDir<'p> {
    pub(super) parent: &'p VettedDir,
    pub(super) name: LeafBuf,
    path: PathBuf,
    pub(super) id: FileIdentity,
    armed: bool,
    fresh: Option<Adoption>,
    #[cfg(unix)]
    pub(super) inherited: Inherited,
    #[cfg(unix)]
    pub(super) adopted: Option<std::fs::File>,
}

impl<'p> StagingDir<'p> {
    /// Creates a fresh `0700` staging directory in `parent`, whose logical
    /// path is `parent_path`, and prepares it as `seed` says.
    ///
    /// # Errors
    ///
    /// An I/O error when no unused name could be created, or when a step
    /// `seed` makes mandatory failed; the directory is removed then.
    pub(super) fn create(parent: &'p VettedDir, parent_path: &Path, seed: Seed) -> Result<Self> {
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
                Ok(()) => {
                    return Self::claim(parent, parent_path, name)
                        .map_err(|e| failure(&e))?
                        .prepared(seed, parent_path);
                }
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
            fresh: None,
            #[cfg(unix)]
            inherited: Inherited::Parent,
            #[cfg(unix)]
            adopted: None,
        };
        staging.id = parent
            .status(staging.name.as_leaf())?
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
            .identity;
        Ok(staging)
    }

    /// Takes the permissions a directory gets under the umask, probed at
    /// creation when `seed` asked for it and the probe worked.
    pub(super) fn take_fresh(&mut self) -> Option<Adoption> {
        self.fresh.take()
    }

    /// Runs the steps `seed` names, in order.
    #[cfg(unix)]
    fn prepared(mut self, seed: Seed, parent_path: &Path) -> Result<Self> {
        match seed {
            Seed::Absent => self = self.prepared_absent(parent_path)?,
            Seed::FillEmpty(id, inheritance) => {
                self = self.cleared(parent_path)?;
                // Without a probe result the fallback for a vanished
                // destination is a private root.
                if let Ok(fresh) = self.probe_umask(AclPlan::None) {
                    self.fresh = Some(fresh);
                }
                self = self.seeded(SeedSource::Destination(id), &inheritance, parent_path)?;
            }
            Seed::Replace(id, inheritance) => {
                self = self.cleared(parent_path)?;
                self = self.seeded(SeedSource::Destination(id), &inheritance, parent_path)?;
            }
        }
        Ok(self)
    }

    /// Prepares the directory for a destination that is absent: what a `mkdir`
    /// of it in the parent would give it is captured, cleared from the
    /// directory, and written back as entries for children only.
    ///
    /// The captured list also goes to the root that is published, which gets
    /// it after the rename; the directory stays private until then.
    #[cfg(unix)]
    fn prepared_absent(mut self, parent_path: &Path) -> Result<Self> {
        let captured = acl::capture_parent(self.parent, self.name.as_leaf(), parent_path, self.id);
        let plan = match captured {
            Ok(ParentAcl::MaskedByMode | ParentAcl::Captured(AclPlan::None)) => None,
            Ok(ParentAcl::Captured(plan)) => {
                self = self.cleared(parent_path)?;
                Some(plan)
            }
            Err(e) => {
                return Err(self.fail(
                    &e,
                    "failed to read the access control list the staging directory inherited",
                    parent_path,
                ));
            }
        };
        let inheritance = plan.as_ref().map(AclPlan::inheritance);
        match self.probe_umask(plan.unwrap_or(AclPlan::None)) {
            Ok(fresh) => self.fresh = Some(fresh),
            Err(e) => return Err(self.fail(&e, "failed to probe the umask", parent_path)),
        }
        match inheritance {
            Some(inheritance) => self.seeded(SeedSource::Parent, &inheritance, parent_path),
            None => Ok(self),
        }
    }

    #[cfg(not(unix))]
    #[allow(
        clippy::unnecessary_wraps,
        clippy::needless_pass_by_value,
        reason = "keeps the call site platform-neutral"
    )]
    fn prepared(mut self, seed: Seed, _parent_path: &Path) -> Result<Self> {
        if !matches!(seed, Seed::Replace(..))
            && let Ok(fresh) = self.probe_umask()
        {
            self.fresh = Some(fresh);
        }
        Ok(self)
    }

    /// Removes the directory and turns `error` into the failure of the run,
    /// naming what survived the removal.
    #[cfg(unix)]
    fn fail(self, error: &io::Error, context: &'static str, path: &Path) -> ArchiveError {
        ArchiveError::Io(io_context(error, context, path)).rolled_back_with(self.discard())
    }

    /// Removes the ACL the directory inherited from the parent it was created
    /// in, before anything is extracted into it.
    ///
    /// A directory that fills or replaces an existing destination takes that
    /// destination's access control, never the parent's: an inherited entry
    /// would make the published root, and everything extracted under it,
    /// more permissive than the destination.
    #[cfg(unix)]
    fn cleared(self, parent_path: &Path) -> Result<Self> {
        match acl::clear_inherited(self.parent, self.name.as_leaf()) {
            Ok(()) => Ok(self),
            Err(e) => Err(self.fail(
                &e,
                "failed to clear the access control list the staging directory inherited",
                parent_path,
            )),
        }
    }

    /// Writes `inheritance` onto the cleared directory, so its children
    /// inherit what an in-place extraction's would.
    ///
    /// A write that fails is cleared again and recorded as
    /// [`Inherited::Withheld`]; when that clear fails too the run fails, as a
    /// directory with half an ACL must not be extracted into.
    #[cfg(unix)]
    fn seeded(
        mut self,
        source: SeedSource,
        inheritance: &Inheritance,
        parent_path: &Path,
    ) -> Result<Self> {
        if let Inheritance::Withheld(reason) = inheritance {
            self.inherited = Inherited::Withheld(*reason);
            return Ok(self);
        }
        let dir = match self.open_verified() {
            Ok(dir) => dir,
            Err(e) => {
                return Err(self.fail(&e, "failed to open the staging directory", parent_path));
            }
        };
        self.inherited = match acl::stage(&dir, inheritance) {
            Ok(()) => match source {
                SeedSource::Parent => Inherited::Parent,
                SeedSource::Destination(id) if matches!(inheritance, Inheritance::None) => {
                    Inherited::Destination(id)
                }
                SeedSource::Destination(id) => Inherited::Seeded(id),
            },
            Err(_) => match acl::clear_inherited(self.parent, self.name.as_leaf()) {
                Ok(()) => Inherited::Withheld(NarrowingReason::AclCopyFailed),
                Err(e) => {
                    return Err(self.fail(
                        &e,
                        "failed to clear the access control list of the staging directory",
                        parent_path,
                    ));
                }
            },
        };
        Ok(self)
    }

    /// Opens the directory through the pinned parent, which must still be the
    /// one that was created.
    ///
    /// # Errors
    ///
    /// The I/O error of opening it, or an error when it was replaced.
    #[cfg(unix)]
    pub(super) fn open_verified(&self) -> io::Result<std::fs::File> {
        let dir = self.parent.open_dir_file(self.name.as_leaf())?;
        if FileIdentity::of_file(&dir).check(self.id) != IdentityCheck::Same {
            return Err(io::Error::other("the staging directory was replaced"));
        }
        Ok(dir)
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
    pub(super) fn publish(&mut self, destination: &LeafBuf) -> io::Result<Published> {
        self.parent
            .rename_dir_within(self.name.as_leaf(), destination.as_leaf())?;
        self.armed = false;
        Ok(Published(()))
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
