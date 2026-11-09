//! The private staging directory an atomic extraction builds its output in.
//!
//! A [`StagingDir`] is created next to the destination through a pinned
//! descriptor of the destination's parent, readable and writable by the owner
//! only, so nothing extracted into it is visible to other local users before
//! the run publishes it. It is an armed guard: dropping it (an early `?` or an
//! unwind) removes the directory, and [`discard`](StagingDir::discard) removes
//! it explicitly and reports what survived.

use std::io;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
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
/// the steps that prepare it (create, clear, prove empty, probe, seed).
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

/// A descriptor on a staging directory that was checked to be the directory
/// the run created.
///
/// Every read or change of the stage's ACL and every check of its contents goes
/// through one, so none of them can reach a directory another user swapped in
/// under the name. Only [`StagingDir::open_verified`] makes one.
#[cfg(unix)]
#[derive(Debug)]
pub(super) struct VerifiedStage(std::fs::File);

#[cfg(unix)]
impl VerifiedStage {
    /// The descriptor, for the calls that act on the stage itself.
    pub(super) const fn as_file(&self) -> &std::fs::File {
        &self.0
    }

    /// The descriptor, kept past the verification.
    pub(super) fn into_file(self) -> std::fs::File {
        self.0
    }

    /// Fails unless the directory has no entry.
    ///
    /// A directory made a moment ago by this run is empty; an entry means
    /// another user wrote into it, and what it names must not be published.
    ///
    /// # Errors
    ///
    /// [`NotEmpty::Planted`] for an entry, [`NotEmpty::Unlistable`] when the
    /// listing failed and so proves nothing either way.
    pub(super) fn ensure_empty(&self) -> std::result::Result<(), NotEmpty> {
        match list_entries(&self.0) {
            Ok(entries) if entries.is_empty() => Ok(()),
            Ok(_) => Err(NotEmpty::Planted),
            Err(_) => Err(NotEmpty::Unlistable),
        }
    }
}

/// Why a staging directory could not be shown to be empty.
#[cfg(unix)]
#[derive(Debug)]
pub(super) enum NotEmpty {
    /// It holds an entry this run did not make.
    Planted,
    /// It could not be listed, so what it holds is unknown.
    Unlistable,
}

/// The names in the directory `dir`, without `.` and `..`, read through a
/// fresh descriptor opened relative to it so the caller's offset is untouched.
///
/// # Errors
///
/// The I/O error of opening or listing the directory.
#[cfg(unix)]
pub(super) fn list_entries(dir: &impl std::os::fd::AsFd) -> io::Result<Vec<std::ffi::OsString>> {
    use rustix::fs::Mode;
    use rustix::fs::OFlags;

    let fd = rustix::fs::openat(
        dir,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::new(fd)? {
        let name = entry?.file_name().to_bytes().to_vec();
        if name != b"." && name != b".." {
            names.push(std::ffi::OsStr::from_bytes(&name).to_os_string());
        }
    }
    Ok(names)
}

/// What a failure to list the staging directory means for the run.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OnUnlistable {
    /// The run goes on, as it did before the listing existed.
    Continue,
    /// The run fails: an inherited ACL was read and cleared from the
    /// directory, and what it let other users do cannot be ruled out.
    Fail,
}

/// Proof that the staging directory was empty after its ACL was cleared, so
/// its root holds nothing but what the run put there.
///
/// It says nothing about the staged subdirectories, which inherit entries
/// that may let another user write into them: the sweep's per-entry checks
/// (owner, link count, inherited-only entries, all read from the opened
/// descriptor) decide what it may clear, and "inherited" is a heuristic since
/// the flag can be set by hand.
///
/// Made only by [`StagingDir::emptied`], and lost by `adopt`, whose mode may
/// open the root to others.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy)]
pub(super) struct OwnContents(());

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
    #[cfg(target_os = "macos")]
    pub(super) own: Option<OwnContents>,
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
            #[cfg(target_os = "macos")]
            own: None,
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
                let stage;
                (self, stage) = self.opened(parent_path)?;
                self = self.cleared(&stage, parent_path)?.emptied(
                    &stage,
                    OnUnlistable::Continue,
                    parent_path,
                )?;
                // Without a probe result the fallback for a vanished
                // destination is a private root.
                if let Ok(fresh) = self.probe_umask(AclPlan::None) {
                    self.fresh = Some(fresh);
                }
                self = self.seeded(SeedSource::Destination(id), &inheritance, parent_path)?;
            }
            Seed::Replace(id, inheritance) => {
                let stage;
                (self, stage) = self.opened(parent_path)?;
                self = self.cleared(&stage, parent_path)?.emptied(
                    &stage,
                    OnUnlistable::Continue,
                    parent_path,
                )?;
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
        let stage;
        (self, stage) = self.opened(parent_path)?;
        let mut on_unlistable = OnUnlistable::Continue;
        let plan = match acl::capture_parent(&stage) {
            Ok(ParentAcl::MaskedByMode | ParentAcl::Captured(AclPlan::None)) => None,
            Ok(ParentAcl::Captured(plan)) => {
                self = self.cleared(&stage, parent_path)?;
                on_unlistable = OnUnlistable::Fail;
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
        self = self.emptied(&stage, on_unlistable, parent_path)?;
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
    fn cleared(self, stage: &VerifiedStage, parent_path: &Path) -> Result<Self> {
        match acl::clear_inherited(stage) {
            Ok(()) => Ok(self),
            Err(e) => Err(self.fail(
                &e,
                "failed to clear the access control list the staging directory inherited",
                parent_path,
            )),
        }
    }

    /// Opens the directory through the pinned parent, failing the run when it
    /// is not the one that was created.
    #[cfg(unix)]
    fn opened(self, parent_path: &Path) -> Result<(Self, VerifiedStage)> {
        match self.open_verified() {
            Ok(stage) => Ok((self, stage)),
            Err(e) => Err(self.fail(&e, "failed to open the staging directory", parent_path)),
        }
    }

    /// Proves the cleared directory holds nothing, so what the run publishes
    /// is only what it extracted; an entry planted meanwhile fails the run.
    ///
    /// On macOS the proof also lets a rollback strip the deny entries the
    /// run's own children inherited (see [`OwnContents`]).
    #[cfg(unix)]
    #[cfg_attr(
        not(target_os = "macos"),
        allow(
            unused_mut,
            reason = "only macOS records that the stage holds the run's own entries"
        )
    )]
    fn emptied(
        mut self,
        stage: &VerifiedStage,
        on_unlistable: OnUnlistable,
        parent_path: &Path,
    ) -> Result<Self> {
        match stage.ensure_empty() {
            Ok(()) => {
                #[cfg(target_os = "macos")]
                {
                    self.own = Some(OwnContents(()));
                }
                Ok(self)
            }
            Err(NotEmpty::Planted) => Err(self.fail(
                &io::Error::other("the staging directory is not empty"),
                "the staging directory was written into before the extraction",
                parent_path,
            )),
            // As before the check existed: the run goes on, but without the
            // proof that lets a rollback sweep.
            Err(NotEmpty::Unlistable) if on_unlistable == OnUnlistable::Continue => Ok(self),
            Err(NotEmpty::Unlistable) => Err(self.fail(
                &io::Error::other("the staging directory cannot be listed"),
                "failed to check that the staging directory is empty after clearing its access control list",
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
        let stage;
        (self, stage) = self.opened(parent_path)?;
        self.inherited = match acl::stage(&stage, inheritance) {
            Ok(()) => match source {
                SeedSource::Parent => Inherited::Parent,
                SeedSource::Destination(id) if matches!(inheritance, Inheritance::None) => {
                    Inherited::Destination(id)
                }
                SeedSource::Destination(id) => Inherited::Seeded(id),
            },
            Err(_) => match acl::clear_inherited(&stage) {
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
    pub(super) fn open_verified(&self) -> io::Result<VerifiedStage> {
        let dir = self.parent.open_dir_for_attributes(self.name.as_leaf())?;
        if FileIdentity::of_file(&dir).check(self.id) != IdentityCheck::Same {
            return Err(io::Error::other("the staging directory was replaced"));
        }
        Ok(VerifiedStage(dir))
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
        if std::fs::remove_dir_all(&self.path).is_err() {
            #[cfg(target_os = "macos")]
            self.sweep_own_contents();
        }
    }

    /// Unlinks the run's own entries that inherited a deny entry the removal
    /// stopped at, then the directory itself while it is still the one
    /// created. Best effort, as the removal it follows.
    #[cfg(target_os = "macos")]
    fn sweep_own_contents(&self) {
        let (Some(own), Ok(stage)) = (self.own, self.open_verified()) else {
            return;
        };
        super::sweep::sweep(&stage, own);
        let still_created = matches!(
            self.parent.status(self.name.as_leaf()),
            Ok(Some(observed)) if observed.identity.check(self.id) == IdentityCheck::Same
        );
        if still_created {
            let _ = self.parent.remove_dir(self.name.as_leaf());
        }
    }
}

impl Drop for StagingDir<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.remove_tree();
        }
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn pin_of(temp: &TempDir) -> (VettedDir, PathBuf) {
        let parent = temp.path().canonicalize().unwrap();
        (VettedDir::open_path(&parent).unwrap(), parent)
    }

    /// A staging directory created and claimed, but not yet prepared: the
    /// window in which another user could plant something.
    fn claimed<'p>(pin: &'p VettedDir, parent: &Path) -> StagingDir<'p> {
        let name = LeafBuf::random(PREFIX);
        pin.make_private_dir(name.as_leaf()).unwrap();
        StagingDir::claim(pin, parent, name).unwrap()
    }

    fn seeds() -> [Seed; 3] {
        [
            Seed::Absent,
            Seed::FillEmpty(FileIdentity::Unknown, Inheritance::None),
            Seed::Replace(FileIdentity::Unknown, Inheritance::None),
        ]
    }

    fn staging_names(parent: &Path) -> Vec<std::ffi::OsString> {
        std::fs::read_dir(parent)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().starts_with(PREFIX))
            .collect()
    }

    #[test]
    fn a_file_planted_in_a_claimed_stage_fails_the_run_and_removes_the_stage() {
        for seed in seeds() {
            let temp = TempDir::new().unwrap();
            let (pin, parent) = pin_of(&temp);
            let stage = claimed(&pin, &parent);
            std::fs::write(stage.path().join("planted"), b"x").unwrap();

            let error = stage.prepared(seed, &parent).err().unwrap();

            assert!(error.to_string().contains("written into"), "{error}");
            assert_eq!(staging_names(&parent), Vec::<std::ffi::OsString>::new());
        }
    }

    #[test]
    fn a_stage_replaced_under_its_name_is_not_opened() {
        let temp = TempDir::new().unwrap();
        let (pin, parent) = pin_of(&temp);
        let stage = claimed(&pin, &parent);
        let moved = parent.join("moved");
        std::fs::rename(stage.path(), &moved).unwrap();
        std::fs::create_dir(stage.path()).unwrap();
        #[cfg(target_os = "macos")]
        super::super::test_acl::add_ace(stage.path(), "everyone allow list");

        assert!(stage.open_verified().is_err());

        #[cfg(target_os = "macos")]
        assert_eq!(super::super::test_acl::aces_of(stage.path()).len(), 1);
        assert!(moved.is_dir());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_stage_that_cannot_be_listed_goes_on_without_the_sweep_proof() {
        use super::super::test_acl::AclCleanup;
        use super::super::test_acl::add_ace;

        let temp = TempDir::new().unwrap();
        let _cleanup = AclCleanup(temp.path());
        let (pin, parent) = pin_of(&temp);
        let stage = claimed(&pin, &parent);
        add_ace(stage.path(), "everyone deny list");
        let opened = stage.open_verified().unwrap();

        std::assert_matches!(opened.ensure_empty(), Err(NotEmpty::Unlistable));
        let stage = stage
            .emptied(&opened, OnUnlistable::Continue, &parent)
            .ok()
            .unwrap();

        assert!(stage.own.is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_stage_that_cannot_be_listed_after_its_inherited_acl_was_cleared_fails_the_run() {
        use super::super::test_acl::AclCleanup;
        use super::super::test_acl::add_ace;

        let temp = TempDir::new().unwrap();
        let _cleanup = AclCleanup(temp.path());
        let (pin, parent) = pin_of(&temp);
        let stage = claimed(&pin, &parent);
        add_ace(stage.path(), "everyone deny list");
        let opened = stage.open_verified().unwrap();

        let error = stage
            .emptied(&opened, OnUnlistable::Fail, &parent)
            .err()
            .unwrap();

        assert!(error.to_string().contains("cannot be listed"), "{error}");
        assert!(!error.to_string().contains("written into"), "{error}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_hard_link_planted_in_a_claimed_stage_is_neither_cleared_nor_swept() {
        use super::super::test_acl::AclCleanup;
        use super::super::test_acl::aces_of;
        use super::super::test_acl::add_ace;

        let temp = TempDir::new().unwrap();
        let _cleanup = AclCleanup(temp.path());
        let root = temp.path().canonicalize().unwrap();
        let parent = root.join("parent");
        std::fs::create_dir(&parent).unwrap();
        add_ace(
            &parent,
            "everyone deny delete,file_inherit,directory_inherit",
        );
        let victim = root.join("victim");
        std::fs::write(&victim, b"x").unwrap();
        add_ace(&victim, "everyone deny delete");
        let pin = VettedDir::open_path(&parent).unwrap();
        let stage = claimed(&pin, &parent);
        std::fs::hard_link(&victim, stage.path().join("link")).unwrap();

        let error = stage.prepared(Seed::Absent, &parent).err().unwrap();

        let ArchiveError::PartialExtraction(partial) = &error else {
            panic!("expected a partial extraction, got {error}");
        };
        assert!(partial.leftover().is_some(), "the link cannot be unlinked");
        assert_eq!(aces_of(&victim), ["group:everyone deny delete"]);
    }
}
