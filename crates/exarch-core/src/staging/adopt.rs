//! Giving the published root the destination's permissions.
//!
//! The staging directory is private (`0700`) while the archive extracts. The
//! root that gets published must look like the destination it replaces, or a
//! `0700` destination would come back `0755` and expose what it holds.

use super::dir::StagingDir;

#[cfg(unix)]
mod imp {
    use std::io;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::fchown;

    use super::StagingDir;
    use crate::formats::file_identity::FileIdentity;
    use crate::formats::file_identity::IdentityCheck;
    use crate::formats::pinned_dir::EntryStatus;
    use crate::formats::pinned_dir::LeafBuf;

    const PROBE_ATTEMPTS: usize = 16;
    const GROUP_ACCESS_AND_SETGID: u32 = 0o2070;
    pub(super) const PRIVATE: u32 = 0o700;
    const FOREIGN_WRITE_AND_SETGID: u32 = 0o2022;

    /// The permission bits and owner the published root takes.
    #[derive(Debug, Clone, Copy)]
    pub(in crate::staging) struct Adoption {
        mode: u32,
        owner: Option<Owner>,
    }

    #[derive(Debug, Clone, Copy)]
    struct Owner {
        uid: u32,
        gid: u32,
        claim: Claim,
    }

    /// How far the published root takes over the destination's owner.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(in crate::staging) enum Claim {
        /// The uid and the gid, as for a destination being replaced.
        Full,
        /// Never the uid; the gid only when the caller owns the destination;
        /// and a destination the caller does not own gives up its group and
        /// world write bits and its setgid bit. An empty directory someone else
        /// made must not hand them the tree.
        Cautious,
    }

    impl Adoption {
        /// The mode and owner of an existing destination directory (sticky
        /// and setgid bits included, setuid never).
        pub(in crate::staging) fn of(status: &EntryStatus) -> Self {
            Self::claiming(status, Claim::Full)
        }

        /// Like [`of`](Self::of) for an existing but empty destination that
        /// is filled rather than replaced: its owner is not adopted, see
        /// [`Claim::Cautious`].
        pub(in crate::staging) fn of_empty_destination(status: &EntryStatus) -> Self {
            Self::claiming(status, Claim::Cautious)
        }

        fn claiming(status: &EntryStatus, claim: Claim) -> Self {
            Self {
                mode: status.mode.bits & 0o3777,
                owner: Some(Owner {
                    uid: status.mode.uid,
                    gid: status.mode.gid,
                    claim,
                }),
            }
        }

        #[cfg(test)]
        pub(in crate::staging) const fn for_test(
            mode: u32,
            uid: u32,
            gid: u32,
            claim: Claim,
        ) -> Self {
            Self {
                mode,
                owner: Some(Owner { uid, gid, claim }),
            }
        }
    }

    impl StagingDir<'_> {
        /// The mode a new directory gets under the process umask, read from a
        /// throwaway directory made inside the private staging directory, so
        /// the umask is never read through the racy `umask()` call.
        ///
        /// # Errors
        ///
        /// The I/O error of creating, inspecting or removing the probe.
        pub(in crate::staging) fn probe_umask(&self) -> io::Result<Adoption> {
            let staging = self.parent.open_dir(self.name.as_leaf())?;
            for _ in 0..PROBE_ATTEMPTS {
                let probe = LeafBuf::random(".exarch-probe-");
                match staging.make_dir(probe.as_leaf()) {
                    Ok(()) => {
                        let status = staging.status(probe.as_leaf());
                        staging.remove_dir(probe.as_leaf())?;
                        let status =
                            status?.ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
                        return Ok(Adoption {
                            mode: status.mode.bits & 0o777,
                            owner: None,
                        });
                    }
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e),
                }
            }
            Err(io::Error::from(io::ErrorKind::AlreadyExists))
        }

        /// Applies `adoption` to the staging directory through a descriptor.
        ///
        /// A [`Claim::Cautious`] adoption never changes the uid.
        ///
        /// The group is applied alone and first, so a uid the caller may not
        /// give away cannot take a group it may keep down with it. When the
        /// directory still is not in the destination's group, the group
        /// permission bits and setgid are dropped instead of being granted to
        /// whichever group the directory ended up in.
        ///
        /// # Errors
        ///
        /// The I/O error of opening the directory or changing its mode, or a
        /// directory that is no longer the one created.
        pub(in crate::staging) fn adopt(&mut self, adoption: Adoption) -> io::Result<()> {
            let dir = self.parent.open_dir_file(self.name.as_leaf())?;
            if FileIdentity::of_file(&dir).check(self.id) != IdentityCheck::Same {
                return Err(io::Error::other("the staging directory was replaced"));
            }
            let mut mode = adoption.mode;
            if let Some(owner) = adoption.owner {
                let ours = dir.metadata()?.uid();
                let own_destination = owner.uid == ours;
                // Best effort: only root may chown to a foreign uid, and a
                // group member to any of its groups. The outcome is read back.
                if owner.claim == Claim::Full || own_destination {
                    let _ = fchown(&dir, None, Some(owner.gid));
                }
                if owner.claim == Claim::Full {
                    let _ = fchown(&dir, Some(owner.uid), None);
                }
                if dir.metadata()?.gid() != owner.gid {
                    mode &= !GROUP_ACCESS_AND_SETGID;
                }
                if owner.claim == Claim::Cautious && !own_destination {
                    mode &= !FOREIGN_WRITE_AND_SETGID;
                }
            }
            let applied = dir.set_permissions(std::fs::Permissions::from_mode(mode));
            self.adopted = Some(dir);
            applied
        }

        /// Makes an adopted directory private again, through the descriptor
        /// opened before the mode changed, so it can be removed.
        pub(in crate::staging) fn reset_private(&self) {
            if let Some(dir) = &self.adopted {
                // Best effort: this runs on the way to removing the directory.
                let _ = dir.set_permissions(std::fs::Permissions::from_mode(PRIVATE));
            }
        }
    }
}

#[cfg(unix)]
mod removable {
    use std::os::unix::fs::PermissionsExt;

    use crate::formats::file_identity::FileIdentity;
    use crate::formats::file_identity::IdentityCheck;
    use crate::formats::pinned_dir::Leaf;
    use crate::formats::pinned_dir::VettedDir;

    /// Makes the directory `name` of `pin` writable by its owner so it can be
    /// removed, through a descriptor on the entry itself, when it still is
    /// the directory `expected` names. Best effort: the removal reports what
    /// survives.
    pub(in crate::staging) fn make_removable(
        pin: &VettedDir,
        name: Leaf<'_>,
        expected: FileIdentity,
    ) {
        let Ok(dir) = pin.open_dir_file(name) else {
            return;
        };
        if FileIdentity::of_file(&dir).check(expected) != IdentityCheck::Different {
            let _ = dir.set_permissions(std::fs::Permissions::from_mode(super::imp::PRIVATE));
        }
    }
}

#[cfg(not(unix))]
mod removable {
    use crate::formats::file_identity::FileIdentity;
    use crate::formats::pinned_dir::Leaf;
    use crate::formats::pinned_dir::VettedDir;

    /// Windows removal does not depend on the directory's mode bits.
    pub(in crate::staging) const fn make_removable(
        _pin: &VettedDir,
        _name: Leaf<'_>,
        _expected: FileIdentity,
    ) {
    }
}

#[cfg(not(unix))]
mod imp {
    use std::io;

    use super::StagingDir;
    use crate::formats::pinned_dir::EntryStatus;

    /// Platforms without Unix modes publish the staging directory as it is.
    #[derive(Debug, Clone, Copy)]
    pub(in crate::staging) struct Adoption;

    impl Adoption {
        pub(in crate::staging) const fn of(_status: &EntryStatus) -> Self {
            Self
        }

        pub(in crate::staging) const fn of_empty_destination(_status: &EntryStatus) -> Self {
            Self
        }
    }

    // No permission model to adopt here, so these only keep the call sites
    // platform-neutral.
    #[allow(
        clippy::unused_self,
        clippy::unnecessary_wraps,
        clippy::needless_pass_by_ref_mut
    )]
    impl StagingDir<'_> {
        pub(in crate::staging) fn probe_umask(&self) -> io::Result<Adoption> {
            Ok(Adoption)
        }

        pub(in crate::staging) fn adopt(&mut self, _adoption: Adoption) -> io::Result<()> {
            Ok(())
        }

        pub(in crate::staging) fn reset_private(&self) {}
    }
}

pub(super) use imp::Adoption;
#[cfg(all(test, unix))]
pub(super) use imp::Claim;
pub(super) use removable::make_removable;
