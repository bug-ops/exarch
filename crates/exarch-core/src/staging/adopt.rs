//! Giving the published root the destination's permissions.
//!
//! The staging directory is private (`0700`) while the archive extracts. The
//! root that gets published must look like the destination it replaces, or a
//! `0700` destination would come back `0755` and expose what it holds. The
//! destination's ACL is carried over where it can be, see [`super::acl`].

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
    use crate::formats::pinned_dir::EntryMode;
    use crate::formats::pinned_dir::EntryStatus;
    use crate::formats::pinned_dir::LeafBuf;
    use crate::staging::acl;
    use crate::staging::acl::AclPlan;
    use crate::staging::acl::Ownership;
    use crate::staging::acl::Resolution;

    const PROBE_ATTEMPTS: usize = 16;

    /// A group of mode bits that [`DirMode::without`] clears.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(in crate::staging) enum DirBits {
        /// Group read, write and execute, and setgid: meaningless for a group
        /// the directory is not in.
        GroupAccessAndSetgid,
        /// Group and world write, and setgid: not handed to others by a
        /// directory the caller does not own.
        ForeignWriteAndSetgid,
    }

    impl DirBits {
        const fn mask(self) -> u32 {
            match self {
                Self::GroupAccessAndSetgid => 0o2070,
                Self::ForeignWriteAndSetgid => 0o2022,
            }
        }
    }

    /// The mode bits of a directory that is never setuid.
    ///
    /// Built only from a `stat` result or as [`PRIVATE`](Self::PRIVATE), so a
    /// raw mode cannot reach `fchmod` without its setuid bit being dropped.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(in crate::staging) struct DirMode(u32);

    impl DirMode {
        /// Owner read, write and search only.
        pub(in crate::staging) const PRIVATE: Self = Self(0o700);

        /// The mode of an existing destination: permission, sticky and setgid
        /// bits, never setuid.
        pub(in crate::staging) const fn of_destination(mode: EntryMode) -> Self {
            Self(mode.bits() & 0o3777)
        }

        /// The mode a new directory gets under the umask: permission bits only.
        pub(in crate::staging) const fn of_umask_probe(mode: EntryMode) -> Self {
            Self(mode.bits() & 0o777)
        }

        /// This mode with `bits` cleared.
        #[must_use]
        pub(in crate::staging) const fn without(self, bits: DirBits) -> Self {
            Self(self.0 & !bits.mask())
        }

        /// This mode with its permission bits replaced and its sticky and
        /// setgid bits kept.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        #[must_use]
        const fn with_permission_bits(self, permission: u32) -> Self {
            Self((self.0 & 0o7000) | (permission & 0o777))
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        const fn permission_bits(self) -> u32 {
            self.0 & 0o777
        }

        #[cfg(test)]
        pub(in crate::staging) const fn as_u32(self) -> u32 {
            self.0
        }

        pub(in crate::staging) fn permissions(self) -> std::fs::Permissions {
            std::fs::Permissions::from_mode(self.0)
        }
    }

    /// The permission bits, owner and ACL the published root takes.
    #[derive(Debug, Clone)]
    pub(in crate::staging) struct Adoption {
        mode: DirMode,
        owner: Option<Owner>,
        acl: AclPlan,
    }

    #[derive(Debug, Clone, Copy)]
    struct Owner {
        ids: Ownership,
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
        /// The mode, owner and ACL of an existing destination directory
        /// (sticky and setgid bits included, setuid never).
        pub(in crate::staging) fn of(status: &EntryStatus, acl: AclPlan) -> Self {
            Self::claiming(status, Claim::Full, acl)
        }

        /// Like [`of`](Self::of) for an existing but empty destination that
        /// is filled rather than replaced: its owner is not adopted, see
        /// [`Claim::Cautious`].
        pub(in crate::staging) fn of_empty_destination(status: &EntryStatus, acl: AclPlan) -> Self {
            Self::claiming(status, Claim::Cautious, acl)
        }

        fn claiming(status: &EntryStatus, claim: Claim, acl: AclPlan) -> Self {
            let mode = if acl == AclPlan::Private {
                DirMode::PRIVATE
            } else {
                DirMode::of_destination(status.mode)
            };
            Self {
                mode,
                owner: Some(Owner {
                    ids: Ownership {
                        uid: status.mode.uid(),
                        gid: status.mode.gid(),
                    },
                    claim,
                }),
                acl,
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
                mode: DirMode(mode),
                owner: Some(Owner {
                    ids: Ownership { uid, gid },
                    claim,
                }),
                acl: AclPlan::None,
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
                            mode: DirMode::of_umask_probe(status.mode),
                            owner: None,
                            acl: AclPlan::None,
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
        /// Whatever ACL the root inherited from its parent is removed first, so
        /// the root's ACL is the destination's and nothing else. The
        /// destination's ACL is copied only onto a root that ended up with the
        /// destination's uid and gid; otherwise, and when the copy fails, the
        /// root stays `0700`.
        ///
        /// # Errors
        ///
        /// The I/O error of opening the directory, clearing its ACL or
        /// changing its mode, or a directory that is no longer the one
        /// created.
        pub(in crate::staging) fn adopt(&mut self, adoption: Adoption) -> io::Result<()> {
            let dir = self.parent.open_dir_file(self.name.as_leaf())?;
            if FileIdentity::of_file(&dir).check(self.id) != IdentityCheck::Same {
                return Err(io::Error::other("the staging directory was replaced"));
            }
            let Adoption {
                mut mode,
                owner,
                acl,
            } = adoption;
            let resolution = match owner {
                Some(owner) => {
                    acl::clear_inherited(self.parent, self.name.as_leaf())?;
                    let root = claim_owner(&dir, owner, &mut mode)?;
                    acl::resolve(acl, owner.ids, root)
                }
                None => Resolution::NoAcl,
            };
            let applied = match resolution {
                Resolution::NoAcl => dir.set_permissions(mode.permissions()),
                Resolution::Private => dir.set_permissions(DirMode::PRIVATE.permissions()),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Resolution::Copy(acl) => copy_acl(&dir, &acl, mode),
            };
            self.adopted = Some(dir);
            applied
        }

        /// Makes an adopted directory private again, through the descriptor
        /// opened before the mode changed, so it can be removed.
        pub(in crate::staging) fn reset_private(&self) {
            if let Some(dir) = &self.adopted {
                // Best effort: this runs on the way to removing the directory.
                let _ = dir.set_permissions(DirMode::PRIVATE.permissions());
            }
        }
    }

    /// Takes over as much of the destination's owner as `owner.claim` and the
    /// caller's privileges allow, drops the mode bits that would be wrong for
    /// the result in `mode`, and returns who owns the root afterwards.
    fn claim_owner(dir: &std::fs::File, owner: Owner, mode: &mut DirMode) -> io::Result<Ownership> {
        let own_destination = owner.ids.uid == dir.metadata()?.uid();
        // Best effort: only root may chown to a foreign uid, and a group
        // member to any of its groups. The outcome is read back.
        if owner.claim == Claim::Full || own_destination {
            let _ = fchown(dir, None, Some(owner.ids.gid));
        }
        if owner.claim == Claim::Full {
            let _ = fchown(dir, Some(owner.ids.uid), None);
        }
        let root = Ownership::of(&dir.metadata()?);
        if root.gid != owner.ids.gid {
            *mode = mode.without(DirBits::GroupAccessAndSetgid);
        }
        if owner.claim == Claim::Cautious && !own_destination {
            *mode = mode.without(DirBits::ForeignWriteAndSetgid);
        }
        Ok(root)
    }

    /// Writes `acl` onto the root, then restores the adopted sticky and setgid
    /// bits on top of the permission bits the ACL produced, so the ACL mask is
    /// not rewritten. A directory without an access ACL gets the destination's
    /// permission bits as they are.
    ///
    /// The root stays `0700` until the ACL is written. When writing fails the
    /// ACL is removed again and the root stays private; when that fails too the
    /// error is returned, so the publish fails instead of exposing the root.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn copy_acl(dir: &std::fs::File, acl: &acl::PosixAcl, mode: DirMode) -> io::Result<()> {
        let copied = acl.write_to(dir).and_then(|()| {
            let permission = if acl.has_access() {
                dir.metadata()?.mode() & 0o777
            } else {
                mode.permission_bits()
            };
            dir.set_permissions(mode.with_permission_bits(permission).permissions())
        });
        if copied.is_err() {
            acl::PosixAcl::clear(dir)?;
            dir.set_permissions(DirMode::PRIVATE.permissions())?;
        }
        Ok(())
    }

    #[cfg(all(test, any(target_os = "linux", target_os = "android")))]
    #[allow(clippy::unwrap_used)]
    mod copy_acl_tests {
        use super::*;

        const ACCESS: &str = "system.posix_acl_access";
        const DEFAULT: &str = "system.posix_acl_default";

        /// A valid default ACL: version 2 with the owner, group and other
        /// entries.
        fn default_blob() -> Vec<u8> {
            let mut bytes = 2_u32.to_le_bytes().to_vec();
            for (tag, perm) in [(0x01_u16, 7_u16), (0x04, 5), (0x20, 0)] {
                bytes.extend_from_slice(&tag.to_le_bytes());
                bytes.extend_from_slice(&perm.to_le_bytes());
                bytes.extend_from_slice(&u32::MAX.to_le_bytes());
            }
            bytes
        }

        fn has(dir: &std::fs::File, name: &str) -> bool {
            let mut buffer = vec![0_u8; 65_536];
            rustix::fs::fgetxattr(dir, name, &mut buffer[..]).is_ok()
        }

        #[test]
        fn a_rejected_acl_leaves_a_private_root_without_either_acl() {
            let temp = tempfile::tempdir().unwrap();
            let dir = std::fs::File::open(temp.path()).unwrap();
            let acl = acl::PosixAcl::for_test(Some(vec![0xff; 7]), Some(default_blob()));
            let mode = DirMode::of_destination(EntryMode::for_test(0o755, 0, 0));

            copy_acl(&dir, &acl, mode).unwrap();

            assert_eq!(dir.metadata().unwrap().mode() & 0o7777, 0o700);
            assert!(!has(&dir, ACCESS));
            assert!(!has(&dir, DEFAULT));
        }

        #[test]
        fn an_acl_that_is_absent_from_the_copy_is_removed_from_the_root() {
            let temp = tempfile::tempdir().unwrap();
            let dir = std::fs::File::open(temp.path()).unwrap();
            rustix::fs::fsetxattr(
                &dir,
                DEFAULT,
                &default_blob(),
                rustix::fs::XattrFlags::empty(),
            )
            .unwrap();
            let acl = acl::PosixAcl::for_test(None, None);

            acl.write_to(&dir).unwrap();

            assert!(!has(&dir, DEFAULT));
        }
    }
}

#[cfg(all(test, unix))]
mod dir_mode_tests {
    use super::imp::DirBits;
    use super::imp::DirMode;
    use crate::formats::pinned_dir::EntryMode;

    const ALL_BITS: EntryMode = EntryMode::for_test(0o7777, 1, 1);

    #[test]
    fn a_destination_mode_never_carries_setuid() {
        assert_eq!(DirMode::of_destination(ALL_BITS).as_u32(), 0o3777);
    }

    #[test]
    fn an_umask_probe_mode_carries_permission_bits_only() {
        assert_eq!(DirMode::of_umask_probe(ALL_BITS).as_u32(), 0o777);
    }

    #[test]
    fn dropping_bits_leaves_the_rest() {
        let mode = DirMode::of_destination(ALL_BITS);
        assert_eq!(mode.without(DirBits::GroupAccessAndSetgid).as_u32(), 0o1707);
        assert_eq!(
            mode.without(DirBits::ForeignWriteAndSetgid).as_u32(),
            0o1755
        );
    }

    #[test]
    fn a_private_mode_is_owner_only() {
        assert_eq!(DirMode::PRIVATE.as_u32(), 0o700);
    }
}

#[cfg(unix)]
mod removable {
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
            let _ = dir.set_permissions(super::imp::DirMode::PRIVATE.permissions());
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
    use crate::staging::acl::AclPlan;

    /// Platforms without Unix modes publish the staging directory as it is.
    #[derive(Debug, Clone, Copy)]
    pub(in crate::staging) struct Adoption;

    impl Adoption {
        pub(in crate::staging) const fn of(_status: &EntryStatus, _acl: AclPlan) -> Self {
            Self
        }

        pub(in crate::staging) const fn of_empty_destination(
            _status: &EntryStatus,
            _acl: AclPlan,
        ) -> Self {
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
