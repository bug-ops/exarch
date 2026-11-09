//! Giving the published root the destination's permissions.
//!
//! The staging directory is private (`0700`) while the archive extracts. The
//! root that gets published must look like the destination it replaces, or a
//! `0700` destination would come back `0755` and expose what it holds. The
//! destination's ACL is carried over where it can be, see [`super::acl`].
//!
//! Adoption is split around the publishing rename. [`StagingDir::adopt`] does
//! everything that may still fail the run and returns an [`AdoptedRoot`];
//! the ACL, which may deny deleting the very directory being renamed, is
//! written by [`AdoptedRoot::finish`], which takes the [`Published`] proof the
//! rename returns.

use super::dir::Published;
use super::dir::StagingDir;

#[cfg(unix)]
mod imp {
    use std::io;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::fchown;

    use super::Published;
    use super::StagingDir;
    use crate::NarrowingReason;
    use crate::formats::file_identity::FileIdentity;
    use crate::formats::pinned_dir::EntryMode;
    use crate::formats::pinned_dir::EntryStatus;
    use crate::formats::pinned_dir::LeafBuf;
    use crate::report::Narrowed;
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
        origin: RootOrigin,
    }

    /// What the published root takes its owner and ACL from.
    #[derive(Debug, Clone)]
    enum RootOrigin {
        /// A directory made for a destination that was absent: it keeps the
        /// owner it was created with, and takes the ACL a directory made at
        /// the destination's path was given.
        Fresh { captured: AclPlan },
        /// An existing destination: its owner is taken as far as the claim
        /// allows, and its ACL as `acl` says. `identity` names the directory,
        /// or is unknown when the volume provides none.
        Destination {
            owner: Owner,
            acl: AclPlan,
            identity: FileIdentity,
        },
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
            let mode = if matches!(acl, AclPlan::Private(_)) {
                DirMode::PRIVATE
            } else {
                DirMode::of_destination(status.mode)
            };
            Self {
                mode,
                origin: RootOrigin::Destination {
                    owner: Owner {
                        ids: Ownership {
                            uid: status.mode.uid(),
                            gid: status.mode.gid(),
                        },
                        claim,
                    },
                    acl,
                    identity: status.identity,
                },
            }
        }

        /// The adoption of a root made for an absent destination, with the
        /// mode a new directory gets under the umask and `captured`: the ACL
        /// a directory made at the destination's path was given.
        fn fresh(mode: DirMode, captured: AclPlan) -> Self {
            Self {
                mode,
                origin: RootOrigin::Fresh { captured },
            }
        }

        #[cfg(test)]
        pub(in crate::staging) const fn for_test(
            mode: u32,
            uid: u32,
            gid: u32,
            claim: Claim,
        ) -> Self {
            Self::for_test_with_acl(mode, uid, gid, claim, AclPlan::None)
        }

        #[cfg(test)]
        pub(in crate::staging) const fn for_test_with_acl(
            mode: u32,
            uid: u32,
            gid: u32,
            claim: Claim,
            acl: AclPlan,
        ) -> Self {
            Self {
                mode: DirMode(mode),
                origin: RootOrigin::Destination {
                    owner: Owner {
                        ids: Ownership { uid, gid },
                        claim,
                    },
                    acl,
                    identity: FileIdentity::Unknown,
                },
            }
        }

        /// This adoption as taken from the destination `named` names; a root
        /// made for an absent destination has none.
        #[cfg(test)]
        pub(in crate::staging) fn of_destination_identity(mut self, named: FileIdentity) -> Self {
            if let RootOrigin::Destination { identity, .. } = &mut self.origin {
                *identity = named;
            }
            self
        }
    }

    /// The ACL and mode a root takes once it has been renamed onto the
    /// destination, with the descriptor that was held across the rename.
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    #[derive(Debug)]
    struct PendingCopy {
        dir: std::fs::File,
        acl: acl::CopiedAcl,
        mode: DirMode,
    }

    /// A staging root made as close to the destination as can be before the
    /// publishing rename.
    ///
    /// [`finish`](Self::finish) does the rest, so dropping one leaves the root
    /// as private as it was before the rename.
    #[must_use = "the root's ACL is only written by `finish`"]
    #[derive(Debug)]
    pub(in crate::staging) struct AdoptedRoot {
        narrowed: Narrowed,
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
        pending: Option<PendingCopy>,
    }

    impl AdoptedRoot {
        /// Writes the destination's ACL and then its mode onto the published
        /// root, through the descriptor held across the rename, and returns
        /// every way the root has less access than the destination.
        ///
        /// The `Published` proof only a successful rename gives is what makes
        /// writing the ACL before the rename unrepresentable. The directory is
        /// published by now, so a failure is not an error:
        /// [`NarrowingReason::AclCopyFailed`] is recorded and the root is made
        /// private where the OS lets it.
        pub(in crate::staging) fn finish(self, _published: Published) -> Narrowed {
            #[allow(
                unused_mut,
                reason = "only platforms that copy an ACL have anything to record"
            )]
            let mut narrowed = self.narrowed;
            #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
            if let Some(PendingCopy { dir, acl, mode }) = self.pending {
                copy_acl(&dir, &acl, mode, &mut narrowed);
            }
            narrowed
        }

        /// What has been recorded as narrowed so far, before the rename.
        #[cfg(test)]
        pub(in crate::staging) fn reasons(&self) -> &[NarrowingReason] {
            self.narrowed.reasons()
        }
    }

    impl StagingDir<'_> {
        /// The adoption of a root made for an absent destination: the mode a
        /// new directory gets under the process umask, read from a throwaway
        /// directory made inside the private staging directory (so the umask
        /// is never read through the racy `umask()` call), and `captured`, the
        /// ACL such a directory was given.
        ///
        /// # Errors
        ///
        /// The I/O error of creating, inspecting or removing the probe.
        pub(in crate::staging) fn probe_umask(&self, captured: AclPlan) -> io::Result<Adoption> {
            let staging = self.parent.open_dir(self.name.as_leaf())?;
            for _ in 0..PROBE_ATTEMPTS {
                let probe = LeafBuf::random(".exarch-probe-");
                match staging.make_dir(probe.as_leaf()) {
                    Ok(()) => {
                        let status = staging.status(probe.as_leaf());
                        staging.remove_dir(probe.as_leaf())?;
                        let status =
                            status?.ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
                        return Ok(Adoption::fresh(
                            DirMode::of_umask_probe(status.mode),
                            captured,
                        ));
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
        /// Whatever ACL the root inherited from its parent, or was seeded with
        /// for its children, is removed first, so the root's ACL is the
        /// destination's and nothing else. The destination's ACL is copied
        /// only onto a root that ended up with the destination's uid and gid;
        /// otherwise the root stays `0700`. The copy itself is not made here:
        /// it waits in the returned [`AdoptedRoot`] for
        /// [`finish`](AdoptedRoot::finish), as an entry that denies deleting
        /// the root would stop the publishing rename.
        ///
        /// The root also stays `0700`, with no ACL, when its children could
        /// not inherit from the destination being adopted, or were seeded from
        /// one that is gone (see [`Inherited::withholds`]): they would
        /// otherwise sit under a root that grants more than what they were
        /// made under. The destination's owner is still claimed, so the
        /// owner keeps access, unless the destination is another directory.
        ///
        /// Returns every way the root ended up with less access than the
        /// destination had, and what is left to do after the rename.
        ///
        /// # Errors
        ///
        /// The I/O error of opening the directory, clearing its ACL or
        /// changing its mode, or a directory that is no longer the one
        /// created.
        pub(in crate::staging) fn adopt(&mut self, adoption: Adoption) -> io::Result<AdoptedRoot> {
            // TODO(#1088): rollback after adoption skips the macOS sweep
            #[cfg(target_os = "macos")]
            {
                self.own = None;
            }
            let stage = self.open_verified()?;
            let dir = stage.as_file();
            let Adoption { mut mode, origin } = adoption;
            let (acl, destination, owner) = match origin {
                RootOrigin::Fresh { captured } => (captured, None, None),
                RootOrigin::Destination {
                    owner,
                    acl,
                    identity,
                } => (acl, Some(identity), Some(owner)),
            };
            let mut narrowed = Narrowed::none();
            let withheld = self.inherited.withholds(destination);
            // A fresh root with nothing captured keeps what it has: on Linux
            // that is the parent's default ACL, which a clear would strip.
            if withheld.is_some() || owner.is_some() || !matches!(acl, AclPlan::None) {
                acl::clear_inherited(&stage)?;
            }
            // Another directory than the one that was seeded from has other
            // owners: its uid and gid are not this destination's to claim.
            let claimed = match owner {
                Some(owner) if withheld != Some(NarrowingReason::DestinationChanged) => Some((
                    owner.ids,
                    claim_owner(dir, owner, &mut mode, &mut narrowed)?,
                )),
                Some(_) => None,
                None => {
                    let root = Ownership::of(&dir.metadata()?);
                    Some((root, root))
                }
            };
            let resolution = match (withheld, claimed) {
                (Some(reason), _) => Resolution::Private(reason),
                (None, Some((destination, root))) => acl::resolve(acl, destination, root),
                (None, None) => Resolution::NoAcl,
            };
            #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
            let mut pending = None;
            let applied = match resolution {
                Resolution::NoAcl => dir.set_permissions(mode.permissions()),
                Resolution::Private(reason) => {
                    narrowed.push(reason);
                    dir.set_permissions(DirMode::PRIVATE.permissions())
                }
                #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
                Resolution::Copy(acl) => dir.try_clone().map(|dir| {
                    pending = Some(PendingCopy { dir, acl, mode });
                }),
            };
            self.adopted = Some(stage.into_file());
            applied.map(|()| AdoptedRoot {
                narrowed,
                #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
                pending,
            })
        }

        /// The reason the root stays as private as it is although the
        /// destination vanished before it could be adopted, if its children
        /// were seeded from that destination or could not inherit from it;
        /// the root's ACL is cleared then, as [`adopt`](Self::adopt) does.
        ///
        /// # Errors
        ///
        /// The I/O error of clearing the ACL.
        pub(in crate::staging) fn vanished_reason(&self) -> io::Result<Option<NarrowingReason>> {
            let reason = self.inherited.withholds(None);
            if reason.is_some() {
                acl::clear_inherited(&self.open_verified()?)?;
            }
            Ok(reason)
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
    /// the result in `mode`, records in `narrowed` what could not be kept, and
    /// returns who owns the root afterwards.
    fn claim_owner(
        dir: &std::fs::File,
        owner: Owner,
        mode: &mut DirMode,
        narrowed: &mut Narrowed,
    ) -> io::Result<Ownership> {
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
        if owner.claim == Claim::Full && root.uid != owner.ids.uid {
            narrowed.push(NarrowingReason::OwnerNotKept);
        }
        if root.gid != owner.ids.gid {
            drop_bits(
                mode,
                DirBits::GroupAccessAndSetgid,
                NarrowingReason::GroupNotKept,
                narrowed,
            );
        }
        if owner.claim == Claim::Cautious && !own_destination {
            drop_bits(
                mode,
                DirBits::ForeignWriteAndSetgid,
                NarrowingReason::ForeignWriteDropped,
                narrowed,
            );
        }
        Ok(root)
    }

    /// Clears `bits` from `mode` and records `reason` when that removed any.
    fn drop_bits(
        mode: &mut DirMode,
        bits: DirBits,
        reason: NarrowingReason,
        narrowed: &mut Narrowed,
    ) {
        let reduced = mode.without(bits);
        if reduced != *mode {
            *mode = reduced;
            narrowed.push(reason);
        }
    }

    /// Writes `acl` onto the root, then restores the adopted sticky and setgid
    /// bits on top of the permission bits the ACL produced, so the ACL mask is
    /// not rewritten. A directory without an access ACL gets the destination's
    /// permission bits as they are.
    ///
    /// The root stays `0700` until the ACL is written; see [`write_acl_then`]
    /// for what a failure leaves.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn copy_acl(dir: &std::fs::File, acl: &acl::CopiedAcl, mode: DirMode, narrowed: &mut Narrowed) {
        write_acl_then(dir, acl, narrowed, |dir| {
            let permission = if acl.has_access() {
                dir.metadata()?.mode() & 0o777
            } else {
                mode.permission_bits()
            };
            dir.set_permissions(mode.with_permission_bits(permission).permissions())
        });
    }

    /// Writes `acl` onto the root, then applies the destination's mode, so
    /// the root is never wider than the destination while its entries are
    /// missing; the kernel keeps the ACL across the mode change.
    #[cfg(target_os = "macos")]
    fn copy_acl(dir: &std::fs::File, acl: &acl::CopiedAcl, mode: DirMode, narrowed: &mut Narrowed) {
        write_acl_then(dir, acl, narrowed, |dir| {
            dir.set_permissions(mode.permissions())
        });
    }

    /// Writes `acl` onto the published root and then runs `set_mode`.
    ///
    /// The root is `0700` until the ACL is written. When either step fails
    /// [`NarrowingReason::AclCopyFailed`] is recorded and the ACL is removed
    /// and the mode set to `0700` where the OS allows. The root is published
    /// already, so nothing here can fail the run.
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    fn write_acl_then(
        dir: &std::fs::File,
        acl: &acl::CopiedAcl,
        narrowed: &mut Narrowed,
        set_mode: impl FnOnce(&std::fs::File) -> io::Result<()>,
    ) {
        if acl.write_to(dir).and_then(|()| set_mode(dir)).is_err() {
            // Best effort: the root is published and there is no one to fail.
            let _ = acl::CopiedAcl::clear(dir);
            let _ = dir.set_permissions(DirMode::PRIVATE.permissions());
            narrowed.push(NarrowingReason::AclCopyFailed);
        }
    }

    #[cfg(all(
        test,
        any(target_os = "linux", target_os = "android", target_os = "macos")
    ))]
    #[allow(clippy::unwrap_used)]
    mod post_rename_tests {
        use super::*;
        use crate::formats::pinned_dir::VettedDir;
        use crate::staging::acl::InheritedAcl;

        #[cfg(any(target_os = "linux", target_os = "android"))]
        fn valid_acl() -> acl::CopiedAcl {
            acl::CopiedAcl::for_test(None, Some(InheritedAcl::valid_for_test().bytes().to_vec()))
        }

        #[cfg(target_os = "macos")]
        fn valid_acl() -> acl::CopiedAcl {
            InheritedAcl::valid_for_test().acl().clone()
        }

        #[test]
        fn a_mode_that_fails_after_the_acl_was_written_leaves_a_private_root_without_it() {
            let temp = tempfile::tempdir().unwrap();
            let parent = temp.path().canonicalize().unwrap();
            let root = parent.join("root");
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
            let dir = std::fs::File::open(&root).unwrap();
            let mut narrowed = Narrowed::none();

            write_acl_then(&dir, &valid_acl(), &mut narrowed, |_| {
                Err(io::Error::other("mode refused"))
            });

            assert_eq!(narrowed.reasons(), [NarrowingReason::AclCopyFailed]);
            assert_eq!(dir.metadata().unwrap().mode() & 0o7777, 0o700);
            let pin = VettedDir::open_path(&parent).unwrap();
            let name = LeafBuf::of(&root).unwrap();
            let id = pin.status(name.as_leaf()).unwrap().unwrap().identity;
            let plan = acl::read_destination(&pin, name.as_leaf(), &parent, id).unwrap();
            assert_eq!(plan, AclPlan::None);
        }
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
            let acl = acl::CopiedAcl::for_test(Some(vec![0xff; 7]), Some(default_blob()));
            let mode = DirMode::of_destination(EntryMode::for_test(0o755, 0, 0));
            let mut narrowed = Narrowed::none();

            copy_acl(&dir, &acl, mode, &mut narrowed);

            assert_eq!(narrowed.reasons(), [NarrowingReason::AclCopyFailed]);
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
            let acl = acl::CopiedAcl::for_test(None, None);

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
        let _ = pin.set_dir_mode(name, expected, &super::imp::DirMode::PRIVATE.permissions());
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

    use super::Published;
    use super::StagingDir;
    use crate::formats::pinned_dir::EntryStatus;
    use crate::report::Narrowed;
    use crate::staging::acl::AclPlan;

    /// Platforms without Unix modes publish the staging directory as it is.
    #[derive(Debug, Clone, Copy)]
    pub(in crate::staging) struct Adoption;

    /// Nothing is left to do to a root after its rename here.
    #[derive(Debug)]
    pub(in crate::staging) struct AdoptedRoot;

    impl AdoptedRoot {
        #[allow(
            clippy::unused_self,
            clippy::missing_const_for_fn,
            reason = "keeps the call sites platform-neutral"
        )]
        pub(in crate::staging) fn finish(self, _published: Published) -> Narrowed {
            Narrowed::none()
        }
    }

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

        pub(in crate::staging) fn adopt(&mut self, _adoption: Adoption) -> io::Result<AdoptedRoot> {
            Ok(AdoptedRoot)
        }

        pub(in crate::staging) fn vanished_reason(
            &self,
        ) -> io::Result<Option<crate::NarrowingReason>> {
            Ok(None)
        }

        pub(in crate::staging) fn reset_private(&self) {}
    }
}

pub(super) use imp::Adoption;
#[cfg(all(test, unix))]
pub(super) use imp::Claim;
pub(super) use removable::make_removable;
