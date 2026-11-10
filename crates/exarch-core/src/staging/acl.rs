//! The access control list of the destination the published root replaces.
//!
//! The published root takes the destination's mode bits, but a mode cannot say
//! what an ACL says: on Linux the group bits of a directory with a POSIX ACL
//! hold the ACL mask, and a macOS deny entry has no mode bit at all. A root
//! given only the mode could be readable by users the destination denied.
//!
//! Linux, Android and macOS copy the ACL onto the root. Wherever an ACL cannot
//! be carried over faithfully the root stays private (`0700`) and the reason
//! is reported as a [`NarrowingReason`](crate::NarrowingReason). Other Unixes
//! and `NFSv4` ACLs are not detected.
//!
//! A staging directory made in the destination's parent also inherits that
//! parent's default ACL (Linux) or inheritable entries (macOS). For an
//! existing destination those are removed at creation and again at adoption,
//! and a failure to remove them fails the run. For an absent destination
//! macOS captures them first, clears them, and seeds them back for children
//! only, so the directory is private; Linux leaves them, which its mode masks.
//!
//! The children of an in-place extraction inherit the destination's own
//! inheritable entries, so the staging directory is seeded with them at
//! creation (see [`Inheritance`]): the Linux default ACL, and on macOS the
//! inheritable entries rewritten as `ONLY_INHERIT`, which children receive and
//! the staging directory itself does not apply. Adoption then replaces the
//! seed with the destination's full list, which is written only once the
//! directory has been renamed onto the destination: an entry that denies
//! deleting would stop the rename.

/// What the children of a staging directory inherit from the destination the
/// staged tree will fill or replace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Inheritance {
    /// The destination has nothing its children inherit.
    None,
    /// Inheritable entries to write onto the staging directory before
    /// anything is extracted into it.
    #[cfg(acl_copy)]
    Stage(InheritedAcl),
    /// The destination's ACL cannot be carried faithfully, so its children
    /// inherit nothing from it and the published root stays `0700`.
    #[cfg(unix)]
    #[cfg_attr(
        not(acl_copy),
        allow(
            dead_code,
            reason = "only platforms that look for an ACL ever withhold the inheritance"
        )
    )]
    Withheld(crate::NarrowingReason),
}

/// Reads the inheritance of the directory `name` of `pin`, which must still be
/// the directory `expected` names.
///
/// # Errors
///
/// The I/O error of [`read_destination`].
#[cfg(unix)]
pub(super) fn read_inheritance(
    pin: &crate::formats::pinned_dir::VettedDir,
    name: crate::formats::pinned_dir::Leaf<'_>,
    parent_path: &std::path::Path,
    expected: crate::formats::file_identity::FileIdentity,
) -> std::io::Result<Inheritance> {
    read_destination(pin, name, parent_path, expected).map(|plan| plan.inheritance())
}

/// Platforms without Unix ACLs have no inheritance to carry.
#[cfg(not(unix))]
#[allow(
    clippy::unnecessary_wraps,
    clippy::missing_const_for_fn,
    reason = "keeps the call sites platform-neutral"
)]
pub(super) fn read_inheritance(
    _pin: &crate::formats::pinned_dir::VettedDir,
    _name: crate::formats::pinned_dir::Leaf<'_>,
    _parent_path: &std::path::Path,
    _expected: crate::formats::file_identity::FileIdentity,
) -> std::io::Result<Inheritance> {
    Ok(Inheritance::None)
}

#[cfg(unix)]
mod imp {
    use crate::NarrowingReason;
    use crate::formats::pinned_dir::Gid;
    use crate::formats::pinned_dir::Uid;
    use crate::staging::dir::VerifiedStage;

    /// The user and group a directory belongs to.
    ///
    /// An ACL names its owner and owning group by id, so it only keeps its
    /// meaning on a directory that has the same ones.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(in crate::staging) struct Ownership {
        pub(in crate::staging) uid: Uid,
        pub(in crate::staging) gid: Gid,
    }

    impl Ownership {
        pub(in crate::staging) fn of(metadata: &std::fs::Metadata) -> Self {
            Self {
                uid: Uid::of(metadata),
                gid: Gid::of(metadata),
            }
        }
    }

    /// What the published root does about the destination's ACL.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(in crate::staging) enum AclPlan {
        /// No ACL was found, or this platform does not look for one.
        None,
        /// Copy the ACL onto the root.
        #[cfg(acl_copy)]
        Copy(super::CopiedAcl),
        /// The ACL cannot be copied faithfully: the root stays `0700`.
        #[cfg_attr(
            not(acl_copy),
            allow(
                dead_code,
                reason = "only platforms that look for an ACL ever fall back to a private root"
            )
        )]
        Private(NarrowingReason),
    }

    /// What `adopt` does with an [`AclPlan`] once the root's owner is known.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(in crate::staging) enum Resolution {
        /// Nothing to copy; the destination's mode is applied as it is.
        NoAcl,
        /// Write this ACL onto the root.
        #[cfg(acl_copy)]
        Copy(super::CopiedAcl),
        /// Keep the root `0700`, for this reason.
        Private(NarrowingReason),
    }

    /// Decides what to do with `plan` for a root that ended up owned by `root`
    /// when the destination was owned by `destination`.
    ///
    /// An ACL copied onto a root with another owner or group would grant the
    /// destination's owner entry to the wrong user, so it is not copied.
    #[cfg_attr(
        not(acl_copy),
        allow(
            unused_variables,
            clippy::needless_pass_by_value,
            reason = "only a copied ACL depends on who owns the root"
        )
    )]
    pub(in crate::staging) fn resolve(
        plan: AclPlan,
        destination: Ownership,
        root: Ownership,
    ) -> Resolution {
        let same_owner = destination == root;
        match plan {
            AclPlan::None => Resolution::NoAcl,
            #[cfg(acl_copy)]
            AclPlan::Copy(acl) if same_owner => Resolution::Copy(acl),
            #[cfg(acl_copy)]
            AclPlan::Copy(_) => Resolution::Private(NarrowingReason::OwnershipDiffers),
            AclPlan::Private(reason) => Resolution::Private(reason),
        }
    }

    /// What a new directory got from the ACL of its parent.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(in crate::staging) enum ParentAcl {
        /// Nothing that is read or cleared: a POSIX default ACL lives in the
        /// mode's group bits, and clearing it would hide it from the umask
        /// probe.
        #[cfg_attr(
            target_os = "macos",
            allow(dead_code, reason = "macOS lists the inherited entries instead")
        )]
        MaskedByMode,
        /// The list the directory inherited, read before it is cleared.
        #[cfg_attr(
            not(target_os = "macos"),
            allow(dead_code, reason = "only macOS lists the inherited entries")
        )]
        Captured(AclPlan),
    }

    /// Reads what `stage`, just created in a parent, inherited from that
    /// parent. Only macOS lists it: its inherited entries are ordinary ACL
    /// entries the directory applies to itself.
    ///
    /// # Errors
    ///
    /// The I/O error of reading the list through the descriptor, or a bad
    /// descriptor.
    #[cfg(target_os = "macos")]
    pub(in crate::staging) fn capture_parent(stage: &VerifiedStage) -> std::io::Result<ParentAcl> {
        super::macos::read_stage(stage.as_file()).map(ParentAcl::Captured)
    }

    /// Only macOS lists what a new directory inherited.
    #[cfg(not(target_os = "macos"))]
    #[allow(
        clippy::unnecessary_wraps,
        clippy::missing_const_for_fn,
        reason = "keeps the signature of the platform that captures the parent's list"
    )]
    pub(in crate::staging) fn capture_parent(_stage: &VerifiedStage) -> std::io::Result<ParentAcl> {
        Ok(ParentAcl::MaskedByMode)
    }

    impl AclPlan {
        /// What the children of a directory with this ACL inherit.
        pub(in crate::staging) fn inheritance(&self) -> super::Inheritance {
            match self {
                Self::None => super::Inheritance::None,
                #[cfg(acl_copy)]
                Self::Copy(acl) => acl
                    .inheritance()
                    .map_or(super::Inheritance::None, super::Inheritance::Stage),
                Self::Private(reason) => super::Inheritance::Withheld(*reason),
            }
        }
    }

    /// Writes `inheritance` onto the freshly cleared staging directory `dir`.
    ///
    /// # Errors
    ///
    /// The I/O error of writing the entries.
    #[cfg(acl_copy)]
    pub(in crate::staging) fn stage(
        dir: &VerifiedStage,
        inheritance: &super::Inheritance,
    ) -> std::io::Result<()> {
        match inheritance {
            super::Inheritance::Stage(acl) => acl.write_to(dir.as_file()),
            super::Inheritance::None | super::Inheritance::Withheld(_) => Ok(()),
        }
    }

    /// Other Unixes carry no ACL handling.
    #[cfg(not(acl_copy))]
    #[allow(
        clippy::unnecessary_wraps,
        clippy::missing_const_for_fn,
        reason = "keeps the signature of the platforms that stage an ACL"
    )]
    pub(in crate::staging) fn stage(
        _dir: &VerifiedStage,
        _inheritance: &super::Inheritance,
    ) -> std::io::Result<()> {
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(in crate::staging) use super::linux::clear_inherited;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(in crate::staging) use super::linux::read_destination;
    #[cfg(target_os = "macos")]
    pub(in crate::staging) use super::macos::clear_inherited;
    #[cfg(target_os = "macos")]
    pub(in crate::staging) use super::macos::read_destination;

    /// Other Unixes carry no ACL handling.
    #[cfg(not(acl_copy))]
    #[allow(
        clippy::unnecessary_wraps,
        clippy::missing_const_for_fn,
        reason = "keeps the signature of the platforms that clear an ACL"
    )]
    pub(in crate::staging) fn clear_inherited(_stage: &VerifiedStage) -> std::io::Result<()> {
        Ok(())
    }

    /// Other Unixes carry no ACL detection.
    #[cfg(not(acl_copy))]
    #[allow(
        clippy::unnecessary_wraps,
        clippy::missing_const_for_fn,
        reason = "keeps the signature of the platforms that read an ACL"
    )]
    pub(in crate::staging) fn read_destination(
        _pin: &crate::formats::pinned_dir::VettedDir,
        _name: crate::formats::pinned_dir::Leaf<'_>,
        _parent_path: &std::path::Path,
        _expected: crate::formats::file_identity::FileIdentity,
    ) -> std::io::Result<AclPlan> {
        Ok(AclPlan::None)
    }

    /// Whether `observed` is still the entry `expected` names.
    #[cfg(acl_copy)]
    pub(super) fn is_expected(
        observed: crate::formats::file_identity::FileIdentity,
        expected: crate::formats::file_identity::FileIdentity,
    ) -> bool {
        observed.check(expected) == crate::formats::file_identity::IdentityCheck::Same
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const DESTINATION: Ownership = Ownership {
            uid: Uid::from_raw(1000),
            gid: Gid::from_raw(100),
        };

        #[test]
        fn a_destination_without_an_acl_resolves_to_no_acl() {
            let other = Ownership {
                uid: Uid::from_raw(0),
                gid: Gid::from_raw(0),
            };
            assert_eq!(
                resolve(AclPlan::None, DESTINATION, other),
                Resolution::NoAcl
            );
        }

        #[test]
        fn a_private_plan_stays_private_for_its_reason_whoever_owns_the_root() {
            assert_eq!(
                resolve(
                    AclPlan::Private(NarrowingReason::AclUnreadable),
                    DESTINATION,
                    DESTINATION
                ),
                Resolution::Private(NarrowingReason::AclUnreadable)
            );
        }

        #[cfg(acl_copy)]
        mod copied {
            use std::assert_matches;

            use super::*;

            #[cfg(any(target_os = "linux", target_os = "android"))]
            fn plan() -> AclPlan {
                AclPlan::Copy(crate::staging::acl::CopiedAcl::for_test(
                    Some(vec![2, 0, 0, 0]),
                    None,
                ))
            }

            #[cfg(target_os = "macos")]
            fn plan() -> AclPlan {
                AclPlan::Copy(crate::staging::acl::CopiedAcl::for_test())
            }

            #[test]
            fn an_acl_is_copied_onto_a_root_with_the_same_owner_and_group() {
                assert_matches!(
                    resolve(plan(), DESTINATION, DESTINATION),
                    Resolution::Copy(_)
                );
            }

            #[test]
            fn an_acl_is_not_copied_onto_a_root_in_another_group() {
                let root = Ownership {
                    gid: Gid::from_raw(DESTINATION.gid.get() + 1),
                    ..DESTINATION
                };
                assert_eq!(
                    resolve(plan(), DESTINATION, root),
                    Resolution::Private(NarrowingReason::OwnershipDiffers)
                );
            }

            #[test]
            fn an_acl_is_not_copied_onto_a_root_of_another_user() {
                let root = Ownership {
                    uid: Uid::from_raw(DESTINATION.uid.get() + 1),
                    ..DESTINATION
                };
                assert_eq!(
                    resolve(plan(), DESTINATION, root),
                    Resolution::Private(NarrowingReason::OwnershipDiffers)
                );
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux {
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::path::Path;

    use rustix::io::Errno;

    use super::imp::AclPlan;
    use crate::NarrowingReason;
    use crate::formats::file_identity::FileIdentity;
    use crate::formats::le;
    use crate::formats::pinned_dir::DirHandle;
    use crate::formats::pinned_dir::Leaf;
    use crate::formats::pinned_dir::VettedDir;
    use crate::staging::dir::VerifiedStage;

    const ACCESS: &str = "system.posix_acl_access";
    const DEFAULT: &str = "system.posix_acl_default";
    /// `XATTR_SIZE_MAX`: no extended attribute value is larger.
    const XATTR_SIZE_MAX: usize = 65_536;
    const VERSION: u32 = 2;
    const HEADER_LEN: usize = 4;
    const ENTRY_LEN: usize = 8;
    const TAG_USER: u16 = 0x02;
    const TAG_GROUP: u16 = 0x08;
    /// What the kernel returns for an id the reader's namespace cannot map
    /// (`ACL_UNDEFINED_ID`). No valid named entry carries it.
    const UNDEFINED_ID: u32 = u32::MAX;

    /// A POSIX ACL extended attribute that has the version-2 header and a whole
    /// number of 8-byte entries.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(in crate::staging) struct AclBlob(Box<[u8]>);

    impl AclBlob {
        /// Checks the shape of `bytes` as read from the kernel.
        ///
        /// # Errors
        ///
        /// [`NarrowingReason::AclUnreadable`] for a value that is too large,
        /// has another version or has a partial entry.
        fn parse(bytes: &[u8]) -> Result<Self, NarrowingReason> {
            let version = le::u32_at(bytes, 0);
            let whole_entries = bytes
                .len()
                .checked_sub(HEADER_LEN)
                .is_some_and(|rest| rest.is_multiple_of(ENTRY_LEN));
            if version == Some(VERSION) && whole_entries && bytes.len() <= XATTR_SIZE_MAX {
                Ok(Self(Box::from(bytes)))
            } else {
                Err(NarrowingReason::AclUnreadable)
            }
        }

        /// Whether a named user or group entry carries the undefined id.
        fn names_an_undefined_id(&self) -> bool {
            self.0
                .get(HEADER_LEN..)
                .unwrap_or_default()
                .as_chunks::<ENTRY_LEN>()
                .0
                .iter()
                .any(|entry| {
                    let tag = le::u16_at(entry, 0);
                    let id = le::u32_at(entry, 4);
                    matches!(tag, Some(TAG_USER | TAG_GROUP)) && id == Some(UNDEFINED_ID)
                })
        }
    }

    /// The two POSIX ACL extended attributes of a directory, as stored.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(in crate::staging) struct PosixAcl {
        access: Option<AclBlob>,
        default: Option<AclBlob>,
    }

    impl PosixAcl {
        /// Whether the directory has an access ACL, which sets the group bits
        /// of its mode to the ACL mask.
        pub(in crate::staging) const fn has_access(&self) -> bool {
            self.access.is_some()
        }

        /// The default ACL, which is what children inherit.
        pub(in crate::staging) fn inheritance(&self) -> Option<InheritedAcl> {
            self.default.clone().map(InheritedAcl)
        }

        /// Makes the ACLs of `dir` exactly these: a blob that is present is
        /// written (default first, then access) and one that is absent is
        /// removed, so nothing inherited from the parent survives.
        ///
        /// The kernel derives the owner, mask and other bits of the mode from
        /// the access ACL.
        pub(in crate::staging) fn write_to(&self, dir: &File) -> io::Result<()> {
            for (name, blob) in [(DEFAULT, &self.default), (ACCESS, &self.access)] {
                match blob {
                    Some(AclBlob(blob)) => {
                        rustix::fs::fsetxattr(dir, name, blob, rustix::fs::XattrFlags::empty())?;
                    }
                    None => remove_blob(dir, name)?,
                }
            }
            Ok(())
        }

        /// Removes both ACLs from `dir`; an ACL that is not there is fine.
        ///
        /// # Errors
        ///
        /// The error of removing an ACL that exists.
        pub(in crate::staging) fn clear(dir: &File) -> io::Result<()> {
            remove_blob(dir, DEFAULT)?;
            remove_blob(dir, ACCESS)
        }

        /// An ACL with these raw values, which need not be valid: the kernel
        /// is the judge when it is written.
        #[cfg(test)]
        pub(in crate::staging) fn for_test(
            access: Option<Vec<u8>>,
            default: Option<Vec<u8>>,
        ) -> Self {
            let raw = |bytes: Vec<u8>| AclBlob(bytes.into_boxed_slice());
            Self {
                access: access.map(raw),
                default: default.map(raw),
            }
        }
    }

    /// The default ACL of a destination, staged on the root before anything is
    /// extracted so that children inherit it as they would in place.
    ///
    /// Only the default ACL is written: it is never consulted for access to
    /// the directory that holds it, so the staging directory stays `0700`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(in crate::staging) struct InheritedAcl(AclBlob);

    impl InheritedAcl {
        pub(in crate::staging) fn write_to(&self, dir: &File) -> io::Result<()> {
            rustix::fs::fsetxattr(dir, DEFAULT, &self.0.0, rustix::fs::XattrFlags::empty())?;
            Ok(())
        }

        /// The bytes of the default ACL.
        #[cfg(test)]
        pub(in crate::staging) fn bytes(&self) -> &[u8] {
            &self.0.0
        }

        /// A value the kernel refuses to store.
        #[cfg(test)]
        pub(in crate::staging) fn invalid_for_test() -> Self {
            Self(AclBlob(vec![0xff; 7].into_boxed_slice()))
        }

        /// A minimal valid default ACL: owner `rwx`, group `r-x`, other none.
        #[cfg(test)]
        pub(in crate::staging) fn valid_for_test() -> Self {
            let mut bytes = VERSION.to_le_bytes().to_vec();
            for (tag, perm) in [(0x01_u16, 7_u16), (0x04, 5), (0x20, 0)] {
                bytes.extend_from_slice(&tag.to_le_bytes());
                bytes.extend_from_slice(&perm.to_le_bytes());
                bytes.extend_from_slice(&UNDEFINED_ID.to_le_bytes());
            }
            Self(AclBlob(bytes.into_boxed_slice()))
        }
    }

    fn remove_blob(dir: &File, name: &str) -> io::Result<()> {
        match rustix::fs::fremovexattr(dir, name) {
            Ok(()) | Err(Errno::NODATA | Errno::NOTSUP) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Removes the ACLs `stage` inherited from its parent.
    ///
    /// # Errors
    ///
    /// The I/O error of removing an ACL it has.
    pub(in crate::staging) fn clear_inherited(stage: &VerifiedStage) -> io::Result<()> {
        PosixAcl::clear(stage.as_file())
    }

    /// One ACL attribute of a directory.
    #[derive(Debug, PartialEq, Eq)]
    enum Blob {
        Present(AclBlob),
        Absent,
        Unreadable(NarrowingReason),
    }

    fn read_blob(dir: &File, name: &str, buffer: &mut [u8]) -> io::Result<Blob> {
        let read = rustix::fs::fgetxattr(dir, name, &mut *buffer);
        classify(read, buffer)
    }

    fn classify(read: Result<usize, Errno>, buffer: &[u8]) -> io::Result<Blob> {
        match read {
            Ok(len) => Ok(buffer
                .get(..len)
                .filter(|blob| !blob.is_empty())
                .map_or(Blob::Absent, |blob| {
                    AclBlob::parse(blob).map_or_else(Blob::Unreadable, Blob::Present)
                })),
            Err(Errno::NODATA | Errno::NOTSUP) => Ok(Blob::Absent),
            // A bad descriptor is a bug here, not a property of the directory.
            Err(Errno::BADF) => Err(Errno::BADF.into()),
            Err(_) => Ok(Blob::Unreadable(NarrowingReason::AclUnreadable)),
        }
    }

    /// Turns a blob that names an id the reader's user namespace cannot map
    /// into an unreadable one. The kernel returns such an id as
    /// [`UNDEFINED_ID`] (verified inside `unshare -U`), and no valid named
    /// entry carries it.
    fn screen(blob: Blob) -> Blob {
        match &blob {
            Blob::Present(acl) if acl.names_an_undefined_id() => {
                Blob::Unreadable(NarrowingReason::UnmappedId)
            }
            Blob::Present(_) | Blob::Absent | Blob::Unreadable(_) => blob,
        }
    }

    /// Reads the POSIX ACL of the directory `name` of `pin`, which must still
    /// be the directory `expected` names.
    ///
    /// The directory is opened for reading. One its caller cannot open for
    /// reading is opened through an `O_PATH` handle, whose ACL is read through
    /// its `/proc` link. A directory that no handle can be opened on, an ACL
    /// that cannot be read in full or names an id the namespace cannot map, and
    /// a directory that is no longer `expected` give [`AclPlan::Private`].
    ///
    /// # Errors
    ///
    /// The I/O error of opening the directory (other than a permission
    /// failure), or a bad descriptor.
    pub(in crate::staging) fn read_destination(
        pin: &VettedDir,
        name: Leaf<'_>,
        _parent_path: &Path,
        expected: FileIdentity,
    ) -> io::Result<AclPlan> {
        let opened = match pin.open_dir_file(name) {
            Ok(dir) => Ok(DirHandle::Read(dir)),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                pin.open_dir_for_metadata(name)
            }
            Err(e) => Err(e),
        };
        let handle = match opened {
            Ok(handle) => handle,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                return Ok(AclPlan::Private(NarrowingReason::AclUnreadable));
            }
            Err(e) => return Err(e),
        };
        if !super::imp::is_expected(FileIdentity::of_file(handle.as_file()), expected) {
            return Ok(AclPlan::Private(NarrowingReason::DestinationChanged));
        }
        let mut buffer = vec![0_u8; XATTR_SIZE_MAX];
        let access = screen(read_handle_blob(&handle, ACCESS, &mut buffer)?);
        let default = screen(read_handle_blob(&handle, DEFAULT, &mut buffer)?);
        Ok(plan_of(access, default))
    }

    fn read_handle_blob(handle: &DirHandle, name: &str, buffer: &mut [u8]) -> io::Result<Blob> {
        match handle {
            DirHandle::Read(dir) => read_blob(dir, name, buffer),
            DirHandle::Search(dir) => read_blob_by_proc(dir, name, buffer),
        }
    }

    /// Reads an ACL attribute of the directory an `O_PATH` descriptor names:
    /// the descriptor cannot take `fgetxattr`, but its `/proc` link acts on the
    /// same inode and needs no permission on it. Without `/proc` the lookup
    /// fails with `ENOENT`, which is an unreadable ACL, never an absent one.
    fn read_blob_by_proc(dir: &File, name: &str, buffer: &mut [u8]) -> io::Result<Blob> {
        let link = format!("/proc/self/fd/{}", dir.as_raw_fd());
        let read = rustix::fs::getxattr(link.as_str(), name, &mut *buffer);
        classify(read, buffer)
    }

    fn plan_of(access: Blob, default: Blob) -> AclPlan {
        match (access, default) {
            (Blob::Unreadable(reason), _) | (_, Blob::Unreadable(reason)) => {
                AclPlan::Private(reason)
            }
            (Blob::Absent, Blob::Absent) => AclPlan::None,
            (access, default) => AclPlan::Copy(PosixAcl {
                access: present(access),
                default: present(default),
            }),
        }
    }

    fn present(blob: Blob) -> Option<AclBlob> {
        match blob {
            Blob::Present(bytes) => Some(bytes),
            Blob::Absent | Blob::Unreadable(_) => None,
        }
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    mod tests {
        use std::assert_matches;
        use std::os::fd::OwnedFd;

        use rustix::fs::Mode;
        use rustix::fs::OFlags;

        use super::*;

        const USER_OBJ: u16 = 0x01;
        const GROUP_OBJ: u16 = 0x04;
        const OTHER: u16 = 0x20;
        const NO_ID: u32 = u32::MAX;

        fn blob_of(entries: &[(u16, u32)]) -> Vec<u8> {
            let mut bytes = VERSION.to_le_bytes().to_vec();
            for &(tag, id) in entries {
                bytes.extend_from_slice(&tag.to_le_bytes());
                bytes.extend_from_slice(&5_u16.to_le_bytes());
                bytes.extend_from_slice(&id.to_le_bytes());
            }
            bytes
        }

        fn present(entries: &[(u16, u32)]) -> Blob {
            Blob::Present(AclBlob::parse(&blob_of(entries)).unwrap())
        }

        fn read_error(errno: Errno) -> io::Result<Blob> {
            classify(Err(errno), &[])
        }

        #[test]
        fn a_refused_read_of_an_acl_is_unreadable() {
            for errno in [Errno::ACCESS, Errno::PERM, Errno::IO] {
                assert_matches!(
                    read_error(errno),
                    Ok(Blob::Unreadable(NarrowingReason::AclUnreadable)),
                    "{errno}"
                );
            }
        }

        #[test]
        fn a_missing_or_unsupported_acl_is_absent() {
            for errno in [Errno::NODATA, Errno::NOTSUP] {
                assert_matches!(read_error(errno), Ok(Blob::Absent), "{errno}");
            }
        }

        #[test]
        fn a_bad_descriptor_is_an_error_not_a_property_of_the_directory() {
            let error = read_error(Errno::BADF).err().unwrap();
            assert_eq!(error.raw_os_error(), Some(Errno::BADF.raw_os_error()));
        }

        #[test]
        fn reading_an_acl_through_a_path_only_handle_fails_with_a_bad_descriptor() {
            let temp = tempfile::tempdir().unwrap();
            let fd: OwnedFd = rustix::fs::open(
                temp.path(),
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap();
            let handle = File::from(fd);
            let mut buffer = vec![0_u8; 16];
            let error = read_blob(&handle, ACCESS, &mut buffer).err().unwrap();
            assert_eq!(error.raw_os_error(), Some(Errno::BADF.raw_os_error()));
        }

        #[test]
        fn a_malformed_blob_is_unreadable() {
            let mut wrong_version = blob_of(&[(USER_OBJ, NO_ID)]);
            wrong_version[0] = 3;
            let mut partial = blob_of(&[(USER_OBJ, NO_ID)]);
            partial.pop();
            for bytes in [wrong_version, partial, vec![2, 0, 0], vec![0xff; 7]] {
                let read = classify(Ok(bytes.len()), &bytes).unwrap();
                assert_eq!(
                    read,
                    Blob::Unreadable(NarrowingReason::AclUnreadable),
                    "{bytes:?}"
                );
            }
        }

        #[test]
        fn an_unreadable_blob_makes_the_plan_private_whatever_the_other_one_is() {
            let reason = NarrowingReason::AclUnreadable;
            let private = AclPlan::Private(reason);
            let entries = [(USER_OBJ, NO_ID)];
            assert_eq!(plan_of(Blob::Unreadable(reason), Blob::Absent), private);
            assert_eq!(plan_of(Blob::Absent, Blob::Unreadable(reason)), private);
            assert_eq!(
                plan_of(present(&entries), Blob::Unreadable(reason)),
                private
            );
            assert_eq!(
                plan_of(Blob::Unreadable(reason), present(&entries)),
                private
            );
        }

        #[test]
        fn two_absent_blobs_make_no_plan() {
            assert_eq!(plan_of(Blob::Absent, Blob::Absent), AclPlan::None);
        }

        #[test]
        fn a_named_entry_with_an_undefined_id_is_refused() {
            for tag in [TAG_USER, TAG_GROUP] {
                let entries = [(USER_OBJ, NO_ID), (tag, NO_ID), (OTHER, NO_ID)];
                assert_eq!(
                    screen(present(&entries)),
                    Blob::Unreadable(NarrowingReason::UnmappedId),
                    "{tag:#x}"
                );
            }
        }

        #[test]
        fn a_mapped_named_entry_and_unnamed_undefined_ids_pass() {
            let entries = [
                (USER_OBJ, NO_ID),
                (TAG_USER, 65_534),
                (TAG_GROUP, 0),
                (GROUP_OBJ, NO_ID),
                (OTHER, NO_ID),
            ];
            assert_matches!(screen(present(&entries)), Blob::Present(_));
        }

        #[test]
        fn only_the_default_acl_is_what_children_inherit() {
            let entries = [(USER_OBJ, NO_ID), (GROUP_OBJ, NO_ID), (OTHER, NO_ID)];
            let default = blob_of(&entries);
            let both = PosixAcl::for_test(Some(blob_of(&entries)), Some(default.clone()));
            let access_only = PosixAcl::for_test(Some(blob_of(&entries)), None);

            assert_eq!(both.inheritance().unwrap().bytes(), default.as_slice());
            assert!(access_only.inheritance().is_none());
            assert_matches!(
                AclPlan::Copy(access_only).inheritance(),
                crate::staging::acl::Inheritance::None
            );
        }

        #[test]
        fn a_private_plan_withholds_the_inheritance_for_its_reason() {
            assert_matches!(
                AclPlan::Private(NarrowingReason::UnmappedId).inheritance(),
                crate::staging::acl::Inheritance::Withheld(NarrowingReason::UnmappedId)
            );
        }

        #[test]
        fn the_size_limit_of_an_attribute_is_the_boundary_of_a_readable_blob() {
            let blob_of_len = |len: usize| {
                let mut bytes = vec![0_u8; len];
                bytes[..HEADER_LEN].copy_from_slice(&VERSION.to_le_bytes());
                bytes
            };
            // The largest whole-entry blob is 4 bytes under the limit; the next
            // whole-entry size is over it.
            assert!(AclBlob::parse(&blob_of_len(XATTR_SIZE_MAX - HEADER_LEN)).is_ok());
            assert_eq!(
                AclBlob::parse(&blob_of_len(XATTR_SIZE_MAX + HEADER_LEN)).unwrap_err(),
                NarrowingReason::AclUnreadable
            );
        }

        #[test]
        fn a_value_larger_than_the_buffer_is_unreadable_not_a_failure() {
            assert_matches!(
                read_error(Errno::RANGE),
                Ok(Blob::Unreadable(NarrowingReason::AclUnreadable))
            );
        }

        /// A destination `parent/dest` with `mode` and, when given, the access
        /// ACL `entries` of `(tag, permission, id)`, read as a replace reads
        /// it.
        ///
        /// `None` when the temporary directory has no POSIX ACLs.
        fn read_with_mode(
            mode: u32,
            entries: &[(u16, u16, u32)],
        ) -> Option<(tempfile::TempDir, io::Result<AclPlan>)> {
            use std::os::unix::fs::PermissionsExt;

            let temp = tempfile::tempdir().unwrap();
            let parent = temp.path().canonicalize().unwrap();
            let dest = parent.join("dest");
            std::fs::create_dir(&dest).unwrap();
            if !entries.is_empty() {
                let mut blob = VERSION.to_le_bytes().to_vec();
                for &(tag, permission, id) in entries {
                    blob.extend_from_slice(&tag.to_le_bytes());
                    blob.extend_from_slice(&permission.to_le_bytes());
                    blob.extend_from_slice(&id.to_le_bytes());
                }
                let dir = File::open(&dest).unwrap();
                match rustix::fs::fsetxattr(&dir, ACCESS, &blob, rustix::fs::XattrFlags::empty()) {
                    Ok(()) => {}
                    Err(Errno::NOTSUP) => return None,
                    Err(e) => panic!("setting the ACL: {e}"),
                }
            }
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(mode)).unwrap();
            let pin = VettedDir::open_path(&parent).unwrap();
            let name = crate::formats::pinned_dir::LeafBuf::of(&dest).unwrap();
            let id = pin.status(name.as_leaf()).unwrap().unwrap().identity;
            let plan = read_destination(&pin, name.as_leaf(), &parent, id);
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755)).unwrap();
            Some((temp, plan))
        }

        #[test]
        fn a_destination_without_read_access_and_without_an_acl_has_none() {
            for mode in [0o311, 0o000] {
                let (_temp, plan) = read_with_mode(mode, &[]).unwrap();
                assert_matches!(plan, Ok(AclPlan::None), "{mode:o}");
            }
        }

        #[test]
        fn a_destination_without_read_access_keeps_its_acl() {
            // The owner entry has no read bit, so the owner cannot list it.
            let entries = [
                (USER_OBJ, 3, NO_ID),
                (TAG_USER, 5, 12_345),
                (GROUP_OBJ, 1, NO_ID),
                (0x10, 5, NO_ID),
                (OTHER, 1, NO_ID),
            ];
            let Some((_temp, plan)) = read_with_mode(0o311, &entries) else {
                eprintln!("skipping: the temporary directory has no POSIX ACLs");
                return;
            };
            assert_matches!(plan, Ok(AclPlan::Copy(_)));
        }

        #[test]
        fn a_real_attribute_larger_than_the_buffer_is_unreadable() {
            let temp = tempfile::tempdir().unwrap();
            let dir = File::open(temp.path()).unwrap();
            // A named entry and a mask: a minimal ACL is folded into the mode.
            let blob = blob_of(&[
                (USER_OBJ, NO_ID),
                (TAG_USER, 12_345),
                (GROUP_OBJ, NO_ID),
                (0x10, NO_ID),
                (OTHER, NO_ID),
            ]);
            match rustix::fs::fsetxattr(&dir, ACCESS, &blob, rustix::fs::XattrFlags::empty()) {
                Ok(()) => {}
                Err(Errno::NOTSUP) => {
                    eprintln!("skipping: the temporary directory has no POSIX ACLs");
                    return;
                }
                Err(e) => panic!("setting the ACL: {e}"),
            }
            let mut small = vec![0_u8; 8];
            assert_eq!(
                read_blob(&dir, ACCESS, &mut small).unwrap(),
                Blob::Unreadable(NarrowingReason::AclUnreadable)
            );
            let mut full = vec![0_u8; XATTR_SIZE_MAX];
            assert_matches!(read_blob(&dir, ACCESS, &mut full), Ok(Blob::Present(_)));
        }

        proptest::proptest! {
            #[test]
            fn parsing_never_panics_and_accepts_only_whole_v2_blobs(
                tail in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..200),
                valid_header in proptest::prelude::any::<bool>(),
            ) {
                let mut bytes = if valid_header {
                    VERSION.to_le_bytes().to_vec()
                } else {
                    Vec::new()
                };
                bytes.extend_from_slice(&tail);
                let parsed = AclBlob::parse(&bytes);
                if let Ok(blob) = parsed {
                    proptest::prop_assert!(valid_header || bytes.len() >= HEADER_LEN);
                    proptest::prop_assert_eq!((bytes.len() - HEADER_LEN) % ENTRY_LEN, 0);
                    let _ = blob.names_an_undefined_id();
                }
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::fs::File;
    use std::io;
    use std::path::Path;

    use rustix::io::Errno;

    use super::imp::AclPlan;
    use crate::NarrowingReason;
    use crate::formats::common::errno_is;
    use crate::formats::file_identity::FileIdentity;
    use crate::formats::pinned_dir::Leaf;
    use crate::formats::pinned_dir::VettedDir;
    use crate::formats::pinned_dir::darwin_acl;
    use crate::formats::pinned_dir::darwin_acl::Fetched;
    use crate::staging::dir::VerifiedStage;

    /// `KAUTH_FILESEC_MAGIC`.
    const MAGIC: u32 = 0x012c_c16d;
    /// `KAUTH_FILESEC_NOACL` in `acl_entrycount`.
    const NO_ACL: u32 = 0xffff_ffff;
    /// `KAUTH_ACL_MAX_ENTRIES`.
    const MAX_ENTRIES: u32 = 128;
    /// Offset of `fsec_owner` in a `kauth_filesec`.
    const OWNER_AT: usize = 4;
    /// Offset of `acl_entrycount`; `fsec_group` ends here.
    const COUNT_AT: usize = 36;
    /// Size of a `kauth_filesec` without entries: magic, owner, group,
    /// entry count and flags.
    const HEADER_LEN: usize = 44;
    /// Size of a `kauth_ace`: applicable GUID, flags and rights.
    const ENTRY_LEN: usize = 24;
    const GUID_LEN: usize = 16;
    const ENVELOPE_LEN: usize = 12;
    /// Offset of the `attrreference_t` in the attribute buffer.
    const REFERENCE_AT: usize = 4;
    /// `KAUTH_ACE_FILE_INHERIT | DIRECTORY_INHERIT`: the flags that make an
    /// entry reach children. `LIMIT_INHERIT` alone does not.
    const CHILD_INHERIT_FLAGS: u32 = 0x20 | 0x40;
    /// `KAUTH_ACE_INHERITED`: the entry was inherited from the parent.
    const INHERITED: u32 = 0x10;
    /// `KAUTH_ACE_ONLY_INHERIT`: the entry is for children only and is not
    /// evaluated for the directory that holds it.
    const ONLY_INHERIT: u32 = 0x100;

    /// A destination's ACL as a serialized `kauth_filesec` with its owner and
    /// group GUIDs zeroed.
    ///
    /// The bytes passed the checks of [`parse`]: the magic, the entry count and
    /// the size agree.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(in crate::staging) struct MacAcl(Box<[u8]>);

    /// The entries of a destination's ACL that children inherit, rewritten as
    /// `ONLY_INHERIT` so the staging directory that holds them does not apply
    /// them to itself (measured on Darwin 25.6: children get them with
    /// `inherited` set and `ONLY_INHERIT` cleared).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(in crate::staging) struct InheritedAcl(MacAcl);

    impl InheritedAcl {
        pub(in crate::staging) fn write_to(&self, dir: &File) -> io::Result<()> {
            self.0.write_to(dir)
        }

        #[cfg(test)]
        pub(in crate::staging) fn acl(&self) -> &MacAcl {
            &self.0
        }

        /// A value the kernel refuses to store.
        #[cfg(test)]
        pub(in crate::staging) fn invalid_for_test() -> Self {
            Self(MacAcl::raw_for_test(vec![0xff; 5]))
        }

        /// One inheritable allow entry for everyone.
        #[cfg(test)]
        pub(in crate::staging) fn valid_for_test() -> Self {
            const EVERYONE: [u8; GUID_LEN] = [
                0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0x00, 0x00,
                0x00, 0x0C,
            ];
            let list = MacAcl::from_entries(&[(EVERYONE, 1 | 0x20 | 0x40, 0x2)]);
            list.inheritance().unwrap_or_else(Self::invalid_for_test)
        }
    }

    /// One access control entry.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Ace {
        applicable: [u8; GUID_LEN],
        flags: u32,
        rights: u32,
    }

    impl MacAcl {
        /// Writes the ACL onto `dir`.
        ///
        /// The kernel keeps the mode, so the caller sets it afterwards.
        pub(in crate::staging) fn write_to(&self, dir: &File) -> io::Result<()> {
            darwin_acl::store(dir, &self.0)
        }

        /// Removes every entry, inherited ones included, from `dir`.
        ///
        /// A macOS allow entry beats the mode bits, so a root that kept an
        /// inherited one cannot be made private with `chmod`.
        ///
        /// # Errors
        ///
        /// The OS error of clearing the list; a volume without ACL support
        /// has nothing to clear and counts as cleared.
        pub(in crate::staging) fn clear(dir: &File) -> io::Result<()> {
            match darwin_acl::store(dir, &no_acl()) {
                Err(e) if is_unsupported(&e) => Ok(()),
                other => other,
            }
        }

        /// The inheritable entries in their original order, or `None` when no
        /// entry reaches children.
        pub(in crate::staging) fn inheritance(&self) -> Option<InheritedAcl> {
            let entries: Vec<_> = self
                .aces()
                .into_iter()
                .filter(|ace| ace.flags & CHILD_INHERIT_FLAGS != 0)
                .map(|ace| (ace.applicable, ace.flags | ONLY_INHERIT, ace.rights))
                .collect();
            (!entries.is_empty()).then(|| InheritedAcl(Self(filesec(&entries).into_boxed_slice())))
        }

        fn aces(&self) -> Vec<Ace> {
            self.0
                .get(HEADER_LEN..)
                .unwrap_or_default()
                .as_chunks::<ENTRY_LEN>()
                .0
                .iter()
                .filter_map(|entry| {
                    Some(Ace {
                        applicable: *entry.first_chunk()?,
                        flags: ne_u32(entry, GUID_LEN)?,
                        rights: ne_u32(entry, GUID_LEN + 4)?,
                    })
                })
                .collect()
        }

        /// An ACL with these entries, in the layout the kernel returns.
        #[cfg(test)]
        pub(in crate::staging) fn from_entries(entries: &[([u8; GUID_LEN], u32, u32)]) -> Self {
            Self(filesec(entries).into_boxed_slice())
        }

        /// An ACL with these raw bytes, which need not be valid: the kernel is
        /// the judge when it is written.
        #[cfg(test)]
        pub(in crate::staging) fn raw_for_test(bytes: Vec<u8>) -> Self {
            Self(bytes.into_boxed_slice())
        }

        #[cfg(test)]
        pub(in crate::staging) fn for_test() -> Self {
            Self::from_entries(&[])
        }
    }

    /// A `kauth_filesec` in the host byte order the kernel uses for it, with
    /// zeroed owner and group.
    fn filesec(entries: &[([u8; GUID_LEN], u32, u32)]) -> Vec<u8> {
        let count = u32::try_from(entries.len()).unwrap_or(NO_ACL);
        let mut bytes =
            Vec::with_capacity(HEADER_LEN.saturating_add(ENTRY_LEN.saturating_mul(entries.len())));
        bytes.extend_from_slice(&MAGIC.to_ne_bytes());
        bytes.extend_from_slice(&[0; COUNT_AT - OWNER_AT]);
        bytes.extend_from_slice(&count.to_ne_bytes());
        bytes.extend_from_slice(&0_u32.to_ne_bytes());
        for (applicable, flags, rights) in entries {
            bytes.extend_from_slice(applicable);
            bytes.extend_from_slice(&flags.to_ne_bytes());
            bytes.extend_from_slice(&rights.to_ne_bytes());
        }
        bytes
    }

    fn no_acl() -> Vec<u8> {
        let mut bytes = filesec(&[]);
        if let Some(count) = bytes.get_mut(COUNT_AT..COUNT_AT + 4) {
            count.copy_from_slice(&NO_ACL.to_ne_bytes());
        }
        bytes
    }

    fn ne_u32(bytes: &[u8], at: usize) -> Option<u32> {
        bytes
            .get(at..)?
            .first_chunk()
            .map(|word| u32::from_ne_bytes(*word))
    }

    /// Reads the ACL out of the attribute buffer `fgetattrlist` filled.
    ///
    /// The buffer is a native-endian total length, an `attrreference_t` whose
    /// offset is relative to the reference itself, and the `kauth_filesec` it
    /// points at; the kernel fills the integer fields of the `kauth_filesec`
    /// in host byte order (verified on the real kernel: the magic reads
    /// `6d c1 2c 01` on little-endian hardware). Nothing is trusted: a magic
    /// that does not read back as [`MAGIC`] (a byte-order mismatch included),
    /// an out-of-range reference, too many entries or a size that does not
    /// match the entry count is unreadable.
    ///
    /// # Errors
    ///
    /// [`NarrowingReason::AclUnreadable`] for any of the above.
    fn parse(attribute: &[u8]) -> Result<Option<MacAcl>, NarrowingReason> {
        let unreadable = NarrowingReason::AclUnreadable;
        let total = ne_u32(attribute, 0)
            .and_then(|total| usize::try_from(total).ok())
            .filter(|total| *total >= ENVELOPE_LEN && *total <= attribute.len())
            .ok_or(unreadable)?;
        let offset = ne_u32(attribute, REFERENCE_AT)
            .and_then(|offset| usize::try_from(offset.cast_signed()).ok())
            .filter(|offset| *offset >= ENVELOPE_LEN - REFERENCE_AT)
            .ok_or(unreadable)?;
        let length = ne_u32(attribute, REFERENCE_AT + 4)
            .and_then(|length| usize::try_from(length).ok())
            .ok_or(unreadable)?;
        if length == 0 {
            return Ok(None);
        }
        let start = REFERENCE_AT.checked_add(offset).ok_or(unreadable)?;
        let end = start.checked_add(length).ok_or(unreadable)?;
        let filesec = attribute
            .get(..total)
            .and_then(|buffer| buffer.get(start..end))
            .ok_or(unreadable)?;
        parse_filesec(filesec)
    }

    fn parse_filesec(filesec: &[u8]) -> Result<Option<MacAcl>, NarrowingReason> {
        let unreadable = NarrowingReason::AclUnreadable;
        if ne_u32(filesec, 0) != Some(MAGIC) {
            return Err(unreadable);
        }
        let count = ne_u32(filesec, COUNT_AT).ok_or(unreadable)?;
        if count == NO_ACL || count == 0 {
            return Ok(None);
        }
        let expected = (count <= MAX_ENTRIES)
            .then(|| usize::try_from(count).ok())
            .flatten()
            .and_then(|count| count.checked_mul(ENTRY_LEN))
            .and_then(|entries| entries.checked_add(HEADER_LEN))
            .ok_or(unreadable)?;
        if filesec.len() != expected {
            return Err(unreadable);
        }
        let mut owned = filesec.to_vec();
        if let Some(guids) = owned.get_mut(OWNER_AT..COUNT_AT) {
            guids.fill(0);
        }
        Ok(Some(MacAcl(owned.into_boxed_slice())))
    }

    // `fsetattrlist` reports a volume without ACL support as `ENOTSUP`.
    fn is_unsupported(error: &io::Error) -> bool {
        errno_is(error, &[Errno::NOTSUP])
    }

    /// FAT32 and exFAT answer a read of the (constant) extended security
    /// attribute list with `EINVAL` rather than `ENOTSUP`: no ACL can exist
    /// there. Only the read maps it; a write that fails with `EINVAL` stays an
    /// error so an inherited entry is never left in place.
    fn is_attribute_unavailable(error: &io::Error) -> bool {
        errno_is(error, &[Errno::INVAL])
    }

    /// Removes every ACL entry, inherited ones included, from `stage`.
    ///
    /// # Errors
    ///
    /// The I/O error of clearing its ACL; a volume without ACL support (FAT,
    /// exFAT) cannot hold an inherited entry, so its refusal counts as cleared.
    pub(in crate::staging) fn clear_inherited(stage: &VerifiedStage) -> io::Result<()> {
        MacAcl::clear(stage.as_file())
    }

    /// Whether the ACL of `file` can be read and every entry in it was
    /// inherited, which is all an entry staged by this run can hold.
    pub(in crate::staging) fn only_inherited_entries(file: &File) -> bool {
        every_entry_has(file, INHERITED)
    }

    /// Whether the ACL of `file` can be read and every entry in it is for
    /// children only, so none applies to `file` itself. A file without an ACL
    /// qualifies; a value that cannot be read or parsed does not.
    pub(in crate::staging) fn only_inherit_entries(file: &File) -> bool {
        every_entry_has(file, ONLY_INHERIT)
    }

    fn every_entry_has(file: &File, flag: u32) -> bool {
        entries_have(darwin_acl::fetch(file), flag)
    }

    /// Whether every entry of a fetched ACL carries `flag`, reading the
    /// attribute as [`plan_of`] does: a volume that answers `ENOTSUP` or
    /// `EINVAL` (FAT, exFAT) has no ACL, so it holds no foreign entry. Any
    /// other failure and a truncated or malformed value are unproven.
    fn entries_have(fetched: io::Result<Fetched>, flag: u32) -> bool {
        match fetched {
            Ok(Fetched::Complete(attribute)) => match parse(&attribute) {
                Ok(None) => true,
                Ok(Some(acl)) => acl.aces().iter().all(|ace| ace.flags & flag != 0),
                Err(_) => false,
            },
            Err(e) => is_unsupported(&e) || is_attribute_unavailable(&e),
            Ok(Fetched::Truncated) => false,
        }
    }

    /// Reads the ACL of `stage` through its descriptor, which needs no read
    /// access to the directory.
    ///
    /// # Errors
    ///
    /// A bad descriptor.
    pub(in crate::staging) fn read_stage(stage: &File) -> io::Result<AclPlan> {
        plan_of(darwin_acl::fetch(stage))
    }

    fn plan_of(fetched: io::Result<Fetched>) -> io::Result<AclPlan> {
        match fetched {
            Ok(Fetched::Complete(attribute)) => Ok(match parse(&attribute) {
                Ok(None) => AclPlan::None,
                Ok(Some(acl)) => AclPlan::Copy(acl),
                Err(reason) => AclPlan::Private(reason),
            }),
            Err(e) if is_unsupported(&e) || is_attribute_unavailable(&e) => Ok(AclPlan::None),
            // A bad descriptor is a bug here, not a property of the directory.
            Err(e) if errno_is(&e, &[Errno::BADF]) => Err(e),
            Ok(Fetched::Truncated) | Err(_) => Ok(AclPlan::Private(NarrowingReason::AclUnreadable)),
        }
    }

    /// Reads the ACL of the directory `name` of `pin`, which must still be the
    /// directory `expected` names.
    ///
    /// The directory is opened relative to the pin without following a
    /// symlink, its identity is compared with `expected`, and the ACL is read
    /// through that same descriptor, so a swap of the entry cannot change
    /// which object is read. The handle is search-only where the directory
    /// allows it, so a mode such as `0311` does not hide its ACL. A directory
    /// that no handle can be opened on, an ACL that cannot be read in full or
    /// parsed, and a directory that is no longer `expected` give
    /// [`AclPlan::Private`].
    ///
    /// # Errors
    ///
    /// The I/O error of opening the directory (other than a permission
    /// failure), or a bad descriptor.
    pub(in crate::staging) fn read_destination(
        pin: &VettedDir,
        name: Leaf<'_>,
        _parent_path: &Path,
        expected: FileIdentity,
    ) -> io::Result<AclPlan> {
        let handle = match pin.open_dir_for_metadata(name) {
            Ok(handle) => handle,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                return Ok(AclPlan::Private(NarrowingReason::AclUnreadable));
            }
            Err(e) => return Err(e),
        };
        let dir = handle.as_file();
        if !super::imp::is_expected(FileIdentity::of_file(dir), expected) {
            return Ok(AclPlan::Private(NarrowingReason::DestinationChanged));
        }
        read_stage(dir)
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    mod tests {
        use std::assert_matches;
        use std::process::Command;

        use super::*;
        use crate::staging::test_acl::add_ace;

        const EVERYONE: [u8; GUID_LEN] = [
            0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0x00, 0x00,
            0x00, 0x0C,
        ];
        const KIND_ALLOW: u32 = 1;
        const KIND_DENY: u32 = 2;
        const KIND_MASK: u32 = 0xf;
        const FILE_INHERIT: u32 = 0x20;
        const DIRECTORY_INHERIT: u32 = 0x40;
        const LIMIT_INHERIT: u32 = 0x80;
        const RIGHT_DELETE: u32 = 0x10;
        const RIGHT_LIST: u32 = 0x2;

        /// The attribute buffer `fgetattrlist` returns for `filesec`.
        fn attribute_of(filesec: &[u8]) -> Vec<u8> {
            let total = ENVELOPE_LEN + filesec.len();
            let mut bytes = u32::try_from(total).unwrap().to_ne_bytes().to_vec();
            bytes.extend_from_slice(&8_i32.to_ne_bytes());
            bytes.extend_from_slice(&u32::try_from(filesec.len()).unwrap().to_ne_bytes());
            bytes.extend_from_slice(filesec);
            bytes
        }

        fn entry(flags: u32) -> ([u8; GUID_LEN], u32, u32) {
            (EVERYONE, flags, RIGHT_LIST)
        }

        fn read_acl(dir: &File) -> Option<MacAcl> {
            match plan_of(darwin_acl::fetch(dir)).unwrap() {
                AclPlan::Copy(acl) => Some(acl),
                AclPlan::None => None,
                AclPlan::Private(reason) => panic!("unexpected {reason}"),
            }
        }

        #[test]
        fn a_well_formed_attribute_parses_into_its_entries() {
            let attribute = attribute_of(&filesec(&[entry(KIND_DENY)]));
            let acl = parse(&attribute).unwrap().unwrap();
            assert_eq!(
                acl.aces(),
                [Ace {
                    applicable: EVERYONE,
                    flags: KIND_DENY,
                    rights: RIGHT_LIST
                }]
            );
        }

        #[test]
        fn owner_and_group_are_zeroed_in_the_copy() {
            let mut bytes = filesec(&[entry(KIND_DENY)]);
            bytes[OWNER_AT..COUNT_AT].fill(0x55);
            let acl = parse(&attribute_of(&bytes)).unwrap().unwrap();
            assert!(acl.0[OWNER_AT..COUNT_AT].iter().all(|byte| *byte == 0));
        }

        #[test]
        fn a_magic_in_the_other_byte_order_is_unreadable() {
            let mut bytes = filesec(&[entry(KIND_DENY)]);
            bytes[..4].copy_from_slice(&MAGIC.swap_bytes().to_ne_bytes());
            assert_eq!(
                parse(&attribute_of(&bytes)).unwrap_err(),
                NarrowingReason::AclUnreadable
            );
        }

        #[test]
        fn no_acl_markers_mean_no_acl() {
            assert_matches!(parse(&attribute_of(&no_acl())), Ok(None));
            assert_matches!(parse(&attribute_of(&filesec(&[]))), Ok(None));
            let mut empty = attribute_of(&[]);
            empty.truncate(ENVELOPE_LEN);
            assert_matches!(parse(&empty), Ok(None));
        }

        #[test]
        fn inheritable_entries_parse() {
            for flags in [0x20, 0x40, 0x100, KIND_DENY | FILE_INHERIT] {
                let attribute = attribute_of(&filesec(&[entry(KIND_DENY), entry(flags)]));
                assert_matches!(parse(&attribute), Ok(Some(_)), "{flags:#x}");
            }
        }

        #[test]
        fn a_limit_inherit_entry_alone_is_not_inheritance() {
            let acl = MacAcl::from_entries(&[entry(KIND_DENY | 0x80)]);
            assert!(acl.inheritance().is_none());
        }

        #[test]
        fn an_access_only_list_has_no_inheritance() {
            let acl = MacAcl::from_entries(&[entry(KIND_DENY), entry(KIND_ALLOW)]);
            assert!(acl.inheritance().is_none());
        }

        /// The GUID the kernel stores for an entry that names the current user.
        fn own_guid() -> [u8; GUID_LEN] {
            let output = Command::new("/usr/bin/id").arg("-un").output().unwrap();
            let name = String::from_utf8(output.stdout).unwrap();
            let scratch = tempfile::tempdir().unwrap();
            let _clear = ClearAcl(scratch.path());
            add_ace(
                scratch.path(),
                &format!("user:{} allow list,directory_inherit", name.trim()),
            );
            let acl = read_acl(&File::open(scratch.path()).unwrap()).unwrap();
            acl.aces().first().unwrap().applicable
        }

        /// The kernel keeps its promise that an `ONLY_INHERIT` entry is for
        /// children alone: a `deny list` aimed at the current user leaves the
        /// directory that holds it listable and not the directory made in it.
        #[test]
        fn only_inherit_entries_reach_children_and_not_the_directory_holding_them() {
            let denying =
                MacAcl::from_entries(&[(own_guid(), KIND_DENY | DIRECTORY_INHERIT, RIGHT_LIST)]);
            let stage = tempfile::tempdir().unwrap();
            let _clear = ClearAcl(stage.path());

            denying
                .inheritance()
                .unwrap()
                .write_to(&File::open(stage.path()).unwrap())
                .unwrap();

            assert!(std::fs::read_dir(stage.path()).is_ok());
            std::fs::create_dir(stage.path().join("child")).unwrap();
            let refused = std::fs::read_dir(stage.path().join("child")).unwrap_err();
            assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
        }

        #[test]
        fn writing_an_inheritable_list_does_not_reach_existing_children() {
            let temp = tempfile::tempdir().unwrap();
            let _clear = ClearAcl(temp.path());
            std::fs::create_dir(temp.path().join("child")).unwrap();
            let list = MacAcl::from_entries(&[(
                EVERYONE,
                KIND_DENY | FILE_INHERIT | DIRECTORY_INHERIT,
                RIGHT_DELETE,
            )]);

            list.write_to(&File::open(temp.path()).unwrap()).unwrap();

            let child = File::open(temp.path().join("child")).unwrap();
            assert!(read_acl(&child).is_none());
        }

        #[test]
        fn a_plan_maps_to_the_inheritance_of_its_list() {
            use crate::staging::acl::Inheritance;

            assert_matches!(
                AclPlan::Copy(MacAcl::from_entries(&[entry(KIND_DENY)])).inheritance(),
                Inheritance::None
            );
            assert_matches!(
                AclPlan::Copy(MacAcl::from_entries(&[entry(KIND_DENY | FILE_INHERIT)]))
                    .inheritance(),
                Inheritance::Stage(_)
            );
            assert_matches!(
                AclPlan::Private(NarrowingReason::UnmappedId).inheritance(),
                Inheritance::Withheld(NarrowingReason::UnmappedId)
            );
        }

        #[test]
        fn inheritable_entries_are_kept_in_order_as_only_inherit() {
            let acl = MacAcl::from_entries(&[
                (EVERYONE, KIND_DENY | FILE_INHERIT, RIGHT_DELETE),
                (EVERYONE, KIND_ALLOW, RIGHT_LIST),
                (
                    EVERYONE,
                    KIND_ALLOW | DIRECTORY_INHERIT | LIMIT_INHERIT,
                    RIGHT_LIST,
                ),
                (
                    EVERYONE,
                    KIND_DENY | ONLY_INHERIT | FILE_INHERIT,
                    RIGHT_LIST,
                ),
            ]);

            let staged = acl.inheritance().unwrap();

            assert_eq!(
                staged.acl().aces(),
                [
                    Ace {
                        applicable: EVERYONE,
                        flags: KIND_DENY | FILE_INHERIT | ONLY_INHERIT,
                        rights: RIGHT_DELETE
                    },
                    Ace {
                        applicable: EVERYONE,
                        flags: KIND_ALLOW | DIRECTORY_INHERIT | LIMIT_INHERIT | ONLY_INHERIT,
                        rights: RIGHT_LIST
                    },
                    Ace {
                        applicable: EVERYONE,
                        flags: KIND_DENY | ONLY_INHERIT | FILE_INHERIT,
                        rights: RIGHT_LIST
                    },
                ]
            );
        }

        #[test]
        fn malformed_attributes_are_unreadable() {
            let good = attribute_of(&filesec(&[entry(KIND_DENY)]));
            let with = |edit: &dyn Fn(&mut Vec<u8>)| {
                let mut bytes = good.clone();
                edit(&mut bytes);
                bytes
            };
            let cases = [
                with(&|b| b.truncate(8)),
                with(&|b| b.truncate(good.len() - 1)),
                with(&|b| b[0..4].copy_from_slice(&u32::MAX.to_ne_bytes())),
                with(&|b| b[4..8].copy_from_slice(&(-8_i32).to_ne_bytes())),
                with(&|b| b[4..8].copy_from_slice(&0_i32.to_ne_bytes())),
                with(&|b| b[4..8].copy_from_slice(&i32::MAX.to_ne_bytes())),
                with(&|b| b[8..12].copy_from_slice(&u32::MAX.to_ne_bytes())),
                with(&|b| {
                    b[12 + COUNT_AT..12 + COUNT_AT + 4].copy_from_slice(&2_u32.to_ne_bytes());
                }),
                with(&|b| {
                    b[12 + COUNT_AT..12 + COUNT_AT + 4]
                        .copy_from_slice(&(MAX_ENTRIES + 1).to_ne_bytes());
                }),
            ];
            for (index, bytes) in cases.iter().enumerate() {
                assert_eq!(
                    parse(bytes).unwrap_err(),
                    NarrowingReason::AclUnreadable,
                    "case {index}"
                );
            }
        }

        #[test]
        fn a_deny_entry_the_kernel_returns_reads_back_with_its_semantics() {
            let temp = tempfile::tempdir().unwrap();
            let _clear = ClearAcl(temp.path());
            add_ace(temp.path(), "everyone deny delete,file_inherit");
            let dir = File::open(temp.path()).unwrap();

            let Ok(Fetched::Complete(attribute)) = darwin_acl::fetch(&dir) else {
                panic!("the attribute should be readable");
            };
            assert_matches!(parse(&attribute), Ok(Some(_)));
            let filesec = attribute.get(ENVELOPE_LEN..).unwrap();
            assert_eq!(ne_u32(filesec, 0), Some(MAGIC), "the kernel's byte order");
            let acl = MacAcl(filesec.into());
            let [ace] = acl.aces().try_into().unwrap();
            assert_eq!(ace.flags & KIND_MASK, KIND_DENY);
            assert_ne!(ace.flags & FILE_INHERIT, 0);
            assert_ne!(ace.rights & RIGHT_DELETE, 0);
            assert_eq!(ace.applicable, EVERYONE);
        }

        #[test]
        fn a_stored_acl_reads_back_and_clearing_removes_it() {
            let temp = tempfile::tempdir().unwrap();
            let dir = File::open(temp.path()).unwrap();
            assert!(read_acl(&dir).is_none());
            let acl = MacAcl::from_entries(&[entry(KIND_DENY)]);

            acl.write_to(&dir).unwrap();

            assert_eq!(read_acl(&dir), Some(acl));
            MacAcl::clear(&dir).unwrap();
            assert!(read_acl(&dir).is_none());
        }

        #[test]
        fn a_truncated_fetch_and_an_unsupported_volume_are_told_apart() {
            assert_matches!(
                plan_of(Ok(Fetched::Truncated)),
                Ok(AclPlan::Private(NarrowingReason::AclUnreadable))
            );
            let unsupported = io::Error::from_raw_os_error(Errno::NOTSUP.raw_os_error());
            assert_matches!(plan_of(Err(unsupported)), Ok(AclPlan::None));
            let denied = io::Error::from_raw_os_error(Errno::ACCESS.raw_os_error());
            assert_matches!(
                plan_of(Err(denied)),
                Ok(AclPlan::Private(NarrowingReason::AclUnreadable))
            );
            let bad_fd = io::Error::from_raw_os_error(Errno::BADF.raw_os_error());
            assert!(plan_of(Err(bad_fd)).is_err());
        }

        /// FAT32 and exFAT answer `EINVAL` (observed with a C probe on such a
        /// volume); the same errno from a write is not mapped.
        #[test]
        fn a_volume_that_answers_einval_has_no_acl_but_a_failed_clear_stays_an_error() {
            let einval = || io::Error::from_raw_os_error(Errno::INVAL.raw_os_error());
            assert_matches!(plan_of(Err(einval())), Ok(AclPlan::None));
            assert!(!is_unsupported(&einval()));
        }

        #[test]
        fn a_volume_without_acls_holds_no_foreign_entry_and_other_failures_prove_nothing() {
            let errno = |errno: Errno| io::Error::from_raw_os_error(errno.raw_os_error());
            for flag in [INHERITED, ONLY_INHERIT] {
                assert!(entries_have(Err(errno(Errno::NOTSUP)), flag));
                assert!(entries_have(Err(errno(Errno::INVAL)), flag));
                assert!(!entries_have(Err(errno(Errno::BADF)), flag));
                assert!(!entries_have(Err(errno(Errno::ACCESS)), flag));
                assert!(!entries_have(Ok(Fetched::Truncated), flag));
                assert!(!entries_have(
                    Ok(Fetched::Complete(Box::from([0u8; 3]))),
                    flag
                ));
            }
        }

        #[test]
        fn a_directory_without_an_acl_holds_only_inherited_and_only_inherit_entries() {
            let temp = tempfile::tempdir().unwrap();
            let dir = File::open(temp.path()).unwrap();
            assert!(only_inherited_entries(&dir));
            assert!(only_inherit_entries(&dir));
        }

        /// A destination `parent/dest` with `mode`, read as a replace reads it.
        fn read_with_mode(
            mode: u32,
            prepare: impl FnOnce(&Path),
        ) -> (tempfile::TempDir, io::Result<AclPlan>) {
            use std::os::unix::fs::PermissionsExt;

            let temp = tempfile::tempdir().unwrap();
            let parent = temp.path().canonicalize().unwrap();
            let dest = parent.join("dest");
            std::fs::create_dir(&dest).unwrap();
            prepare(&dest);
            let pin = VettedDir::open_path(&parent).unwrap();
            let name = crate::formats::pinned_dir::LeafBuf::of(&dest).unwrap();
            let id = pin.status(name.as_leaf()).unwrap().unwrap().identity;
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(mode)).unwrap();
            let plan = read_destination(&pin, name.as_leaf(), &parent, id);
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755)).unwrap();
            (temp, plan)
        }

        #[test]
        fn a_destination_without_read_access_and_without_an_acl_has_none() {
            let (_temp, plan) = read_with_mode(0o311, |_| {});
            assert_matches!(plan, Ok(AclPlan::None));
        }

        #[test]
        fn a_destination_without_read_access_keeps_its_acl() {
            let (temp, plan) = read_with_mode(0o311, |dest| add_ace(dest, "everyone allow search"));
            let _clear = ClearAcl(temp.path());
            assert_matches!(plan, Ok(AclPlan::Copy(_)));
        }

        #[test]
        fn an_acl_that_denies_listing_to_the_caller_is_still_read() {
            let user = Command::new("/usr/bin/id").arg("-un").output().unwrap();
            let user = String::from_utf8(user.stdout).unwrap();
            let ace = format!("user:{} deny list", user.trim());
            let (temp, plan) = read_with_mode(0o755, |dest| add_ace(dest, &ace));
            let _clear = ClearAcl(temp.path());
            let Ok(AclPlan::Copy(acl)) = plan else {
                panic!("expected the ACL to be copied: {plan:?}");
            };
            assert_eq!(acl.aces().first().unwrap().flags & KIND_MASK, KIND_DENY);
        }

        #[test]
        fn a_destination_no_handle_can_be_opened_on_is_unreadable() {
            if rustix::process::geteuid().is_root() {
                return;
            }
            let (_temp, plan) = read_with_mode(0o000, |_| {});
            assert_matches!(plan, Ok(AclPlan::Private(NarrowingReason::AclUnreadable)));
        }

        /// Measured on Darwin 25.6: a `deny readsecurity` entry makes the
        /// attribute read fail with `EACCES`, so it is never read as "no ACL".
        #[test]
        fn a_destination_that_denies_reading_its_security_is_not_read_as_aclless() {
            let temp = tempfile::tempdir().unwrap();
            let _clear = ClearAcl(temp.path());
            add_ace(temp.path(), "everyone deny readsecurity");
            let denied = File::open(temp.path()).unwrap();

            let fetched = darwin_acl::fetch(&denied);

            assert_matches!(
                plan_of(fetched),
                Ok(AclPlan::Private(NarrowingReason::AclUnreadable))
            );
        }

        /// Removes the ACL of a test directory even when an assertion fails, so
        /// the temporary directory can be deleted.
        struct ClearAcl<'a>(&'a Path);

        impl Drop for ClearAcl<'_> {
            fn drop(&mut self) {
                let _ = Command::new("/bin/chmod")
                    .args(["-R", "-N"])
                    .arg(self.0)
                    .status();
            }
        }

        proptest::proptest! {
            #[test]
            fn parsing_arbitrary_bytes_never_panics(
                bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..300),
            ) {
                let _ = parse(&bytes);
                let _ = parse_filesec(&bytes);
            }

            #[test]
            fn parsing_with_a_valid_prefix_reaches_the_count_and_size_branches(
                count in 0_u32..200,
                tail in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..400),
                declared_extra in 0_usize..4,
            ) {
                let mut filesec = filesec(&[]);
                filesec[COUNT_AT..COUNT_AT + 4].copy_from_slice(&count.to_ne_bytes());
                filesec.extend_from_slice(&tail);
                let _ = parse_filesec(&filesec);
                let attribute = {
                    let total = ENVELOPE_LEN + filesec.len();
                    let mut bytes = u32::try_from(total).unwrap().to_ne_bytes().to_vec();
                    bytes.extend_from_slice(&8_i32.to_ne_bytes());
                    let declared = filesec.len().saturating_sub(declared_extra);
                    bytes.extend_from_slice(&u32::try_from(declared).unwrap().to_ne_bytes());
                    bytes.extend_from_slice(&filesec);
                    bytes
                };
                let _ = parse(&attribute);
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) use linux::InheritedAcl;
#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
pub(super) use linux::PosixAcl as CopiedAcl;
#[cfg(target_os = "macos")]
pub(super) use macos::InheritedAcl;
#[cfg(all(unix, target_os = "macos"))]
pub(super) use macos::MacAcl as CopiedAcl;

#[cfg(windows)]
mod imp {
    use std::io;
    use std::path::Path;

    use crate::NarrowingReason;
    use crate::formats::file_identity::FileIdentity;
    use crate::formats::pinned_dir::DirRead;
    use crate::formats::pinned_dir::DirSecurity;
    use crate::formats::pinned_dir::Leaf;
    use crate::formats::pinned_dir::VettedDir;

    /// What the published root does about the destination's DACL.
    #[derive(Debug)]
    pub(in crate::staging) enum AclPlan {
        /// Give the root the destination's descriptor, and the tree what it
        /// would have inherited from it.
        Copy(DirSecurity),
        /// The destination's DACL cannot be read or no longer is the one that
        /// was displaced: the root stays owner-only.
        Private(NarrowingReason),
    }

    /// Reads the DACL of the directory `name` of `pin`, which must still be
    /// the directory `expected` names.
    ///
    /// A directory whose security the caller may not read, or that was
    /// replaced, is a [`AclPlan::Private`] plan, not an error: the run goes on
    /// with a root that is narrower than the destination and says so.
    ///
    /// # Errors
    ///
    /// Any other I/O error of opening or reading it.
    pub(in crate::staging) fn read_destination(
        pin: &VettedDir,
        name: Leaf<'_>,
        _parent_path: &Path,
        expected: FileIdentity,
    ) -> io::Result<AclPlan> {
        match pin.read_dir_security(name, expected) {
            Ok(DirRead::Read(security)) => Ok(AclPlan::Copy(security)),
            Ok(DirRead::Replaced) => Ok(AclPlan::Private(NarrowingReason::DestinationChanged)),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                Ok(AclPlan::Private(NarrowingReason::AclUnreadable))
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use std::io;
    use std::path::Path;

    use crate::formats::file_identity::FileIdentity;
    use crate::formats::pinned_dir::Leaf;
    use crate::formats::pinned_dir::VettedDir;

    /// Platforms without ACLs read none.
    #[derive(Debug, Clone, Copy)]
    pub(in crate::staging) struct AclPlan;

    #[allow(
        clippy::unnecessary_wraps,
        clippy::missing_const_for_fn,
        reason = "keeps the call sites platform-neutral"
    )]
    pub(in crate::staging) fn read_destination(
        _pin: &VettedDir,
        _name: Leaf<'_>,
        _parent_path: &Path,
        _expected: FileIdentity,
    ) -> io::Result<AclPlan> {
        Ok(AclPlan)
    }
}

pub(super) use imp::AclPlan;
#[cfg(unix)]
pub(super) use imp::Ownership;
#[cfg(unix)]
pub(super) use imp::ParentAcl;
#[cfg(unix)]
pub(super) use imp::Resolution;
#[cfg(unix)]
pub(super) use imp::capture_parent;
#[cfg(unix)]
pub(super) use imp::clear_inherited;
pub(super) use imp::read_destination;
#[cfg(unix)]
pub(super) use imp::resolve;
#[cfg(unix)]
pub(super) use imp::stage;
#[cfg(target_os = "macos")]
pub(super) use macos::only_inherit_entries;
#[cfg(target_os = "macos")]
pub(super) use macos::only_inherited_entries;
