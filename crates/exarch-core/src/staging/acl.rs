//! The access control list of the destination the published root replaces.
//!
//! The published root takes the destination's mode bits, but a mode cannot say
//! what an ACL says: on Linux the group bits of a directory with a POSIX ACL
//! hold the ACL mask, and a macOS deny entry has no mode bit at all. A root
//! given only the mode could be readable by users the destination denied.
//!
//! Linux and Android copy the POSIX ACL. macOS only detects an ACL. Wherever
//! an ACL cannot be carried over faithfully the root stays private (`0700`).
//! Other Unixes and `NFSv4` ACLs are not detected.
//!
//! A staging directory made in the destination's parent also inherits that
//! parent's default ACL (Linux) or inheritable entries (macOS). For an
//! existing destination those are removed at creation and again at adoption,
//! and a failure to remove them fails the run.

#[cfg(unix)]
mod imp {
    use std::os::unix::fs::MetadataExt;

    // TODO(#1060, #1020): copy the ACL on macOS (exacl setfacl) and Windows
    // (DACL) instead of falling back to 0700

    /// The user and group a directory belongs to.
    ///
    /// An ACL names its owner and owning group by id, so it only keeps its
    /// meaning on a directory that has the same ones.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(in crate::staging) struct Ownership {
        pub(in crate::staging) uid: u32,
        pub(in crate::staging) gid: u32,
    }

    impl Ownership {
        pub(in crate::staging) fn of(metadata: &std::fs::Metadata) -> Self {
            Self {
                uid: metadata.uid(),
                gid: metadata.gid(),
            }
        }
    }

    /// What the published root does about the destination's ACL.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(in crate::staging) enum AclPlan {
        /// No ACL was found, or this platform does not look for one.
        None,
        /// Copy the POSIX ACL onto the root.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Copy(super::linux::PosixAcl),
        /// The ACL cannot be copied faithfully: the root stays `0700`.
        #[cfg_attr(
            not(any(target_os = "linux", target_os = "android", target_os = "macos")),
            allow(
                dead_code,
                reason = "only platforms that look for an ACL ever fall back to a private root"
            )
        )]
        Private,
    }

    /// What `adopt` does with an [`AclPlan`] once the root's owner is known.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(in crate::staging) enum Resolution {
        /// Nothing to copy; the destination's mode is applied as it is.
        NoAcl,
        /// Write this ACL onto the root.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Copy(super::linux::PosixAcl),
        /// Keep the root `0700`.
        Private,
    }

    /// Decides what to do with `plan` for a root that ended up owned by `root`
    /// when the destination was owned by `destination`.
    ///
    /// An ACL copied onto a root with another owner or group would grant the
    /// destination's owner entry to the wrong user, so it is not copied.
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
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
            #[cfg(any(target_os = "linux", target_os = "android"))]
            AclPlan::Copy(acl) if same_owner => Resolution::Copy(acl),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            AclPlan::Copy(_) => Resolution::Private,
            AclPlan::Private => Resolution::Private,
        }
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
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    #[allow(
        clippy::unnecessary_wraps,
        clippy::missing_const_for_fn,
        reason = "keeps the signature of the platforms that clear an ACL"
    )]
    pub(in crate::staging) fn clear_inherited(
        _pin: &crate::formats::pinned_dir::VettedDir,
        _name: crate::formats::pinned_dir::Leaf<'_>,
    ) -> std::io::Result<()> {
        Ok(())
    }

    /// Other Unixes carry no ACL detection.
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
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
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
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
            uid: 1000,
            gid: 100,
        };

        #[test]
        fn a_destination_without_an_acl_resolves_to_no_acl() {
            let other = Ownership { uid: 0, gid: 0 };
            assert_eq!(
                resolve(AclPlan::None, DESTINATION, other),
                Resolution::NoAcl
            );
        }

        #[test]
        fn a_private_plan_stays_private_whoever_owns_the_root() {
            assert_eq!(
                resolve(AclPlan::Private, DESTINATION, DESTINATION),
                Resolution::Private
            );
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        mod posix {
            use std::assert_matches;

            use super::*;
            use crate::staging::acl::linux::PosixAcl;

            fn plan() -> AclPlan {
                AclPlan::Copy(PosixAcl::for_test(Some(vec![2, 0, 0, 0]), None))
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
                    gid: DESTINATION.gid + 1,
                    ..DESTINATION
                };
                assert_eq!(resolve(plan(), DESTINATION, root), Resolution::Private);
            }

            #[test]
            fn an_acl_is_not_copied_onto_a_root_of_another_user() {
                let root = Ownership {
                    uid: DESTINATION.uid + 1,
                    ..DESTINATION
                };
                assert_eq!(resolve(plan(), DESTINATION, root), Resolution::Private);
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux {
    use std::fs::File;
    use std::io;
    use std::path::Path;

    use rustix::io::Errno;

    use super::imp::AclPlan;
    use crate::formats::file_identity::FileIdentity;
    use crate::formats::pinned_dir::Leaf;
    use crate::formats::pinned_dir::VettedDir;

    const ACCESS: &str = "system.posix_acl_access";
    const DEFAULT: &str = "system.posix_acl_default";
    /// `XATTR_SIZE_MAX`: no extended attribute value is larger.
    const XATTR_SIZE_MAX: usize = 65_536;

    /// The two POSIX ACL extended attributes of a directory, as stored.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(in crate::staging) struct PosixAcl {
        access: Option<Box<[u8]>>,
        default: Option<Box<[u8]>>,
    }

    impl PosixAcl {
        /// Whether the directory has an access ACL, which sets the group bits
        /// of its mode to the ACL mask.
        pub(in crate::staging) const fn has_access(&self) -> bool {
            self.access.is_some()
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
                    Some(blob) => {
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

        #[cfg(test)]
        pub(in crate::staging) fn for_test(
            access: Option<Vec<u8>>,
            default: Option<Vec<u8>>,
        ) -> Self {
            Self {
                access: access.map(Vec::into_boxed_slice),
                default: default.map(Vec::into_boxed_slice),
            }
        }
    }

    fn remove_blob(dir: &File, name: &str) -> io::Result<()> {
        match rustix::fs::fremovexattr(dir, name) {
            Ok(()) | Err(Errno::NODATA | Errno::NOTSUP) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Removes the ACLs the directory `name` of `pin` inherited from its
    /// parent.
    ///
    /// # Errors
    ///
    /// The I/O error of opening the directory or of removing an ACL it has.
    pub(in crate::staging) fn clear_inherited(pin: &VettedDir, name: Leaf<'_>) -> io::Result<()> {
        PosixAcl::clear(&pin.open_dir_file(name)?)
    }

    /// One ACL attribute of a directory.
    #[derive(Debug)]
    enum Blob {
        Present(Box<[u8]>),
        Absent,
        Unreadable,
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
                .map_or(Blob::Absent, |blob| Blob::Present(Box::from(blob)))),
            Err(Errno::NODATA | Errno::NOTSUP) => Ok(Blob::Absent),
            // A bad descriptor is a bug here, not a property of the directory.
            Err(Errno::BADF) => Err(Errno::BADF.into()),
            Err(_) => Ok(Blob::Unreadable),
        }
    }

    /// Reads the POSIX ACL of the directory `name` of `pin`, which must still
    /// be the directory `expected` names.
    ///
    /// The directory is opened for reading, never through an `O_PATH` handle.
    /// A directory its caller cannot open for reading, an ACL that cannot be
    /// read in full and a directory that is no longer `expected` give
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
        let dir = match pin.open_dir_file(name) {
            Ok(dir) => dir,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Ok(AclPlan::Private),
            Err(e) => return Err(e),
        };
        if !super::imp::is_expected(FileIdentity::of_file(&dir), expected) {
            return Ok(AclPlan::Private);
        }
        let mut buffer = vec![0_u8; XATTR_SIZE_MAX];
        let access = read_blob(&dir, ACCESS, &mut buffer)?;
        let default = read_blob(&dir, DEFAULT, &mut buffer)?;
        Ok(plan_of(access, default))
    }

    fn plan_of(access: Blob, default: Blob) -> AclPlan {
        match (access, default) {
            (Blob::Unreadable, _) | (_, Blob::Unreadable) => AclPlan::Private,
            (Blob::Absent, Blob::Absent) => AclPlan::None,
            (access, default) => AclPlan::Copy(PosixAcl {
                access: present(access),
                default: present(default),
            }),
        }
    }

    fn present(blob: Blob) -> Option<Box<[u8]>> {
        match blob {
            Blob::Present(bytes) => Some(bytes),
            Blob::Absent | Blob::Unreadable => None,
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

        fn read_error(errno: Errno) -> io::Result<Blob> {
            classify(Err(errno), &[])
        }

        fn is_unreadable(blob: &io::Result<Blob>) -> bool {
            matches!(blob, Ok(Blob::Unreadable))
        }

        #[test]
        fn a_refused_read_of_an_acl_is_unreadable() {
            for errno in [Errno::ACCESS, Errno::PERM, Errno::IO] {
                assert!(is_unreadable(&read_error(errno)), "{errno}");
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
        fn an_unreadable_blob_makes_the_plan_private_whatever_the_other_one_is() {
            let present = || Blob::Present(Box::from([2_u8, 0, 0, 0].as_slice()));
            assert_eq!(plan_of(Blob::Unreadable, Blob::Absent), AclPlan::Private);
            assert_eq!(plan_of(Blob::Absent, Blob::Unreadable), AclPlan::Private);
            assert_eq!(plan_of(present(), Blob::Unreadable), AclPlan::Private);
            assert_eq!(plan_of(Blob::Unreadable, present()), AclPlan::Private);
        }

        #[test]
        fn two_absent_blobs_make_no_plan() {
            assert_eq!(plan_of(Blob::Absent, Blob::Absent), AclPlan::None);
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::io;
    use std::path::Path;

    use exacl::AclOption;

    use super::imp::AclPlan;
    use crate::formats::file_identity::FileIdentity;
    use crate::formats::file_identity::IdentityKey;
    use crate::formats::pinned_dir::Leaf;
    use crate::formats::pinned_dir::VettedDir;

    /// Removes every ACL entry, inherited ones included, from the directory
    /// `name` of `pin`, addressed through a descriptor on the entry itself.
    ///
    /// A macOS allow entry beats the mode bits, so a root that kept an
    /// inherited one cannot be made private with `chmod`.
    ///
    /// # Errors
    ///
    /// A volume without ACL support (FAT, exFAT) cannot hold an inherited
    /// entry, so its refusal counts as cleared.
    ///
    /// # Errors
    ///
    /// The I/O error of clearing the ACL, or `NotFound` when the directory's
    /// path cannot be resolved.
    pub(in crate::staging) fn clear_inherited(pin: &VettedDir, name: Leaf<'_>) -> io::Result<()> {
        let path = pin
            .entry_path(name)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        cleared(exacl::setfacl(&[path], &[], AclOption::SYMLINK_ACL))
    }

    fn cleared(result: io::Result<()>) -> io::Result<()> {
        match result {
            Err(e) if is_unsupported(&e) => Ok(()),
            other => other,
        }
    }

    // exacl keeps the kind and the message of an OS error but not its code,
    // and std maps ENOTSUP to `Uncategorized`, so the message is the only
    // trace of it.
    fn is_unsupported(error: &io::Error) -> bool {
        let not_supported = io::Error::from_raw_os_error(rustix::io::Errno::NOTSUP.raw_os_error());
        error.raw_os_error() == not_supported.raw_os_error()
            || error.to_string().ends_with(&not_supported.to_string())
    }

    fn is_acl_free(read: io::Result<Vec<exacl::AclEntry>>) -> bool {
        match read {
            Ok(entries) => entries.is_empty(),
            Err(e) => is_unsupported(&e),
        }
    }

    /// Detects an ACL on the directory `name` inside `parent_path`.
    ///
    /// A non-empty ACL, an unreadable one and an entry that is no longer
    /// `expected` give [`AclPlan::Private`]; the ACL itself is not copied.
    ///
    /// # Errors
    ///
    /// Never: every failure falls back to a private root.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "keeps the signature of the platforms that can fail"
    )]
    pub(in crate::staging) fn read_destination(
        _pin: &VettedDir,
        name: Leaf<'_>,
        parent_path: &Path,
        expected: FileIdentity,
    ) -> io::Result<AclPlan> {
        let path = parent_path.join(name.as_os_str());
        let acl_free = is_acl_free(exacl::getfacl(&path, AclOption::SYMLINK_ACL));
        let same_entry = rustix::fs::lstat(&path)
            .ok()
            .and_then(|stat| IdentityKey::of_stat(&stat).ok())
            .is_some_and(|key| super::imp::is_expected(FileIdentity::Known(key), expected));
        Ok(if acl_free && same_entry {
            AclPlan::None
        } else {
            AclPlan::Private
        })
    }

    #[cfg(test)]
    mod tests {
        use std::io;

        use super::cleared;
        use super::is_acl_free;

        fn error(kind: io::ErrorKind) -> io::Error {
            io::Error::from(kind)
        }

        fn not_supported() -> io::Error {
            io::Error::from_raw_os_error(rustix::io::Errno::NOTSUP.raw_os_error())
        }

        fn wrapped_not_supported() -> io::Error {
            io::Error::other(format!("File \"/Volumes/T/d\": {}", not_supported()))
        }

        #[test]
        fn an_unsupported_clear_is_a_success() {
            assert!(cleared(Err(not_supported())).is_ok());
            assert!(cleared(Err(wrapped_not_supported())).is_ok());
        }

        #[test]
        fn every_other_clear_error_stays_an_error() {
            for kind in [
                io::ErrorKind::PermissionDenied,
                io::ErrorKind::NotFound,
                io::ErrorKind::InvalidInput,
                io::ErrorKind::Other,
            ] {
                assert_eq!(
                    cleared(Err(error(kind))).err().map(|e| e.kind()),
                    Some(kind)
                );
            }
        }

        #[test]
        fn a_volume_without_acl_support_reads_as_acl_free() {
            assert!(is_acl_free(Err(wrapped_not_supported())));
            assert!(is_acl_free(Ok(Vec::new())));
        }

        #[test]
        fn a_refused_acl_read_is_not_acl_free() {
            assert!(!is_acl_free(Err(error(io::ErrorKind::PermissionDenied))));
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use std::io;
    use std::path::Path;

    use crate::formats::file_identity::FileIdentity;
    use crate::formats::pinned_dir::Leaf;
    use crate::formats::pinned_dir::VettedDir;

    /// Platforms without Unix ACLs read none.
    #[derive(Debug, Clone, Copy)]
    pub(in crate::staging) struct AclPlan;

    // TODO(#1060, #1020): copy the ACL on macOS (exacl setfacl) and Windows
    // (DACL) instead of falling back to 0700
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

    #[allow(
        clippy::unnecessary_wraps,
        clippy::missing_const_for_fn,
        reason = "keeps the call sites platform-neutral"
    )]
    pub(in crate::staging) fn clear_inherited(_pin: &VettedDir, _name: Leaf<'_>) -> io::Result<()> {
        Ok(())
    }
}

pub(super) use imp::AclPlan;
#[cfg(unix)]
pub(super) use imp::Ownership;
#[cfg(unix)]
pub(super) use imp::Resolution;
pub(super) use imp::clear_inherited;
pub(super) use imp::read_destination;
#[cfg(unix)]
pub(super) use imp::resolve;
#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
pub(super) use linux::PosixAcl;
