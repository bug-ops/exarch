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
    pub(in crate::staging) use super::linux::read_destination;
    #[cfg(target_os = "macos")]
    pub(in crate::staging) use super::macos::read_destination;

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
            use super::*;
            use crate::staging::acl::linux::PosixAcl;

            fn plan() -> AclPlan {
                AclPlan::Copy(PosixAcl::for_test(Some(vec![2, 0, 0, 0]), None))
            }

            #[test]
            fn an_acl_is_copied_onto_a_root_with_the_same_owner_and_group() {
                assert!(matches!(
                    resolve(plan(), DESTINATION, DESTINATION),
                    Resolution::Copy(_)
                ));
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

        /// Writes the default ACL and then the access ACL onto `dir`.
        ///
        /// The kernel derives the owner, mask and other bits of the mode from
        /// the access ACL.
        pub(in crate::staging) fn write_to(&self, dir: &File) -> io::Result<()> {
            for (name, blob) in [(DEFAULT, &self.default), (ACCESS, &self.access)] {
                if let Some(blob) = blob {
                    rustix::fs::fsetxattr(dir, name, blob, rustix::fs::XattrFlags::empty())?;
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
            for name in [DEFAULT, ACCESS] {
                match rustix::fs::fremovexattr(dir, name) {
                    Ok(()) | Err(Errno::NODATA | Errno::NOTSUP) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Ok(())
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

    /// One ACL attribute of a directory.
    enum Blob {
        Present(Box<[u8]>),
        Absent,
        Unreadable,
    }

    fn read_blob(dir: &File, name: &str, buffer: &mut [u8]) -> io::Result<Blob> {
        match rustix::fs::fgetxattr(dir, name, &mut *buffer) {
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
        Ok(match (access, default) {
            (Blob::Unreadable, _) | (_, Blob::Unreadable) => AclPlan::Private,
            (Blob::Absent, Blob::Absent) => AclPlan::None,
            (access, default) => AclPlan::Copy(PosixAcl {
                access: present(access),
                default: present(default),
            }),
        })
    }

    fn present(blob: Blob) -> Option<Box<[u8]>> {
        match blob {
            Blob::Present(bytes) => Some(bytes),
            Blob::Absent | Blob::Unreadable => None,
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
        let acl_free =
            exacl::getfacl(&path, AclOption::SYMLINK_ACL).is_ok_and(|acl| acl.is_empty());
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
}

pub(super) use imp::AclPlan;
#[cfg(unix)]
pub(super) use imp::Ownership;
#[cfg(unix)]
pub(super) use imp::Resolution;
pub(super) use imp::read_destination;
#[cfg(unix)]
pub(super) use imp::resolve;
#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
pub(super) use linux::PosixAcl;
