//! Atomic publication never leaves the root more permissive than the
//! destination it fills or replaces: the destination's ACL is copied on Linux
//! and macOS, and the root stays private, with a warning, when it cannot be
//! (#1031, #1060, #1063).

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::ExtractionReport;
use exarch_core::ExtractionWarning;
use exarch_core::NarrowingReason;
use exarch_core::SecurityConfig;
use exarch_core::Staging;
use tempfile::TempDir;

const MODES: [Staging; 2] = [Staging::Atomic, Staging::AtomicReplace];

struct Fixture {
    #[cfg_attr(
        not(target_os = "macos"),
        allow(
            dead_code,
            reason = "keeps the directory alive; only macOS cleanup reads it"
        )
    )]
    temp: TempDir,
    archive: PathBuf,
    dest: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(2);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "p.txt", &b"ok"[..])
            .unwrap();
        let archive = temp.path().canonicalize().unwrap().join("a.tar");
        std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();
        let dest = archive.with_file_name("dest");
        std::fs::create_dir(&dest).unwrap();
        Self {
            temp,
            archive,
            dest,
        }
    }

    fn extract(&self, staging: Staging) -> ExtractionReport {
        let report = ExtractRequest::new(&SecurityConfig::default())
            .with_options(ExtractionOptions::default().with_staging(staging))
            .extract(&self.archive, &self.dest)
            .unwrap_or_else(|e| panic!("{staging:?}: {e}"));
        assert_eq!(
            std::fs::read(self.dest.join("p.txt")).unwrap(),
            b"ok",
            "{staging:?}"
        );
        report
    }
}

#[cfg(target_os = "macos")]
impl Drop for Fixture {
    fn drop(&mut self) {
        // Deny entries would keep the temporary directory from being removed.
        let _ = std::process::Command::new("/bin/chmod")
            .args(["-R", "-N"])
            .arg(self.temp.path())
            .status();
    }
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().mode() & 0o7777
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn narrowing_of(report: &ExtractionReport) -> Vec<NarrowingReason> {
    report
        .warnings
        .iter()
        .filter_map(|warning| match warning {
            ExtractionWarning::RootAccessNarrowed { reason } => Some(*reason),
            _ => None,
        })
        .collect()
}

#[test]
fn a_destination_without_an_acl_publishes_its_mode_unchanged() {
    for staging in MODES {
        let fx = Fixture::new();
        chmod(&fx.dest, 0o750);

        fx.extract(staging);

        assert_eq!(mode_of(&fx.dest), 0o750, "{staging:?}");
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assert_eq!(linux::read(&fx.dest), linux::Acls::default(), "{staging:?}");
        #[cfg(target_os = "macos")]
        assert!(macos::aces_of(&fx.dest).is_empty(), "{staging:?}");
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux {
    use rustix::fs::XattrFlags;
    use rustix::io::Errno;

    use super::*;

    const ACCESS: &str = "system.posix_acl_access";
    const DEFAULT: &str = "system.posix_acl_default";

    const USER_OBJ: u16 = 0x01;
    const USER: u16 = 0x02;
    const GROUP_OBJ: u16 = 0x04;
    const MASK: u16 = 0x10;
    const OTHER: u16 = 0x20;
    const NO_ID: u32 = u32::MAX;
    const NAMED_UID: u32 = 12_345;
    const INHERITED_UID: u32 = 54_321;

    const R: u16 = 4;
    const W: u16 = 2;
    const X: u16 = 1;

    #[derive(Debug, Default, PartialEq, Eq)]
    pub struct Acls {
        access: Option<Vec<u8>>,
        default: Option<Vec<u8>>,
    }

    fn is_root(path: &Path) -> bool {
        std::fs::metadata(path).unwrap().uid() == 0
    }

    fn blob(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut bytes = 2_u32.to_le_bytes().to_vec();
        for &(tag, perm, id) in entries {
            bytes.extend_from_slice(&tag.to_le_bytes());
            bytes.extend_from_slice(&perm.to_le_bytes());
            bytes.extend_from_slice(&id.to_le_bytes());
        }
        bytes
    }

    /// `user::rwx`, `user:12345:rwx`, `group::---`, `mask::rwx`, `other::---`:
    /// the owning group has no access, yet `st_mode` reads `0770`.
    fn access_acl() -> Vec<u8> {
        blob(&[
            (USER_OBJ, R | W | X, NO_ID),
            (USER, R | W | X, NAMED_UID),
            (GROUP_OBJ, 0, NO_ID),
            (MASK, R | W | X, NO_ID),
            (OTHER, 0, NO_ID),
        ])
    }

    fn default_acl() -> Vec<u8> {
        blob(&[
            (USER_OBJ, R | W | X, NO_ID),
            (USER, R | X, NAMED_UID),
            (GROUP_OBJ, R | X, NO_ID),
            (MASK, R | X, NO_ID),
            (OTHER, 0, NO_ID),
        ])
    }

    fn set(path: &Path, name: &str, value: &[u8]) {
        match rustix::fs::setxattr(path, name, value, XattrFlags::empty()) {
            Ok(()) => {}
            Err(Errno::NOTSUP) => panic!("the test directory's filesystem has no POSIX ACLs"),
            Err(e) => panic!("setting {name}: {e}"),
        }
    }

    fn get(path: &Path, name: &str) -> Option<Vec<u8>> {
        let mut buffer = vec![0_u8; 65_536];
        match rustix::fs::getxattr(path, name, &mut buffer[..]) {
            Ok(len) => {
                buffer.truncate(len);
                Some(buffer)
            }
            Err(Errno::NODATA | Errno::NOTSUP) => None,
            Err(e) => panic!("reading {name}: {e}"),
        }
    }

    pub fn read(path: &Path) -> Acls {
        Acls {
            access: get(path, ACCESS),
            default: get(path, DEFAULT),
        }
    }

    #[test]
    fn the_destination_acl_is_copied_onto_the_published_root() {
        for staging in MODES {
            let fx = Fixture::new();
            set(&fx.dest, ACCESS, &access_acl());
            set(&fx.dest, DEFAULT, &default_acl());
            let before = read(&fx.dest);
            assert!(before.access.is_some() && before.default.is_some());
            assert_eq!(mode_of(&fx.dest), 0o770, "the mask shows as the group bits");

            fx.extract(staging);

            assert_eq!(read(&fx.dest), before, "{staging:?}");
            assert_eq!(mode_of(&fx.dest), 0o770, "{staging:?}");
        }
    }

    #[test]
    fn a_default_acl_alone_keeps_the_destination_mode() {
        for staging in MODES {
            let fx = Fixture::new();
            set(&fx.dest, DEFAULT, &default_acl());
            chmod(&fx.dest, 0o755);
            let before = read(&fx.dest);
            assert!(before.access.is_none() && before.default.is_some());

            fx.extract(staging);

            assert_eq!(read(&fx.dest), before, "{staging:?}");
            assert_eq!(mode_of(&fx.dest), 0o755, "{staging:?}");
        }
    }

    /// A default ACL on the destination's parent that grants a named user
    /// everything: a directory made there inherits it.
    fn parent_default_acl() -> Vec<u8> {
        blob(&[
            (USER_OBJ, R | W | X, NO_ID),
            (USER, R | W | X, INHERITED_UID),
            (GROUP_OBJ, R | X, NO_ID),
            (MASK, R | W | X, NO_ID),
            (OTHER, 0, NO_ID),
        ])
    }

    #[derive(Debug, Clone, Copy)]
    enum DestinationAcl {
        None,
        DefaultOnly,
        AccessOnly,
    }

    #[test]
    fn a_parent_default_acl_is_not_inherited_by_the_published_root() {
        for staging in MODES {
            for case in [
                DestinationAcl::None,
                DestinationAcl::DefaultOnly,
                DestinationAcl::AccessOnly,
            ] {
                let fx = Fixture::new();
                chmod(&fx.dest, 0o750);
                match case {
                    DestinationAcl::None => {}
                    DestinationAcl::DefaultOnly => set(&fx.dest, DEFAULT, &default_acl()),
                    DestinationAcl::AccessOnly => set(&fx.dest, ACCESS, &access_acl()),
                }
                set(fx.dest.parent().unwrap(), DEFAULT, &parent_default_acl());
                let acls_before = read(&fx.dest);
                let mode_before = mode_of(&fx.dest);

                fx.extract(staging);

                let label = format!("{staging:?} {case:?}");
                assert_eq!(read(&fx.dest), acls_before, "{label}");
                assert_eq!(mode_of(&fx.dest), mode_before, "{label}");
                assert_eq!(read(&fx.dest.join("p.txt")), Acls::default(), "{label}");
            }
        }
    }

    #[test]
    fn a_setgid_destination_with_an_acl_stays_setgid() {
        for staging in MODES {
            let fx = Fixture::new();
            set(&fx.dest, ACCESS, &access_acl());
            chmod(&fx.dest, 0o2770);
            let before = mode_of(&fx.dest);
            assert_eq!(before, 0o2770);

            fx.extract(staging);

            assert_eq!(mode_of(&fx.dest), before, "{staging:?}");
            assert!(read(&fx.dest).access.is_some(), "{staging:?}");
        }
    }

    /// `Staging::Atomic` refuses such a destination earlier, when it checks
    /// that the directory is empty.
    #[test]
    fn a_replaced_destination_its_owner_cannot_read_publishes_a_private_root() {
        let fx = Fixture::new();
        chmod(&fx.dest, 0o300);
        let root = is_root(&fx.dest);
        let expected = if root { 0o300 } else { 0o700 };

        let report = fx.extract(Staging::AtomicReplace);

        assert_eq!(mode_of(&fx.dest), expected);
        let reasons = narrowing_of(&report);
        if root {
            assert!(reasons.is_empty(), "{reasons:?}");
        } else {
            assert_eq!(reasons, [NarrowingReason::AclUnreadable]);
        }
    }

    /// Needs root to give the destination away, so it only runs there; on an
    /// unprivileged run the decision itself is covered by the unit tests of
    /// `resolve` in `staging/acl.rs`.
    #[test]
    fn an_acl_is_not_copied_onto_a_root_another_user_owns() {
        let fx = Fixture::new();
        if !is_root(&fx.dest) {
            eprintln!("skipping: needs root to give the destination to another user");
            return;
        }
        set(&fx.dest, ACCESS, &access_acl());
        std::os::unix::fs::chown(&fx.dest, Some(1000), Some(1000)).unwrap();

        let report = fx.extract(Staging::Atomic);

        assert_eq!(mode_of(&fx.dest), 0o700);
        assert_eq!(read(&fx.dest), Acls::default());
        assert_eq!(
            narrowing_of(&report),
            [
                NarrowingReason::GroupNotKept,
                NarrowingReason::OwnershipDiffers
            ]
        );
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::process::Command;

    use super::*;

    /// The entries `ls -led` prints for `path`, without their index.
    pub fn aces_of(path: &Path) -> Vec<String> {
        let output = Command::new("/bin/ls")
            .args(["-led"])
            .arg(path)
            .output()
            .unwrap();
        assert!(output.status.success(), "ls -led");
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .skip(1)
            .map(|line| {
                let (_, ace) = line.trim().split_once(": ").unwrap();
                ace.to_owned()
            })
            .collect()
    }

    fn add_ace(path: &Path, ace: &str) {
        let status = Command::new("/bin/chmod")
            .args(["+a", ace])
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success(), "chmod +a {ace:?}");
    }

    /// `Staging::Atomic` refuses such a destination earlier, when it checks
    /// that the directory is empty.
    #[test]
    fn a_destination_whose_acl_denies_the_caller_a_read_publishes_a_private_root() {
        let fx = Fixture::new();
        chmod(&fx.dest, 0o755);
        add_ace(&fx.dest, "group:staff deny list,search");
        add_ace(&fx.dest, "everyone deny list,search");
        assert_eq!(aces_of(&fx.dest).len(), 2);

        let report = fx.extract(Staging::AtomicReplace);

        assert_eq!(mode_of(&fx.dest), 0o700);
        assert!(aces_of(&fx.dest).is_empty());
        assert_eq!(narrowing_of(&report), [NarrowingReason::AclUnreadable]);
    }

    #[test]
    fn an_acl_with_inheritable_entries_gives_a_private_root_with_a_warning() {
        for staging in MODES {
            let fx = Fixture::new();
            chmod(&fx.dest, 0o755);
            add_ace(&fx.dest, "group:staff allow list,search,file_inherit");
            assert_eq!(aces_of(&fx.dest).len(), 1);

            let report = fx.extract(staging);

            assert_eq!(mode_of(&fx.dest), 0o700, "{staging:?}");
            assert!(aces_of(&fx.dest).is_empty(), "{staging:?}");
            assert!(aces_of(&fx.dest.join("p.txt")).is_empty(), "{staging:?}");
            assert_eq!(
                narrowing_of(&report),
                [NarrowingReason::AclHasInheritableEntries],
                "{staging:?}"
            );
        }
    }

    #[test]
    fn a_parent_inheritable_entry_is_not_inherited_by_the_published_root() {
        for staging in MODES {
            let fx = Fixture::new();
            chmod(&fx.dest, 0o700);
            add_ace(
                fx.dest.parent().unwrap(),
                "everyone allow list,search,read,file_inherit,directory_inherit",
            );
            assert!(aces_of(&fx.dest).is_empty(), "{staging:?}");

            fx.extract(staging);

            assert_eq!(mode_of(&fx.dest), 0o700, "{staging:?}");
            assert!(aces_of(&fx.dest).is_empty(), "{staging:?}");
            assert!(aces_of(&fx.dest.join("p.txt")).is_empty(), "{staging:?}");
        }
    }

    #[test]
    fn named_deny_entries_are_copied_onto_the_published_root() {
        for staging in MODES {
            let fx = Fixture::new();
            chmod(&fx.dest, 0o755);
            add_ace(&fx.dest, "user:nobody deny list,search");
            add_ace(&fx.dest, "group:_www deny list,search");
            let before = aces_of(&fx.dest);
            assert_eq!(before.len(), 2);

            fx.extract(staging);

            assert_eq!(aces_of(&fx.dest), before, "{staging:?}");
            assert_eq!(mode_of(&fx.dest), 0o755, "{staging:?}");
        }
    }
}
