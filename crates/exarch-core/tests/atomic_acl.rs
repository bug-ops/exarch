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

use exarch_core::EntryPosition;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::ExtractionReport;
use exarch_core::ExtractionWarning;
use exarch_core::NarrowingReason;
use exarch_core::ProgressCallback;
use exarch_core::SecurityConfig;
use exarch_core::Staging;
use tempfile::TempDir;

const MODES: [Staging; 2] = [Staging::Atomic, Staging::AtomicReplace];

/// The paths of the archive's tree, relative to the destination, which the
/// root's own ACL is compared at as well as its children's.
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
const TREE: [&str; 4] = ["", "p.txt", "d", "d/q.txt"];

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
    twin: PathBuf,
    config: SecurityConfig,
}

/// A tar of the directory `d/` and these files, each with its mode.
fn archive_of(files: &[(&str, u32)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut dir = tar::Header::new_gnu();
    dir.set_entry_type(tar::EntryType::Directory);
    dir.set_mode(0o755);
    dir.set_size(0);
    dir.set_cksum();
    builder.append_data(&mut dir, "d/", &b""[..]).unwrap();
    for (name, mode) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(2);
        header.set_mode(*mode);
        header.set_cksum();
        builder.append_data(&mut header, name, &b"ok"[..]).unwrap();
    }
    builder.into_inner().unwrap()
}

/// Runs a closure once the extraction wrote its last entry, before anything
/// is published, and can cancel the run right after.
struct AtEnd {
    act: Option<Box<dyn FnOnce() + Send>>,
    cancel: bool,
    finished: bool,
}

impl AtEnd {
    fn new(act: impl FnOnce() + Send + 'static) -> Self {
        Self {
            act: Some(Box::new(act)),
            cancel: false,
            finished: false,
        }
    }

    #[cfg(target_os = "macos")]
    fn cancelling() -> Self {
        Self {
            act: None,
            cancel: true,
            finished: false,
        }
    }
}

impl ProgressCallback for AtEnd {
    fn on_entry_start(&mut self, _: &Path, _: EntryPosition) {}

    fn on_bytes_written(&mut self, _: u64) {}

    fn on_entry_complete(&mut self, _: &Path) {}

    fn on_complete(&mut self) {
        if let Some(act) = self.act.take() {
            act();
        }
        self.finished = true;
    }

    fn is_cancelled(&mut self) -> bool {
        self.cancel && self.finished
    }
}

impl Fixture {
    /// A destination, and a twin of it that is extracted in place, which is
    /// what a staged extraction must be indistinguishable from.
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let archive = root.join("a.tar");
        std::fs::write(
            &archive,
            archive_of(&[("p.txt", 0o644), ("d/q.txt", 0o644)]),
        )
        .unwrap();
        let dest = root.join("dest");
        let twin = root.join("twin");
        std::fs::create_dir(&dest).unwrap();
        std::fs::create_dir(&twin).unwrap();
        Self {
            temp,
            archive,
            dest,
            twin,
            config: SecurityConfig::default(),
        }
    }

    fn request(&self, staging: Staging) -> ExtractRequest<'_> {
        ExtractRequest::new(&self.config)
            .with_options(ExtractionOptions::default().with_staging(staging))
    }

    fn extract(&self, staging: Staging) -> ExtractionReport {
        let report = self
            .request(staging)
            .extract(&self.archive, &self.dest)
            .unwrap_or_else(|e| panic!("{staging:?}: {e}"));
        assert_eq!(
            std::fs::read(self.dest.join("p.txt")).unwrap(),
            b"ok",
            "{staging:?}"
        );
        report
    }

    /// Like [`extract`](Self::extract), running `observe` when the last entry
    /// was written.
    fn extract_observed(
        &self,
        staging: Staging,
        observe: impl FnOnce() + Send + 'static,
    ) -> ExtractionReport {
        let mut progress = AtEnd::new(observe);
        self.request(staging)
            .with_progress(&mut progress)
            .extract(&self.archive, &self.dest)
            .unwrap_or_else(|e| panic!("{staging:?}: {e}"))
    }

    /// The failure of a run that is cancelled once everything was extracted.
    #[cfg(target_os = "macos")]
    fn extract_cancelled(&self, staging: Staging) -> exarch_core::ArchiveError {
        let mut progress = AtEnd::cancelling();
        self.request(staging)
            .with_progress(&mut progress)
            .extract(&self.archive, &self.dest)
            .unwrap_err()
    }

    fn extract_twin(&self) {
        self.request(Staging::InPlace)
            .extract(&self.archive, &self.twin)
            .unwrap();
    }
}

/// The staging directory of a running extraction in `parent`.
fn staging_dir_in(parent: &Path) -> PathBuf {
    let found: Vec<_> = std::fs::read_dir(parent)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".exarch-"))
        })
        .collect();
    let [staging] = <[PathBuf; 1]>::try_from(found)
        .unwrap_or_else(|found| panic!("expected one staging directory, found {found:?}"));
    staging
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
                for dir in [&fx.dest, &fx.twin] {
                    chmod(dir, 0o750);
                    match case {
                        DestinationAcl::None => {}
                        DestinationAcl::DefaultOnly => set(dir, DEFAULT, &default_acl()),
                        DestinationAcl::AccessOnly => set(dir, ACCESS, &access_acl()),
                    }
                }
                set(fx.dest.parent().unwrap(), DEFAULT, &parent_default_acl());
                let acls_before = read(&fx.dest);
                let mode_before = mode_of(&fx.dest);

                fx.extract(staging);
                fx.extract_twin();

                let label = format!("{staging:?} {case:?}");
                assert_eq!(read(&fx.dest), acls_before, "{label}");
                assert_eq!(mode_of(&fx.dest), mode_before, "{label}");
                for path in TREE {
                    assert_eq!(
                        read(&fx.dest.join(path)),
                        read(&fx.twin.join(path)),
                        "{label} {path:?}"
                    );
                }
                let inherited = read(&fx.dest.join("p.txt"));
                assert_eq!(
                    inherited.access.is_some(),
                    matches!(case, DestinationAcl::DefaultOnly),
                    "{label}"
                );
            }
        }
    }

    #[test]
    fn staged_children_inherit_the_destination_default_acl_as_an_in_place_twin_does() {
        for staging in MODES {
            let fx = Fixture::new();
            for dir in [&fx.dest, &fx.twin] {
                set(dir, DEFAULT, &default_acl());
                chmod(dir, 0o755);
            }

            fx.extract(staging);
            fx.extract_twin();

            for path in TREE {
                assert_eq!(
                    read(&fx.dest.join(path)),
                    read(&fx.twin.join(path)),
                    "{staging:?} {path:?}"
                );
            }
            let child_dir = read(&fx.dest.join("d"));
            assert!(child_dir.access.is_some(), "{staging:?}");
            assert_eq!(child_dir.default, Some(default_acl()), "{staging:?}");
        }
    }

    #[test]
    fn the_stage_holds_only_a_default_acl_while_the_archive_extracts() {
        for staging in MODES {
            let fx = Fixture::new();
            set(&fx.dest, DEFAULT, &default_acl());
            set(fx.dest.parent().unwrap(), DEFAULT, &parent_default_acl());
            let parent = fx.dest.parent().unwrap().to_path_buf();

            fx.extract_observed(staging, move || {
                let stage = staging_dir_in(&parent);
                assert_eq!(mode_of(&stage), 0o700, "{staging:?}");
                assert_eq!(
                    read(&stage),
                    Acls {
                        access: None,
                        default: Some(default_acl())
                    },
                    "{staging:?}"
                );
            });
        }
    }

    #[test]
    fn a_destination_that_vanishes_after_seeding_publishes_a_private_root_without_its_acl() {
        let fx = Fixture::new();
        set(&fx.dest, DEFAULT, &default_acl());
        chmod(&fx.dest, 0o755);

        let removed = fx.dest.clone();
        let report = fx.extract_observed(Staging::Atomic, move || {
            std::fs::remove_dir(&removed).unwrap();
        });

        assert_eq!(mode_of(&fx.dest), 0o700);
        assert_eq!(read(&fx.dest), Acls::default());
        assert_eq!(
            narrowing_of(&report),
            [NarrowingReason::DestinationVanished]
        );
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
    use std::assert_matches;
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

    /// A mix of access-only and inheritable entries, allow and deny, in an
    /// order the copy must keep.
    fn mixed_entries(dir: &Path) {
        chmod(dir, 0o755);
        add_ace(
            dir,
            "user:nobody deny delete,file_inherit,directory_inherit",
        );
        add_ace(dir, "group:_www deny read,file_inherit");
        add_ace(dir, "group:staff allow list,search,read,directory_inherit");
        add_ace(dir, "group:_www deny list,search");
    }

    #[test]
    fn staged_children_inherit_the_destination_entries_as_an_in_place_twin_does() {
        for staging in MODES {
            let fx = Fixture::new();
            mixed_entries(&fx.dest);
            mixed_entries(&fx.twin);
            let root_before = aces_of(&fx.dest);
            assert_eq!(root_before.len(), 4);

            let report = fx.extract(staging);
            fx.extract_twin();

            assert!(narrowing_of(&report).is_empty(), "{staging:?}");
            assert_eq!(aces_of(&fx.dest), root_before, "{staging:?}");
            assert_eq!(mode_of(&fx.dest), 0o755, "{staging:?}");
            for path in TREE {
                assert_eq!(
                    aces_of(&fx.dest.join(path)),
                    aces_of(&fx.twin.join(path)),
                    "{staging:?} {path:?}"
                );
            }
            assert!(!aces_of(&fx.dest.join("p.txt")).is_empty(), "{staging:?}");
            assert!(!aces_of(&fx.dest.join("d")).is_empty(), "{staging:?}");
        }
    }

    #[test]
    fn the_stage_holds_only_entries_that_children_receive_while_the_archive_extracts() {
        for staging in MODES {
            let fx = Fixture::new();
            mixed_entries(&fx.dest);
            let parent = fx.dest.parent().unwrap().to_path_buf();

            fx.extract_observed(staging, move || {
                let stage = staging_dir_in(&parent);
                assert_eq!(mode_of(&stage), 0o700, "{staging:?}");
                let aces = aces_of(&stage);
                assert_eq!(aces.len(), 3, "{staging:?} {aces:?}");
                assert!(
                    aces.iter().all(|ace| ace.contains("only_inherit")),
                    "{staging:?} {aces:?}"
                );
            });
        }
    }

    #[test]
    fn a_destination_that_vanishes_after_seeding_publishes_a_private_root_without_its_entries() {
        let fx = Fixture::new();
        mixed_entries(&fx.dest);

        let removed = fx.dest.clone();
        let report = fx.extract_observed(Staging::Atomic, move || {
            std::fs::remove_dir(&removed).unwrap();
        });

        assert_eq!(mode_of(&fx.dest), 0o700);
        assert!(aces_of(&fx.dest).is_empty());
        std::fs::write(fx.dest.join("later.txt"), b"x").unwrap();
        assert!(aces_of(&fx.dest.join("later.txt")).is_empty());
        assert_eq!(
            narrowing_of(&report),
            [NarrowingReason::DestinationVanished]
        );
    }

    #[test]
    fn a_destination_deny_that_children_inherit_does_not_strand_the_umask_probe() {
        let fx = Fixture::new();
        chmod(&fx.dest, 0o755);
        chmod(&fx.twin, 0o755);
        let deny = "everyone deny delete,directory_inherit,only_inherit";
        add_ace(&fx.dest, deny);
        add_ace(&fx.twin, deny);

        fx.extract(Staging::Atomic);
        fx.extract_twin();

        assert_eq!(
            probes_under(&fx.dest),
            Vec::<PathBuf>::new(),
            "no probe directory is published"
        );
        for path in TREE {
            assert_eq!(
                aces_of(&fx.dest.join(path)),
                aces_of(&fx.twin.join(path)),
                "{path:?}"
            );
        }
        assert_eq!(aces_of(&fx.dest.join("d")).len(), 1);
    }

    fn probes_under(root: &Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(".exarch-probe-"))
                {
                    found.push(path.clone());
                }
                if path.is_dir() {
                    pending.push(path);
                }
            }
        }
        found
    }

    #[test]
    fn a_failed_run_under_an_inherited_delete_deny_leaves_nothing_behind() {
        let fx = Fixture::new();
        chmod(&fx.dest, 0o755);
        add_ace(
            &fx.dest,
            "everyone deny delete,directory_inherit,only_inherit",
        );

        let error = fx.extract_cancelled(Staging::Atomic);

        let exarch_core::ArchiveError::PartialExtraction(partial) = &error else {
            panic!("expected a partial extraction, got {error}");
        };
        assert!(partial.leftover().is_none(), "{:?}", partial.leftover());
        assert_eq!(
            staging_dirs_in(fx.dest.parent().unwrap()),
            Vec::<PathBuf>::new()
        );
    }

    /// Cancelled runs under a parent whose children inherit `ace`, with a
    /// directory, an ordinary file and a write-only file staged.
    fn assert_rolled_back_cleanly_under(ace: &str) {
        for staging in MODES {
            let fx = absent_fixture();
            std::fs::write(
                &fx.archive,
                archive_of(&[("p.txt", 0o644), ("d/q.txt", 0o644), ("w.txt", 0o200)]),
            )
            .unwrap();
            let parent = fx.dest.parent().unwrap().to_path_buf();
            add_ace(&parent, ace);

            let error = fx.extract_cancelled(staging);

            remove_acl(&parent);
            let exarch_core::ArchiveError::PartialExtraction(partial) = &error else {
                panic!("{staging:?}: expected a partial extraction, got {error}");
            };
            assert!(partial.leftover().is_none(), "{staging:?}");
            assert_eq!(
                staging_dirs_in(&parent),
                Vec::<PathBuf>::new(),
                "{staging:?}"
            );
        }
    }

    fn remove_acl(path: &Path) {
        let status = Command::new("/bin/chmod")
            .args(["-N"])
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success(), "chmod -N");
    }

    #[test]
    fn a_rollback_under_an_inheritable_delete_deny_removes_every_staged_entry() {
        assert_rolled_back_cleanly_under("everyone deny delete,file_inherit,directory_inherit");
    }

    #[test]
    fn a_rollback_under_inheritable_list_and_delete_denies_removes_every_staged_entry() {
        assert_rolled_back_cleanly_under(
            "everyone deny list,delete,file_inherit,directory_inherit",
        );
    }

    #[test]
    fn a_staged_file_nobody_may_open_is_named_as_the_leftover() {
        let fx = absent_fixture();
        std::fs::write(&fx.archive, archive_of(&[("z.txt", 0o000)])).unwrap();
        let parent = fx.dest.parent().unwrap().to_path_buf();
        add_ace(
            &parent,
            "everyone deny delete,file_inherit,directory_inherit",
        );

        let error = fx.extract_cancelled(Staging::Atomic);

        let exarch_core::ArchiveError::PartialExtraction(partial) = &error else {
            panic!("expected a partial extraction, got {error}");
        };
        let leftover = partial.leftover().unwrap();
        assert!(leftover.path.join("z.txt").exists());
    }

    #[test]
    fn an_absent_destination_under_an_inheritable_deny_list_extracts_like_in_place() {
        for staging in MODES {
            let fx = absent_fixture();
            let parent = fx.dest.parent().unwrap().to_path_buf();
            add_ace(&parent, "everyone deny list,directory_inherit");

            fx.extract(staging);
            fx.extract_twin();

            remove_acl(&parent);
            assert_eq!(
                staging_dirs_in(&parent),
                Vec::<PathBuf>::new(),
                "{staging:?}"
            );
            for path in TREE {
                assert_eq!(
                    aces_of(&fx.dest.join(path)),
                    aces_of(&fx.twin.join(path)),
                    "{staging:?} {path:?}"
                );
            }
            assert!(!aces_of(&fx.dest).is_empty(), "{staging:?}");
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

    fn staging_dirs_in(parent: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(parent)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(".exarch-"))
            })
            .collect()
    }

    /// A fixture whose destination and twin do not exist yet.
    fn absent_fixture() -> Fixture {
        let fx = Fixture::new();
        std::fs::remove_dir(&fx.dest).unwrap();
        std::fs::remove_dir(&fx.twin).unwrap();
        fx
    }

    #[test]
    fn a_destination_denying_its_own_deletion_is_published_with_its_acl() {
        let fx = Fixture::new();
        chmod(&fx.dest, 0o755);
        add_ace(&fx.dest, "everyone deny delete");
        let before = aces_of(&fx.dest);
        assert_eq!(before.len(), 1);

        let report = fx.extract(Staging::Atomic);

        assert_eq!(aces_of(&fx.dest), before);
        assert_eq!(mode_of(&fx.dest), 0o755);
        assert!(narrowing_of(&report).is_empty());
        assert_eq!(
            staging_dirs_in(fx.dest.parent().unwrap()),
            Vec::<PathBuf>::new()
        );
    }

    #[test]
    fn a_destination_denying_deletion_to_its_children_matches_the_in_place_twin() {
        let fx = Fixture::new();
        for dir in [&fx.dest, &fx.twin] {
            chmod(dir, 0o755);
            add_ace(dir, "everyone deny delete,file_inherit,directory_inherit");
        }

        fx.extract(Staging::Atomic);
        fx.extract_twin();

        for path in TREE {
            assert_eq!(
                aces_of(&fx.dest.join(path)),
                aces_of(&fx.twin.join(path)),
                "{path:?}"
            );
        }
        assert_eq!(
            staging_dirs_in(fx.dest.parent().unwrap()),
            Vec::<PathBuf>::new()
        );
    }

    #[test]
    fn a_destination_filled_meanwhile_is_refused_without_a_leftover() {
        let fx = Fixture::new();
        chmod(&fx.dest, 0o755);
        add_ace(&fx.dest, "everyone deny delete");
        let planted = fx.dest.join("planted");
        let mut progress = AtEnd::new(move || std::fs::write(planted, b"x").unwrap());

        let error = fx
            .request(Staging::Atomic)
            .with_progress(&mut progress)
            .extract(&fx.archive, &fx.dest)
            .unwrap_err();

        assert_matches!(
            error,
            exarch_core::ArchiveError::OutputExists { .. },
            "{error}"
        );
        assert_eq!(
            staging_dirs_in(fx.dest.parent().unwrap()),
            Vec::<PathBuf>::new()
        );
    }

    #[test]
    fn an_absent_destination_is_private_while_the_archive_extracts_and_inherits_as_in_place() {
        for staging in MODES {
            let fx = absent_fixture();
            let parent = fx.dest.parent().unwrap().to_path_buf();
            add_ace(
                &parent,
                "everyone allow list,add_file,search,add_subdirectory,directory_inherit",
            );
            let observed = parent.clone();

            let report = fx.extract_observed(staging, move || {
                let stage = staging_dir_in(&observed);
                assert_eq!(mode_of(&stage), 0o700, "{staging:?}");
                let aces = aces_of(&stage);
                assert!(!aces.is_empty(), "{staging:?}");
                assert!(
                    aces.iter().all(|ace| ace.contains("only_inherit")),
                    "{staging:?} {aces:?}"
                );
            });
            fx.extract_twin();

            assert!(narrowing_of(&report).is_empty(), "{staging:?}");
            assert_eq!(mode_of(&fx.dest), mode_of(&fx.twin), "{staging:?}");
            for path in TREE {
                assert_eq!(
                    aces_of(&fx.dest.join(path)),
                    aces_of(&fx.twin.join(path)),
                    "{staging:?} {path:?}"
                );
            }
            assert!(!aces_of(&fx.dest).is_empty(), "{staging:?}");
        }
    }

    #[test]
    fn an_absent_destination_under_an_inheritable_deny_extracts_like_in_place() {
        for staging in MODES {
            let fx = absent_fixture();
            let parent = fx.dest.parent().unwrap().to_path_buf();
            add_ace(&parent, "everyone deny delete,directory_inherit");

            fx.extract(staging);
            fx.extract_twin();

            assert_eq!(probes_under(&fx.dest), Vec::<PathBuf>::new(), "{staging:?}");
            assert_eq!(
                staging_dirs_in(&parent),
                Vec::<PathBuf>::new(),
                "{staging:?}"
            );
            for path in TREE {
                assert_eq!(
                    aces_of(&fx.dest.join(path)),
                    aces_of(&fx.twin.join(path)),
                    "{staging:?} {path:?}"
                );
            }
        }
    }

    #[test]
    fn an_absent_destination_under_a_parent_without_an_acl_gets_none() {
        for staging in MODES {
            let fx = absent_fixture();

            fx.extract(staging);
            fx.extract_twin();

            assert!(aces_of(&fx.dest).is_empty(), "{staging:?}");
            assert_eq!(mode_of(&fx.dest), mode_of(&fx.twin), "{staging:?}");
        }
    }
}
