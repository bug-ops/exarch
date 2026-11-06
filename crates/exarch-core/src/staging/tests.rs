use std::assert_matches;
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::path::PathBuf;

use tempfile::TempDir;

use super::replace::is_within;
use super::replace::protected_path;
use super::staged_options;
use crate::ArchiveError;
use crate::BackupIdentity;
use crate::ConfigProblem;
use crate::ConfigSetting;
use crate::EntryPosition;
use crate::ExistingFiles;
use crate::ExtractRequest;
use crate::ExtractionOptions;
use crate::ExtractionReport;
use crate::ExtractionWarning;
use crate::ProgressCallback;
use crate::ProtectedPath;
use crate::Restore;
use crate::SecurityConfig;
use crate::Staging;
use crate::Violation;
use crate::formats::file_identity::FileIdentity;
use crate::formats::file_identity::IdentityKey;
use crate::formats::file_identity::identity_of;
use crate::test_utils::create_test_tar;

type Action = Box<dyn FnMut() + Send>;

/// A progress callback that acts at chosen moments of an extraction.
#[derive(Default)]
struct Hooks {
    started: usize,
    cancelled: bool,
    cancel_at_end: bool,
    on_first_entry: Option<Action>,
    at_end: Option<Action>,
}

impl ProgressCallback for Hooks {
    fn on_entry_start(&mut self, _: &Path, _: EntryPosition) {
        self.started += 1;
        if self.started == 1
            && let Some(act) = self.on_first_entry.as_mut()
        {
            act();
        }
    }

    fn on_bytes_written(&mut self, _: u64) {}

    fn on_entry_complete(&mut self, _: &Path) {}

    fn on_complete(&mut self) {
        if let Some(act) = self.at_end.as_mut() {
            act();
        }
        self.cancelled = self.cancel_at_end;
    }

    fn is_cancelled(&mut self) -> bool {
        self.cancelled
    }
}

struct Fixture {
    root: TempDir,
    parent: PathBuf,
    archive: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        let parent = parent.canonicalize().unwrap();
        let archive = root.path().join("a.tar");
        std::fs::write(
            &archive,
            create_test_tar(vec![("a.txt", b"new a"), ("sub/b.txt", b"new b")]),
        )
        .unwrap();
        Self {
            root,
            parent,
            archive,
        }
    }

    fn dest(&self) -> PathBuf {
        self.parent.join("dest")
    }

    fn extract(
        &self,
        dest: &Path,
        staging: Staging,
        progress: &mut Hooks,
    ) -> Result<ExtractionReport, ArchiveError> {
        extract(&self.archive, dest, staging, progress)
    }

    fn with_old_destination(&self) -> PathBuf {
        let dest = self.dest();
        std::fs::create_dir_all(dest.join("old_dir")).unwrap();
        std::fs::write(dest.join("old.txt"), b"old").unwrap();
        std::fs::write(dest.join("old_dir/inner.txt"), b"old inner").unwrap();
        dest
    }

    fn leftovers(&self) -> Vec<OsString> {
        leftovers(&self.parent)
    }
}

fn extract(
    archive: &Path,
    dest: &Path,
    staging: Staging,
    progress: &mut Hooks,
) -> Result<ExtractionReport, ArchiveError> {
    ExtractRequest::new(&SecurityConfig::default())
        .with_options(ExtractionOptions::default().with_staging(staging))
        .with_progress(progress)
        .extract(archive, dest)
}

fn leftovers(parent: &Path) -> Vec<OsString> {
    std::fs::read_dir(parent)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| name.to_string_lossy().starts_with(".exarch-"))
        .collect()
}

fn staging_dirs(parent: &Path) -> Vec<PathBuf> {
    leftovers(parent)
        .into_iter()
        .map(|name| parent.join(name))
        .collect()
}

fn cause(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    }
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

#[test]
fn staged_options_raise_skip_to_refuse_and_keep_the_others() {
    let options = |existing_files| ExtractionOptions::default().with_existing_files(existing_files);
    for (given, staged) in [
        (ExistingFiles::Skip, ExistingFiles::Refuse),
        (ExistingFiles::Refuse, ExistingFiles::Refuse),
        (ExistingFiles::Overwrite, ExistingFiles::Overwrite),
    ] {
        assert_eq!(staged_options(&options(given)).existing_files, staged);
    }
}

#[test]
fn atomic_into_a_symlink_to_an_empty_directory_fills_the_target() {
    let fx = Fixture::new();
    let real = fx.parent.join("real");
    std::fs::create_dir(&real).unwrap();
    let link = fx.parent.join("link");
    symlink(&real, &link).unwrap();

    fx.extract(&link, Staging::Atomic, &mut Hooks::default())
        .unwrap();

    assert_eq!(read(&real.join("a.txt")), "new a");
    assert!(link.symlink_metadata().unwrap().is_symlink());
    assert!(fx.leftovers().is_empty());
}

#[test]
fn atomic_into_a_non_empty_directory_is_refused_before_extracting() {
    let fx = Fixture::new();
    let dest = fx.with_old_destination();
    let mut hooks = Hooks::default();

    let error = fx.extract(&dest, Staging::Atomic, &mut hooks).unwrap_err();

    assert_matches!(error, ArchiveError::OutputExists { .. });
    assert_eq!(hooks.started, 0, "nothing was extracted");
    assert_eq!(read(&dest.join("old.txt")), "old");
    assert!(fx.leftovers().is_empty());
}

#[test]
fn atomic_into_a_file_is_refused() {
    let fx = Fixture::new();
    let dest = fx.dest();
    std::fs::write(&dest, b"a file").unwrap();

    let error = fx
        .extract(&dest, Staging::Atomic, &mut Hooks::default())
        .unwrap_err();

    assert_matches!(
        error,
        ArchiveError::InvalidConfiguration {
            setting: ConfigSetting::OutputPath,
            problem: ConfigProblem::NotADirectory
        }
    );
    assert_eq!(read(&dest), "a file");
}

#[test]
fn atomic_into_a_dangling_symlink_is_refused() {
    let fx = Fixture::new();
    let dest = fx.dest();
    symlink(fx.parent.join("nowhere"), &dest).unwrap();

    let error = fx
        .extract(&dest, Staging::Atomic, &mut Hooks::default())
        .unwrap_err();

    assert_matches!(
        error,
        ArchiveError::InvalidConfiguration {
            problem: ConfigProblem::IsSymlink,
            ..
        }
    );
}

#[test]
fn atomic_cancelled_after_the_last_entry_publishes_nothing() {
    let fx = Fixture::new();
    let dest = fx.dest();
    let mut hooks = Hooks {
        cancel_at_end: true,
        ..Hooks::default()
    };

    let error = fx.extract(&dest, Staging::Atomic, &mut hooks).unwrap_err();

    assert!(error.is_cancelled(), "{error}");
    assert!(!dest.exists());
    assert!(fx.leftovers().is_empty());
}

fn plant_in_staging(parent: &Path, name: &'static str) -> Action {
    let parent = parent.to_path_buf();
    Box::new(move || {
        for staging in staging_dirs(&parent) {
            std::fs::write(staging.join(name), b"planted").unwrap();
        }
    })
}

#[test]
fn atomic_refuses_a_file_planted_in_the_staging_directory() {
    let fx = Fixture::new();
    let dest = fx.dest();
    std::fs::write(
        &fx.archive,
        create_test_tar(vec![("first.txt", b"1"), ("second.txt", b"2")]),
    )
    .unwrap();
    let mut hooks = Hooks {
        on_first_entry: Some(plant_in_staging(&fx.parent, "second.txt")),
        ..Hooks::default()
    };

    let error = fx.extract(&dest, Staging::Atomic, &mut hooks).unwrap_err();

    assert_matches!(cause(&error), ArchiveError::DestinationOccupied { .. });
    assert!(!dest.exists(), "nothing was published");
    assert!(fx.leftovers().is_empty());
}

#[test]
fn atomic_still_skips_an_in_archive_duplicate() {
    let fx = Fixture::new();
    let dest = fx.dest();
    std::fs::write(
        &fx.archive,
        create_test_tar(vec![("f", b"first"), ("f", b"second")]),
    )
    .unwrap();

    let report = fx
        .extract(&dest, Staging::Atomic, &mut Hooks::default())
        .unwrap();

    assert_eq!(report.files_skipped(), 1);
    assert_eq!(read(&dest.join("f")), "first");
}

#[test]
fn replace_swaps_the_new_tree_over_the_old_destination() {
    let fx = Fixture::new();
    let dest = fx.with_old_destination();

    let report = fx
        .extract(&dest, Staging::AtomicReplace, &mut Hooks::default())
        .unwrap();

    assert_eq!(read(&dest.join("a.txt")), "new a");
    assert_eq!(read(&dest.join("sub/b.txt")), "new b");
    assert!(!dest.join("old.txt").exists());
    assert!(!dest.join("old_dir").exists());
    assert!(report.warnings.is_empty());
    assert!(fx.leftovers().is_empty(), "{:?}", fx.leftovers());
}

#[test]
fn replace_of_an_absent_destination_behaves_as_atomic() {
    let fx = Fixture::new();
    let dest = fx.dest();

    fx.extract(&dest, Staging::AtomicReplace, &mut Hooks::default())
        .unwrap();

    assert_eq!(read(&dest.join("a.txt")), "new a");
    assert!(fx.leftovers().is_empty());
}

#[test]
fn replace_refuses_a_symlink_destination_and_keeps_its_target() {
    let fx = Fixture::new();
    let real = fx.parent.join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::write(real.join("keep.txt"), b"keep").unwrap();
    let link = fx.dest();
    symlink(&real, &link).unwrap();

    let error = fx
        .extract(&link, Staging::AtomicReplace, &mut Hooks::default())
        .unwrap_err();

    assert_matches!(
        error,
        ArchiveError::InvalidConfiguration {
            setting: ConfigSetting::OutputPath,
            problem: ConfigProblem::IsSymlink
        }
    );
    assert_eq!(read(&real.join("keep.txt")), "keep");
    assert!(link.symlink_metadata().unwrap().is_symlink());
}

#[test]
fn replace_refuses_a_file_destination() {
    let fx = Fixture::new();
    let dest = fx.dest();
    std::fs::write(&dest, b"a file").unwrap();

    let error = fx
        .extract(&dest, Staging::AtomicReplace, &mut Hooks::default())
        .unwrap_err();

    assert_matches!(
        error,
        ArchiveError::InvalidConfiguration {
            problem: ConfigProblem::NotADirectory,
            ..
        }
    );
    assert_eq!(read(&dest), "a file");
}

fn assert_protected(error: &ArchiveError, expected: ProtectedPath) {
    assert_matches!(
        error,
        ArchiveError::InvalidConfiguration {
            setting: ConfigSetting::OutputPath,
            problem: ConfigProblem::ReplacesProtectedPath { path }
        } if *path == expected
    );
}

#[test]
fn replace_refuses_a_filesystem_root() {
    let fx = Fixture::new();

    let error = fx
        .extract(
            Path::new("/"),
            Staging::AtomicReplace,
            &mut Hooks::default(),
        )
        .unwrap_err();

    assert_protected(&error, ProtectedPath::FilesystemRoot);
}

#[test]
fn replace_refuses_a_destination_that_contains_the_archive() {
    let fx = Fixture::new();
    let dest = fx.with_old_destination();
    let archive = dest.join("a.tar");
    std::fs::copy(&fx.archive, &archive).unwrap();

    let error = extract(
        &archive,
        &dest,
        Staging::AtomicReplace,
        &mut Hooks::default(),
    )
    .unwrap_err();

    assert_protected(&error, ProtectedPath::ArchiveAncestor);
    assert!(archive.exists());
    assert_eq!(read(&dest.join("old.txt")), "old");
    assert!(fx.leftovers().is_empty());
}

#[test]
fn a_destination_that_holds_the_working_directory_is_protected() {
    let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
    let parent = cwd.parent().unwrap();
    let id = |path: &Path| identity_of(path).unwrap();

    assert_eq!(
        protected_path(&cwd, id(&cwd), None),
        Some(ProtectedPath::WorkingDirectory)
    );
    assert_eq!(
        protected_path(parent, id(parent), None),
        Some(ProtectedPath::WorkingDirectory)
    );
    assert_eq!(
        protected_path(Path::new("/"), id(Path::new("/")), None),
        Some(ProtectedPath::FilesystemRoot)
    );
    let unrelated = tempfile::tempdir().unwrap();
    let unrelated = unrelated.path().canonicalize().unwrap();
    assert_eq!(protected_path(&unrelated, id(&unrelated), None), None);
}

#[test]
fn the_guard_compares_identity_so_another_spelling_of_the_destination_is_caught() {
    let fx = Fixture::new();
    let dest = fx.with_old_destination();
    let alias = fx.parent.join("alias");
    symlink(&fx.parent, &alias).unwrap();
    let archive = alias.join("dest/a.tar");
    std::fs::copy(&fx.archive, &archive).unwrap();
    let dest_id = identity_of(&dest).unwrap();

    assert!(
        !archive.starts_with(&dest),
        "the text of the archive path does not contain the destination's"
    );
    assert!(is_within(&dest, dest_id, &archive, identity_of));
    assert!(!is_within(
        &fx.parent.join("elsewhere"),
        identity_of(&fx.parent).unwrap(),
        &fx.root.path().join("a.tar"),
        identity_of
    ));
}

#[test]
fn the_guard_follows_an_injected_identity_source_not_the_path_text() {
    let known = |ino| Ok(FileIdentity::Known(IdentityKey { dev: 1, ino }));
    let dest = Path::new("/p/dest");
    let dest_id = FileIdentity::Known(IdentityKey { dev: 1, ino: 7 });
    // A case-insensitive volume: `/p/DEST` and `/p/dest` are one directory.
    let case_insensitive = |path: &Path| match path.to_str().unwrap().to_lowercase().as_str() {
        "/p/dest" => known(7),
        "/p" => known(2),
        "/" => known(1),
        _ => known(9),
    };

    assert!(is_within(
        dest,
        dest_id,
        Path::new("/p/DEST/a/b.tar"),
        case_insensitive
    ));
    assert!(is_within(
        dest,
        dest_id,
        Path::new("/p/Dest"),
        case_insensitive
    ));
    assert!(!is_within(
        dest,
        dest_id,
        Path::new("/p/other/b.tar"),
        case_insensitive
    ));
    assert!(
        is_within(dest, dest_id, Path::new("/p/other/b.tar"), |_| Err(
            std::io::Error::from(std::io::ErrorKind::PermissionDenied)
        )),
        "an ancestor that cannot be identified refuses"
    );
}

#[test]
fn an_unknown_identity_compares_the_canonical_destination_and_fails_closed() {
    let fx = Fixture::new();
    let dest = fx.with_old_destination();
    let sibling = fx.parent.join("destx");
    std::fs::create_dir(&sibling).unwrap();
    let alias = fx.parent.join("alias");
    symlink(&dest, &alias).unwrap();
    let unknown = |_: &Path| Ok(FileIdentity::Unknown);
    let inner = dest.join("a.tar");

    assert!(
        is_within(&alias, FileIdentity::Unknown, &inner, unknown),
        "another spelling of the destination is the destination"
    );
    assert!(!is_within(&sibling, FileIdentity::Unknown, &inner, unknown));
    assert!(
        is_within(
            &fx.parent.join("missing"),
            FileIdentity::Unknown,
            &inner,
            unknown
        ),
        "a destination that cannot be canonicalized refuses"
    );
}

#[test]
fn a_failed_extraction_leaves_the_original_destination() {
    let fx = Fixture::new();
    let dest = fx.with_old_destination();

    let error = extract(
        &fx.root.path().join("missing.tar"),
        &dest,
        Staging::AtomicReplace,
        &mut Hooks::default(),
    )
    .unwrap_err();

    assert!(!matches!(error, ArchiveError::ReplaceFailed(_)), "{error}");
    assert_eq!(read(&dest.join("old.txt")), "old");
    assert!(fx.leftovers().is_empty());
}

#[test]
fn a_cancelled_replace_publishes_nothing() {
    let fx = Fixture::new();
    let dest = fx.with_old_destination();
    let mut hooks = Hooks {
        cancel_at_end: true,
        ..Hooks::default()
    };

    let error = fx
        .extract(&dest, Staging::AtomicReplace, &mut hooks)
        .unwrap_err();

    assert!(error.is_cancelled(), "{error}");
    assert_eq!(read(&dest.join("old.txt")), "old");
    assert!(!dest.join("a.txt").exists());
    assert!(fx.leftovers().is_empty());
}

#[test]
fn a_destination_swapped_during_extraction_is_not_replaced() {
    let fx = Fixture::new();
    let dest = fx.with_old_destination();
    let aside = fx.parent.join("aside");
    let (swap_dest, swap_aside) = (dest.clone(), aside.clone());
    let mut hooks = Hooks {
        at_end: Some(Box::new(move || {
            std::fs::rename(&swap_dest, &swap_aside).unwrap();
            std::fs::create_dir(&swap_dest).unwrap();
        })),
        ..Hooks::default()
    };

    let error = fx
        .extract(&dest, Staging::AtomicReplace, &mut hooks)
        .unwrap_err();

    assert_matches!(
        error,
        ArchiveError::SecurityViolation {
            kind: Violation::DestinationChanged
        }
    );
    assert_eq!(read(&aside.join("old.txt")), "old");
    assert!(std::fs::read_dir(&dest).unwrap().next().is_none());
    assert!(fx.leftovers().is_empty(), "{:?}", fx.leftovers());
}

#[test]
fn a_failed_swap_restores_the_original_destination() {
    let fx = Fixture::new();
    let dest = fx.with_old_destination();
    let parent = fx.parent.clone();
    let mut hooks = Hooks {
        at_end: Some(Box::new(move || {
            for staging in staging_dirs(&parent) {
                std::fs::remove_dir_all(staging).unwrap();
            }
        })),
        ..Hooks::default()
    };

    let error = fx
        .extract(&dest, Staging::AtomicReplace, &mut hooks)
        .unwrap_err();

    match error {
        ArchiveError::ReplaceFailed(failure) => {
            assert_matches!(failure.restore, Restore::Restored);
            assert!(failure.leftover.is_none());
        }
        other => panic!("expected ReplaceFailed, got {other}"),
    }
    assert_eq!(read(&dest.join("old.txt")), "old");
    assert_eq!(read(&dest.join("old_dir/inner.txt")), "old inner");
    assert!(fx.leftovers().is_empty(), "{:?}", fx.leftovers());
}

#[test]
fn a_backup_that_cannot_be_removed_is_reported_as_a_warning() {
    let fx = Fixture::new();
    let dest = fx.with_old_destination();
    let locked = dest.join("old_dir");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read_dir(&locked).is_ok() {
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        eprintln!("skipping: directory permissions are not enforced (running as root?)");
        return;
    }

    let report = fx
        .extract(&dest, Staging::AtomicReplace, &mut Hooks::default())
        .unwrap();

    assert_eq!(read(&dest.join("a.txt")), "new a");
    assert!(!dest.join("old.txt").exists());
    let [ExtractionWarning::BackupCleanupFailed { path, identity, .. }] =
        report.warnings.as_slice()
    else {
        panic!("expected one cleanup warning, got {:?}", report.warnings);
    };
    assert_eq!(*identity, BackupIdentity::Verified);
    std::fs::set_permissions(path.join("old_dir"), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn a_read_only_destination_is_replaced_and_its_backup_removed() {
    let fx = Fixture::new();
    let dest = fx.with_old_destination();
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o555)).unwrap();

    let result = fx.extract(&dest, Staging::AtomicReplace, &mut Hooks::default());
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755)).unwrap();
    let report = result.unwrap();

    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    assert_eq!(read(&dest.join("a.txt")), "new a");
    assert!(fx.leftovers().is_empty(), "{:?}", fx.leftovers());
}

/// Races an attacker that flips the destination between a real directory and a
/// symlink to a victim directory against `AtomicReplace`. Whatever the outcome
/// of a run, the victim must keep exactly what it had: nothing is ever written
/// through, renamed over, or removed behind the planted link.
#[test]
fn a_racing_destination_flip_never_touches_a_planted_symlinks_target() {
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;

    for _ in 0..60 {
        let fx = Fixture::new();
        let dest = fx.with_old_destination();
        let victim = fx.parent.join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::fs::write(victim.join("sentinel"), b"victim").unwrap();
        let aside = fx.parent.join("aside");
        let stop = std::sync::Arc::new(AtomicBool::new(false));

        let attacker = {
            let (stop, dest, victim, aside) =
                (stop.clone(), dest.clone(), victim.clone(), aside.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    if std::fs::rename(&dest, &aside).is_ok() {
                        let _ = symlink(&victim, &dest);
                        let _ = std::fs::remove_file(&dest);
                        let _ = std::fs::rename(&aside, &dest);
                    }
                }
            })
        };
        let outcome = fx.extract(&dest, Staging::AtomicReplace, &mut Hooks::default());
        stop.store(true, Ordering::Relaxed);
        attacker.join().unwrap();

        if let Err(error) = &outcome {
            assert_matches!(
                error,
                ArchiveError::SecurityViolation { .. }
                    | ArchiveError::ReplaceFailed(_)
                    | ArchiveError::InvalidConfiguration { .. }
                    | ArchiveError::OutputExists { .. }
                    | ArchiveError::Io(_),
                "{error}"
            );
        }
        let names: Vec<_> = std::fs::read_dir(&victim)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, [OsString::from("sentinel")]);
        assert_eq!(read(&victim.join("sentinel")), "victim");
    }
}

fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o7777
}

fn private_destination(fx: &Fixture) -> PathBuf {
    let dest = fx.with_old_destination();
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o700)).unwrap();
    dest
}

#[test]
fn replace_keeps_a_private_destination_private() {
    let fx = Fixture::new();
    let dest = private_destination(&fx);

    fx.extract(&dest, Staging::AtomicReplace, &mut Hooks::default())
        .unwrap();

    assert_eq!(mode_of(&dest), 0o700);
    assert_eq!(read(&dest.join("a.txt")), "new a");
}

#[test]
fn replace_gives_the_published_root_the_destination_mode() {
    let fx = Fixture::new();
    let dest = fx.with_old_destination();
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o750)).unwrap();

    fx.extract(&dest, Staging::AtomicReplace, &mut Hooks::default())
        .unwrap();

    assert_eq!(mode_of(&dest), 0o750);
}

#[test]
fn atomic_onto_an_empty_private_directory_keeps_it_private() {
    let fx = Fixture::new();
    let dest = fx.dest();
    std::fs::create_dir(&dest).unwrap();
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o700)).unwrap();

    fx.extract(&dest, Staging::Atomic, &mut Hooks::default())
        .unwrap();

    assert_eq!(mode_of(&dest), 0o700);
    assert_eq!(read(&dest.join("a.txt")), "new a");
}

#[test]
fn atomic_into_an_absent_destination_gets_the_umask_mode() {
    let fx = Fixture::new();
    let expected = fx.parent.join("expected");
    std::fs::create_dir(&expected).unwrap();
    let dest = fx.dest();

    fx.extract(&dest, Staging::Atomic, &mut Hooks::default())
        .unwrap();

    assert_eq!(mode_of(&dest), mode_of(&expected));
}

#[test]
fn the_staging_directory_is_private_while_the_archive_extracts() {
    use std::sync::Arc;
    use std::sync::Mutex;

    for staging in [Staging::Atomic, Staging::AtomicReplace] {
        let fx = Fixture::new();
        let dest = if staging == Staging::Atomic {
            fx.dest()
        } else {
            fx.with_old_destination()
        };
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (parent, record) = (fx.parent.clone(), seen.clone());
        let mut hooks = Hooks {
            on_first_entry: Some(Box::new(move || {
                for dir in staging_dirs(&parent) {
                    record.lock().unwrap().push(mode_of(&dir));
                }
            })),
            ..Hooks::default()
        };

        fx.extract(&dest, staging, &mut hooks).unwrap();

        assert_eq!(*seen.lock().unwrap(), [0o700], "{staging:?}");
    }
}

#[test]
fn an_extraction_error_removes_the_staging_directory_on_every_path() {
    let fx = Fixture::new();
    let dest = fx.with_old_destination();
    let mut hooks = Hooks {
        cancel_at_end: true,
        ..Hooks::default()
    };

    for staging in [Staging::Atomic, Staging::AtomicReplace] {
        let target = if staging == Staging::Atomic {
            fx.parent.join("fresh")
        } else {
            dest.clone()
        };
        let error = fx.extract(&target, staging, &mut hooks).unwrap_err();
        assert!(error.is_cancelled(), "{error}");
        assert!(fx.leftovers().is_empty(), "{:?}", fx.leftovers());
    }
}

/// Plants a directory the staging removal cannot enter, so removal fails.
fn lock_inside_staging(parent: &Path) -> Action {
    let parent = parent.to_path_buf();
    Box::new(move || {
        for staging in staging_dirs(&parent) {
            let locked = staging.join("locked");
            std::fs::create_dir(&locked).unwrap();
            std::fs::write(locked.join("f"), b"x").unwrap();
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
    })
}

fn removal_is_enforced(parent: &Path) -> bool {
    let probe = parent.join("probe_locked");
    std::fs::create_dir(&probe).unwrap();
    std::fs::write(probe.join("f"), b"x").unwrap();
    std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o000)).unwrap();
    let enforced = std::fs::read_dir(&probe).is_err();
    std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::remove_dir_all(&probe).unwrap();
    enforced
}

fn unlock_and_remove(leftover: &Path) {
    std::fs::set_permissions(
        leftover.join("locked"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    std::fs::remove_dir_all(leftover).unwrap();
}

#[test]
fn a_staging_directory_that_survives_its_removal_is_named_by_the_error() {
    for staging in [Staging::Atomic, Staging::AtomicReplace] {
        let fx = Fixture::new();
        if !removal_is_enforced(&fx.parent) {
            eprintln!("skipping: directory permissions are not enforced (running as root?)");
            return;
        }
        let target = if staging == Staging::Atomic {
            fx.dest()
        } else {
            fx.with_old_destination()
        };
        let mut hooks = Hooks {
            cancel_at_end: true,
            at_end: Some(lock_inside_staging(&fx.parent)),
            ..Hooks::default()
        };

        let error = fx.extract(&target, staging, &mut hooks).unwrap_err();

        let ArchiveError::PartialExtraction(partial) = &error else {
            panic!("expected a partial extraction, got {error}");
        };
        assert_eq!(partial.writes(), crate::PartialWrites::RolledBack);
        let leftover = partial.leftover().expect("the leftover is named");
        assert_eq!(fx.leftovers().len(), 1);
        assert!(leftover.path.starts_with(&fx.parent), "{leftover:?}");
        assert!(leftover.path.join("locked").exists());
        unlock_and_remove(&leftover.path);
    }
}

mod adoption {
    use std::os::unix::fs::MetadataExt;

    use super::super::adopt::Adoption;
    use super::super::adopt::Claim;
    use super::super::dir::StagingDir;
    use super::*;
    use crate::formats::pinned_dir::VettedDir;

    fn staging_in(parent: &Path) -> (VettedDir, PathBuf) {
        let parent = parent.canonicalize().unwrap();
        (VettedDir::open_path(&parent).unwrap(), parent)
    }

    #[test]
    fn an_adopted_mode_is_applied_through_the_descriptor() {
        let temp = TempDir::new().unwrap();
        let (pin, parent) = staging_in(temp.path());
        let mut staging = StagingDir::create(&pin, &parent).unwrap();
        let own = std::fs::metadata(&parent).unwrap();

        staging
            .adopt(Adoption::for_test(
                0o2750,
                own.uid(),
                own.gid(),
                Claim::Full,
            ))
            .unwrap();

        assert_eq!(mode_of(staging.path()) & 0o777, 0o750);
    }

    #[test]
    fn a_group_the_directory_cannot_join_loses_its_group_access() {
        let temp = TempDir::new().unwrap();
        let (pin, parent) = staging_in(temp.path());
        let mut staging = StagingDir::create(&pin, &parent).unwrap();
        let own = std::fs::metadata(&parent).unwrap();
        let foreign = std::fs::metadata("/").unwrap().gid();
        if foreign == own.gid() || own.uid() == 0 {
            eprintln!("skipping: no group this caller is outside of");
            return;
        }

        staging
            .adopt(Adoption::for_test(0o2775, own.uid(), foreign, Claim::Full))
            .unwrap();

        assert_eq!(mode_of(staging.path()), 0o705);
    }

    #[test]
    fn a_cautious_adoption_never_takes_a_foreign_uid_nor_its_write_bits() {
        let temp = TempDir::new().unwrap();
        let (pin, parent) = staging_in(temp.path());
        let mut staging = StagingDir::create(&pin, &parent).unwrap();
        let own = std::fs::metadata(&parent).unwrap();
        let foreign_uid = own.uid().wrapping_add(1);

        staging
            .adopt(Adoption::for_test(
                0o2777,
                foreign_uid,
                own.gid(),
                Claim::Cautious,
            ))
            .unwrap();

        let applied = std::fs::metadata(staging.path()).unwrap();
        assert_eq!(applied.uid(), own.uid());
        assert_eq!(applied.mode() & 0o7777, 0o755);
    }

    #[test]
    fn a_cautious_adoption_of_an_own_destination_keeps_its_mode() {
        let temp = TempDir::new().unwrap();
        let (pin, parent) = staging_in(temp.path());
        let mut staging = StagingDir::create(&pin, &parent).unwrap();
        let own = std::fs::metadata(&parent).unwrap();

        staging
            .adopt(Adoption::for_test(
                0o775,
                own.uid(),
                own.gid(),
                Claim::Cautious,
            ))
            .unwrap();

        assert_eq!(mode_of(staging.path()) & 0o777, 0o775);
    }

    #[test]
    fn a_read_only_adopted_directory_can_still_be_discarded() {
        let temp = TempDir::new().unwrap();
        let (pin, parent) = staging_in(temp.path());
        let mut staging = StagingDir::create(&pin, &parent).unwrap();
        let own = std::fs::metadata(&parent).unwrap();
        std::fs::write(staging.path().join("f"), b"x").unwrap();

        staging
            .adopt(Adoption::for_test(0o000, own.uid(), own.gid(), Claim::Full))
            .unwrap();
        let path = staging.path().to_path_buf();

        assert!(staging.discard().is_none());
        assert!(!path.exists());
    }

    #[test]
    fn dropping_a_staging_directory_removes_it() {
        let temp = TempDir::new().unwrap();
        let (pin, parent) = staging_in(temp.path());
        let staging = StagingDir::create(&pin, &parent).unwrap();
        let path = staging.path().to_path_buf();
        assert_eq!(mode_of(&path), 0o700);

        drop(staging);

        assert!(!path.exists());
    }
}

#[test]
fn a_bare_destination_name_has_the_working_directory_as_its_parent() {
    assert_eq!(super::parent_or_cwd(Path::new("out")), Path::new("."));
    assert_eq!(super::parent_or_cwd(Path::new("a/out")), Path::new("a"));
    assert_eq!(super::parent_or_cwd(Path::new("/out")), Path::new("/"));
}
