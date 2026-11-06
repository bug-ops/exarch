use std::assert_matches;
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::path::PathBuf;

use tempfile::TempDir;

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

    assert_eq!(
        protected_path(&cwd, None),
        Some(ProtectedPath::WorkingDirectory)
    );
    assert_eq!(
        protected_path(parent, None),
        Some(ProtectedPath::WorkingDirectory)
    );
    assert_eq!(
        protected_path(Path::new("/"), None),
        Some(ProtectedPath::FilesystemRoot)
    );
    let unrelated = tempfile::tempdir().unwrap();
    assert_eq!(
        protected_path(&unrelated.path().canonicalize().unwrap(), None),
        None
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
