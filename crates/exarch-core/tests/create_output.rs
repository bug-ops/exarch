//! Creation publishes its output only when the archive is complete: a failed
//! creation leaves the output path as it was, `CreateNew` never replaces and
//! `Replace` swaps the previous archive atomically.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

use std::assert_matches;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::ConfigProblem;
use exarch_core::ConfigSetting;
use exarch_core::CreateRequest;
use exarch_core::CreationConfig;
use exarch_core::OutputFile;
use exarch_core::SecurityConfig;
use exarch_core::create_archive;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use tempfile::TempDir;

const OUTPUTS: [&str; 2] = ["out.tar.gz", "out.zip"];

fn source() -> TempDir {
    let src = TempDir::new().unwrap();
    fs::write(src.path().join("a.txt"), b"alpha").unwrap();
    src
}

fn entries(archive: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = list_archive(archive, &SecurityConfig::default())
        .unwrap()
        .entries()
        .iter()
        .map(|e| e.path.clone())
        .collect();
    paths.sort();
    paths
}

fn dir_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn create(
    output: &OutputFile,
    sources: &[&Path],
) -> exarch_core::Result<exarch_core::CreationReport> {
    CreateRequest::new(&CreationConfig::default()).create(output, sources)
}

#[test]
fn a_failed_create_leaves_no_output_and_no_temporary_file() {
    for name in OUTPUTS {
        let dir = TempDir::new().unwrap();
        let output = dir.path().join(name);

        let err = create_archive(
            &output,
            &[dir.path().join("does-not-exist")],
            &CreationConfig::default(),
        )
        .unwrap_err();

        assert_matches!(err, ArchiveError::SourceNotFound { .. });
        assert!(dir_names(dir.path()).is_empty(), "{name}");
    }
}

#[test]
fn a_failed_replace_keeps_the_previous_archive() {
    for name in OUTPUTS {
        let src = source();
        let dir = TempDir::new().unwrap();
        let output = dir.path().join(name);
        create_archive(&output, &[src.path()], &CreationConfig::default()).unwrap();
        let before = fs::read(&output).unwrap();

        let err = create(
            &OutputFile::replace(&output),
            &[&dir.path().join("does-not-exist")],
        )
        .unwrap_err();

        assert_matches!(err, ArchiveError::SourceNotFound { .. });
        assert_eq!(fs::read(&output).unwrap(), before, "{name}");
        assert_eq!(dir_names(dir.path()), [name], "{name}");
    }
}

#[test]
fn create_new_refuses_an_existing_output_and_leaves_it_alone() {
    let src = source();
    let dir = TempDir::new().unwrap();
    let output = dir.path().join("out.tar.gz");
    fs::write(&output, b"precious").unwrap();

    let err = create(&OutputFile::create_new(&output), &[src.path()]).unwrap_err();

    assert_matches!(err, ArchiveError::OutputExists { .. });
    assert_eq!(fs::read(&output).unwrap(), b"precious");
    assert_eq!(dir_names(dir.path()), ["out.tar.gz"]);
}

#[test]
fn replace_swaps_in_a_complete_archive() {
    for name in OUTPUTS {
        let first = source();
        let second = TempDir::new().unwrap();
        fs::write(second.path().join("b.txt"), b"bravo").unwrap();
        let dir = TempDir::new().unwrap();
        let output = dir.path().join(name);
        create(
            &OutputFile::create_new(&output),
            &[&first.path().join("a.txt")],
        )
        .unwrap();
        assert_eq!(entries(&output), [PathBuf::from("a.txt")]);

        create(
            &OutputFile::replace(&output),
            &[&second.path().join("b.txt")],
        )
        .unwrap();

        assert_eq!(entries(&output), [PathBuf::from("b.txt")], "{name}");
        assert_eq!(
            verify_archive(&output, &SecurityConfig::default())
                .unwrap()
                .status(),
            exarch_core::VerificationStatus::Pass
        );
        assert_eq!(dir_names(dir.path()), [name], "{name}");
    }
}

/// Runs `work` on a thread and fails instead of hanging if it never returns,
/// which is what an archive that includes its own growing output does.
fn within_timeout(work: impl FnOnce() + Send + 'static) {
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        work();
        let _ = done.send(());
    });
    assert!(
        finished
            .recv_timeout(std::time::Duration::from_secs(60))
            .is_ok(),
        "creation did not finish: the archive includes its own output"
    );
}

#[test]
fn the_output_is_never_archived_even_inside_a_source_directory() {
    within_timeout(never_archived_inside_a_source_directory);
}

fn never_archived_inside_a_source_directory() {
    for name in OUTPUTS {
        let src = source();
        let output = src.path().join(name);
        let config = CreationConfig::default().with_include_hidden(true);
        let request = || CreateRequest::new(&config);

        request()
            .create(&OutputFile::create_new(&output), &[src.path()])
            .unwrap();
        assert_eq!(entries(&output), [PathBuf::from("a.txt")], "{name}");

        request()
            .create(&OutputFile::replace(&output), &[src.path()])
            .unwrap();
        assert_eq!(entries(&output), [PathBuf::from("a.txt")], "{name}");
    }
}

#[test]
fn the_staged_file_is_neither_archived_nor_counted_as_a_skipped_hidden_entry() {
    for name in OUTPUTS {
        let src = source();
        let output = src.path().join(name);

        let report = create(&OutputFile::create_new(&output), &[src.path()]).unwrap();
        assert_eq!(report.files_skipped(), 0, "{name}: {:?}", report.skipped);

        let report = create(&OutputFile::replace(&output), &[src.path()]).unwrap();
        assert_eq!(report.files_skipped(), 0, "{name}: {:?}", report.skipped);
        assert_eq!(entries(&output), [PathBuf::from("a.txt")], "{name}");
    }
}

#[derive(Default)]
struct CancelAfterFirstEntry {
    started: usize,
}

impl exarch_core::ProgressCallback for CancelAfterFirstEntry {
    fn on_entry_start(&mut self, _: &Path, _: exarch_core::EntryPosition) {
        self.started += 1;
    }

    fn on_bytes_written(&mut self, _: u64) {}

    fn on_entry_complete(&mut self, _: &Path) {}

    fn on_complete(&mut self) {}

    fn is_cancelled(&mut self) -> bool {
        self.started >= 1
    }
}

#[test]
fn a_cancelling_progress_callback_discards_the_staged_file_and_keeps_the_previous_archive() {
    for name in OUTPUTS {
        let src = TempDir::new().unwrap();
        fs::write(src.path().join("a.txt"), b"alpha").unwrap();
        fs::write(src.path().join("b.txt"), b"bravo").unwrap();
        let dir = TempDir::new().unwrap();
        let output = dir.path().join(name);
        create(
            &OutputFile::create_new(&output),
            &[&src.path().join("a.txt")],
        )
        .unwrap();
        let before = fs::read(&output).unwrap();

        let config = CreationConfig::default();
        let mut progress = CancelAfterFirstEntry::default();
        let err = CreateRequest::new(&config)
            .with_progress(&mut progress)
            .create(&OutputFile::replace(&output), &[src.path()])
            .unwrap_err();

        assert_matches!(err, ArchiveError::Io(e) if e.kind() == std::io::ErrorKind::Interrupted);
        assert_eq!(fs::read(&output).unwrap(), before, "{name}");
        assert_eq!(dir_names(dir.path()), [name], "{name}");
    }
}

#[test]
fn the_output_given_as_a_source_file_is_skipped() {
    let src = source();
    let output = src.path().join("out.tar");
    create(
        &OutputFile::create_new(&output),
        &[&src.path().join("a.txt")],
    )
    .unwrap();

    create(
        &OutputFile::replace(&output),
        &[&src.path().join("a.txt"), &output],
    )
    .unwrap();

    assert_eq!(entries(&output), [PathBuf::from("a.txt")]);
}

#[test]
fn a_directory_output_is_refused_for_both_policies() {
    let src = source();
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("out.tar");
    fs::create_dir(&target).unwrap();

    for output in [
        OutputFile::create_new(&target),
        OutputFile::replace(&target),
    ] {
        let err = create(&output, &[src.path()]).unwrap_err();
        assert_matches!(
            err,
            ArchiveError::InvalidConfiguration {
                setting: ConfigSetting::OutputPath,
                problem: ConfigProblem::NotSupported,
            }
        );
    }
    assert!(target.is_dir());
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;

    use exarch_core::formats::detect::CreatableFormat;

    use super::*;

    #[test]
    fn a_device_output_is_refused_for_both_policies() {
        let src = source();
        for output in [
            OutputFile::create_new("/dev/null").with_format(CreatableFormat::Tar),
            OutputFile::replace("/dev/null").with_format(CreatableFormat::Tar),
        ] {
            let err = create(&output, &[src.path()]).unwrap_err();
            assert_matches!(
                err,
                ArchiveError::InvalidConfiguration {
                    problem: ConfigProblem::NotSupported,
                    ..
                }
            );
        }
    }

    #[test]
    fn replace_over_a_symlink_replaces_the_link_and_spares_its_destination() {
        let src = source();
        let dir = TempDir::new().unwrap();
        let real = dir.path().join("real.bin");
        fs::write(&real, b"unrelated").unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("out.tar");
        symlink(&real, &link).unwrap();

        create(&OutputFile::replace(&link), &[src.path()]).unwrap();

        assert!(!fs::symlink_metadata(&link).unwrap().is_symlink());
        assert_eq!(fs::read(&real).unwrap(), b"unrelated");
        assert_eq!(
            fs::metadata(&link).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(entries(&link), [PathBuf::from("a.txt")]);
    }

    #[test]
    fn create_new_refuses_a_symlink_output() {
        let src = source();
        let dir = TempDir::new().unwrap();
        let link = dir.path().join("out.tar");
        symlink(dir.path().join("missing"), &link).unwrap();

        let err = create(&OutputFile::create_new(&link), &[src.path()]).unwrap_err();

        assert_matches!(err, ArchiveError::OutputExists { .. });
        assert!(fs::symlink_metadata(&link).unwrap().is_symlink());
    }
}
