//! Acceptance contract of #1244 (core side): `StagingReservation::reserve`
//! holds the stage and the pinned parent, and
//! `ExtractRequest::extract_reserved` publishes or discards through them with
//! the all-or-nothing outcome of `Staging::Atomic`, whatever `options.staging`
//! says.

#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

use std::assert_matches;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::ProgressCallback;
use exarch_core::STAGING_PREFIX;
use exarch_core::SecurityConfig;
use exarch_core::Staging;
use exarch_core::StagingReservation;
use tempfile::TempDir;

fn write_tar(path: &Path, files: &[(&str, &[u8])], symlink_at: Option<usize>) {
    let mut builder = tar::Builder::new(std::fs::File::create(path).unwrap());
    for (index, (name, data)) in files.iter().enumerate() {
        if symlink_at == Some(index) {
            let mut link = tar::Header::new_gnu();
            link.set_entry_type(tar::EntryType::Symlink);
            link.set_size(0);
            link.set_mode(0o777);
            builder.append_link(&mut link, "link", "a").unwrap();
        }
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        builder.append_data(&mut header, name, *data).unwrap();
    }
    builder.finish().unwrap();
}

struct Fixture {
    work: TempDir,
    archive: PathBuf,
    dest: PathBuf,
}

fn fixture(symlink_at: Option<usize>) -> Fixture {
    let work = TempDir::new().unwrap();
    let archive = work.path().join("a.tar");
    write_tar(
        &archive,
        &[("a", b"one"), ("d/b", b"two"), ("c", b"three")],
        symlink_at,
    );
    let dest = work.path().join("out");
    Fixture {
        work,
        archive,
        dest,
    }
}

fn leftovers(parent: &Path) -> Vec<String> {
    std::fs::read_dir(parent)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(STAGING_PREFIX))
        .collect()
}

fn tree(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn visit(root: &Path, dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(root, &path, out);
            } else {
                out.push((
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    std::fs::read(&path).unwrap(),
                ));
            }
        }
    }
    let mut out = Vec::new();
    visit(root, root, &mut out);
    out.sort();
    out
}

#[test]
fn reserve_of_an_absent_destination_creates_a_staging_sibling_and_no_destination() {
    let fx = fixture(None);

    let reservation = StagingReservation::reserve(&fx.dest).unwrap();

    assert!(!fx.dest.exists());
    assert_eq!(leftovers(fx.work.path()).len(), 1);
    drop(reservation);
}

#[test]
fn reserve_of_an_empty_existing_directory_is_accepted() {
    let fx = fixture(None);
    std::fs::create_dir(&fx.dest).unwrap();

    let reservation = StagingReservation::reserve(&fx.dest).unwrap();

    assert_eq!(leftovers(fx.work.path()).len(), 1);
    drop(reservation);
}

#[test]
fn reserve_of_a_non_empty_directory_is_output_exists() {
    let fx = fixture(None);
    std::fs::create_dir(&fx.dest).unwrap();
    std::fs::write(fx.dest.join("keep"), b"k").unwrap();

    let error = StagingReservation::reserve(&fx.dest).unwrap_err();

    assert_matches!(error, ArchiveError::OutputExists { .. });
    assert!(leftovers(fx.work.path()).is_empty());
}

#[test]
fn dropping_an_unused_reservation_removes_its_stage() {
    let fx = fixture(None);

    drop(StagingReservation::reserve(&fx.dest).unwrap());

    assert!(leftovers(fx.work.path()).is_empty());
    assert!(!fx.dest.exists());
}

#[test]
fn extract_reserved_publishes_the_tree_of_an_atomic_extraction() {
    let fx = fixture(None);
    let twin = fx.work.path().join("twin");
    let config = SecurityConfig::default();
    let expected = ExtractRequest::new(&config)
        .with_options(ExtractionOptions::default().with_staging(Staging::Atomic))
        .extract(&fx.archive, &twin)
        .unwrap();

    let reservation = StagingReservation::reserve(&fx.dest).unwrap();
    let report = ExtractRequest::new(&config)
        .extract_reserved(&fx.archive, reservation)
        .unwrap();

    assert_eq!(report.files_extracted, expected.files_extracted);
    assert_eq!(tree(&fx.dest), tree(&twin));
    assert!(leftovers(fx.work.path()).is_empty());
}

#[test]
fn extract_reserved_failure_leaves_no_destination_and_no_stage() {
    let fx = fixture(Some(1));
    let config = SecurityConfig::default();

    let reservation = StagingReservation::reserve(&fx.dest).unwrap();
    let _error = ExtractRequest::new(&config)
        .extract_reserved(&fx.archive, reservation)
        .unwrap_err();

    assert!(!fx.dest.exists());
    assert!(leftovers(fx.work.path()).is_empty());
}

#[test]
fn extract_reserved_failure_reports_the_error_of_the_atomic_extraction() {
    let fx = fixture(Some(1));
    let config = SecurityConfig::default();
    let atomic = ExtractRequest::new(&config)
        .with_options(ExtractionOptions::default().with_staging(Staging::Atomic))
        .extract(&fx.archive, fx.work.path().join("twin"))
        .unwrap_err();

    let reservation = StagingReservation::reserve(&fx.dest).unwrap();
    let reserved = ExtractRequest::new(&config)
        .extract_reserved(&fx.archive, reservation)
        .unwrap_err();

    assert_eq!(reserved.error_code(), atomic.error_code());
    assert_eq!(reserved.sub_code(), atomic.sub_code());
}

#[test]
fn extract_reserved_ignores_options_staging_and_stays_all_or_nothing() {
    let fx = fixture(Some(1));
    let config = SecurityConfig::default();

    let reservation = StagingReservation::reserve(&fx.dest).unwrap();
    let _ = ExtractRequest::new(&config)
        .with_options(ExtractionOptions::default().with_staging(Staging::InPlace))
        .extract_reserved(&fx.archive, reservation)
        .unwrap_err();

    assert!(!fx.dest.exists());
}

struct CancelAfterFirstEntry {
    started: usize,
}

impl ProgressCallback for CancelAfterFirstEntry {
    fn on_entry_start(&mut self, _path: &Path, _position: exarch_core::EntryPosition) {
        self.started += 1;
    }

    fn on_bytes_written(&mut self, _bytes: u64) {}

    fn on_entry_complete(&mut self, _path: &Path) {}

    fn on_complete(&mut self) {}

    fn is_cancelled(&mut self) -> bool {
        self.started >= 1
    }
}

#[test]
fn extract_reserved_cancel_discards_the_stage_and_keeps_the_destination_absent() {
    let fx = fixture(None);
    let config = SecurityConfig::default();
    let mut progress = CancelAfterFirstEntry { started: 0 };

    let reservation = StagingReservation::reserve(&fx.dest).unwrap();
    let error = ExtractRequest::new(&config)
        .with_progress(&mut progress)
        .extract_reserved(&fx.archive, reservation)
        .unwrap_err();

    assert!(error.is_cancelled(), "{error:?}");
    assert!(!fx.dest.exists());
    assert!(leftovers(fx.work.path()).is_empty());
}

#[cfg(unix)]
#[test]
fn the_reservation_exposes_the_stage_and_the_parent_as_distinct_directories() {
    use std::os::fd::AsFd as _;
    use std::os::unix::fs::MetadataExt as _;

    let fx = fixture(None);
    let reservation = StagingReservation::reserve(&fx.dest).unwrap();

    let stage = rustix::fs::fstat(reservation.staging_fd().as_fd()).unwrap();
    let parent = rustix::fs::fstat(reservation.parent_fd().as_fd()).unwrap();
    let work = std::fs::metadata(fx.work.path()).unwrap();

    assert_eq!(parent.st_ino, work.ino());
    assert_ne!(stage.st_ino, parent.st_ino);
}
