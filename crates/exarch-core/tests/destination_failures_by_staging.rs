//! Acceptance contract of #1206: a destination below a file, a too-long
//! destination leaf and a destination without search permission fail as the
//! typed `DestinationNotAccessible` in every staging mode, with the same step
//! and the same I/O kind, naming the destination and not the archive.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

mod sink_support;

use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use exarch_core::ArchiveError;
use exarch_core::DestinationStep;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::SecurityConfig;
use exarch_core::Staging;
use sink_support::tar_archive;
use sink_support::tar_file;
use tempfile::TempDir;

const MODES: [Staging; 3] = [Staging::InPlace, Staging::Atomic, Staging::AtomicReplace];

fn extract(archive: &Path, dest: &Path, staging: Staging) -> ArchiveError {
    ExtractRequest::new(&SecurityConfig::default())
        .with_options(ExtractionOptions::default().with_staging(staging))
        .extract(archive, dest)
        .unwrap_err()
}

fn archive(dir: &TempDir) -> std::path::PathBuf {
    let path = dir.path().join("a.tar");
    std::fs::write(&path, tar_archive(&[tar_file("f", b"x")])).unwrap();
    path
}

fn destination_failure(error: &ArchiveError) -> (DestinationStep, ErrorKind, Option<i32>) {
    match error {
        ArchiveError::DestinationNotAccessible { step, error, .. } => {
            (*step, error.kind(), error.raw_os_error())
        }
        other => panic!("expected DestinationNotAccessible, got {other}"),
    }
}

#[test]
fn extract_destination_below_a_file_is_not_a_directory_at_create_in_every_mode() {
    let work = TempDir::new().unwrap();
    let archive = archive(&work);
    let blocker = work.path().join("afile");
    std::fs::write(&blocker, b"f").unwrap();

    for staging in MODES {
        let error = extract(&archive, &blocker.join("sub"), staging);

        let (step, kind, errno) = destination_failure(&error);
        assert_eq!(step, DestinationStep::Create, "{staging:?}");
        assert_eq!(kind, ErrorKind::NotADirectory, "{staging:?}");
        assert_eq!(errno, Some(20), "{staging:?}");
    }
}

#[test]
fn extract_too_long_destination_leaf_is_typed_with_the_step_of_plain_mode() {
    let work = TempDir::new().unwrap();
    let archive = archive(&work);
    let dest = work.path().join("d").join("n".repeat(300));

    let plain = destination_failure(&extract(&archive, &dest, Staging::InPlace));

    for staging in [Staging::Atomic, Staging::AtomicReplace] {
        let error = extract(&archive, &dest, staging);

        assert!(
            !error.to_string().contains("a.tar"),
            "{staging:?} names the archive: {error}"
        );
        assert_eq!(destination_failure(&error), plain, "{staging:?}");
    }
}

#[test]
fn extract_unsearchable_destination_is_a_write_access_failure_naming_the_destination() {
    let work = TempDir::new().unwrap();
    let archive = archive(&work);
    let dest = work.path().join("ns");
    std::fs::create_dir(&dest).unwrap();
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o600)).unwrap();
    let probe = std::fs::metadata(dest.join("f")).unwrap_err();
    if probe.kind() != ErrorKind::PermissionDenied {
        return;
    }

    let error = extract(&archive, &dest, Staging::InPlace);

    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (step, kind, errno) = destination_failure(&error);
    assert_eq!(step, DestinationStep::WriteAccess);
    assert_eq!(kind, ErrorKind::PermissionDenied);
    assert_eq!(errno, Some(13));
    assert!(error.to_string().contains("ns"), "{error}");
}
