//! Acceptance contract of #1203 (`by` and the refused entry of a symlink
//! parent), #1204 (one error kind per scenario over an existing symlink) and
//! #1216 (`by: archive` for an occupant the run made, under every
//! `ExistingFiles` mode).

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

mod sink_support;

use std::os::unix::fs::symlink;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::DecodeReuse;
use exarch_core::DestinationCheck;
use exarch_core::ErrorCode;
use exarch_core::ExistingFiles;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::ListRequest;
use exarch_core::OccupiedBy;
use exarch_core::PathOccupant;
use exarch_core::SecurityConfig;
use exarch_core::Violation;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use sink_support::tar_archive;
use sink_support::tar_dir;
use sink_support::tar_file;
use sink_support::tar_symlink;
use sink_support::zip_archive;
use sink_support::zip_dir;
use sink_support::zip_file;
use tempfile::TempDir;

const POLICIES: [ExistingFiles; 3] = [
    ExistingFiles::Skip,
    ExistingFiles::Refuse,
    ExistingFiles::Overwrite,
];

fn config() -> SecurityConfig {
    SecurityConfig::default().with_allow_symlinks(true)
}

fn cause(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    }
}

fn extract(
    archive: &Path,
    dest: &Path,
    policy: ExistingFiles,
    config: &SecurityConfig,
) -> Result<(), ArchiveError> {
    ExtractRequest::new(config)
        .with_options(ExtractionOptions::default().with_existing_files(policy))
        .extract(archive, dest)
        .map(drop)
}

fn write(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn sevenz(dir: &TempDir, entries: &[(&str, bool)]) -> PathBuf {
    let path = dir.path().join("a.7z");
    let mut writer = ArchiveWriter::new(std::fs::File::create(&path).unwrap()).unwrap();
    for (name, is_dir) in entries {
        if *is_dir {
            writer
                .push_archive_entry::<&[u8]>(ArchiveEntry::new_directory(name), None)
                .unwrap();
        } else {
            writer
                .push_archive_entry(ArchiveEntry::new_file(name), Some(&b"ok"[..]))
                .unwrap();
        }
    }
    writer.finish().unwrap();
    path
}

#[test]
fn symlink_parent_names_the_entry_and_the_maker_on_the_host() {
    let dir = TempDir::new().unwrap();
    let tar = write(&dir, "a.tar", &tar_archive(&[tar_file("d/e/f", b"x\n")]));
    let zip = write(&dir, "a.zip", &zip_archive(vec![zip_file("d/e/f", b"x\n")]));
    for archive in [tar, zip] {
        let dest = TempDir::new().unwrap();
        std::fs::write(dest.path().join("t"), b"old").unwrap();
        symlink("t", dest.path().join("d")).unwrap();

        let error = extract(&archive, dest.path(), ExistingFiles::Refuse, &config()).unwrap_err();

        match cause(&error) {
            ArchiveError::SecurityViolation {
                kind: Violation::SymlinkParent { entry, parent, by },
                ..
            } => {
                assert_eq!(&**entry, "d/e/f");
                assert_eq!(&**parent, "d");
                assert_eq!(*by, OccupiedBy::Existing);
            }
            other => panic!("expected SymlinkParent, got {other}"),
        }
    }
}

#[test]
fn check_destination_symlink_parent_names_the_refused_entry_not_the_implied_parent() {
    let dir = TempDir::new().unwrap();
    let archive = write(&dir, "a.tar", &tar_archive(&[tar_file("d/e/f", b"x\n")]));
    let listed = ListRequest::new(&config())
        .for_extraction(&archive, DecodeReuse::default())
        .unwrap();
    for check in [DestinationCheck::Vacant, DestinationCheck::Replaceable] {
        let dest = TempDir::new().unwrap();
        std::fs::write(dest.path().join("t"), b"old").unwrap();
        symlink("t", dest.path().join("d")).unwrap();

        let error = listed.check_destination(dest.path(), check).unwrap_err();

        match cause(&error) {
            ArchiveError::SecurityViolation {
                kind: Violation::SymlinkParent { entry, by, .. },
                ..
            } => {
                assert_eq!(&**entry, "d/e/f", "{check:?}");
                assert_eq!(*by, OccupiedBy::Existing, "{check:?}");
            }
            other => panic!("{check:?}: expected SymlinkParent, got {other}"),
        }
    }
}

#[test]
fn symlink_parent_of_the_run_names_the_archive_as_the_maker() {
    let dir = TempDir::new().unwrap();
    let archive = write(
        &dir,
        "a.tar",
        &tar_archive(&[
            tar_file("t", b"x"),
            tar_symlink("l", "t"),
            tar_file("l/x", b"y"),
        ]),
    );
    for policy in POLICIES {
        let dest = TempDir::new().unwrap();

        let error = extract(&archive, dest.path(), policy, &config()).unwrap_err();

        assert!(
            matches!(
                cause(&error),
                ArchiveError::SecurityViolation {
                    kind: Violation::SymlinkParent {
                        by: OccupiedBy::Archive,
                        ..
                    },
                    ..
                }
            ),
            "{policy:?}: {error}"
        );
    }
}

#[test]
fn file_over_an_existing_symlink_is_a_conflict_in_refuse_mode_everywhere() {
    let dir = TempDir::new().unwrap();
    let archive = write(&dir, "f.tar", &tar_archive(&[tar_file("x", b"n\n")]));
    let listed = ListRequest::new(&SecurityConfig::default())
        .for_extraction(&archive, DecodeReuse::default())
        .unwrap();
    let plant = || {
        let dest = TempDir::new().unwrap();
        std::fs::write(dest.path().join("t"), b"old").unwrap();
        symlink("t", dest.path().join("x")).unwrap();
        dest
    };

    let host = plant();
    let host_error = extract(
        &archive,
        host.path(),
        ExistingFiles::Refuse,
        &SecurityConfig::default(),
    )
    .unwrap_err();
    let check = plant();
    let check_error = listed
        .check_destination(check.path(), DestinationCheck::Vacant)
        .unwrap_err();

    for error in [host_error, check_error] {
        assert_eq!(error.error_code(), ErrorCode::OutputExists, "{error}");
        match cause(&error) {
            ArchiveError::DestinationOccupied { conflicts, by, .. } => {
                assert_eq!(*by, OccupiedBy::Existing);
                let seen: Vec<_> = conflicts
                    .iter()
                    .map(|c| (c.path.clone(), c.occupant))
                    .collect();
                assert_eq!(seen, [(PathBuf::from("x"), Some(PathOccupant::Symlink))]);
            }
            other => panic!("expected DestinationOccupied, got {other}"),
        }
    }
}

#[test]
fn file_over_an_existing_symlink_stays_replaces_symlink_when_overwriting() {
    let dir = TempDir::new().unwrap();
    let archive = write(&dir, "f.tar", &tar_archive(&[tar_file("x", b"n\n")]));
    let listed = ListRequest::new(&SecurityConfig::default())
        .for_extraction(&archive, DecodeReuse::default())
        .unwrap();
    let dest = TempDir::new().unwrap();
    std::fs::write(dest.path().join("t"), b"old").unwrap();
    symlink("t", dest.path().join("x")).unwrap();

    let host = extract(
        &archive,
        dest.path(),
        ExistingFiles::Overwrite,
        &SecurityConfig::default(),
    )
    .unwrap_err();
    let check = listed
        .check_destination(dest.path(), DestinationCheck::Replaceable)
        .unwrap_err();

    for error in [host, check] {
        assert!(
            matches!(
                cause(&error),
                ArchiveError::SecurityViolation {
                    kind: Violation::ReplacesSymlink {
                        by: OccupiedBy::Existing,
                        ..
                    },
                    ..
                }
            ),
            "{error}"
        );
    }
}

#[test]
fn directory_over_an_escaping_existing_symlink_is_replaces_symlink_in_every_format() {
    for policy in [ExistingFiles::Refuse, ExistingFiles::Overwrite] {
        let dir = TempDir::new().unwrap();
        let tar = write(
            &dir,
            "d.tar",
            &tar_archive(&[tar_dir("x/"), tar_file("x/a", b"ok")]),
        );
        let tar_bare = write(
            &dir,
            "bare.tar",
            &tar_archive(&[sink_support::tar_entry(
                "x",
                tar::EntryType::Directory,
                b"",
                None,
            )]),
        );
        let zip = write(
            &dir,
            "d.zip",
            &zip_archive(vec![zip_dir("x/"), zip_file("x/a", b"ok")]),
        );
        let seven = sevenz(&dir, &[("x", true), ("x/a", false)]);
        for archive in [tar, tar_bare, zip, seven] {
            let root = TempDir::new().unwrap();
            let dest = root.path().join("out");
            let outside = root.path().join("outside");
            std::fs::create_dir(&dest).unwrap();
            std::fs::create_dir(&outside).unwrap();
            symlink("../outside", dest.join("x")).unwrap();

            let error = extract(&archive, &dest, policy, &SecurityConfig::default()).unwrap_err();

            assert!(
                matches!(
                    cause(&error),
                    ArchiveError::SecurityViolation {
                        kind: Violation::ReplacesSymlink {
                            by: OccupiedBy::Existing,
                            ..
                        },
                        ..
                    }
                ),
                "{policy:?} {}: {error}",
                archive.display()
            );
            assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
        }
    }
}

#[test]
fn directory_over_a_file_of_the_run_names_the_archive_under_every_mode() {
    let dir = TempDir::new().unwrap();
    let archives = [
        write(
            &dir,
            "n.tar",
            &tar_archive(&[tar_file("x", b"1"), tar_file("x/a", b"2")]),
        ),
        write(
            &dir,
            "d.tar",
            &tar_archive(&[tar_file("x", b"1"), tar_dir("x/")]),
        ),
    ];
    for archive in &archives {
        for policy in POLICIES {
            let dest = TempDir::new().unwrap();

            let error =
                extract(archive, dest.path(), policy, &SecurityConfig::default()).unwrap_err();

            match cause(&error) {
                ArchiveError::DestinationOccupied { by, .. } => {
                    assert_eq!(*by, OccupiedBy::Archive, "{policy:?} {}", archive.display());
                }
                other => panic!("{policy:?}: expected DestinationOccupied, got {other}"),
            }
        }
    }
}

#[test]
fn directory_over_a_symlink_of_the_run_names_the_archive_under_every_mode() {
    let dir = TempDir::new().unwrap();
    let archive = write(
        &dir,
        "s.tar",
        &tar_archive(&[tar_file("t", b"1"), tar_symlink("l", "t"), tar_dir("l/")]),
    );
    for policy in POLICIES {
        let dest = TempDir::new().unwrap();

        let error = extract(&archive, dest.path(), policy, &config()).unwrap_err();

        assert!(
            matches!(
                cause(&error),
                ArchiveError::SecurityViolation {
                    kind: Violation::ReplacesSymlink {
                        by: OccupiedBy::Archive,
                        ..
                    },
                    ..
                }
            ),
            "{policy:?}: {error}"
        );
    }
}
