//! `ListedArchive::check_destination` refuses what the write phase would
//! refuse.
//!
//! The check and the write phase share the destination walk, so a symlink
//! among the parents gives the same typed error from both, and a path that
//! cannot be inspected is an I/O error rather than a security refusal.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

mod sink_support;

use std::assert_matches;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::DecodeReuse;
use exarch_core::DestinationCheck;
use exarch_core::ExistingFiles;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::ListRequest;
use exarch_core::ListedArchive;
use exarch_core::SecurityConfig;
use sink_support::tar_archive;
use sink_support::tar_dir;
use sink_support::tar_file;
use tempfile::TempDir;

fn listed(entries: &[Vec<u8>], config: &SecurityConfig) -> (TempDir, PathBuf, ListedArchive) {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.tar");
    std::fs::write(&archive, tar_archive(entries)).unwrap();
    let listed = ListRequest::new(config)
        .for_extraction(&archive, DecodeReuse::default())
        .unwrap();
    (dir, archive, listed)
}

fn conflicts(error: &ArchiveError) -> Vec<&Path> {
    match error {
        ArchiveError::DestinationOccupied { conflicts, .. } => {
            conflicts.iter().map(|c| c.path.as_path()).collect()
        }
        other => panic!("expected DestinationOccupied, got {other}"),
    }
}

#[test]
fn a_destination_that_does_not_exist_passes() {
    let (dir, _, listed) = listed(&[tar_file("f", b"x")], &SecurityConfig::default());

    for check in [DestinationCheck::Vacant, DestinationCheck::Replaceable] {
        listed
            .check_destination(&dir.path().join("absent"), check)
            .unwrap();
    }
}

#[test]
fn a_vacant_check_names_an_occupied_file_landing() {
    let (_dir, _, listed) = listed(
        &[tar_file("f", b"x"), tar_file("g", b"y")],
        &SecurityConfig::default(),
    );
    let dest = TempDir::new().unwrap();
    std::fs::write(dest.path().join("f"), b"keep").unwrap();

    let error = listed
        .check_destination(dest.path(), DestinationCheck::Vacant)
        .unwrap_err();

    assert_eq!(conflicts(&error), [Path::new("f")]);
    assert_eq!(std::fs::read(dest.path().join("f")).unwrap(), b"keep");
}

#[test]
fn a_duplicate_archive_entry_names_its_occupied_landing_once() {
    let (_dir, _, listed) = listed(
        &[tar_file("f", b"x"), tar_file("f", b"y")],
        &SecurityConfig::default(),
    );
    let dest = TempDir::new().unwrap();
    std::fs::write(dest.path().join("f"), b"keep").unwrap();

    let error = listed
        .check_destination(dest.path(), DestinationCheck::Vacant)
        .unwrap_err();

    assert_eq!(conflicts(&error), [Path::new("f")]);
}

#[test]
fn a_replaceable_check_ignores_occupied_file_landings() {
    let (_dir, _, listed) = listed(&[tar_file("f", b"x")], &SecurityConfig::default());
    let dest = TempDir::new().unwrap();
    std::fs::write(dest.path().join("f"), b"keep").unwrap();

    listed
        .check_destination(dest.path(), DestinationCheck::Replaceable)
        .unwrap();
}

#[test]
fn an_existing_directory_at_a_directory_landing_is_accepted() {
    let (_dir, _, listed) = listed(
        &[tar_dir("d"), tar_file("d/f", b"x")],
        &SecurityConfig::default(),
    );
    let dest = TempDir::new().unwrap();
    std::fs::create_dir(dest.path().join("d")).unwrap();

    listed
        .check_destination(dest.path(), DestinationCheck::Vacant)
        .unwrap();
}

#[test]
fn a_file_at_an_implied_parent_is_named_there_and_not_below_it() {
    let (_dir, _, listed) = listed(&[tar_file("d/f", b"x")], &SecurityConfig::default());
    let dest = TempDir::new().unwrap();
    std::fs::write(dest.path().join("d"), b"a file").unwrap();

    for check in [DestinationCheck::Vacant, DestinationCheck::Replaceable] {
        let error = listed.check_destination(dest.path(), check).unwrap_err();
        assert_eq!(conflicts(&error), [Path::new("d")], "{check:?}");
    }
}

#[test]
fn a_file_destination_is_a_typed_refusal() {
    let (dir, _, listed) = listed(&[tar_file("f", b"x")], &SecurityConfig::default());
    let file = dir.path().join("not_a_dir");
    std::fs::write(&file, b"x").unwrap();

    let error = listed
        .check_destination(&file, DestinationCheck::Vacant)
        .unwrap_err();

    assert_matches!(error, ArchiveError::InvalidConfiguration { .. });
}

#[cfg(unix)]
mod symlinks {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;

    use exarch_core::Violation;

    use super::*;

    #[test]
    fn a_symlink_at_a_file_landing_is_a_typed_refusal_not_a_conflict() {
        let (_dir, _, listed) = listed(&[tar_file("f", b"x")], &SecurityConfig::default());
        let dest = TempDir::new().unwrap();
        symlink("elsewhere", dest.path().join("f")).unwrap();

        let error = listed
            .check_destination(dest.path(), DestinationCheck::Vacant)
            .unwrap_err();

        assert_matches!(
            error,
            ArchiveError::SecurityViolation {
                kind: Violation::ReplacesSymlink { .. },
                ..
            }
        );
    }

    #[test]
    fn a_symlink_parent_leading_outside_is_refused_like_extraction_refuses_it() {
        let config = SecurityConfig::default().with_allow_symlinks(true);
        let (_dir, archive, listed) = listed(&[tar_file("d/f", b"x")], &config);
        let root = TempDir::new().unwrap();
        let dest = root.path().join("dest");
        let outside = root.path().join("outside");
        std::fs::create_dir(&dest).unwrap();
        std::fs::create_dir(&outside).unwrap();
        symlink(&outside, dest.join("d")).unwrap();

        let checked = listed
            .check_destination(&dest, DestinationCheck::Replaceable)
            .unwrap_err();
        let extracted = ExtractRequest::new(&config)
            .with_options(
                ExtractionOptions::default().with_existing_files(ExistingFiles::Overwrite),
            )
            .extract(&archive, &dest)
            .unwrap_err();

        assert_matches!(checked, ArchiveError::SymlinkEscape { .. });
        assert_eq!(
            std::mem::discriminant(&checked),
            std::mem::discriminant(&extracted),
            "check: {checked}, extraction: {extracted}"
        );
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none());
    }

    #[test]
    fn a_symlink_parent_is_refused_when_symlinks_are_not_allowed() {
        let (_dir, _, listed) = listed(&[tar_file("d/f", b"x")], &SecurityConfig::default());
        let dest = TempDir::new().unwrap();
        std::fs::create_dir(dest.path().join("real")).unwrap();
        symlink("real", dest.path().join("d")).unwrap();

        let error = listed
            .check_destination(dest.path(), DestinationCheck::Replaceable)
            .unwrap_err();

        assert_matches!(error, ArchiveError::SecurityViolation { .. });
    }

    #[test]
    fn an_uninspectable_parent_is_an_io_error_not_a_symlink_refusal() {
        let (_dir, _, listed) = listed(&[tar_file("d/f", b"x")], &SecurityConfig::default());
        let dest = TempDir::new().unwrap();
        let locked = dest.path().join("d");
        std::fs::create_dir(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let inspectable = std::fs::read_dir(&locked).is_ok();

        let result = listed.check_destination(dest.path(), DestinationCheck::Vacant);

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        if inspectable {
            eprintln!("skipping: directory permissions are not enforced (running as root?)");
            return;
        }
        assert_matches!(result, Err(ArchiveError::Io(_)), "{result:?}");
    }
}

#[test]
fn a_passing_vacant_check_means_a_refusing_extraction_succeeds() {
    let (_dir, archive, listed) = listed(
        &[tar_dir("d"), tar_file("d/f", b"x"), tar_file("g", b"y")],
        &SecurityConfig::default(),
    );
    let dest = TempDir::new().unwrap();
    std::fs::create_dir(dest.path().join("d")).unwrap();

    listed
        .check_destination(dest.path(), DestinationCheck::Vacant)
        .unwrap();
    let report = ExtractRequest::new(&SecurityConfig::default())
        .with_options(ExtractionOptions::default().with_existing_files(ExistingFiles::Refuse))
        .extract(&archive, dest.path())
        .unwrap();

    assert_eq!(report.files_extracted, 2);
}

#[cfg(unix)]
mod replaceable_matrix {
    use std::os::unix::fs::symlink;

    use exarch_core::Violation;
    use sink_support::tar_hardlink;
    use sink_support::tar_symlink;

    use super::*;

    #[derive(Clone, Copy)]
    enum Arrives {
        File,
        Symlink,
        Hardlink,
    }

    #[derive(Clone, Copy)]
    enum Planted {
        File,
        Dir,
        SameLink,
        OtherLink,
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Verdict {
        Free,
        Conflict,
        ReplacesSymlink,
    }

    fn entries(arrives: Arrives) -> Vec<Vec<u8>> {
        match arrives {
            Arrives::File => vec![tar_file("x", b"new")],
            Arrives::Symlink => vec![tar_symlink("x", "same")],
            Arrives::Hardlink => vec![tar_file("t", b"payload"), tar_hardlink("x", "t")],
        }
    }

    fn plant(dest: &Path, planted: Planted) {
        let x = dest.join("x");
        match planted {
            Planted::File => std::fs::write(x, b"keep").unwrap(),
            Planted::Dir => std::fs::create_dir(x).unwrap(),
            Planted::SameLink => symlink("same", x).unwrap(),
            Planted::OtherLink => symlink("other", x).unwrap(),
        }
    }

    fn verdict(result: &Result<(), ArchiveError>) -> Verdict {
        match result {
            Ok(()) => Verdict::Free,
            Err(ArchiveError::DestinationOccupied { .. }) => Verdict::Conflict,
            Err(ArchiveError::SecurityViolation {
                kind: Violation::ReplacesSymlink { .. },
                ..
            }) => Verdict::ReplacesSymlink,
            Err(other) => panic!("unexpected {other}"),
        }
    }

    /// The up-front verdict, with the in-place `Overwrite` extraction that must
    /// agree: it fails exactly when the verdict is not `Free`.
    fn cell(arrives: Arrives, planted: Planted, expected: Verdict) {
        let config = SecurityConfig::default()
            .with_allow_symlinks(true)
            .with_allow_hardlinks(true);
        let (_dir, archive, listed) = listed(&entries(arrives), &config);
        let dest = TempDir::new().unwrap();
        plant(dest.path(), planted);

        let checked = listed.check_destination(dest.path(), DestinationCheck::Replaceable);
        assert_eq!(verdict(&checked), expected);

        let extracted = ExtractRequest::new(&config)
            .with_options(
                ExtractionOptions::default().with_existing_files(ExistingFiles::Overwrite),
            )
            .extract(&archive, dest.path());
        assert_eq!(
            extracted.is_ok(),
            expected == Verdict::Free,
            "{extracted:?}"
        );
    }

    #[test]
    fn file_over_file_is_replaced() {
        cell(Arrives::File, Planted::File, Verdict::Free);
    }

    #[test]
    fn file_over_symlink_is_refused_as_a_symlink() {
        cell(Arrives::File, Planted::SameLink, Verdict::ReplacesSymlink);
    }

    #[test]
    fn file_over_another_symlink_is_refused_as_a_symlink() {
        cell(Arrives::File, Planted::OtherLink, Verdict::ReplacesSymlink);
    }

    #[test]
    fn hardlink_over_another_symlink_is_refused_as_a_symlink() {
        cell(
            Arrives::Hardlink,
            Planted::OtherLink,
            Verdict::ReplacesSymlink,
        );
    }

    #[test]
    fn file_over_directory_conflicts() {
        cell(Arrives::File, Planted::Dir, Verdict::Conflict);
    }

    #[test]
    fn symlink_over_file_is_replaced() {
        cell(Arrives::Symlink, Planted::File, Verdict::Free);
    }

    #[test]
    fn symlink_over_the_same_symlink_is_skipped() {
        cell(Arrives::Symlink, Planted::SameLink, Verdict::Free);
    }

    #[test]
    fn symlink_over_another_symlink_is_refused_as_a_symlink() {
        cell(
            Arrives::Symlink,
            Planted::OtherLink,
            Verdict::ReplacesSymlink,
        );
    }

    #[test]
    fn symlink_over_directory_conflicts() {
        cell(Arrives::Symlink, Planted::Dir, Verdict::Conflict);
    }

    #[test]
    fn hardlink_over_file_conflicts() {
        cell(Arrives::Hardlink, Planted::File, Verdict::Conflict);
    }

    #[test]
    fn hardlink_over_symlink_is_refused_as_a_symlink() {
        cell(
            Arrives::Hardlink,
            Planted::SameLink,
            Verdict::ReplacesSymlink,
        );
    }

    #[test]
    fn hardlink_over_directory_conflicts() {
        cell(Arrives::Hardlink, Planted::Dir, Verdict::Conflict);
    }
}
