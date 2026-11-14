//! A directory entry over a symlink behaves the same on the host write phase,
//! the in-memory sink, the list model and the destination pre-check, on Linux
//! and macOS alike (#1186): over a link to a file it is refused as an existing
//! symlink, over a link to a directory inside the destination it is accepted.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(clippy::disallowed_methods)]

mod sink_support;

use std::io::Cursor;
use std::os::unix::fs::symlink;
use std::path::Path;

use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::DecodeReuse;
use exarch_core::DestinationCheck;
use exarch_core::DispositionKind;
use exarch_core::ExistingFiles;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::ListRequest;
use exarch_core::OccupiedBy;
use exarch_core::SecurityConfig;
use exarch_core::SinkExtractRequest;
use exarch_core::SinkOptions;
use exarch_core::Violation;
use sink_support::RecordingSink;
use sink_support::tar_archive;
use sink_support::tar_dir;
use sink_support::tar_file;
use sink_support::tar_symlink;
use tempfile::TempDir;

const POLICIES: [ExistingFiles; 3] = [
    ExistingFiles::Skip,
    ExistingFiles::Refuse,
    ExistingFiles::Overwrite,
];

fn config() -> SecurityConfig {
    SecurityConfig::default().with_allow_symlinks(true)
}

fn host(bytes: Vec<u8>, dest: &Path, policy: ExistingFiles) -> Result<(), ArchiveError> {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.tar");
    std::fs::write(&archive, bytes).unwrap();
    ExtractRequest::new(&config())
        .with_options(ExtractionOptions::default().with_existing_files(policy))
        .extract(&archive, dest)
        .map(drop)
}

fn sink(bytes: Vec<u8>, policy: ExistingFiles) -> Result<(), ArchiveError> {
    let mut recorder = RecordingSink::default();
    SinkExtractRequest::new(&config())
        .with_options(SinkOptions::default().with_existing_files(policy))
        .extract(ArchiveReader::tar(Cursor::new(bytes), None), &mut recorder)
        .map(drop)
}

fn listed(bytes: Vec<u8>) -> exarch_core::Result<exarch_core::ListedArchive> {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.tar");
    std::fs::write(&archive, bytes).unwrap();
    ListRequest::new(&config()).for_extraction(&archive, DecodeReuse::default())
}

fn dispositions(bytes: Vec<u8>) -> Vec<DispositionKind> {
    let archive = listed(bytes).unwrap();
    archive
        .manifest()
        .dispositions(&config())
        .map(|(_, disposition)| disposition.kind())
        .collect()
}

fn cause(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    }
}

fn assert_existing_symlink(result: Result<(), ArchiveError>, by: OccupiedBy, context: &str) {
    let error = result.expect_err(context);
    let ArchiveError::SecurityViolation {
        kind: Violation::ReplacesSymlink { by: seen, .. },
        ..
    } = cause(&error)
    else {
        panic!("{context}: expected the existing-symlink refusal, got {error}");
    };
    assert_eq!(*seen, by, "{context}");
}

fn link_then_directory(target_is_dir: bool) -> Vec<u8> {
    let target = if target_is_dir {
        tar_dir("t/")
    } else {
        tar_file("t", b"t")
    };
    tar_archive(&[target, tar_symlink("l", "t"), tar_dir("l/")])
}

#[test]
fn dir_over_a_symlink_to_a_file_is_refused_on_host_sink_and_list() {
    for policy in POLICIES {
        let context = format!("{policy:?}");
        let dest = TempDir::new().unwrap();

        // Skip keeps no run record, so the maker of the link is unknown.
        let maker = if policy == ExistingFiles::Skip {
            OccupiedBy::Existing
        } else {
            OccupiedBy::Archive
        };
        assert_existing_symlink(
            host(link_then_directory(false), dest.path(), policy),
            maker,
            &format!("host {context}"),
        );
        assert_existing_symlink(
            sink(link_then_directory(false), policy),
            OccupiedBy::Archive,
            &format!("sink {context}"),
        );
    }
    assert_eq!(
        dispositions(link_then_directory(false)),
        [
            DispositionKind::Extract,
            DispositionKind::Extract,
            DispositionKind::Refuse
        ],
        "list model"
    );
}

#[test]
fn dir_over_a_symlink_to_a_directory_inside_the_destination_is_accepted_everywhere() {
    for policy in POLICIES {
        let dest = TempDir::new().unwrap();

        host(link_then_directory(true), dest.path(), policy)
            .unwrap_or_else(|error| panic!("host {policy:?}: {error}"));
        sink(link_then_directory(true), policy)
            .unwrap_or_else(|error| panic!("sink {policy:?}: {error}"));
        assert!(
            std::fs::symlink_metadata(dest.path().join("l"))
                .unwrap()
                .is_symlink(),
            "{policy:?}: the link stays a link"
        );
    }
    assert_eq!(
        dispositions(link_then_directory(true)),
        [DispositionKind::Extract; 3],
        "list model"
    );
}

#[test]
fn dir_over_a_preexisting_symlink_to_a_file_is_refused_as_existing() {
    for policy in POLICIES {
        let dest = TempDir::new().unwrap();
        std::fs::write(dest.path().join("t"), b"t").unwrap();
        symlink("t", dest.path().join("l")).unwrap();
        let bytes = || tar_archive(&[tar_dir("l/")]);

        assert_existing_symlink(
            host(bytes(), dest.path(), policy),
            OccupiedBy::Existing,
            &format!("host {policy:?}"),
        );
    }

    let dest = TempDir::new().unwrap();
    std::fs::write(dest.path().join("t"), b"t").unwrap();
    symlink("t", dest.path().join("l")).unwrap();
    for check in [DestinationCheck::Vacant, DestinationCheck::Replaceable] {
        let archive = listed(tar_archive(&[tar_dir("l/")])).unwrap();
        assert_existing_symlink(
            archive.check_destination(dest.path(), check),
            OccupiedBy::Existing,
            &format!("pre-check {check:?}"),
        );
    }
}

#[test]
fn dir_over_a_preexisting_symlink_to_a_directory_inside_the_destination_is_accepted() {
    for policy in POLICIES {
        let dest = TempDir::new().unwrap();
        std::fs::create_dir(dest.path().join("t")).unwrap();
        symlink("t", dest.path().join("l")).unwrap();

        host(tar_archive(&[tar_dir("l/")]), dest.path(), policy)
            .unwrap_or_else(|error| panic!("host {policy:?}: {error}"));
    }

    let dest = TempDir::new().unwrap();
    std::fs::create_dir(dest.path().join("t")).unwrap();
    symlink("t", dest.path().join("l")).unwrap();
    for check in [DestinationCheck::Vacant, DestinationCheck::Replaceable] {
        listed(tar_archive(&[tar_dir("l/")]))
            .unwrap()
            .check_destination(dest.path(), check)
            .unwrap_or_else(|error| panic!("pre-check {check:?}: {error}"));
    }
}
