//! Acceptance contract of #1201: `RepeatedPaths::Refuse` refuses an archive
//! that names a landing twice, under every `ExistingFiles` mode, on the host
//! and the in-memory sink, while `KeepFirst` keeps the outcome of 0.10.
//!
//! The tar cases rebuild S07, S09, S10, S14, S15 and S17 of the tar-minefield
//! suite (<https://github.com/haampie/tar-minefield>, commit
//! e3060bda2a54631c37d088914a24dddac34e7360) in-test.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

mod sink_support;

use std::assert_matches;
use std::io::Cursor;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::ErrorCode;
use exarch_core::ExistingFiles;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::OccupiedBy;
use exarch_core::PathRewrite;
use exarch_core::RepeatedPaths;
use exarch_core::SecurityConfig;
use exarch_core::SecurityViolationSubCode;
use exarch_core::SinkExtractRequest;
use exarch_core::SinkOptions;
use exarch_core::StripComponents;
use exarch_core::Violation;
use exarch_core::ZipConsistencyPolicy;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use sink_support::RecordingSink;
use sink_support::tar_archive;
use sink_support::tar_dir;
use sink_support::tar_file;
use sink_support::tar_hardlink;
use sink_support::tar_symlink;
use sink_support::zip_archive;
use sink_support::zip_file;
use tempfile::TempDir;

const POLICIES: [ExistingFiles; 3] = [
    ExistingFiles::Skip,
    ExistingFiles::Refuse,
    ExistingFiles::Overwrite,
];

fn config(repeats: RepeatedPaths) -> SecurityConfig {
    SecurityConfig::default()
        .with_allow_symlinks(true)
        .with_allow_hardlinks(true)
        .with_repeated_paths(repeats)
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

fn assert_repeated_path(error: &ArchiveError, expected_path: &str, context: &str) {
    assert_eq!(
        error.error_code(),
        ErrorCode::SecurityViolation,
        "{context}: {error}"
    );
    match cause(error) {
        ArchiveError::SecurityViolation { kind, .. } => {
            assert_eq!(
                kind.sub_code(),
                SecurityViolationSubCode::RepeatedPath,
                "{context}: {error}"
            );
            assert_matches!(
                kind,
                Violation::RepeatedPath { path, .. } if &**path == expected_path,
                "{context}: {error}"
            );
        }
        other => panic!("{context}: expected RepeatedPath, got {other}"),
    }
}

struct Case {
    id: &'static str,
    tar: Vec<u8>,
}

fn s07() -> Case {
    Case {
        id: "S07",
        tar: tar_archive(&[tar_file("a", b"first\n"), tar_file("a", b"last\n")]),
    }
}

fn s09() -> Case {
    Case {
        id: "S09",
        tar: tar_archive(&[tar_file("a", b"same\n"), tar_file("a", b"same\n")]),
    }
}

fn s10() -> Case {
    Case {
        id: "S10",
        tar: tar_archive(&[tar_symlink("a", "target"), tar_file("a", b"payload\n")]),
    }
}

fn s14() -> Case {
    Case {
        id: "S14",
        tar: tar_archive(&[
            tar_dir("target/"),
            tar_symlink("a", "target"),
            tar_dir("a/"),
        ]),
    }
}

fn s15() -> Case {
    Case {
        id: "S15",
        tar: tar_archive(&[
            tar_file("a", b"A\n"),
            tar_file("b", b"B\n"),
            tar_hardlink("a", "b"),
        ]),
    }
}

fn s17() -> Case {
    Case {
        id: "S17",
        tar: tar_archive(&[
            tar_file("a", b"first\n"),
            tar_hardlink("b", "a"),
            tar_file("a", b"second\n"),
        ]),
    }
}

fn all_cases() -> [Case; 6] {
    [s07(), s09(), s10(), s14(), s15(), s17()]
}

#[test]
fn extract_refuse_gives_repeated_path_for_every_minefield_case_and_mode() {
    let dir = TempDir::new().unwrap();
    for case in all_cases() {
        let archive = write(&dir, &format!("{}.tar", case.id), &case.tar);
        for policy in POLICIES {
            let dest = TempDir::new().unwrap();

            let error = extract(
                &archive,
                dest.path(),
                policy,
                &config(RepeatedPaths::Refuse),
            )
            .unwrap_err();

            assert_repeated_path(&error, "a", &format!("{} {policy:?}", case.id));
        }
    }
}

#[test]
fn extract_refuse_names_the_kinds_of_both_copies() {
    let dir = TempDir::new().unwrap();
    let archive = write(&dir, "s07.tar", &s07().tar);
    let dest = TempDir::new().unwrap();

    let error = extract(
        &archive,
        dest.path(),
        ExistingFiles::Skip,
        &config(RepeatedPaths::Refuse),
    )
    .unwrap_err();

    match cause(&error) {
        ArchiveError::SecurityViolation {
            kind: Violation::RepeatedPath { earlier, later, .. },
            ..
        } => assert_eq!(earlier, later),
        other => panic!("expected RepeatedPath, got {other}"),
    }
}

#[test]
fn extract_keep_first_keeps_the_first_copy_of_a_repeated_file() {
    let dir = TempDir::new().unwrap();
    for (case, expected) in [(s07(), "first\n"), (s09(), "same\n")] {
        let archive = write(&dir, &format!("{}.tar", case.id), &case.tar);
        let dest = TempDir::new().unwrap();

        extract(
            &archive,
            dest.path(),
            ExistingFiles::Skip,
            &config(RepeatedPaths::KeepFirst),
        )
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(dest.path().join("a")).unwrap(),
            expected,
            "{}",
            case.id
        );
    }
}

#[test]
fn extract_keep_first_is_the_default_and_matches_explicit_keep_first() {
    let dir = TempDir::new().unwrap();
    let archive = write(&dir, "s07.tar", &s07().tar);
    let default_dest = TempDir::new().unwrap();
    let explicit_dest = TempDir::new().unwrap();

    ExtractRequest::new(&SecurityConfig::default())
        .extract(&archive, default_dest.path())
        .unwrap();
    extract(
        &archive,
        explicit_dest.path(),
        ExistingFiles::Skip,
        &config(RepeatedPaths::KeepFirst),
    )
    .unwrap();

    assert_eq!(
        std::fs::read(default_dest.path().join("a")).unwrap(),
        std::fs::read(explicit_dest.path().join("a")).unwrap()
    );
    assert_eq!(
        SecurityConfig::default().repeated_paths,
        RepeatedPaths::KeepFirst
    );
}

#[test]
fn extract_keep_first_keeps_the_symlink_over_a_later_file_s10() {
    let dir = TempDir::new().unwrap();
    let archive = write(&dir, "s10.tar", &s10().tar);
    let dest = TempDir::new().unwrap();

    extract(
        &archive,
        dest.path(),
        ExistingFiles::Skip,
        &config(RepeatedPaths::KeepFirst),
    )
    .unwrap();

    assert_eq!(
        std::fs::read_link(dest.path().join("a")).unwrap(),
        Path::new("target")
    );
}

#[test]
fn extract_keep_first_refuses_a_directory_over_a_run_symlink_s14() {
    let dir = TempDir::new().unwrap();
    let archive = write(&dir, "s14.tar", &s14().tar);
    let dest = TempDir::new().unwrap();

    let error = extract(
        &archive,
        dest.path(),
        ExistingFiles::Skip,
        &config(RepeatedPaths::KeepFirst),
    )
    .unwrap_err();

    assert_matches!(
        cause(&error),
        ArchiveError::SecurityViolation {
            kind: Violation::ReplacesSymlink {
                by: OccupiedBy::Archive,
                ..
            },
            ..
        },
        "{error}"
    );
}

#[test]
fn extract_keep_first_keeps_the_original_file_over_a_later_hardlink_s15() {
    let dir = TempDir::new().unwrap();
    let archive = write(&dir, "s15.tar", &s15().tar);
    let dest = TempDir::new().unwrap();

    extract(
        &archive,
        dest.path(),
        ExistingFiles::Skip,
        &config(RepeatedPaths::KeepFirst),
    )
    .unwrap();

    assert_eq!(std::fs::read(dest.path().join("a")).unwrap(), b"A\n");
}

#[test]
fn extract_keep_first_keeps_the_first_file_over_a_later_copy_s17() {
    let dir = TempDir::new().unwrap();
    let archive = write(&dir, "s17.tar", &s17().tar);
    let dest = TempDir::new().unwrap();

    extract(
        &archive,
        dest.path(),
        ExistingFiles::Skip,
        &config(RepeatedPaths::KeepFirst),
    )
    .unwrap();

    assert_eq!(std::fs::read(dest.path().join("a")).unwrap(), b"first\n");
}

#[test]
fn extract_refuse_exempts_a_directory_entry_over_a_directory() {
    let dir = TempDir::new().unwrap();
    let archive = write(
        &dir,
        "d.tar",
        &tar_archive(&[
            tar_dir("d/"),
            tar_dir("d/"),
            tar_file("d/f", b"x"),
            tar_dir("d/e/"),
            tar_file("d/e/g", b"y"),
        ]),
    );
    for policy in POLICIES {
        let dest = TempDir::new().unwrap();

        extract(
            &archive,
            dest.path(),
            policy,
            &config(RepeatedPaths::Refuse),
        )
        .unwrap();

        assert_eq!(std::fs::read(dest.path().join("d/e/g")).unwrap(), b"y");
    }
}

#[test]
fn extract_refuse_leaves_a_preexisting_foreign_file_to_the_existing_files_policy() {
    let dir = TempDir::new().unwrap();
    let archive = write(&dir, "once.tar", &tar_archive(&[tar_file("a", b"new\n")]));

    let skip_dest = TempDir::new().unwrap();
    std::fs::write(skip_dest.path().join("a"), b"old\n").unwrap();
    extract(
        &archive,
        skip_dest.path(),
        ExistingFiles::Skip,
        &config(RepeatedPaths::Refuse),
    )
    .unwrap();
    assert_eq!(std::fs::read(skip_dest.path().join("a")).unwrap(), b"old\n");

    let refuse_dest = TempDir::new().unwrap();
    std::fs::write(refuse_dest.path().join("a"), b"old\n").unwrap();
    let error = extract(
        &archive,
        refuse_dest.path(),
        ExistingFiles::Refuse,
        &config(RepeatedPaths::Refuse),
    )
    .unwrap_err();
    assert_matches!(
        cause(&error),
        ArchiveError::DestinationOccupied {
            by: OccupiedBy::Existing,
            ..
        },
        "{error}"
    );

    let overwrite_dest = TempDir::new().unwrap();
    std::fs::write(overwrite_dest.path().join("a"), b"old\n").unwrap();
    extract(
        &archive,
        overwrite_dest.path(),
        ExistingFiles::Overwrite,
        &config(RepeatedPaths::Refuse),
    )
    .unwrap();
    assert_eq!(
        std::fs::read(overwrite_dest.path().join("a")).unwrap(),
        b"new\n"
    );
}

#[test]
fn sink_extract_refuse_gives_repeated_path_for_every_minefield_case() {
    for case in all_cases() {
        let mut sink = RecordingSink::default();

        let error = SinkExtractRequest::new(&config(RepeatedPaths::Refuse))
            .with_options(SinkOptions::default())
            .extract(ArchiveReader::tar(Cursor::new(case.tar), None), &mut sink)
            .unwrap_err();

        assert_repeated_path(&error, "a", case.id);
    }
}

#[test]
fn zip_duplicate_name_under_refuse_is_repeated_path_before_any_write_for_any_consistency() {
    let dir = TempDir::new().unwrap();
    let archive = write(
        &dir,
        "dup.zip",
        &zip_archive(vec![
            zip_file("keep", b"k"),
            zip_file("a", b"first\n"),
            zip_file("a", b"last\n"),
        ]),
    );
    for consistency in [ZipConsistencyPolicy::Enforce, ZipConsistencyPolicy::Ignore] {
        for policy in POLICIES {
            let dest = TempDir::new().unwrap();

            let error = extract(
                &archive,
                dest.path(),
                policy,
                &config(RepeatedPaths::Refuse).with_zip_consistency(consistency),
            )
            .unwrap_err();

            assert_repeated_path(&error, "a", &format!("{consistency:?} {policy:?}"));
            assert_eq!(
                std::fs::read_dir(dest.path()).unwrap().count(),
                0,
                "{consistency:?} {policy:?}: a write preceded the refusal"
            );
        }
    }
}

#[test]
fn zip_duplicate_name_under_keep_first_enforce_stays_a_zip_inconsistency() {
    let dir = TempDir::new().unwrap();
    let archive = write(
        &dir,
        "dup.zip",
        &zip_archive(vec![zip_file("a", b"first\n"), zip_file("a", b"last\n")]),
    );
    let dest = TempDir::new().unwrap();

    let error = extract(
        &archive,
        dest.path(),
        ExistingFiles::Skip,
        &config(RepeatedPaths::KeepFirst).with_zip_consistency(ZipConsistencyPolicy::Enforce),
    )
    .unwrap_err();

    assert_ne!(
        cause(&error).sub_code(),
        Some(exarch_core::SubCode::SecurityViolation(
            SecurityViolationSubCode::RepeatedPath
        )),
        "{error}"
    );
    assert_eq!(std::fs::read_dir(dest.path()).unwrap().count(), 0);
}

#[test]
fn sevenz_duplicate_name_under_refuse_is_repeated_path_before_any_write() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("dup.7z");
    let mut writer = ArchiveWriter::new(std::fs::File::create(&path).unwrap()).unwrap();
    for (name, data) in [("keep", &b"k"[..]), ("a", b"first\n"), ("a", b"last\n")] {
        writer
            .push_archive_entry(ArchiveEntry::new_file(name), Some(data))
            .unwrap();
    }
    writer.finish().unwrap();
    for policy in POLICIES {
        let dest = TempDir::new().unwrap();

        let error =
            extract(&path, dest.path(), policy, &config(RepeatedPaths::Refuse)).unwrap_err();

        assert_repeated_path(&error, "a", &format!("{policy:?}"));
        assert_eq!(
            std::fs::read_dir(dest.path()).unwrap().count(),
            0,
            "{policy:?}: the 7z pre-pass must refuse before any write"
        );
    }
}

#[test]
fn extract_refuse_names_a_strip_collision_as_a_repeated_path() {
    let dir = TempDir::new().unwrap();
    let archive = write(
        &dir,
        "strip.tar",
        &tar_archive(&[tar_file("x/a", b"1"), tar_file("y/a", b"2")]),
    );
    let dest = TempDir::new().unwrap();

    let base = config(RepeatedPaths::Refuse);
    let strip = StripComponents::new(exarch_core::non_zero!(1), base.max_path_depth).unwrap();
    let error = ExtractRequest::new(&base.with_path_rewrite(PathRewrite::Strip(strip)))
        .extract(&archive, dest.path())
        .unwrap_err();

    assert_repeated_path(&error, "a", "strip_components(1)");
}
