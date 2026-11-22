//! A directory entry over an earlier symlink to a directory has the same
//! disposition in `list`, `verify`, host `extract` and the in-memory sink
//! under `RepeatedPaths::Refuse` (#1258), and `KeepFirst` is unchanged.

#![cfg(unix)]
#![expect(clippy::disallowed_methods, reason = "test fixture setup")]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]

mod sink_support;

use std::io::Cursor;

use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::DecodeReuse;
use exarch_core::DispositionKind;
use exarch_core::ExtractRequest;
use exarch_core::FfiKind;
use exarch_core::Finding;
use exarch_core::ListRequest;
use exarch_core::RepeatedPaths;
use exarch_core::SecurityConfig;
use exarch_core::SecurityViolationSubCode;
use exarch_core::SinkExtractRequest;
use exarch_core::SubCode;
use exarch_core::VerifyRequest;
use sink_support::RecordingSink;
use sink_support::tar_archive;
use sink_support::tar_dir;
use sink_support::tar_symlink;
use tempfile::TempDir;

fn config(repeats: RepeatedPaths) -> SecurityConfig {
    SecurityConfig::default()
        .with_allow_symlinks(true)
        .with_repeated_paths(repeats)
}

fn cause(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    }
}

fn is_repeated_path(error: &ArchiveError) -> bool {
    cause(error).sub_code()
        == Some(SubCode::SecurityViolation(
            SecurityViolationSubCode::RepeatedPath,
        ))
}

/// The four shapes of the issue: a symlink to a directory, then the same path
/// as a directory, spelled with and without a trailing slash and nested.
fn shapes() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "m1 link to a sibling directory",
            tar_archive(&[tar_dir("d"), tar_symlink("a", "d"), tar_dir("a")]),
        ),
        (
            "m2 link to the destination root",
            tar_archive(&[tar_symlink("a", "."), tar_dir("a")]),
        ),
        (
            "m3 nested link to its parent",
            tar_archive(&[tar_dir("a"), tar_symlink("a/c", "."), tar_dir("a/c")]),
        ),
        (
            "m4 directory spelled with a trailing slash",
            tar_archive(&[tar_dir("d"), tar_symlink("a", "d"), tar_dir("a/")]),
        ),
    ]
}

fn archive_file(dir: &TempDir, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.path().join("a.tar");
    std::fs::write(&path, bytes).unwrap();
    path
}

fn dispositions(bytes: &[u8], repeats: RepeatedPaths) -> Vec<DispositionKind> {
    let dir = TempDir::new().unwrap();
    let config = config(repeats);
    ListRequest::new(&config)
        .for_extraction(archive_file(&dir, bytes), DecodeReuse::default())
        .unwrap()
        .manifest()
        .dispositions(&config)
        .map(|(_, disposition)| disposition.kind())
        .collect()
}

fn verify_reports_repeat(bytes: &[u8], repeats: RepeatedPaths) -> bool {
    let dir = TempDir::new().unwrap();
    let report = VerifyRequest::new(&config(repeats))
        .verify(archive_file(&dir, bytes))
        .unwrap();
    report.issues().iter().any(|issue| {
        matches!(
            issue.finding(),
            Finding::Refusal {
                kind: FfiKind::SecurityViolation {
                    sub_code: SecurityViolationSubCode::RepeatedPath,
                    ..
                },
                ..
            }
        )
    })
}

fn host(bytes: &[u8], repeats: RepeatedPaths) -> Result<(), ArchiveError> {
    let dir = TempDir::new().unwrap();
    let dest = TempDir::new().unwrap();
    ExtractRequest::new(&config(repeats))
        .extract(archive_file(&dir, bytes), dest.path())
        .map(drop)
}

fn memory_sink(bytes: &[u8], repeats: RepeatedPaths) -> Result<(), ArchiveError> {
    let mut recorder = RecordingSink::default();
    SinkExtractRequest::new(&config(repeats))
        .extract(
            ArchiveReader::tar(Cursor::new(bytes.to_vec()), None),
            &mut recorder,
        )
        .map(drop)
}

#[test]
fn dispositions_of_a_directory_over_a_symlink_to_a_directory_is_refuse_under_refuse() {
    for (name, bytes) in shapes() {
        let kinds = dispositions(&bytes, RepeatedPaths::Refuse);

        assert_eq!(
            kinds.last(),
            Some(&DispositionKind::Refuse),
            "{name}: {kinds:?}"
        );
    }
}

#[test]
fn list_verify_extract_and_sink_agree_that_the_repeat_is_refused() {
    for (name, bytes) in shapes() {
        let extracted = host(&bytes, RepeatedPaths::Refuse).unwrap_err();
        let sunk = memory_sink(&bytes, RepeatedPaths::Refuse).unwrap_err();

        assert!(is_repeated_path(&extracted), "{name} host: {extracted}");
        assert!(is_repeated_path(&sunk), "{name} sink: {sunk}");
        assert!(
            verify_reports_repeat(&bytes, RepeatedPaths::Refuse),
            "{name}: verify"
        );
        assert!(
            dispositions(&bytes, RepeatedPaths::Refuse).contains(&DispositionKind::Refuse),
            "{name}: list"
        );
    }
}

#[test]
fn dispositions_under_keep_first_never_refuse_where_extract_succeeds() {
    for (name, bytes) in shapes() {
        host(&bytes, RepeatedPaths::KeepFirst)
            .unwrap_or_else(|error| panic!("{name} host: {error}"));
        memory_sink(&bytes, RepeatedPaths::KeepFirst)
            .unwrap_or_else(|error| panic!("{name} sink: {error}"));

        assert!(
            !verify_reports_repeat(&bytes, RepeatedPaths::KeepFirst),
            "{name}: verify"
        );
        assert!(
            !dispositions(&bytes, RepeatedPaths::KeepFirst).contains(&DispositionKind::Refuse),
            "{name}: list"
        );
    }
}
