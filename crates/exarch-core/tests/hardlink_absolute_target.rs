//! An absolute hardlink target keeps its root under a selection, and only its
//! normal components are selected and stripped like an entry name; the
//! validator then applies its own absolute-path policy to the result.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

mod sink_support;

use std::assert_matches;
use std::path::Path;

use exarch_core::ArchiveError;
use exarch_core::ExtractRequest;
use exarch_core::PathRewrite;
use exarch_core::SecurityConfig;
use exarch_core::StripComponents;
use exarch_core::Violation;
use tempfile::TempDir;

fn config(allow_absolute: bool) -> SecurityConfig {
    let limits = SecurityConfig::default();
    let strip = StripComponents::new(1.try_into().unwrap(), limits.max_path_depth).unwrap();
    limits
        .with_allow_hardlinks(true)
        .with_allow_absolute_paths(allow_absolute)
        .with_path_rewrite(PathRewrite::Strip(strip))
        .try_add_include("top")
        .unwrap()
}

fn extract(config: &SecurityConfig, target: &str) -> (TempDir, Result<(), ArchiveError>) {
    let work = TempDir::new().unwrap();
    let archive = work.path().join("a.tar");
    let bytes = sink_support::tar_archive(&[
        sink_support::tar_dir("top/"),
        sink_support::tar_file("top/orig", b"payload"),
        sink_support::tar_hardlink("top/l", target),
    ]);
    std::fs::write(&archive, bytes).unwrap();
    let result = ExtractRequest::new(config)
        .extract(&archive, work.path().join("out"))
        .map(|_| ());
    (work, result)
}

fn root(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction(partial) => root(partial.cause()),
        other => other,
    }
}

fn assert_no_link(work: &Path) {
    assert!(!work.join("out/l").exists());
}

#[test]
fn a_rerooted_absolute_target_is_still_refused_when_absolute_paths_are_allowed() {
    let (work, result) = extract(&config(true), "/top/orig");

    assert_matches!(
        root(&result.unwrap_err()),
        ArchiveError::HardlinkEscape { .. }
    );
    assert_no_link(work.path());
}

#[test]
fn the_absolute_path_policy_refuses_when_disallowed() {
    let (work, result) = extract(&config(false), "/top/orig");

    assert!(result.is_err());
    assert_no_link(work.path());
}

#[test]
fn an_absolute_target_outside_the_include_is_not_extracted() {
    let (work, result) = extract(&config(true), "/other/orig");

    assert_matches!(
        root(&result.unwrap_err()),
        ArchiveError::SecurityViolation {
            kind: Violation::HardlinkTargetNotExtracted { .. },
            ..
        }
    );
    assert_no_link(work.path());
}

#[test]
fn an_absolute_target_stripped_away_entirely_is_not_extracted() {
    let (work, result) = extract(&config(true), "/top");

    assert_matches!(
        root(&result.unwrap_err()),
        ArchiveError::SecurityViolation {
            kind: Violation::HardlinkTargetNotExtracted { .. },
            ..
        }
    );
    assert_no_link(work.path());
}
