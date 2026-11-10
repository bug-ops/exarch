//! `MarkPropagation::Never` is today's extraction: with an unmarked archive,
//! every policy produces the same tree (content and exact modes) and the same
//! counts, on every platform.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

use std::path::Path;

use exarch_core::ExistingFiles;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::ExtractionReport;
use exarch_core::MarkOutcome;
use exarch_core::MarkPropagation;
use exarch_core::SecurityConfig;
use exarch_core::Staging;
use tempfile::TempDir;

mod common;

use common::sevenz_fixture;
use common::tar_fixture;
use common::tree_snapshot;
use common::zip_fixture;

fn extract(archive: &Path, out: &Path, options: ExtractionOptions) -> ExtractionReport {
    ExtractRequest::new(&SecurityConfig::default().with_allow_hardlinks(true))
        .with_options(options)
        .extract(archive, out)
        .unwrap()
}

fn counts(report: &ExtractionReport) -> (usize, usize, usize, u64) {
    (
        report.files_extracted,
        report.directories_created,
        report.symlinks_created,
        report.bytes_written,
    )
}

/// Extracts `archive` under each policy with `options` applied and asserts the
/// trees and counts agree; `seed` prepares each fresh destination.
fn assert_policies_agree(
    archive: &Path,
    options: impl Fn(MarkPropagation) -> ExtractionOptions,
    seed: impl Fn(&Path),
) {
    let mut outcomes = Vec::new();
    for policy in [MarkPropagation::Never, MarkPropagation::WhenMarked] {
        let out = TempDir::new().unwrap();
        let dest = out.path().join("dest");
        std::fs::create_dir(&dest).unwrap();
        seed(&dest);
        let report = extract(archive, &dest, options(policy));
        let expected_mark = match policy {
            MarkPropagation::Never => MarkOutcome::NotRequested,
            _ if cfg!(any(target_os = "macos", windows)) => MarkOutcome::Unmarked,
            _ => MarkOutcome::UnsupportedPlatform,
        };
        assert_eq!(report.mark, expected_mark, "{policy}");
        outcomes.push((tree_snapshot(&dest), counts(&report)));
    }
    assert_eq!(outcomes[0], outcomes[1], "{}", archive.display());
}

fn plain(policy: MarkPropagation) -> ExtractionOptions {
    ExtractionOptions::default().with_mark_propagation(policy)
}

#[test]
fn an_unmarked_archive_extracts_the_same_tree_under_every_policy() {
    let work = TempDir::new().unwrap();
    for archive in [
        tar_fixture(work.path()),
        zip_fixture(work.path()),
        sevenz_fixture(work.path()),
    ] {
        assert_policies_agree(&archive, plain, |_| {});
    }
}

#[test]
fn an_overwrite_extracts_the_same_tree_under_every_policy() {
    let work = TempDir::new().unwrap();
    for archive in [
        tar_fixture(work.path()),
        zip_fixture(work.path()),
        sevenz_fixture(work.path()),
    ] {
        assert_policies_agree(
            &archive,
            |policy| plain(policy).with_existing_files(ExistingFiles::Overwrite),
            |dest| std::fs::write(dest.join("ro.txt"), b"old").unwrap(),
        );
    }
}

#[test]
fn an_atomic_extraction_publishes_the_same_tree_under_every_policy() {
    let work = TempDir::new().unwrap();
    let archive = tar_fixture(work.path());
    let mut trees = Vec::new();
    for policy in [MarkPropagation::Never, MarkPropagation::WhenMarked] {
        let out = work.path().join(format!("published-{policy}"));
        let report = extract(&archive, &out, plain(policy).with_staging(Staging::Atomic));
        trees.push((tree_snapshot(&out), counts(&report)));
    }
    assert_eq!(trees[0], trees[1]);
}

#[cfg(unix)]
#[test]
fn read_only_entries_keep_their_exact_modes_under_every_policy() {
    let work = TempDir::new().unwrap();
    let archive = tar_fixture(work.path());
    for policy in [MarkPropagation::Never, MarkPropagation::WhenMarked] {
        let out = TempDir::new().unwrap();
        extract(&archive, out.path(), plain(policy));
        let tree = tree_snapshot(out.path());
        assert_eq!(tree[Path::new("ro.txt")].1, Some(0o444), "{policy}");
        assert_eq!(tree[Path::new("exec")].1, Some(0o555), "{policy}");
        assert_eq!(tree[Path::new("link.txt")].1, Some(0o444), "{policy}");
    }
}
