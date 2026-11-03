//! A deflate ZIP entry is decoded once: the structural check keeps its output
//! and extraction writes it (#857).
//!
//! Every [`DecodeReuse`] mode must extract exactly what a decode from the
//! archive does, with the same report, through `extract_archive` and through a
//! listed archive.

#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

mod common;

use std::path::Path;
use std::process::Command;

use exarch_core::DecodeReuse;
use exarch_core::ExtractionOptions;
use exarch_core::ListOptions;
use exarch_core::NoopProgress;
use exarch_core::ReuseLimit;
use exarch_core::SecurityConfig;
use exarch_core::ZipConsistencyPolicy;
use exarch_core::extract_archive_with_options;
use exarch_core::list_archive_for_extraction;
use tempfile::TempDir;

const ENTRIES: usize = 24;
const ENTRY_LEN: usize = 40_000;

const MODES: [DecodeReuse; 4] = [
    DecodeReuse::Off,
    DecodeReuse::Memory(ReuseLimit::DEFAULT),
    DecodeReuse::TempFile(ReuseLimit::DEFAULT),
    DecodeReuse::TempFile(ReuseLimit::MAX),
];

fn write_archive(dir: &TempDir, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.path().join("a.zip");
    std::fs::write(&path, bytes).unwrap();
    path
}

fn assert_tree(root: &Path) {
    for index in 0..ENTRIES {
        let written = std::fs::read(root.join(format!("dir/file{index}.txt"))).unwrap();
        assert_eq!(written, common::wordy(index, ENTRY_LEN), "file{index}");
    }
}

#[test]
fn every_mode_extracts_the_same_files_and_report() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, &common::deflated_zip(ENTRIES, ENTRY_LEN));
    let config = SecurityConfig::default();

    for mode in MODES {
        let out = TempDir::new().unwrap();
        let options = ExtractionOptions::default().with_decode_reuse(mode);
        let report = extract_archive_with_options(&archive, out.path(), &config, &options).unwrap();
        assert_eq!(report.files_extracted, ENTRIES, "{mode:?}");
        assert_eq!(
            report.bytes_written,
            (ENTRIES * ENTRY_LEN) as u64,
            "{mode:?}"
        );
        assert_tree(out.path());
    }
}

#[test]
fn a_listed_zip_extracts_the_same_files_in_every_mode() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, &common::deflated_zip(ENTRIES, ENTRY_LEN));
    let config = SecurityConfig::default();

    for mode in MODES {
        let listed =
            list_archive_for_extraction(&archive, &config, &ListOptions::default(), mode).unwrap();
        assert_eq!(listed.manifest().total_entries(), ENTRIES, "{mode:?}");
        let out = TempDir::new().unwrap();
        let report = listed
            .extract(
                out.path(),
                &config,
                &ExtractionOptions::default(),
                &mut NoopProgress,
            )
            .unwrap();
        assert_eq!(report.files_extracted, ENTRIES, "{mode:?}");
        assert_tree(out.path());
    }
}

#[test]
fn a_listed_zip_opened_without_stream_checks_extracts_under_the_enforcing_policy() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, &common::deflated_zip(3, ENTRY_LEN));
    let lenient = SecurityConfig::default().with_zip_consistency(ZipConsistencyPolicy::Ignore);
    let listed = list_archive_for_extraction(
        &archive,
        &lenient,
        &ListOptions::default(),
        DecodeReuse::default(),
    )
    .unwrap();

    let out = TempDir::new().unwrap();
    listed
        .extract(
            out.path(),
            &SecurityConfig::default(),
            &ExtractionOptions::default(),
            &mut NoopProgress,
        )
        .unwrap();
    for index in 0..3 {
        let written = std::fs::read(out.path().join(format!("dir/file{index}.txt"))).unwrap();
        assert_eq!(written, common::wordy(index, ENTRY_LEN));
    }
}

#[test]
fn a_corrupt_entry_is_refused_in_every_mode() {
    let mut bytes = common::deflated_zip(2, ENTRY_LEN);
    let at = bytes.len() / 4;
    bytes[at] ^= 0x55;
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, &bytes);
    let config = SecurityConfig::default();

    let refusals: Vec<_> = MODES
        .iter()
        .map(|&mode| {
            let out = TempDir::new().unwrap();
            let options = ExtractionOptions::default().with_decode_reuse(mode);
            extract_archive_with_options(&archive, out.path(), &config, &options)
                .map(|_| ())
                .map_err(|e| e.to_string())
        })
        .collect();
    assert!(refusals[0].is_err(), "a corrupt entry must be refused");
    assert!(
        refusals.iter().all(|r| r == &refusals[0]),
        "modes disagree: {refusals:?}"
    );
}

const CHILD: &str = "EXARCH_TEST_UNWRITABLE_TMPDIR_ARCHIVE";

/// Re-runs this test in a child whose temporary directory does not exist, the
/// only way to set `TMPDIR` without `unsafe`, so no temporary file can be made.
#[test]
fn an_unwritable_temp_dir_falls_back_to_decoding_from_the_archive() {
    if let Some(archive) = std::env::var_os(CHILD) {
        let archive = std::path::PathBuf::from(archive);
        let out = archive.parent().unwrap().join("out");
        let options =
            ExtractionOptions::default().with_decode_reuse(DecodeReuse::TempFile(ReuseLimit::MAX));
        let report =
            extract_archive_with_options(&archive, &out, &SecurityConfig::default(), &options)
                .unwrap();
        assert_eq!(report.files_extracted, ENTRIES);
        assert_tree(&out);
        return;
    }

    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, &common::deflated_zip(ENTRIES, ENTRY_LEN));
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "an_unwritable_temp_dir_falls_back_to_decoding_from_the_archive",
            "--nocapture",
        ])
        .env(CHILD, &archive)
        .env("TMPDIR", dir.path().join("does-not-exist"))
        .status()
        .unwrap();
    assert!(status.success());
}
