//! Download-mark propagation against Windows volumes without named streams
//! (FAT32, exFAT), where no `Zone.Identifier` stream can exist.
//!
//! The volumes come from the environment, so ordinary runs skip these tests:
//! `EXARCH_MARK_VOLUME_FAT32` and `EXARCH_MARK_VOLUME_EXFAT` hold the root of a
//! mounted volume (for example `F:\`). The `windows-volumes` CI job creates
//! them and sets `EXARCH_REQUIRE_MARK_VOLUMES` to fail instead of skip.

#![cfg(windows)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

use std::path::Path;
use std::path::PathBuf;

use exarch_core::ExistingFiles;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::ExtractionReport;
use exarch_core::MarkOutcome;
use exarch_core::MarkPropagation;
use exarch_core::SecurityConfig;
use tempfile::TempDir;

mod common;

use common::zip_fixture;

const REQUIRE: &str = "EXARCH_REQUIRE_MARK_VOLUMES";
const FILES: [&str; 2] = ["ro.txt", "nested/inner.txt"];

struct Volume {
    label: &'static str,
    root: TempDir,
}

fn volumes() -> Vec<Volume> {
    let found: Vec<Volume> = [
        ("FAT32", "EXARCH_MARK_VOLUME_FAT32"),
        ("exFAT", "EXARCH_MARK_VOLUME_EXFAT"),
    ]
    .into_iter()
    .filter_map(|(label, var)| {
        let root = PathBuf::from(std::env::var_os(var)?);
        let scratch = tempfile::Builder::new()
            .prefix("exarch-mark-")
            .tempdir_in(&root)
            .unwrap();
        Some(Volume {
            label,
            root: scratch,
        })
    })
    .collect();
    if found.is_empty() {
        assert!(
            std::env::var_os(REQUIRE).is_none(),
            "{REQUIRE} is set but no EXARCH_MARK_VOLUME_* variable names a volume"
        );
        eprintln!("skipped: no EXARCH_MARK_VOLUME_FAT32 or EXARCH_MARK_VOLUME_EXFAT volume");
    }
    found
}

fn stream(path: &Path) -> String {
    format!("{}:Zone.Identifier", path.display())
}

fn mark_archive(path: &Path) {
    std::fs::write(stream(path), "[ZoneTransfer]\r\nZoneId=3\r\n").unwrap();
}

fn mark_of(path: &Path) -> Option<String> {
    std::fs::read_to_string(stream(path)).ok()
}

fn assert_volume_has_no_streams(volume: &Volume) {
    let probe = volume.root.path().join("probe.txt");
    std::fs::write(&probe, b"x").unwrap();
    assert!(
        std::fs::write(stream(&probe), b"x").is_err(),
        "{} accepted a named stream, so it cannot stand in for a volume without them",
        volume.label
    );
    std::fs::remove_file(&probe).unwrap();
}

fn when_marked() -> ExtractionOptions {
    ExtractionOptions::default().with_mark_propagation(MarkPropagation::WhenMarked)
}

fn extract(archive: &Path, out: &Path, options: ExtractionOptions) -> ExtractionReport {
    ExtractRequest::new(&SecurityConfig::default())
        .with_options(options)
        .extract(archive, out)
        .unwrap()
}

fn assert_extracted_without_marks(out: &Path) {
    for name in FILES {
        let path = out.join(name);
        assert_eq!(std::fs::read(&path).unwrap(), b"data", "{name}");
        assert!(mark_of(&path).is_none(), "{name} carries a mark");
    }
}

fn assert_marks_failed_on_every_file(report: &ExtractionReport) {
    assert_eq!(
        report.mark,
        MarkOutcome::Propagated {
            marked: 0,
            failed: FILES.len(),
        }
    );
    assert!(report.mark.is_incomplete());
}

#[test]
fn a_marked_archive_extracts_onto_a_volume_without_streams_and_counts_the_failed_marks() {
    for volume in volumes() {
        assert_volume_has_no_streams(&volume);
        let work = TempDir::new().unwrap();
        let archive = zip_fixture(work.path());
        mark_archive(&archive);
        let out = volume.root.path().join("out");

        let report = extract(&archive, &out, when_marked());

        assert_marks_failed_on_every_file(&report);
        assert_extracted_without_marks(&out);
    }
}

#[test]
fn a_forced_replacement_on_a_volume_without_streams_counts_the_failed_marks() {
    for volume in volumes() {
        assert_volume_has_no_streams(&volume);
        let work = TempDir::new().unwrap();
        let archive = zip_fixture(work.path());
        mark_archive(&archive);
        let out = volume.root.path().join("out");
        std::fs::create_dir(&out).unwrap();
        std::fs::write(out.join("ro.txt"), b"old").unwrap();

        let options = when_marked().with_existing_files(ExistingFiles::Overwrite);
        let report = extract(&archive, &out, options);

        assert_marks_failed_on_every_file(&report);
        assert_extracted_without_marks(&out);
    }
}

#[test]
fn an_archive_on_a_volume_without_streams_reads_as_unmarked() {
    for volume in volumes() {
        assert_volume_has_no_streams(&volume);
        let archive = zip_fixture(volume.root.path());
        let ntfs = TempDir::new().unwrap();

        let report = extract(&archive, ntfs.path(), when_marked());

        assert_eq!(report.mark, MarkOutcome::Unmarked, "{}", volume.label);
        assert_extracted_without_marks(ntfs.path());
    }
}

#[test]
fn an_archive_and_destination_on_a_volume_without_streams_extract_unmarked_with_and_without_force()
{
    for volume in volumes() {
        assert_volume_has_no_streams(&volume);
        let archive = zip_fixture(volume.root.path());
        let out = volume.root.path().join("out");

        let fresh = extract(&archive, &out, when_marked());
        assert_eq!(fresh.mark, MarkOutcome::Unmarked, "{}", volume.label);
        assert_extracted_without_marks(&out);

        let options = when_marked().with_existing_files(ExistingFiles::Overwrite);
        let forced = extract(&archive, &out, options);
        assert_eq!(forced.mark, MarkOutcome::Unmarked, "{}", volume.label);
        assert_extracted_without_marks(&out);
    }
}
