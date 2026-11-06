//! `ExistingFiles::Refuse` never replaces a file the caller asked to keep.
//!
//! Every occupant site must route `Refuse` to `DestinationOccupied`; a missed
//! arm would fall through to an overwrite. Each test plants a file in the
//! destination, extracts an archive that lands on it, and checks both the typed
//! refusal and that the planted bytes are untouched.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

mod sink_support;

use std::assert_matches;
use std::path::Path;

use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::ErrorCode;
use exarch_core::ExistingFiles;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::MemoryEntry;
use exarch_core::MemoryExtractRequest;
use exarch_core::NoopProgress;
use exarch_core::SecurityConfig;
use exarch_core::SinkOptions;
use exarch_core::extract_reader_to_memory;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use sink_support::tar_archive;
use sink_support::tar_file;
use sink_support::zip_archive;
use sink_support::zip_file;
use tempfile::TempDir;

const KEPT: &[u8] = b"keep";

fn refusing() -> ExtractionOptions {
    ExtractionOptions::default().with_existing_files(ExistingFiles::Refuse)
}

fn destination_with(name: &str) -> TempDir {
    let dest = TempDir::new().unwrap();
    std::fs::write(dest.path().join(name), KEPT).unwrap();
    dest
}

fn extract_refused(archive: &Path, dest: &Path, config: &SecurityConfig) -> ArchiveError {
    ExtractRequest::new(config)
        .with_options(refusing())
        .extract(archive, dest)
        .unwrap_err()
}

fn assert_occupied(error: &ArchiveError) {
    assert_eq!(error.error_code(), ErrorCode::OutputExists, "{error}");
}

fn assert_kept(dest: &Path, name: &str) {
    assert_eq!(std::fs::read(dest.join(name)).unwrap(), KEPT);
}

#[test]
fn tar_file_over_an_existing_file_is_refused() {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.tar");
    std::fs::write(&archive, tar_archive(&[tar_file("f", b"replaced")])).unwrap();
    let dest = destination_with("f");

    let error = extract_refused(&archive, dest.path(), &SecurityConfig::default());

    assert_occupied(&error);
    assert_kept(dest.path(), "f");
}

#[test]
fn zip_file_over_an_existing_file_is_refused() {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.zip");
    std::fs::write(&archive, zip_archive(vec![zip_file("f", b"replaced")])).unwrap();
    let dest = destination_with("f");

    let error = extract_refused(&archive, dest.path(), &SecurityConfig::default());

    assert_occupied(&error);
    assert_kept(dest.path(), "f");
}

#[test]
fn sevenz_file_over_an_existing_file_is_refused() {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.7z");
    {
        let file = std::fs::File::create(&archive).unwrap();
        let mut writer = ArchiveWriter::new(file).unwrap();
        writer
            .push_archive_entry(ArchiveEntry::new_file("f"), Some(&b"replaced"[..]))
            .unwrap();
        writer.finish().unwrap();
    }
    let dest = destination_with("f");

    let error = extract_refused(&archive, dest.path(), &SecurityConfig::default());

    assert_occupied(&error);
    assert_kept(dest.path(), "f");
}

#[cfg(unix)]
#[test]
fn tar_symlink_over_an_existing_file_is_refused() {
    use sink_support::tar_symlink;

    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.tar");
    std::fs::write(&archive, tar_archive(&[tar_symlink("f", "elsewhere")])).unwrap();
    let dest = destination_with("f");
    let config = SecurityConfig::default().with_allow_symlinks(true);

    let error = extract_refused(&archive, dest.path(), &config);

    assert_occupied(&error);
    assert_kept(dest.path(), "f");
}

#[cfg(unix)]
#[test]
fn tar_hardlink_over_an_existing_file_is_refused() {
    use sink_support::tar_hardlink;

    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.tar");
    std::fs::write(
        &archive,
        tar_archive(&[tar_file("target", b"payload"), tar_hardlink("f", "target")]),
    )
    .unwrap();
    let dest = destination_with("f");
    let config = SecurityConfig::default().with_allow_hardlinks(true);

    let error = extract_refused(&archive, dest.path(), &config);

    assert_occupied(&error);
    assert_kept(dest.path(), "f");
}

#[test]
fn a_sink_skips_an_in_archive_duplicate_under_refuse() {
    let archive = tar_archive(&[tar_file("a", b"first"), tar_file("a", b"second")]);
    let request = MemoryExtractRequest::default()
        .with_options(SinkOptions::default().with_existing_files(ExistingFiles::Refuse));

    let (report, sink) = extract_reader_to_memory(
        ArchiveReader::from_bytes(archive, None).unwrap(),
        &request,
        &mut NoopProgress,
    )
    .unwrap();

    assert_eq!(report.files_skipped(), 1);
    assert_matches!(
        sink.get(Path::new("a")),
        Some(MemoryEntry::File { data, .. }) if data == b"first"
    );
}

/// Extracts `archive` twice, under `Skip` and under `Refuse`, into fresh
/// destinations and returns both reports with the content of `name`.
fn extract_both(
    archive: &Path,
    name: &str,
    config: &SecurityConfig,
) -> [(exarch_core::ExtractionReport, Vec<u8>); 2] {
    [ExistingFiles::Skip, ExistingFiles::Refuse].map(|policy| {
        let dest = TempDir::new().unwrap();
        let report = ExtractRequest::new(config)
            .with_options(ExtractionOptions::default().with_existing_files(policy))
            .extract(archive, dest.path())
            .unwrap();
        (report, std::fs::read(dest.path().join(name)).unwrap())
    })
}

fn assert_refuse_matches_skip(archive: &Path, name: &str, config: &SecurityConfig) {
    let [(skipped, skip_content), (refused, refuse_content)] = extract_both(archive, name, config);
    assert_eq!(refuse_content, skip_content);
    assert_eq!(refused.files_extracted, skipped.files_extracted);
    assert_eq!(refused.symlinks_created, skipped.symlinks_created);
    assert_eq!(refused.files_skipped(), skipped.files_skipped());
    assert_eq!(refused.files_skipped(), 1, "the duplicate is counted");
}

#[test]
fn tar_in_archive_duplicate_file_is_skipped_under_refuse() {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.tar");
    std::fs::write(
        &archive,
        tar_archive(&[tar_file("f", b"first"), tar_file("f", b"second")]),
    )
    .unwrap();

    assert_refuse_matches_skip(&archive, "f", &SecurityConfig::default());
}

#[test]
fn sevenz_in_archive_duplicate_file_is_skipped_under_refuse() {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.7z");
    {
        let file = std::fs::File::create(&archive).unwrap();
        let mut writer = ArchiveWriter::new(file).unwrap();
        for data in [&b"first"[..], &b"second"[..]] {
            writer
                .push_archive_entry(ArchiveEntry::new_file("f"), Some(data))
                .unwrap();
        }
        writer.finish().unwrap();
    }

    assert_refuse_matches_skip(&archive, "f", &SecurityConfig::default());
}

#[cfg(unix)]
#[test]
fn tar_in_archive_duplicate_symlink_is_skipped_under_refuse() {
    use sink_support::tar_symlink;

    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.tar");
    std::fs::write(
        &archive,
        tar_archive(&[tar_symlink("l", "one"), tar_symlink("l", "two")]),
    )
    .unwrap();
    let config = SecurityConfig::default().with_allow_symlinks(true);

    for policy in [ExistingFiles::Skip, ExistingFiles::Refuse] {
        let dest = TempDir::new().unwrap();
        let report = ExtractRequest::new(&config)
            .with_options(ExtractionOptions::default().with_existing_files(policy))
            .extract(&archive, dest.path())
            .unwrap();
        assert_eq!(report.symlinks_created, 1, "{policy:?}");
        assert_eq!(report.files_skipped(), 1, "{policy:?}");
        assert_eq!(
            std::fs::read_link(dest.path().join("l")).unwrap(),
            Path::new("one")
        );
    }
}

#[cfg(unix)]
#[test]
fn tar_in_archive_duplicate_hardlink_is_skipped_under_refuse() {
    use sink_support::tar_hardlink;

    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.tar");
    std::fs::write(
        &archive,
        tar_archive(&[
            tar_file("target", b"payload"),
            tar_hardlink("h", "target"),
            tar_hardlink("h", "target"),
        ]),
    )
    .unwrap();
    let config = SecurityConfig::default().with_allow_hardlinks(true);

    assert_refuse_matches_skip(&archive, "h", &config);
}

/// A progress callback that runs `act` on the destination after the entry named
/// `trigger` completed.
#[cfg(unix)]
struct AfterEntry<F: FnMut() + Send> {
    trigger: &'static str,
    act: F,
}

#[cfg(unix)]
impl<F: FnMut() + Send> exarch_core::ProgressCallback for AfterEntry<F> {
    fn on_entry_start(&mut self, _: &Path, _: exarch_core::EntryPosition) {}

    fn on_bytes_written(&mut self, _: u64) {}

    fn on_entry_complete(&mut self, path: &Path) {
        if path == Path::new(self.trigger) {
            (self.act)();
        }
    }

    fn on_complete(&mut self) {}
}

#[cfg(unix)]
#[test]
fn a_created_file_replaced_by_a_foreign_one_is_refused_not_overwritten() {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.tar");
    std::fs::write(
        &archive,
        tar_archive(&[tar_file("f", b"first"), tar_file("f", b"second")]),
    )
    .unwrap();
    let dest = TempDir::new().unwrap();
    let f = dest.path().join("f");
    let mut progress = AfterEntry {
        trigger: "f",
        act: || {
            std::fs::remove_file(&f).unwrap();
            std::fs::write(&f, KEPT).unwrap();
        },
    };

    let error = ExtractRequest::new(&SecurityConfig::default())
        .with_options(refusing())
        .with_progress(&mut progress)
        .extract(&archive, dest.path())
        .unwrap_err();

    assert_occupied(&error);
    assert_kept(dest.path(), "f");
}

#[cfg(unix)]
#[test]
fn a_foreign_hardlink_to_a_created_file_is_skipped_not_overwritten() {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.tar");
    std::fs::write(
        &archive,
        tar_archive(&[tar_file("f", b"first"), tar_file("g", b"second")]),
    )
    .unwrap();
    let dest = TempDir::new().unwrap();
    let (f, g) = (dest.path().join("f"), dest.path().join("g"));
    let mut progress = AfterEntry {
        trigger: "f",
        act: || std::fs::hard_link(&f, &g).unwrap(),
    };

    let report = ExtractRequest::new(&SecurityConfig::default())
        .with_options(refusing())
        .with_progress(&mut progress)
        .extract(&archive, dest.path())
        .unwrap();

    assert_eq!(report.files_skipped(), 1);
    assert_eq!(std::fs::read(&g).unwrap(), b"first");
}
