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
fn a_sink_never_overwrites_an_entry_it_already_holds_under_refuse() {
    let archive = tar_archive(&[tar_file("a", b"first"), tar_file("a", b"second")]);
    let request = MemoryExtractRequest::default()
        .with_options(SinkOptions::default().with_existing_files(ExistingFiles::Refuse));

    let outcome = extract_reader_to_memory(
        ArchiveReader::from_bytes(archive, None).unwrap(),
        &request,
        &mut NoopProgress,
    );

    match outcome {
        Err(error) => assert_occupied(&error),
        Ok((_, sink)) => assert_matches!(
            sink.get(Path::new("a")),
            Some(MemoryEntry::File { data, .. }) if data == b"first"
        ),
    }
}
