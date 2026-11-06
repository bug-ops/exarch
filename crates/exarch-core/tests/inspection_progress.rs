//! Progress events of `list` and `verify`, through the path and reader APIs.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

mod sink_support;

use std::io::Cursor;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveReader;
use exarch_core::ArchiveType;
use exarch_core::DecompressionBudget;
use exarch_core::IntegrityCheck;
use exarch_core::IntegrityStatus;
use exarch_core::ListOptions;
use exarch_core::ListRequest;
use exarch_core::ProgressCallback;
use exarch_core::SecurityConfig;
use exarch_core::VerificationOptions;
use exarch_core::VerificationStatus;
use exarch_core::VerifyRequest;
use sink_support::tar_archive;
use sink_support::tar_file;
use sink_support::zip_archive;
use sink_support::zip_file;
use tempfile::TempDir;

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Start {
        path: PathBuf,
        position: exarch_core::EntryPosition,
    },
    Complete(PathBuf),
    Done,
}

#[derive(Default)]
struct Recorder {
    events: Vec<Event>,
}

impl ProgressCallback for Recorder {
    fn on_entry_start(&mut self, path: &Path, position: exarch_core::EntryPosition) {
        self.events.push(Event::Start {
            path: path.to_path_buf(),
            position,
        });
    }

    fn on_bytes_written(&mut self, _bytes: u64) {}

    fn on_entry_complete(&mut self, path: &Path) {
        self.events.push(Event::Complete(path.to_path_buf()));
    }

    fn on_complete(&mut self) {
        self.events.push(Event::Done);
    }
}

impl Recorder {
    fn starts(&self) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e, Event::Start { .. }))
            .count()
    }

    fn completes(&self) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e, Event::Complete(_)))
            .count()
    }

    fn dones(&self) -> usize {
        self.events.iter().filter(|e| **e == Event::Done).count()
    }

    fn started_paths(&self) -> Vec<String> {
        self.events
            .iter()
            .filter_map(|e| match e {
                Event::Start { path, .. } => Some(path.display().to_string()),
                _ => None,
            })
            .collect()
    }

    /// Every start is closed by its own complete before the next start.
    fn assert_balanced(&self, entries: usize, expect_done: usize) {
        assert_eq!(self.starts(), entries, "{:?}", self.events);
        assert_eq!(self.completes(), entries, "{:?}", self.events);
        assert_eq!(self.dones(), expect_done, "{:?}", self.events);
        let mut open: Option<&Path> = None;
        for event in &self.events {
            match event {
                Event::Start { path, .. } => {
                    assert!(open.replace(path).is_none(), "{:?}", self.events);
                }
                Event::Complete(path) => {
                    assert_eq!(open.take(), Some(path.as_path()), "{:?}", self.events);
                }
                Event::Done => assert!(open.is_none()),
            }
        }
        if expect_done == 1 {
            assert_eq!(self.events.last(), Some(&Event::Done));
        }
    }
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn tar_gz() -> Vec<u8> {
    gzip(&tar_archive(&[
        tar_file("a.txt", b"alpha"),
        tar_file("b.txt", b"beta"),
        tar_file("c.txt", b"gamma"),
    ]))
}

fn zip() -> Vec<u8> {
    zip_archive(vec![
        zip_file("a.txt", b"alpha"),
        zip_file("b.txt", b"beta"),
        zip_file("c.txt", b"gamma"),
    ])
}

/// A file first, then an empty directory: the directory has no payload.
fn seven_z() -> Vec<u8> {
    let mut writer = sevenz_rust2::ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    for (name, data) in [("a.txt", &b"alpha"[..]), ("b.txt", &b"beta"[..])] {
        let mut entry = sevenz_rust2::ArchiveEntry::new_file(name);
        entry.has_stream = true;
        entry.size = data.len() as u64;
        writer
            .push_archive_entry(entry, Some(Cursor::new(data.to_vec())))
            .unwrap();
    }
    writer
        .push_archive_entry(
            sevenz_rust2::ArchiveEntry::new_directory("d"),
            None::<Cursor<Vec<u8>>>,
        )
        .unwrap();
    writer.finish().unwrap().into_inner()
}

fn formats() -> Vec<(ArchiveType, &'static str, Vec<u8>, usize)> {
    vec![
        (ArchiveType::TarGz, "x.tar.gz", tar_gz(), 3),
        (ArchiveType::Zip, "x.zip", zip(), 3),
        (ArchiveType::SevenZ, "x.7z", seven_z(), 3),
    ]
}

fn integrity() -> VerificationOptions {
    VerificationOptions::default()
        .with_integrity(IntegrityCheck::DecodeToEof(DecompressionBudget::DEFAULT))
}

fn write(name: &str, bytes: &[u8]) -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    (dir, path)
}

fn reader(bytes: &[u8], format: ArchiveType) -> ArchiveReader<'static> {
    ArchiveReader::of_type(Cursor::new(bytes.to_vec()), format)
}

#[test]
fn list_reports_every_entry_once_through_path_and_reader() {
    let config = SecurityConfig::default();
    for (format, name, bytes, entries) in formats() {
        let (_dir, path) = write(name, &bytes);
        let mut by_path = Recorder::default();
        let manifest = ListRequest::new(&config)
            .with_options(ListOptions::default())
            .with_progress(&mut by_path)
            .list(&path)
            .unwrap();
        assert_eq!(manifest.total_entries(), entries, "{format}");
        by_path.assert_balanced(entries, 1);

        let mut by_reader = Recorder::default();
        ListRequest::new(&config)
            .with_options(ListOptions::default())
            .with_progress(&mut by_reader)
            .list_reader(reader(&bytes, format))
            .unwrap();
        by_reader.assert_balanced(entries, 1);
        assert_eq!(
            by_reader.started_paths(),
            by_path.started_paths(),
            "{format}"
        );
    }
}

#[test]
fn verify_reports_every_entry_once_with_and_without_integrity() {
    let config = SecurityConfig::default();
    for (format, name, bytes, entries) in formats() {
        let (_dir, path) = write(name, &bytes);
        for options in [VerificationOptions::default(), integrity()] {
            let mut by_path = Recorder::default();
            VerifyRequest::new(&config)
                .with_options(options)
                .with_progress(&mut by_path)
                .verify(&path)
                .unwrap();
            by_path.assert_balanced(entries, 1);

            let mut by_reader = Recorder::default();
            VerifyRequest::new(&config)
                .with_options(options)
                .with_progress(&mut by_reader)
                .verify_reader(reader(&bytes, format))
                .unwrap();
            by_reader.assert_balanced(entries, 1);
        }
    }
}

#[test]
fn entry_numbers_are_one_based_and_totals_follow_the_format() {
    let config = SecurityConfig::default();
    for (format, name, bytes, entries) in formats() {
        let (_dir, path) = write(name, &bytes);
        let mut recorder = Recorder::default();
        ListRequest::new(&config)
            .with_options(ListOptions::default())
            .with_progress(&mut recorder)
            .list(&path)
            .unwrap();
        let expected_total = if format == ArchiveType::TarGz {
            exarch_core::EntryTotal::Unknown
        } else {
            exarch_core::EntryTotal::Known(entries)
        };
        let numbers: Vec<(exarch_core::EntryTotal, usize)> = recorder
            .events
            .iter()
            .filter_map(|e| match e {
                Event::Start { position, .. } => Some((position.total, position.current.get())),
                _ => None,
            })
            .collect();
        let expected: Vec<(exarch_core::EntryTotal, usize)> =
            (1..=entries).map(|n| (expected_total, n)).collect();
        assert_eq!(numbers, expected, "{format}");
    }
}

#[test]
fn a_7z_payload_is_announced_while_its_block_is_decoded() {
    let config = SecurityConfig::default();
    let (_dir, path) = write("x.7z", &seven_z());

    let mut metadata_only = Recorder::default();
    VerifyRequest::new(&config)
        .with_options(VerificationOptions::default())
        .with_progress(&mut metadata_only)
        .verify(&path)
        .unwrap();
    assert_eq!(metadata_only.started_paths(), ["a.txt", "b.txt", "d"]);

    let mut decoding = Recorder::default();
    VerifyRequest::new(&config)
        .with_options(integrity())
        .with_progress(&mut decoding)
        .verify(&path)
        .unwrap();
    assert_eq!(
        decoding.started_paths(),
        ["d", "a.txt", "b.txt"],
        "the directory is announced by the listing walk, the payloads by the decode"
    );
    decoding.assert_balanced(3, 1);
}

#[test]
fn a_tar_entry_that_fails_to_decode_still_closes_its_event() {
    let mut bytes = tar_archive(&[tar_file("a.txt", b"alpha"), tar_file("b.txt", &[7; 2000])]);
    bytes.truncate(512 + 512 + 512 + 100);
    let (_dir, path) = write("x.tar", &bytes);

    let mut recorder = Recorder::default();
    let result = VerifyRequest::new(&SecurityConfig::default())
        .with_options(integrity())
        .with_progress(&mut recorder)
        .verify(&path);
    assert!(result.is_err());
    assert_eq!(recorder.started_paths(), ["a.txt", "b.txt"]);
    assert_eq!(recorder.starts(), recorder.completes());
    assert_eq!(recorder.dones(), 0);
}

#[test]
fn a_failing_verify_report_still_signals_completion() {
    let bytes = tar_archive(&[sink_support::tar_symlink("link", "../../etc/passwd")]);
    let (_dir, path) = write("x.tar", &bytes);
    let mut recorder = Recorder::default();
    let report = VerifyRequest::new(&SecurityConfig::default())
        .with_options(VerificationOptions::default())
        .with_progress(&mut recorder)
        .verify(&path)
        .unwrap();
    assert_ne!(report.status(), exarch_core::VerificationStatus::Pass);
    recorder.assert_balanced(1, 1);
}

#[test]
fn a_failed_listing_never_signals_completion() {
    let (_dir, path) = write("x.zip", b"not an archive");
    let mut recorder = Recorder::default();
    let result = ListRequest::new(&SecurityConfig::default())
        .with_options(ListOptions::default())
        .with_progress(&mut recorder)
        .list(&path);
    assert!(result.is_err());
    assert_eq!(recorder.dones(), 0);
}

/// Three files in one solid block, then a directory, stored without
/// compression.
fn solid_7z() -> Vec<u8> {
    use sevenz_rust2::ArchiveEntry;
    use sevenz_rust2::EncoderConfiguration;
    use sevenz_rust2::EncoderMethod;
    use sevenz_rust2::SourceReader;

    let files: [(&str, &[u8]); 3] = [("a.txt", b"alpha"), ("b.txt", b"beta"), ("c.txt", b"gamma")];
    let mut writer = sevenz_rust2::ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    writer.set_content_methods(vec![EncoderConfiguration::new(EncoderMethod::COPY)]);
    let entries = files
        .iter()
        .map(|(name, data)| {
            let mut entry = ArchiveEntry::new_file(name);
            entry.has_stream = true;
            entry.size = data.len() as u64;
            entry
        })
        .collect();
    let readers = files
        .iter()
        .map(|(_, data)| SourceReader::from(Cursor::new(*data)))
        .collect();
    writer.push_archive_entries(entries, readers).unwrap();
    writer
        .push_archive_entry(ArchiveEntry::new_directory("d"), None::<Cursor<Vec<u8>>>)
        .unwrap();
    writer.finish().unwrap().into_inner()
}

fn verify_solid(
    config: &SecurityConfig,
    options: VerificationOptions,
) -> (Recorder, IntegrityStatus) {
    let (_dir, path) = write("x.7z", &solid_7z());
    let mut recorder = Recorder::default();
    let report = VerifyRequest::new(config)
        .with_options(options)
        .with_progress(&mut recorder)
        .verify(&path)
        .unwrap();
    (recorder, report.integrity_status())
}

#[test]
fn a_7z_block_the_policy_refuses_is_still_announced_once_per_file() {
    let (recorder, status) = verify_solid(&SecurityConfig::default(), integrity());
    assert_eq!(status, IntegrityStatus::Incomplete);
    recorder.assert_balanced(4, 1);
    assert_eq!(recorder.started_paths(), ["d", "a.txt", "b.txt", "c.txt"]);
}

#[test]
fn a_7z_block_over_the_decompression_budget_is_still_announced_once_per_file() {
    let config = SecurityConfig::default().with_allow_solid_archives(true);
    let options = VerificationOptions::default().with_integrity(IntegrityCheck::DecodeToEof(
        DecompressionBudget::try_from_bytes(1).unwrap(),
    ));
    let (recorder, status) = verify_solid(&config, options);
    assert_eq!(status, IntegrityStatus::Incomplete);
    recorder.assert_balanced(4, 1);
}

#[test]
fn a_decoded_solid_7z_block_announces_each_file_in_decode_order() {
    let config = SecurityConfig::default().with_allow_solid_archives(true);
    let (recorder, status) = verify_solid(&config, integrity());
    assert_eq!(status, IntegrityStatus::Pass);
    recorder.assert_balanced(4, 1);
    assert_eq!(recorder.started_paths(), ["d", "a.txt", "b.txt", "c.txt"]);
}

fn assert_failed_integrity(path: &Path) {
    let mut recorder = Recorder::default();
    let report = VerifyRequest::new(&SecurityConfig::default().with_allow_solid_archives(true))
        .with_options(integrity())
        .with_progress(&mut recorder)
        .verify(path)
        .unwrap();
    assert_eq!(report.integrity_status(), IntegrityStatus::Fail);
    assert_eq!(recorder.starts(), recorder.completes());
    assert_eq!(recorder.dones(), 1);
}

#[test]
fn zip_and_7z_with_corrupt_payload_report_balanced_events_and_complete() {
    for (name, mut bytes) in [("x.zip", zip()), ("x.7z", solid_7z())] {
        let at = bytes.windows(5).position(|w| w == b"alpha").unwrap();
        bytes[at] ^= 0xff;
        let (_dir, path) = write(name, &bytes);
        assert_failed_integrity(&path);
    }
}

#[test]
fn a_security_problem_mid_archive_keeps_the_scan_going() {
    let bytes = tar_archive(&[
        tar_file("a.txt", b"alpha"),
        sink_support::tar_symlink("link", "../../etc/passwd"),
        tar_file("c.txt", b"gamma"),
    ]);
    let (_dir, path) = write("x.tar", &bytes);
    let mut recorder = Recorder::default();
    let report = VerifyRequest::new(&SecurityConfig::default())
        .with_options(VerificationOptions::default())
        .with_progress(&mut recorder)
        .verify(&path)
        .unwrap();
    assert_ne!(report.status(), VerificationStatus::Pass);
    recorder.assert_balanced(3, 1);
    assert_eq!(recorder.started_paths(), ["a.txt", "link", "c.txt"]);
}
