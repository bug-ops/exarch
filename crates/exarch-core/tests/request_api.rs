//! The request values cover every combination of optional inputs, including the
//! ones the plain functions never had (progress for a path-based list/verify).

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

mod sink_support;

use std::io::Cursor;
use std::path::Path;

use exarch_core::ArchiveReader;
use exarch_core::CreateRequest;
use exarch_core::CreationConfig;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::ListOptions;
use exarch_core::ListRequest;
use exarch_core::MemorySink;
use exarch_core::ProgressCallback;
use exarch_core::SecurityConfig;
use exarch_core::SinkExtractRequest;
use exarch_core::VerificationOptions;
use exarch_core::VerificationStatus;
use exarch_core::VerifyRequest;
use exarch_core::formats::detect::CreatableFormat;
use exarch_core::list_archive;
use exarch_core::list_reader;
use exarch_core::verify_archive;
use sink_support::tar_archive;
use sink_support::tar_file;
use sink_support::zip_archive;
use sink_support::zip_file;
use tempfile::TempDir;

#[derive(Default)]
struct Count {
    starts: usize,
    completes: usize,
    dones: usize,
}

impl ProgressCallback for Count {
    fn on_entry_start(&mut self, _: &Path, _: usize, _: usize) {
        self.starts += 1;
    }

    fn on_bytes_written(&mut self, _: u64) {}

    fn on_entry_complete(&mut self, _: &Path) {
        self.completes += 1;
    }

    fn on_complete(&mut self) {
        self.dones += 1;
    }
}

fn archives() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "a.tar",
            tar_archive(&[tar_file("a.txt", b"alpha"), tar_file("b.txt", b"bravo")]),
        ),
        (
            "a.zip",
            zip_archive(vec![
                zip_file("a.txt", b"alpha"),
                zip_file("b.txt", b"bravo"),
            ]),
        ),
    ]
}

fn write(dir: &TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn a_path_based_list_reports_progress() {
    let config = SecurityConfig::default();
    for (name, bytes) in archives() {
        let dir = TempDir::new().unwrap();
        let archive = write(&dir, name, &bytes);
        let mut progress = Count::default();

        let manifest = ListRequest::new(&config)
            .with_options(ListOptions::default())
            .with_progress(&mut progress)
            .list(&archive)
            .unwrap();

        assert_eq!(manifest.total_entries(), 2, "{name}");
        assert_eq!(progress.starts, 2, "{name}");
        assert_eq!(progress.completes, 2, "{name}");
        assert_eq!(progress.dones, 1, "{name}");
        assert_eq!(
            manifest.total_entries(),
            list_archive(&archive, &config).unwrap().total_entries()
        );
    }
}

#[test]
fn a_path_based_verify_reports_progress() {
    let config = SecurityConfig::default();
    for (name, bytes) in archives() {
        let dir = TempDir::new().unwrap();
        let archive = write(&dir, name, &bytes);
        let mut progress = Count::default();

        let report = VerifyRequest::new(&config)
            .with_options(VerificationOptions::default())
            .with_progress(&mut progress)
            .verify(&archive)
            .unwrap();

        assert_eq!(report.status(), VerificationStatus::Pass, "{name}");
        assert_eq!(progress.starts, 2, "{name}");
        assert_eq!(progress.dones, 1, "{name}");
        assert_eq!(
            report.status(),
            verify_archive(&archive, &config).unwrap().status()
        );
    }
}

#[test]
fn reader_requests_match_the_plain_reader_functions() {
    let config = SecurityConfig::default();
    let bytes = archives().remove(0).1;
    let mut progress = Count::default();

    let manifest = ListRequest::new(&config)
        .with_progress(&mut progress)
        .list_reader(ArchiveReader::tar(Cursor::new(bytes.clone()), None))
        .unwrap();
    let plain = list_reader(
        ArchiveReader::tar(Cursor::new(bytes.clone()), None),
        &config,
        &ListOptions::default(),
    )
    .unwrap();
    assert_eq!(manifest.total_entries(), plain.total_entries());
    assert_eq!(progress.dones, 1);

    let mut progress = Count::default();
    let report = VerifyRequest::new(&config)
        .with_progress(&mut progress)
        .verify_reader(ArchiveReader::tar(Cursor::new(bytes), None))
        .unwrap();
    assert_eq!(report.status(), VerificationStatus::Pass);
    assert_eq!(progress.dones, 1);
}

#[test]
fn an_extract_request_applies_its_options_and_progress() {
    let config = SecurityConfig::default();
    for (name, bytes) in archives() {
        let dir = TempDir::new().unwrap();
        let archive = write(&dir, name, &bytes);
        let out = dir.path().join("out");
        let mut progress = Count::default();

        let report = ExtractRequest::new(&config)
            .with_options(ExtractionOptions::default().with_atomic(true))
            .with_progress(&mut progress)
            .extract(&archive, &out)
            .unwrap();

        assert_eq!(report.files_extracted, 2, "{name}");
        assert_eq!(progress.starts, 2, "{name}");
        assert_eq!(std::fs::read(out.join("b.txt")).unwrap(), b"bravo");

        // Atomic extraction refuses an existing destination without touching
        // it.
        assert!(
            ExtractRequest::new(&config)
                .with_options(ExtractionOptions::default().with_atomic(true))
                .extract(&archive, &out)
                .is_err()
        );
        assert_eq!(std::fs::read(out.join("a.txt")).unwrap(), b"alpha");
    }
}

#[test]
fn a_sink_request_delivers_the_entries_and_reports_progress() {
    let config = SecurityConfig::default();
    let bytes = archives().remove(0).1;
    let mut sink = MemorySink::default();
    let mut progress = Count::default();

    let report = SinkExtractRequest::new(&config)
        .with_progress(&mut progress)
        .extract(ArchiveReader::tar(Cursor::new(bytes), None), &mut sink)
        .unwrap();

    assert_eq!(report.files_extracted, 2);
    assert_eq!(progress.starts, 2);
}

#[test]
fn a_create_request_writes_to_bytes_and_reports_progress() {
    let src = TempDir::new().unwrap();
    std::fs::write(src.path().join("a.txt"), b"alpha").unwrap();
    let config = CreationConfig::default();

    for format in [CreatableFormat::TarGz, CreatableFormat::Zip] {
        let mut progress = Count::default();
        let (bytes, report) = CreateRequest::new(&config)
            .with_progress(&mut progress)
            .to_bytes(format, &[src.path().join("a.txt")])
            .unwrap();

        assert_eq!(report.bytes_compressed, bytes.len() as u64, "{format:?}");
        assert_eq!(progress.starts, 1, "{format:?}");
        assert_eq!(progress.dones, 1, "{format:?}");
    }
}
