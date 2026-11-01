//! Behaviour of `extract_to_sink` that has no path-based counterpart: how it
//! treats the sink, its inputs and its unsupported shapes.

#![allow(clippy::unwrap_used)]

mod sink_support;

use std::io;
use std::io::Cursor;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::EntrySink;
use exarch_core::ExtractionOptions;
use exarch_core::SafePath;
use exarch_core::SanitizedMode;
use exarch_core::SecurityConfig;
use exarch_core::SeekableFormat;
use exarch_core::extract_to_sink;
use exarch_core::formats::compression::CompressionCodec;
use exarch_testkit::raw_zip::RawEntry;
use sink_support::RecordingSink;
use sink_support::tar_archive;
use sink_support::tar_file;
use sink_support::zip_archive;
use sink_support::zip_file;

struct ReadOnly<R>(R);

impl<R: Read> Read for ReadOnly<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

fn tar_reader(entries: &[Vec<u8>]) -> ArchiveReader<'static> {
    ArchiveReader::tar(Cursor::new(tar_archive(entries)), None)
}

fn zip_reader(bytes: Vec<u8>) -> ArchiveReader<'static> {
    ArchiveReader::seekable(Cursor::new(bytes), SeekableFormat::Zip)
}

fn extract(
    reader: ArchiveReader<'_>,
    sink: &mut impl EntrySink,
) -> Result<exarch_core::ExtractionReport, ArchiveError> {
    extract_to_sink(
        reader,
        sink,
        &SecurityConfig::default(),
        &ExtractionOptions::default(),
    )
}

/// A sink whose methods can be made to fail.
#[derive(Default)]
struct FailingSink {
    fail_create: bool,
    fail_finish: bool,
    fail_directory: bool,
    fail_symlink: bool,
    fail_hardlink: bool,
    finished: Vec<PathBuf>,
}

impl EntrySink for FailingSink {
    type File = Vec<u8>;

    fn create_directory(&mut self, _: &SafePath) -> io::Result<()> {
        if self.fail_directory {
            return Err(io::Error::other("mkdir refused"));
        }
        Ok(())
    }

    fn create_file(
        &mut self,
        _: &SafePath,
        _: Option<SanitizedMode>,
        _: u64,
    ) -> io::Result<Vec<u8>> {
        if self.fail_create {
            return Err(io::Error::other("create refused"));
        }
        Ok(Vec::new())
    }

    fn finish_file(&mut self, path: &SafePath, _: Vec<u8>) -> io::Result<()> {
        if self.fail_finish {
            return Err(io::Error::other("flush failed"));
        }
        self.finished.push(path.as_path().to_path_buf());
        Ok(())
    }

    fn create_symlink(&mut self, _: &SafePath, _: &Path) -> io::Result<()> {
        if self.fail_symlink {
            return Err(io::Error::other("symlink refused"));
        }
        Ok(())
    }

    fn create_hardlink(&mut self, _: &SafePath, _: &SafePath) -> io::Result<()> {
        if self.fail_hardlink {
            return Err(io::Error::other("hardlink refused"));
        }
        Ok(())
    }
}

#[test]
fn a_failing_finish_file_ends_the_extraction_with_io() {
    let mut sink = FailingSink {
        fail_finish: true,
        ..FailingSink::default()
    };
    let error = extract(tar_reader(&[tar_file("a", b"x")]), &mut sink).unwrap_err();
    assert!(matches!(error, ArchiveError::Io(_)), "{error:?}");
}

#[test]
fn a_failing_create_file_ends_the_extraction_with_io() {
    let mut sink = FailingSink {
        fail_create: true,
        ..FailingSink::default()
    };
    let error = extract(tar_reader(&[tar_file("a", b"x")]), &mut sink).unwrap_err();
    assert!(matches!(error, ArchiveError::Io(_)), "{error:?}");
}

#[test]
fn a_crc_corrupt_zip_entry_is_never_finished() {
    let mut bytes = zip_archive(vec![
        zip_file("ok", b"fine"),
        zip_file("bad", b"UNIQUE-PAYLOAD"),
    ]);
    let at = bytes
        .windows(14)
        .position(|w| w == b"UNIQUE-PAYLOAD")
        .unwrap();
    bytes[at] ^= 1;
    let mut sink = RecordingSink::default();

    let error = extract(zip_reader(bytes), &mut sink).unwrap_err();

    assert!(
        matches!(
            error,
            ArchiveError::PartialExtraction { .. } | ArchiveError::Io(_)
        ),
        "{error:?}"
    );
    assert_eq!(sink.finished, [PathBuf::from("ok")]);
}

#[test]
fn a_forged_declared_size_is_a_security_violation_and_not_finished() {
    let payload = vec![0x41u8; 1024 * 1024];
    let entry = RawEntry {
        date: 0,
        size: 50,
        ..RawEntry::deflated("bomb.txt", &payload).unwrap()
    };
    let mut sink = RecordingSink::default();

    let error = extract(zip_reader(zip_archive(vec![entry])), &mut sink).unwrap_err();

    assert!(
        matches!(error, ArchiveError::SecurityViolation { .. }),
        "{error:?}"
    );
    assert!(sink.finished.is_empty());
}

#[test]
fn a_tar_source_that_cannot_seek_is_extracted() {
    let bytes = tar_archive(&[tar_file("dir/a.txt", b"alpha")]);
    let mut compressed = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    io::Write::write_all(&mut compressed, &bytes).unwrap();
    let reader = ArchiveReader::tar(
        ReadOnly(Cursor::new(compressed.finish().unwrap())),
        Some(CompressionCodec::Gzip),
    );
    let mut sink = RecordingSink::default();

    let report = extract(reader, &mut sink).unwrap();

    assert_eq!(report.files_extracted, 1);
    assert_eq!(sink.tree.files[Path::new("dir/a.txt")], b"alpha");
}

#[test]
fn seven_z_sources_are_not_supported() {
    let mut sink = RecordingSink::default();
    let reader = ArchiveReader::seekable(Cursor::new(Vec::new()), SeekableFormat::SevenZ);
    let error = extract(reader, &mut sink).unwrap_err();
    assert!(
        matches!(error, ArchiveError::InvalidConfiguration { .. }),
        "{error:?}"
    );
}

#[test]
fn atomic_extraction_is_not_supported() {
    let mut sink = RecordingSink::default();
    let options = ExtractionOptions::default().with_atomic(true);
    let error = extract_to_sink(
        tar_reader(&[tar_file("a", b"x")]),
        &mut sink,
        &SecurityConfig::default(),
        &options,
    )
    .unwrap_err();
    assert!(
        matches!(error, ArchiveError::InvalidConfiguration { .. }),
        "{error:?}"
    );
    assert!(sink.finished.is_empty());
}

#[test]
fn directories_and_files_are_announced_with_relative_paths() {
    let mut sink = RecordingSink::default();
    let reader = tar_reader(&[
        sink_support::tar_dir("d/"),
        tar_file("d/a.txt", b"alpha"),
        tar_file("deep/er/b.txt", b"b"),
    ]);

    extract(reader, &mut sink).unwrap();

    assert!(sink.tree.dirs.contains(Path::new("d")));
    assert!(sink.tree.files.contains_key(Path::new("deep/er/b.txt")));
    assert!(sink.tree.files.keys().all(|p| p.is_relative()));
}

fn links_config() -> SecurityConfig {
    SecurityConfig::default()
        .with_allow_symlinks(true)
        .with_allow_hardlinks(true)
}

fn extract_links(
    entries: &[Vec<u8>],
    sink: &mut impl EntrySink,
    options: &ExtractionOptions,
) -> Result<exarch_core::ExtractionReport, ArchiveError> {
    extract_to_sink(tar_reader(entries), sink, &links_config(), options)
}

fn is_io(error: &ArchiveError) -> bool {
    match error {
        ArchiveError::PartialExtraction { source, .. } => is_io(source),
        ArchiveError::Io(_) => true,
        _ => false,
    }
}

#[test]
fn failing_directory_symlink_and_hardlink_hooks_end_with_io() {
    let dir = [sink_support::tar_dir("d/")];
    let mut sink = FailingSink {
        fail_directory: true,
        ..FailingSink::default()
    };
    let error = extract_links(&dir, &mut sink, &ExtractionOptions::default()).unwrap_err();
    assert!(is_io(&error), "{error:?}");

    let link = [tar_file("t", b"x"), sink_support::tar_symlink("s", "t")];
    let mut sink = FailingSink {
        fail_symlink: true,
        ..FailingSink::default()
    };
    let error = extract_links(&link, &mut sink, &ExtractionOptions::default()).unwrap_err();
    assert!(is_io(&error), "{error:?}");

    let hard = [tar_file("t", b"x"), sink_support::tar_hardlink("h", "t")];
    let mut sink = FailingSink {
        fail_hardlink: true,
        ..FailingSink::default()
    };
    let error = extract_links(&hard, &mut sink, &ExtractionOptions::default()).unwrap_err();
    assert!(is_io(&error), "{error:?}");
}

#[test]
fn hardlink_to_a_symlink_to_a_file_is_delivered_at_the_resolved_target() {
    let mut sink = RecordingSink::default();
    let entries = [
        tar_file("t", b"data"),
        sink_support::tar_symlink("s", "t"),
        sink_support::tar_hardlink("h", "s"),
    ];
    extract_links(&entries, &mut sink, &ExtractionOptions::default()).unwrap();
    assert_eq!(sink.tree.files[Path::new("h")], b"data");
}

#[test]
fn hardlink_to_a_dangling_symlink_is_rejected() {
    let mut sink = RecordingSink::default();
    let entries = [
        sink_support::tar_symlink("s", "nowhere"),
        sink_support::tar_hardlink("h", "s"),
    ];
    let error = extract_links(&entries, &mut sink, &ExtractionOptions::default()).unwrap_err();
    assert!(!sink.tree.files.contains_key(Path::new("h")), "{error:?}");
}

#[test]
fn hardlink_to_a_directory_is_invalid_for_the_sink() {
    let mut sink = RecordingSink::default();
    let entries = [
        sink_support::tar_dir("d/"),
        sink_support::tar_hardlink("h", "d"),
    ];
    let error = extract_links(&entries, &mut sink, &ExtractionOptions::default()).unwrap_err();
    let ArchiveError::PartialExtraction { source, .. } = &error else {
        panic!("{error:?}");
    };
    assert!(
        matches!(**source, ArchiveError::InvalidArchive(_)),
        "{error:?}"
    );
}

#[test]
fn skipped_duplicate_hardlink_is_counted_and_not_delivered() {
    let mut sink = RecordingSink::default();
    let entries = [
        tar_file("t", b"x"),
        tar_file("h", b"y"),
        sink_support::tar_hardlink("h", "t"),
    ];
    let report = extract_links(&entries, &mut sink, &ExtractionOptions::default()).unwrap();
    assert_eq!(report.files_skipped, 1);
    assert_eq!(sink.tree.files[Path::new("h")], b"y");
    assert!(
        report.warnings.iter().any(|w| w.contains("hardlink")),
        "{:?}",
        report.warnings
    );
}
