//! 7z into an `EntrySink`: progress parity with the path-based API, typed
//! sink errors and the shapes unique to a sink.

#![allow(clippy::unwrap_used)]

mod common;
mod sink_support;

use std::io::Cursor;
use std::num::NonZeroU64;
use std::path::Path;

use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::EntrySink;
use exarch_core::ExtractionOptions;
use exarch_core::MemoryLimit;
use exarch_core::MemorySink;
use exarch_core::ProgressCallback;
use exarch_core::QuotaResource;
use exarch_core::SecurityConfig;
use exarch_core::SeekableFormat;
use exarch_core::extract_archive_with_progress;
use exarch_core::extract_to_sink_with_progress;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use sevenz_rust2::EncoderConfiguration;
use sevenz_rust2::EncoderMethod;
use sink_support::RecordingSink;
use sink_support::tar_archive;
use sink_support::tar_dir;
use sink_support::tar_file;
use sink_support::zip_archive;
use sink_support::zip_dir;
use sink_support::zip_file;
use tempfile::TempDir;

#[derive(Default)]
struct Events(Vec<String>);

impl ProgressCallback for Events {
    fn on_entry_start(&mut self, path: &Path, total: usize, current: usize) {
        self.0
            .push(format!("start {} {current}/{total}", path.display()));
    }

    fn on_bytes_written(&mut self, bytes: u64) {
        self.0.push(format!("bytes {bytes}"));
    }

    fn on_entry_complete(&mut self, path: &Path) {
        self.0.push(format!("complete {}", path.display()));
    }

    fn on_complete(&mut self) {
        self.0.push("done".into());
    }
}

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name);
    std::fs::read(path).unwrap()
}

fn config() -> SecurityConfig {
    SecurityConfig::default().with_allow_solid_archives(true)
}

fn host_events(file_name: &str, bytes: &[u8]) -> Vec<String> {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join(file_name);
    std::fs::write(&archive, bytes).unwrap();
    let mut events = Events::default();
    extract_archive_with_progress(&archive, dir.path().join("out"), &config(), &mut events)
        .unwrap();
    events.0
}

fn sink_events(reader: ArchiveReader<'_>) -> Vec<String> {
    let mut events = Events::default();
    extract_to_sink_with_progress(
        reader,
        &mut RecordingSink::default(),
        &config(),
        &ExtractionOptions::default(),
        &mut events,
    )
    .unwrap();
    events.0
}

#[test]
fn tar_progress_events_match_the_path_based_api() {
    let bytes = tar_archive(&[
        tar_dir("d/"),
        tar_file("d/a.txt", b"alpha"),
        tar_file("b.txt", b"beta"),
    ]);
    let host = host_events("a.tar", &bytes);
    let sink = sink_events(ArchiveReader::tar(Cursor::new(bytes), None));
    assert_eq!(sink, host);
    assert!(host.iter().any(|e| e.starts_with("bytes")), "{host:?}");
}

#[test]
fn zip_progress_events_match_the_path_based_api() {
    let bytes = zip_archive(vec![zip_dir("d/"), zip_file("d/a.txt", b"alpha")]);
    let host = host_events("a.zip", &bytes);
    let sink = sink_events(ArchiveReader::seekable(
        Cursor::new(bytes),
        SeekableFormat::Zip,
    ));
    assert_eq!(sink, host);
}

#[test]
fn sevenz_progress_events_match_the_path_based_api() {
    for name in ["simple.7z", "nested-dirs.7z", "solid.7z"] {
        let bytes = fixture(name);
        let host = host_events("a.7z", &bytes);
        let sink = sink_events(ArchiveReader::seekable(
            Cursor::new(bytes),
            SeekableFormat::SevenZ,
        ));
        assert_eq!(sink, host, "{name}");
        assert_eq!(host.last().map(String::as_str), Some("done"), "{name}");
    }
}

#[test]
fn a_full_memory_sink_stays_typed_through_the_7z_abort() {
    let mut sink = MemorySink::new(MemoryLimit::new(NonZeroU64::MIN));
    let error = extract(&mut sink, "simple.7z").unwrap_err();
    let mut cause = &error;
    while let ArchiveError::PartialExtraction { source, .. } = cause {
        cause = source;
    }
    assert!(
        matches!(
            cause,
            ArchiveError::QuotaExceeded {
                resource: QuotaResource::SinkCapacity { max: 1 }
            }
        ),
        "{error:?}"
    );
}

#[test]
fn a_memory_sink_with_room_receives_every_file() {
    let mut sink = MemorySink::default();
    let report = extract(&mut sink, "nested-dirs.7z").unwrap();
    assert!(sink.iter().count() >= report.files_extracted);
    assert!(report.files_extracted > 0);
}

#[test]
fn the_empty_archive_extracts_nothing_and_never_completes() {
    let mut events = Events::default();
    let report = extract_to_sink_with_progress(
        ArchiveReader::seekable(Cursor::new(fixture("empty.7z")), SeekableFormat::SevenZ),
        &mut RecordingSink::default(),
        &config(),
        &ExtractionOptions::default(),
        &mut events,
    )
    .unwrap();
    assert_eq!(report.files_extracted, 0);
    assert!(events.0.is_empty(), "{:?}", events.0);
}

#[test]
fn a_source_that_is_not_a_7z_is_rejected() {
    let error = extract_to_sink_with_progress(
        ArchiveReader::seekable(Cursor::new(vec![0; 64]), SeekableFormat::SevenZ),
        &mut RecordingSink::default(),
        &config(),
        &ExtractionOptions::default(),
        &mut Events::default(),
    )
    .unwrap_err();
    assert!(
        matches!(error, ArchiveError::InvalidArchive(_)),
        "{error:?}"
    );
}

#[test]
fn symlinks_are_delivered_where_the_archive_allows_them() {
    let mut sink = RecordingSink::default();
    let config = config().with_allow_symlinks(true);
    let report = extract_to_sink_with_progress(
        ArchiveReader::seekable(
            Cursor::new(fixture("symlink-mode.7z")),
            SeekableFormat::SevenZ,
        ),
        &mut sink,
        &config,
        &ExtractionOptions::default(),
        &mut Events::default(),
    )
    .unwrap();
    assert!(report.symlinks_created >= 1, "{report:?}");
    assert_eq!(sink.tree.symlinks.len(), report.symlinks_created);
}

#[test]
fn symlinks_are_refused_unless_allowed() {
    let error = extract_to_sink_with_progress(
        ArchiveReader::seekable(
            Cursor::new(fixture("symlink-mode.7z")),
            SeekableFormat::SevenZ,
        ),
        &mut RecordingSink::default(),
        &config(),
        &ExtractionOptions::default(),
        &mut Events::default(),
    )
    .unwrap_err();
    assert!(
        matches!(error, ArchiveError::SecurityViolation { .. }),
        "{error:?}"
    );
}

const UNIX_EXTENSION: u32 = 0x8000;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
const S_IFLNK: u32 = 0o12_0000;

enum Member<'a> {
    Dir(&'a str),
    File(&'a str, &'a [u8]),
    Link(&'a str, &'a [u8]),
    Junction(&'a str),
}

fn archive(members: &[Member<'_>], stored: bool) -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    if stored {
        writer.set_content_methods(vec![EncoderConfiguration::new(EncoderMethod::COPY)]);
    }
    for member in members {
        let (mut entry, data): (ArchiveEntry, &[u8]) = match *member {
            Member::File(name, data) => (ArchiveEntry::new_file(name), data),
            Member::Link(name, target) => {
                let mut entry = ArchiveEntry::new_file(name);
                entry.has_windows_attributes = true;
                entry.windows_attributes = UNIX_EXTENSION | ((S_IFLNK | 0o777) << 16);
                (entry, target)
            }
            Member::Dir(name) => {
                writer
                    .push_archive_entry(ArchiveEntry::new_directory(name), None::<Cursor<Vec<u8>>>)
                    .unwrap();
                continue;
            }
            Member::Junction(name) => {
                let mut entry = ArchiveEntry::new_directory(name);
                entry.has_windows_attributes = true;
                entry.windows_attributes = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT;
                writer
                    .push_archive_entry(entry, None::<Cursor<Vec<u8>>>)
                    .unwrap();
                continue;
            }
        };
        entry.has_stream = !data.is_empty();
        entry.size = data.len() as u64;
        let reader = entry.has_stream.then(|| Cursor::new(data.to_vec()));
        writer.push_archive_entry(entry, reader).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn extract_bytes<S: EntrySink>(
    bytes: Vec<u8>,
    config: &SecurityConfig,
    sink: &mut S,
) -> Result<exarch_core::ExtractionReport, ArchiveError> {
    extract_to_sink_with_progress(
        ArchiveReader::seekable(Cursor::new(bytes), SeekableFormat::SevenZ),
        sink,
        config,
        &ExtractionOptions::default(),
        &mut Events::default(),
    )
}

fn cause(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction { source, .. } => cause(source),
        other => other,
    }
}

#[test]
fn a_ratio_bomb_is_refused_before_the_sink_sees_an_entry() {
    let bomb = vec![0_u8; 8 * 1024 * 1024];
    let bytes = archive(
        &[
            Member::File("ok.txt", b"hi"),
            Member::File("bomb.bin", &bomb),
        ],
        false,
    );
    let mut sink = RecordingSink::default();
    let error = extract_bytes(bytes, &config(), &mut sink).unwrap_err();
    assert!(matches!(error, ArchiveError::ZipBomb(_)), "{error:?}");
    assert!(sink.finished.is_empty() && sink.tree.dirs.is_empty());
}

#[test]
fn an_escaping_symlink_is_refused_after_the_earlier_entries() {
    let bytes = archive(
        &[Member::File("a.txt", b"hi"), Member::Link("l", b"../../x")],
        false,
    );
    let mut sink = RecordingSink::default();
    let config = config().with_allow_symlinks(true);
    let error = extract_bytes(bytes, &config, &mut sink).unwrap_err();
    assert!(
        matches!(cause(&error), ArchiveError::SymlinkEscape { .. }),
        "{error:?}"
    );
    assert!(matches!(error, ArchiveError::PartialExtraction { .. }));
    assert!(sink.tree.symlinks.is_empty());
    assert_eq!(sink.finished.len(), 1);
}

fn is_name_too_long(error: &ArchiveError) -> bool {
    matches!(error, ArchiveError::Io(io) if io.kind() == std::io::ErrorKind::InvalidFilename)
}

#[test]
fn an_overlong_name_is_refused_before_any_block_is_decoded() {
    let long = "a".repeat(256);
    let mut bytes = archive(
        &[
            Member::File("ok.txt", b"FIRST-PAYLOAD-0123456789"),
            Member::File(&long, b"hi"),
        ],
        true,
    );
    common::flip_first(&mut bytes, b"FIRST-PAYLOAD");
    let mut sink = RecordingSink::default();
    let error = extract_bytes(bytes, &config(), &mut sink).unwrap_err();
    assert!(is_name_too_long(&error), "{error:?}");
    assert!(sink.finished.is_empty() && sink.tree.dirs.is_empty());
}

#[test]
fn an_overlong_directory_name_is_refused_before_any_delivery() {
    let bytes = archive(
        &[Member::File("ok.txt", b"hi"), Member::Dir(&"d".repeat(256))],
        false,
    );
    let mut sink = RecordingSink::default();
    let error = extract_bytes(bytes, &config(), &mut sink).unwrap_err();
    assert!(is_name_too_long(&error), "{error:?}");
    assert!(sink.finished.is_empty() && sink.tree.dirs.is_empty());
}

#[test]
fn an_overlong_symlink_name_is_refused_before_any_delivery() {
    let bytes = archive(
        &[
            Member::File("ok.txt", b"hi"),
            Member::Link(&"l".repeat(256), b"ok.txt"),
        ],
        false,
    );
    let mut sink = RecordingSink::default();
    let config = config().with_allow_symlinks(true);
    let error = extract_bytes(bytes, &config, &mut sink).unwrap_err();
    assert!(is_name_too_long(&error), "{error:?}");
    assert!(sink.finished.is_empty() && sink.tree.symlinks.is_empty());
}

#[test]
fn a_255_byte_name_is_accepted_and_a_256_byte_name_refused() {
    let at_limit = "a".repeat(255);
    let bytes = archive(&[Member::File(&at_limit, b"hi")], false);
    let mut sink = RecordingSink::default();
    extract_bytes(bytes, &config(), &mut sink).unwrap();
    assert!(sink.tree.files.contains_key(Path::new(&at_limit)));

    let bytes = archive(&[Member::File(&"a".repeat(256), b"hi")], false);
    let error = extract_bytes(bytes, &config(), &mut RecordingSink::default()).unwrap_err();
    assert!(is_name_too_long(&error), "{error:?}");
}

#[test]
fn the_portable_path_limit_applies_to_a_portable_sink() {
    let name = vec!["a".repeat(250); 5].join("/");
    let bytes = archive(&[Member::File(&name, b"hi")], false);
    #[cfg(target_os = "linux")]
    extract_bytes(bytes.clone(), &config(), &mut RecordingSink::default()).unwrap();

    let error = extract_bytes(bytes, &config(), &mut MemorySink::default()).unwrap_err();
    assert!(is_name_too_long(&error), "{error:?}");
}

#[test]
fn an_overlong_name_of_a_skipped_extension_is_not_refused() {
    let long = format!("{}.bin", "a".repeat(256));
    let bytes = archive(
        &[Member::File("ok.txt", b"hi"), Member::File(&long, b"hi")],
        false,
    );
    let config = config().with_allowed_extensions(vec!["txt".to_string()]);
    let mut sink = RecordingSink::default();
    let report = extract_bytes(bytes, &config, &mut sink).unwrap();
    assert_eq!(report.files_skipped, 1);
    assert_eq!(sink.finished.len(), 1);
}

#[test]
fn a_reparse_point_is_refused_before_any_delivery() {
    let bytes = archive(
        &[Member::File("a.txt", b"hi"), Member::Junction("junction")],
        false,
    );
    let mut sink = RecordingSink::default();
    let error = extract_bytes(bytes, &config(), &mut sink).unwrap_err();
    assert!(
        matches!(&error, ArchiveError::SecurityViolation { reason, .. } if reason.contains("reparse point")),
        "{error:?}"
    );
    assert!(sink.finished.is_empty());
}

#[test]
fn a_corrupt_stream_is_a_partial_extraction_and_publishes_nothing_of_the_bad_file() {
    let mut bytes = archive(
        &[
            Member::File("first.txt", b"FIRST-PAYLOAD-0123456789"),
            Member::File("second.txt", b"SECOND-PAYLOAD-0123456789"),
        ],
        true,
    );
    common::flip_first(&mut bytes, b"SECOND-PAYLOAD");
    let mut sink = RecordingSink::default();
    let error = extract_bytes(bytes, &config(), &mut sink).unwrap_err();
    assert!(
        matches!(error, ArchiveError::PartialExtraction { .. }),
        "{error:?}"
    );
    assert_eq!(sink.tree.files.len(), 1);
    assert!(sink.tree.files.contains_key(Path::new("first.txt")));
}

#[test]
fn a_symlink_through_the_sink_is_refused_without_allow_symlinks() {
    let bytes = archive(&[Member::Link("l", b"a.txt")], false);
    let mut sink = RecordingSink::default();
    let error = extract_bytes(bytes, &config(), &mut sink).unwrap_err();
    assert!(
        matches!(error, ArchiveError::SecurityViolation { .. }),
        "{error:?}"
    );
    assert!(sink.tree.symlinks.is_empty());
}

fn extract(
    sink: &mut MemorySink,
    name: &str,
) -> Result<exarch_core::ExtractionReport, ArchiveError> {
    extract_to_sink_with_progress(
        ArchiveReader::seekable(Cursor::new(fixture(name)), SeekableFormat::SevenZ),
        sink,
        &config(),
        &ExtractionOptions::default(),
        &mut Events::default(),
    )
}
