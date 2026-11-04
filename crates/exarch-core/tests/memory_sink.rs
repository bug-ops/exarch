//! `MemorySink`: round trips, the capacity limit and how it is reported.

#![allow(clippy::unwrap_used)]

mod sink_support;

use std::assert_matches;
use std::io::Cursor;
use std::num::NonZeroU64;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::EntrySink as _;
use exarch_core::ExtractionOptions;
use exarch_core::ExtractionReport;
use exarch_core::MemoryEntry;
use exarch_core::MemoryEntryKind;
use exarch_core::MemoryExtractRequest;
use exarch_core::MemoryLimit;
use exarch_core::MemorySink;
use exarch_core::NoopProgress;
use exarch_core::PartialWrites;
use exarch_core::PathModel;
use exarch_core::QuotaResource;
use exarch_core::SecurityConfig;
use exarch_core::SeekableFormat;
use exarch_core::SinkOptions;
use exarch_core::extract_reader_to_memory;
use exarch_core::extract_to_sink;
use sink_support::tar_archive;
use sink_support::tar_dir;
use sink_support::tar_entry_mode;
use sink_support::tar_file;
use sink_support::tar_hardlink;
use sink_support::tar_symlink;
use sink_support::zip_archive;
use sink_support::zip_dir;
use sink_support::zip_file;

const KIB: u64 = 1024;
const OVERHEAD: u64 = MemorySink::ENTRY_OVERHEAD;

/// What an entry at `path` with `payload` bytes is charged.
fn charge(path: &str, payload: u64) -> u64 {
    OVERHEAD + path.len() as u64 + payload
}

fn limit(bytes: u64) -> MemoryLimit {
    MemoryLimit::new(NonZeroU64::new(bytes).unwrap())
}

fn links() -> SecurityConfig {
    SecurityConfig::default()
        .with_allow_symlinks(true)
        .with_allow_hardlinks(true)
}

fn run_tar(
    entries: &[Vec<u8>],
    sink: &mut MemorySink,
    config: &SecurityConfig,
    options: SinkOptions,
) -> Result<ExtractionReport, ArchiveError> {
    extract_to_sink(
        ArchiveReader::tar(Cursor::new(tar_archive(entries)), None),
        sink,
        config,
        &options,
    )
}

fn sink_capacity(error: &ArchiveError) -> Option<u64> {
    match error {
        ArchiveError::PartialExtraction(partial) => sink_capacity(partial.cause()),
        ArchiveError::QuotaExceeded {
            resource: QuotaResource::SinkCapacity { max },
        } => Some(*max),
        _ => None,
    }
}

fn file_bytes<'a>(sink: &'a MemorySink, path: &str) -> &'a [u8] {
    match sink.get(Path::new(path)) {
        Some(MemoryEntry::File { data, .. }) => data,
        other => panic!("{path}: {other:?}"),
    }
}

fn long_dir(name: &str) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_size(0);
    header.set_mode(0o755);
    builder
        .append_data(&mut header, name, std::io::empty())
        .unwrap();
    let mut bytes = builder.into_inner().unwrap();
    bytes.truncate(bytes.len() - 1024);
    bytes
}

#[test]
fn a_tar_round_trips_files_directories_and_links() {
    let mut sink = MemorySink::default();
    let entries = [
        tar_dir("d/"),
        tar_file("d/a.txt", b"alpha"),
        tar_symlink("d/link", "a.txt"),
        tar_hardlink("d/copy", "d/a.txt"),
    ];
    let report = run_tar(&entries, &mut sink, &links(), SinkOptions::default()).unwrap();

    assert_eq!(report.files_extracted, 2);
    assert_matches!(sink.get(Path::new("d")), Some(MemoryEntry::Directory));
    assert_eq!(file_bytes(&sink, "d/a.txt"), b"alpha");
    assert_eq!(file_bytes(&sink, "d/copy"), b"alpha");
    assert_matches!(
        sink.get(Path::new("d/link")),
        Some(MemoryEntry::Symlink { target }) if target == Path::new("a.txt")
    );
    assert_eq!(
        sink.stored_bytes(),
        charge("d", 0) + charge("d/a.txt", 5) + charge("d/link", 5) + charge("d/copy", 5)
    );
}

#[test]
fn a_zip_round_trips() {
    let mut sink = MemorySink::default();
    let bytes = zip_archive(vec![zip_dir("d/"), zip_file("d/a.txt", b"alpha")]);
    extract_to_sink(
        ArchiveReader::seekable(Cursor::new(bytes), SeekableFormat::Zip),
        &mut sink,
        &SecurityConfig::default(),
        &SinkOptions::default(),
    )
    .unwrap();
    assert_eq!(file_bytes(&sink, "d/a.txt"), b"alpha");
    assert_eq!(sink.iter().count(), 2);
}

#[test]
fn into_entries_hands_over_everything() {
    let mut sink = MemorySink::default();
    run_tar(
        &[tar_file("a", b"x"), tar_file("b", b"y")],
        &mut sink,
        &SecurityConfig::default(),
        SinkOptions::default(),
    )
    .unwrap();
    let entries = sink.into_entries();
    assert_eq!(
        entries.keys().cloned().collect::<Vec<_>>(),
        [PathBuf::from("a"), PathBuf::from("b")]
    );
}

#[test]
fn exceeding_the_limit_is_a_typed_quota_error_and_wraps_after_delivery() {
    let one = charge("a", 5);
    let mut sink = MemorySink::new(limit(one + 10));
    let entries = [tar_file("a", b"12345"), tar_file("b", b"67890")];
    let error = run_tar(
        &entries,
        &mut sink,
        &SecurityConfig::default(),
        SinkOptions::default(),
    )
    .unwrap_err();

    assert_matches!(error, ArchiveError::PartialExtraction(_));
    assert_eq!(sink_capacity(&error), Some(one + 10), "{error:?}");
    assert_eq!(file_bytes(&sink, "a"), b"12345");
    assert!(sink.get(Path::new("b")).is_none());
    assert_eq!(sink.stored_bytes(), one);
}

#[test]
fn the_first_entry_over_the_limit_is_not_wrapped() {
    let mut sink = MemorySink::new(limit(4));
    let error = run_tar(
        &[tar_file("a", b"12345")],
        &mut sink,
        &SecurityConfig::default(),
        SinkOptions::default(),
    )
    .unwrap_err();
    assert_matches!(
        error,
        ArchiveError::QuotaExceeded {
            resource: QuotaResource::SinkCapacity { max: 4 }
        }
    );
    assert_eq!(sink.iter().count(), 0);
}

#[test]
fn a_declared_size_over_the_limit_is_refused_before_any_allocation() {
    const GIB: u64 = 1024 * 1024 * 1024;
    let mut header = tar::Header::new_gnu();
    header.set_size(4 * GIB);
    header.set_mode(0o644);
    header.as_old_mut().name[..4].copy_from_slice(b"huge");
    header.set_cksum();
    let config = SecurityConfig::default()
        .with_max_file_size(exarch_core::non_zero!(8 * GIB))
        .with_max_total_size(exarch_core::non_zero!(8 * GIB));
    let mut sink = MemorySink::new(limit(KIB));
    let error = run_tar(
        &[header.as_bytes().to_vec()],
        &mut sink,
        &config,
        SinkOptions::default(),
    )
    .unwrap_err();
    assert_eq!(sink_capacity(&error), Some(KIB), "{error:?}");
}

#[test]
fn overwriting_a_file_near_the_limit_releases_the_old_bytes() {
    let one = charge("a", 9);
    let mut sink = MemorySink::new(limit(one + 4));
    let options = SinkOptions::default().with_skip_duplicates(false);
    run_tar(
        &[tar_file("a", b"123456789"), tar_file("a", b"abcdefghi")],
        &mut sink,
        &SecurityConfig::default(),
        options,
    )
    .unwrap();
    assert_eq!(file_bytes(&sink, "a"), b"abcdefghi");
    assert_eq!(sink.stored_bytes(), one);
}

#[test]
fn a_symlink_over_a_file_frees_the_file_bytes() {
    let mut sink = MemorySink::new(limit(KIB));
    let options = SinkOptions::default().with_skip_duplicates(false);
    run_tar(
        &[tar_file("l", &[7; 50]), tar_symlink("l", "t")],
        &mut sink,
        &links(),
        options,
    )
    .unwrap();
    assert_eq!(sink.stored_bytes(), charge("l", 1));
    assert_matches!(sink.get(Path::new("l")), Some(MemoryEntry::Symlink { .. }));
}

#[test]
fn a_hardlink_copy_counts_against_the_limit() {
    let entries = [tar_file("t", &[1; 40]), tar_hardlink("h", "t")];
    let both = charge("t", 40) + charge("h", 40);
    let mut roomy = MemorySink::new(limit(both));
    run_tar(&entries, &mut roomy, &links(), SinkOptions::default()).unwrap();
    assert_eq!(roomy.stored_bytes(), both);

    let mut tight = MemorySink::new(limit(both - 1));
    let error = run_tar(&entries, &mut tight, &links(), SinkOptions::default()).unwrap_err();
    assert_eq!(sink_capacity(&error), Some(both - 1), "{error:?}");
    assert!(tight.get(Path::new("h")).is_none());
    assert_eq!(tight.stored_bytes(), charge("t", 40));
}

#[test]
fn symlink_targets_count_against_the_limit() {
    let mut sink = MemorySink::new(limit(OVERHEAD + 3));
    let error = run_tar(
        &[tar_symlink("l", "long-target")],
        &mut sink,
        &links(),
        SinkOptions::default(),
    )
    .unwrap_err();
    assert_eq!(sink_capacity(&error), Some(OVERHEAD + 3), "{error:?}");
}

#[test]
fn a_flood_of_long_directory_names_fills_the_sink_instead_of_growing_it() {
    let budget = 64 * KIB;
    let mut sink = MemorySink::new(limit(budget));
    let entries: Vec<_> = (0..2000)
        .map(|i| long_dir(&format!("{i:0>200}/")))
        .collect();
    let error = run_tar(
        &entries,
        &mut sink,
        &SecurityConfig::default(),
        SinkOptions::default(),
    )
    .unwrap_err();
    assert_eq!(sink_capacity(&error), Some(budget), "{error:?}");
    assert!(sink.stored_bytes() <= budget);
    assert!(sink.iter().count() < 2000);
    assert!(sink.iter().count() > 50);
}

#[test]
fn a_directory_alone_is_charged_its_path_and_the_overhead() {
    let mut sink = MemorySink::default();
    run_tar(
        &[tar_dir("some/dir/")],
        &mut sink,
        &SecurityConfig::default(),
        SinkOptions::default(),
    )
    .unwrap();
    assert_eq!(sink.stored_bytes(), charge("some/dir", 0));
}

#[test]
fn a_stored_file_keeps_no_spare_capacity() {
    let mut sink = MemorySink::default();
    let payload = vec![3_u8; 70_000];
    run_tar(
        &[tar_file("big", &payload)],
        &mut sink,
        &SecurityConfig::default(),
        SinkOptions::default(),
    )
    .unwrap();
    match sink.get(Path::new("big")) {
        Some(MemoryEntry::File { data, .. }) => {
            assert_eq!(data.len(), payload.len());
            assert_eq!(data.capacity(), data.len());
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn setuid_and_setgid_are_stripped_from_the_stored_mode() {
    for preserve in [true, false] {
        let mut sink = MemorySink::default();
        let config = SecurityConfig::default().with_preserve_permissions(preserve);
        run_tar(
            &[tar_entry_mode(
                "f",
                tar::EntryType::Regular,
                b"x",
                None,
                0o6755,
            )],
            &mut sink,
            &config,
            SinkOptions::default(),
        )
        .unwrap();
        match sink.get(Path::new("f")) {
            Some(MemoryEntry::File { mode, .. }) => {
                let bits = mode.map(exarch_core::SanitizedMode::as_u32);
                assert!(
                    bits.is_none_or(|bits| bits & 0o6000 == 0),
                    "preserve={preserve}: {bits:?}"
                );
                if preserve {
                    assert_eq!(bits.map(|b| b & 0o777), Some(0o755));
                }
            }
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn the_limit_follows_the_config_quota() {
    let config = SecurityConfig::default().with_max_total_size(exarch_core::non_zero!(2048));
    assert_eq!(MemoryLimit::from_config(&config).bytes().get(), 2048);
    let mut sink = MemorySink::new(MemoryLimit::from_config(&config));
    run_tar(
        &[tar_file("a", &[0; 1024])],
        &mut sink,
        &config,
        SinkOptions::default(),
    )
    .unwrap();
    assert_eq!(sink.stored_bytes(), charge("a", 1024));
}

#[test]
fn an_unbounded_quota_gives_the_largest_limit() {
    let config = SecurityConfig::default().with_max_total_size(exarch_core::Limit::Unbounded);
    assert_eq!(MemoryLimit::from_config(&config).bytes().get(), u64::MAX);
}

#[test]
fn a_failed_file_publishes_nothing() {
    let mut sink = MemorySink::default();
    let mut header = tar::Header::new_gnu();
    header.set_size(100);
    header.set_mode(0o644);
    header.as_old_mut().name[..1].copy_from_slice(b"t");
    header.set_cksum();
    let mut truncated = header.as_bytes().to_vec();
    truncated.extend_from_slice(&[9; 10]);
    let result = extract_to_sink(
        ArchiveReader::tar(Cursor::new(truncated), None),
        &mut sink,
        &SecurityConfig::default(),
        &SinkOptions::default(),
    );
    assert!(result.is_err());
    assert!(sink.get(Path::new("t")).is_none());
    assert_eq!(sink.stored_bytes(), 0);
}

#[test]
fn extract_reader_to_memory_detects_the_format_and_applies_the_default_limit() {
    let bytes = tar_archive(&[tar_dir("d/"), tar_file("d/a.txt", b"alpha")]);

    let (report, sink) = extract_reader_to_memory(
        ArchiveReader::from_bytes(bytes, None).unwrap(),
        &MemoryExtractRequest::default(),
        &mut NoopProgress,
    )
    .unwrap();

    assert_eq!(report.files_extracted, 1);
    assert_eq!(
        sink.limit(),
        MemoryLimit::from_config(&SecurityConfig::default())
    );
    assert_eq!(
        sink.get(Path::new("d")).map(MemoryEntry::kind),
        Some(MemoryEntryKind::Directory)
    );
    assert_eq!(
        sink.get(Path::new("d/a.txt")).map(MemoryEntry::kind),
        Some(MemoryEntryKind::File)
    );
}

#[test]
fn extract_reader_to_memory_reports_discarded_writes_after_delivered_entries() {
    let bytes = tar_archive(&[tar_file("a", b"x"), tar_file("../b", b"y")]);

    let error = extract_reader_to_memory(
        ArchiveReader::from_bytes(bytes, None).unwrap(),
        &MemoryExtractRequest::default(),
        &mut NoopProgress,
    )
    .unwrap_err();

    assert_matches!(
        &error,
        ArchiveError::PartialExtraction(partial) if partial.writes() == PartialWrites::Discarded,
        "{error:?}"
    );
}

#[test]
fn extract_reader_to_memory_honours_an_explicit_limit() {
    let bytes = tar_archive(&[tar_file("a", b"0123456789")]);

    let error = extract_reader_to_memory(
        ArchiveReader::from_bytes(bytes, None).unwrap(),
        &MemoryExtractRequest::default().with_limit(limit(4)),
        &mut NoopProgress,
    )
    .unwrap_err();

    assert_eq!(sink_capacity(&error), Some(4), "{error:?}");
}

#[test]
fn extract_reader_to_memory_derives_the_default_limit_from_the_request_config() {
    let request = MemoryExtractRequest::default()
        .with_config(SecurityConfig::default().with_max_total_size(exarch_core::non_zero!(4096)))
        .with_path_model(PathModel::Portable);

    let (_, sink) = extract_reader_to_memory(
        ArchiveReader::from_bytes(tar_archive(&[tar_file("a", b"x")]), None).unwrap(),
        &request,
        &mut NoopProgress,
    )
    .unwrap();

    assert_eq!(sink.limit(), limit(4096));
    assert_eq!(sink.path_model(), PathModel::Portable);
}

#[cfg(unix)]
#[test]
fn extract_reader_to_memory_applies_the_request_path_model() {
    let archive = || tar_archive(&[tar_file("a?b", b"x")]);
    let reader = |bytes| ArchiveReader::from_bytes(bytes, None).unwrap();

    let (_, host) = extract_reader_to_memory(
        reader(archive()),
        &MemoryExtractRequest::default(),
        &mut NoopProgress,
    )
    .unwrap();
    assert!(host.get(Path::new("a?b")).is_some());

    let request = MemoryExtractRequest::default().with_path_model(PathModel::Portable);
    let error =
        extract_reader_to_memory(reader(archive()), &request, &mut NoopProgress).unwrap_err();
    assert!(error.to_string().contains("not portable"), "{error}");
}

#[test]
fn extract_reader_to_memory_applies_the_request_options() {
    let archive = || tar_archive(&[tar_file("a", b"first"), tar_file("a", b"second")]);
    let data_of = |request: &MemoryExtractRequest| {
        let (_, sink) = extract_reader_to_memory(
            ArchiveReader::from_bytes(archive(), None).unwrap(),
            request,
            &mut NoopProgress,
        )
        .unwrap();
        match sink.get(Path::new("a")) {
            Some(MemoryEntry::File { data, .. }) => data.clone(),
            other => panic!("unexpected entry: {other:?}"),
        }
    };

    assert_eq!(data_of(&MemoryExtractRequest::default()), b"first");
    let overwrite = MemoryExtractRequest::default()
        .with_options(SinkOptions::default().with_skip_duplicates(false));
    assert_eq!(data_of(&overwrite), b"second");
}

#[test]
fn sink_options_keep_the_duplicate_policy_and_refuse_atomic() {
    let overwrite = ExtractionOptions::default().with_skip_duplicates(false);
    assert!(!SinkOptions::try_from(&overwrite).unwrap().skip_duplicates);
    assert!(
        SinkOptions::try_from(&ExtractionOptions::default())
            .unwrap()
            .skip_duplicates
    );
    assert_matches!(
        SinkOptions::try_from(&ExtractionOptions::default().with_atomic(true)),
        Err(ArchiveError::InvalidConfiguration { .. })
    );
}
