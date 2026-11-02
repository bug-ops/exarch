//! A directory entry that declares a payload is refused by every extraction
//! entry point, including the in-memory one.

#![allow(clippy::unwrap_used)]

use std::assert_matches;

use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::MemoryExtractRequest;
use exarch_core::NoopProgress;
use exarch_core::SecurityConfig;
use exarch_core::ZipConsistencyPolicy;
use exarch_core::ZipInconsistency;
use exarch_core::ZipNonRegularKind;
use exarch_core::extract_archive;
use exarch_core::extract_reader_to_memory;
use exarch_testkit::raw_zip::RawEntry;
use exarch_testkit::raw_zip::RawZip;
use tempfile::TempDir;

fn directory_with_data() -> Vec<u8> {
    let mut entry = RawEntry::stored("d/", b"x\nsome payload\n");
    entry.external_attributes = 0o040_755 << 16;
    RawZip::new(vec![entry, RawEntry::stored("d/b.txt", b"world")])
        .build()
        .bytes
}

fn ignoring() -> MemoryExtractRequest {
    MemoryExtractRequest::default()
        .with_config(SecurityConfig::default().with_zip_consistency(ZipConsistencyPolicy::Ignore))
}

#[test]
fn memory_extraction_refuses_a_directory_with_data() {
    let error = extract_reader_to_memory(
        ArchiveReader::from_bytes(directory_with_data(), None).unwrap(),
        &MemoryExtractRequest::default(),
        &mut NoopProgress,
    )
    .unwrap_err();
    assert_matches!(
        error,
        ArchiveError::ZipInconsistency(ZipInconsistency::NonRegularPayload {
            kind: ZipNonRegularKind::Directory,
            ..
        }),
        "{error:?}"
    );
}

#[test]
fn memory_extraction_accepts_it_when_the_policy_is_ignore() {
    let (report, _) = extract_reader_to_memory(
        ArchiveReader::from_bytes(directory_with_data(), None).unwrap(),
        &ignoring(),
        &mut NoopProgress,
    )
    .unwrap();
    assert_eq!(report.files_extracted, 1);
}

#[test]
fn path_extraction_refuses_a_directory_with_data_and_writes_nothing() {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.zip");
    std::fs::write(&archive, directory_with_data()).unwrap();
    let out = TempDir::new().unwrap();

    let error = extract_archive(&archive, out.path(), &SecurityConfig::default()).unwrap_err();

    assert_matches!(
        error,
        ArchiveError::ZipInconsistency(ZipInconsistency::NonRegularPayload { .. })
    );
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}
