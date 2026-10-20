#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::assert_matches;
use std::io::Cursor;

use tempfile::TempDir;

use super::*;
use crate::ExtractionOptions;
use crate::IssueCategory;
use crate::NoopProgress;
use crate::QuotaResource;
use crate::SecurityConfig;
use crate::VerificationOptions;
use crate::ZipConsistencyPolicy;
use crate::config::Validated;
use crate::formats::ZipArchive;
use crate::formats::traits::ArchiveFormat;
use crate::inspection::report::VerificationStatus;
use crate::raw_zip::BuiltZip;
use crate::raw_zip::RawEntry;
use crate::raw_zip::RawZip;
use crate::raw_zip::deflate_zeros;
use crate::test_utils::create_test_zip;

fn config(policy: ZipConsistencyPolicy) -> SecurityConfig<Validated> {
    SecurityConfig::default()
        .with_zip_consistency(policy)
        .validate()
        .unwrap()
}

fn open_bytes(bytes: Vec<u8>) -> ZipArchive<Cursor<Vec<u8>>> {
    ZipArchive::new(Cursor::new(bytes)).unwrap()
}

fn findings_of(built: &BuiltZip) -> Vec<ZipInconsistency> {
    let archive = open_bytes(built.bytes.clone());
    archive.structure().findings().to_vec()
}

fn two_files() -> RawZip {
    RawZip::new(vec![
        RawEntry::stored("a.txt", b"hello"),
        RawEntry::stored("b.txt", b"world"),
    ])
}

fn patch(built: &mut BuiltZip, entry: usize, at: usize, bytes: &[u8]) {
    let start = built.local_offsets[entry] + at;
    built.bytes[start..start + bytes.len()].copy_from_slice(bytes);
}

fn mismatch(field: ZipHeaderField) -> ZipInconsistency {
    ZipInconsistency::HeaderMismatch {
        entry: ZipEntryIndex::new(0),
        field,
        name: "a.txt".into(),
    }
}

fn unicode_path_extra(name: &[u8]) -> Vec<u8> {
    let mut crc = flate2::Crc::new();
    crc.update(name);
    let mut body = vec![1u8];
    body.extend_from_slice(&crc.sum().to_le_bytes());
    body.extend_from_slice(name);
    let mut extra = 0x7075u16.to_le_bytes().to_vec();
    extra.extend_from_slice(&u16::try_from(body.len()).unwrap().to_le_bytes());
    extra.extend(body);
    extra
}

fn extended_timestamp_with_bad_flags() -> Vec<u8> {
    let mut extra = 0x5455u16.to_le_bytes().to_vec();
    extra.extend_from_slice(&9u16.to_le_bytes());
    extra.push(0x07);
    extra.extend_from_slice(&[0; 8]);
    extra
}

#[test]
fn clean_archives_have_no_findings() {
    let created = create_test_zip(vec![("a.txt", b"hello"), ("dir/b.txt", b"world")]);
    assert!(open_bytes(created).structure().findings().is_empty());

    let empty = RawZip::new(Vec::new()).build();
    assert!(findings_of(&empty).is_empty());

    for (signature, zip64) in [(true, false), (false, false), (true, true), (false, true)] {
        let built = RawZip::new(vec![
            RawEntry::stored("a.txt", b"hello").with_descriptor(signature, zip64),
            RawEntry::stored("b.txt", b"world").with_descriptor(signature, zip64),
        ])
        .build();
        let archive = open_bytes(built.bytes);
        assert!(archive.structure().findings().is_empty());
        assert_eq!(archive.structure().gap_reads(), 0, "{signature} {zip64}");
    }
}

#[test]
fn every_header_field_mismatch_is_named() {
    let cases: [(&str, usize, &[u8], ZipHeaderField); 8] = [
        ("file name", 30, b"b", ZipHeaderField::FileName),
        ("method", 8, &[8, 0], ZipHeaderField::CompressionMethod),
        ("encryption", 6, &[1, 0], ZipHeaderField::EncryptionFlag),
        (
            "descriptor flag",
            6,
            &[8, 0],
            ZipHeaderField::DataDescriptorFlag,
        ),
        ("time", 10, &[1, 0], ZipHeaderField::ModifiedTime),
        ("crc", 14, &[1, 2, 3, 4], ZipHeaderField::Crc32),
        (
            "compressed",
            18,
            &[9, 0, 0, 0],
            ZipHeaderField::CompressedSize,
        ),
        ("size", 22, &[9, 0, 0, 0], ZipHeaderField::UncompressedSize),
    ];
    for (label, at, bytes, field) in cases {
        let mut built = two_files().build();
        patch(&mut built, 0, at, bytes);
        assert_eq!(findings_of(&built), [mismatch(field)], "{label}");
    }
}

#[test]
fn local_unicode_path_field_is_a_mismatch() {
    let mut entry = RawEntry::stored("a.txt", b"hello");
    entry.local_extra = unicode_path_extra(b"other.txt");
    let built = RawZip::new(vec![entry]).build();
    assert_eq!(findings_of(&built), [mismatch(ZipHeaderField::UnicodePath)]);
}

#[test]
fn unparseable_local_extra_field_is_recorded_not_fatal() {
    let mut entry = RawEntry::stored("a.txt", b"hello");
    entry.local_extra = extended_timestamp_with_bad_flags();
    let built = RawZip::new(vec![entry]).build();
    assert_eq!(findings_of(&built), [mismatch(ZipHeaderField::Unparseable)]);
}

#[test]
fn entry_with_a_header_mismatch_is_still_admitted() {
    let mut forged = RawEntry::stored("a.txt", b"hello");
    forged.local_extra = extended_timestamp_with_bad_flags();
    forged.declared_compressed = Some(1 << 20);
    let budget = ZipArchive::new(Cursor::new(RawZip::new(vec![forged]).build().bytes)).map(drop);
    assert_matches!(budget, Err(ArchiveError::InvalidArchive(_)));

    let mut unsupported = RawEntry::stored("a.txt", b"hello");
    unsupported.local_extra = extended_timestamp_with_bad_flags();
    unsupported.method = 9;
    let method =
        ZipArchive::new(Cursor::new(RawZip::new(vec![unsupported]).build().bytes)).map(drop);
    assert_matches!(method, Err(ArchiveError::SecurityViolation { .. }));
}

#[test]
fn duplicate_names_are_found_even_though_the_crate_collapses_them() {
    let built = RawZip::new(vec![
        RawEntry::stored("a.txt", b"first"),
        RawEntry::stored("b.txt", b"other"),
        RawEntry::stored("a.txt", b"EVIL"),
    ])
    .build();
    let mut archive = open_bytes(built.bytes);
    assert_eq!(archive.reader_mut().len(), 2);
    assert_eq!(archive.structure().central_entries(), 3);
    assert_eq!(
        archive.structure().findings(),
        [ZipInconsistency::DuplicateName {
            record: CentralRecordOrdinal::new(0),
            name: "a.txt".into()
        }]
    );
}

#[test]
fn central_records_past_the_end_count_are_found() {
    let mut zip = two_files();
    zip.end_count = Some(1);
    let built = zip.build();
    let mut archive = open_bytes(built.bytes.clone());
    assert_eq!(archive.reader_mut().len(), 1);
    assert_eq!(archive.structure().central_entries(), 2);
    assert_eq!(
        archive.structure().findings(),
        [
            ZipInconsistency::HiddenLocalHeader {
                offset: built.local_offsets[1] as u64
            },
            ZipInconsistency::UncountedCentralRecords {
                counted: 1,
                found: 2
            },
        ]
    );
}

#[test]
fn local_header_without_a_central_record_is_found() {
    let evil = RawZip::new(vec![RawEntry::stored("evil.sh", b"echo pwned\n")]).build();
    let mut zip = RawZip::new(vec![RawEntry::stored("benign.txt", b"hello")]);
    zip.before_directory = evil.bytes[..evil.directory_start].to_vec();
    let built = zip.build();
    assert_eq!(
        findings_of(&built),
        [ZipInconsistency::HiddenLocalHeader {
            offset: built.directory_start as u64 - evil.directory_start as u64
        }]
    );
}

#[test]
fn local_header_after_a_descriptor_is_found_at_every_descriptor_width() {
    let evil = RawZip::new(vec![RawEntry::stored("evil.sh", b"echo pwned\n")]).build();
    for (signature, zip64, width) in [
        (true, false, 16u64),
        (false, false, 12),
        (true, true, 24),
        (false, true, 20),
    ] {
        let entry = RawEntry::stored("a.txt", b"hello").with_descriptor(signature, zip64);
        let mut zip = RawZip::new(vec![entry]);
        zip.before_directory = evil.bytes[..evil.directory_start].to_vec();
        let built = zip.build();
        let archive = open_bytes(built.bytes.clone());
        let end = built.local_offsets[0] as u64 + 30 + 5 + if zip64 { 20 } else { 0 } + 5;
        assert_eq!(
            archive.structure().findings(),
            [ZipInconsistency::HiddenLocalHeader {
                offset: end + width
            }],
            "{signature} {zip64}"
        );
    }
}

#[test]
fn descriptor_size_equal_to_the_header_magic_is_not_a_hidden_header() {
    const MAGIC_AS_SIZE: u64 = 0x0403_4b50;
    let mut entry = RawEntry::stored("zeros.bin", b"").with_descriptor(true, false);
    entry.data = deflate_zeros(MAGIC_AS_SIZE);
    entry.method = 8;
    entry.size = MAGIC_AS_SIZE;
    let built = RawZip::new(vec![entry]).build();
    let archive = open_bytes(built.bytes);
    assert!(archive.structure().findings().is_empty());
    assert_eq!(archive.structure().gap_reads(), 0);
}

#[test]
fn gaps_and_prefixes_that_hold_no_header_are_not_reported() {
    let apk_like = RawZip::new(vec![
        RawEntry::stored("a.txt", b"hello").with_padding_after(64),
        RawEntry::stored("b.txt", b"world").with_padding_after(64),
    ])
    .build();
    let archive = open_bytes(apk_like.bytes);
    assert!(archive.structure().findings().is_empty());
    assert_eq!(archive.structure().gap_reads(), 2);

    let mut with_stub = vec![b'#'; 100];
    with_stub.extend(two_files().build().bytes);
    assert!(open_bytes(with_stub).structure().findings().is_empty());
}

#[test]
fn overlapping_entries_are_found() {
    let mut built = two_files().build();
    let second_record = built.directory_start + (46 + "a.txt".len());
    let first_offset = u32::try_from(built.local_offsets[0]).unwrap().to_le_bytes();
    built.bytes[second_record + 42..second_record + 46].copy_from_slice(&first_offset);
    assert!(findings_of(&built).contains(&ZipInconsistency::OverlappingEntries));
}

#[test]
fn field_classification_ignores_names_embedded_in_messages() {
    let message = |text: &'static str| ZipError::InvalidArchive(text.into());
    assert_eq!(
        classify(&message(
            "header inconsistency detected: encryption flag mismatch for 'CRC32 checksum mismatch'"
        )),
        ZipHeaderField::EncryptionFlag
    );
    assert_eq!(
        classify(&message("header inconsistency detected: a new check")),
        ZipHeaderField::Unrecognized
    );
    assert_eq!(
        classify(&message("something else entirely")),
        ZipHeaderField::Unparseable
    );
    assert_eq!(
        classify(&ZipError::Io(std::io::Error::other("x"))),
        ZipHeaderField::Unparseable
    );
}

#[test]
fn census_fails_closed_when_it_disagrees_with_the_reader() {
    let built = two_files().build();
    let mut cursor = Cursor::new(built.bytes);
    let map = DirectoryMap {
        directory_start: built.directory_start as u64,
        archive_offset: 0,
        central_starts: vec![
            built.directory_start as u64,
            built.directory_start as u64 + 3,
        ],
    };
    let result = Census::run(&mut cursor, &map, &Scan::default());
    assert_matches!(result, Err(ArchiveError::InvalidArchive(msg)) if msg.contains("census"));

    let map = DirectoryMap {
        directory_start: built.directory_start as u64,
        archive_offset: 0,
        central_starts: vec![built.directory_start as u64],
    };
    let scan = Scan {
        crate_duplicates: true,
        ..Scan::default()
    };
    assert_matches!(
        Census::run(&mut cursor, &map, &scan),
        Err(ArchiveError::InvalidArchive(_))
    );
}

fn name_mismatch_zip() -> Vec<u8> {
    RawZip::new(vec![
        RawEntry::stored("cron_worker.sh", b"payload").with_central_name("doc_report.pdf"),
    ])
    .build()
    .bytes
}

#[test]
fn enforce_rejects_before_creating_the_destination() {
    let temp = TempDir::new().unwrap();
    let dest = temp.path().join("out");
    let mut archive = open_bytes(name_mismatch_zip());
    let err = archive
        .extract(
            &dest,
            &config(ZipConsistencyPolicy::Enforce),
            &ExtractionOptions::default(),
            &mut NoopProgress,
        )
        .unwrap_err();
    assert_matches!(
        err,
        ArchiveError::ZipInconsistency(ZipInconsistency::HeaderMismatch {
            field: ZipHeaderField::FileName,
            ..
        })
    );
    assert!(!dest.exists());
}

#[test]
fn ignore_keeps_the_central_directory_interpretation() {
    let temp = TempDir::new().unwrap();
    let mut archive = open_bytes(name_mismatch_zip());
    let ignore = config(ZipConsistencyPolicy::Ignore);
    archive
        .extract(
            temp.path(),
            &ignore,
            &ExtractionOptions::default(),
            &mut NoopProgress,
        )
        .unwrap();
    assert!(temp.path().join("doc_report.pdf").exists());

    let manifest = archive.list(&ignore).unwrap();
    assert_eq!(manifest.total_entries(), 1);
}

#[test]
fn list_rejects_under_enforce() {
    let mut archive = open_bytes(name_mismatch_zip());
    assert_matches!(
        archive.list(&config(ZipConsistencyPolicy::Enforce)),
        Err(ArchiveError::ZipInconsistency(_))
    );
}

#[test]
fn verify_reports_findings_and_the_true_entry_count() {
    let duplicate = RawZip::new(vec![
        RawEntry::stored("a.txt", b"first"),
        RawEntry::stored("a.txt", b"EVIL"),
    ])
    .build()
    .bytes;

    let report = open_bytes(duplicate.clone())
        .verify(
            &config(ZipConsistencyPolicy::Enforce),
            &VerificationOptions::default(),
        )
        .unwrap();
    assert_eq!(report.total_entries(), 2);
    assert_ne!(report.status(), VerificationStatus::Pass);
    assert!(
        report
            .issues()
            .iter()
            .any(|i| i.category == IssueCategory::DuplicateEntry)
    );

    let report = open_bytes(duplicate)
        .verify(
            &config(ZipConsistencyPolicy::Ignore),
            &VerificationOptions::default(),
        )
        .unwrap();
    assert_eq!(report.total_entries(), 2);
    assert_eq!(report.status(), VerificationStatus::Pass);
}

#[test]
fn uncounted_records_are_visible_to_verify() {
    let mut zip = two_files();
    zip.end_count = Some(1);
    let report = open_bytes(zip.build().bytes)
        .verify(
            &config(ZipConsistencyPolicy::Enforce),
            &VerificationOptions::default(),
        )
        .unwrap();
    assert_eq!(report.total_entries(), 2);
    assert!(
        report
            .issues()
            .iter()
            .any(|i| i.category == IssueCategory::HiddenEntry)
    );
    assert_matches!(
        open_bytes(zip.build().bytes).list(&config(ZipConsistencyPolicy::Enforce)),
        Err(ArchiveError::ZipInconsistency(_))
    );
}

#[test]
fn header_mismatch_counts_once_with_the_entrys_own_issues() {
    let mut setuid = RawEntry::stored("a.txt", b"hello");
    setuid.external_attributes = 0o104_755 << 16;
    let mut built = RawZip::new(vec![setuid, RawEntry::stored("b.txt", b"world")]).build();
    patch(&mut built, 0, 30, b"x");
    let report = open_bytes(built.bytes)
        .verify(
            &config(ZipConsistencyPolicy::Enforce),
            &VerificationOptions::default(),
        )
        .unwrap();
    assert_eq!(report.total_entries(), 2);
    assert_eq!(report.suspicious_entries(), 1);
    let mismatch = report
        .issues()
        .iter()
        .find(|i| i.category == IssueCategory::HeaderMismatch)
        .unwrap();
    assert_eq!(mismatch.entry_path.as_deref(), Some("a.txt".as_ref()));
}

#[test]
fn raw_record_count_is_limited_whatever_the_policy() {
    let record = RawEntry::stored("a.txt", b"x");
    let mut zip = RawZip::new(vec![record.clone()]);
    zip.extra_central_records = (1..20_000).map(|_| (record.clone(), 0)).collect();
    zip.end_count = Some(20_000);
    let bytes = zip.build().bytes;

    for policy in [ZipConsistencyPolicy::Enforce, ZipConsistencyPolicy::Ignore] {
        let config = config(policy);
        let expected = |r: Result<()>| {
            assert_matches!(
                r,
                Err(ArchiveError::QuotaExceeded {
                    resource: QuotaResource::FileCount {
                        current: 20_000,
                        max: 10_000
                    }
                })
            );
        };
        expected(
            open_bytes(bytes.clone())
                .verify(&config, &VerificationOptions::default())
                .map(drop),
        );
        expected(open_bytes(bytes.clone()).list(&config).map(drop));
        let temp = TempDir::new().unwrap();
        expected(
            open_bytes(bytes.clone())
                .extract(
                    temp.path(),
                    &config,
                    &ExtractionOptions::default(),
                    &mut NoopProgress,
                )
                .map(drop),
        );
    }
}

#[test]
fn findings_are_capped_per_kind() {
    let record = RawEntry::stored("a.txt", b"x");
    let mut zip = RawZip::new(vec![record.clone()]);
    zip.extra_central_records = (1..200).map(|_| (record.clone(), 0)).collect();
    let archive = open_bytes(zip.build().bytes);
    assert_eq!(archive.structure().findings().len(), 16);
    assert_eq!(archive.structure().omitted_findings(), 199 - 16);
    assert_eq!(archive.structure().central_entries(), 200);
}

fn evil_local() -> Vec<u8> {
    let evil = RawZip::new(vec![RawEntry::stored("evil.sh", b"echo pwned\n")]).build();
    evil.bytes[..evil.directory_start].to_vec()
}

fn hidden_at(offset: usize) -> ZipInconsistency {
    ZipInconsistency::HiddenLocalHeader {
        offset: offset as u64,
    }
}

#[test]
fn local_header_at_file_start_before_the_archive_is_found() {
    let mut bytes = evil_local();
    bytes.extend(two_files().build().bytes);
    let archive = open_bytes(bytes);
    assert_eq!(archive.structure().findings(), [hidden_at(0)]);
}

#[test]
fn local_header_after_padding_is_found() {
    let local = evil_local();
    for (label, padding) in [
        ("one zero byte", vec![0u8]),
        ("signature prefix", b"PK".to_vec()),
        ("hundred bytes", vec![0u8; 100]),
    ] {
        let mut zip = RawZip::new(vec![RawEntry::stored("a.txt", b"hello")]);
        zip.before_directory = [padding.clone(), local.clone()].concat();
        let built = zip.build();
        let end = built.directory_start - local.len() - padding.len();
        assert_eq!(
            findings_of(&built),
            [hidden_at(end + padding.len())],
            "{label}"
        );
    }
}

#[test]
fn local_header_between_two_entries_is_found() {
    let local = evil_local();
    let mut first = RawEntry::stored("a.txt", b"hello");
    first.padding_after = 3;
    let mut built = RawZip::new(vec![first, RawEntry::stored("b.txt", b"world")]).build();
    let at = built.local_offsets[1];
    built.bytes.splice(at..at, local.clone());
    // Shift the second record's local offset past the inserted header.
    let shift = u32::try_from(local.len()).unwrap();
    let second_record = built.directory_start + local.len() + (46 + "a.txt".len());
    let old = u32::from_le_bytes(
        built.bytes[second_record + 42..second_record + 46]
            .try_into()
            .unwrap(),
    );
    built.bytes[second_record + 42..second_record + 46]
        .copy_from_slice(&(old + shift).to_le_bytes());
    let eocd = built.bytes.len() - 22;
    let dir = u32::from_le_bytes(built.bytes[eocd + 16..eocd + 20].try_into().unwrap());
    built.bytes[eocd + 16..eocd + 20].copy_from_slice(&(dir + shift).to_le_bytes());
    let found = open_bytes(built.bytes).structure().findings().to_vec();
    assert_eq!(found, [hidden_at(at)]);
}

#[test]
fn embedded_signature_in_a_stub_or_gap_is_not_a_hidden_header() {
    let mut stub = b"#!/bin/sh\n".to_vec();
    stub.extend_from_slice(b"PK\x03\x04");
    stub.extend(vec![b'#'; 100]);
    stub.extend(two_files().build().bytes);
    assert!(open_bytes(stub).structure().findings().is_empty());

    let mut zip = RawZip::new(vec![RawEntry::stored("a.txt", b"hello")]);
    let mut gap = b"PK\x03\x04".to_vec();
    gap.extend(vec![0u8; 60]);
    zip.before_directory = gap;
    assert!(findings_of(&zip.build()).is_empty());
}

#[test]
fn large_gaps_are_searched_across_read_boundaries() {
    let local = evil_local();
    for padding in [GAP_CHUNK - 1, GAP_CHUNK, GAP_CHUNK + 5] {
        let mut zip = RawZip::new(vec![RawEntry::stored("a.txt", b"hello")]);
        zip.before_directory = [vec![0u8; padding], local.clone()].concat();
        let built = zip.build();
        let archive = open_bytes(built.bytes.clone());
        let at = built.directory_start - local.len();
        assert_eq!(archive.structure().findings(), [hidden_at(at)], "{padding}");
        assert!(archive.structure().gap_reads() >= 2);
    }
}

#[test]
fn contiguous_archives_need_no_gap_read() {
    for bytes in [
        two_files().build().bytes,
        with_prefix_stub(two_files().build().bytes),
    ] {
        let archive = open_bytes(bytes);
        assert!(archive.structure().findings().is_empty());
        assert!(archive.structure().gap_reads() <= 1);
    }
    assert_eq!(
        open_bytes(two_files().build().bytes)
            .structure()
            .gap_reads(),
        0
    );
}

fn with_prefix_stub(archive: Vec<u8>) -> Vec<u8> {
    [b"MZ stub ".repeat(10), archive].concat()
}

#[test]
fn many_header_mismatches_do_not_push_out_other_findings() {
    let local = evil_local();
    let entries: Vec<_> = (0..40)
        .map(|i| RawEntry::stored(&format!("f{i:02}.txt"), b"x"))
        .collect();
    let mut zip = RawZip::new(entries);
    zip.before_directory = local;
    zip.end_count = Some(39);
    let mut built = zip.build();
    for entry in 0..40 {
        patch(&mut built, entry, 30, b"g");
    }
    let archive = open_bytes(built.bytes);
    let found = archive.structure().findings();
    assert!(
        found
            .iter()
            .any(|f| matches!(f, ZipInconsistency::HiddenLocalHeader { .. }))
    );
    assert!(
        found
            .iter()
            .any(|f| matches!(f, ZipInconsistency::UncountedCentralRecords { .. }))
    );
    assert!(archive.structure().omitted_findings() > 0);
    assert!(found.len() <= MAX_RETAINED_FINDINGS);
}

#[test]
fn omitted_findings_are_reported_by_verify() {
    let mut zip = RawZip::new(
        (0..40)
            .map(|i| RawEntry::stored(&format!("f{i:02}.txt"), b"x"))
            .collect(),
    );
    zip.end_count = None;
    let mut built = zip.build();
    for entry in 0..40 {
        patch(&mut built, entry, 30, b"g");
    }
    let report = open_bytes(built.bytes)
        .verify(
            &config(ZipConsistencyPolicy::Enforce),
            &VerificationOptions::default(),
        )
        .unwrap();
    assert!(
        report
            .issues()
            .iter()
            .any(|i| i.message.contains("further ZIP structure findings"))
    );
}

#[test]
fn every_structural_finding_is_ignored_under_the_ignore_policy() {
    let ignore = config(ZipConsistencyPolicy::Ignore);
    let mut uncounted = two_files();
    uncounted.end_count = Some(1);
    let mut hidden = RawZip::new(vec![RawEntry::stored("a.txt", b"hello")]);
    hidden.before_directory = evil_local();
    let mut overlap = two_files().build();
    let second_record = overlap.directory_start + (46 + "a.txt".len());
    let first = u32::try_from(overlap.local_offsets[0])
        .unwrap()
        .to_le_bytes();
    overlap.bytes[second_record + 42..second_record + 46].copy_from_slice(&first);

    for bytes in [uncounted.build().bytes, hidden.build().bytes, overlap.bytes] {
        assert!(!open_bytes(bytes.clone()).structure().findings().is_empty());
        let mut archive = open_bytes(bytes.clone());
        archive.list(&ignore).unwrap();
        let report = open_bytes(bytes)
            .verify(&ignore, &VerificationOptions::default())
            .unwrap();
        assert!(report.issues().iter().all(|i| !matches!(
            i.category,
            IssueCategory::HiddenEntry
                | IssueCategory::OverlappingEntries
                | IssueCategory::HeaderMismatch
        )));
    }
}

fn ut_archive() -> Vec<u8> {
    let mut entry = RawEntry::stored("a.txt", b"hello");
    entry.local_extra = extended_timestamp_with_bad_flags();
    RawZip::new(vec![entry]).build().bytes
}

#[test]
fn unparseable_local_header_is_rejected_by_every_operation_under_enforce() {
    let enforce = config(ZipConsistencyPolicy::Enforce);
    let temp = TempDir::new().unwrap();
    let dest = temp.path().join("out");
    let unparseable = |r: Result<()>| {
        assert_matches!(
            r,
            Err(ArchiveError::ZipInconsistency(
                ZipInconsistency::HeaderMismatch {
                    field: ZipHeaderField::Unparseable,
                    ..
                }
            ))
        );
    };
    unparseable(open_bytes(ut_archive()).list(&enforce).map(drop));
    unparseable(
        open_bytes(ut_archive())
            .extract(
                &dest,
                &enforce,
                &ExtractionOptions::default(),
                &mut NoopProgress,
            )
            .map(drop),
    );
    assert!(!dest.exists());
    let report = open_bytes(ut_archive())
        .verify(&enforce, &VerificationOptions::default())
        .unwrap();
    assert_eq!(report.status(), VerificationStatus::Fail);
    assert!(
        report
            .issues()
            .iter()
            .any(|i| i.category == IssueCategory::HeaderMismatch)
    );
}

#[test]
fn unparseable_local_header_extracts_as_before_under_ignore() {
    let ignore = config(ZipConsistencyPolicy::Ignore);
    let temp = TempDir::new().unwrap();
    open_bytes(ut_archive())
        .extract(
            temp.path(),
            &ignore,
            &ExtractionOptions::default(),
            &mut NoopProgress,
        )
        .unwrap();
    assert_eq!(std::fs::read(temp.path().join("a.txt")).unwrap(), b"hello");
    assert_eq!(
        open_bytes(ut_archive())
            .list(&ignore)
            .unwrap()
            .total_entries(),
        1
    );
    assert_eq!(
        open_bytes(ut_archive())
            .verify(&ignore, &VerificationOptions::default())
            .unwrap()
            .status(),
        VerificationStatus::Pass
    );
}

/// Records every absolute seek so tests can count how often a region is read.
#[derive(Clone)]
struct Probe {
    inner: Cursor<Vec<u8>>,
    seeks: std::sync::Arc<std::sync::Mutex<Vec<u64>>>,
}

impl Read for Probe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Seek for Probe {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        if let SeekFrom::Start(at) = pos {
            self.seeks.lock().unwrap().push(at);
        }
        self.inner.seek(pos)
    }
}

#[test]
fn the_central_directory_is_parsed_once_and_offsets_stay_cached() {
    let built = two_files().build();
    let seeks = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let probe = Probe {
        inner: Cursor::new(built.bytes.clone()),
        seeks: seeks.clone(),
    };
    let mut archive = ZipArchive::new(probe).unwrap();
    let count_at = |position: usize| {
        let at = position as u64;
        seeks.lock().unwrap().iter().filter(|&&s| s == at).count()
    };

    // One parse by the crate plus the census walk; a re-open would add more.
    let plain_seeks = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let plain = Probe {
        inner: Cursor::new(built.bytes.clone()),
        seeks: plain_seeks.clone(),
    };
    zip::ZipArchive::new(plain).unwrap();
    let crate_parse = plain_seeks
        .lock()
        .unwrap()
        .iter()
        .filter(|&&s| s == built.directory_start as u64)
        .count();
    assert_eq!(count_at(built.directory_start), crate_parse + 1);

    let before: Vec<_> = built.local_offsets.iter().map(|&o| count_at(o)).collect();
    archive
        .list(&config(ZipConsistencyPolicy::Enforce))
        .unwrap();
    let temp = TempDir::new().unwrap();
    archive
        .extract(
            temp.path(),
            &config(ZipConsistencyPolicy::Enforce),
            &ExtractionOptions::default(),
            &mut NoopProgress,
        )
        .unwrap();
    let after: Vec<_> = built.local_offsets.iter().map(|&o| count_at(o)).collect();
    assert_eq!(before, after, "operations re-read local headers");
}

#[test]
fn shared_reader_serves_the_archive_and_the_census_from_one_handle() {
    let mut shared = Shared::new(Cursor::new(b"abcdef".to_vec()));
    let mut other = shared.clone();
    shared.seek(SeekFrom::Start(2)).unwrap();
    let mut two = [0u8; 2];
    other.read_exact(&mut two).unwrap();
    assert_eq!(&two, b"cd");
}

#[test]
fn a_gap_full_of_signatures_costs_a_bounded_number_of_reads() {
    const GAP: usize = 8 * 1024 * 1024;
    let mut zip = RawZip::new(vec![RawEntry::stored("a.txt", b"hello")]);
    zip.before_directory = b"PK\x03\x04".repeat(GAP / 4);
    let archive = open_bytes(zip.build().bytes);
    let found = archive.structure().findings();
    assert_eq!(found.len(), 16);
    assert!(
        found
            .iter()
            .all(|f| matches!(f, ZipInconsistency::HiddenLocalHeader { .. }))
    );
    assert!(archive.structure().omitted_findings() >= 1);
    // The search stops at the first header past the limit: one chunk, not one
    // read per signature.
    assert!(
        archive.structure().gap_reads() <= 4,
        "{}",
        archive.structure().gap_reads()
    );
}

#[test]
fn a_gap_of_implausible_signatures_is_read_in_chunks_not_per_hit() {
    const GAP: usize = 4 * 1024 * 1024;
    let mut gap = Vec::with_capacity(GAP);
    while gap.len() < GAP {
        gap.extend_from_slice(b"PK\x03\x04");
        gap.extend_from_slice(&[0u8; 28]);
    }
    let mut zip = RawZip::new(vec![RawEntry::stored("a.txt", b"hello")]);
    zip.before_directory = gap;
    let archive = open_bytes(zip.build().bytes);
    assert!(archive.structure().findings().is_empty());
    let chunks = GAP / GAP_CHUNK;
    assert!(
        archive.structure().gap_reads() <= chunks + 4,
        "{} reads for {} chunks",
        archive.structure().gap_reads(),
        chunks
    );
}

fn many_mismatches() -> Vec<u8> {
    let mut built = RawZip::new(
        (0..40)
            .map(|i| RawEntry::stored(&format!("f{i:02}.txt"), b"x"))
            .collect(),
    )
    .build();
    for entry in 0..40 {
        patch(&mut built, entry, 30, b"g");
    }
    built.bytes
}

#[test]
fn ignore_policy_adds_no_omitted_findings_note() {
    let report = open_bytes(many_mismatches())
        .verify(
            &config(ZipConsistencyPolicy::Ignore),
            &VerificationOptions::default(),
        )
        .unwrap();
    assert!(report.issues().is_empty(), "{:?}", report.issues());
}

#[test]
fn suspicious_entries_never_exceed_the_entries() {
    let mut zip = RawZip::new(vec![RawEntry::stored("a.txt", b"hello")]);
    zip.before_directory = evil_local().repeat(20);
    let report = open_bytes(zip.build().bytes)
        .verify(
            &config(ZipConsistencyPolicy::Enforce),
            &VerificationOptions::default(),
        )
        .unwrap();
    assert_eq!(report.total_entries(), 1);
    assert!(report.suspicious_entries() <= report.total_entries());
    assert_eq!(report.status(), VerificationStatus::Fail);
}

/// Fails every read below `limit`, as a disk that stops answering would.
struct FailingBelow {
    inner: Cursor<Vec<u8>>,
    limit: u64,
}

impl Read for FailingBelow {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.inner.position() < self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "disk gone",
            ));
        }
        self.inner.read(buf)
    }
}

impl Seek for FailingBelow {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

#[test]
fn a_failing_reader_is_an_io_error_not_a_finding() {
    let built = two_files().build();
    let reader = FailingBelow {
        inner: Cursor::new(built.bytes),
        limit: built.directory_start as u64,
    };
    let result = ZipArchive::new(reader).map(drop);
    assert_matches!(
        result,
        Err(ArchiveError::Io(e)) if e.kind() == std::io::ErrorKind::PermissionDenied
    );
}

#[test]
fn a_malformed_extra_field_stays_a_finding_not_an_io_error() {
    let archive = open_bytes(ut_archive());
    assert_matches!(
        archive.structure().findings(),
        [ZipInconsistency::HeaderMismatch {
            field: ZipHeaderField::Unparseable,
            ..
        }]
    );
}

/// Fails every read of the central directory after `allowed` of them, which
/// is past what the `zip` crate's own parse needs.
struct FailingPastParse {
    inner: Cursor<Vec<u8>>,
    directory_start: u64,
    reads: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    allowed: usize,
}

impl Read for FailingPastParse {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.inner.position() >= self.directory_start {
            let seen = self
                .reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if seen >= self.allowed {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "disk gone",
                ));
            }
        }
        self.inner.read(buf)
    }
}

impl Seek for FailingPastParse {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

#[test]
fn a_reader_failing_in_the_raw_directory_walk_is_an_io_error() {
    let built = two_files().build();
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reader = |allowed| FailingPastParse {
        inner: Cursor::new(built.bytes.clone()),
        directory_start: built.directory_start as u64,
        reads: counter.clone(),
        allowed,
    };

    zip::ZipArchive::new(reader(usize::MAX)).unwrap();
    let crate_reads = counter.swap(0, std::sync::atomic::Ordering::Relaxed);

    let result = ZipArchive::new(reader(crate_reads)).map(drop);
    assert_matches!(
        result,
        Err(ArchiveError::Io(e)) if e.kind() == std::io::ErrorKind::PermissionDenied
    );
}
