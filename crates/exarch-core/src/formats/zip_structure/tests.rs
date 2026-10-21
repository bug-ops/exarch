#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::assert_matches;
use std::io::Cursor;

use tempfile::TempDir;

use super::*;
use crate::DecompressionBudget;
use crate::EndRecordKind;
use crate::ExtractionOptions;
use crate::HiddenRegion;
use crate::IntegrityCheck;
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

mod streaming;

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
        let built = deflated_pair(signature, zip64).build();
        let archive = open_bytes(built.bytes);
        assert!(archive.structure().findings().is_empty());
        let reads = archive.structure().gap_reads();
        assert!(
            reads <= 2 * MAX_READS_PER_DESCRIPTOR,
            "{signature} {zip64}: {reads}"
        );
    }
    for zip64 in [false, true] {
        let built = RawZip::new(vec![
            RawEntry::stored("a.txt", b"hello").with_descriptor(true, zip64),
            RawEntry::stored("b.txt", b"world").with_descriptor(true, zip64),
        ])
        .build();
        assert!(findings_of(&built).is_empty(), "stored {zip64}");
    }
}

/// Local header, lookahead and the descriptor bytes themselves.
const MAX_READS_PER_DESCRIPTOR: usize = 4;

fn deflated_pair(signature: bool, zip64: bool) -> RawZip {
    RawZip::new(vec![
        RawEntry::deflated("a.txt", b"hello hello hello").with_descriptor(signature, zip64),
        RawEntry::deflated("b.txt", b"world world world").with_descriptor(signature, zip64),
    ])
}

/// Offset where the data of `entry`, written at `local_offset`, ends.
fn data_end(entry: &RawEntry, local_offset: usize) -> usize {
    local_offset + LFH_FIXED_LEN + entry.name.len() + entry.local_extra.len() + entry.data.len()
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
                offset: built.local_offsets[1] as u64,
                region: HiddenRegion::Gap,
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
            offset: built.directory_start as u64 - evil.directory_start as u64,
            region: HiddenRegion::Gap,
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
        let entry = RawEntry::deflated("a.txt", b"hello").with_descriptor(signature, zip64);
        let mut zip = RawZip::new(vec![entry.clone()]);
        zip.before_directory = evil.bytes[..evil.directory_start].to_vec();
        let built = zip.build();
        let archive = open_bytes(built.bytes.clone());
        let end = data_end(&entry, built.local_offsets[0]);
        assert_eq!(
            archive.structure().findings(),
            [ZipInconsistency::HiddenLocalHeader {
                offset: end as u64 + width,
                region: HiddenRegion::Gap,
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
    assert!(archive.structure().gap_reads() <= MAX_READS_PER_DESCRIPTOR);
}

#[test]
fn descriptor_size_equal_to_the_header_magic_before_another_entry_is_a_hidden_header() {
    const MAGIC_AS_SIZE: u64 = 0x0403_4b50;
    let mut first = RawEntry::stored("zeros.bin", b"").with_descriptor(true, false);
    first.data = deflate_zeros(MAGIC_AS_SIZE);
    first.method = 8;
    first.size = MAGIC_AS_SIZE;
    let end = data_end(&first, 0);
    let built = RawZip::new(vec![first, RawEntry::stored("b.txt", b"world")]).build();
    assert_eq!(findings_of(&built), [hidden_at(end + 12)]);
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
        comment: Vec::new(),
    };
    let result = Census::run(&mut cursor, &map, &Scan::default());
    assert_matches!(result, Err(ArchiveError::InvalidArchive(msg)) if msg.contains("census"));

    let map = DirectoryMap {
        directory_start: built.directory_start as u64,
        archive_offset: 0,
        central_starts: vec![built.directory_start as u64],
        comment: Vec::new(),
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
    hidden_in(offset, HiddenRegion::Gap)
}

fn hidden_in(offset: usize, region: HiddenRegion) -> ZipInconsistency {
    ZipInconsistency::HiddenLocalHeader {
        offset: offset as u64,
        region,
    }
}

#[test]
fn local_header_at_file_start_before_the_archive_is_found() {
    let mut bytes = evil_local();
    bytes.extend(two_files().build().bytes);
    let archive = open_bytes(bytes);
    assert_eq!(
        archive.structure().findings(),
        [hidden_in(0, HiddenRegion::Prefix)]
    );
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

    for bytes in [
        uncounted.build().bytes,
        hidden.build().bytes,
        overlap.bytes,
        stray_before_entry(&stray_central()).bytes,
    ] {
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

    // One parse by the crate plus the census walk at most.
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
    // The window serves repeated reads of the directory without touching the
    // reader, so it can only seek there less often than an unwindowed parse.
    assert!(count_at(built.directory_start) <= crate_parse + 1);

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
        if self.inner.position() + buf.len() as u64 > self.directory_start {
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

    ZipArchive::new(reader(usize::MAX)).unwrap();
    let opening_reads = counter.swap(0, std::sync::atomic::Ordering::Relaxed);
    assert!(opening_reads > 0);

    for allowed in 0..opening_reads {
        counter.store(0, std::sync::atomic::Ordering::Relaxed);
        let result = ZipArchive::new(reader(allowed)).map(drop);
        assert_matches!(
            result,
            Err(ArchiveError::Io(e)) if e.kind() == std::io::ErrorKind::PermissionDenied,
            "allowed {allowed}"
        );
    }
}

fn local_header(version: u16, flags: u16, method: u16, name: &[u8], compressed: u32) -> Vec<u8> {
    let mut bytes = b"PK\x03\x04".to_vec();
    bytes.extend_from_slice(&version.to_le_bytes());
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&method.to_le_bytes());
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&compressed.to_le_bytes());
    bytes.extend_from_slice(&compressed.to_le_bytes());
    bytes.extend_from_slice(&u16::try_from(name.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(name);
    bytes
}

fn with_prefix(prefix: Vec<u8>) -> ZipArchive<Cursor<Vec<u8>>> {
    let mut bytes = prefix;
    bytes.extend(two_files().build().bytes);
    open_bytes(bytes)
}

#[test]
fn local_header_inside_the_prefix_is_found() {
    for lead in [1usize, 100, 70_000, 131_000, 131_072 - 10, 300_000] {
        let mut prefix = vec![b'#'; lead];
        prefix.extend(evil_local());
        prefix.extend(vec![b'#'; 50]);
        let archive = with_prefix(prefix);
        assert_eq!(
            archive.structure().findings(),
            [hidden_in(lead, HiddenRegion::Prefix)],
            "{lead}"
        );
    }
}

#[test]
fn prefix_headers_that_do_not_fit_or_look_odd_are_ignored() {
    let name = b"evil.sh";
    let cases: [(&str, Vec<u8>); 7] = [
        ("data past the prefix", local_header(20, 0, 0, name, 1_000)),
        ("code-like version", local_header(0x2323, 0, 0, name, 0)),
        ("reserved flag", local_header(20, 0x0100, 0, name, 0)),
        ("unknown method", local_header(20, 0, 0x7777, name, 0)),
        ("nul in name", local_header(20, 0, 0, b"a\0b", 0)),
        ("empty name", local_header(20, 0, 0, b"", 0)),
        ("name cut by the archive", {
            let mut cut = local_header(20, 0, 0, name, 0);
            cut.truncate(cut.len() - 3);
            cut
        }),
    ];
    for (label, header) in cases {
        let archive = with_prefix([b"#".to_vec(), header].concat());
        assert!(archive.structure().findings().is_empty(), "{label}");
    }
}

#[test]
fn header_at_offset_zero_is_judged_like_one_in_a_gap() {
    let name = b"evil.sh";
    let cases: [(&str, Vec<u8>); 5] = [
        ("version 64", local_header(64, 0, 0, name, 0)),
        ("version 0x0314", local_header(0x0314, 0, 0, name, 0)),
        ("flag bit 15", local_header(20, 0x8000, 0, name, 0)),
        ("nul in name", local_header(20, 0, 0, b"a\0b", 0)),
        (
            "data past the archive start",
            local_header(20, 0, 0, name, 1_000),
        ),
    ];
    for (label, header) in cases {
        let archive = with_prefix(header);
        assert_eq!(
            archive.structure().findings(),
            [hidden_in(0, HiddenRegion::Prefix)],
            "{label}"
        );
    }
}

/// Shifts every offset of `built` by the stub length, as `zip -A` does.
fn with_absolute_offsets(stub: &[u8], built: &BuiltZip) -> Vec<u8> {
    let shift = u32::try_from(stub.len()).unwrap();
    let mut bytes = built.bytes.clone();
    let mut at = built.directory_start;
    let patch = |bytes: &mut Vec<u8>, at: usize| {
        let old = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        bytes[at..at + 4].copy_from_slice(&(old + shift).to_le_bytes());
    };
    while bytes[at..at + 4] == *b"PK\x01\x02" {
        let field = |bytes: &[u8], o: usize| {
            usize::from(u16::from_le_bytes([bytes[at + o], bytes[at + o + 1]]))
        };
        let len = 46 + field(&bytes, 28) + field(&bytes, 30) + field(&bytes, 32);
        patch(&mut bytes, at + 42);
        at += len;
    }
    patch(&mut bytes, at + 16);
    [stub.to_vec(), bytes].concat()
}

fn stub_with_embedded_signatures() -> Vec<u8> {
    let mut stub = b"MZ\x90\x00".to_vec();
    for i in 0u8..200 {
        stub.extend_from_slice(&[0xB8, b'P', b'K', 3, 4, 0x48, 0x89, 0xC3 ^ i, 0x90]);
    }
    stub
}

#[test]
fn self_extractor_stub_is_not_a_hidden_header() {
    let stub = stub_with_embedded_signatures();
    let built = two_files().build();

    let relative = [stub.clone(), built.bytes.clone()].concat();
    let absolute = with_absolute_offsets(&stub, &built);
    for (label, bytes) in [("relative", relative), ("absolute", absolute)] {
        let mut archive = open_bytes(bytes);
        assert_eq!(archive.reader_mut().len(), 2, "{label}");
        assert!(archive.structure().findings().is_empty(), "{label}");
        let report = archive
            .verify(
                &config(ZipConsistencyPolicy::Enforce),
                &VerificationOptions::default(),
            )
            .unwrap();
        assert_eq!(report.status(), VerificationStatus::Pass, "{label}");
    }
}

#[test]
fn header_hidden_in_an_absolute_offset_stub_is_found() {
    let mut stub = vec![b'#'; 64];
    stub.extend(evil_local());
    let absolute = with_absolute_offsets(&stub, &two_files().build());
    let archive = open_bytes(absolute);
    assert_eq!(
        archive.structure().findings(),
        [hidden_in(64, HiddenRegion::Prefix)]
    );
}

#[test]
fn prefix_header_with_a_descriptor_needs_no_data_in_the_prefix() {
    let archive = with_prefix(local_header(20, 0x0008, 8, b"evil.sh", 5_000));
    assert_eq!(
        archive.structure().findings(),
        [hidden_in(0, HiddenRegion::Prefix)]
    );
}

#[test]
fn prefix_with_many_signature_hits_stays_bounded() {
    let archive = with_prefix([b"#".to_vec(), b"PK\x03\x04".repeat(100_000)].concat());
    assert!(archive.structure().findings().is_empty());
}

fn with_second_end_record(valid_tail: &[u8]) -> Vec<u8> {
    let mut bytes = two_files().build().bytes;
    bytes.extend_from_slice(valid_tail);
    bytes
}

fn end_record(directory_offset: u32, comment: &[u8]) -> Vec<u8> {
    let mut record = b"PK\x05\x06".to_vec();
    record.extend_from_slice(&[0; 8]);
    record.extend_from_slice(&0u32.to_le_bytes());
    record.extend_from_slice(&directory_offset.to_le_bytes());
    record.extend_from_slice(&u16::try_from(comment.len()).unwrap().to_le_bytes());
    record.extend_from_slice(comment);
    record
}

#[test]
fn end_record_the_crate_skipped_is_found() {
    let built = two_files().build();
    let used_end = built.bytes.len();
    // The last record points past the file, so the crate falls back to the
    // record before it.
    let archive = open_bytes(with_second_end_record(&end_record(0x00ff_ffff, b"")));
    assert_eq!(
        archive.structure().findings(),
        [ZipInconsistency::IgnoredEndRecord {
            offset: used_end as u64
        }]
    );
}

#[test]
fn end_record_text_inside_a_comment_is_not_a_finding() {
    let mut zip = two_files();
    zip.comment = b"see PK\x05\x06 for details".to_vec();
    let built = zip.build();
    assert!(findings_of(&built).is_empty());
}

#[test]
fn ignored_end_record_is_fatal_under_enforce() {
    let temp = TempDir::new().unwrap();
    let dest = temp.path().join("out");
    let mut archive = open_bytes(with_second_end_record(&end_record(0x00ff_ffff, b"")));
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
        ArchiveError::ZipInconsistency(ZipInconsistency::IgnoredEndRecord { .. })
    );
    assert!(!dest.exists());
}

fn compress(method: u16, payload: &[u8]) -> Vec<u8> {
    match method {
        8 => {
            let mut encoder =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            std::io::Write::write_all(&mut encoder, payload).unwrap();
            encoder.finish().unwrap()
        }
        12 => {
            let mut encoder =
                bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
            std::io::Write::write_all(&mut encoder, payload).unwrap();
            encoder.finish().unwrap()
        }
        93 => zstd::encode_all(payload, 0).unwrap(),
        _ => payload.to_vec(),
    }
}

fn descriptor(payload: &[u8], compressed: usize) -> Vec<u8> {
    let mut crc = flate2::Crc::new();
    crc.update(payload);
    let mut bytes = b"PK\x07\x08".to_vec();
    bytes.extend_from_slice(&crc.sum().to_le_bytes());
    bytes.extend_from_slice(&u32::try_from(compressed).unwrap().to_le_bytes());
    bytes.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
    bytes
}

/// An entry with a data descriptor whose declared range is `stream + tail`.
fn descriptor_entry(method: u16, payload: &[u8], tail: &[u8]) -> RawEntry {
    let mut entry = RawEntry::stored("a.txt", payload).with_descriptor(true, false);
    entry.method = method;
    entry.data = [compress(method, payload), tail.to_vec()].concat();
    entry
}

fn verify_with_integrity(bytes: Vec<u8>) -> crate::VerificationReport {
    open_bytes(bytes)
        .verify(
            &config(ZipConsistencyPolicy::Enforce),
            &VerificationOptions::default()
                .with_integrity(IntegrityCheck::DecodeToEof(DecompressionBudget::DEFAULT)),
        )
        .unwrap()
}

fn hidden_issues(report: &crate::VerificationReport) -> Vec<&crate::VerificationIssue> {
    report
        .issues()
        .iter()
        .filter(|i| i.category == IssueCategory::HiddenEntry)
        .collect()
}

#[test]
fn header_hidden_behind_a_compressed_stream_is_found_with_integrity() {
    let payload = b"hello hello hello hello";
    for method in [8u16, 12, 93] {
        let stream_len = compress(method, payload).len();
        let mut tail = [descriptor(payload, 0), evil_local()].concat();
        if method == 93 {
            // A bare tail makes the zstd decoder fail; a skippable frame is
            // decoded around, so only the stream end shows what it hides.
            let mut frame = 0x184D_2A50u32.to_le_bytes().to_vec();
            frame.extend_from_slice(&u32::try_from(tail.len()).unwrap().to_le_bytes());
            tail = [frame, tail].concat();
        }
        let built = RawZip::new(vec![descriptor_entry(method, payload, &tail)]).build();
        let skippable_header = if method == 93 { 8 } else { 0 };
        let expected = built.local_offsets[0] + 30 + 5 + stream_len + skippable_header + 16;
        let report = verify_with_integrity(built.bytes.clone());
        let found = hidden_issues(&report);
        assert_eq!(found.len(), 1, "method {method}");
        assert!(
            found[0].message.contains(&format!("offset {expected} ")),
            "method {method}: {}",
            found[0].message
        );
        assert_eq!(report.status(), VerificationStatus::Fail);

        let plain = open_bytes(built.bytes)
            .verify(
                &config(ZipConsistencyPolicy::Enforce),
                &VerificationOptions::default(),
            )
            .unwrap();
        assert!(hidden_issues(&plain).is_empty(), "method {method}");
    }
}

#[test]
fn header_hidden_inside_stored_data_is_found_with_integrity() {
    for filler in [5usize, 200_000] {
        let content = vec![b'x'; filler];
        let whole = [content.clone(), descriptor(&content, filler), evil_local()].concat();
        let built = RawZip::new(vec![descriptor_entry(0, &whole, &[])]).build();
        let expected = built.local_offsets[0] + 30 + 5 + filler + 16;
        let report = verify_with_integrity(built.bytes);
        let found = hidden_issues(&report);
        assert_eq!(found.len(), 1, "{filler}");
        assert!(found[0].message.contains(&format!("offset {expected} ")));
    }
}

#[test]
fn ordinary_descriptor_entries_have_no_tail_finding() {
    let payload = b"hello hello hello hello";
    for method in [0u16, 8, 12, 93] {
        for tail in [Vec::new(), descriptor(payload, 0)] {
            let built = RawZip::new(vec![
                descriptor_entry(method, payload, &tail),
                RawEntry::stored("b.txt", b"world").with_descriptor(true, false),
            ])
            .build();
            let report = verify_with_integrity(built.bytes);
            assert!(hidden_issues(&report).is_empty(), "method {method}");
        }
    }
}

#[test]
fn window_reads_match_the_underlying_reader() {
    let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let mut windowed = Windowed::new(Cursor::new(data.clone()));
    let mut plain = Cursor::new(data);
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..2_000 {
        let seek = match next() % 4 {
            0 => SeekFrom::Start(next() % 210_000),
            1 => SeekFrom::Current((next() % 9_000).cast_signed() - 4_500),
            2 => SeekFrom::End(-((next() % 200_000).cast_signed())),
            _ => SeekFrom::Current(0),
        };
        let expected = plain.seek(seek).map_err(|e| e.kind());
        assert_eq!(
            windowed.seek(seek).map_err(|e| e.kind()),
            expected,
            "{seek:?}"
        );
        let len = [1usize, 30, 4_095, 4_096, 9_000, 40_000][(next() % 6) as usize];
        let mut a = vec![0u8; len];
        let mut b = vec![0u8; len];
        let got = windowed.read(&mut a).unwrap();
        let want = plain.read(&mut b).unwrap();
        // A short read is legal; what was returned must still match.
        let n = got.min(want);
        assert_eq!(a[..n], b[..n]);
        plain
            .seek(SeekFrom::Start(windowed.stream_position().unwrap()))
            .unwrap();
    }
}

#[test]
fn opening_many_entries_reads_the_file_in_a_bounded_number_of_requests() {
    let entries: Vec<_> = (0..2_000)
        .map(|i| RawEntry::stored(&format!("f{i:04}.txt"), b"x"))
        .collect();
    let built = RawZip::new(entries).build();
    let seeks = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let probe = Probe {
        inner: Cursor::new(built.bytes),
        seeks: seeks.clone(),
    };
    let mut archive = ZipArchive::new(probe).unwrap();
    archive
        .list(&config(ZipConsistencyPolicy::Enforce))
        .unwrap();
    assert!(seeks.lock().unwrap().len() < 100);
}

fn zip64_end_chain(directory_start: usize, directory_len: usize, at: usize) -> Vec<u8> {
    let mut record = b"PK\x06\x06".to_vec();
    record.extend_from_slice(&44u64.to_le_bytes());
    record.extend_from_slice(&[45, 0, 45, 0]);
    record.extend_from_slice(&[0; 8]);
    record.extend_from_slice(&5u64.to_le_bytes());
    record.extend_from_slice(&5u64.to_le_bytes());
    record.extend_from_slice(&(directory_len as u64).to_le_bytes());
    record.extend_from_slice(&(directory_start as u64).to_le_bytes());
    let mut locator = b"PK\x06\x07".to_vec();
    locator.extend_from_slice(&0u32.to_le_bytes());
    locator.extend_from_slice(&(at as u64).to_le_bytes());
    locator.extend_from_slice(&1u32.to_le_bytes());
    let mut end = b"PK\x05\x06".to_vec();
    end.extend_from_slice(&[0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
    end.extend_from_slice(&[0xff; 8]);
    end.extend_from_slice(&[0, 0]);
    [record, locator, end].concat()
}

#[test]
fn zip64_end_record_the_crate_rejected_is_not_taken_for_the_used_one() {
    let base = two_files().build().bytes;
    let evil = RawZip::new(vec![RawEntry::stored("evil.sh", b"echo pwned\n")]).build();
    let lfh = evil.bytes[..evil.directory_start].to_vec();
    let mut central = evil.bytes[evil.directory_start..evil.bytes.len() - 22].to_vec();
    central[42..46].copy_from_slice(&u32::try_from(base.len()).unwrap().to_le_bytes());

    let directory_start = base.len() + lfh.len();
    let end_at = directory_start + central.len();
    let bytes = [
        base,
        lfh,
        central.clone(),
        zip64_end_chain(directory_start, central.len(), end_at),
    ]
    .concat();
    let mut archive = open_bytes(bytes);
    assert_eq!(archive.reader_mut().len(), 2);
    assert!(
        archive
            .structure()
            .findings()
            .iter()
            .any(|f| matches!(f, ZipInconsistency::IgnoredEndRecord { .. }))
    );
}

#[test]
fn end_record_at_the_far_edge_of_the_search_range_is_still_compared() {
    // The crate searches 65562 bytes back from the end; the used record sits
    // 65560 bytes back and a rejected one closes the file.
    let mut bytes = two_files().build().bytes;
    let used = bytes.len() - 22;
    bytes.extend(vec![0u8; 65_538 - 22]);
    bytes.extend(end_record(0x00ff_ffff, b""));
    let archive = open_bytes(bytes.clone());
    assert_eq!(bytes.len() - used, 65_560);
    assert_eq!(
        archive.structure().findings(),
        [ZipInconsistency::IgnoredEndRecord {
            offset: bytes.len() as u64 - 22
        }]
    );
}

#[test]
fn unidentified_used_record_is_ambiguous_only_with_several_candidates() {
    let map = DirectoryMap {
        directory_start: 999,
        archive_offset: 0,
        central_starts: Vec::new(),
        comment: Vec::new(),
    };
    let run = |bytes: Vec<u8>| {
        let len = bytes.len() as u64;
        let mut findings = Findings::default();
        find_ignored_end_records(&mut Cursor::new(bytes), len, &map, &mut findings).unwrap();
        findings.items
    };
    let one = end_record(1, b"");
    assert!(run(one.clone()).is_empty());
    assert_eq!(
        run([one, end_record(2, b"")].concat()),
        [ZipInconsistency::IgnoredEndRecord { offset: 22 }]
    );
}

struct InterruptedOnce {
    inner: Cursor<Vec<u8>>,
    reads: usize,
}

impl Read for InterruptedOnce {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reads += 1;
        if self.reads == 2 {
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        self.inner.read(buf)
    }
}

impl Seek for InterruptedOnce {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

#[test]
fn failed_refill_leaves_no_stale_window() {
    let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    let mut windowed = Windowed::new(InterruptedOnce {
        inner: Cursor::new(data.clone()),
        reads: 0,
    });
    let mut head = [0u8; 16];
    windowed.read_exact(&mut head).unwrap();
    windowed.seek(SeekFrom::Start(50_000)).unwrap();
    let mut tail = [0u8; 16];
    windowed.read_exact(&mut tail).unwrap();
    assert_eq!(tail, data[50_000..50_016]);
}

#[test]
fn header_in_a_skippable_frame_between_zstd_frames_is_found() {
    let (first, second) = (b"hello hello ".as_slice(), b"world world".as_slice());
    let hidden = [descriptor(first, 0), evil_local()].concat();
    let mut skippable = 0x184D_2A50u32.to_le_bytes().to_vec();
    skippable.extend_from_slice(&u32::try_from(hidden.len()).unwrap().to_le_bytes());
    skippable.extend(hidden);

    let payload = [first, second].concat();
    let mut entry = RawEntry::stored("a.txt", &payload).with_descriptor(true, false);
    entry.method = 93;
    entry.data = [compress(93, first), skippable, compress(93, second)].concat();
    let report = verify_with_integrity(RawZip::new(vec![entry]).build().bytes);
    assert_eq!(hidden_issues(&report).len(), 1, "{:?}", report.issues());
}

#[test]
fn descriptor_tail_check_is_off_under_the_ignore_policy() {
    let payload = b"hello hello hello hello";
    let tail = [descriptor(payload, 0), evil_local()].concat();
    let built = RawZip::new(vec![descriptor_entry(8, payload, &tail)]).build();
    let report = open_bytes(built.bytes)
        .verify(
            &config(ZipConsistencyPolicy::Ignore),
            &VerificationOptions::default()
                .with_integrity(IntegrityCheck::DecodeToEof(DecompressionBudget::DEFAULT)),
        )
        .unwrap();
    assert!(hidden_issues(&report).is_empty());
}

#[test]
fn file_starting_with_pk_is_judged_leniently_before_the_first_entry() {
    let prefix = [b"PK00".to_vec(), local_header(64, 0, 0, b"evil.sh", 0)].concat();
    let built = two_files().build();
    let relative = [prefix.clone(), built.bytes.clone()].concat();
    let absolute = with_absolute_offsets(&prefix, &built);
    for (label, bytes) in [("relative", relative), ("absolute", absolute)] {
        let archive = open_bytes(bytes);
        assert_eq!(
            archive.structure().findings(),
            [hidden_in(4, HiddenRegion::Prefix)],
            "{label}"
        );
    }

    let stub = [b"MZ00".to_vec(), local_header(64, 0, 0, b"evil.sh", 0)].concat();
    let absolute = with_absolute_offsets(&stub, &built);
    assert!(open_bytes(absolute).structure().findings().is_empty());
}

fn stray_central() -> Vec<u8> {
    let evil = RawZip::new(vec![RawEntry::stored("evil.sh", b"echo pwned\n")]).build();
    evil.bytes[evil.directory_start..evil.bytes.len() - 22].to_vec()
}

fn stray(offset: usize) -> ZipInconsistency {
    ZipInconsistency::StrayCentralRecord {
        offset: offset as u64,
    }
}

/// Two entries with `gap` written into the bytes between them, where a
/// streaming reader that stops at it never reaches the second entry. Returns
/// the archive and the offset of the gap.
fn gap_before_entry(gap: &[u8]) -> (BuiltZip, usize) {
    gap_with_padding(0, gap)
}

fn gap_with_padding(padding: usize, gap: &[u8]) -> (BuiltZip, usize) {
    let mut first = RawEntry::stored("a.txt", b"hello");
    first.padding_after = padding + gap.len();
    let mut built = RawZip::new(vec![first, RawEntry::stored("b.txt", b"world")]).build();
    let at = built.local_offsets[1] - gap.len();
    built.bytes[at..at + gap.len()].copy_from_slice(gap);
    (built, at)
}

fn stray_before_entry(gap: &[u8]) -> BuiltZip {
    gap_before_entry(gap).0
}

fn record_with(patch: impl FnOnce(&mut [u8])) -> Vec<u8> {
    let mut record = stray_central();
    patch(&mut record);
    record
}

#[test]
fn central_signature_before_an_entry_is_found_whatever_follows_it() {
    let shapes = [
        ("full record", stray_central()),
        ("bare signature", b"PK\x01\x02".to_vec()),
        ("nameless", record_with(|r| r[28..30].fill(0))),
        ("version 0xFFFF", record_with(|r| r[6..8].fill(0xFF))),
        ("zip64 offset", record_with(|r| r[42..46].fill(0xFF))),
        ("name past the file", record_with(|r| r[28..30].fill(0xFF))),
    ];
    for (label, shape) in shapes {
        let (built, at) = gap_before_entry(&shape);
        assert_eq!(findings_of(&built), [stray(at)], "{label}");
    }
}

#[test]
fn central_record_in_the_final_gap_hides_nothing_and_is_not_reported() {
    for shape in [stray_central(), b"PK\x01\x02".to_vec()] {
        let mut zip = RawZip::new(vec![RawEntry::stored("a.txt", b"hello")]);
        zip.before_directory = shape;
        assert!(findings_of(&zip.build()).is_empty());
    }
    let mut zip = two_files();
    zip.before_directory = stray_central();
    assert!(findings_of(&zip.build()).is_empty());
}

#[test]
fn central_signature_split_by_a_read_boundary_is_found() {
    for padding in [
        GAP_CHUNK - 5,
        GAP_CHUNK - 4,
        GAP_CHUNK - 3,
        GAP_CHUNK - 2,
        GAP_CHUNK - 1,
        GAP_CHUNK,
    ] {
        let (built, at) = gap_with_padding(padding, b"PK\x01\x02");
        assert_eq!(findings_of(&built), [stray(at)], "{padding}");
    }
}

#[test]
fn central_record_in_the_prefix_is_found_only_when_the_file_starts_with_pk() {
    let built = two_files().build();
    for (label, record) in [
        ("bare signature", b"PK\x01\x02".to_vec()),
        ("nameless", record_with(|r| r[28..30].fill(0))),
        ("full record", stray_central()),
    ] {
        let relative = [record.clone(), built.bytes.clone()].concat();
        let absolute = with_absolute_offsets(&record, &built);
        for (kind, bytes) in [("relative", relative), ("absolute", absolute)] {
            assert_eq!(
                open_bytes(bytes).structure().findings(),
                [stray(0)],
                "{label} {kind}"
            );
        }

        let after_pk = [b"PK00".to_vec(), record.clone()].concat();
        let absolute = with_absolute_offsets(&after_pk, &built);
        assert_eq!(
            open_bytes(absolute).structure().findings(),
            [stray(4)],
            "{label} behind PK00"
        );

        let stub = [b"MZ00".to_vec(), record].concat();
        let absolute = with_absolute_offsets(&stub, &built);
        assert!(open_bytes(absolute).structure().findings().is_empty());
    }
}

#[test]
fn central_signature_after_a_descriptor_is_found_at_every_descriptor_width() {
    for (signature, zip64) in [(true, false), (false, false), (true, true), (false, true)] {
        let mut first = RawEntry::deflated("a.txt", b"hello").with_descriptor(signature, zip64);
        first.padding_after = 4;
        let mut built = RawZip::new(vec![first, RawEntry::stored("b.txt", b"world")]).build();
        let at = built.local_offsets[1] - 4;
        built.bytes[at..at + 4].copy_from_slice(b"PK\x01\x02");
        assert_eq!(findings_of(&built), [stray(at)], "{signature} {zip64}");
    }
}

#[test]
fn stray_central_records_are_capped() {
    let (built, _) = gap_before_entry(&b"PK\x01\x02".repeat(40));
    let found = findings_of(&built);
    assert_eq!(found.len(), 16);
    assert!(
        found
            .iter()
            .all(|f| matches!(f, ZipInconsistency::StrayCentralRecord { .. }))
    );
}

#[test]
fn stray_central_record_is_fatal_under_enforce_and_reported_by_verify() {
    let bytes = stray_before_entry(&stray_central()).bytes;

    assert_matches!(
        open_bytes(bytes.clone()).list(&config(ZipConsistencyPolicy::Enforce)),
        Err(ArchiveError::ZipInconsistency(
            ZipInconsistency::StrayCentralRecord { .. }
        ))
    );
    let report = open_bytes(bytes)
        .verify(
            &config(ZipConsistencyPolicy::Enforce),
            &VerificationOptions::default(),
        )
        .unwrap();
    assert_eq!(report.status(), VerificationStatus::Fail);
    assert!(report.issues().iter().any(|i| {
        i.category == IssueCategory::HiddenEntry
            && i.message
                .contains("central directory record outside the central directory")
    }));
}

#[test]
fn descriptor_tail_the_budget_cannot_cover_is_listed_with_its_own_reason() {
    let payload = b"hello hello hello hello";
    let built = RawZip::new(vec![descriptor_entry(8, payload, &descriptor(payload, 0))]).build();
    let report = open_bytes(built.bytes)
        .verify(
            &config(ZipConsistencyPolicy::Enforce),
            &VerificationOptions::default().with_integrity(IntegrityCheck::DecodeToEof(
                DecompressionBudget::try_from_bytes(payload.len() as u64).unwrap(),
            )),
        )
        .unwrap();
    let gaps = report.integrity_gaps().unwrap();
    assert_eq!(gaps.total(), 1);
    assert_eq!(gaps.count(crate::UnverifiedReason::DescriptorTail), 1);
    assert_eq!(gaps.entries().len(), 1);
    assert_eq!(
        gaps.entries()[0].reason(),
        crate::UnverifiedReason::DescriptorTail
    );
}
