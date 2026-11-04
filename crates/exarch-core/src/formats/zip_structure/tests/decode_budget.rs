//! The census decode budget: charged for every outcome, never a reason to
//! refuse an ordinary archive, and skipped when the policy discards findings.

use super::descriptor_resume::findings_with_budgets;
use super::descriptor_resume::findings_with_decode_budget;
use super::descriptor_resume::zstd_raw_frame;
use super::*;
use crate::ZipStreamUndecided;
use crate::formats::zip_tail::DECODED;

const PAYLOAD: &[u8] = b"hello hello hello hello";

fn decoded_so_far() -> u64 {
    DECODED.with(std::cell::Cell::get)
}

fn known_size_entry(name: &str, method: u16, payload: &[u8], tail: &[u8]) -> RawEntry {
    let mut entry = RawEntry::stored(name, payload);
    entry.method = method;
    entry.data = [compress(method, payload), tail.to_vec()].concat();
    entry
}

fn unknown(found: &[ZipInconsistency], reason: ZipStreamUndecided) -> bool {
    found
        .iter()
        .any(|f| matches!(f, ZipInconsistency::StreamEndUnknown { reason: r, .. } if *r == reason))
}

#[test]
fn entries_past_the_budget_are_not_decoded_again() {
    const BUDGET: u64 = 1000;
    let zeros = vec![0u8; 1 << 16];
    for method in [8u16, 12, 93] {
        let base = known_size_entry("e.bin", method, &zeros, &[]);
        let entries = (0..40)
            .map(|i| RawEntry {
                name: format!("e{i:02}.bin").into_bytes(),
                ..base.clone()
            })
            .collect();
        let built = RawZip::new(entries).build();
        let before = decoded_so_far();
        findings_with_decode_budget(&built, BUDGET);
        let spent = decoded_so_far() - before;
        assert!(
            spent > 0 && spent <= BUDGET + 1,
            "method {method}: decoded {spent}"
        );
    }
}

#[test]
fn a_rejected_stream_is_charged_for_what_it_produced() {
    const BUDGET: u64 = 100_000;
    let zeros = vec![0u8; 1 << 18];
    let mut base = known_size_entry("e.bin", 12, &zeros, &[]);
    let end = base.data.len() - 4;
    base.data.truncate(end);
    let entries = (0..20)
        .map(|i| RawEntry {
            name: format!("e{i:02}.bin").into_bytes(),
            ..base.clone()
        })
        .collect();
    let built = RawZip::new(entries).build();
    let before = decoded_so_far();
    findings_with_decode_budget(&built, BUDGET);
    let spent = decoded_so_far() - before;
    assert!(spent > 0 && spent <= BUDGET + 1, "{spent}");
}

#[test]
fn a_last_byte_that_starts_a_signature_does_not_refuse_an_entry_past_the_budget() {
    for tail in [&b"P"[..], b"PK", b"PK\x03", b"PK\x01", b"PK\x05"] {
        for method in [8u16, 12, 93] {
            let built = RawZip::new(vec![
                known_size_entry("a.bin", method, PAYLOAD, tail),
                RawEntry::stored("b.txt", b"world"),
            ])
            .build();
            let found = findings_with_decode_budget(&built, 0);
            assert!(found.is_empty(), "method {method} {tail:?}: {found:?}");
        }
    }
}

/// Records a streaming reader acts on whatever their fields hold.
fn reader_records() -> Vec<(String, Vec<u8>)> {
    let mut records = vec![("local header".to_string(), unmapped_local())];
    for (version, flags, method) in [
        (64u16, 0u16, 0u16),
        (0x0314, 0, 0),
        (20, 0x0080, 0),
        (20, 0x4000, 0),
        (20, 0, 50),
        (20, 0, 77),
    ] {
        records.push((
            format!("local header {version:#x} {flags:#x} {method}"),
            local_header(version, flags, method, b"x", 0),
        ));
    }
    records.push(("bare central signature".into(), b"PK\x01\x02 junk".to_vec()));
    for (disk, total) in [(0u16, 1u16), (0, 2), (3, 7)] {
        let mut end = b"PK\x05\x06".to_vec();
        end.extend_from_slice(&disk.to_le_bytes());
        end.extend_from_slice(&disk.to_le_bytes());
        end.extend_from_slice(&total.to_le_bytes());
        end.extend_from_slice(&(total + 1).to_le_bytes());
        records.push((format!("end record {disk} {total}"), end));
    }
    records.push(("bare zip64 end signature".into(), b"PK\x06\x06".to_vec()));
    records
}

#[test]
fn the_same_bytes_get_the_same_verdict_inside_and_past_the_budget() {
    for (label, record) in reader_records() {
        for method in [8u16, 12, 93] {
            let built = RawZip::new(vec![
                known_size_entry("a.bin", method, PAYLOAD, &record),
                RawEntry::stored("b.txt", b"world"),
            ])
            .build();
            let inside = findings_of(&built);
            assert!(!inside.is_empty(), "{label} method {method}");
            assert_eq!(
                findings_with_decode_budget(&built, 0),
                inside,
                "{label} method {method}"
            );
        }
    }
}

#[test]
fn a_record_whose_recheck_the_allowance_cannot_cover_is_refused() {
    for (label, record) in reader_records() {
        let built = RawZip::new(vec![
            known_size_entry("a.bin", 8, PAYLOAD, &record),
            RawEntry::stored("b.txt", b"world"),
        ])
        .build();
        let found = findings_with_budgets(&built, 0, 0);
        assert!(
            unknown(&found, ZipStreamUndecided::BudgetExhausted),
            "{label}: {found:?}"
        );
    }
}

fn deflate_holding_a_header() -> RawEntry {
    let inner = RawZip::new(vec![RawEntry::stored("x.txt", b"inner x")])
        .build()
        .bytes;
    let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::none());
    std::io::Write::write_all(&mut encoder, &inner).unwrap();
    let mut entry = RawEntry::stored("a.bin", &inner);
    entry.method = 8;
    entry.data = encoder.finish().unwrap();
    entry
}

#[test]
fn a_signature_spelled_by_compressed_data_is_cleared_by_the_recheck() {
    let zstd_inner = RawZip::new(vec![RawEntry::stored("x.txt", b"inner x")])
        .build()
        .bytes[..90]
        .to_vec();
    let mut zstd = RawEntry::stored("a.bin", &zstd_inner);
    zstd.method = 93;
    zstd.data = zstd_raw_frame(&zstd_inner);
    for entry in [deflate_holding_a_header(), zstd] {
        assert!(
            entry
                .data
                .array_windows::<4>()
                .any(|&window| window == LFH_SIGNATURE)
        );
        let built = RawZip::new(vec![entry, RawEntry::stored("b.txt", b"world")]).build();
        let before = decoded_so_far();
        let found = findings_with_decode_budget(&built, 0);
        assert!(found.is_empty(), "{found:?}");
        assert!(decoded_so_far() > before);
    }
}

#[test]
fn rechecks_never_decode_more_than_their_allowance() {
    const ALLOWANCE: u64 = 2500;
    let entries = (0..30)
        .map(|i| {
            let mut entry = deflate_holding_a_header();
            entry.name = format!("e{i:02}.bin").into_bytes();
            entry
        })
        .collect();
    let built = RawZip::new(entries).build();
    let before = decoded_so_far();
    findings_with_budgets(&built, 0, ALLOWANCE);
    let spent = decoded_so_far() - before;
    assert!(spent > 0 && spent <= ALLOWANCE + 1, "{spent}");
}

#[test]
fn an_entry_past_the_budget_that_spells_a_signature_is_refused_without_an_allowance() {
    let built = RawZip::new(vec![deflate_holding_a_header()]).build();
    let found = findings_with_budgets(&built, 0, 0);
    assert!(
        unknown(&found, ZipStreamUndecided::BudgetExhausted),
        "{found:?}"
    );
}

/// Entries that each hold a nested archive of about `size` bytes, stored in
/// deflate blocks so the nested records stay visible in the compressed bytes.
fn nested_archives(count: usize, size: usize) -> BuiltZip {
    let members = (0..size / (100 * 1024))
        .map(|i| {
            RawEntry::stored(
                &format!("m{i}"),
                &vec![u8::try_from(i).unwrap(); 100 * 1024],
            )
        })
        .collect();
    let inner = RawZip::new(members).build().bytes;
    let entries = (0..count)
        .map(|i| {
            let mut encoder =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::none());
            std::io::Write::write_all(&mut encoder, &inner).unwrap();
            let mut entry = RawEntry::stored(&format!("n{i:02}.jar"), &inner);
            entry.method = 8;
            entry.data = encoder.finish().unwrap();
            entry
        })
        .collect();
    RawZip::new(entries).build()
}

#[test]
fn nested_archives_beyond_the_budget_pass_when_the_allowance_scales_with_the_quota() {
    const MIB: u64 = 1 << 20;
    let built = nested_archives(14, 2 << 20);
    let allowance = 64 * MIB;
    assert_eq!(findings_with_budgets(&built, 4 * MIB, allowance), []);
    assert_eq!(
        findings_with_budgets(&built, 4 * MIB, allowance),
        findings_of_ignoring_streams(&built)
    );
    let found = findings_with_budgets(&built, 4 * MIB, 4 * MIB);
    assert!(
        unknown(&found, ZipStreamUndecided::BudgetExhausted),
        "{found:?}"
    );
}

fn findings_of_ignoring_streams(built: &BuiltZip) -> Vec<ZipInconsistency> {
    open_with(
        Cursor::new(built.bytes.clone()),
        StreamChecks::Skip,
        crate::Limit::Unbounded,
        ZstdWindowLog::LIBZSTD_DEFAULT,
        crate::formats::zip_reuse::ReusePlan::OFF,
    )
    .unwrap()
    .1
    .findings()
    .to_vec()
}

#[test]
fn a_header_straddling_the_end_of_an_entry_past_the_budget_gets_the_verdict_it_has_inside() {
    let mut entry = known_size_entry("a.bin", 8, PAYLOAD, &unmapped_local());
    entry.declared_compressed = Some((compress(8, PAYLOAD).len() + 10) as u64);
    let built = RawZip::new(vec![entry]).build();
    let inside = findings_of(&built);
    assert!(!inside.is_empty());
    assert_eq!(findings_with_decode_budget(&built, 0), inside);
}

#[test]
fn a_record_deep_inside_a_large_entry_past_the_budget_is_found() {
    let mut data = vec![b'q'; 3 * crate::formats::zip_tail::SCAN_CHUNK + 17];
    data.extend(unmapped_local());
    data.extend(vec![b'q'; 5000]);
    let mut entry = RawEntry::stored("a.bin", &data);
    entry.method = 8;
    entry.data = data;
    let found = findings_with_decode_budget(&RawZip::new(vec![entry]).build(), 0);
    assert!(unknown(&found, ZipStreamUndecided::Rejected), "{found:?}");
}

#[test]
fn the_ignore_policy_decodes_nothing_and_finds_nothing_in_entry_data() {
    let archive_bytes = RawZip::new(vec![known_size_entry(
        "a.bin",
        8,
        PAYLOAD,
        &unmapped_local(),
    )])
    .build();
    let before = decoded_so_far();
    let archive = ZipArchive::new(
        Cursor::new(archive_bytes.bytes.clone()),
        &config(ZipConsistencyPolicy::Ignore),
    )
    .unwrap();
    assert_eq!(decoded_so_far(), before);
    assert!(archive.structure().findings().is_empty());

    let archive = ZipArchive::new(
        Cursor::new(archive_bytes.bytes),
        &config(ZipConsistencyPolicy::Enforce),
    )
    .unwrap();
    assert!(decoded_so_far() > before);
    assert!(!archive.structure().findings().is_empty());
}

#[test]
fn an_archive_opened_without_stream_checks_cannot_be_rebound_to_enforce() {
    let built = RawZip::new(vec![known_size_entry("a.bin", 8, PAYLOAD, &[])]).build();
    let open = || {
        ZipArchive::new(
            Cursor::new(built.bytes.clone()),
            &config(ZipConsistencyPolicy::Ignore),
        )
        .unwrap()
    };
    assert!(
        open()
            .rebind(&config(ZipConsistencyPolicy::Enforce))
            .is_none()
    );
    assert!(
        open()
            .rebind(&config(ZipConsistencyPolicy::Ignore))
            .is_some()
    );
}
