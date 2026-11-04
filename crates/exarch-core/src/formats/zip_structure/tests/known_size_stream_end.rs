//! Compressed entries whose local header states their sizes: where a
//! streaming reader resumes when their stream ends before the declared end.

use super::descriptor_resume::findings_with_budgets;
use super::descriptor_resume::findings_with_decode_budget;
use super::*;
use crate::ZipStreamUndecided;

const NAME_LEN: usize = 5;
const PAYLOAD: &[u8] = b"hello hello hello hello";
const METHODS: [u16; 3] = [8, 12, 93];

/// An entry without a descriptor whose declared range is `stream + tail`.
fn known_size_entry(method: u16, tail: &[u8]) -> RawEntry {
    let mut entry = RawEntry::stored("a.txt", PAYLOAD);
    entry.method = method;
    entry.data = [compress(method, PAYLOAD), tail.to_vec()].concat();
    entry
}

fn stream_tail_at(built: &BuiltZip, method: u16) -> ZipInconsistency {
    let at = built.local_offsets[0] + LFH_FIXED_LEN + NAME_LEN + compress(method, PAYLOAD).len();
    hidden_in(at, HiddenRegion::StreamTail)
}

fn stream_end_unknown(built: &BuiltZip, reason: ZipStreamUndecided) -> ZipInconsistency {
    ZipInconsistency::StreamEndUnknown {
        entry: ZipEntryIndex::new(0),
        offset: built.directory_start as u64,
        reason,
    }
}

#[test]
fn a_header_behind_the_stream_end_of_a_known_size_entry_is_found() {
    for method in METHODS {
        let built = RawZip::new(vec![known_size_entry(method, &unmapped_local())]).build();
        assert_eq!(
            findings_of(&built),
            [stream_tail_at(&built, method)],
            "method {method}"
        );
    }
}

#[test]
fn a_header_behind_the_stream_end_is_found_before_another_entry() {
    for method in METHODS {
        let built = RawZip::new(vec![
            known_size_entry(method, &unmapped_local()),
            RawEntry::stored("b.txt", b"world"),
        ])
        .build();
        assert_eq!(
            findings_of(&built),
            [stream_tail_at(&built, method)],
            "method {method}"
        );
    }
}

#[test]
fn a_record_signature_behind_the_stream_end_is_a_stray_record() {
    let central = [b"PK\x01\x02".to_vec(), vec![0; 42]].concat();
    let end = [b"PK\x05\x06".to_vec(), vec![0; 18]].concat();
    for method in METHODS {
        for record in [&central, &end] {
            let built = RawZip::new(vec![
                known_size_entry(method, record),
                RawEntry::stored("b.txt", b"x"),
            ])
            .build();
            let found = findings_of(&built);
            assert!(
                found.iter().any(|f| matches!(
                    f,
                    ZipInconsistency::StrayCentralRecord { .. }
                        | ZipInconsistency::StrayEndRecord { .. }
                )),
                "method {method}: {found:?}"
            );
        }
    }
}

#[test]
fn a_header_behind_the_stream_end_is_fatal_under_enforce_with_plain_verify() {
    let built = RawZip::new(vec![known_size_entry(8, &unmapped_local())]).build();
    assert_matches!(
        open_bytes(built.bytes.clone(), &config(ZipConsistencyPolicy::Enforce)).list(),
        Err(ArchiveError::ZipInconsistency(
            ZipInconsistency::HiddenLocalHeader {
                region: HiddenRegion::StreamTail,
                ..
            }
        ))
    );
    let report = open_bytes(built.bytes.clone(), &config(ZipConsistencyPolicy::Enforce))
        .verify(&VerificationOptions::default())
        .unwrap();
    assert_eq!(report.status(), VerificationStatus::Fail);
    assert_eq!(hidden_issues(&report).len(), 1);
    assert!(
        open_bytes(built.bytes, &config(ZipConsistencyPolicy::Ignore))
            .list()
            .is_ok()
    );
}

#[test]
fn a_header_behind_the_stream_end_is_found_with_duplicate_names() {
    let built = RawZip::new(vec![
        RawEntry::stored("a.txt", b"first"),
        known_size_entry(8, &unmapped_local()),
    ])
    .build();
    let at = built.local_offsets[1] + LFH_FIXED_LEN + NAME_LEN + compress(8, PAYLOAD).len();
    let found = findings_of(&built);
    assert!(
        found.contains(&hidden_in(at, HiddenRegion::StreamTail)),
        "{found:?}"
    );
}

#[test]
fn ordinary_known_size_entries_have_no_findings() {
    for method in METHODS {
        let built = RawZip::new(vec![
            known_size_entry(method, &[]),
            RawEntry::stored("b.txt", b"world"),
        ])
        .build();
        let found = findings_of(&built);
        assert!(found.is_empty(), "method {method}: {found:?}");
    }
}

#[test]
fn a_stream_ending_exactly_at_the_declared_end_needs_no_gap_search() {
    for method in METHODS {
        let built = RawZip::new(vec![known_size_entry(method, &[])]).build();
        let archive = open_bytes(built.bytes, &SecurityConfig::default());
        assert!(archive.structure().findings().is_empty(), "method {method}");
    }
}

#[test]
fn slack_without_a_record_signature_is_not_a_finding() {
    for method in METHODS {
        let built = RawZip::new(vec![
            known_size_entry(method, &[0; 40]),
            RawEntry::stored("b.txt", b"world"),
        ])
        .build();
        let found = findings_of(&built);
        assert!(found.is_empty(), "method {method}: {found:?}");
    }
}

#[test]
fn archives_written_by_common_producers_have_no_findings() {
    use std::io::Write;

    for method in [
        zip::CompressionMethod::Deflated,
        zip::CompressionMethod::Bzip2,
        zip::CompressionMethod::Zstd,
    ] {
        let mut zip = zip::write::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default().compression_method(method);
        for (name, len) in [("a.txt", 5usize), ("b.bin", 200_000), ("c.txt", 300)] {
            zip.start_file(name, options).unwrap();
            zip.write_all(&vec![b'k'; len]).unwrap();
        }
        let bytes = zip.finish().unwrap().into_inner();
        assert!(
            open_bytes(bytes, &SecurityConfig::default())
                .structure()
                .findings()
                .is_empty()
        );
    }
}

#[test]
fn an_empty_compressed_entry_with_no_data_is_not_a_finding() {
    let mut entry = RawEntry::stored("a.txt", b"");
    entry.method = 8;
    entry.data = Vec::new();
    assert!(findings_of(&RawZip::new(vec![entry]).build()).is_empty());
}

#[test]
fn a_known_size_entry_the_budget_cannot_cover_is_checked_again_when_it_holds_a_record() {
    for method in METHODS {
        let built = RawZip::new(vec![known_size_entry(method, &unmapped_local())]).build();
        assert_eq!(
            findings_with_decode_budget(&built, 0),
            [stream_tail_at(&built, method)],
            "method {method}"
        );
        let found = findings_with_budgets(&built, 0, 0);
        assert_eq!(
            found,
            [stream_end_unknown(
                &built,
                ZipStreamUndecided::BudgetExhausted
            )],
            "method {method}"
        );
    }
}

#[test]
fn a_known_size_entry_the_budget_cannot_cover_passes_without_a_record_signature() {
    for method in METHODS {
        let built = RawZip::new(vec![known_size_entry(method, &[0; 40])]).build();
        let found = findings_with_decode_budget(&built, 0);
        assert!(found.is_empty(), "method {method}: {found:?}");
    }
}

#[test]
fn a_known_size_entry_within_the_budget_finds_the_header() {
    let size = PAYLOAD.len() as u64;
    for method in METHODS {
        let built = RawZip::new(vec![known_size_entry(method, &unmapped_local())]).build();
        for budget in [size, size + 1, u64::MAX] {
            assert_eq!(
                findings_with_decode_budget(&built, budget),
                [stream_tail_at(&built, method)],
                "method {method} budget {budget}"
            );
        }
    }
}

#[test]
fn a_declared_size_smaller_than_the_stream_does_not_change_where_the_stream_ends() {
    for method in METHODS {
        let mut entry = known_size_entry(method, &[]);
        entry.size = 5;
        let built = RawZip::new(vec![entry]).build();
        assert!(findings_of(&built).is_empty(), "method {method}");

        let mut entry = known_size_entry(method, &unmapped_local());
        entry.size = 5;
        let built = RawZip::new(vec![entry]).build();
        assert_eq!(
            findings_of(&built),
            [stream_tail_at(&built, method)],
            "method {method}"
        );
    }
}

#[test]
fn a_stream_the_decoder_rejects_is_refused() {
    for method in METHODS {
        let mut entry = known_size_entry(method, &[]);
        entry.data = vec![0xff; 40];
        let built = RawZip::new(vec![entry]).build();
        assert_eq!(
            findings_of(&built),
            [stream_end_unknown(&built, ZipStreamUndecided::Rejected)],
            "method {method}"
        );
    }
}

#[test]
fn a_stream_running_past_the_declared_range_is_refused() {
    for method in METHODS {
        let mut entry = known_size_entry(method, &[]);
        entry.data.truncate(entry.data.len() - 2);
        let built = RawZip::new(vec![entry, RawEntry::stored("b.txt", b"x")]).build();
        let found = findings_of(&built);
        assert!(
            found
                .iter()
                .any(|f| matches!(f, ZipInconsistency::StreamEndUnknown { .. })),
            "method {method}: {found:?}"
        );
    }
}
