//! Findings about what a streaming reader skips or stops at: stray end
//! records, data descriptors, nameless headers and the read boundaries of the
//! gap search.

use super::*;

fn end_record_of(kind: EndRecordKind) -> &'static [u8; 4] {
    match kind {
        EndRecordKind::Classic => b"PK\x05\x06",
        EndRecordKind::Zip64 => b"PK\x06\x06",
    }
}

fn stray_end(offset: usize, kind: EndRecordKind) -> ZipInconsistency {
    ZipInconsistency::StrayEndRecord {
        offset: offset as u64,
        kind,
    }
}

#[test]
fn end_record_signature_before_an_entry_is_found_whatever_follows_it() {
    for &kind in EndRecordKind::ALL {
        let signature = end_record_of(kind);
        for (label, shape) in [
            ("bare signature", signature.to_vec()),
            ("zeroed record", [signature.to_vec(), vec![0; 60]].concat()),
        ] {
            let (built, at) = gap_before_entry(&shape);
            assert_eq!(findings_of(&built), [stray_end(at, kind)], "{kind} {label}");
        }
    }
}

#[test]
fn signatures_that_do_not_stop_a_streaming_reader_are_not_stray_records() {
    for signature in [b"PK\x06\x07", b"PK\x07\x08", b"PK\x05\x07", b"PK\x01\x01"] {
        let (built, _) = gap_before_entry(signature);
        assert!(findings_of(&built).is_empty(), "{signature:?}");
    }
}

#[test]
fn end_record_signature_in_the_final_gap_hides_nothing_and_is_not_reported() {
    for &kind in EndRecordKind::ALL {
        let mut zip = two_files();
        zip.before_directory = end_record_of(kind).to_vec();
        assert!(findings_of(&zip.build()).is_empty(), "{kind}");
    }
}

#[test]
fn end_record_signature_split_by_a_read_boundary_is_found() {
    for &kind in EndRecordKind::ALL {
        for padding in [GAP_CHUNK - 5, GAP_CHUNK - 3, GAP_CHUNK - 1, GAP_CHUNK] {
            let (built, at) = gap_with_padding(padding, end_record_of(kind));
            assert_eq!(
                findings_of(&built),
                [stray_end(at, kind)],
                "{kind} {padding}"
            );
        }
    }
}

#[test]
fn end_record_in_the_prefix_is_found_only_when_the_file_starts_with_pk() {
    let built = two_files().build();
    for &kind in EndRecordKind::ALL {
        let record = end_record_of(kind).to_vec();
        let relative = [record.clone(), built.bytes.clone()].concat();
        let absolute = with_absolute_offsets(&record, &built);
        for (label, bytes) in [("relative", relative), ("absolute", absolute)] {
            assert_eq!(
                open_bytes(bytes).structure().findings(),
                [stray_end(0, kind)],
                "{kind} {label}"
            );
        }
        let after_pk = [b"PK00".to_vec(), record.clone()].concat();
        let absolute = with_absolute_offsets(&after_pk, &built);
        assert_eq!(
            open_bytes(absolute).structure().findings(),
            [stray_end(4, kind)],
            "{kind} behind PK00"
        );
        let stub = [b"MZ00".to_vec(), record].concat();
        let absolute = with_absolute_offsets(&stub, &built);
        assert!(open_bytes(absolute).structure().findings().is_empty());
    }
}

#[test]
fn each_kind_of_stray_record_keeps_its_own_limit() {
    let (built, _) = gap_before_entry(&b"PK\x05\x06".repeat(40));
    let found = findings_of(&built);
    assert_eq!(found.len(), 16);
    assert!(
        found
            .iter()
            .all(|f| matches!(f, ZipInconsistency::StrayEndRecord { .. }))
    );

    let mixed = [b"PK\x01\x02".repeat(8), b"PK\x05\x06".repeat(8)].concat();
    let (built, _) = gap_before_entry(&mixed);
    assert_eq!(findings_of(&built).len(), 16);
}

#[test]
fn stray_end_record_is_fatal_under_enforce_and_reported_by_verify() {
    let (built, _) = gap_before_entry(b"PK\x05\x06");
    let bytes = built.bytes;
    assert_matches!(
        open_bytes(bytes.clone()).list(&config(ZipConsistencyPolicy::Enforce)),
        Err(ArchiveError::ZipInconsistency(
            ZipInconsistency::StrayEndRecord { .. }
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
                .contains("end of central directory record before an entry")
    }));
}

fn overrun(entry: usize, offset: usize) -> ZipInconsistency {
    ZipInconsistency::DescriptorOverrun {
        entry: ZipEntryIndex::new(entry),
        offset: offset as u64,
    }
}

/// The first entry followed by two stored entries; returns the archive and
/// where the first entry's data ends.
fn first_then_stored(first: RawEntry) -> (BuiltZip, usize) {
    let end = data_end(&first, 0);
    let built = RawZip::new(vec![
        first,
        RawEntry::stored("b.txt", b"stored b\n"),
        RawEntry::stored("c.txt", b"stored c\n"),
    ])
    .build();
    (built, end)
}

fn u32_fields(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}

#[test]
fn descriptor_crc_that_is_a_central_signature_is_a_stray_record() {
    let payload = b"hello hello hello";
    let first = RawEntry::deflated("a.txt", payload).unwrap();
    let descriptor = u32_fields(&[
        u32::from_le_bytes(*b"PK\x01\x02"),
        u32::try_from(first.data.len()).unwrap(),
        u32::try_from(payload.len()).unwrap(),
    ]);
    let (built, end) = first_then_stored(first.with_raw_descriptor(&descriptor));
    assert_eq!(findings_of(&built), [stray(end)]);
}

#[test]
fn descriptor_compressed_size_that_is_an_end_signature_is_a_stray_end_record() {
    let payload = b"hello hello hello";
    let first = RawEntry::deflated("a.txt", payload).unwrap();
    let descriptor = u32_fields(&[
        first.crc,
        u32::from_le_bytes(*b"PK\x05\x06"),
        u32::try_from(payload.len()).unwrap(),
    ]);
    let (built, end) = first_then_stored(first.with_raw_descriptor(&descriptor));
    assert_eq!(
        findings_of(&built),
        [stray_end(end + 4, EndRecordKind::Classic)]
    );
}

#[test]
fn stored_signed_descriptor_of_16_bytes_with_a_zip64_extra_overruns() {
    let first = RawEntry::stored("a.txt", b"stored a\n")
        .with_descriptor(true, false)
        .with_local_extra_field(1, &[0; 16]);
    let (built, end) = first_then_stored(first);
    assert_eq!(findings_of(&built), [overrun(0, end)]);
}

#[test]
fn exact_local_compressed_size_through_a_zip64_extra_does_not_overrun() {
    // bsdtar skips the local size and lists all three entries.
    let data = b"stored a\n";
    let first = RawEntry::stored("a.txt", data)
        .with_descriptor(true, false)
        .with_local_extra_field(1, &(data.len() as u64).to_le_bytes())
        .with_local_sizes(u32::MAX, 0);
    let (built, _) = first_then_stored(first);
    assert!(findings_of(&built).is_empty());
}

#[test]
fn local_compressed_size_spanning_the_next_entry_overruns_with_duplicate_names() {
    let shadowed = RawEntry::stored("a.txt", b"other");
    let survivor = RawEntry::stored("a.txt", b"stored a\n")
        .with_descriptor(true, false)
        .with_local_sizes(4096, 0);
    let end = data_end(&survivor, data_end(&shadowed, 0));
    let built = RawZip::new(vec![shadowed, survivor, RawEntry::stored("c.txt", b"c")]).build();
    assert!(findings_of(&built).contains(&overrun(0, end)));
}

#[test]
fn stored_descriptor_with_the_width_its_zip64_extra_implies_does_not_overrun() {
    let first = RawEntry::stored("a.txt", b"stored a\n").with_descriptor(true, true);
    let (built, _) = first_then_stored(first);
    assert!(findings_of(&built).is_empty());
}

#[test]
fn descriptor_sizes_that_a_longer_layout_reads_from_the_next_header_overrun() {
    const MAGIC: u64 = 0x0403_4b50;
    let mut first = RawEntry::stored("zeros.bin", b"");
    first.data = deflate_zeros(MAGIC);
    first.method = 8;
    first.size = MAGIC;
    let descriptor = u32_fields(&[first.crc, u32::try_from(first.data.len()).unwrap(), 0]);
    let end = data_end(&first, 0);
    let mut built = RawZip::new(vec![
        first.with_raw_descriptor(&descriptor),
        RawEntry::stored("b.txt", b"stored b\n"),
    ])
    .build();
    let second = built.local_offsets[1];
    built.bytes[second + 4..second + 6].fill(0);
    assert_eq!(findings_of(&built), [overrun(0, end)]);
}

#[test]
fn stored_entry_with_an_unsigned_descriptor_is_unbounded() {
    let first = RawEntry::stored("a.txt", b"stored a\n").with_descriptor(false, false);
    let (built, end) = first_then_stored(first);
    assert_eq!(findings_of(&built), [overrun(0, end)]);
}

#[test]
fn escaped_local_sizes_resolve_through_the_zip64_extra() {
    let escaped = RawEntry::stored("a.txt", b"stored a\n")
        .with_descriptor(true, false)
        .with_local_extra_field(1, &[0; 16])
        .with_local_sizes(u32::MAX, u32::MAX);
    let (built, end) = first_then_stored(escaped);
    assert!(findings_of(&built).contains(&overrun(0, end)));

    let plain = RawEntry::stored("a.txt", b"stored a\n").with_descriptor(true, false);
    let (built, _) = first_then_stored(plain);
    assert!(findings_of(&built).is_empty());
}

#[test]
fn local_compressed_size_does_not_bound_a_stored_descriptor_entry() {
    let data = b"stored a\n";
    let len = u32::try_from(data.len()).unwrap();
    let first = RawEntry::stored("a.txt", data)
        .with_descriptor(false, false)
        .with_local_sizes(len, len);
    let (built, end) = first_then_stored(first);
    assert!(findings_of(&built).contains(&overrun(0, end)));
}

#[test]
fn symlink_marked_by_a_local_extra_does_not_bound_a_stored_descriptor_entry() {
    let data = b"stored a\n";
    let len = u32::try_from(data.len()).unwrap();
    let mut link_extra = vec![4u8];
    link_extra.extend_from_slice(&(0o120_777u32 << 16).to_le_bytes());
    let first = RawEntry::stored("a.txt", data)
        .with_descriptor(false, false)
        .with_local_sizes(len, len)
        .with_local_extra_field(0x6C78, &link_extra);
    let (built, end) = first_then_stored(first);
    assert!(findings_of(&built).contains(&overrun(0, end)));
}

#[test]
fn deflated_entry_with_a_local_compressed_size_past_the_next_header_overruns() {
    let first = RawEntry::deflated("a.txt", b"hello hello hello")
        .unwrap()
        .with_descriptor(true, false)
        .with_local_sizes(4096, 0);
    let (built, end) = first_then_stored(first);
    assert!(findings_of(&built).contains(&overrun(0, end)));
}

#[test]
fn descriptor_overrun_is_fatal_under_enforce_and_reported_by_verify() {
    let first = RawEntry::stored("a.txt", b"stored a\n").with_descriptor(false, false);
    let bytes = first_then_stored(first).0.bytes;
    assert_matches!(
        open_bytes(bytes.clone()).list(&config(ZipConsistencyPolicy::Enforce)),
        Err(ArchiveError::ZipInconsistency(
            ZipInconsistency::DescriptorOverrun { .. }
        ))
    );
    let report = open_bytes(bytes.clone())
        .verify(
            &config(ZipConsistencyPolicy::Enforce),
            &VerificationOptions::default(),
        )
        .unwrap();
    assert_eq!(report.status(), VerificationStatus::Fail);
    assert!(report.issues().iter().any(|i| {
        i.category == IssueCategory::HiddenEntry && i.message.contains("data descriptor of entry 0")
    }));
    assert!(
        open_bytes(bytes)
            .list(&config(ZipConsistencyPolicy::Ignore))
            .is_ok()
    );
}

#[test]
fn descriptor_overrun_is_found_with_duplicate_names_too() {
    let shadowed = RawEntry::stored("a.txt", b"stored a\n");
    let survivor = RawEntry::stored("a.txt", b"stored b\n").with_descriptor(false, false);
    let end = data_end(&survivor, data_end(&shadowed, 0));
    let built = RawZip::new(vec![shadowed, survivor, RawEntry::stored("c.txt", b"c")]).build();
    assert!(findings_of(&built).contains(&overrun(0, end)));
}

#[test]
fn hidden_header_behind_every_descriptor_width_is_probed_with_duplicate_names() {
    let evil = evil_local();
    for (signature, zip64, width) in [
        (true, false, 16usize),
        (false, false, 12),
        (true, true, 24),
        (false, true, 20),
    ] {
        let shadowed = RawEntry::stored("a.txt", b"other");
        let mut survivor = RawEntry::deflated("a.txt", b"hello")
            .unwrap()
            .with_descriptor(signature, zip64);
        survivor.padding_after = evil.len();
        let end = data_end(&survivor, data_end(&shadowed, 0));
        let mut built = RawZip::new(vec![shadowed, survivor]).build();
        built.bytes[end + width..end + width + evil.len()].copy_from_slice(&evil);
        assert!(
            findings_of(&built).contains(&hidden_at(end + width)),
            "{signature} {zip64}"
        );
    }
}

#[test]
fn nameless_header_in_a_gap_is_found_when_it_skips_data() {
    let nameless = |compressed: u32| {
        let mut header = b"PK\x03\x04".to_vec();
        header.extend_from_slice(&[0; 14]);
        header.extend_from_slice(&compressed.to_le_bytes());
        header.extend_from_slice(&[0; 8]);
        header
    };
    let skip = u32::try_from(LFH_FIXED_LEN + "b.txt".len() + "stored b\n".len()).unwrap();
    let mut first = RawEntry::stored("a.txt", b"hello");
    first.padding_after = LFH_FIXED_LEN;
    let mut built = RawZip::new(vec![first, RawEntry::stored("b.txt", b"stored b\n")]).build();
    let at = built.local_offsets[1] - LFH_FIXED_LEN;
    built.bytes[at..at + LFH_FIXED_LEN].copy_from_slice(&nameless(skip));
    assert_eq!(findings_of(&built), [hidden_at(at)]);

    built.bytes[at..at + LFH_FIXED_LEN].copy_from_slice(&nameless(0));
    assert!(findings_of(&built).is_empty());
}

#[test]
fn header_split_by_a_read_boundary_is_found_whatever_the_overlap() {
    let local = evil_local();
    for tail in 4..=36 {
        let padding = GAP_CHUNK - tail;
        let mut zip = RawZip::new(vec![RawEntry::stored("a.txt", b"hello")]);
        zip.before_directory = [vec![0u8; padding], local.clone()].concat();
        let built = zip.build();
        let at = built.directory_start - local.len();
        assert_eq!(findings_of(&built), [hidden_at(at)], "{tail}");
    }
}

#[test]
fn a_gap_just_under_two_chunks_takes_two_reads() {
    let mut first = RawEntry::stored("a.txt", b"hello");
    first.padding_after = 2 * GAP_CHUNK - 40;
    let built = RawZip::new(vec![first, RawEntry::stored("b.txt", b"world")]).build();
    let archive = open_bytes(built.bytes);
    assert!(archive.structure().findings().is_empty());
    assert_eq!(archive.structure().gap_reads(), 2);
}

#[test]
fn signature_in_the_overlap_of_two_chunks_is_reported_once() {
    for signature in [b"PK\x01\x02", b"PK\x05\x06"] {
        let mut first = RawEntry::stored("a.txt", b"hello");
        first.padding_after = GAP_CHUNK + 100;
        let mut built = RawZip::new(vec![first, RawEntry::stored("b.txt", b"world")]).build();
        let at = built.local_offsets[1] - 100 - 10;
        built.bytes[at..at + 4].copy_from_slice(signature);
        let found = findings_of(&built);
        assert_eq!(found.len(), 1, "{signature:?}: {found:?}");
        let reported = match found[0] {
            ZipInconsistency::StrayCentralRecord { offset }
            | ZipInconsistency::StrayEndRecord { offset, .. } => offset,
            ref other => panic!("{other:?}"),
        };
        assert_eq!(reported, at as u64);
    }
}

#[test]
fn central_signature_at_offset_zero_is_reported() {
    let bytes = [b"PK\x01\x02".to_vec(), two_files().build().bytes].concat();
    assert_eq!(open_bytes(bytes).structure().findings(), [stray(0)]);
}

#[test]
fn truncated_header_at_the_end_of_the_last_chunk_is_judged_from_the_file() {
    // The fake header in the 4-byte gap spills into the next entry's header,
    // whose uncompressed size lands on its name and extra lengths.
    let mut first = RawEntry::stored("a.txt", b"hello");
    first.padding_after = 4;
    let mut built = RawZip::new(vec![first, RawEntry::stored("b.txt", b"world")]).build();
    let at = built.local_offsets[1] - 4;
    built.bytes[at..at + 4].copy_from_slice(b"PK\x03\x04");
    assert_eq!(findings_of(&built), [hidden_at(at)]);
}

#[test]
fn truncated_header_at_the_end_of_a_middle_chunk_costs_no_extra_read() {
    let local = evil_local();
    let mut zip = RawZip::new(vec![RawEntry::stored("a.txt", b"hello")]);
    zip.before_directory = [vec![0u8; GAP_CHUNK - 20], local.clone()].concat();
    let built = zip.build();
    let archive = open_bytes(built.bytes.clone());
    assert_eq!(
        archive.structure().findings(),
        [hidden_at(built.directory_start - local.len())]
    );
    assert_eq!(archive.structure().gap_reads(), 2);
}
