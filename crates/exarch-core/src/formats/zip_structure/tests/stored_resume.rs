//! Stored data-descriptor entries: where a streaming reader resumes inside
//! the declared range.

use std::cell::Cell;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::rc::Rc;

use super::*;

use crate::formats::zip_tail::SCAN_CHUNK;

/// A stored descriptor entry whose data is `filler`, a descriptor with the
/// given sizes, and a complete local entry.
fn stored_with_in_data_header(filler: usize, descriptor_bytes: &[u8]) -> (BuiltZip, usize) {
    let whole = [vec![b'x'; filler], descriptor_bytes.to_vec(), evil_local()].concat();
    let built = RawZip::new(vec![descriptor_entry(0, &whole, &[])]).build();
    let header_at = built.local_offsets[0] + LFH_FIXED_LEN + 5 + filler + descriptor_bytes.len();
    (built, header_at)
}

fn descriptor_with_sizes(compressed: u32, size: u32) -> Vec<u8> {
    let mut bytes = b"PK\x07\x08".to_vec();
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&compressed.to_le_bytes());
    bytes.extend_from_slice(&size.to_le_bytes());
    bytes
}

#[test]
fn stored_dd_in_data_header_any_descriptor_fields() {
    for filler in [40usize, 200_000] {
        for sizes in [(0, 0), (7, 9), (u32::MAX, u32::MAX)] {
            let descriptor = descriptor_with_sizes(sizes.0, sizes.1);
            let (built, at) = stored_with_in_data_header(filler, &descriptor);
            assert_eq!(
                findings_of(&built),
                [hidden_in(at, HiddenRegion::DescriptorTail)],
                "{filler} {sizes:?}"
            );
        }
    }
}

#[test]
fn stored_dd_in_data_resume_signature_split_by_a_read_boundary_is_found() {
    for filler in [SCAN_CHUNK - 5, SCAN_CHUNK - 3, SCAN_CHUNK - 1, SCAN_CHUNK] {
        let (built, at) = stored_with_in_data_header(filler, &descriptor_with_sizes(0, 0));
        assert_eq!(
            findings_of(&built),
            [hidden_in(at, HiddenRegion::DescriptorTail)],
            "{filler}"
        );
    }
}

#[test]
fn stored_dd_in_data_header_is_fatal_under_enforce_with_plain_verify() {
    let bytes = stored_with_in_data_header(40, &descriptor_with_sizes(0, 0))
        .0
        .bytes;
    assert_matches!(
        open_bytes(bytes.clone()).list(&config(ZipConsistencyPolicy::Enforce)),
        Err(ArchiveError::ZipInconsistency(
            ZipInconsistency::HiddenLocalHeader {
                region: HiddenRegion::DescriptorTail,
                ..
            }
        ))
    );
    let report = open_bytes(bytes.clone())
        .verify(
            &config(ZipConsistencyPolicy::Enforce),
            &VerificationOptions::default(),
        )
        .unwrap();
    assert_eq!(report.status(), VerificationStatus::Fail);
    assert_eq!(hidden_issues(&report).len(), 1);
    assert!(
        open_bytes(bytes)
            .list(&config(ZipConsistencyPolicy::Ignore))
            .is_ok()
    );
}

#[test]
fn stored_dd_in_data_header_is_reported_once_with_integrity() {
    let bytes = stored_with_in_data_header(40, &descriptor_with_sizes(0, 0))
        .0
        .bytes;
    assert_eq!(hidden_issues(&verify_with_integrity(bytes)).len(), 1);
}

#[test]
fn stored_dd_legitimate_entries_have_no_findings() {
    let signature_only = [b"PK\x07\x08".as_slice(), &[0; 80]].concat();
    let header_only = [vec![b'y'; 20], b"PK\x03\x04".to_vec(), vec![0; 80]].concat();
    let nameless = [descriptor_with_sizes(0, 0), local_header(64, 0, 0, b"", 0)].concat();
    let payloads: [&[u8]; 5] = [
        b"hello",
        &[b'z'; 300],
        &signature_only,
        &header_only,
        &nameless,
    ];
    for zip64 in [false, true] {
        for payload in payloads {
            let built = RawZip::new(vec![
                RawEntry::stored("a.txt", payload).with_descriptor(true, zip64),
                RawEntry::stored("b.txt", b"world").with_descriptor(true, zip64),
            ])
            .build();
            let found = findings_of(&built);
            assert!(found.is_empty(), "{zip64} {} {found:?}", payload.len());
        }
    }
}

#[test]
fn stored_dd_cut_off_header_is_reported() {
    let truncated = [
        vec![b'x'; 40],
        descriptor_with_sizes(0, 0),
        evil_local()[..LFH_FIXED_LEN + 3].to_vec(),
    ]
    .concat();
    let built = RawZip::new(vec![descriptor_entry(0, &truncated, &[])]).build();
    let at = built.local_offsets[0] + LFH_FIXED_LEN + 5 + 40 + 16;
    assert_eq!(
        findings_of(&built),
        [hidden_in(at, HiddenRegion::DescriptorTail)]
    );
}

#[test]
fn stored_dd_later_header_is_reported() {
    let whole = [
        vec![b'x'; 40],
        descriptor_with_sizes(0, 0),
        vec![0x11; 7],
        evil_local(),
    ]
    .concat();
    let built = RawZip::new(vec![descriptor_entry(0, &whole, &[])]).build();
    let at = built.local_offsets[0] + LFH_FIXED_LEN + 5 + 40 + 16 + 7;
    assert_eq!(
        findings_of(&built),
        [hidden_in(at, HiddenRegion::DescriptorTail)]
    );
}

#[test]
fn stored_dd_later_central_signature_is_a_stray_record() {
    let whole = [
        vec![b'x'; 40],
        descriptor_with_sizes(0, 0),
        b"PK\x01\x02".to_vec(),
        vec![0; 30],
    ]
    .concat();
    let built = RawZip::new(vec![
        descriptor_entry(0, &whole, &[]),
        RawEntry::stored("b.txt", b"world"),
    ])
    .build();
    let at = built.local_offsets[0] + LFH_FIXED_LEN + 5 + 40 + 16;
    assert_eq!(findings_of(&built), [stray(at)]);
}

#[test]
fn stored_dd_search_follows_the_first_signature() {
    let whole = [
        vec![b'x'; 40],
        b"PK\x07\x08".to_vec(),
        vec![0; 60],
        descriptor_with_sizes(0, 0),
        evil_local(),
    ]
    .concat();
    let built = RawZip::new(vec![descriptor_entry(0, &whole, &[])]).build();
    let at = built.local_offsets[0] + LFH_FIXED_LEN + 5 + 40 + 64 + 16;
    assert_eq!(
        findings_of(&built),
        [hidden_in(at, HiddenRegion::DescriptorTail)]
    );
}

#[test]
fn stored_dd_in_data_header_is_found_with_duplicate_names() {
    let whole = [vec![b'x'; 40], descriptor_with_sizes(0, 0), evil_local()].concat();
    let mut survivor = descriptor_entry(0, &whole, &[]);
    survivor.name = b"a.txt".to_vec();
    let built = RawZip::new(vec![RawEntry::stored("a.txt", b"first"), survivor]).build();
    let at = built.local_offsets[1] + LFH_FIXED_LEN + 5 + 40 + 16;
    assert!(findings_of(&built).contains(&hidden_in(at, HiddenRegion::DescriptorTail)));
}

#[test]
fn stored_streaming_writer_archive_has_no_findings() {
    use std::io::Write;

    let mut zip = zip::write::ZipWriter::new_stream(Vec::new());
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, len) in [("a.txt", 5usize), ("b.bin", 200_000), ("c.txt", 300)] {
        zip.start_file(name, options).unwrap();
        zip.write_all(&vec![b'k'; len]).unwrap();
    }
    let bytes = zip.finish().unwrap().into_inner();
    assert!(open_bytes(bytes).structure().findings().is_empty());
}

#[test]
fn stored_dd_holding_a_whole_archive_is_reported_as_accepted_behaviour() {
    let inner = RawZip::new(vec![
        RawEntry::stored("x.txt", b"inner x").with_descriptor(true, false),
        RawEntry::stored("y.txt", b"inner y").with_descriptor(true, false),
    ])
    .build();
    let built = RawZip::new(vec![descriptor_entry(0, &inner.bytes, &[])]).build();
    let found = findings_of(&built);
    assert!(
        found.iter().any(|f| matches!(
            f,
            ZipInconsistency::HiddenLocalHeader {
                region: HiddenRegion::DescriptorTail,
                ..
            }
        )),
        "{found:?}"
    );
}

#[test]
fn stored_entries_without_a_descriptor_are_not_scanned() {
    let whole = [vec![b'x'; 40], descriptor_with_sizes(0, 0), evil_local()].concat();
    let built = RawZip::new(vec![RawEntry::stored("a.txt", &whole)]).build();
    assert!(findings_of(&built).is_empty());
}

#[test]
fn deflate_dd_tail_stays_integrity_only() {
    let payload = b"hello hello hello hello";
    let tail = [descriptor(payload, 0), evil_local()].concat();
    let built = RawZip::new(vec![descriptor_entry(8, payload, &tail)]).build();
    assert!(findings_of(&built).is_empty());
    assert_eq!(hidden_issues(&verify_with_integrity(built.bytes)).len(), 1);
}

#[test]
fn stored_dd_findings_share_the_hidden_header_limit() {
    let entries = (0..20)
        .map(|i| {
            let whole = [vec![b'x'; 8], descriptor_with_sizes(0, 0), evil_local()].concat();
            let mut entry = descriptor_entry(0, &whole, &[]);
            entry.name = format!("e{i:02}.txt").into_bytes();
            entry
        })
        .collect();
    let found = findings_of(&RawZip::new(entries).build());
    assert_eq!(found.len(), 16);
}

fn has_overrun(found: &[ZipInconsistency], entry: usize) -> bool {
    found.iter().any(
        |f| matches!(f, ZipInconsistency::DescriptorOverrun { entry: e, .. } if e.get() == entry),
    )
}

fn signature_ending_the_data() -> Vec<u8> {
    [vec![b'x'; 40], b"PK\x07\x08".to_vec()].concat()
}

fn with_second_entry(first: RawEntry) -> BuiltZip {
    RawZip::new(vec![first, RawEntry::stored("b.txt", b"world")]).build()
}

#[test]
fn stored_dd_resume_inside_the_descriptor_is_not_reported() {
    let first = descriptor_entry(0, &signature_ending_the_data(), &[]);
    assert!(findings_of(&with_second_entry(first)).is_empty());
}

#[test]
fn stored_dd_resume_past_the_next_header_is_reported_for_a_wider_layout() {
    let first =
        descriptor_entry(0, &signature_ending_the_data(), &[]).with_local_extra_field(1, &[0; 16]);
    let found = findings_of(&with_second_entry(first));
    assert!(has_overrun(&found, 0), "{found:?}");
}

#[test]
fn stored_dd_resume_past_the_next_header_is_reported_without_descriptor_bytes() {
    let mut first =
        RawEntry::stored("a.txt", &signature_ending_the_data()).with_raw_descriptor(&[]);
    first.flags |= 0x0008;
    let found = findings_of(&with_second_entry(first));
    assert!(has_overrun(&found, 0), "{found:?}");
}

#[test]
fn stored_dd_header_signature_straddling_the_declared_end_is_reported() {
    let data = [vec![b'x'; 40], b"PK\x07\x08PK\x03".to_vec()].concat();
    let mut descriptor = vec![4u8];
    descriptor.extend_from_slice(&[0; 11]);
    let first = RawEntry::stored("a.txt", &data).with_raw_descriptor(&descriptor);
    let found = findings_of(&with_second_entry(first));
    assert!(has_overrun(&found, 0), "{found:?}");
}

fn duplicate_names_with_header_at(offset_after_signature: Option<usize>) -> BuiltZip {
    let mut data = [vec![b'x'; 40], b"PK\x07\x08".to_vec()].concat();
    if let Some(offset) = offset_after_signature {
        data.extend(vec![0u8; offset - 4]);
        data.extend(evil_local());
    }
    let survivor = descriptor_entry(0, &data, &[]);
    RawZip::new(vec![RawEntry::stored("a.txt", b"first"), survivor]).build()
}

fn assert_probe_finds_header_at(offset: usize) {
    let built = duplicate_names_with_header_at(Some(offset));
    let at = built.local_offsets[1] + LFH_FIXED_LEN + 5 + 40 + offset;
    let found = findings_of(&built);
    assert!(
        found.contains(&hidden_in(at, HiddenRegion::DescriptorTail)),
        "{offset}: {found:?}"
    );
}

#[test]
fn stored_dd_duplicate_names_find_a_header_12_bytes_after_the_signature() {
    assert_probe_finds_header_at(12);
}

#[test]
fn stored_dd_duplicate_names_find_a_header_16_bytes_after_the_signature() {
    assert_probe_finds_header_at(16);
}

#[test]
fn stored_dd_duplicate_names_find_a_header_20_bytes_after_the_signature() {
    assert_probe_finds_header_at(20);
}

#[test]
fn stored_dd_duplicate_names_find_a_header_24_bytes_after_the_signature() {
    assert_probe_finds_header_at(24);
}

#[test]
fn stored_dd_duplicate_names_without_a_header_report_no_hidden_header() {
    let built = duplicate_names_with_header_at(None);
    let found = findings_of(&built);
    assert!(
        !found
            .iter()
            .any(|f| matches!(f, ZipInconsistency::HiddenLocalHeader { .. })),
        "{found:?}"
    );
}

#[test]
fn stored_dd_duplicate_names_probe_a_bounded_number_of_times() {
    let reads_of = |bytes: Vec<u8>| open_bytes(bytes).structure().gap_reads();
    let with_signature = duplicate_names_with_header_at(None);
    let plain = RawZip::new(vec![
        RawEntry::stored("a.txt", b"first"),
        descriptor_entry(0, &[vec![b'x'; 40], b"PKxx".to_vec()].concat(), &[]),
    ]);
    let extra = reads_of(with_signature.bytes).saturating_sub(reads_of(plain.build().bytes));
    assert!(extra <= 5, "{extra}");
}

struct Metered<R> {
    inner: R,
    largest: Rc<Cell<usize>>,
    total: Rc<Cell<u64>>,
}

impl<R: Read> Read for Metered<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.largest.set(self.largest.get().max(n));
        self.total.set(self.total.get() + n as u64);
        Ok(n)
    }
}

impl<R: Seek> Seek for Metered<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// Largest single read and total bytes read while opening `bytes`.
fn open_metered(bytes: Vec<u8>) -> (usize, u64) {
    let largest = Rc::new(Cell::new(0));
    let total = Rc::new(Cell::new(0));
    let reader = Metered {
        inner: Cursor::new(bytes),
        largest: Rc::clone(&largest),
        total: Rc::clone(&total),
    };
    let (_, structure) = open(reader).unwrap();
    assert!(structure.findings().is_empty());
    (largest.get(), total.get())
}

#[test]
fn stored_dd_scan_reads_each_declared_byte_once_in_bounded_chunks() {
    const FILLER: usize = 1 << 20;
    let whole = vec![b'q'; FILLER];
    let plain = RawZip::new(vec![RawEntry::stored("a.txt", &whole)]).build();
    let described = RawZip::new(vec![descriptor_entry(0, &whole, &[])]).build();
    let (plain_largest, plain_total) = open_metered(plain.bytes);
    let (largest, total) = open_metered(described.bytes);
    assert!(largest <= plain_largest.max(SCAN_CHUNK), "{largest}");
    assert!(total <= plain_total + FILLER as u64 + 4096, "{total}");
}
