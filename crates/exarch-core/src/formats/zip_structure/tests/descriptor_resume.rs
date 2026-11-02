//! Data-descriptor entries of every method: where a streaming reader resumes
//! inside and behind the declared range, found without an integrity pass.

use std::io::Write;

use super::*;

const NAME_LEN: usize = 5;

fn data_start(built: &BuiltZip, entry: usize) -> usize {
    built.local_offsets[entry] + LFH_FIXED_LEN + NAME_LEN
}

fn has_overrun(found: &[ZipInconsistency], entry: usize) -> bool {
    found.iter().any(
        |f| matches!(f, ZipInconsistency::DescriptorOverrun { entry: e, .. } if e.get() == entry),
    )
}

fn plain_verify(bytes: Vec<u8>) -> crate::VerificationReport {
    open_bytes(bytes)
        .verify(
            &config(ZipConsistencyPolicy::Enforce),
            &VerificationOptions::default(),
        )
        .unwrap()
}

#[test]
fn deflate_header_behind_the_stream_end_is_found_without_integrity() {
    let payload = b"hello hello hello hello";
    let stream_len = compress(8, payload).len();
    let signed = descriptor(payload, 0);
    for (tail, skipped) in [
        ([signed.clone(), evil_local()].concat(), 16),
        ([signed[4..].to_vec(), evil_local()].concat(), 12),
        (evil_local(), 0),
    ] {
        let built = RawZip::new(vec![descriptor_entry(8, payload, &tail)]).build();
        let at = data_start(&built, 0) + stream_len + skipped;
        assert_eq!(
            findings_of(&built),
            [hidden_in(at, HiddenRegion::DescriptorTail)],
            "{skipped}"
        );
        let report = plain_verify(built.bytes.clone());
        assert_eq!(report.status(), VerificationStatus::Fail, "{skipped}");
        assert_eq!(hidden_issues(&report).len(), 1, "{skipped}");
        assert_eq!(
            hidden_issues(&verify_with_integrity(built.bytes)).len(),
            1,
            "{skipped}"
        );
    }
}

#[test]
fn deflate_header_behind_the_stream_end_is_fatal_for_listing_under_enforce() {
    let payload = b"hello hello hello hello";
    let tail = [descriptor(payload, 0), evil_local()].concat();
    let built = RawZip::new(vec![descriptor_entry(8, payload, &tail)]).build();
    assert_matches!(
        open_bytes(built.bytes.clone()).list(&config(ZipConsistencyPolicy::Enforce)),
        Err(ArchiveError::ZipInconsistency(
            ZipInconsistency::HiddenLocalHeader {
                region: HiddenRegion::DescriptorTail,
                ..
            }
        ))
    );
    assert!(
        open_bytes(built.bytes)
            .list(&config(ZipConsistencyPolicy::Ignore))
            .is_ok()
    );
}

#[test]
fn deflate_header_behind_the_stream_end_is_found_with_duplicate_names() {
    let payload = b"hello hello hello hello";
    let tail = [descriptor(payload, 0), evil_local()].concat();
    let built = RawZip::new(vec![
        RawEntry::stored("a.txt", b"first"),
        descriptor_entry(8, payload, &tail),
    ])
    .build();
    let at = data_start(&built, 1) + compress(8, payload).len() + 16;
    assert!(findings_of(&built).contains(&hidden_in(at, HiddenRegion::DescriptorTail)));
}

#[test]
fn deflate_stream_holding_a_header_signature_is_not_a_hidden_header() {
    let inner = RawZip::new(vec![
        RawEntry::stored("x.txt", b"inner x").with_descriptor(true, false),
    ])
    .build()
    .bytes;
    let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::none());
    encoder.write_all(&inner).unwrap();
    let stored_blocks = encoder.finish().unwrap();
    assert!(
        stored_blocks
            .windows(4)
            .any(|window| window == LFH_SIGNATURE)
    );
    let mut entry = RawEntry::stored("a.txt", &inner).with_descriptor(true, false);
    entry.method = 8;
    entry.data = stored_blocks;
    let built = RawZip::new(vec![entry, RawEntry::stored("b.txt", b"world")]).build();
    assert!(findings_of(&built).is_empty());
    assert!(hidden_issues(&verify_with_integrity(built.bytes)).is_empty());
}

#[test]
fn deflate_streaming_writer_archive_has_no_findings() {
    let mut zip = zip::write::ZipWriter::new_stream(Vec::new());
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, len) in [("a.txt", 5usize), ("b.bin", 200_000), ("c.txt", 300)] {
        zip.start_file(name, options).unwrap();
        zip.write_all(&vec![b'k'; len]).unwrap();
    }
    let bytes = zip.finish().unwrap().into_inner();
    assert!(open_bytes(bytes).structure().findings().is_empty());
}

fn zstd_raw_frame(content: &[u8]) -> Vec<u8> {
    let len = u8::try_from(content.len()).unwrap();
    let block = u32::try_from(content.len() << 3 | 1).unwrap().to_le_bytes();
    [
        &[0x28, 0xb5, 0x2f, 0xfd, 0x20, len][..],
        &block[..3],
        content,
    ]
    .concat()
}

#[test]
fn zstd_header_behind_a_descriptor_signature_in_the_frame_is_found_without_integrity() {
    let mut content = b"benign text\n".to_vec();
    content.extend_from_slice(b"PK\x07\x08");
    content.extend_from_slice(&[0; 12]);
    content.extend(evil_local());
    assert!(content.len() < 256);
    let mut entry = RawEntry::stored("a.txt", &content).with_descriptor(true, false);
    entry.method = 93;
    entry.data = zstd_raw_frame(&content);
    let built = RawZip::new(vec![entry]).build();
    let at = data_start(&built, 0) + 9 + 12 + 16;
    assert_eq!(
        findings_of(&built),
        [hidden_in(at, HiddenRegion::DescriptorTail)]
    );
    assert_eq!(hidden_issues(&plain_verify(built.bytes.clone())).len(), 1);
    assert_eq!(hidden_issues(&verify_with_integrity(built.bytes)).len(), 1);
}

#[test]
fn bzip2_and_zstd_entries_with_an_honest_descriptor_have_no_findings() {
    let payload = b"hello hello hello hello";
    for method in [0u16, 8, 12, 93] {
        let built = RawZip::new(vec![
            descriptor_entry(method, payload, &[]),
            RawEntry::stored("b.txt", b"world").with_descriptor(true, false),
        ])
        .build();
        let found = findings_of(&built);
        assert!(found.is_empty(), "method {method}: {found:?}");
    }
}

fn forged_crc_entry(method: u16, crc_xor: u32) -> BuiltZip {
    let payload = b"echo benign\n";
    let mut first = descriptor_entry(method, payload, &[]);
    let mut raw = b"PK\x07\x08".to_vec();
    raw.extend_from_slice(&(first.crc ^ crc_xor).to_le_bytes());
    raw.extend_from_slice(&u32::try_from(first.data.len()).unwrap().to_le_bytes());
    raw.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
    first = first.with_raw_descriptor(&raw);
    RawZip::new(vec![first, RawEntry::stored("b.txt", b"echo second\n")]).build()
}

#[test]
fn a_descriptor_with_a_forged_crc_does_not_end_a_scanned_entry() {
    for method in [0u16, 12, 93] {
        let found = findings_of(&forged_crc_entry(method, 0xDEAD_BEEF));
        assert!(has_overrun(&found, 0), "method {method}: {found:?}");
    }
}

#[test]
fn a_descriptor_with_the_entrys_crc_ends_a_scanned_entry() {
    for method in [0u16, 12, 93] {
        let found = findings_of(&forged_crc_entry(method, 0));
        assert!(found.is_empty(), "method {method}: {found:?}");
    }
}

#[test]
fn a_forged_descriptor_crc_is_fatal_under_enforce_with_plain_verify() {
    let built = forged_crc_entry(0, 0xDEAD_BEEF);
    let report = plain_verify(built.bytes.clone());
    assert_eq!(report.status(), VerificationStatus::Fail);
    assert_matches!(
        open_bytes(built.bytes).list(&config(ZipConsistencyPolicy::Enforce)),
        Err(ArchiveError::ZipInconsistency(
            ZipInconsistency::DescriptorOverrun { .. }
        ))
    );
}

#[test]
fn a_forged_crc_does_not_change_a_deflated_entrys_end() {
    let found = findings_of(&forged_crc_entry(8, 0xDEAD_BEEF));
    assert!(found.is_empty(), "{found:?}");
}
