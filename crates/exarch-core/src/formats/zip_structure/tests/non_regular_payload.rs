//! Directory and special entries that declare a payload, and stored
//! descriptor entries whose data holds a descriptor signature.

use super::*;
use crate::ZipNonRegularKind;

const UNIX_DIRECTORY: u32 = 0o040_755 << 16;
const DOS_DIRECTORY: u32 = 0x10;
const DOS_HOST: u16 = 0x001e;
const CHAR_DEVICE: u32 = 0o020_666 << 16;

/// Data of an entry that holds a descriptor signature whose sizes do not match,
/// a complete local entry and a tail, ended by the real descriptor.
fn enclosing_data() -> Vec<u8> {
    let mut data = b"x\n".to_vec();
    data.extend_from_slice(b"PK\x07\x08");
    data.extend_from_slice(&0x2222_2222u32.to_le_bytes());
    data.extend_from_slice(&5u32.to_le_bytes());
    data.extend_from_slice(&5u32.to_le_bytes());
    data.extend(unmapped_local());
    data.extend_from_slice(b"y\n");
    data
}

fn enclosing(name: &str, attributes: u32, made_by: u16) -> RawEntry {
    let mut entry = RawEntry::stored(name, &enclosing_data()).with_descriptor(true, false);
    entry.external_attributes = attributes;
    entry.made_by = made_by;
    entry
}

fn payload(entry: usize, kind: ZipNonRegularKind, compressed_size: usize) -> ZipInconsistency {
    ZipInconsistency::NonRegularPayload {
        entry: ZipEntryIndex::new(entry),
        kind,
        compressed_size: compressed_size as u64,
    }
}

fn payload_findings(found: &[ZipInconsistency]) -> Vec<&ZipInconsistency> {
    found
        .iter()
        .filter(|f| matches!(f, ZipInconsistency::NonRegularPayload { .. }))
        .collect()
}

fn directory_variants() -> [(&'static str, RawEntry); 3] {
    [
        ("unix mode", enclosing("d", UNIX_DIRECTORY, 0x031e)),
        ("dos attribute", enclosing("d", DOS_DIRECTORY, DOS_HOST)),
        ("trailing slash", enclosing("d/", 0o100_644 << 16, 0x031e)),
    ]
}

#[test]
fn a_directory_entry_with_data_is_found_however_it_is_marked() {
    let len = enclosing_data().len();
    for (label, entry) in directory_variants() {
        let built = RawZip::new(vec![entry]).build();
        let found = findings_of(&built);
        assert_eq!(
            payload_findings(&found),
            [&payload(0, ZipNonRegularKind::Directory, len)],
            "{label}: {found:?}"
        );
    }
}

#[test]
fn a_directory_entry_with_data_is_found_with_zero_descriptor_fields() {
    let len = enclosing_data().len();
    for (label, entry) in directory_variants() {
        let zeroed = [b"PK\x07\x08".as_slice(), &[0; 12]].concat();
        let entry = entry.with_raw_descriptor(&zeroed);
        let found = findings_of(&RawZip::new(vec![entry]).build());
        assert!(
            found.contains(&payload(0, ZipNonRegularKind::Directory, len)),
            "{label}: {found:?}"
        );
    }
}

#[test]
fn a_directory_entry_with_data_and_no_descriptor_is_found() {
    let data = enclosing_data();
    for (name, attributes) in [("d/", 0o040_755 << 16), ("d", UNIX_DIRECTORY)] {
        let mut entry = RawEntry::stored(name, &data);
        entry.external_attributes = attributes;
        let found = findings_of(&RawZip::new(vec![entry]).build());
        assert!(
            found.contains(&payload(0, ZipNonRegularKind::Directory, data.len())),
            "{name}: {found:?}"
        );
    }
}

#[test]
fn a_directory_entry_followed_by_a_regular_entry_is_found() {
    let len = enclosing_data().len();
    let built = RawZip::new(vec![
        enclosing("d/", UNIX_DIRECTORY, 0x031e),
        RawEntry::stored("b.txt", b"world"),
    ])
    .build();
    let found = findings_of(&built);
    assert_eq!(
        payload_findings(&found),
        [&payload(0, ZipNonRegularKind::Directory, len)]
    );
    let header_at = built.local_offsets[0] + LFH_FIXED_LEN + 2 + 2 + 16;
    assert!(found.contains(&hidden_in(header_at, HiddenRegion::DescriptorTail)));
}

#[test]
fn a_special_entry_with_data_is_found() {
    let data = b"payload";
    let mut entry = RawEntry::stored("dev", data);
    entry.external_attributes = CHAR_DEVICE;
    let found = findings_of(&RawZip::new(vec![entry]).build());
    assert_eq!(
        payload_findings(&found),
        [&payload(0, ZipNonRegularKind::Special, data.len())]
    );
}

#[test]
fn a_directory_entry_with_data_is_fatal_under_enforce_and_reported_by_verify() {
    let built = RawZip::new(vec![enclosing("d/", UNIX_DIRECTORY, 0x031e)]).build();
    assert_matches!(
        open_bytes(built.bytes.clone(), &config(ZipConsistencyPolicy::Enforce)).list(),
        Err(ArchiveError::ZipInconsistency(
            ZipInconsistency::NonRegularPayload { .. }
        ))
    );
    let report = open_bytes(built.bytes.clone(), &config(ZipConsistencyPolicy::Enforce))
        .verify(VerificationOptions::default())
        .unwrap();
    assert_eq!(report.status(), VerificationStatus::Fail);
    assert!(
        open_bytes(built.bytes, &config(ZipConsistencyPolicy::Ignore))
            .list()
            .is_ok()
    );
}

#[test]
fn empty_directory_entries_are_not_findings() {
    let mut unix = RawEntry::stored("u/", b"");
    unix.external_attributes = UNIX_DIRECTORY;
    let mut dos = RawEntry::stored("d", b"");
    dos.external_attributes = DOS_DIRECTORY;
    dos.made_by = DOS_HOST;
    let mut deflated = RawEntry::deflated("z/", b"").unwrap();
    deflated.external_attributes = UNIX_DIRECTORY;
    assert!(deflated.data.len() < LFH_FIXED_LEN);
    for entry in [unix, dos, deflated] {
        let found = findings_of(&RawZip::new(vec![entry, RawEntry::stored("b", b"x")]).build());
        assert!(found.is_empty(), "{found:?}");
    }
}

#[test]
fn symlink_entries_keep_their_target_as_data() {
    let mut link = RawEntry::stored("link", b"target.txt");
    link.external_attributes = crate::raw_zip::SYMLINK_MODE << 16;
    let found = findings_of(&RawZip::new(vec![link, RawEntry::stored("b", b"x")]).build());
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn a_stored_regular_entry_holding_a_record_is_found_whatever_its_descriptor_states() {
    let built = RawZip::new(vec![enclosing("a.txt", 0o100_644 << 16, 0x031e)]).build();
    let at = built.local_offsets[0] + LFH_FIXED_LEN + 5 + 2 + 16;
    assert_eq!(
        findings_of(&built),
        [hidden_in(at, HiddenRegion::DescriptorTail)]
    );
}

#[test]
fn a_stored_regular_entry_holding_a_record_is_fatal_under_enforce_with_plain_verify() {
    let built = RawZip::new(vec![enclosing("a.txt", 0o100_644 << 16, 0x031e)]).build();
    let report = open_bytes(built.bytes, &config(ZipConsistencyPolicy::Enforce))
        .verify(VerificationOptions::default())
        .unwrap();
    assert_eq!(report.status(), VerificationStatus::Fail);
    assert_eq!(hidden_issues(&report).len(), 1);
}

#[test]
fn a_nested_archive_without_reachable_records_after_a_signature_has_no_findings() {
    let inner = RawZip::new(vec![
        RawEntry::stored("x.txt", b"inner x"),
        RawEntry::stored("y.txt", b"inner y").with_descriptor(false, false),
    ])
    .build();
    let signature_then_unreachable = [
        b"x\n".to_vec(),
        b"PK\x07\x08".to_vec(),
        vec![0; 12],
        local_header(20, 0, 0, b"", 0),
        vec![0; 30],
    ]
    .concat();
    for data in [inner.bytes, signature_then_unreachable] {
        let built = RawZip::new(vec![
            RawEntry::stored("a.bin", &data).with_descriptor(true, false),
            RawEntry::stored("b.txt", b"world"),
        ])
        .build();
        let found = findings_of(&built);
        assert!(found.is_empty(), "{found:?}");
    }
}

#[test]
fn a_nested_archive_with_signed_descriptors_is_found() {
    let inner = RawZip::new(vec![
        RawEntry::stored("x.txt", b"inner x").with_descriptor(true, false),
        RawEntry::stored("y.txt", b"inner y").with_descriptor(true, false),
    ])
    .build();
    let built = RawZip::new(vec![
        RawEntry::stored("a.bin", &inner.bytes).with_descriptor(true, false),
        RawEntry::stored("b.txt", b"world"),
    ])
    .build();
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
fn a_backslash_terminated_name_with_data_is_a_directory_with_a_payload() {
    for name in ["d\\", "sub/d\\"] {
        let data = b"payload bytes";
        let entry = RawEntry::stored(name, data);
        let found = findings_of(&RawZip::new(vec![entry]).build());
        assert!(
            found.contains(&payload(0, ZipNonRegularKind::Directory, data.len())),
            "{name}: {found:?}"
        );
    }
}
