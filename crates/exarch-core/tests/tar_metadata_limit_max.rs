//! A `max_tar_metadata_bytes` of `u64::MAX` is a legal budget: the budget no
//! longer uses that value as its disarmed marker.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

use std::num::NonZeroU64;

use exarch_core::ArchiveReader;
use exarch_core::ListOptions;
use exarch_core::MemoryExtractRequest;
use exarch_core::NoopProgress;
use exarch_core::SecurityConfig;
use exarch_core::extract_reader_to_memory;
use exarch_core::list_reader;

fn pax_tar() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    builder
        .append_pax_extensions([("comment", &b"a pax record"[..])])
        .unwrap();
    let mut header = tar::Header::new_gnu();
    header.set_size(2);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "a.txt", &b"hi"[..])
        .unwrap();
    builder.into_inner().unwrap()
}

fn maximal() -> SecurityConfig {
    SecurityConfig::default().with_max_tar_metadata_bytes(NonZeroU64::MAX)
}

#[test]
fn a_pax_tar_lists_under_the_maximal_budget() {
    let reader = ArchiveReader::from_bytes(pax_tar(), None).unwrap();
    let manifest = list_reader(reader, &maximal(), &ListOptions::default()).unwrap();
    assert_eq!(manifest.total_entries(), 1);
}

#[test]
fn a_pax_tar_extracts_under_the_maximal_budget() {
    let reader = ArchiveReader::from_bytes(pax_tar(), None).unwrap();
    let request = MemoryExtractRequest::default().with_config(maximal());
    let (report, _) = extract_reader_to_memory(reader, &request, &mut NoopProgress).unwrap();
    assert_eq!(report.files_extracted, 1);
}
