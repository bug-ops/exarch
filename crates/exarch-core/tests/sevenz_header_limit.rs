//! The encoded 7z header is decoded under `max_decoder_memory` (#674): the
//! header coder's declared dictionary, the plain and decoded header sizes are
//! all held to it, and a refusal is `QuotaExceeded { DecoderMemory }` from
//! `list`, `verify` and `extract` alike.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

use std::assert_matches;
use std::path::Path;
use std::path::PathBuf;

use common::RawEntry;
use common::number;
use common::solid_copy_7z;

use exarch_core::ArchiveError;
use exarch_core::QuotaResource;
use exarch_core::SecurityConfig;
use exarch_core::VerifyRequest;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use exarch_core::non_zero;
use tempfile::TempDir;

mod common;

const KIB: u64 = 1024;

fn fixture_bytes(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name);
    std::fs::read(path).unwrap()
}

fn crc(data: &[u8]) -> [u8; 4] {
    let mut crc = flate2::Crc::new();
    crc.update(data);
    crc.sum().to_le_bytes()
}

/// `simple.7z` with its header coder's LZMA dictionary raised to 1 GiB. The
/// next header is the encoded-header record, whose CRC and the start header
/// CRC are refreshed so the archive opens up to the memory check.
fn simple_with_huge_header_dictionary() -> Vec<u8> {
    const LZMA_PROPS: [u8; 6] = [0x05, 0x5D, 0x00, 0x10, 0x00, 0x00];
    let mut bytes = fixture_bytes("simple.7z");
    let next_header =
        usize::try_from(u64::from_le_bytes(bytes[12..20].try_into().unwrap())).unwrap() + 32;
    let at = bytes[next_header..]
        .windows(LZMA_PROPS.len())
        .position(|w| w == LZMA_PROPS)
        .unwrap()
        + next_header;
    bytes[at + 3..at + 6].copy_from_slice(&[0x00, 0x00, 0x40]);
    let header_crc = crc(&bytes[next_header..]);
    bytes[28..32].copy_from_slice(&header_crc);
    let start_crc = crc(&bytes[12..32]);
    bytes[8..12].copy_from_slice(&start_crc);
    bytes
}

fn write(dir: &TempDir, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join("archive.7z");
    std::fs::write(&path, bytes).unwrap();
    path
}

fn assert_decoder_memory(err: &ArchiveError, max: u64) {
    assert_matches!(
        err,
        ArchiveError::QuotaExceeded { resource: QuotaResource::DecoderMemory { max: m } } if *m == max,
        "{err:?}"
    );
}

fn refused_by_every_operation(path: &std::path::Path, config: &SecurityConfig, max: u64) {
    assert_decoder_memory(&list_archive(path, config).unwrap_err(), max);
    assert_decoder_memory(&VerifyRequest::new(config).verify(path).unwrap_err(), max);
    let out = TempDir::new().unwrap();
    assert_decoder_memory(&extract_archive(path, out.path(), config).unwrap_err(), max);
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

#[test]
fn a_header_dictionary_over_the_limit_is_refused_by_default() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, &simple_with_huge_header_dictionary());
    let config = SecurityConfig::default();

    refused_by_every_operation(&path, &config, config.max_decoder_memory.get());
}

#[test]
fn a_small_cap_refuses_an_archive_with_an_encoded_header_at_open() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, &fixture_bytes("simple.7z"));
    let config = SecurityConfig::default().with_max_decoder_memory(non_zero!(KIB));

    refused_by_every_operation(&path, &config, KIB);
}

#[test]
fn the_default_cap_opens_an_archive_with_an_encoded_header() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, &fixture_bytes("simple.7z"));

    let config = SecurityConfig::default();
    assert!(list_archive(&path, &config).unwrap().total_entries() > 0);
    let out = TempDir::new().unwrap();
    extract_archive(&path, out.path(), &config).unwrap();
}

#[test]
fn a_plain_header_is_held_only_to_its_own_size() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, &fixture_bytes("large-file.7z"));
    let config = SecurityConfig::default().with_max_decoder_memory(non_zero!(KIB));

    assert!(list_archive(&path, &config).unwrap().total_entries() > 0);
}

fn config_with_memory(bytes: u64) -> SecurityConfig {
    SecurityConfig::default().with_max_decoder_memory(std::num::NonZeroU64::new(bytes).unwrap())
}

fn opens(path: &Path, config: &SecurityConfig) -> bool {
    match list_archive(path, config) {
        Ok(_) => true,
        Err(ArchiveError::QuotaExceeded {
            resource: QuotaResource::DecoderMemory { .. },
        }) => false,
        Err(other) => panic!("neither opened nor refused on memory: {other:?}"),
    }
}

/// An archive whose header is the encoded-header record over `decoded`, stored
/// in LZMA2 uncompressed chunks so the file is as large as the header.
fn stored_header_archive(decoded: &[u8]) -> Vec<u8> {
    let mut packed = Vec::new();
    for (i, chunk) in decoded.chunks(1 << 16).enumerate() {
        packed.push(if i == 0 { 0x01 } else { 0x02 });
        packed.extend_from_slice(&u16::try_from(chunk.len() - 1).unwrap().to_be_bytes());
        packed.extend_from_slice(chunk);
    }
    packed.push(0x00);

    let mut record = vec![0x17, 0x06];
    record.extend(number(0));
    record.extend(number(1));
    record.push(0x09);
    record.extend(number(packed.len()));
    record.extend([0x00, 0x07, 0x0B]);
    record.extend(number(1));
    record.push(0x00);
    record.extend(number(1));
    record.extend([0x21, 0x21, 0x01, 0x00]);
    record.push(0x0C);
    record.extend(number(decoded.len()));
    record.extend([0x00, 0x00]);

    let mut start = Vec::new();
    start.extend((packed.len() as u64).to_le_bytes());
    start.extend((record.len() as u64).to_le_bytes());
    start.extend(crc(&record));
    let mut out = vec![b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    out.extend(crc(&start));
    out.extend(start);
    out.extend(packed);
    out.extend(record);
    out
}

/// A decoded header that declares `entries` files and nothing else.
fn entry_count_only_header(entries: usize, padded_to: usize) -> Vec<u8> {
    let mut decoded = vec![0x01, 0x05];
    decoded.extend(number(entries));
    decoded.resize(padded_to, 0);
    decoded
}

#[test]
fn the_stored_header_builder_makes_an_archive_that_opens() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, &stored_header_archive(&[0x01, 0x00]));

    assert!(opens(&path, &SecurityConfig::default()));
}

#[test]
fn a_header_declaring_more_entries_than_max_file_count_allows_is_refused_unparsed() {
    let dir = TempDir::new().unwrap();
    let decoded = entry_count_only_header(200_000, 200_000);
    let path = write(&dir, &stored_header_archive(&decoded));
    let config = SecurityConfig::default().with_max_file_count(non_zero!(10));
    let by_entries = config.max_decoder_memory.get();

    for err in [
        list_archive(&path, &config).unwrap_err(),
        VerifyRequest::new(&config).verify(&path).unwrap_err(),
        extract_archive(&path, TempDir::new().unwrap().path(), &config).unwrap_err(),
    ] {
        assert_matches!(
            err,
            ArchiveError::QuotaExceeded { resource: QuotaResource::DecoderMemory { max } }
                if max < by_entries && max >= 64 * KIB,
            "{err:?}"
        );
    }
}

#[test]
fn the_decoded_header_size_is_held_to_the_limit_when_the_raw_header_is_small() {
    let dir = TempDir::new().unwrap();
    let path = write(
        &dir,
        &stored_header_archive(&entry_count_only_header(0, 200 * 1024)),
    );
    let record_len = u64::from_le_bytes(std::fs::read(&path).unwrap()[20..28].try_into().unwrap());
    assert!(record_len < 100, "the raw header record stays tiny");

    assert!(!opens(&path, &config_with_memory(100 * KIB)));
}

#[test]
fn long_names_within_the_entry_budget_open() {
    let names: Vec<String> = (0..1000)
        .map(|i| format!("{i:04}{}", "n".repeat(196)))
        .collect();
    let entries: Vec<RawEntry<'_>> = names.iter().map(|n| RawEntry::Dir(n)).collect();
    let dir = TempDir::new().unwrap();
    let path = write(&dir, &solid_copy_7z(&entries));
    let config = SecurityConfig::default().with_max_file_count(non_zero!(1000));

    assert_eq!(list_archive(&path, &config).unwrap().total_entries(), 1000);
}

#[test]
fn the_dictionary_branch_is_held_at_the_whole_kib_the_header_needs() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, &fixture_bytes("simple.7z"));

    assert!(opens(&path, &config_with_memory(26 * KIB)));
    assert!(!opens(&path, &config_with_memory(26 * KIB - 1)));
    assert!(!opens(&path, &config_with_memory(25 * KIB)));
}

/// A plain-header archive whose header is exactly `size` bytes, or `None`.
///
/// Directory names grow the header two bytes per character and each file adds
/// one byte of sub-stream size, so the search reaches both parities.
fn plain_header_archive_of(size: usize) -> Option<Vec<u8>> {
    (1..=4).find_map(|dirs| {
        (0..=1).find_map(|files| {
            (1..=400).find_map(|len| {
                let names: Vec<String> = (0..dirs)
                    .map(|i| format!("{i}{}", "a".repeat(len)))
                    .collect();
                let mut raw: Vec<RawEntry<'_>> = names.iter().map(|n| RawEntry::Dir(n)).collect();
                if files == 1 {
                    raw.push(RawEntry::File("f", b"x"));
                    raw.push(RawEntry::File("g", b"y"));
                }
                let bytes = solid_copy_7z(&raw);
                let header = u64::from_le_bytes(bytes[20..28].try_into().unwrap());
                (header == size as u64).then_some(bytes)
            })
        })
    })
}

#[test]
fn a_plain_header_is_held_at_exactly_the_limit() {
    let at_limit = plain_header_archive_of(1024).unwrap();
    let over = plain_header_archive_of(1026).unwrap();
    let dir = TempDir::new().unwrap();

    let path = write(&dir, &at_limit);
    assert!(opens(&path, &config_with_memory(1024)));
    assert!(!opens(&path, &config_with_memory(1023)));
    let path = write(&dir, &over);
    assert!(!opens(&path, &config_with_memory(1024)));
    assert!(opens(&path, &config_with_memory(2048)));
}
