//! The encoded 7z header is decoded under `max_decoder_memory` (#674): the
//! header coder's declared dictionary, the plain and decoded header sizes are
//! all held to it, and a refusal is `QuotaExceeded { DecoderMemory }` from
//! `list`, `verify` and `extract` alike.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

use std::assert_matches;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::QuotaResource;
use exarch_core::SecurityConfig;
use exarch_core::VerifyRequest;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use exarch_core::non_zero;
use tempfile::TempDir;

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
