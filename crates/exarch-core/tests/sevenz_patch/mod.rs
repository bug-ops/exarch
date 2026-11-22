//! Byte-level edits of the encrypted 7z fixtures in `tests/data/encryption`,
//! shared by the encryption precedence and mixed-block tests.

#![expect(clippy::disallowed_methods, reason = "test fixture setup")]
#![allow(dead_code, reason = "helpers are used by only some test binaries")]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]

use std::path::Path;
use std::path::PathBuf;

const SIGNATURE_HEADER: usize = 32;
const AES_METHOD_ID: [u8; 4] = [0x06, 0xF1, 0x07, 0x01];
const RAW_KEY_POWER: u8 = 0x3F;

pub fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/encryption")
        .join(name)
}

pub fn fixture_bytes(name: &str) -> Vec<u8> {
    std::fs::read(fixture_path(name)).unwrap()
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn le_u64(bytes: &[u8]) -> usize {
    usize::try_from(u64::from_le_bytes(bytes.try_into().unwrap())).unwrap()
}

/// Range of the next header (the plain header, or the plain description of an
/// encoded header) inside `bytes`.
fn next_header(bytes: &[u8]) -> std::ops::Range<usize> {
    let offset = le_u64(&bytes[12..20]);
    let size = le_u64(&bytes[20..28]);
    let start = SIGNATURE_HEADER + offset;
    start..start + size
}

/// Offset one past the last packed-stream byte: where the next header starts.
pub fn packed_streams_end(bytes: &[u8]) -> usize {
    next_header(bytes).start
}

fn refresh_crcs(bytes: &mut [u8]) {
    let range = next_header(bytes);
    let next_crc = crc32(&bytes[range]);
    bytes[28..32].copy_from_slice(&next_crc.to_le_bytes());
    let start_crc = crc32(&bytes[12..32]);
    bytes[8..12].copy_from_slice(&start_crc.to_le_bytes());
}

/// `bytes` with the `NumCyclesPower` of every AES coder described by the next
/// header set to the raw-key value `0x3F`, and the header checksums repaired.
pub fn with_raw_key_aes_coders(mut bytes: Vec<u8>) -> Vec<u8> {
    let range = next_header(&bytes);
    let mut patched = 0;
    let mut at = range.start;
    while at + AES_METHOD_ID.len() + 2 < range.end {
        if bytes[at..at + AES_METHOD_ID.len()] == AES_METHOD_ID {
            let first_property = at + AES_METHOD_ID.len() + 1;
            bytes[first_property] = (bytes[first_property] & 0xC0) | RAW_KEY_POWER;
            patched += 1;
            at = first_property;
        }
        at += 1;
    }
    assert!(patched > 0, "no AES coder in the next header");
    refresh_crcs(&mut bytes);
    bytes
}

/// `bytes` with one bit flipped at `offset`.
pub fn flipped(mut bytes: Vec<u8>, offset: usize) -> Vec<u8> {
    bytes[offset] ^= 0x01;
    bytes
}

/// Writes `bytes` as `name` inside `dir` and returns its path.
pub fn written(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}
