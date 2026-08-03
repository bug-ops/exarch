//! Regression test for GHSA-5j8q-wxg5-hj4r: ZIP extraction trusted the
//! archive-declared `uncompressed_size` field for zip-bomb ratio detection
//! and quota reservation, but never verified it against the number of bytes
//! actually produced by DEFLATE decompression. A ZIP entry could declare a
//! small `uncompressed_size` (passing both checks) while its real DEFLATE
//! stream decompressed to an arbitrarily large payload, since the copy loop
//! had no ceiling tied to the declared/reserved size.
//!
//! This constructs a real, spec-valid DEFLATE ZIP entry at the raw byte
//! level (the `zip` crate's writer computes sizes itself and cannot be made
//! to lie), so the forged header is read by the same DEFLATE decompression
//! path production traffic uses, not a mock.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use exarch_core::ArchiveError;
use exarch_core::ExtractionOptions;
use exarch_core::SecurityConfig;
use exarch_core::formats::ArchiveFormat;
use exarch_core::formats::ZipArchive;
use flate2::Compression;
use flate2::write::DeflateEncoder;
use std::io::Cursor;
use std::io::Write;
use tempfile::TempDir;

/// CRC32 (IEEE 802.3 polynomial) for raw ZIP construction.
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Raw-DEFLATEs `data` (RFC 1951, no zlib/gzip wrapper), the format ZIP's
/// compression method 8 requires.
fn deflate(data: &[u8]) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// Builds a single-entry, spec-valid DEFLATE ZIP archive whose local file
/// header and central directory both declare `declared_uncompressed_size`
/// for `entry_name`, regardless of what `real_payload` actually decompresses
/// to. Mirrors the `PoC` shape from the advisory: a forged small
/// `uncompressed_size` alongside a real, much larger compressed stream.
#[allow(clippy::cast_possible_truncation)]
fn build_forged_size_zip(
    entry_name: &str,
    real_payload: &[u8],
    declared_uncompressed_size: u32,
) -> Vec<u8> {
    let compressed = deflate(real_payload);
    let crc = crc32_ieee(real_payload);
    let name_bytes = entry_name.as_bytes();
    let name_len = name_bytes.len() as u16;
    let compressed_len = compressed.len() as u32;

    let mut buf: Vec<u8> = Vec::new();
    let local_offset = 0u32;

    // Local file header
    buf.extend_from_slice(b"PK\x03\x04");
    buf.extend_from_slice(&20u16.to_le_bytes()); // version needed (DEFLATE)
    buf.extend_from_slice(&0u16.to_le_bytes()); // flags (no data descriptor)
    buf.extend_from_slice(&8u16.to_le_bytes()); // compression: DEFLATE
    buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
    buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
    buf.extend_from_slice(&crc.to_le_bytes());
    buf.extend_from_slice(&compressed_len.to_le_bytes()); // compressed size (accurate)
    buf.extend_from_slice(&declared_uncompressed_size.to_le_bytes()); // FORGED
    buf.extend_from_slice(&name_len.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // extra field length
    buf.extend_from_slice(name_bytes);
    buf.extend_from_slice(&compressed);

    let central_dir_offset = buf.len() as u32;

    // Central directory file header
    buf.extend_from_slice(b"PK\x01\x02");
    buf.extend_from_slice(&0x031eu16.to_le_bytes()); // version made by: Unix
    buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
    buf.extend_from_slice(&0u16.to_le_bytes()); // flags
    buf.extend_from_slice(&8u16.to_le_bytes()); // compression: DEFLATE
    buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
    buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
    buf.extend_from_slice(&crc.to_le_bytes());
    buf.extend_from_slice(&compressed_len.to_le_bytes()); // compressed size (accurate)
    buf.extend_from_slice(&declared_uncompressed_size.to_le_bytes()); // FORGED
    buf.extend_from_slice(&name_len.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // extra length
    buf.extend_from_slice(&0u16.to_le_bytes()); // comment length
    buf.extend_from_slice(&0u16.to_le_bytes()); // disk number start
    buf.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
    buf.extend_from_slice(&(0o100_644u32 << 16).to_le_bytes()); // external attributes
    buf.extend_from_slice(&local_offset.to_le_bytes());
    buf.extend_from_slice(name_bytes);

    let central_dir_size = (buf.len() as u32) - central_dir_offset;

    // End of central directory record
    buf.extend_from_slice(b"PK\x05\x06");
    buf.extend_from_slice(&0u16.to_le_bytes()); // disk number
    buf.extend_from_slice(&0u16.to_le_bytes()); // disk with central dir
    buf.extend_from_slice(&1u16.to_le_bytes()); // entries on this disk
    buf.extend_from_slice(&1u16.to_le_bytes()); // total entries
    buf.extend_from_slice(&central_dir_size.to_le_bytes());
    buf.extend_from_slice(&central_dir_offset.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // comment length

    buf
}

/// Reproduces the advisory `PoC`: a ZIP entry declares `uncompressed_size = 50`
/// in both the local file header and the central directory, but its DEFLATE
/// stream really decompresses to several megabytes of repeated data. Both
/// the zip-bomb ratio check and the quota pre-check only see the declared
/// 50-byte size and pass; the streaming ceiling added for GHSA-5j8q-wxg5-hj4r
/// must be what actually stops the oversized write.
#[test]
fn ghsa_5j8q_forged_small_uncompressed_size_aborts_and_cleans_up() {
    let dest = TempDir::new().unwrap();
    let config = SecurityConfig::default().validate().unwrap();

    // Highly compressible so the real DEFLATE stream is tiny while still
    // decompressing to several megabytes — the same shape a real
    // decompression-bomb PoC uses.
    let real_payload = vec![0x41u8; 4 * 1024 * 1024];
    let data = build_forged_size_zip("bomb.txt", &real_payload, 50);

    let mut archive = ZipArchive::new(Cursor::new(data)).unwrap();
    let result = archive.extract(
        dest.path(),
        &config,
        &ExtractionOptions::default(),
        &mut exarch_core::NoopProgress,
    );

    match result {
        Err(ArchiveError::SecurityViolation { reason }) => {
            assert!(
                reason.contains("50 bytes"),
                "error must name the declared 50-byte ceiling, got: {reason:?}"
            );
        }
        other => panic!("expected SecurityViolation naming the 50-byte ceiling, got: {other:?}"),
    }

    let extracted_path = dest.path().join("bomb.txt");
    assert!(
        !extracted_path.exists(),
        "aborted extraction must not leave a partial or oversized file on disk"
    );
}

/// Companion case: the declared size is forged to be *larger* than what the
/// stream actually produces (an undersized real payload). This must also be
/// rejected once the stream reaches EOF short of the declared size, even
/// though it never trips the streaming ceiling.
///
/// Uses a compression-ratio-safe shape deliberately: the real payload is
/// low-entropy but not compressible enough to make declared/compressed
/// exceed `max_compression_ratio` (100:1) on its own, so this test actually
/// exercises the new post-copy exact-match check in `copy_with_buffer`
/// rather than being rejected earlier by the pre-existing `ZipBomb` ratio
/// check (a previous version of this test used a tiny real payload declared
/// as 1,000,000 bytes, which tripped `ZipBomb` before the new code ever ran).
#[test]
fn ghsa_5j8q_forged_oversized_declared_size_rejected_after_eof() {
    let dest = TempDir::new().unwrap();
    let config = SecurityConfig::default().validate().unwrap();

    let real_payload: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    let declared = real_payload.len() as u32 * 2;
    let data = build_forged_size_zip("liar.txt", &real_payload, declared);

    let mut archive = ZipArchive::new(Cursor::new(data)).unwrap();
    let result = archive.extract(
        dest.path(),
        &config,
        &ExtractionOptions::default(),
        &mut exarch_core::NoopProgress,
    );

    match result {
        Err(ArchiveError::SecurityViolation { reason }) => {
            assert!(
                reason.contains(&declared.to_string()),
                "error must name the declared size ({declared}), got: {reason:?}"
            );
        }
        other => panic!(
            "expected SecurityViolation from the post-copy exact-match check, got: {other:?}"
        ),
    }
    assert!(
        !dest.path().join("liar.txt").exists(),
        "rejected entry must not leave a truncated file on disk"
    );
}

/// Sanity check that the raw builder produces a well-formed archive when
/// sizes are declared accurately, isolating the forged-size tests above from
/// a bug in the builder itself.
#[test]
fn forged_size_zip_builder_round_trips_when_size_is_accurate() {
    let dest = TempDir::new().unwrap();
    let config = SecurityConfig::default().validate().unwrap();

    // Low-repetition bytes so DEFLATE cannot compress this below the
    // default max_compression_ratio (100:1) and trigger an unrelated
    // ZipBomb rejection.
    let real_payload: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    let declared = real_payload.len() as u32;
    let data = build_forged_size_zip("honest.txt", &real_payload, declared);

    let mut archive = ZipArchive::new(Cursor::new(data)).unwrap();
    let result = archive.extract(
        dest.path(),
        &config,
        &ExtractionOptions::default(),
        &mut exarch_core::NoopProgress,
    );

    assert!(
        result.is_ok(),
        "accurate size must extract cleanly: {result:?}"
    );
    let extracted = std::fs::read(dest.path().join("honest.txt")).unwrap();
    assert_eq!(extracted, real_payload);
}
