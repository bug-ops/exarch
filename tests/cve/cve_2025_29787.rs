//! Regression test for CVE-2025-29787 (ZIP symlink zip-slip).
//!
//! The vulnerability (in the Go `quic-go` ecosystem) describes a pattern where
//! a ZIP archive contains a symlink entry pointing outside the extraction root,
//! followed by a file entry routed through that symlink to escape the root.
//!
//! Attack chain:
//!   Entry 1: symlink  `up`            ->  `../..`
//!   Entry 2: file     `up/etc/passwd` content=`ESCAPE`
//!
//! exarch is NOT vulnerable. `SafeSymlink::validate` (via
//! `resolve_through_symlinks`) rejects symlinks whose resolved target falls
//! outside the extraction root BEFORE writing anything to disk. Entry 1 is
//! therefore rejected with `SymlinkEscape`, and entry 2 is never reached.
//!
//! This test verifies that behaviour holds for the ZIP extraction path.
//!
//! Requires: `allow_symlinks = true` to exercise the escape-detection branch.
//! With symlinks disabled (default) the archive is rejected at entry 1 with
//! `SecurityViolation` — that branch is also covered.

use exarch_core::ExtractionError;
use exarch_core::SecurityConfig;
use exarch_core::formats::ZipArchive;
use exarch_core::formats::traits::ArchiveFormat;
use std::io::Cursor;
use tempfile::TempDir;

// Unix symlink file-type constant: S_IFLNK (octal 0120000).
const S_IFLNK: u32 = 0o120_000;

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

struct RawEntry<'a> {
    name: &'a str,
    content: &'a [u8],
    /// Unix file mode (e.g. `0o120_777` for symlink, `0o100_644` for regular).
    unix_mode: u32,
}

/// Builds a multi-entry ZIP in memory using raw byte assembly so that Unix
/// file-type bits in the external attributes are preserved exactly. The `zip`
/// crate's `unix_permissions()` API strips the file-type nibble, making it
/// impossible to mark entries as symlinks through the high-level API.
#[allow(clippy::cast_possible_truncation)]
fn build_raw_zip(entries: &[RawEntry<'_>]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut central_dir_entries: Vec<(u32, u16, u32, &[u8])> = Vec::new();

    for entry in entries {
        let crc = crc32_ieee(entry.content);
        let name_bytes = entry.name.as_bytes();
        let name_len = name_bytes.len() as u16;
        let content_len = entry.content.len() as u32;
        let external_attributes = entry.unix_mode << 16;

        let local_offset = buf.len() as u32;

        // Local file header
        buf.extend_from_slice(b"PK\x03\x04");
        buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
        buf.extend_from_slice(&0u16.to_le_bytes()); // flags
        buf.extend_from_slice(&0u16.to_le_bytes()); // compression: Stored
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&content_len.to_le_bytes()); // compressed size
        buf.extend_from_slice(&content_len.to_le_bytes()); // uncompressed size
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // extra field length
        buf.extend_from_slice(name_bytes);
        buf.extend_from_slice(entry.content);

        central_dir_entries.push((local_offset, name_len, external_attributes, name_bytes));
    }

    let central_dir_offset = buf.len() as u32;

    for (i, entry) in entries.iter().enumerate() {
        let (local_offset, name_len, external_attributes, name_bytes) =
            central_dir_entries[i];
        let crc = crc32_ieee(entry.content);
        let content_len = entry.content.len() as u32;

        // Central directory file header
        buf.extend_from_slice(b"PK\x01\x02");
        buf.extend_from_slice(&0x031eu16.to_le_bytes()); // version made by: Unix (0x03 = Unix, 0x1e = 30)
        buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
        buf.extend_from_slice(&0u16.to_le_bytes()); // flags
        buf.extend_from_slice(&0u16.to_le_bytes()); // compression: Stored
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&content_len.to_le_bytes()); // compressed size
        buf.extend_from_slice(&content_len.to_le_bytes()); // uncompressed size
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // extra length
        buf.extend_from_slice(&0u16.to_le_bytes()); // comment length
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        buf.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        buf.extend_from_slice(&external_attributes.to_le_bytes());
        buf.extend_from_slice(&local_offset.to_le_bytes());
        buf.extend_from_slice(name_bytes);
    }

    let central_dir_size = (buf.len() as u32) - central_dir_offset;
    let entry_count = entries.len() as u16;

    // End of central directory record
    buf.extend_from_slice(b"PK\x05\x06");
    buf.extend_from_slice(&0u16.to_le_bytes()); // disk number
    buf.extend_from_slice(&0u16.to_le_bytes()); // disk with central dir
    buf.extend_from_slice(&entry_count.to_le_bytes());
    buf.extend_from_slice(&entry_count.to_le_bytes());
    buf.extend_from_slice(&central_dir_size.to_le_bytes());
    buf.extend_from_slice(&central_dir_offset.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // comment length

    buf
}

/// Build the CVE-2025-29787 attack ZIP: symlink `up -> ../..` followed by
/// a file `up/etc/passwd` with content `ESCAPE`.
fn build_attack_zip() -> Vec<u8> {
    build_raw_zip(&[
        RawEntry {
            name: "up",
            content: b"../..",
            unix_mode: S_IFLNK | 0o777,
        },
        RawEntry {
            name: "up/etc/passwd",
            content: b"ESCAPE",
            unix_mode: 0o100_644,
        },
    ])
}

/// When `allow_symlinks` is enabled, the symlink escape is caught by
/// `SafeSymlink::validate` before being written to disk. The archive must
/// return a `SymlinkEscape` error and no file must escape the extraction root.
#[test]
#[cfg(unix)]
fn zip_symlink_zip_slip_blocked_with_symlinks_enabled() {
    let dest = TempDir::new().expect("temp dir");
    let mut config = SecurityConfig::default();
    config.allowed.symlinks = true;

    let data = build_attack_zip();
    let cursor = Cursor::new(data);
    let mut archive = ZipArchive::new(cursor).expect("valid zip");

    let result = archive.extract(dest.path(), &config);

    assert!(
        result.is_err(),
        "extraction must fail: escaping symlink must be rejected"
    );

    let err = result.unwrap_err();
    assert!(
        matches!(err, ExtractionError::SymlinkEscape { .. }),
        "expected SymlinkEscape, got: {err:?}"
    );

    // The symlink must not have been written to disk.
    assert!(
        !dest.path().join("up").exists(),
        "symlink 'up' must not be written to disk"
    );

    // The payload file must not exist inside the extraction root.
    assert!(
        !dest.path().join("up/etc/passwd").exists(),
        "payload file must not be extracted"
    );

    // The real /etc/passwd (if present) must not have been replaced with ESCAPE.
    if std::path::Path::new("/etc/passwd").exists() {
        let content = std::fs::read("/etc/passwd").expect("read /etc/passwd");
        assert_ne!(
            content, b"ESCAPE",
            "/etc/passwd must not have been overwritten by the attack"
        );
    }
}

/// With symlinks disabled (the default), the archive is rejected at the first
/// symlink entry before the escape can even be attempted.
#[test]
fn zip_symlink_zip_slip_blocked_with_symlinks_disabled() {
    let dest = TempDir::new().expect("temp dir");
    let config = SecurityConfig::default(); // symlinks = false

    let data = build_attack_zip();
    let cursor = Cursor::new(data);
    let mut archive = ZipArchive::new(cursor).expect("valid zip");

    let result = archive.extract(dest.path(), &config);

    assert!(
        result.is_err(),
        "extraction must fail when symlinks are disabled"
    );

    assert!(
        !dest.path().join("up").exists(),
        "symlink 'up' must not be written when symlinks are disabled"
    );
}
