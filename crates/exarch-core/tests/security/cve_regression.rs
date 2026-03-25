//! CVE regression tests: CVE-2024-12718, CVE-2024-12905, CVE-2025-29787,
//! CVE-2025-48387, CVE-2026-24842, and Windows backslash path traversal.
//!
//! Each test constructs a minimal archive reproducing the attack vector and
//! verifies that extraction fails with the expected security error.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use exarch_core::ExtractionError;
use exarch_core::SecurityConfig;
use exarch_core::formats::ArchiveFormat;
use exarch_core::formats::TarArchive;
use exarch_core::formats::ZipArchive;
use exarch_core::test_utils::TarTestBuilder;
use std::io::Cursor;
use tempfile::TempDir;

/// Creates a minimal POSIX ustar TAR archive where each entry has an arbitrary
/// raw path (bypassing the `tar` crate's path sanitization).
///
/// This is needed to craft archives that reproduce CVE attack vectors —
/// attackers control raw archive bytes and are not constrained by safe APIs.
fn make_raw_tar(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();

    for (path, data) in entries {
        let mut header = [0u8; 512];

        // Filename: first 100 bytes (null-padded)
        let path_len = path.len().min(100);
        header[..path_len].copy_from_slice(&path[..path_len]);

        // Mode "0000644\0"
        header[100..108].copy_from_slice(b"0000644\0");
        // UID / GID "0000000\0"
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");

        // Size in 11-digit octal + null
        let size_str = format!("{:011o}\0", data.len());
        header[124..136].copy_from_slice(size_str.as_bytes());

        // mtime (zero timestamp)
        header[136..148].copy_from_slice(b"00000000000\0");

        // Typeflag: '0' = regular file
        header[156] = b'0';

        // POSIX ustar magic + version
        header[257..263].copy_from_slice(b"ustar ");
        header[263..265].copy_from_slice(b" \0");

        // Checksum: sum of all bytes with the checksum field treated as spaces
        header[148..156].copy_from_slice(b"        ");
        let checksum: u32 = header.iter().map(|&b| u32::from(b)).sum();
        // Format: 6-digit octal, NUL, space
        let ck_str = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(ck_str.as_bytes());

        out.extend_from_slice(&header);

        // File content padded to 512-byte blocks
        out.extend_from_slice(data);
        let rem = data.len() % 512;
        if rem != 0 {
            out.extend(std::iter::repeat_n(0u8, 512 - rem));
        }
    }

    // End-of-archive: two zero blocks
    out.extend(std::iter::repeat_n(0u8, 1024));
    out
}

// ── CVE-2024-12718: Python tarfile filter bypass
// ──────────────────────────────
//
// Python's tarfile `filter='data'` could be bypassed by paths that start with
// `./` before parent-traversal components, e.g. `./../../etc/passwd`.  The
// validator must reject these regardless of the leading `./` prefix.
// We craft archives at the raw byte level because safe TAR builders refuse to
// add `..` components.

#[test]
fn test_cve_2024_12718_dotslash_prefix_traversal() {
    // ./../../etc/passwd: looks relative but escapes the destination
    let tar_data = make_raw_tar(&[(b"./../../etc/passwd", b"pwned")]);

    let temp = TempDir::new().unwrap();
    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = archive.extract(temp.path(), &SecurityConfig::default());

    assert!(
        matches!(result, Err(ExtractionError::PathTraversal { .. })),
        "dotslash-prefixed traversal must be rejected, got: {result:?}"
    );
}

#[test]
fn test_cve_2024_12718_dotslash_complex_traversal() {
    // foo/./bar/../../../etc/passwd: intermediate ./ still leads to escape
    let tar_data = make_raw_tar(&[(b"foo/./bar/../../../etc/passwd", b"pwned")]);

    let temp = TempDir::new().unwrap();
    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = archive.extract(temp.path(), &SecurityConfig::default());

    assert!(
        matches!(result, Err(ExtractionError::PathTraversal { .. })),
        "complex dotslash traversal must be rejected, got: {result:?}"
    );
}

#[test]
fn test_cve_2024_12718_multiple_traversal_variants() {
    // Each of these path patterns was used to bypass tarfile filters.
    let traversal_paths: &[&[u8]] = &[
        b"./../../shadow",
        b"./../../../etc/crontab",
        b"safe/./../../outside",
        b"a/b/./../../..",
    ];

    for &path in traversal_paths {
        let tar_data = make_raw_tar(&[(path, b"x")]);
        let temp = TempDir::new().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));
        let result = archive.extract(temp.path(), &SecurityConfig::default());

        let path_str = std::str::from_utf8(path).unwrap_or("<binary>");
        assert!(
            result.is_err(),
            "traversal path '{path_str}' must be rejected"
        );
    }
}

// ── CVE-2024-12905: tar-fs symlink chain escape
// ───────────────────────────────
//
// tar-fs 3.0.6 followed symlinks during extraction, allowing an archive to
// create `link -> ../outside` and then extract `link/payload.txt`, which would
// resolve to `../outside/payload.txt` on disk.

#[test]
fn test_cve_2024_12905_symlink_outside_dest_rejected_by_default() {
    // Default config: symlinks are disabled, so the symlink entry itself
    // must be rejected with SecurityViolation before the file can escape.
    let tar_data = TarTestBuilder::new()
        .add_symlink("evil_link", "../outside")
        .add_file("innocent.txt", b"filler")
        .build();

    let temp = TempDir::new().unwrap();
    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = archive.extract(temp.path(), &SecurityConfig::default());

    assert!(
        matches!(
            result,
            Err(ExtractionError::SecurityViolation { .. } | ExtractionError::SymlinkEscape { .. })
        ),
        "symlink to outside dest must be rejected with default config, got: {result:?}"
    );
}

#[test]
fn test_cve_2024_12905_symlink_outside_dest_rejected_when_allowed() {
    // With symlinks enabled, the target `../outside` resolves outside the
    // destination directory and must be rejected with SymlinkEscape.
    let tar_data = TarTestBuilder::new()
        .add_symlink("evil_link", "../outside")
        .add_file("innocent.txt", b"filler")
        .build();

    let temp = TempDir::new().unwrap();
    let mut config = SecurityConfig::default();
    config.allowed.symlinks = true;

    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = archive.extract(temp.path(), &config);

    assert!(
        matches!(result, Err(ExtractionError::SymlinkEscape { .. })),
        "symlink to outside destination must be rejected, got: {result:?}"
    );
}

#[test]
fn test_cve_2024_12905_deep_symlink_chain() {
    // Deeper chain: a/b/link -> ../../../../outside
    let tar_data = TarTestBuilder::new()
        .add_symlink("a/b/link", "../../../../outside")
        .add_file("innocent.txt", b"filler")
        .build();

    let temp = TempDir::new().unwrap();
    let mut config = SecurityConfig::default();
    config.allowed.symlinks = true;

    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = archive.extract(temp.path(), &config);

    assert!(
        matches!(result, Err(ExtractionError::SymlinkEscape { .. })),
        "deep symlink chain escape must be rejected, got: {result:?}"
    );
}

// ── CVE-2025-48387: tar-fs hardlink traversal ────────────────────────────────
//
// tar-fs allowed archives to create hardlinks to files outside the destination
// directory, potentially exposing or corrupting sensitive files on the host.

#[test]
fn test_cve_2025_48387_hardlink_outside_dest_rejected_by_default() {
    // Default config: hardlinks are disabled, so the hardlink entry must be
    // rejected with SecurityViolation.
    let tar_data = TarTestBuilder::new()
        .add_hardlink("link.txt", "../../etc/shadow")
        .build();

    let temp = TempDir::new().unwrap();
    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = archive.extract(temp.path(), &SecurityConfig::default());

    assert!(
        matches!(
            result,
            Err(ExtractionError::SecurityViolation { .. } | ExtractionError::HardlinkEscape { .. })
        ),
        "hardlink outside dest must be rejected with default config, got: {result:?}"
    );
}

#[test]
fn test_cve_2025_48387_hardlink_outside_dest_rejected_when_allowed() {
    // With hardlinks enabled, a traversal target must still be rejected with
    // HardlinkEscape.
    let tar_data = TarTestBuilder::new()
        .add_hardlink("link.txt", "../../etc/shadow")
        .build();

    let temp = TempDir::new().unwrap();
    let mut config = SecurityConfig::default();
    config.allowed.hardlinks = true;

    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = archive.extract(temp.path(), &config);

    assert!(
        matches!(result, Err(ExtractionError::HardlinkEscape { .. })),
        "hardlink traversal outside dest must be rejected, got: {result:?}"
    );
}

#[test]
fn test_cve_2025_48387_absolute_hardlink_rejected() {
    // Absolute hardlink target must also be rejected.
    let tar_data = TarTestBuilder::new()
        .add_hardlink("link.txt", "/etc/passwd")
        .build();

    let temp = TempDir::new().unwrap();
    let mut config = SecurityConfig::default();
    config.allowed.hardlinks = true;

    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = archive.extract(temp.path(), &config);

    assert!(
        matches!(result, Err(ExtractionError::HardlinkEscape { .. })),
        "absolute hardlink target must be rejected, got: {result:?}"
    );
}

// ── RUSTSEC-2026-0067 / CVE-2026-33056: tar-rs symlink+directory chmod ───────
//
// tar-rs < 0.4.45 followed symlinks when applying chmod during directory entry
// extraction.  An archive that creates `subdir -> ../external` (symlink) and
// then a directory entry `subdir` would chmod the external directory on the
// host filesystem.  Fixed in tar-rs 0.4.45.
//
// exarch blocks this at the security layer: the symlink entry is rejected
// (symlinks disabled by default), so the subsequent directory entry either
// also fails or is harmless because the symlink was never written.

#[test]
fn test_rustsec_2026_0067_symlink_dir_chmod_default_config() {
    // Default config: symlinks are disabled; the symlink entry must be rejected
    // before tar-rs ever has a chance to follow it for the directory chmod.
    let tar_data = TarTestBuilder::new()
        .add_symlink("subdir", "../external")
        .add_directory("subdir/")
        .build();

    let temp = TempDir::new().unwrap();
    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = archive.extract(temp.path(), &SecurityConfig::default());

    assert!(
        matches!(
            result,
            Err(ExtractionError::SecurityViolation { .. }
                | ExtractionError::SymlinkEscape { .. }
                | ExtractionError::PathTraversal { .. })
        ),
        "symlink+dir chmod attack must be rejected with default config, got: {result:?}"
    );

    // No files must exist outside the extraction root.
    let external = temp.path().parent().unwrap().join("external");
    assert!(
        !external.exists(),
        "extraction must not create directories outside root"
    );
}

#[test]
fn test_rustsec_2026_0067_symlink_dir_chmod_symlinks_allowed() {
    // With symlinks enabled, the symlink `subdir -> ../external` points outside
    // the extraction root and must be rejected with SymlinkEscape.
    let tar_data = TarTestBuilder::new()
        .add_symlink("subdir", "../external")
        .add_directory("subdir/")
        .build();

    let temp = TempDir::new().unwrap();
    let mut config = SecurityConfig::default();
    config.allowed.symlinks = true;

    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = archive.extract(temp.path(), &config);

    assert!(
        matches!(result, Err(ExtractionError::SymlinkEscape { .. })),
        "symlink escaping root must be rejected even when symlinks are allowed, got: {result:?}"
    );

    // No files must exist outside the extraction root.
    let external = temp.path().parent().unwrap().join("external");
    assert!(
        !external.exists(),
        "extraction must not create directories outside root"
    );
}

// ── GHSA-2367-c296-3mp2 variant: hardlink inode corruption (issue #130) ──────
//
// When a TAR archive contains a hardlink entry whose link name is later reused
// by a plain-file entry, the two-pass extraction model creates the OS hardlink
// (second pass) after the plain file is written (first pass). With
// `fs::hard_link` both paths would share an inode; a subsequent write to either
// path silently corrupts the other. The fix replaces `hard_link` with
// `fs::copy` so each extracted file has its own independent inode.

#[test]
fn test_ghsa_2367_hardlink_does_not_corrupt_target() {
    // Archive: legit.txt → hardlink link_to_legit→legit.txt → plain link_to_legit
    // ATTACK. Two-pass: first pass extracts legit.txt and plain link_to_legit;
    // second pass calls fs::copy for the hardlink (which overwrites
    // link_to_legit with a copy of legit.txt). legit.txt must always contain
    // "legit\n".
    let tar_data = TarTestBuilder::new()
        .add_file("legit.txt", b"legit\n")
        .add_hardlink("link_to_legit", "legit.txt")
        .add_file("link_to_legit", b"ATTACK\n")
        .build();

    let temp = TempDir::new().unwrap();
    let mut config = SecurityConfig::default();
    config.allowed.hardlinks = true;

    let mut archive = TarArchive::new(Cursor::new(tar_data));
    // Extraction may succeed or fail depending on platform duplicate-file handling,
    // but legit.txt must never be corrupted.
    let _ = archive.extract(temp.path(), &config);

    let legit = std::fs::read_to_string(temp.path().join("legit.txt")).unwrap();
    assert_eq!(
        legit, "legit\n",
        "legit.txt was corrupted via hardlink inode sharing"
    );
}

#[test]
#[cfg(unix)]
fn test_ghsa_2367_hardlink_produces_independent_inode() {
    use std::os::unix::fs::MetadataExt;

    // Simple two-entry archive: legit.txt + hardlink to it.
    let tar_data = TarTestBuilder::new()
        .add_file("legit.txt", b"legit\n")
        .add_hardlink("link_to_legit", "legit.txt")
        .build();

    let temp = TempDir::new().unwrap();
    let mut config = SecurityConfig::default();
    config.allowed.hardlinks = true;

    let mut archive = TarArchive::new(Cursor::new(tar_data));
    archive.extract(temp.path(), &config).unwrap();

    let ino_legit = std::fs::metadata(temp.path().join("legit.txt"))
        .unwrap()
        .ino();
    let ino_link = std::fs::metadata(temp.path().join("link_to_legit"))
        .unwrap()
        .ino();
    assert_ne!(
        ino_legit, ino_link,
        "hardlink created a shared inode — content-copy was not applied"
    );
}

// ── CVE-2026-24842: hardlink root-anchor mismatch ────────────────────────────
//
// A crafted archive could place the hardlink entry deep in a subdirectory
// (e.g. a/b/c/d/link) and set linkpath to ../../../../etc/passwd.  If the
// validator resolved linkpath relative to the entry's parent directory instead
// of the extraction root (dest), the result would be dest/etc/passwd — which
// looks safe.  At creation time, however, fs::hard_link uses dest as the base,
// so dest/../../../../etc/passwd escapes.
//
// The correct behaviour: validate_hardlink uses dest as the base for both
// containment check and creation, so the escape is detected during validation.

#[test]
fn test_cve_2026_24842_deep_nested_hardlink_escape_rejected_by_default() {
    // Default config: hardlinks are disabled, so the entry is rejected before
    // any path resolution.
    let tar_data = TarTestBuilder::new()
        .add_hardlink("a/b/c/d/link", "../../../../etc/passwd")
        .build();

    let temp = TempDir::new().unwrap();
    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = archive.extract(temp.path(), &SecurityConfig::default());

    assert!(
        matches!(
            result,
            Err(ExtractionError::SecurityViolation { .. } | ExtractionError::HardlinkEscape { .. })
        ),
        "deep nested hardlink escape must be rejected with default config, got: {result:?}"
    );
}

#[test]
fn test_cve_2026_24842_deep_nested_hardlink_escape_rejected_when_allowed() {
    // With hardlinks enabled, linkpath ../../../../etc/passwd from a/b/c/d/
    // resolves to dest/../../../../etc/passwd from dest — which escapes — and
    // must be rejected with HardlinkEscape.
    let tar_data = TarTestBuilder::new()
        .add_hardlink("a/b/c/d/link", "../../../../etc/passwd")
        .build();

    let temp = TempDir::new().unwrap();
    let mut config = SecurityConfig::default();
    config.allowed.hardlinks = true;

    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = archive.extract(temp.path(), &config);

    assert!(
        matches!(result, Err(ExtractionError::HardlinkEscape { .. })),
        "deep nested hardlink escape must be rejected even with hardlinks allowed, got: {result:?}"
    );

    assert!(
        !temp.path().join("a/b/c/d/link").exists(),
        "hardlink must not be written to disk after escape rejection"
    );
}

#[test]
fn test_cve_2026_24842_safe_deep_nested_hardlink_allowed() {
    // A valid hardlink in a deep directory pointing to a target within dest
    // must be allowed (avoid false positives).
    let tar_data = TarTestBuilder::new()
        .add_file("target.txt", b"content")
        .add_hardlink("a/b/c/d/link", "target.txt")
        .build();

    let temp = TempDir::new().unwrap();
    let mut config = SecurityConfig::default();
    config.allowed.hardlinks = true;

    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = archive.extract(temp.path(), &config);

    assert!(
        result.is_ok(),
        "valid internal deep-nested hardlink must be allowed, got: {result:?}"
    );
}

// ── CVE-2025-29787: ZIP symlink zip-slip ─────────────────────────────────────
//
// The vulnerability pattern: a ZIP archive contains a symlink pointing outside
// the extraction root, followed by a file entry routed through that symlink.
//
// Attack chain:
//   Entry 1: symlink  `up`            -> `../..`
//   Entry 2: file     `up/etc/passwd` content=`ESCAPE`
//
// exarch is NOT vulnerable. `SafeSymlink::validate` rejects the escaping
// symlink before it is written to disk, so entry 2 is never extracted.
//
// ZIP symlinks use Unix external attributes (mode 0o120_777 = S_IFLNK | 0o777).
// The `zip` crate's `unix_permissions()` strips the file-type nibble, so this
// helper assembles the raw ZIP bytes to preserve the mode exactly.

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

struct RawZipEntry<'a> {
    name: &'a str,
    content: &'a [u8],
    /// Unix file mode (e.g. `S_IFLNK | 0o777` for symlink, `0o100_644` for
    /// regular).
    unix_mode: u32,
}

/// Builds a multi-entry ZIP in memory with correct Unix file-type bits in the
/// external attributes field. The `zip` crate's high-level API strips the
/// file-type nibble, making it impossible to mark entries as symlinks without
/// raw byte assembly.
fn build_raw_zip(entries: &[RawZipEntry<'_>]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    // Collect (local_offset, name_len, external_attributes, crc, content_len) per
    // entry.
    let mut meta: Vec<(u32, u16, u32, u32, u32)> = Vec::new();

    for entry in entries {
        let crc = crc32_ieee(entry.content);
        let name_bytes = entry.name.as_bytes();
        let name_len = name_bytes.len() as u16;
        let content_len = entry.content.len() as u32;
        let external_attributes = entry.unix_mode << 16;

        let local_offset = buf.len() as u32;
        meta.push((
            local_offset,
            name_len,
            external_attributes,
            crc,
            content_len,
        ));

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
    }

    let central_dir_offset = buf.len() as u32;

    for (i, entry) in entries.iter().enumerate() {
        let (local_offset, name_len, external_attributes, crc, content_len) = meta[i];
        let name_bytes = entry.name.as_bytes();

        // Central directory file header
        buf.extend_from_slice(b"PK\x01\x02");
        buf.extend_from_slice(&0x031eu16.to_le_bytes()); // version made by: Unix
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
fn build_cve_2025_29787_zip() -> Vec<u8> {
    build_raw_zip(&[
        RawZipEntry {
            name: "up",
            content: b"../..",
            unix_mode: S_IFLNK | 0o777,
        },
        RawZipEntry {
            name: "up/etc/passwd",
            content: b"ESCAPE",
            unix_mode: 0o100_644,
        },
    ])
}

/// When `allow_symlinks` is enabled, `SafeSymlink::validate` rejects the
/// escaping symlink before it is written to disk. The archive must return a
/// `SymlinkEscape` error and no file must escape the extraction root.
#[test]
#[cfg(unix)]
fn test_cve_2025_29787_zip_slip_blocked_with_symlinks_enabled() {
    let dest = TempDir::new().unwrap();
    let mut config = SecurityConfig::default();
    config.allowed.symlinks = true;

    let data = build_cve_2025_29787_zip();
    let mut archive = ZipArchive::new(Cursor::new(data)).unwrap();

    let result = archive.extract(dest.path(), &config);

    assert!(
        result.is_err(),
        "extraction must fail: escaping symlink must be rejected"
    );
    assert!(
        matches!(result.unwrap_err(), ExtractionError::SymlinkEscape { .. }),
        "expected SymlinkEscape"
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

    // The real /etc/passwd must not have been overwritten.
    if std::path::Path::new("/etc/passwd").exists() {
        let content = std::fs::read("/etc/passwd").unwrap();
        assert_ne!(
            content, b"ESCAPE",
            "/etc/passwd must not have been overwritten by the attack"
        );
    }
}

/// With symlinks disabled (the default), the archive is rejected at the first
/// symlink entry with a `SecurityViolation` before the escape is attempted.
#[test]
fn test_cve_2025_29787_zip_slip_blocked_with_symlinks_disabled() {
    let dest = TempDir::new().unwrap();
    let config = SecurityConfig::default(); // symlinks = false

    let data = build_cve_2025_29787_zip();
    let mut archive = ZipArchive::new(Cursor::new(data)).unwrap();

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

// ── Windows backslash path traversal ─────────────────────────────────────────
//
// Archives created on Windows may use `\` as a path separator.  On Windows
// hosts, paths like `subdir\..\evil.txt` traverse to the parent directory and
// must be blocked.  On Unix `\` is a valid filename character, so
// `subdir\..\..\etc\passwd` is a single-component name and lands safely inside
// the destination.

#[test]
#[cfg(windows)]
fn test_windows_backslash_parent_traversal() {
    // On Windows `\` is a path separator, so this entry escapes to the parent.
    let tar_data = make_raw_tar(&[(b"subdir\\..\\evil.txt", b"escaped")]);

    let temp = TempDir::new().unwrap();
    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = archive.extract(temp.path(), &SecurityConfig::default());

    assert!(
        result.is_err(),
        "Windows backslash traversal must be rejected"
    );
}

#[test]
#[cfg(windows)]
fn test_windows_backslash_deep_traversal() {
    let tar_data = make_raw_tar(&[(b"foo\\..\\..\\etc\\passwd", b"content")]);

    let temp = TempDir::new().unwrap();
    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = archive.extract(temp.path(), &SecurityConfig::default());

    assert!(
        result.is_err(),
        "Windows backslash traversal must be rejected"
    );
}

/// On non-Windows, archives containing Windows-style backslash paths land the
/// file inside the destination as a single path component (safe).
#[test]
#[cfg(not(windows))]
fn test_windows_backslash_treated_as_filename_on_unix() {
    // On Unix, `\` is not a path separator.  `foo\..\..\etc\passwd` is a
    // single-component filename and should extract safely inside the dest.
    let tar_data = make_raw_tar(&[(b"foo\\..\\..\\etc\\passwd", b"content")]);

    let temp = TempDir::new().unwrap();
    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = archive.extract(temp.path(), &SecurityConfig::default());

    // Extraction should succeed — the path is not a traversal on Unix.
    assert!(
        result.is_ok(),
        "single-component backslash path should extract on Unix, got: {result:?}"
    );

    // The file must be inside the destination directory.
    let extracted = temp.path().join("foo\\..\\..\\etc\\passwd");
    assert!(
        extracted.exists(),
        "extracted file must be inside the destination"
    );
}

#[test]
#[cfg(not(windows))]
fn test_windows_absolute_path_treated_as_filename_on_unix() {
    // `C:\Windows\evil.txt` is a single-component filename on Unix.
    let tar_data = make_raw_tar(&[(b"C:\\Windows\\evil.txt", b"content")]);

    let temp = TempDir::new().unwrap();
    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = archive.extract(temp.path(), &SecurityConfig::default());

    // Extraction should succeed and the file must be inside the destination.
    assert!(
        result.is_ok(),
        "Windows absolute path is a single component on Unix, got: {result:?}"
    );
    let extracted = temp.path().join("C:\\Windows\\evil.txt");
    assert!(
        extracted.exists(),
        "extracted file must be inside the destination"
    );
}
