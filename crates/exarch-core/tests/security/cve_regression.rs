//! CVE regression tests: CVE-2024-12718, CVE-2024-12905, CVE-2025-48387, and
//! Windows backslash path traversal.
//!
//! Each test constructs a minimal archive reproducing the attack vector and
//! verifies that extraction fails with the expected security error.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use exarch_core::ExtractionError;
use exarch_core::SecurityConfig;
use exarch_core::formats::ArchiveFormat;
use exarch_core::formats::TarArchive;
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
