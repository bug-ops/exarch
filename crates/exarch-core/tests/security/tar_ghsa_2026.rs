//! Regression tests mapping node-tar GHSA vulnerability classes onto the TAR
//! extraction pipeline (issue #399).
//!
//! All cases here currently pass: protection against these classes is
//! inherited from the `tar` crate dependency (tar-0.4.46), not implemented
//! locally in `exarch-core`. Their value is locking in that inherited
//! behavior so a future `tar` crate bump that regresses parsing precedence,
//! NUL-byte handling, or size framing is caught immediately.
//!
//! - GHSA-vmf3 (node-tar): PAX/GNU long-name/long-link record smuggling and
//!   stream re-framing.
//! - GHSA-gvwx / GHSA-w8wr (node-tar): NUL byte / malformed field handling in
//!   PAX and GNU long-name records.
//! - GHSA-23hp (node-tar): declared vs. actual entry size mismatches.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use exarch_core::ArchiveError;
use exarch_core::ExtractionOptions;
use exarch_core::NoopProgress;
use exarch_core::SecurityConfig;
use exarch_core::formats::ArchiveFormat;
use exarch_core::formats::TarArchive;
use std::io::Cursor;
use tempfile::TempDir;

const BLOCK: usize = 512;

/// Builds a raw 512-byte TAR header block.
///
/// `gnu_magic` selects GNU-flavored magic bytes (`"ustar "` + `" \0"`) at
/// offsets 257/265, required for the `tar` crate's `is_recognized_header` to
/// process GNU long-name/long-link ('L'/'K') typeflags at all — without it,
/// long-name processing is silently skipped and these tests would pass
/// without exercising the real code path.
fn header(name: &[u8], size: u64, typeflag: u8, linkname: &[u8], gnu_magic: bool) -> Vec<u8> {
    let mut h = vec![0u8; BLOCK];
    let name_len = name.len().min(100);
    h[..name_len].copy_from_slice(&name[..name_len]);
    h[100..108].copy_from_slice(b"0000644\0");
    h[108..116].copy_from_slice(b"0000000\0");
    h[116..124].copy_from_slice(b"0000000\0");
    let sz = format!("{size:011o}\0");
    h[124..136].copy_from_slice(sz.as_bytes());
    h[136..148].copy_from_slice(b"00000000000\0");
    h[156] = typeflag;
    let link_len = linkname.len().min(100);
    h[157..157 + link_len].copy_from_slice(&linkname[..link_len]);
    if gnu_magic {
        h[257..263].copy_from_slice(b"ustar ");
        h[263..265].copy_from_slice(b" \0");
    } else {
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
    }
    // The checksum field itself is treated as 8 ASCII spaces during the sum.
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    let cksum = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(cksum.as_bytes());
    h
}

/// Pads `data` to a 512-byte boundary and appends it to `out`.
fn pad(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(data);
    let rem = data.len() % BLOCK;
    if rem != 0 {
        out.extend(std::iter::repeat_n(0u8, BLOCK - rem));
    }
}

/// Encodes one PAX extended-header record: `"LEN key=value\n"`, where `LEN`
/// includes its own decimal digit count (the standard PAX self-referential
/// length format).
fn pax_record(key: &[u8], value: &[u8]) -> Vec<u8> {
    let base = key.len() + value.len() + 3; // ' ', '=', '\n'
    let mut len = base + 1;
    loop {
        let candidate_len = len.to_string().len() + base;
        if candidate_len == len {
            break;
        }
        len = candidate_len;
    }
    let mut record = format!("{len} ").into_bytes();
    record.extend_from_slice(key);
    record.push(b'=');
    record.extend_from_slice(value);
    record.push(b'\n');
    record
}

/// Appends two all-zero blocks: the standard TAR end-of-archive marker.
fn eof(out: &mut Vec<u8>) {
    out.extend(std::iter::repeat_n(0u8, BLOCK * 2));
}

/// Appends a GNU long-name ('L') or long-link ('K') metadata entry carrying
/// `name`, NUL-terminated per the GNU tar convention.
fn gnu_longname(out: &mut Vec<u8>, typeflag: u8, name: &[u8]) {
    let mut data = name.to_vec();
    data.push(0);
    out.extend_from_slice(&header(
        b"././@LongLink",
        data.len() as u64,
        typeflag,
        b"",
        true,
    ));
    pad(out, &data);
}

/// Appends a PAX local extended header ('x') carrying `records`.
fn pax_header(out: &mut Vec<u8>, records: &[u8]) {
    out.extend_from_slice(&header(
        b"PaxHeaders/entry",
        records.len() as u64,
        b'x',
        b"",
        false,
    ));
    pad(out, records);
}

fn extract(bytes: &[u8]) -> (exarch_core::Result<exarch_core::ExtractionReport>, TempDir) {
    let temp = TempDir::new().unwrap();
    let mut archive = TarArchive::new(Cursor::new(bytes.to_vec()));
    let result = archive.extract(
        temp.path(),
        &SecurityConfig::default(),
        &ExtractionOptions::default(),
        &mut NoopProgress,
    );
    (result, temp)
}

fn extract_with_config(
    bytes: &[u8],
    config: &SecurityConfig,
) -> (exarch_core::Result<exarch_core::ExtractionReport>, TempDir) {
    let temp = TempDir::new().unwrap();
    let mut archive = TarArchive::new(Cursor::new(bytes.to_vec()));
    let result = archive.extract(
        temp.path(),
        config,
        &ExtractionOptions::default(),
        &mut NoopProgress,
    );
    (result, temp)
}

// ─────────────────────────────────────────────────────────────────────────
// GHSA-vmf3: PAX/GNU long-name smuggling and stream re-framing
// ─────────────────────────────────────────────────────────────────────────

/// GNU longname is benign, PAX `path` is a traversal attempt. `tar` resolves
/// naming precedence as GNU long-name > PAX `path` > ustar name, so the
/// malicious PAX path is never applied at all — the entry extracts safely
/// under its benign GNU-supplied name, and no escaping path is ever written.
#[test]
fn ghsa_vmf3_gnu_longname_benign_pax_path_traversal_ignored_by_precedence() {
    let mut t = Vec::new();
    gnu_longname(&mut t, b'L', b"benign_from_gnu.txt");
    let mut recs = pax_record(b"path", b"../../PWNED_FROM_PAX.txt");
    recs.extend(pax_record(b"size", b"5"));
    pax_header(&mut t, &recs);
    t.extend_from_slice(&header(b"ustar_name.txt", 5, b'0', b"", true));
    pad(&mut t, b"hello");
    eof(&mut t);

    let (result, temp) = extract(&t);
    let report = result.expect("GNU long-name precedence must win, extracting safely");
    assert_eq!(
        report.files_extracted, 1,
        "exactly one entry must be written"
    );
    assert!(
        temp.path().join("benign_from_gnu.txt").exists(),
        "must extract under the winning (benign) GNU long-name"
    );
}

/// GNU longname is a traversal attempt, PAX `path` is benign: the GNU name
/// (lower precedence but still validated as the entry advances) must not
/// allow the escape through.
#[test]
fn ghsa_vmf3_gnu_longname_traversal_pax_path_benign_rejected() {
    let mut t = Vec::new();
    gnu_longname(&mut t, b'L', b"../../PWNED_FROM_GNU.txt");
    let recs = pax_record(b"path", b"benign_from_pax.txt");
    pax_header(&mut t, &recs);
    t.extend_from_slice(&header(b"ustar_name.txt", 5, b'0', b"", true));
    pad(&mut t, b"hello");
    eof(&mut t);

    let (result, _temp) = extract(&t);
    assert!(
        matches!(result, Err(ArchiveError::PathTraversal { .. })),
        "GNU longname traversal must be rejected, got: {result:?}"
    );
}

/// PAX `path` traversal with no GNU longname at all: plain PAX override must
/// still be validated.
#[test]
fn ghsa_vmf3_pax_path_traversal_alone_rejected() {
    let mut t = Vec::new();
    let recs = pax_record(b"path", b"../../PWNED_PAX_ONLY.txt");
    pax_header(&mut t, &recs);
    t.extend_from_slice(&header(b"ustar_name.txt", 5, b'0', b"", true));
    pad(&mut t, b"hello");
    eof(&mut t);

    let (result, _temp) = extract(&t);
    assert!(
        matches!(result, Err(ArchiveError::PathTraversal { .. })),
        "PAX-only path traversal must be rejected, got: {result:?}"
    );
}

/// GNU `LongLink` ('K') carries a traversal target while the ustar linkname
/// fallback is benign: the smuggled traversal target must still be rejected
/// (default config: symlinks disabled, so the entry is rejected outright).
#[test]
fn ghsa_vmf3_gnu_longlink_traversal_benign_ustar_linkname_rejected() {
    let mut t = Vec::new();
    gnu_longname(&mut t, b'K', b"../../../../../../etc/passwd");
    t.extend_from_slice(&header(b"link.txt", 0, b'2', b"benign_target", true));
    eof(&mut t);

    let (result, _temp) = extract(&t);
    assert!(
        result.is_err(),
        "GNU LongLink traversal must be rejected, got: {result:?}"
    );
}

/// GHSA-vmf3 core shape: a PAX `size` record precedes an intermediary GNU
/// long-name ('L') header, then a zero-declared-size real entry, then a
/// trailing entry. The PAX `size` record is accumulated and, per the
/// dependency's `is_extension_header` guard, is *not* applied to the
/// intermediary 'L' header (which uses its own declared length) — instead it
/// is applied to the next real (non-metadata) entry, exactly like an
/// ordinary PAX-preceding-a-file record. That entry surfaces under the GNU
/// long name with the PAX-declared size, and no separately-named smuggled
/// entry ever appears. A vulnerable parser that mis-applied the size to the
/// 'L' header itself would shift framing differently and could expose a
/// distinctly-named smuggled member instead.
#[test]
fn ghsa_vmf3_pax_size_framing_before_gnu_longname_smuggled_member_absent() {
    let mut t = Vec::new();
    let recs = pax_record(b"size", b"1024");
    pax_header(&mut t, &recs);
    gnu_longname(&mut t, b'L', b"visible.txt");
    t.extend_from_slice(&header(b"placeholder.txt", 0, b'0', b"", true));
    t.extend_from_slice(&header(b"trailer.txt", 5, b'0', b"", true));
    pad(&mut t, b"hello");
    eof(&mut t);

    let (result, temp) = extract(&t);
    let report = result.expect("well-formed archive must extract");
    assert_eq!(report.files_extracted, 1, "exactly one entry must surface");
    assert!(
        temp.path().join("visible.txt").exists(),
        "the entry must surface under its GNU long name"
    );
    assert!(
        !temp.path().join("trailer.txt").exists(),
        "the trailing entry must not appear as a separately-named member \
         (its bytes were consumed as data of the PAX-sized entry)"
    );
    assert!(
        !temp.path().join("placeholder.txt").exists(),
        "the entry must be visible only under its GNU long name, never its raw header name"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// GHSA-gvwx / GHSA-w8wr: NUL byte / malformed field handling
// ─────────────────────────────────────────────────────────────────────────

/// A NUL byte embedded in a PAX `path` record must be rejected as a security
/// violation, never panic.
#[test]
fn ghsa_gvwx_nul_byte_in_pax_path_rejected_without_panic() {
    let mut t = Vec::new();
    let recs = pax_record(b"path", b"foo\0bar.txt");
    pax_header(&mut t, &recs);
    t.extend_from_slice(&header(b"ustar_name.txt", 5, b'0', b"", false));
    pad(&mut t, b"hello");
    eof(&mut t);

    let result = std::panic::catch_unwind(|| extract(&t).0);
    let result = result.expect("must not panic on NUL byte in PAX path");
    assert!(
        matches!(result, Err(ArchiveError::SecurityViolation { .. })),
        "NUL byte in PAX path must be a SecurityViolation, got: {result:?}"
    );
    if let Err(ArchiveError::SecurityViolation { reason }) = result {
        assert!(reason.contains("null bytes"), "reason: {reason}");
    }
}

/// A NUL byte embedded in a GNU long-name ('L') record must be rejected as a
/// security violation, never panic — this bypasses the PAX record parser
/// entirely, so it is a distinct code path from the PAX case above.
#[test]
fn ghsa_gvwx_nul_byte_in_gnu_longname_rejected_without_panic() {
    let mut t = Vec::new();
    gnu_longname(&mut t, b'L', b"gnu\0nul.txt");
    t.extend_from_slice(&header(b"ustar_name.txt", 5, b'0', b"", true));
    pad(&mut t, b"hello");
    eof(&mut t);

    let result = std::panic::catch_unwind(|| extract(&t).0);
    let result = result.expect("must not panic on NUL byte in GNU longname");
    assert!(
        matches!(result, Err(ArchiveError::SecurityViolation { .. })),
        "NUL byte in GNU longname must be a SecurityViolation, got: {result:?}"
    );
    if let Err(ArchiveError::SecurityViolation { reason }) = result {
        assert!(reason.contains("null bytes"), "reason: {reason}");
    }
}

/// An empty PAX `path` record must be rejected with the dedicated "empty
/// path" message, not treated as a valid (root-relative) path.
#[test]
fn ghsa_w8wr_empty_pax_path_rejected() {
    let mut t = Vec::new();
    let recs = pax_record(b"path", b"");
    pax_header(&mut t, &recs);
    t.extend_from_slice(&header(b"ustar_name.txt", 5, b'0', b"", false));
    pad(&mut t, b"hello");
    eof(&mut t);

    let (result, _temp) = extract(&t);
    match &result {
        Err(ArchiveError::SecurityViolation { reason }) => {
            assert!(reason.contains("empty path"), "reason: {reason}");
        }
        other => panic!("expected SecurityViolation for empty path, got: {other:?}"),
    }
}

/// A numeric-looking PAX `path` value (`"0"`) is the GHSA-w8wr type-confusion
/// shape (some parsers treat a bare `"0"` as falsy/absent). In Rust, path
/// values are byte strings, so `"0"` must extract literally as a file named
/// `0` with no crash or misinterpretation.
#[test]
fn ghsa_w8wr_numeric_pax_path_extracts_literally() {
    let mut t = Vec::new();
    let recs = pax_record(b"path", b"0");
    pax_header(&mut t, &recs);
    t.extend_from_slice(&header(b"ustar_name.txt", 5, b'0', b"", false));
    pad(&mut t, b"hello");
    eof(&mut t);

    let (result, temp) = extract(&t);
    assert!(
        result.is_ok(),
        "numeric-looking path must extract, got: {result:?}"
    );
    assert!(
        temp.path().join("0").exists(),
        "must extract literally as a file named '0'"
    );
}

/// A PAX `size` record at `u64::MAX` must surface as a graceful size-overflow
/// error, never a panic or unbounded allocation attempt.
#[test]
fn ghsa_w8wr_pax_size_u64_max_rejected_without_panic() {
    let mut t = Vec::new();
    let recs = pax_record(b"size", b"18446744073709551615");
    pax_header(&mut t, &recs);
    t.extend_from_slice(&header(b"ustar_name.txt", 5, b'0', b"", false));
    pad(&mut t, b"hello");
    eof(&mut t);

    let result = std::panic::catch_unwind(|| extract(&t).0);
    let result = result.expect("must not panic on PAX size = u64::MAX");
    assert!(
        result.is_err(),
        "u64::MAX declared size must be rejected, got: {result:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// GHSA-23hp: declared vs. actual entry size mismatches
// ─────────────────────────────────────────────────────────────────────────

/// Asserts `result` is not a quota rejection. The synthetic archives in this
/// section deliberately leave non-zero-byte "garbage" after the declared
/// entry (masquerading as the next header), which the real `tar` crate
/// correctly refuses to parse as a valid header once reached — an unrelated,
/// expected `InvalidArchive`/`PartialExtraction` failure that must not be
/// confused with the single invariant under test: the declared size, not the
/// real payload length, is what gets written and quota-charged.
fn assert_not_quota_rejected(result: &exarch_core::Result<exarch_core::ExtractionReport>) {
    let quota_hit = result.as_ref().err().and_then(ArchiveError::quota_resource);
    assert!(
        quota_hit.is_none(),
        "quota must not be tripped by the real (undeclared) payload size, got: {result:?}"
    );
}

/// A ustar header declares `size=10` but is followed by 4096 real payload
/// bytes: exactly 10 bytes must be written, never the full payload.
#[test]
fn ghsa_23hp_declared_size_understates_actual_payload() {
    let mut t = Vec::new();
    t.extend_from_slice(&header(b"liar.txt", 10, b'0', b"", false));
    pad(&mut t, &vec![b'A'; 4096]);
    eof(&mut t);

    let (result, temp) = extract(&t);
    assert_not_quota_rejected(&result);
    let written = std::fs::metadata(temp.path().join("liar.txt"))
        .unwrap()
        .len();
    assert_eq!(
        written, 10,
        "must write exactly the declared 10 bytes, not the full payload"
    );
}

/// ustar `size` and PAX `size` disagree (PAX is smaller and wins): only the
/// PAX-declared byte count must be written.
#[test]
fn ghsa_23hp_pax_size_smaller_than_ustar_size_wins() {
    let mut t = Vec::new();
    let recs = pax_record(b"size", b"10");
    pax_header(&mut t, &recs);
    t.extend_from_slice(&header(b"paxsmall.txt", 4096, b'0', b"", false));
    pad(&mut t, &vec![b'B'; 4096]);
    eof(&mut t);

    let (result, temp) = extract(&t);
    assert_not_quota_rejected(&result);
    let written = std::fs::metadata(temp.path().join("paxsmall.txt"))
        .unwrap()
        .len();
    assert_eq!(written, 10, "PAX size must win over the larger ustar size");
}

/// A small declared size (10) with a small `max_file_size` quota (64) and a
/// 100,000-byte real payload: exactly 10 bytes must be written, and the
/// quota must not be incorrectly tripped by the real (much larger) payload
/// that follows in the stream.
#[test]
fn ghsa_23hp_declared_size_respects_small_quota_despite_large_payload() {
    let mut t = Vec::new();
    t.extend_from_slice(&header(b"liar2.txt", 10, b'0', b"", false));
    pad(&mut t, &vec![b'C'; 100_000]);
    eof(&mut t);

    let config = SecurityConfig::default().with_max_file_size(64);
    let (result, temp) = extract_with_config(&t, &config);
    assert_not_quota_rejected(&result);
    let written = std::fs::metadata(temp.path().join("liar2.txt"))
        .unwrap()
        .len();
    assert_eq!(written, 10, "must write exactly the declared 10 bytes");
}
