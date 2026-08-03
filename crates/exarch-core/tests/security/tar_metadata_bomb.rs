//! Regression tests for issue #414: TAR metadata-entry decompression bomb.
//!
//! GNU long-name ('L'), GNU long-link ('K'), and PAX extended header ('x'/'g')
//! records are buffered fully into memory by the `tar` crate before any entry
//! reaches `exarch-core`'s validator or quota tracker. A crafted record
//! declaring a huge length backed by a real stream of that length causes
//! unbounded allocation with no quota enforcement.
//!
//! `SecurityConfig::max_tar_metadata_bytes` closes this via a read budget
//! (`formats::tar_metadata_limit`) metered on bytes the `tar` crate actually
//! reads while searching for the next entry — not on any header's declared
//! size — so these fixtures use *real* backing bytes matching (or exceeding)
//! the configured budget, not a huge declared size behind a tiny stream: a
//! byte-budget mechanism has nothing to trip on unless the bytes are actually
//! there to be read.
//!
//! An earlier version of this fix re-parsed TAR headers to reject an
//! oversized *declared* size before the `tar` crate could buffer it. Three
//! rounds of adversarial review found three independent ways a shadow parser
//! could disagree with the real one about entry framing (S1: untracked PAX
//! `size=` overrides, S2: framing typeflags without gating on valid magic,
//! S3: a PAX global header draining the real parser's override state without
//! draining the mirror's). The historical-shape tests below reconstruct all
//! three attack byte-sequences and confirm the budget mechanism — which does
//! not parse headers at all, so has no framing belief to diverge — rejects
//! them regardless.
//!
//! These tests use small, test-specific `max_tar_metadata_bytes` values
//! (instead of reproducing a multi-gigabyte archive) so the budget can be
//! verified without allocating large amounts of memory in CI.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use exarch_core::ArchiveError;
use exarch_core::ExtractionOptions;
use exarch_core::NoopProgress;
use exarch_core::SecurityConfig;
use exarch_core::formats::ArchiveFormat;
use exarch_core::formats::TarArchive;
use std::io::Cursor;
use std::io::Write;
use tempfile::TempDir;

const BLOCK: usize = 512;

/// Builds a raw 512-byte TAR header block.
fn header(name: &[u8], size: u64, typeflag: u8, gnu_magic: bool) -> Vec<u8> {
    let mut h = vec![0u8; BLOCK];
    let name_len = name.len().min(100);
    h[..name_len].copy_from_slice(&name[..name_len]);
    h[100..108].copy_from_slice(b"0000644\0");
    h[108..116].copy_from_slice(b"0000000\0");
    h[116..124].copy_from_slice(b"0000000\0");
    h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    h[136..148].copy_from_slice(b"00000000000\0");
    h[156] = typeflag;
    if gnu_magic {
        h[257..263].copy_from_slice(b"ustar ");
        h[263..265].copy_from_slice(b" \0");
    } else {
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
    }
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

/// Builds a raw header with the magic/version field left zeroed — neither
/// valid ustar nor valid GNU magic.
fn header_invalid_magic(name: &[u8], size: u64, typeflag: u8) -> Vec<u8> {
    let mut h = vec![0u8; BLOCK];
    let name_len = name.len().min(100);
    h[..name_len].copy_from_slice(&name[..name_len]);
    h[100..108].copy_from_slice(b"0000644\0");
    h[108..116].copy_from_slice(b"0000000\0");
    h[116..124].copy_from_slice(b"0000000\0");
    h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    h[136..148].copy_from_slice(b"00000000000\0");
    h[156] = typeflag;
    // magic bytes (257..265) intentionally left zeroed: invalid.
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

fn pad_to_block(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(data);
    let rem = data.len() % BLOCK;
    if rem != 0 {
        out.extend(std::iter::repeat_n(0u8, BLOCK - rem));
    }
}

/// Encodes one PAX extended-header record: `"LEN key=value\n"`, where `LEN`
/// includes its own decimal digit count (the standard self-referential PAX
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

/// Builds a single metadata record (`'L'`/`'K'`/`'x'`) whose declared size
/// matches `real_bytes` exactly (a real, readable stream of that length, not
/// a huge declared size behind a tiny one) — the shape the read-budget
/// mechanism actually needs to trip on, since it only counts bytes really
/// delivered.
fn metadata_bomb(typeflag: u8, real_bytes: usize) -> Vec<u8> {
    let name: &[u8] = if typeflag == b'x' {
        b"PaxHeaders/bomb"
    } else {
        b"././@LongLink"
    };
    let mut out = header(name, real_bytes as u64, typeflag, typeflag != b'x');
    pad_to_block(&mut out, &vec![b'A'; real_bytes]);
    out
}

fn write_tar_file(dir: &TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(bytes).unwrap();
    path
}

/// Asserts the result is a security violation caused by the TAR metadata read
/// budget. Matches both a direct `SecurityViolation` and one wrapped in
/// `PartialExtraction` (extraction reports a wrapped source once any file was
/// written before the violation, e.g. a decoy entry preceding the hidden
/// bomb).
fn assert_is_budget_violation(result: &exarch_core::Result<impl std::fmt::Debug>) {
    match result {
        Err(e) if e.is_security_violation() => {
            let reason = e.context().unwrap_or_default();
            assert!(
                reason.contains("budget") || reason.contains("metadata"),
                "reason should reference the TAR metadata read budget: {reason}"
            );
        }
        other => panic!("expected a budget SecurityViolation, got: {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// TarArchive::extract() — direct entry point
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn extract_rejects_oversized_gnu_longname_metadata_entry() {
    let bomb = metadata_bomb(b'L', 8192);
    let temp = TempDir::new().unwrap();
    let config = SecurityConfig::default()
        .with_max_tar_metadata_bytes(4096)
        .validate()
        .unwrap();

    let mut archive = TarArchive::new(Cursor::new(bomb));
    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut NoopProgress,
    );
    assert_is_budget_violation(&result);
}

#[test]
fn extract_rejects_oversized_gnu_longlink_metadata_entry() {
    let bomb = metadata_bomb(b'K', 8192);
    let temp = TempDir::new().unwrap();
    let config = SecurityConfig::default()
        .with_max_tar_metadata_bytes(4096)
        .validate()
        .unwrap();

    let mut archive = TarArchive::new(Cursor::new(bomb));
    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut NoopProgress,
    );
    assert_is_budget_violation(&result);
}

#[test]
fn extract_rejects_oversized_pax_metadata_entry() {
    let bomb = metadata_bomb(b'x', 8192);
    let temp = TempDir::new().unwrap();
    let config = SecurityConfig::default()
        .with_max_tar_metadata_bytes(4096)
        .validate()
        .unwrap();

    let mut archive = TarArchive::new(Cursor::new(bomb));
    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut NoopProgress,
    );
    assert_is_budget_violation(&result);
}

#[test]
fn extract_accepts_metadata_entry_within_the_configured_budget() {
    // A GNU longname just under a generous budget must extract normally —
    // the budget must not produce false positives on legitimate long paths.
    // A single long component (no extra path depth) that still exceeds the
    // 100-byte ustar name field, forcing GNU long-name usage.
    let long_name = "x".repeat(150) + "_file.txt";
    let mut data = long_name.clone().into_bytes();
    data.push(0);

    let mut t = Vec::new();
    t.extend_from_slice(&header(b"././@LongLink", data.len() as u64, b'L', true));
    pad_to_block(&mut t, &data);
    t.extend_from_slice(&header(b"file.txt", 5, b'0', true));
    pad_to_block(&mut t, b"hello");
    t.extend(std::iter::repeat_n(0u8, BLOCK * 2));

    let temp = TempDir::new().unwrap();
    let config = SecurityConfig::default()
        .with_max_tar_metadata_bytes(4096)
        .validate()
        .unwrap();
    let mut archive = TarArchive::new(Cursor::new(t));
    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut NoopProgress,
    );
    let report = result.expect("a metadata entry within the budget must extract normally");
    assert_eq!(report.files_extracted, 1);
    assert!(temp.path().join(&long_name).exists());
}

// ─────────────────────────────────────────────────────────────────────────
// list_archive() / verify_archive() — the actual public API entry points,
// which bypass `TarArchive` entirely and open `tar::Archive` directly
// (see `inspection::list`), so they need their own coverage.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn list_archive_rejects_oversized_metadata_entry() {
    let bomb = metadata_bomb(b'L', 8192);
    let temp = TempDir::new().unwrap();
    let path = write_tar_file(&temp, "bomb.tar", &bomb);
    let config = SecurityConfig::default().with_max_tar_metadata_bytes(4096);

    let result = exarch_core::list_archive(&path, &config);
    assert_is_budget_violation(&result);
}

#[test]
fn verify_archive_rejects_oversized_metadata_entry() {
    let bomb = metadata_bomb(b'x', 8192);
    let temp = TempDir::new().unwrap();
    let path = write_tar_file(&temp, "bomb.tar", &bomb);
    let config = SecurityConfig::default().with_max_tar_metadata_bytes(4096);

    let result = exarch_core::verify_archive(&path, &config);
    assert_is_budget_violation(&result);
}

#[test]
fn extract_archive_rejects_oversized_metadata_entry_via_public_api() {
    let bomb = metadata_bomb(b'K', 8192);
    let temp = TempDir::new().unwrap();
    let path = write_tar_file(&temp, "bomb.tar", &bomb);
    let out = temp.path().join("out");
    let config = SecurityConfig::default().with_max_tar_metadata_bytes(4096);

    let result = exarch_core::extract_archive(&path, &out, &config);
    assert_is_budget_violation(&result);
}

#[test]
fn default_config_budget_rejects_a_moderately_oversized_metadata_entry() {
    // Exercises the *default* 4 MiB budget (no custom config) against a
    // record just over it. A few MB of real in-memory bytes is fine for CI
    // (unlike the multi-gigabyte scale of the original PoC): this is a
    // linear real-bytes-in/real-bytes-metered relationship now, not a
    // compression-amplified bomb.
    let bomb = metadata_bomb(b'L', 4 * 1024 * 1024 + 4096);
    let temp = TempDir::new().unwrap();

    let mut archive = TarArchive::new(Cursor::new(bomb));
    let result = archive.extract(
        temp.path(),
        &SecurityConfig::default().validate().unwrap(),
        &ExtractionOptions::default(),
        &mut NoopProgress,
    );
    assert_is_budget_violation(&result);
}

// ─────────────────────────────────────────────────────────────────────────
// Historical-shape regression tests: the exact byte sequences that broke
// three rounds of the earlier shadow-parser fix. The budget mechanism does
// not parse PAX overrides, magic bytes, or typeflags at all, so none of
// these shapes are individually meaningful to it any more — they are kept
// as concrete regressions proving each historical PoC is still rejected,
// not because the new mechanism treats them specially.
// ─────────────────────────────────────────────────────────────────────────

/// S1 shape: a local PAX header declaring `size=0` (an override the real
/// `tar` crate applies to the next entry), a decoy regular file, then a GNU
/// long-name record whose real bytes exceed the budget.
fn s1_shape_bomb(bomb_real_bytes: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let pax_body = b"9 size=0\n".to_vec();
    out.extend_from_slice(&header(
        b"PaxHeaders/decoy",
        pax_body.len() as u64,
        b'x',
        false,
    ));
    pad_to_block(&mut out, &pax_body);
    out.extend_from_slice(&header(b"decoy.txt", 4096, b'0', true));
    out.extend_from_slice(&header(
        b"././@LongLink",
        bomb_real_bytes as u64,
        b'L',
        true,
    ));
    pad_to_block(&mut out, &vec![b'A'; bomb_real_bytes]);
    out
}

/// S2 shape: like S1, but the leading PAX header has invalid (zeroed) magic
/// — a `tar`-crate-observable difference the earlier shadow parser's
/// typeflag-only detection missed, the budget mechanism does not care about
/// at all.
fn s2_shape_bomb(bomb_real_bytes: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let pax_body = pax_record(b"size", b"0");
    out.extend_from_slice(&header_invalid_magic(
        b"PaxHeaders/decoy",
        pax_body.len() as u64,
        b'x',
    ));
    pad_to_block(&mut out, &pax_body);
    out.extend_from_slice(&header(b"decoy.txt", 512, b'0', true));
    pad_to_block(&mut out, &vec![b'D'; 512]);
    out.extend_from_slice(&header(
        b"././@LongLink",
        bomb_real_bytes as u64,
        b'L',
        true,
    ));
    pad_to_block(&mut out, &vec![b'A'; bomb_real_bytes]);
    out
}

/// S3 shape: a local PAX override record, then a PAX **global** header
/// (which the real `tar` crate yields as an ordinary entry, draining any
/// pending override — a state transition the earlier shadow parser's
/// per-typeflag mirror missed), then a decoy, then the bomb.
fn s3_shape_bomb(bomb_real_bytes: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let pax_body = pax_record(b"size", b"0");
    out.extend_from_slice(&header(
        b"PaxHeaders/decoy",
        pax_body.len() as u64,
        b'x',
        false,
    ));
    pad_to_block(&mut out, &pax_body);
    let global_body = pax_record(b"comment", b"hi");
    out.extend_from_slice(&header(
        b"././@PaxHeader",
        global_body.len() as u64,
        b'g',
        true,
    ));
    pad_to_block(&mut out, &global_body);
    // Unlike the S1/S2 shapes, no PAX size override is active by the time
    // `decoy.txt` is reached (the preceding 'g' header already drains it in
    // the real `tar` crate) — so `decoy.txt` is framed at its own declared
    // size in both the real parser and this budget mechanism, and needs
    // matching real content.
    out.extend_from_slice(&header(b"decoy.txt", 4096, b'0', true));
    pad_to_block(&mut out, &vec![b'D'; 4096]);
    out.extend_from_slice(&header(
        b"././@LongLink",
        bomb_real_bytes as u64,
        b'L',
        true,
    ));
    pad_to_block(&mut out, &vec![b'A'; bomb_real_bytes]);
    out
}

fn assert_all_entry_points_reject(bomb: &[u8], file_name: &str) {
    let config = SecurityConfig::default().with_max_tar_metadata_bytes(4096);
    let validated_config = config.clone().validate().unwrap();

    let temp = TempDir::new().unwrap();
    let mut archive = TarArchive::new(Cursor::new(bomb.to_owned()));
    let result = archive.extract(
        temp.path(),
        &validated_config,
        &ExtractionOptions::default(),
        &mut NoopProgress,
    );
    assert_is_budget_violation(&result);

    let temp = TempDir::new().unwrap();
    let path = write_tar_file(&temp, file_name, bomb);
    assert_is_budget_violation(&exarch_core::list_archive(&path, &config));
    assert_is_budget_violation(&exarch_core::verify_archive(&path, &config));
    let out = temp.path().join("out");
    assert_is_budget_violation(&exarch_core::extract_archive(&path, &out, &config));
}

#[test]
fn s1_shape_pax_size_zero_override_hiding_a_bomb_is_still_rejected() {
    assert_all_entry_points_reject(&s1_shape_bomb(8192), "s1.tar");
}

#[test]
fn s2_shape_invalid_magic_pax_override_hiding_a_bomb_is_still_rejected() {
    assert_all_entry_points_reject(&s2_shape_bomb(8192), "s2.tar");
}

#[test]
fn s3_shape_pax_global_header_hiding_a_bomb_is_still_rejected() {
    assert_all_entry_points_reject(&s3_shape_bomb(8192), "s3.tar");
}

#[test]
fn legitimate_pax_global_header_does_not_false_positive() {
    // A small, real PAX global header ('g') ahead of an ordinary file must
    // not itself be mistaken for a bypass attempt or rejected.
    let mut t = Vec::new();
    let global_body = pax_record(b"comment", b"hi");
    t.extend_from_slice(&header(
        b"././@PaxHeader",
        global_body.len() as u64,
        b'g',
        true,
    ));
    pad_to_block(&mut t, &global_body);
    t.extend_from_slice(&header(b"file.txt", 5, b'0', true));
    pad_to_block(&mut t, b"hello");
    t.extend(std::iter::repeat_n(0u8, BLOCK * 2));

    let temp = TempDir::new().unwrap();
    let config = SecurityConfig::default()
        .with_max_tar_metadata_bytes(4096)
        .validate()
        .unwrap();
    let mut archive = TarArchive::new(Cursor::new(t));
    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut NoopProgress,
    );
    let report = result.expect("a small legitimate PAX global header must not be rejected");
    assert_eq!(report.files_extracted, 1);
    assert!(temp.path().join("file.txt").exists());
}

// ─────────────────────────────────────────────────────────────────────────
// C1 regression: GNU sparse `realsize` bomb on `verify` (issue #414 follow-up)
//
// A GNU old-format sparse entry ('S') can declare a `realsize` field (the
// entry's *logical* size) far larger than its actual backing bytes — `tar`
// materializes the shortfall as synthesized zero padding
// (`EntryIo::Pad(io::repeat(0).take(gap))`), not real archive content. The
// read-budget mechanism above never inspects this (headers are opaque to
// it), so it cannot trip on an oversized *declared* size — it only bounds
// bytes actually read while searching for the next entry. What must bound
// the cost of an unread sparse entry's `Drop`-time drain is
// `TarEntryGuard`'s synthesized-byte accounting (`SYNTHETIC_PAD_CAP_BYTES`):
// output produced with no corresponding read from the underlying reader is
// capped regardless of any caller-supplied quota.
//
// `verify_archive()`'s pre-listing pass (`listing_config_for_verify`)
// legitimately relaxes `max_file_size` to `u64::MAX` so a metadata-only
// listing does not false-reject large files. An earlier version of this fix
// threaded that same relaxed quota straight into the drain bound, so a
// sparse entry with an astronomical `realsize` turned `verify` into an
// unbounded CPU sink with no corresponding heap growth (drained to
// `io::sink`) — invisible to allocation-based tests, but a real wall-clock
// hang scaling linearly with the attacker-chosen `realsize`.
// ─────────────────────────────────────────────────────────────────────────

/// Encodes `n` as a classic octal numeric field of `width` bytes (including
/// the trailing NUL), or `None` if `n` does not fit in `width - 1` octal
/// digits.
fn octal_field(n: u64, width: usize) -> Option<Vec<u8>> {
    let digits = format!("{n:o}").into_bytes();
    if digits.len() > width - 1 {
        return None;
    }
    let mut out = vec![b'0'; width - 1 - digits.len()];
    out.extend_from_slice(&digits);
    out.push(0);
    Some(out)
}

/// Encodes `n` as a GNU base-256 numeric field: big-endian bytes with the
/// high bit of the first byte set, used whenever a value is too large for
/// the field's octal digit capacity (this is exactly how a GNU sparse
/// entry's `realsize` reaches values up to `u64::MAX`).
fn base256_field(n: u64, width: usize) -> Vec<u8> {
    let mut out = vec![0u8; width];
    let bytes = n.to_be_bytes();
    out[width - bytes.len()..].copy_from_slice(&bytes);
    out[0] |= 0x80;
    out
}

fn num_field(n: u64, width: usize) -> Vec<u8> {
    octal_field(n, width).unwrap_or_else(|| base256_field(n, width))
}

/// Builds a raw GNU old-format sparse header (typeflag `'S'`) declaring a
/// `realsize` (logical size) that may vastly exceed `size_field` (the
/// physical/allocated size backing it), with up to 4 inline sparse
/// `(offset, numbytes)` blocks — mirroring the actual GNU tar on-disk layout
/// (inline sparse array at byte offset 386, `isextended` at 482, `realsize`
/// at 483).
fn gnu_sparse_header(
    name: &[u8],
    size_field: u64,
    realsize: u64,
    blocks: &[(u64, u64)],
) -> Vec<u8> {
    let mut h = vec![0u8; BLOCK];
    let name_len = name.len().min(100);
    h[..name_len].copy_from_slice(&name[..name_len]);
    h[100..108].copy_from_slice(&num_field(0o644, 8));
    h[108..116].copy_from_slice(&num_field(0, 8));
    h[116..124].copy_from_slice(&num_field(0, 8));
    h[124..136].copy_from_slice(&num_field(size_field, 12));
    h[136..148].copy_from_slice(&num_field(0, 12));
    h[156] = b'S';
    h[257..263].copy_from_slice(b"ustar ");
    h[263..265].copy_from_slice(b" \0");
    let mut off = 386;
    for &(offset, numbytes) in blocks.iter().take(4) {
        h[off..off + 12].copy_from_slice(&num_field(offset, 12));
        h[off + 12..off + 24].copy_from_slice(&num_field(numbytes, 12));
        off += 24;
    }
    h[482] = 0; // isextended: no additional sparse-header blocks follow
    h[483..495].copy_from_slice(&num_field(realsize, 12));
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

/// Builds a complete single-entry TAR whose one GNU sparse entry declares
/// `realsize` logical bytes backed by exactly one physical block.
fn sparse_realsize_bomb(realsize: u64) -> Vec<u8> {
    let gap = realsize - BLOCK as u64;
    let hdr = gnu_sparse_header(
        b"sparsebomb.bin",
        BLOCK as u64,
        realsize,
        &[(gap, BLOCK as u64)],
    );
    let mut out = hdr;
    out.extend(std::iter::repeat_n(0u8, BLOCK)); // the one backing block
    out.extend(std::iter::repeat_n(0u8, BLOCK * 2)); // end-of-archive trailer
    out
}

/// Bound generous enough to never flake in CI, but far tighter than the
/// multi-second-to-multi-hour hang the C1 bug produced (which scaled
/// linearly with `realsize`, not with any constant like this one).
const SPARSE_BOMB_WALL_CLOCK_BOUND: std::time::Duration = std::time::Duration::from_secs(2);

#[test]
fn verify_archive_stays_bounded_against_gnu_sparse_realsize_bomb() {
    // `1 << 62`: far beyond any real filesystem, and far beyond the 500 MiB
    // default `max_total_size` quota — chosen to prove wall-clock time does
    // not scale with the claimed size at all, not merely to exceed a smaller
    // threshold.
    let bomb = sparse_realsize_bomb(1u64 << 62);
    let temp = TempDir::new().unwrap();
    let path = write_tar_file(&temp, "sparse_bomb.tar", &bomb);

    let start = std::time::Instant::now();
    let result = exarch_core::verify_archive(&path, &SecurityConfig::default());
    let elapsed = start.elapsed();

    assert!(
        result.is_err(),
        "a sparse entry claiming a multi-exabyte realsize must fail quota, not verify clean: \
         {result:?}"
    );
    assert!(
        elapsed < SPARSE_BOMB_WALL_CLOCK_BOUND,
        "verify must not scale with the entry's claimed (unbacked) realsize, took {elapsed:?}"
    );
}

#[test]
fn list_and_extract_archive_also_stay_bounded_against_gnu_sparse_realsize_bomb() {
    // Defense in depth (critic's Q2): the absolute drain cap applies to
    // every path, not only `verify`, so a caller who legitimately raises
    // `max_file_size` for `list`/`extract` does not reopen a smaller version
    // of C1 either.
    let bomb = sparse_realsize_bomb(1u64 << 62);
    let config = SecurityConfig::default();

    let temp = TempDir::new().unwrap();
    let path = write_tar_file(&temp, "sparse_bomb.tar", &bomb);
    let start = std::time::Instant::now();
    let result = exarch_core::list_archive(&path, &config);
    let elapsed = start.elapsed();
    assert!(
        result.is_err(),
        "list must reject the sparse bomb: {result:?}"
    );
    assert!(
        elapsed < SPARSE_BOMB_WALL_CLOCK_BOUND,
        "list must not scale with the entry's claimed realsize, took {elapsed:?}"
    );

    let temp = TempDir::new().unwrap();
    let path = write_tar_file(&temp, "sparse_bomb.tar", &bomb);
    let out = temp.path().join("out");
    let start = std::time::Instant::now();
    let result = exarch_core::extract_archive(&path, &out, &config);
    let elapsed = start.elapsed();
    assert!(
        result.is_err(),
        "extract must reject the sparse bomb: {result:?}"
    );
    assert!(
        elapsed < SPARSE_BOMB_WALL_CLOCK_BOUND,
        "extract must not scale with the entry's claimed realsize, took {elapsed:?}"
    );
}

#[test]
fn known_limitation_legitimate_sparse_hole_above_the_synthetic_cap_is_rejected() {
    // Pins the module's documented residual limitation (see
    // `formats::tar_metadata_limit`'s module docs): a *legitimate* GNU
    // sparse file whose real hole exceeds `SYNTHETIC_PAD_CAP_BYTES` is
    // indistinguishable, by pure byte accounting, from the C1 attack shape
    // when skipped unread on `list_archive`/`verify_archive` — both produce
    // output with no corresponding read. This is a deliberately accepted
    // trade-off (P3 follow-up tracked separately), not a bug: this test
    // exists so a future change to `SYNTHETIC_PAD_CAP_BYTES` cannot silently
    // move this threshold without a test noticing.
    //
    // `exarch_core::extract_archive` (the library function) is unaffected —
    // it never calls `list_archive` itself, so this exact shape extracts
    // cleanly through it. The `exarch` CLI's `extract` *command* runs its
    // own separate `list_archive` pre-flight for progress-bar/conflict
    // detection (`exarch-cli/src/commands/extract.rs`), so it IS affected;
    // that CLI-specific behavior is pinned separately in
    // `exarch-cli/tests/cli_tests.rs`, which can invoke the actual binary.
    //
    // Shape: a leading hole (bigger than the 8 MiB synthetic cap, so the drop's
    // drain gives up while still inside the virtual hole, never touching
    // the trailing real data) followed by a real trailing data segment
    // (bigger than the default 4 MiB `max_tar_metadata_bytes`): with the
    // drop having consumed zero real bytes, `tar`'s own catch-up skip to
    // the next header — which runs *while the metadata budget is armed* —
    // must consume the entire unread real segment itself, tripping the
    // budget. A hole with a *small* trailing real segment, or one under the
    // synthetic cap, does not reproduce this: physical stream position is
    // untouched by virtual padding either way, so only a large real segment
    // left entirely unread by the drop actually costs anything once `tar`
    // catches up.
    let gap = 12 * 1024 * 1024u64;
    let real_trailing = 6 * 1024 * 1024u64;
    let bomb_hdr = gnu_sparse_header(
        b"legit_sparse.bin",
        real_trailing,
        gap + real_trailing,
        &[(gap, real_trailing)],
    );
    let mut bomb = bomb_hdr;
    pad_to_block(&mut bomb, &vec![b'D'; real_trailing as usize]);
    bomb.extend(std::iter::repeat_n(0u8, BLOCK * 2));
    let config = SecurityConfig::default();

    let temp = TempDir::new().unwrap();
    let path = write_tar_file(&temp, "legit_sparse_hole.tar", &bomb);
    let result = exarch_core::list_archive(&path, &config);
    assert!(
        result.is_err(),
        "known limitation: a legitimate sparse hole above the synthetic cap is currently \
         rejected by list_archive, got: {result:?}"
    );

    let result = exarch_core::verify_archive(&path, &config);
    assert!(
        result.is_err(),
        "known limitation: a legitimate sparse hole above the synthetic cap is currently \
         rejected by verify_archive, got: {result:?}"
    );

    // `extract_archive` (library) never calls `list_archive` itself, so it
    // reads the entry directly and is unaffected — confirming the
    // limitation is specific to the metadata-only paths above, not to
    // extraction in general.
    let out = temp.path().join("out");
    let report = exarch_core::extract_archive(&path, &out, &config).expect(
        "extract_archive reads the entry itself (no list_archive pre-flight in the library \
         function) and is not subject to this limitation",
    );
    assert_eq!(report.files_extracted, 1);

    // A direct `TarArchive::extract` library call is unaffected for the
    // same reason: the entry is actually read, not drained unread.
    let mut archive = TarArchive::new(Cursor::new(bomb));
    let validated_config = config.validate().unwrap();
    let report = archive
        .extract(
            temp.path().join("direct_out").as_path(),
            &validated_config,
            &ExtractionOptions::default(),
            &mut NoopProgress,
        )
        .expect(
            "a direct TarArchive::extract call reads the entry itself and is not subject to \
             this limitation",
        );
    assert_eq!(report.files_extracted, 1);
}

/// Builds a 3-entry TAR: a small allowed file, a large disallowed-extension
/// file, then another small allowed file — used to prove skip-and-continue
/// survives a legitimately large skipped entry.
fn skip_and_continue_fixture(big_size: usize) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    let mut h1 = tar::Header::new_gnu();
    h1.set_size(5);
    h1.set_mode(0o644);
    h1.set_cksum();
    builder
        .append_data(&mut h1, "before.txt", &b"hello"[..])
        .unwrap();

    let mut h2 = tar::Header::new_gnu();
    h2.set_size(big_size as u64);
    h2.set_mode(0o644);
    h2.set_cksum();
    builder
        .append_data(&mut h2, "big.bin", &vec![b'B'; big_size][..])
        .unwrap();

    let mut h3 = tar::Header::new_gnu();
    h3.set_size(5);
    h3.set_mode(0o644);
    h3.set_cksum();
    builder
        .append_data(&mut h3, "after.txt", &b"world"[..])
        .unwrap();

    builder.into_inner().unwrap()
}

#[test]
fn extract_fully_skips_a_legitimate_large_disallowed_extension_entry_and_continues() {
    // Critic's explicit constraint on the C1/C2/C3 fixes: the drain
    // mechanism must not break the (unrelated, pre-existing) "skip a
    // disallowed-extension entry and continue extracting the rest"
    // behavior. The extension filter runs before `validate_entry` (so a
    // skipped entry is never charged against the size/count quota), which
    // means this entry is skipped without ever being validated — the guard
    // must still fully drain it on skip so the *next* entry's header is
    // found correctly, regardless of size or whether quota validation ran.
    // 45 MiB is chosen specifically because it is well above every fixed
    // bound tried and rejected during this fix's history (4 MiB, 16 MiB,
    // 20 MiB) — C3 found the previous version of this test (10 MiB) passed
    // only because it stayed under those since-removed caps, certifying a
    // behavior actually broken above ~20 MiB.
    let big_size = 45 * 1024 * 1024;
    let data = skip_and_continue_fixture(big_size);
    let temp = TempDir::new().unwrap();
    let config = SecurityConfig::default().with_allowed_extensions(vec!["txt".to_string()]);
    let validated_config = config.clone().validate().unwrap();

    let mut archive = TarArchive::new(Cursor::new(data.clone()));
    let result = archive.extract(
        temp.path(),
        &validated_config,
        &ExtractionOptions::default(),
        &mut NoopProgress,
    );

    let report = result.expect(
        "skipping a disallowed-extension entry within quota must not corrupt subsequent header \
         search",
    );
    assert_eq!(report.files_extracted, 2, "before.txt and after.txt");
    assert_eq!(report.files_skipped, 1, "big.bin skipped for its extension");
    assert!(temp.path().join("before.txt").exists());
    assert!(temp.path().join("after.txt").exists());
    assert!(!temp.path().join("big.bin").exists());

    // Also check the public `extract_archive` API (a thin wrapper distinct
    // from `TarArchive::extract` above, though it does not run a
    // `list_archive` pre-flight itself — only the `exarch` CLI's own
    // `extract` command does, in `exarch-cli/src/commands/extract.rs`).
    let path = write_tar_file(&temp, "skip_and_continue.tar", &data);
    let out = temp.path().join("out2");
    let report = exarch_core::extract_archive(&path, &out, &config)
        .expect("extract_archive must not reject this archive");
    assert_eq!(report.files_extracted, 2);
    assert_eq!(report.files_skipped, 1);
}

#[test]
fn list_and_verify_accept_a_single_legitimate_entry_at_every_size_that_broke_c2() {
    // C2 regression: any fixed cap on total drained output false-rejects
    // ordinary archives once a single entry exceeds it. The critic's live
    // repro found the exact threshold at 8 MiB (`max_tar_metadata_bytes`
    // doubled, since one entry both trips the metadata budget on the next
    // header search AND drains up to the same value): 3/6 MiB entries
    // listed fine, 9/12/30 MiB entries were all incorrectly rejected. Re-run
    // that exact table (plus 45 MiB, matching the skip-and-continue test
    // above, and staying under the default 50 MB `max_file_size` quota so
    // this isolates the drain mechanism from an unrelated quota rejection)
    // against `list`/`verify`/`extract`, none crafted — a plain single-entry
    // archive, nothing sparse or malformed.
    for size_mib in [3, 6, 9, 12, 30, 45] {
        let size = size_mib * 1024 * 1024;
        let mut builder = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(size as u64);
        h.set_mode(0o644);
        h.set_cksum();
        builder
            .append_data(&mut h, "legit.bin", &vec![b'L'; size][..])
            .unwrap();
        let data = builder.into_inner().unwrap();

        let temp = TempDir::new().unwrap();
        let path = write_tar_file(&temp, "legit.tar", &data);
        let config = SecurityConfig::default();

        let manifest = exarch_core::list_archive(&path, &config).unwrap_or_else(|e| {
            panic!("list_archive rejected a legitimate {size_mib} MiB entry: {e}")
        });
        assert_eq!(manifest.total_entries, 1);

        let report = exarch_core::verify_archive(&path, &config).unwrap_or_else(|e| {
            panic!("verify_archive rejected a legitimate {size_mib} MiB entry: {e}")
        });
        assert_eq!(
            report.status,
            exarch_core::VerificationStatus::Pass,
            "verify_archive reported issues for a legitimate {size_mib} MiB entry: {:?}",
            report.issues
        );

        let out = temp.path().join("out");
        let extract_report =
            exarch_core::extract_archive(&path, &out, &config).unwrap_or_else(|e| {
                panic!("extract_archive rejected a legitimate {size_mib} MiB entry: {e}")
            });
        assert_eq!(extract_report.files_extracted, 1);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Issue #422: cumulative synthetic-byte budget across many small entries
// ─────────────────────────────────────────────────────────────────────────
//
// SYNTHETIC_PAD_CAP_BYTES (formats::tar_metadata_limit) bounds the drain
// cost of any *single* unread GNU sparse entry, but a caller with an
// extension allowlist configured skips disallowed entries before
// QuotaTracker ever runs (PR #421 moved the check there specifically to
// stop quota from double-counting files that end up skipped) — so nothing
// previously bounded the *count* of synthetic-heavy entries an archive
// could contain. An archive of many small extension-filtered GNU sparse
// entries could sum to an unbounded amount of wasted drain work even though
// each entry alone stayed within its own cap. The deterministic version of
// this regression (entry-yield counts, not wall-clock) lives in
// `formats::tar_metadata_limit`'s own test module, which can drive the
// crate-internal `BudgetedEntries` iterator directly; the tests below
// exercise the same shapes through the public API these internals actually
// serve, so wall-clock is the only externally observable "failed fast"
// signal available here. (Since #505, a skip-only report — nonzero
// `files_skipped` but zero `total_items()` — does populate `PartialExtraction`
// on a later failure, but `assert_is_budget_violation` below deliberately
// keys off `is_security_violation()`/`context()`, which delegate through
// `PartialExtraction` either way, so it is agnostic to whether that wrapping
// occurred.)

/// Builds a multi-entry TAR of `n` GNU sparse entries, each named
/// `spam{i}.bin`, each declaring a hole (`gap`) beyond its one physical
/// backing block — many small copies of the same C1 shape used above,
/// concatenated instead of standing alone.
fn many_sparse_bombs_tar(n: usize, gap: u64) -> Vec<u8> {
    let mut out = Vec::new();
    for i in 0..n {
        let name = format!("spam{i}.bin");
        let realsize = BLOCK as u64 + gap;
        let hdr = gnu_sparse_header(
            name.as_bytes(),
            BLOCK as u64,
            realsize,
            &[(gap, BLOCK as u64)],
        );
        out.extend(hdr);
        out.extend(std::iter::repeat_n(0u8, BLOCK)); // one real backing block
    }
    out.extend(std::iter::repeat_n(0u8, BLOCK * 2)); // end-of-archive trailer
    out
}

#[test]
fn extract_rejects_many_extension_filtered_sparse_entries_via_cumulative_budget() {
    // Reproduces the issue directly: an extension allowlist skips every one
    // of 200 small sparse-bomb entries before QuotaTracker ever sees them,
    // so max_total_size/max_file_count provide no cover. Without a
    // cumulative bound, extraction would drain every entry (bounded per-entry
    // but unbounded in sum) and eventually "succeed" having done far more
    // work than a well-formed archive of this size should ever cost. With
    // the fix, iteration must fail fast once the cross-entry synthetic sum
    // exceeds the cumulative cap (roughly 128 maximally-saturating entries
    // at the current 1 GiB cap) — well before entry 200.
    let bomb = many_sparse_bombs_tar(200, 1u64 << 40);
    let config = SecurityConfig::default().with_allowed_extensions(vec!["txt".to_string()]);

    let temp = TempDir::new().unwrap();
    let path = write_tar_file(&temp, "many_sparse.tar", &bomb);
    let out = temp.path().join("out");

    let start = std::time::Instant::now();
    let result = exarch_core::extract_archive(&path, &out, &config);
    let elapsed = start.elapsed();

    assert_is_budget_violation(&result);
    assert!(
        elapsed < SPARSE_BOMB_WALL_CLOCK_BOUND,
        "extract must not scale with the number of skipped synthetic-heavy entries, took \
         {elapsed:?}"
    );
}

#[test]
fn extract_rejects_many_extension_filtered_sub_cap_sparse_entries_via_cumulative_budget() {
    // Regression for critic finding S3: the test above only proves the
    // budget trips when every entry individually saturates
    // SYNTHETIC_PAD_CAP_BYTES (8 MiB). The issue's own reported shape is
    // 20,000 *small* entries — each producing far less synthesized output
    // than the per-entry cap on its own — whose sum, not any single entry,
    // exceeds the cumulative cap. A regression that only accumulated when
    // the per-entry cap tripped would pass the test above but let this one
    // drain in full. 300 entries of a 4 MiB (sub-cap) hole each are needed
    // to exceed the 1 GiB cumulative cap (~256 entries) with margin.
    let bomb = many_sparse_bombs_tar(300, 4 * 1024 * 1024);
    let config = SecurityConfig::default().with_allowed_extensions(vec!["txt".to_string()]);

    let temp = TempDir::new().unwrap();
    let path = write_tar_file(&temp, "many_sub_cap_sparse.tar", &bomb);
    let out = temp.path().join("out");

    let start = std::time::Instant::now();
    let result = exarch_core::extract_archive(&path, &out, &config);
    let elapsed = start.elapsed();

    assert_is_budget_violation(&result);
    assert!(
        elapsed < SPARSE_BOMB_WALL_CLOCK_BOUND,
        "extract must not scale with the number of skipped sub-cap synthetic-heavy entries, \
         took {elapsed:?}"
    );
}

#[test]
fn list_and_verify_bound_total_drain_across_many_sparse_entries_even_with_relaxed_quota() {
    // The cumulative budget lives in `next_entry()`, used by extract, list,
    // and (via list) verify alike — not gated on extension filtering at
    // all — so it also covers a caller that legitimately relaxes quota
    // limits (e.g. to list/verify a huge archive) and would otherwise let
    // QuotaTracker wave every sparse-bomb entry through instead of catching
    // it early.
    //
    // This config relaxation is deliberately broader than what
    // `listing_config_for_verify` (inspection/verify.rs) applies on its
    // own — that helper only relaxes `max_file_size` to `u64::MAX`, not
    // `max_total_size`/`max_file_count`, so `verify_archive` under its
    // *default* config would already reject a huge declared `realsize` via
    // ordinary total-size quota before ever reaching the cumulative
    // synthetic path. The manual relaxation below represents a caller who
    // has legitimately raised every quota limit (e.g. to inspect a
    // multi-terabyte archive), which is exactly the case
    // `listing_config_for_verify` does *not* cover and where this budget is
    // the only remaining defense.
    let bomb = many_sparse_bombs_tar(200, 1u64 << 40);
    let config = SecurityConfig::default()
        .with_max_file_size(u64::MAX)
        .with_max_total_size(u64::MAX)
        .with_max_file_count(usize::MAX);

    let temp = TempDir::new().unwrap();
    let path = write_tar_file(&temp, "many_sparse_relaxed.tar", &bomb);

    let start = std::time::Instant::now();
    let result = exarch_core::list_archive(&path, &config);
    let elapsed = start.elapsed();
    assert_is_budget_violation(&result);
    assert!(
        elapsed < SPARSE_BOMB_WALL_CLOCK_BOUND,
        "list must not scale with the number of unbounded-quota sparse entries, took {elapsed:?}"
    );

    let start = std::time::Instant::now();
    let result = exarch_core::verify_archive(&path, &config);
    let elapsed = start.elapsed();
    assert_is_budget_violation(&result);
    assert!(
        elapsed < SPARSE_BOMB_WALL_CLOCK_BOUND,
        "verify must not scale with the number of unbounded-quota sparse entries, took {elapsed:?}"
    );
}

#[test]
fn list_and_verify_accept_many_sparse_entries_comfortably_under_the_cumulative_cap() {
    // Regression for critic finding N1: every other cumulative-budget test
    // either derives its entry count from CUMULATIVE_SYNTHETIC_CAP_BYTES or
    // deliberately exceeds it, so none would notice if the cap were
    // silently retuned back down (e.g. to the original, too-tight 64 MiB) —
    // that would reintroduce the exact S1 false-positive undetected. This
    // pins the acceptance side: 50 entries, each individually saturating
    // SYNTHETIC_PAD_CAP_BYTES (8 MiB), sum to ~400 MiB — comfortably under
    // the 1 GiB cap, and already far more large-hole sparse entries than a
    // real archive would plausibly contain — and must still list and verify
    // cleanly, not trip the cumulative budget.
    const ENTRY_COUNT: usize = 50;
    let bomb = many_sparse_bombs_tar(ENTRY_COUNT, 1u64 << 40);
    let config = SecurityConfig::default()
        .with_max_file_size(u64::MAX)
        .with_max_total_size(u64::MAX)
        .with_max_file_count(usize::MAX);

    let temp = TempDir::new().unwrap();
    let path = write_tar_file(&temp, "many_sparse_under_cap.tar", &bomb);

    let manifest = exarch_core::list_archive(&path, &config)
        .expect("an archive comfortably under the cumulative synthetic cap must list cleanly");
    assert_eq!(manifest.total_entries, ENTRY_COUNT);

    let report = exarch_core::verify_archive(&path, &config)
        .expect("an archive comfortably under the cumulative synthetic cap must verify cleanly");
    assert_eq!(report.status, exarch_core::VerificationStatus::Pass);
}

#[test]
fn budget_violation_is_not_confused_with_other_archive_errors() {
    // Sanity check on the assertion helper itself: an ordinary corrupt
    // archive (not a budget trip) must not be misclassified.
    let garbage = vec![1u8, 2, 3, 4, 5];
    let temp = TempDir::new().unwrap();
    let mut archive = TarArchive::new(Cursor::new(garbage));
    let result = archive.extract(
        temp.path(),
        &SecurityConfig::default().validate().unwrap(),
        &ExtractionOptions::default(),
        &mut NoopProgress,
    );
    assert!(
        !matches!(result, Err(ArchiveError::SecurityViolation { .. })),
        "a truncated/corrupt archive must not surface as a budget SecurityViolation, got: {result:?}"
    );
}
