//! Allocation-bound regression test for issue #414 (TAR metadata
//! decompression bomb) and its historical S1/S2/S3 shadow-parser bypasses.
//!
//! This is the test that actually measures the risk the redesigned
//! `formats::tar_metadata_limit` read-budget mechanism closes: not just "is
//! the right error returned" (see `tests/security/tar_metadata_bomb.rs`) but
//! "does peak heap usage stay bounded regardless of what the archive
//! contains". A `dhat` counting allocator records real peak live bytes across
//! the three historical `PoC` shapes and a batch of randomly generated
//! adversarial archives (random typeflags, random declared sizes up to 4 GiB,
//! valid/invalid/absent magic, random PAX bodies with and without `size=`),
//! each backed by a small repeating-byte reader so any declared size is
//! trivially "satisfiable" without actually allocating gigabytes on disk or
//! in memory ahead of time.
//!
//! Must be its own top-level integration test binary, not nested under
//! `tests/security/`: `#[global_allocator]` applies process-wide (it would
//! change allocator behavior for every other test sharing a binary with it),
//! and `dhat` allows only one `Profiler` alive at a time, so every case here
//! runs sequentially (`Profiler` created and dropped per case) inside a
//! single `#[test]` function rather than relying on nextest's usual
//! process-per-test isolation.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use exarch_core::ExtractionOptions;
use exarch_core::NoopProgress;
use exarch_core::SecurityConfig;
use exarch_core::formats::ArchiveFormat;
use exarch_core::formats::TarArchive;
use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;

const BLOCK: usize = 512;

/// A ceiling generous relative to the small budgets used below (a few KB to
/// a few hundred KB): if peak usage ever approaches this, something is
/// scaling with a declared/attacker-controlled size again, not with the
/// configured budget.
const PEAK_BYTES_CEILING: usize = 32 * 1024 * 1024;

fn header(name: &[u8], size: u64, typeflag: u8, magic: Magic) -> Vec<u8> {
    let mut h = vec![0u8; BLOCK];
    let name_len = name.len().min(100);
    h[..name_len].copy_from_slice(&name[..name_len]);
    h[100..108].copy_from_slice(b"0000644\0");
    h[108..116].copy_from_slice(b"0000000\0");
    h[116..124].copy_from_slice(b"0000000\0");
    h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    h[136..148].copy_from_slice(b"00000000000\0");
    h[156] = typeflag;
    match magic {
        Magic::Gnu => {
            h[257..263].copy_from_slice(b"ustar ");
            h[263..265].copy_from_slice(b" \0");
        }
        Magic::Ustar => {
            h[257..263].copy_from_slice(b"ustar\0");
            h[263..265].copy_from_slice(b"00");
        }
        Magic::Invalid => {} // left zeroed
    }
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

fn pax_record(key: &[u8], value: &[u8]) -> Vec<u8> {
    let base = key.len() + value.len() + 3;
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

#[derive(Clone, Copy)]
enum Magic {
    Gnu,
    Ustar,
    Invalid,
}

/// Encodes `n` as a classic octal numeric field of `width` bytes (including
/// the trailing NUL), or `None` if it does not fit in `width - 1` digits.
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

/// Encodes `n` as a GNU base-256 numeric field (big-endian, high bit of the
/// first byte set) — how a GNU sparse entry's `realsize` reaches values
/// beyond octal's digit capacity, up to `u64::MAX`.
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

/// Builds a raw GNU old-format sparse header (typeflag `'S'`) with real,
/// non-empty sparse fields: an inline `(offset, numbytes)` block at byte
/// offset 386 and a `realsize` at offset 483 that may vastly exceed
/// `size_field` (the physical/allocated size). Without genuine sparse
/// fields, `tar`'s `GnuSparseHeader::is_empty()` (`offset[0] == 0`) treats
/// the entry as non-sparse and never materializes the zero-padding this
/// module exists to bound — this is what the plain `header()` builder above
/// produces for typeflag `'S'`, which is why the random generator below
/// previously never exercised the padding path at all.
fn gnu_sparse_header(name: &[u8], size_field: u64, realsize: u64, gap: u64) -> Vec<u8> {
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
    // One inline sparse block: `gap` bytes of synthesized zeros followed by
    // `size_field` bytes of real backing data.
    h[386..398].copy_from_slice(&num_field(gap, 12));
    h[398..410].copy_from_slice(&num_field(size_field, 12));
    h[482] = 0; // isextended: no further sparse-header blocks follow
    h[483..495].copy_from_slice(&num_field(realsize, 12));
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

/// Runs `bytes` through `TarArchive::extract` inside a fresh, scoped `dhat`
/// testing profiler and returns the peak live heap bytes observed. The
/// profiler is created and dropped entirely within this call so callers can
/// invoke it repeatedly (dhat permits only one profiler alive at a time, not
/// one per process).
fn measure_extract_peak_bytes(bytes: &[u8], budget: u64) -> usize {
    let profiler = dhat::Profiler::builder().testing().build();
    {
        let temp = tempfile::tempdir().unwrap();
        let config = SecurityConfig::default().with_max_tar_metadata_bytes(budget);
        let mut archive = TarArchive::new(Cursor::new(bytes));
        // Outcome (Ok or Err) is irrelevant here — only peak memory matters.
        let _ = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut NoopProgress,
        );
    }
    let stats = dhat::HeapStats::get();
    drop(profiler);
    stats.max_bytes
}

/// Writes `bytes` to a temp file and runs `list_archive` inside a fresh
/// scoped `dhat` profiler, returning peak live heap bytes.
///
/// `list`/`verify` open `tar::Archive` directly (`inspection::list`), a
/// separate code path from `TarArchive::extract` above — the C1 finding was
/// specifically that this path's drain bound could be silently unbounded
/// while `extract`'s stayed bounded, so it needs its own measurement, not an
/// assumption that `extract`'s result generalizes.
fn measure_list_peak_bytes(bytes: &[u8], budget: u64) -> usize {
    let profiler = dhat::Profiler::builder().testing().build();
    {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("archive.tar");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
        let config = SecurityConfig::default().with_max_tar_metadata_bytes(budget);
        let _ = exarch_core::list_archive(&path, &config);
    }
    let stats = dhat::HeapStats::get();
    drop(profiler);
    stats.max_bytes
}

/// As [`measure_list_peak_bytes`], but through `verify_archive` — the path
/// C1 actually broke, since its internal pre-listing pass
/// (`listing_config_for_verify`) relaxes `max_file_size` to `u64::MAX`.
fn measure_verify_peak_bytes(bytes: &[u8], budget: u64) -> usize {
    let profiler = dhat::Profiler::builder().testing().build();
    {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("archive.tar");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
        let config = SecurityConfig::default().with_max_tar_metadata_bytes(budget);
        let _ = exarch_core::verify_archive(&path, &config);
    }
    let stats = dhat::HeapStats::get();
    drop(profiler);
    stats.max_bytes
}

/// S1 historical shape: PAX `size=0` override, decoy, oversized GNU longname.
fn s1_shape(bomb_real_bytes: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let pax_body = b"9 size=0\n".to_vec();
    out.extend_from_slice(&header(
        b"PaxHeaders/decoy",
        pax_body.len() as u64,
        b'x',
        Magic::Ustar,
    ));
    pad_to_block(&mut out, &pax_body);
    out.extend_from_slice(&header(b"decoy.txt", 4096, b'0', Magic::Gnu));
    out.extend_from_slice(&header(
        b"././@LongLink",
        bomb_real_bytes as u64,
        b'L',
        Magic::Gnu,
    ));
    pad_to_block(&mut out, &vec![b'A'; bomb_real_bytes]);
    out
}

/// S2 historical shape: invalid-magic PAX override, decoy, oversized bomb.
fn s2_shape(bomb_real_bytes: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let pax_body = pax_record(b"size", b"0");
    out.extend_from_slice(&header(
        b"PaxHeaders/decoy",
        pax_body.len() as u64,
        b'x',
        Magic::Invalid,
    ));
    pad_to_block(&mut out, &pax_body);
    out.extend_from_slice(&header(b"decoy.txt", 512, b'0', Magic::Gnu));
    pad_to_block(&mut out, &vec![b'D'; 512]);
    out.extend_from_slice(&header(
        b"././@LongLink",
        bomb_real_bytes as u64,
        b'L',
        Magic::Gnu,
    ));
    pad_to_block(&mut out, &vec![b'A'; bomb_real_bytes]);
    out
}

/// S3 historical shape: PAX override, PAX global header, decoy, oversized bomb.
fn s3_shape(bomb_real_bytes: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let pax_body = pax_record(b"size", b"0");
    out.extend_from_slice(&header(
        b"PaxHeaders/decoy",
        pax_body.len() as u64,
        b'x',
        Magic::Ustar,
    ));
    pad_to_block(&mut out, &pax_body);
    let global_body = pax_record(b"comment", b"hi");
    out.extend_from_slice(&header(
        b"././@PaxHeader",
        global_body.len() as u64,
        b'g',
        Magic::Gnu,
    ));
    pad_to_block(&mut out, &global_body);
    out.extend_from_slice(&header(b"decoy.txt", 4096, b'0', Magic::Gnu));
    pad_to_block(&mut out, &vec![b'D'; 4096]);
    out.extend_from_slice(&header(
        b"././@LongLink",
        bomb_real_bytes as u64,
        b'L',
        Magic::Gnu,
    ));
    pad_to_block(&mut out, &vec![b'A'; bomb_real_bytes]);
    out
}

/// One randomly generated "step": a header of a random typeflag, magic
/// validity, and declared size, backed by a real (repeating-byte, so no
/// upfront allocation of the full declared size is needed to build the
/// fixture) payload whose *real* length may itself disagree with the
/// declared size — this is deliberately allowed to construct malformed
/// archives, since the property under test is "peak memory stays bounded no
/// matter what", not "the archive is well-formed".
#[derive(Debug, Clone)]
struct RandomStep {
    typeflag: u8,
    magic: u8, // 0 = gnu, 1 = ustar, 2 = invalid
    declared_size: u64,
    real_bytes: usize,
    /// Only meaningful when `typeflag == b'S'`: the GNU sparse `realsize` to
    /// declare, independent of (and possibly vastly exceeding) the physical
    /// backing bytes — the C1 attack shape. Drawn from the full `u64` range
    /// so the corpus also covers values only reachable via base-256 encoding.
    sparse_realsize: u64,
}

fn random_step_strategy() -> impl Strategy<Value = RandomStep> {
    (
        prop::sample::select(vec![b'L', b'K', b'x', b'g', b'0', b'S', b'5']),
        0u8..3,
        0u64..(4u64 * 1024 * 1024 * 1024),
        0usize..8192,
        any::<u64>(),
    )
        .prop_map(
            |(typeflag, magic, declared_size, real_bytes, sparse_realsize)| RandomStep {
                typeflag,
                magic,
                declared_size,
                real_bytes,
                sparse_realsize,
            },
        )
}

fn magic_from_u8(m: u8) -> Magic {
    match m {
        0 => Magic::Gnu,
        1 => Magic::Ustar,
        _ => Magic::Invalid,
    }
}

/// Builds an archive from a sequence of `RandomStep`s: each step is a header
/// (whatever typeflag/magic/declared size the generator picked) followed by
/// `real_bytes` of real, repeating-byte content — never the declared size
/// itself, so building the fixture stays cheap even when `declared_size`
/// is huge.
fn build_from_steps(steps: &[RandomStep]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, step) in steps.iter().enumerate() {
        let name = format!("entry-{i}");
        if step.typeflag == b'S' {
            // Real GNU sparse fields, not just typeflag `'S'` with an empty
            // sparse header (which `GnuSparseHeader::is_empty()` treats as
            // non-sparse, skipping the zero-padding path entirely — the gap
            // that let the corpus previously miss C1 even though it included
            // typeflag `'S'` steps).
            let size_field = step.real_bytes as u64;
            let gap = step.sparse_realsize.saturating_sub(size_field);
            out.extend_from_slice(&gnu_sparse_header(
                name.as_bytes(),
                size_field,
                step.sparse_realsize,
                gap,
            ));
        } else {
            out.extend_from_slice(&header(
                name.as_bytes(),
                step.declared_size,
                step.typeflag,
                magic_from_u8(step.magic),
            ));
        }
        pad_to_block(&mut out, &vec![b'A'; step.real_bytes]);
    }
    out
}

/// Everything runs inside this single `#[test]` function, per-case profilers
/// created and dropped sequentially. `dhat` allows only one profiler alive at
/// a time; under `cargo test`'s default in-process, multi-threaded harness
/// (as opposed to nextest's process-per-test isolation, which this crate
/// otherwise relies on), two `#[test]` functions each creating a profiler can
/// run concurrently and panic on that constraint — merging into one function
/// makes the ordering (and therefore the profiler lifetime) explicit instead
/// of dependent on which test harness happens to run this binary.
#[test]
fn tar_metadata_bomb_allocations_stay_bounded() {
    // Sanity check the measurement harness itself first: a false "pass"
    // below must not be mistaken for "the mechanism truly bounds memory"
    // when it might just be "the harness never measures anything real".
    // Deliberately allocate well past the ceiling and confirm it is caught.
    {
        let profiler = dhat::Profiler::builder().testing().build();
        {
            let mut sink = vec![0u8; PEAK_BYTES_CEILING + 1024 * 1024];
            let mut reader = Cursor::new(&mut sink);
            let mut discard = [0u8; 1];
            let _ = reader.read(&mut discard);
        }
        let stats = dhat::HeapStats::get();
        drop(profiler);
        assert!(
            stats.max_bytes > PEAK_BYTES_CEILING,
            "harness failed to detect a deliberate over-ceiling allocation: {}",
            stats.max_bytes
        );
    }

    // Historical shapes at a scale that would have measured in the hundreds
    // of MB to low GB range on the pre-redesign shadow parser (the original
    // PoCs reached 3.3 GB / 608 MB on a few hundred KB of archive bytes).
    // Measured through all three entry points: C1 (issue #414 follow-up)
    // showed `extract` staying bounded is not evidence `list`/`verify` do,
    // since they open `tar::Archive` via a separate code path
    // (`inspection::list`) with its own drain-bound wiring.
    for (label, bytes) in [
        ("S1", s1_shape(64 * 1024)),
        ("S2", s2_shape(64 * 1024)),
        ("S3", s3_shape(64 * 1024)),
    ] {
        let peak = measure_extract_peak_bytes(&bytes, 4096);
        assert!(
            peak < PEAK_BYTES_CEILING,
            "{label} shape (extract): peak {peak} bytes exceeded the {PEAK_BYTES_CEILING}-byte \
             ceiling"
        );
        let peak = measure_list_peak_bytes(&bytes, 4096);
        assert!(
            peak < PEAK_BYTES_CEILING,
            "{label} shape (list): peak {peak} bytes exceeded the {PEAK_BYTES_CEILING}-byte \
             ceiling"
        );
        let peak = measure_verify_peak_bytes(&bytes, 4096);
        assert!(
            peak < PEAK_BYTES_CEILING,
            "{label} shape (verify): peak {peak} bytes exceeded the {PEAK_BYTES_CEILING}-byte \
             ceiling"
        );
    }

    // C1 regression: a real GNU sparse entry declaring a `realsize` far
    // beyond its one-block physical backing, run through all three entry
    // points. `verify` is the path C1 actually broke (its internal
    // `listing_config_for_verify` relaxes `max_file_size` to `u64::MAX`,
    // which used to flow straight into the drop-time drain bound) — heap
    // stays flat here regardless since the drain writes to `io::sink`, so
    // this is a complementary check to the wall-clock assertions in
    // `tests/security/tar_metadata_bomb.rs`, not a replacement for them.
    {
        let realsize = 1u64 << 62;
        let bytes = gnu_sparse_header(
            b"sparsebomb.bin",
            BLOCK as u64,
            realsize,
            realsize - BLOCK as u64,
        );
        let mut archive_bytes = bytes;
        archive_bytes.extend(std::iter::repeat_n(0u8, BLOCK)); // the one backing block
        archive_bytes.extend(std::iter::repeat_n(0u8, BLOCK * 2)); // end-of-archive trailer

        for (label, peak) in [
            ("extract", measure_extract_peak_bytes(&archive_bytes, 4096)),
            ("list", measure_list_peak_bytes(&archive_bytes, 4096)),
            ("verify", measure_verify_peak_bytes(&archive_bytes, 4096)),
        ] {
            assert!(
                peak < PEAK_BYTES_CEILING,
                "GNU sparse realsize bomb ({label}): peak {peak} bytes exceeded the \
                 {PEAK_BYTES_CEILING}-byte ceiling"
            );
        }
    }

    // Randomly generated adversarial archives: random typeflags, magic
    // validity, and declared sizes up to 4 GiB (including real GNU sparse
    // fields for typeflag 'S', with `realsize` drawn from the full `u64`
    // range), each backed by a small real (repeating-byte) payload. No case
    // should come anywhere near the ceiling regardless of what combination
    // of fields it picks or which entry point processes it, proving the
    // budget mechanism's bound does not depend on any parsed header field.
    // `TestRunner` is driven manually (not via the `proptest!` macro) so
    // each generated case can be measured under its own scoped `dhat`
    // profiler; `Config::cases` (the macro's own case count) does not apply
    // here — the loop below controls the case count directly.
    let mut runner = TestRunner::default();
    let strategy = prop::collection::vec(random_step_strategy(), 1..12);

    for _ in 0..100 {
        let tree = strategy.new_tree(&mut runner).unwrap();
        let steps = tree.current();
        let bytes = build_from_steps(&steps);

        let peak = measure_extract_peak_bytes(&bytes, 8192);
        assert!(
            peak < PEAK_BYTES_CEILING,
            "random archive (steps: {steps:?}, extract): peak {peak} bytes exceeded the \
             {PEAK_BYTES_CEILING}-byte ceiling"
        );
        let peak = measure_list_peak_bytes(&bytes, 8192);
        assert!(
            peak < PEAK_BYTES_CEILING,
            "random archive (steps: {steps:?}, list): peak {peak} bytes exceeded the \
             {PEAK_BYTES_CEILING}-byte ceiling"
        );
        let peak = measure_verify_peak_bytes(&bytes, 8192);
        assert!(
            peak < PEAK_BYTES_CEILING,
            "random archive (steps: {steps:?}, verify): peak {peak} bytes exceeded the \
             {PEAK_BYTES_CEILING}-byte ceiling"
        );
    }
}
