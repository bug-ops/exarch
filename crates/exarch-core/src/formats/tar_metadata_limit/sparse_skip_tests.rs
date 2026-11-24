//! Unread old GNU sparse entries are passed by the `tar` crate through the
//! exemption (`SkipPlan::TarSkip`), never drained: no hole is generated, the
//! exempt bytes bypass the metadata window, and they are still charged to the
//! skipped-entry meter.

use std::assert_matches;
use std::io::Cursor;
use std::io::Write as _;

use super::*;
use crate::ArchiveError;
use crate::formats::source_fault::SourceRead;
use crate::formats::source_fault::SourceTap;

const BLOCK: usize = 512;
const HOLE: u64 = 1 << 32;
const EXPAND: TarSparsePolicy = TarSparsePolicy::Expand;

fn octal(value: u64) -> [u8; 12] {
    let mut field = [0u8; 12];
    field[..11].copy_from_slice(format!("{value:011o}").as_bytes());
    field
}

/// An old GNU sparse member with one region of `archived` at offset 0 and a
/// trailing hole up to `real_size`.
fn sparse_member(name: &str, archived: &[u8], real_size: u64) -> Vec<u8> {
    let mut header = [0u8; BLOCK];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(&octal(archived.len() as u64));
    header[136..148].copy_from_slice(&octal(0));
    header[156] = b'S';
    header[257..265].copy_from_slice(b"ustar  \0");
    header[386..398].copy_from_slice(&octal(0));
    header[398..410].copy_from_slice(&octal(archived.len() as u64));
    header[410..422].copy_from_slice(&octal(real_size));
    header[422..434].copy_from_slice(&octal(0));
    header[483..495].copy_from_slice(&octal(real_size));
    header[148..156].fill(b' ');
    let sum: u32 = header.iter().map(|&b| u32::from(b)).sum();
    header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    let mut bytes = header.to_vec();
    bytes.extend_from_slice(archived);
    bytes.resize(bytes.len().next_multiple_of(BLOCK), 0);
    bytes
}

/// A one-entry archive, end-of-archive blocks included.
fn regular_archive(name: &str, content: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append_data(&mut header, name, content).unwrap();
    builder.into_inner().unwrap()
}

fn sparse_then_regular(archived: &[u8]) -> Vec<u8> {
    [
        sparse_member("hole.bin", archived, HOLE),
        regular_archive("after.txt", b"hello"),
    ]
    .concat()
}

/// Bytes gzip cannot shrink (xorshift output).
fn incompressible(len: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn tight_limits() -> SkipLimits {
    SkipLimits {
        per_file: crate::non_zero!(1024).into(),
        total: crate::non_zero!(1024).into(),
        ratio: 10.0,
    }
}

fn end_of(plan: SkipPlan) -> u64 {
    let SkipPlan::TarSkip { end } = plan else {
        panic!("a sparse entry plans a tar skip, got {plan:?}");
    };
    end
}

#[test]
fn an_unread_sparse_entry_is_skipped_without_entering_the_window() {
    // The archived region is far larger than the metadata allowance.
    let data = sparse_then_regular(&vec![7u8; 100_000]);
    let (reader, budget) = budgeted_reader(Cursor::new(data), 2048);
    let handle = budget.clone();
    let mut archive = tar::Archive::new(reader);
    let mut entries = budgeted_tar_entries(&mut archive, budget).unwrap();

    let sparse = entries
        .next_entry()
        .unwrap()
        .unwrap()
        .check(2048, EXPAND)
        .unwrap();
    let end = end_of(sparse.skip_plan());
    assert_eq!(end, (1 + 100_000_usize.div_ceil(BLOCK)) as u64 * 512);
    drop(sparse);

    let next = entries.next_entry().unwrap().unwrap();
    assert_eq!(next.window_start, end);
    let mut next = next.check(2048, EXPAND).unwrap();
    let mut content = Vec::new();
    next.read_to_end(&mut content).unwrap();
    assert_eq!(content, b"hello");
    drop(next);

    assert_eq!(handle.exempt(), 0);
    assert_eq!(
        handle.0.cumulative_synthetic.load(Ordering::Relaxed),
        0,
        "no hole was generated"
    );
    assert!(entries.next_entry().is_none());
}

#[test]
fn an_exemption_smaller_than_tars_skip_chunk_does_not_swallow_the_next_header() {
    let data = sparse_then_regular(&[7u8; 20]);
    let (reader, budget) = budgeted_reader(Cursor::new(data), 2048);
    let mut archive = tar::Archive::new(reader);
    let mut entries = budgeted_tar_entries(&mut archive, budget).unwrap();

    drop(
        entries
            .next_entry()
            .unwrap()
            .unwrap()
            .check(2048, EXPAND)
            .unwrap(),
    );
    let next = entries.next_entry().unwrap().unwrap().check(2048, EXPAND);
    assert_eq!(next.unwrap().path().unwrap().to_str(), Some("after.txt"));
}

#[test]
fn a_tampered_end_is_a_window_mismatch() {
    let data = sparse_then_regular(&[7u8; 20]);
    let forged_end = |delta: i64| {
        let (reader, budget) = budgeted_reader(Cursor::new(data.clone()), 4096);
        let mut archive = tar::Archive::new(reader);
        let mut entries = budgeted_tar_entries(&mut archive, budget).unwrap();
        let mut sparse = entries
            .next_entry()
            .unwrap()
            .unwrap()
            .check(4096, EXPAND)
            .unwrap();
        let end = end_of(sparse.skip_plan());
        sparse.0.skip = SkipPlan::TarSkip {
            end: end.checked_add_signed(delta).unwrap(),
        };
        drop(sparse);
        entries.next_entry().map(|result| result.map(drop))
    };

    // An exemption longer than what tar skips is eaten by the next header read
    // and leaves no window for it...
    let next_header_swallowed = forged_end(512);
    assert_matches!(next_header_swallowed, Some(Ok(())));
    // ...and one longer still is left over after the entry is found.
    assert_matches!(
        forged_end(1536),
        Some(Err(ArchiveError::TarAmbiguity(
            TarAmbiguity::WindowMismatch
        )))
    );
}

#[test]
fn an_exemption_that_leaves_no_window_for_the_next_header_is_refused_by_check() {
    let data = sparse_then_regular(&[7u8; 20]);
    for delta in [512i64, -512] {
        let (reader, budget) = budgeted_reader(Cursor::new(data.clone()), 4096);
        let mut archive = tar::Archive::new(reader);
        let mut entries = budgeted_tar_entries(&mut archive, budget).unwrap();
        let mut sparse = entries
            .next_entry()
            .unwrap()
            .unwrap()
            .check(4096, EXPAND)
            .unwrap();
        let end = end_of(sparse.skip_plan());
        sparse.0.skip = SkipPlan::TarSkip {
            end: end.checked_add_signed(delta).unwrap(),
        };
        drop(sparse);

        let next = entries.next_entry().unwrap().unwrap();
        let refused = next.check(4096, EXPAND).err().unwrap();
        assert_matches!(
            refused,
            ArchiveError::TarAmbiguity(_),
            "{delta}: {refused:?}"
        );
    }
}

#[test]
fn an_error_from_the_skip_keeps_its_classification_over_a_leftover_exemption() {
    let data = sparse_member("hole.bin", &incompressible(4096), HOLE);
    let truncated = data.get(..BLOCK + 1000).unwrap().to_vec();
    let (reader, budget) = budgeted_reader(Cursor::new(truncated), 4096);
    let mut archive = tar::Archive::new(reader);
    let mut entries = budgeted_tar_entries(&mut archive, budget).unwrap();

    drop(
        entries
            .next_entry()
            .unwrap()
            .unwrap()
            .check(4096, EXPAND)
            .unwrap(),
    );
    let refused = entries.next_entry().unwrap().err().unwrap();
    assert_matches!(refused, ArchiveError::InvalidArchive(_), "{refused:?}");
    assert!(
        refused.to_string().contains("sparse entry 'hole.bin'"),
        "the failure names the sparse entry: {refused}"
    );
}

type GzReader = BudgetedReader<flate2::read::GzDecoder<SourceRead<Cursor<Vec<u8>>>>>;

fn gzip_entries(tar_bytes: &[u8]) -> (GzReader, TarReadBudget) {
    let tap = SourceTap::default();
    let decoder =
        flate2::read::GzDecoder::new(SourceRead::new(Cursor::new(gzip(tar_bytes)), tap.clone()));
    budgeted_reader_with(decoder, crate::non_zero!(4096), TapSource::Tapped(tap))
}

#[test]
fn a_metered_sparse_entry_is_marked_and_not_drained() {
    let data = sparse_then_regular(&incompressible(4096));
    let (reader, budget) = gzip_entries(&data);
    let handle = budget.clone();
    let mut archive = tar::Archive::new(reader);
    let mut entries = budgeted_tar_entries(&mut archive, budget).unwrap();

    let mut sparse = entries
        .next_entry()
        .unwrap()
        .unwrap()
        .check(4096, EXPAND)
        .unwrap();
    sparse.drain_skipped(&tight_limits()).unwrap();
    assert!(handle.0.metering.load(Ordering::Relaxed), "marked metered");
    drop(sparse);
    assert_eq!(handle.0.cumulative_synthetic.load(Ordering::Relaxed), 0);
    assert!(handle.exempt() > 0);

    let next = entries.next_entry().unwrap().unwrap().check(4096, EXPAND);
    assert_eq!(next.unwrap().path().unwrap().to_str(), Some("after.txt"));
    assert_eq!(handle.exempt(), 0);
}

#[test]
fn a_metered_sparse_entry_that_out_decodes_its_input_is_a_skipped_entries_bomb() {
    let data = sparse_then_regular(&vec![0u8; 4 << 20]);
    let (reader, budget) = gzip_entries(&data);
    let mut archive = tar::Archive::new(reader);
    let mut entries = budgeted_tar_entries(&mut archive, budget).unwrap();

    let mut sparse = entries
        .next_entry()
        .unwrap()
        .unwrap()
        .check(4096, EXPAND)
        .unwrap();
    assert_eq!(sparse.mark_skipped(&tight_limits()), SkipAdmission::Metered);
    drop(sparse);

    let refused = entries.next_entry().unwrap().err().unwrap();
    assert_matches!(
        refused,
        ArchiveError::ZipBomb(d) if d.scope() == ZipBombScope::SkippedEntries
    );
    assert!(entries.next_entry().is_none(), "the error latches");
}

#[test]
fn an_admitted_sparse_entry_is_not_metered() {
    let data = sparse_then_regular(&vec![0u8; 4 << 20]);
    let (reader, budget) = gzip_entries(&data);
    let mut archive = tar::Archive::new(reader);
    let mut entries = budgeted_tar_entries(&mut archive, budget).unwrap();

    let sparse = entries
        .next_entry()
        .unwrap()
        .unwrap()
        .check(4096, EXPAND)
        .unwrap();
    drop(sparse);

    let next = entries.next_entry().unwrap().unwrap().check(4096, EXPAND);
    assert_eq!(next.unwrap().path().unwrap().to_str(), Some("after.txt"));
}

#[test]
fn a_sparse_entry_is_refused_under_the_refuse_policy() {
    let data = sparse_then_regular(&[7u8; 20]);
    let (reader, budget) = budgeted_reader(Cursor::new(data), 4096);
    let mut archive = tar::Archive::new(reader);
    let mut entries = budgeted_tar_entries(&mut archive, budget).unwrap();

    let refused = entries
        .next_entry()
        .unwrap()
        .unwrap()
        .check(4096, TarSparsePolicy::Refuse)
        .err()
        .unwrap();
    assert_matches!(
        refused,
        ArchiveError::TarAmbiguity(TarAmbiguity::SparseEntry)
    );
}
