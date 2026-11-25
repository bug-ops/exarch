//! Grammar for the bytes `tar` consumed between two entries.
//!
//! The `tar` crate merges `x`, `L` and `K` headers into the entry that follows
//! them and decides on its own where each header and body ends. Readers
//! disagree on how to read a checksum, a size or a PAX length that is not
//! plain, so the raw bytes are verified here against a closed grammar and the
//! result is cross-checked with the positions the `tar` crate reports. The
//! `tar` crate stays the only authority on entry boundaries: this check can
//! only add refusals.
//!
//! The window is a run of 512-byte blocks starting at the next block boundary:
//! zero or more extension headers (`x`, `L`, `K`, each at most once, with a
//! ustar or GNU magic), each followed by its body padded to a block, then the
//! header of the yielded entry exactly at the end of the window.

use std::ops::Range;

use super::BLOCK;
use super::CHECKSUM_FIELD;
use super::ParsedPax;
use super::PrecedingEntry;
use super::SIZE_FIELD;
use super::check_header_block;
use super::is_plain_octal;
use super::numeric_value;
use super::octal_value;
use super::sparse;
use crate::Result;
use crate::TarAmbiguity;
use crate::TarExtensionKind;
use crate::TarHeaderField;
use crate::TarSparsePolicy;
use crate::formats::tar_metadata_limit::MetadataWindow;

const TYPEFLAG_OFFSET: usize = 156;
const MAGIC_FIELD: Range<usize> = 257..265;
const USTAR_MAGIC: &[u8; 8] = b"ustar\x0000";
const GNU_MAGIC: &[u8; 8] = b"ustar  \0";
const CHECKSUM_SPACES: u64 = 8 * b' ' as u64;

fn extension_kind_of(block: &[u8; BLOCK]) -> Option<TarExtensionKind> {
    let magic = &block[MAGIC_FIELD];
    if magic != USTAR_MAGIC && magic != GNU_MAGIC {
        return None;
    }
    match block[TYPEFLAG_OFFSET] {
        b'x' => Some(TarExtensionKind::Pax),
        b'L' => Some(TarExtensionKind::LongName),
        b'K' => Some(TarExtensionKind::LongLink),
        _ => None,
    }
}

fn block_at(bytes: &[u8], offset: usize) -> Option<&[u8; BLOCK]> {
    bytes
        .get(offset..offset.checked_add(BLOCK)?)?
        .try_into()
        .ok()
}

fn declared_size(block: &[u8; BLOCK]) -> Result<u64> {
    numeric_value(&block[SIZE_FIELD]).ok_or_else(|| {
        TarAmbiguity::NonCanonicalNumber {
            field: TarHeaderField::Size,
        }
        .into()
    })
}

fn verify_checksum(block: &[u8; BLOCK]) -> Result<()> {
    let field = &block[CHECKSUM_FIELD];
    let declared = is_plain_octal(field)
        .then(|| octal_value(field))
        .flatten()
        .ok_or(TarAmbiguity::NonCanonicalNumber {
            field: TarHeaderField::Checksum,
        })?;
    let byte_sum = |bytes: &[u8]| bytes.iter().map(|&b| u32::from(b)).sum::<u32>();
    let (Some(head), Some(tail)) = (
        block.get(..CHECKSUM_FIELD.start),
        block.get(CHECKSUM_FIELD.end..),
    ) else {
        return Err(TarAmbiguity::ChecksumMismatch.into());
    };
    let actual = u64::from(byte_sum(head))
        .saturating_add(u64::from(byte_sum(tail)))
        .saturating_add(CHECKSUM_SPACES);
    (declared == actual).ok_or(TarAmbiguity::ChecksumMismatch.into())
}

/// Offset of the first block boundary at or after the window start, which is
/// where the `tar` crate looks for the next header.
fn first_header_offset(window_start: u64) -> Result<usize> {
    let block = BLOCK as u64;
    window_start
        .checked_next_multiple_of(block)
        .and_then(|boundary| boundary.checked_sub(window_start))
        .and_then(|padding| usize::try_from(padding).ok())
        .ok_or_else(|| TarAmbiguity::WindowMismatch.into())
}

/// What a window walk found, next to its verdict.
///
/// `pax` and `extensions` hold what was read before the walk stopped, so the
/// caller can still parse a local PAX body when a later check fails and decide
/// which refusal wins.
pub(super) struct WindowWalk<'w> {
    /// The framed local PAX body, once it passed the framing check.
    pub(super) pax: Option<ParsedPax<'w>>,
    /// The local extension headers walked, in window order.
    pub(super) extensions: Vec<TarExtensionKind>,
    /// Whether every block in the window passed.
    pub(super) outcome: Result<()>,
    /// How many sparse extension blocks follow the final header in the window;
    /// zero unless the entry is a sparse one that `Expand` accepts.
    pub(super) chain_blocks: usize,
}

/// Verifies the bytes `tar` read to reach an entry.
///
/// After a global PAX header the padding up to the first block boundary must
/// be zero, as must the padding after every extension header body, and a GNU
/// long name or link body must be one string ending in a single NUL.
///
/// `header_pos` and `file_pos` are the offsets the `tar` crate reports for the
/// yielded entry's header and data. Under [`TarSparsePolicy::Expand`] a sparse
/// entry's map is checked and its extension blocks may follow the final header,
/// so the window ends that many blocks after `file_pos`.
///
/// # Errors
///
/// Returns [`crate::ArchiveError::InvalidArchive`] when a header's checksum or
/// size is not canonical, a local PAX body is not canonical, an extension
/// header repeats, or the blocks do not end exactly at the entry the `tar`
/// crate yielded.
///
/// The result carries the parsed local PAX body as soon as it passes the
/// framing check, even when a later check fails, so the caller can report a
/// record error before a window error.
pub(super) fn walk_window<'w>(
    window: &MetadataWindow<'w>,
    preceding: PrecedingEntry,
    header_pos: u64,
    file_pos: u64,
    sparse: TarSparsePolicy,
) -> WindowWalk<'w> {
    let mut walk = WindowWalk {
        pax: None,
        extensions: Vec::new(),
        outcome: Ok(()),
        chain_blocks: 0,
    };
    walk.outcome = walk_blocks(window, preceding, header_pos, file_pos, sparse, &mut walk);
    walk
}

fn walk_blocks<'w>(
    window: &MetadataWindow<'w>,
    preceding: PrecedingEntry,
    header_pos: u64,
    file_pos: u64,
    sparse: TarSparsePolicy,
    walk: &mut WindowWalk<'w>,
) -> Result<()> {
    let bytes = window.bytes();
    let mut offset = first_header_offset(window.start())?;
    if preceding == PrecedingEntry::GlobalPax {
        check_zero_padding(bytes.get(..offset))?;
    }
    let mut pax_has_size = false;
    loop {
        let block = block_at(bytes, offset).ok_or(TarAmbiguity::WindowMismatch)?;
        verify_checksum(block)?;
        let size = declared_size(block)?;
        let Some(kind) = extension_kind_of(block) else {
            let has_long = walk.extensions.iter().any(|k| *k != TarExtensionKind::Pax);
            if pax_has_size && has_long {
                return Err(TarAmbiguity::StackedSizeRecord.into());
            }
            walk.chain_blocks =
                check_final_header(window, block, offset, header_pos, file_pos, sparse)?;
            return Ok(());
        };
        if walk.extensions.contains(&kind) {
            return Err(TarAmbiguity::DuplicateExtensionHeader { kind }.into());
        }
        walk.extensions.push(kind);

        let body_start = offset
            .checked_add(BLOCK)
            .ok_or(TarAmbiguity::WindowMismatch)?;
        let body_end = usize::try_from(size)
            .ok()
            .and_then(|len| body_start.checked_add(len))
            .ok_or(TarAmbiguity::WindowMismatch)?;
        let body = bytes
            .get(body_start..body_end)
            .ok_or(TarAmbiguity::WindowMismatch)?;
        if kind == TarExtensionKind::Pax {
            let pax = ParsedPax::parse(body)?;
            pax_has_size = pax.declares_size;
            walk.pax = Some(pax);
        } else {
            check_long_record(kind, body)?;
        }
        offset = body_start
            .checked_add(body.len().next_multiple_of(BLOCK))
            .ok_or(TarAmbiguity::WindowMismatch)?;
        check_zero_padding(bytes.get(body_end..offset))?;
    }
}

/// Checks the padding after a trailing global PAX header, in the window the
/// `tar` crate read before reporting the end of the archive. An archive that
/// ends inside the padding has nothing left to disagree on.
pub(super) fn check_trailing_global_padding(window: &MetadataWindow<'_>) -> Result<()> {
    let bytes = window.bytes();
    let end = first_header_offset(window.start())?.min(bytes.len());
    check_zero_padding(bytes.get(..end))
}

fn check_zero_padding(padding: Option<&[u8]>) -> Result<()> {
    let padding = padding.ok_or(TarAmbiguity::WindowMismatch)?;
    padding
        .iter()
        .all(|&b| b == 0)
        .ok_or_else(|| TarAmbiguity::NonZeroPadding.into())
}

/// Readers cut a GNU long name or link at the first NUL of the padded block,
/// so a non-empty body must end in exactly one NUL. A NUL elsewhere in the
/// text is refused later as a path or target containing null bytes.
fn check_long_record(kind: TarExtensionKind, body: &[u8]) -> Result<()> {
    match body.split_last() {
        None => Ok(()),
        Some((0, text)) if text.last() != Some(&0) => Ok(()),
        _ => Err(TarAmbiguity::MalformedLongRecord { kind }.into()),
    }
}

/// Checks that the window ends where the `tar` crate says the entry's data
/// begins, and returns how many sparse extension blocks sit between the final
/// header and that point.
fn check_final_header(
    window: &MetadataWindow<'_>,
    block: &[u8; BLOCK],
    offset: usize,
    header_pos: u64,
    file_pos: u64,
    sparse: TarSparsePolicy,
) -> Result<usize> {
    let after_header = offset
        .checked_add(BLOCK)
        .ok_or(TarAmbiguity::WindowMismatch)?;
    let chain_blocks = if sparse == TarSparsePolicy::Expand && block[TYPEFLAG_OFFSET] == b'S' {
        let chain = window
            .bytes()
            .get(after_header..)
            .ok_or(TarAmbiguity::WindowMismatch)?;
        sparse::check_map(block, chain)?
    } else {
        0
    };
    let chain_bytes = chain_blocks
        .checked_mul(BLOCK)
        .ok_or(TarAmbiguity::WindowMismatch)?;
    let at_end = after_header.checked_add(chain_bytes) == Some(window.bytes().len());
    let position = window.start().saturating_add(offset as u64);
    let data_start = file_pos.checked_add(chain_bytes as u64);
    if !at_end || position != header_pos || data_start != Some(window.end()) {
        return Err(TarAmbiguity::WindowMismatch.into());
    }
    check_header_block(block, block[MAGIC_FIELD] == *USTAR_MAGIC)?;
    Ok(chain_blocks)
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use tar::Header;

    use super::*;
    use crate::ArchiveError;

    fn check_window(
        window: &MetadataWindow<'_>,
        preceding: PrecedingEntry,
        header_pos: u64,
        file_pos: u64,
    ) -> Result<()> {
        walk_window(
            window,
            preceding,
            header_pos,
            file_pos,
            TarSparsePolicy::Refuse,
        )
        .outcome
    }

    fn header_block(typeflag: u8, size: usize) -> Vec<u8> {
        let mut header = Header::new_gnu();
        header.set_size(size as u64);
        header.set_entry_type(tar::EntryType::new(typeflag));
        header.set_cksum();
        header.as_bytes().to_vec()
    }

    fn padded(mut bytes: Vec<u8>) -> Vec<u8> {
        bytes.resize(bytes.len().next_multiple_of(BLOCK), 0);
        bytes
    }

    fn pax_extension(body: &[u8]) -> Vec<u8> {
        padded([header_block(b'x', body.len()), body.to_vec()].concat())
    }

    fn assert_refused(result: Result<()>, expected: &TarAmbiguity) {
        assert_matches!(
            result,
            Err(ArchiveError::TarAmbiguity(found)) if found == *expected
        );
    }

    #[test]
    fn a_window_start_that_overflows_the_next_block_is_refused() {
        assert_refused(
            first_header_offset(u64::MAX).map(drop),
            &TarAmbiguity::WindowMismatch,
        );
    }

    #[test]
    fn a_bare_final_header_is_accepted() {
        let bytes = header_block(b'0', 0);
        let window = MetadataWindow::new(0, &bytes);
        check_window(&window, PrecedingEntry::Other, 0, 512).unwrap();
    }

    #[test]
    fn the_first_header_starts_at_the_next_block_boundary() {
        let mut bytes = vec![0u8; 5];
        bytes.extend(header_block(b'0', 0));
        let window = MetadataWindow::new(507, &bytes);
        check_window(&window, PrecedingEntry::Other, 512, 1024).unwrap();
    }

    #[test]
    fn a_window_ending_past_the_reported_file_position_is_refused() {
        let bytes = header_block(b'0', 0);
        let window = MetadataWindow::new(0, &bytes);
        assert_refused(
            check_window(&window, PrecedingEntry::Other, 0, 1024),
            &TarAmbiguity::WindowMismatch,
        );
    }

    #[test]
    fn a_final_header_at_another_position_than_reported_is_refused() {
        let bytes = header_block(b'0', 0);
        let window = MetadataWindow::new(0, &bytes);
        assert_refused(
            check_window(&window, PrecedingEntry::Other, 512, 512),
            &TarAmbiguity::WindowMismatch,
        );
    }

    #[test]
    fn a_window_that_ends_inside_a_header_is_refused() {
        let bytes = header_block(b'0', 0);
        let window = MetadataWindow::new(0, &bytes[..300]);
        assert_refused(
            check_window(&window, PrecedingEntry::Other, 0, 300),
            &TarAmbiguity::WindowMismatch,
        );
    }

    #[test]
    fn an_extension_header_followed_by_the_entry_is_accepted() {
        let body = b"18 path=long/name\n";
        let bytes = [pax_extension(body), header_block(b'0', 0)].concat();
        let window = MetadataWindow::new(0, &bytes);
        check_window(&window, PrecedingEntry::Other, 1024, 1536).unwrap();
    }

    #[test]
    fn an_extension_body_running_past_the_window_is_refused() {
        let bytes = [header_block(b'x', 4096), vec![0u8; 512]].concat();
        let window = MetadataWindow::new(0, &bytes);
        assert_refused(
            check_window(&window, PrecedingEntry::Other, 512, 1024),
            &TarAmbiguity::WindowMismatch,
        );
    }

    #[test]
    fn a_repeated_extension_header_is_refused() {
        let body = b"18 path=long/name\n";
        let bytes = [
            pax_extension(body),
            pax_extension(body),
            header_block(b'0', 0),
        ]
        .concat();
        let window = MetadataWindow::new(0, &bytes);
        assert_refused(
            check_window(&window, PrecedingEntry::Other, 2048, 2560),
            &TarAmbiguity::DuplicateExtensionHeader {
                kind: TarExtensionKind::Pax,
            },
        );
    }

    #[test]
    fn a_non_canonical_pax_length_is_refused() {
        let body = b"+20 path=long/name\n";
        let bytes = [pax_extension(body), header_block(b'0', 0)].concat();
        let window = MetadataWindow::new(0, &bytes);
        assert_refused(
            check_window(&window, PrecedingEntry::Other, 1024, 1536),
            &TarAmbiguity::MalformedRecord,
        );
    }

    #[test]
    fn a_checksum_that_is_not_the_byte_sum_is_refused() {
        let mut block = header_block(b'0', 0);
        block[0] = b'a';
        let window = MetadataWindow::new(0, &block);
        assert_refused(
            check_window(&window, PrecedingEntry::Other, 0, 512),
            &TarAmbiguity::ChecksumMismatch,
        );
    }

    #[test]
    fn a_vertical_tab_in_an_extension_header_size_is_refused() {
        let body = b"18 path=long/name\n";
        let mut extension = pax_extension(body);
        extension[SIZE_FIELD.start] = 0x0b;
        let sum: u32 = extension[..BLOCK]
            .iter()
            .enumerate()
            .map(|(i, &b)| u32::from(if CHECKSUM_FIELD.contains(&i) { b' ' } else { b }))
            .sum();
        extension[CHECKSUM_FIELD].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        let bytes = [extension, header_block(b'0', 0)].concat();
        let window = MetadataWindow::new(0, &bytes);
        assert_refused(
            check_window(&window, PrecedingEntry::Other, 1024, 1536),
            &TarAmbiguity::NonCanonicalNumber {
                field: TarHeaderField::Size,
            },
        );
    }

    fn octal_field(value: u64) -> Vec<u8> {
        format!("{value:011o}\0").into_bytes()
    }

    /// An old GNU sparse header whose four slots are all used, so a chain may
    /// follow when `extended`.
    fn sparse_header(extended: bool) -> Vec<u8> {
        let mut header = Header::new_gnu();
        header.set_entry_type(tar::EntryType::new(b'S'));
        header.set_size(2048);
        let mut bytes = header.as_bytes().to_vec();
        for index in 0..4u64 {
            let at = 386 + usize::try_from(index).unwrap() * 24;
            bytes[at..at + 12].copy_from_slice(&octal_field(index * 1024));
            bytes[at + 12..at + 24].copy_from_slice(&octal_field(512));
        }
        bytes[482] = u8::from(extended);
        bytes[483..495].copy_from_slice(&octal_field(4096));
        bytes[CHECKSUM_FIELD].fill(b' ');
        let sum: u32 = bytes.iter().map(|&b| u32::from(b)).sum();
        bytes[CHECKSUM_FIELD].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        bytes
    }

    fn chain_block() -> Vec<u8> {
        vec![0u8; BLOCK]
    }

    fn check_sparse<'w>(
        window: &MetadataWindow<'w>,
        sparse: TarSparsePolicy,
        file_pos: u64,
    ) -> WindowWalk<'w> {
        walk_window(window, PrecedingEntry::Other, 0, file_pos, sparse)
    }

    #[test]
    fn a_sparse_chain_ends_the_window_after_the_extension_blocks() {
        let bytes = [sparse_header(true), chain_block()].concat();
        let window = MetadataWindow::new(0, &bytes);
        let walk = check_sparse(&window, TarSparsePolicy::Expand, 512);
        walk.outcome.unwrap();
        assert_eq!(walk.chain_blocks, 1);
    }

    #[test]
    fn a_sparse_header_without_a_chain_has_none() {
        let bytes = sparse_header(false);
        let window = MetadataWindow::new(0, &bytes);
        let walk = check_sparse(&window, TarSparsePolicy::Expand, 512);
        walk.outcome.unwrap();
        assert_eq!(walk.chain_blocks, 0);
    }

    #[test]
    fn a_chain_that_the_header_does_not_announce_is_refused() {
        let bytes = [sparse_header(false), chain_block()].concat();
        let window = MetadataWindow::new(0, &bytes);
        assert_refused(
            check_sparse(&window, TarSparsePolicy::Expand, 512).outcome,
            &TarAmbiguity::SparseMap {
                defect: crate::SparseMapDefect::ExtensionChain,
            },
        );
    }

    #[test]
    fn a_file_position_that_ignores_the_chain_is_refused() {
        let bytes = [sparse_header(true), chain_block()].concat();
        let window = MetadataWindow::new(0, &bytes);
        assert_refused(
            check_sparse(&window, TarSparsePolicy::Expand, 1024).outcome,
            &TarAmbiguity::WindowMismatch,
        );
    }

    #[test]
    fn a_sparse_chain_is_not_walked_under_the_refuse_policy() {
        let bytes = [sparse_header(true), chain_block()].concat();
        let window = MetadataWindow::new(0, &bytes);
        assert_refused(
            check_sparse(&window, TarSparsePolicy::Refuse, 512).outcome,
            &TarAmbiguity::WindowMismatch,
        );
    }
}
