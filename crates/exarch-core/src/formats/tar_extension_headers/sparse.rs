//! The map of an old GNU sparse entry (typeflag `S`).
//!
//! The `tar` crate parses the map itself: it skips every empty slot, orders and
//! aligns the regions and requires the map to end at the real size.
//! `bsdtar` stops at the first empty slot and Python `tarfile` drops an
//! extension slot whose offset is zero, so a map that relies on any of those
//! choices reads as different bytes in different tools. This module accepts
//! only the maps on which all three agree, and refuses the rest.
//!
//! The map lives in the final header block (four slots) and in the extension
//! blocks the `tar` crate read right after it (21 slots each, no checksum).
//! Both are checked on the bytes of the metadata window, so the map seen here
//! is the one the `tar` crate parsed.

use super::BLOCK;
use super::is_plain_base256;
use super::is_plain_octal;
use super::numeric_value;
use crate::ArchiveError;
use crate::Result;
use crate::SparseMapDefect;
use crate::TarAmbiguity;
use crate::TarHeaderField;

const HEADER_SLOTS_AT: usize = 386;
const HEADER_SLOTS: usize = 4;
const HEADER_EXTENDED_AT: usize = 482;
const REAL_SIZE: std::ops::Range<usize> = 483..495;
const CHAIN_SLOTS: usize = 21;
const CHAIN_EXTENDED_AT: usize = 504;
const SLOT_BYTES: usize = 24;
const FIELD_BYTES: usize = 12;

fn defect(defect: SparseMapDefect) -> ArchiveError {
    TarAmbiguity::SparseMap { defect }.into()
}

fn non_canonical(field: TarHeaderField) -> ArchiveError {
    TarAmbiguity::NonCanonicalNumber { field }.into()
}

fn is_plain_number(field: &[u8]) -> bool {
    is_plain_octal(field) || is_plain_base256(field)
}

fn extended_flag(byte: u8) -> Result<bool> {
    match byte {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(defect(SparseMapDefect::ExtendedFlag)),
    }
}

/// Number of extension blocks the flags announce, which must be all the bytes
/// after the final header.
fn chain_blocks(header: &[u8; BLOCK], chain: &[u8]) -> Result<usize> {
    let (blocks, rest) = chain.as_chunks::<BLOCK>();
    let mut extended = extended_flag(header[HEADER_EXTENDED_AT])?;
    let mut announced = 0usize;
    while extended {
        let block = blocks
            .get(announced)
            .ok_or_else(|| defect(SparseMapDefect::ExtensionChain))?;
        extended = extended_flag(block[CHAIN_EXTENDED_AT])?;
        announced = announced.saturating_add(1);
    }
    (announced == blocks.len() && rest.is_empty())
        .ok_or_else(|| defect(SparseMapDefect::ExtensionChain))
        .map(|()| announced)
}

/// Where a run of slots sits, which decides the rules for its offsets.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Place {
    Header,
    Extension,
}

/// What the slots seen so far imply for the ones that follow.
#[derive(Default)]
struct Scan {
    /// An unused slot was seen: no used slot may follow.
    ended: bool,
    /// The last used slot has no bytes, so it must be the last of the map.
    last_was_empty: bool,
}

impl Scan {
    fn block(&mut self, slots: &[u8], place: Place, extended: bool) -> Result<()> {
        for slot in slots.as_chunks::<SLOT_BYTES>().0 {
            let (offset, length) = slot.split_at(FIELD_BYTES);
            self.slot(offset, length, place)?;
        }
        if self.ended && extended {
            return Err(defect(SparseMapDefect::SlotAfterEnd));
        }
        Ok(())
    }

    fn slot(&mut self, offset: &[u8], length: &[u8], place: Place) -> Result<()> {
        let offset_unused = offset.first() == Some(&0);
        let length_unused = length.first() == Some(&0);
        if offset_unused && length_unused {
            self.ended = true;
            return Ok(());
        }
        if offset_unused || length_unused {
            return Err(defect(SparseMapDefect::PartialSlot));
        }
        if self.ended {
            return Err(defect(SparseMapDefect::SlotAfterEnd));
        }
        let offset = number(offset, TarHeaderField::SparseOffset)?;
        let length = number(length, TarHeaderField::SparseLength)?;
        if place == Place::Extension && offset == 0 {
            return Err(defect(SparseMapDefect::ZeroOffsetExtension));
        }
        if self.last_was_empty {
            return Err(defect(SparseMapDefect::InteriorZeroLength));
        }
        self.last_was_empty = length == 0;
        Ok(())
    }
}

fn number(field: &[u8], name: TarHeaderField) -> Result<u64> {
    if !is_plain_number(field) {
        return Err(non_canonical(name));
    }
    numeric_value(field).ok_or_else(|| non_canonical(name))
}

/// Checks the map of a sparse entry and returns how many extension blocks
/// follow its header.
///
/// `header` is the final header block and `chain` the window bytes after it.
/// Every used slot and the real size must be a plain number, no used slot may
/// follow an unused one, a slot with one empty field is refused, an extended
/// flag must be 0 or 1 and the blocks must be exactly those the flags announce,
/// a used slot of an extension block must not start at offset zero, and only
/// the last used slot of the whole map may be empty (the marker of a trailing
/// hole).
///
/// # Errors
///
/// [`TarAmbiguity::SparseMap`] or [`TarAmbiguity::NonCanonicalNumber`] naming
/// the first rule the map breaks.
pub(super) fn check_map(header: &[u8; BLOCK], chain: &[u8]) -> Result<usize> {
    if !is_plain_number(&header[REAL_SIZE]) {
        return Err(non_canonical(TarHeaderField::RealSize));
    }
    let blocks = chain_blocks(header, chain)?;
    let mut scan = Scan::default();
    let header_slots = &header[HEADER_SLOTS_AT..HEADER_SLOTS_AT + HEADER_SLOTS * SLOT_BYTES];
    scan.block(header_slots, Place::Header, header[HEADER_EXTENDED_AT] == 1)?;
    for block in chain.as_chunks::<BLOCK>().0 {
        let slots = &block[..CHAIN_SLOTS * SLOT_BYTES];
        scan.block(slots, Place::Extension, block[CHAIN_EXTENDED_AT] == 1)?;
    }
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;

    fn octal(value: u64) -> [u8; FIELD_BYTES] {
        let mut field = [0u8; FIELD_BYTES];
        field[..11].copy_from_slice(format!("{value:011o}").as_bytes());
        field
    }

    fn slot(offset: u64, length: u64) -> [u8; SLOT_BYTES] {
        let mut slot = [0u8; SLOT_BYTES];
        slot[..FIELD_BYTES].copy_from_slice(&octal(offset));
        slot[FIELD_BYTES..].copy_from_slice(&octal(length));
        slot
    }

    fn header(slots: &[[u8; SLOT_BYTES]], extended: u8) -> [u8; BLOCK] {
        let mut block = [0u8; BLOCK];
        for (index, slot) in slots.iter().enumerate() {
            let at = HEADER_SLOTS_AT + index * SLOT_BYTES;
            block[at..at + SLOT_BYTES].copy_from_slice(slot);
        }
        block[HEADER_EXTENDED_AT] = extended;
        block[REAL_SIZE].copy_from_slice(&octal(4096));
        block
    }

    fn extension(slots: &[[u8; SLOT_BYTES]], extended: u8) -> Vec<u8> {
        let mut block = vec![0u8; BLOCK];
        for (index, slot) in slots.iter().enumerate() {
            block[index * SLOT_BYTES..(index + 1) * SLOT_BYTES].copy_from_slice(slot);
        }
        block[CHAIN_EXTENDED_AT] = extended;
        block
    }

    fn refused(result: Result<usize>, expected: &TarAmbiguity) {
        assert_matches!(result, Err(ArchiveError::TarAmbiguity(found)) if found == *expected);
    }

    fn sparse(defect: SparseMapDefect) -> TarAmbiguity {
        TarAmbiguity::SparseMap { defect }
    }

    #[test]
    fn a_map_that_fits_the_header_has_no_extension_blocks() {
        let block = header(&[slot(0, 512), slot(1024, 512)], 0);
        assert_eq!(check_map(&block, &[]).unwrap(), 0);
    }

    #[test]
    fn a_zero_length_slot_is_accepted_as_the_last_one() {
        let block = header(&[slot(0, 512), slot(4096, 0)], 0);
        assert_eq!(check_map(&block, &[]).unwrap(), 0);
    }

    #[test]
    fn a_zero_length_slot_before_another_used_slot_is_refused() {
        let block = header(&[slot(0, 512), slot(512, 0), slot(512, 512)], 0);
        refused(
            check_map(&block, &[]),
            &sparse(SparseMapDefect::InteriorZeroLength),
        );
    }

    #[test]
    fn an_extension_chain_is_counted_by_its_flags() {
        let block = header(&[slot(0, 512); 4], 1);
        let chain = [
            extension(&[slot(512, 512); CHAIN_SLOTS], 1),
            extension(&[slot(1024, 512)], 0),
        ]
        .concat();
        assert_eq!(check_map(&block, &chain).unwrap(), 2);
    }

    #[test]
    fn a_used_slot_at_offset_zero_in_an_extension_block_is_refused() {
        let block = header(&[slot(0, 0); 4], 1);
        let chain = extension(&[slot(0, 512)], 0);
        refused(
            check_map(&block, &chain),
            &sparse(SparseMapDefect::InteriorZeroLength),
        );

        let block = header(&[slot(0, 512); 4], 1);
        refused(
            check_map(&block, &chain),
            &sparse(SparseMapDefect::ZeroOffsetExtension),
        );
    }

    #[test]
    fn a_used_slot_after_an_unused_one_is_refused() {
        let block = header(&[slot(0, 512), [0; SLOT_BYTES], slot(1024, 512)], 0);
        refused(
            check_map(&block, &[]),
            &sparse(SparseMapDefect::SlotAfterEnd),
        );
    }

    #[test]
    fn an_unused_slot_before_a_further_extension_block_is_refused() {
        let block = header(&[slot(0, 512), [0; SLOT_BYTES]], 1);
        let chain = extension(&[], 0);
        refused(
            check_map(&block, &chain),
            &sparse(SparseMapDefect::SlotAfterEnd),
        );
    }

    #[test]
    fn a_slot_with_one_empty_field_is_refused() {
        let mut half = slot(512, 512);
        half[..FIELD_BYTES].fill(0);
        let block = header(&[slot(0, 512), half], 0);
        refused(
            check_map(&block, &[]),
            &sparse(SparseMapDefect::PartialSlot),
        );
    }

    #[test]
    fn a_flag_other_than_zero_or_one_is_refused_in_the_header_and_the_chain() {
        let block = header(&[slot(0, 512)], 2);
        refused(
            check_map(&block, &[]),
            &sparse(SparseMapDefect::ExtendedFlag),
        );

        let block = header(&[slot(0, 512); 4], 1);
        let chain = extension(&[slot(512, 512)], b'1');
        refused(
            check_map(&block, &chain),
            &sparse(SparseMapDefect::ExtendedFlag),
        );
    }

    #[test]
    fn a_chain_that_does_not_match_its_flags_is_refused() {
        let block = header(&[slot(0, 512); 4], 1);
        refused(
            check_map(&block, &[]),
            &sparse(SparseMapDefect::ExtensionChain),
        );

        let block = header(&[slot(0, 512)], 0);
        let chain = extension(&[], 0);
        refused(
            check_map(&block, &chain),
            &sparse(SparseMapDefect::ExtensionChain),
        );
    }

    #[test]
    fn a_number_that_is_not_plain_is_refused_with_its_field() {
        let mut offset = slot(1024, 512);
        offset[0] = b'+';
        let block = header(&[slot(0, 512), offset], 0);
        refused(
            check_map(&block, &[]),
            &TarAmbiguity::NonCanonicalNumber {
                field: TarHeaderField::SparseOffset,
            },
        );

        let mut length = slot(0, 512);
        length[FIELD_BYTES] = 0x0b;
        let block = header(&[length], 0);
        refused(
            check_map(&block, &[]),
            &TarAmbiguity::NonCanonicalNumber {
                field: TarHeaderField::SparseLength,
            },
        );

        let mut block = header(&[slot(0, 512)], 0);
        block[REAL_SIZE.start] = 0x0b;
        refused(
            check_map(&block, &[]),
            &TarAmbiguity::NonCanonicalNumber {
                field: TarHeaderField::RealSize,
            },
        );
    }
}
