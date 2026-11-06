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

use super::CHECKSUM_FIELD;
use super::PrecedingEntry;
use super::SIZE_FIELD;
use super::check_header_block;
use super::check_record_framing;
use super::is_plain_base256;
use super::is_plain_octal;
use crate::Result;
use crate::TarAmbiguity;
use crate::TarExtensionKind;
use crate::TarHeaderField;
use crate::formats::tar_metadata_limit::MetadataWindow;

const BLOCK: usize = 512;
const TYPEFLAG_OFFSET: usize = 156;
const MAGIC_FIELD: Range<usize> = 257..265;
const USTAR_MAGIC: &[u8; 8] = b"ustar\x0000";
const GNU_MAGIC: &[u8; 8] = b"ustar  \0";
const BASE256_VALUE: Range<usize> = 4..12;
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

fn octal_value(field: &[u8]) -> Option<u64> {
    field
        .iter()
        .skip_while(|&&b| b == b' ')
        .take_while(|b| (b'0'..=b'7').contains(b))
        .try_fold(0u64, |acc, &b| {
            acc.checked_mul(8)?.checked_add(u64::from(b - b'0'))
        })
}

fn declared_size(block: &[u8; BLOCK]) -> Result<u64> {
    let field = &block[SIZE_FIELD];
    let value = if is_plain_base256(field) {
        field[BASE256_VALUE]
            .as_array::<8>()
            .copied()
            .map(u64::from_be_bytes)
    } else if is_plain_octal(field) {
        octal_value(field)
    } else {
        None
    };
    value.ok_or_else(|| {
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
    let actual = u64::from(byte_sum(&block[..CHECKSUM_FIELD.start]))
        + u64::from(byte_sum(&block[CHECKSUM_FIELD.end..]))
        + CHECKSUM_SPACES;
    (declared == actual).ok_or(TarAmbiguity::ChecksumMismatch.into())
}

/// Offset of the first block boundary at or after the window start, which is
/// where the `tar` crate looks for the next header.
fn first_header_offset(window_start: u64) -> Result<usize> {
    let block = BLOCK as u64;
    let padding = (block - window_start % block) % block;
    usize::try_from(padding).map_err(|_| TarAmbiguity::WindowMismatch.into())
}

/// Verifies the bytes `tar` read to reach an entry.
///
/// After a global PAX header the padding up to the first block boundary must
/// be zero, as must the padding after every extension header body, and a GNU
/// long name or link body must be one string ending in a single NUL.
///
/// `header_pos` and `file_pos` are the offsets the `tar` crate reports for the
/// yielded entry's header and data.
///
/// # Errors
///
/// Returns [`crate::ArchiveError::InvalidArchive`] when a header's checksum or
/// size is not canonical, a local PAX body is not canonical, an extension
/// header repeats, or the blocks do not end exactly at the entry the `tar`
/// crate yielded.
pub(super) fn check_window(
    window: &MetadataWindow<'_>,
    preceding: PrecedingEntry,
    header_pos: u64,
    file_pos: u64,
) -> Result<()> {
    let bytes = window.bytes();
    let mut offset = first_header_offset(window.start())?;
    if preceding == PrecedingEntry::GlobalPax {
        check_zero_padding(bytes.get(..offset))?;
    }
    let mut seen: Vec<TarExtensionKind> = Vec::new();
    let mut pax_has_size = false;
    loop {
        let block = block_at(bytes, offset).ok_or(TarAmbiguity::WindowMismatch)?;
        verify_checksum(block)?;
        let size = declared_size(block)?;
        let Some(kind) = extension_kind_of(block) else {
            let has_long = seen.iter().any(|k| *k != TarExtensionKind::Pax);
            if pax_has_size && has_long {
                return Err(TarAmbiguity::StackedSizeRecord.into());
            }
            return check_final_header(window, block, offset, header_pos, file_pos);
        };
        if seen.contains(&kind) {
            return Err(TarAmbiguity::DuplicateExtensionHeader { kind }.into());
        }
        seen.push(kind);

        let body_start = offset + BLOCK;
        let body = usize::try_from(size)
            .ok()
            .and_then(|len| bytes.get(body_start..body_start.checked_add(len)?))
            .ok_or(TarAmbiguity::WindowMismatch)?;
        if kind == TarExtensionKind::Pax {
            check_record_framing(body)?;
            pax_has_size = pax_declares_size(body);
        } else {
            check_long_record(kind, body)?;
        }
        let body_end = body_start + body.len();
        offset = body_start
            .checked_add(body.len().next_multiple_of(BLOCK))
            .ok_or(TarAmbiguity::WindowMismatch)?;
        check_zero_padding(bytes.get(body_end..offset))?;
    }
}

/// Whether a framed PAX body holds a `size` record.
fn pax_declares_size(body: &[u8]) -> bool {
    tar::PaxExtensions::new(body)
        .flatten()
        .any(|record| record.key_bytes() == b"size")
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

fn check_final_header(
    window: &MetadataWindow<'_>,
    block: &[u8; BLOCK],
    offset: usize,
    header_pos: u64,
    file_pos: u64,
) -> Result<()> {
    let at_end = offset + BLOCK == window.bytes().len();
    let position = window.start().saturating_add(offset as u64);
    if !at_end || position != header_pos || window.end() != file_pos {
        return Err(TarAmbiguity::WindowMismatch.into());
    }
    check_header_block(block, block[MAGIC_FIELD] == *USTAR_MAGIC)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::assert_matches;

    use tar::Header;

    use super::*;
    use crate::ArchiveError;

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
}
