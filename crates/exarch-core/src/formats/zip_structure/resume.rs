//! Where a streaming ZIP reader resumes after a data-descriptor entry.
//!
//! A reader that follows local headers cannot read the sizes of such an entry
//! before its data, so it decides where the entry ends from the data itself and
//! from the descriptor bytes. The model follows libarchive 3.7, the streaming
//! reader this check is written against, in both of its modes:
//!
//! - extraction ends a deflated entry at the end of its compressed stream and
//!   any other entry at a signed descriptor (an entry without a signature has
//!   no defined end), then consumes the descriptor by matching each possible
//!   layout (24, 20, 16 and 12 bytes) against the entry's actual sizes, the CRC
//!   being ignored;
//! - listing skips the entry without decoding it: it consumes the local
//!   compressed size when that is not zero (after resolving a 32-bit escape
//!   through the ZIP64 extra field), and otherwise resumes where a deflated
//!   stream ends, or scans any other entry for the descriptor signature and
//!   resumes after 16 bytes, or 24 when the local header carries a ZIP64 extra
//!   field.
//!
//! The model covers these layouts; other streaming-reader layouts are tracked
//! in #687.
//!
//! Where the two modes disagree the further resume position wins, since either
//! reader can be the one that skips an entry. The sizes are those of the
//! central directory; the CRC is a wildcard.

use zip::CompressionMethod;

use super::DATA_DESCRIPTOR_SIGNATURE;
use super::EntryLayout;
use super::LFH_FIXED_LEN;
use super::ZIP64_EXTRA_ID;
use super::le_u16;
use super::le_u32;
use super::le_u64;

/// Bytes after an entry's data that decide where a streaming reader resumes:
/// the longest data descriptor.
pub(super) const DESCRIPTOR_LOOKAHEAD: usize = 24;

/// How a streaming reader finds the end of the data of a descriptor entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DescriptorExit {
    /// The reader decodes the stream and stops where it ends.
    Inflate,
    /// The reader cannot decode the data and scans for the descriptor.
    Scan,
}

impl DescriptorExit {
    pub(super) const fn of(method: CompressionMethod) -> Self {
        match method {
            CompressionMethod::Deflated => Self::Inflate,
            _ => Self::Scan,
        }
    }
}

/// Length of a data descriptor, from its optional signature and the width of
/// its size fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum DescriptorWidth {
    /// CRC and two 32-bit sizes.
    Twelve,
    /// Signature, CRC and two 32-bit sizes.
    Sixteen,
    /// CRC and two 64-bit sizes.
    Twenty,
    /// Signature, CRC and two 64-bit sizes.
    TwentyFour,
}

impl DescriptorWidth {
    pub(super) const ALL: [Self; 4] = [Self::Twelve, Self::Sixteen, Self::Twenty, Self::TwentyFour];

    pub(super) const fn bytes(self) -> u64 {
        match self {
            Self::Twelve => 12,
            Self::Sixteen => 16,
            Self::Twenty => 20,
            Self::TwentyFour => 24,
        }
    }

    const fn signed(self) -> bool {
        matches!(self, Self::Sixteen | Self::TwentyFour)
    }

    const fn wide(self) -> bool {
        matches!(self, Self::Twenty | Self::TwentyFour)
    }

    /// Whether `at_end` starts with a descriptor of this width for an entry of
    /// the given sizes. The CRC is not compared.
    fn matches(self, at_end: &[u8], compressed: u64, size: u64) -> bool {
        let sizes_at = if self.signed() {
            if !at_end.starts_with(&DATA_DESCRIPTOR_SIGNATURE) {
                return false;
            }
            8
        } else {
            4
        };
        let field = if self.wide() { 8 } else { 4 };
        let Some(sizes) = at_end.get(sizes_at..sizes_at + 2 * field) else {
            return false;
        };
        let read = |at: usize| {
            if self.wide() {
                le_u64(sizes, at)
            } else {
                u64::from(le_u32(sizes, at))
            }
        };
        read(0) == compressed && read(field) == size
    }
}

/// Where a streaming reader continues after the data of a descriptor entry,
/// measured from the end of that data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Resume {
    /// Right at the end of the data, so the descriptor bytes are scanned.
    AtEnd,
    /// After a descriptor of this width.
    After(DescriptorWidth),
    /// At an absolute position given by the local header's compressed size.
    At(u64),
    /// Anywhere: the reader scans on until it meets a signature.
    Unbounded,
}

impl Resume {
    /// Absolute resume position, or `None` when the reader is not bounded.
    pub(super) fn position(self, end: u64) -> Option<u64> {
        match self {
            Self::AtEnd => Some(end),
            Self::After(width) => Some(end.saturating_add(width.bytes())),
            Self::At(position) => Some(position),
            Self::Unbounded => None,
        }
    }

    fn furthest(self, other: Self, end: u64) -> Self {
        match (self.position(end), other.position(end)) {
            (Some(a), Some(b)) if b > a => other,
            (Some(_), Some(_)) => self,
            _ => Self::Unbounded,
        }
    }
}

/// What the local header of a descriptor entry tells a streaming reader.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct LocalFacts {
    /// The header has a ZIP64 extra field, which widens the descriptor.
    pub(super) zip64_extra: bool,
    /// Compressed size the reader uses, resolved through the ZIP64 extra field.
    pub(super) compressed: u64,
}

const SIZE_ESCAPE: u32 = u32::MAX;

impl LocalFacts {
    /// Reads the facts a streaming reader takes from a local header, resolving
    /// a 32-bit escape value through the ZIP64 extra field in the order the
    /// reader does: uncompressed size first, then compressed, each only when
    /// its field holds the escape.
    ///
    /// An extra field the reader rejects makes it fail the header, so it gives
    /// up the entry instead of skipping anything; no facts are taken from it.
    pub(super) fn parse(header: &[u8; LFH_FIXED_LEN], extra: &[u8]) -> Self {
        let raw_compressed = le_u32(header, 18);
        let mut compressed = u64::from(raw_compressed);
        let mut zip64_extra = false;
        let mut rest = extra;
        while let Some((head, tail)) = rest.split_first_chunk::<4>() {
            let (id, len) = (le_u16(head, 0), usize::from(le_u16(head, 2)));
            let Some((mut body, after)) = tail.split_at_checked(len) else {
                return Self::default();
            };
            if id == ZIP64_EXTRA_ID {
                zip64_extra = true;
                let escapes = [
                    (le_u32(header, 22) == SIZE_ESCAPE, false),
                    (raw_compressed == SIZE_ESCAPE, true),
                ];
                for (escaped, is_compressed) in escapes {
                    if !escaped {
                        continue;
                    }
                    let Some((value, remaining)) = body.split_first_chunk::<8>() else {
                        return Self::default();
                    };
                    let value = u64::from_le_bytes(*value);
                    if i64::try_from(value).is_err() {
                        return Self::default();
                    }
                    if is_compressed {
                        compressed = value;
                    }
                    body = remaining;
                }
            }
            rest = after;
        }
        Self {
            zip64_extra,
            compressed,
        }
    }
}

/// Where a streaming reader resumes after the data of `layout`, a descriptor
/// entry that ends as `exit` says, given the bytes that follow the data.
pub(super) fn streaming_resume(
    layout: &EntryLayout,
    exit: DescriptorExit,
    local: LocalFacts,
    at_end: &[u8],
) -> Resume {
    let signed = at_end.starts_with(&DATA_DESCRIPTOR_SIGNATURE);
    let extraction = if exit == DescriptorExit::Scan && !signed {
        Resume::Unbounded
    } else {
        DescriptorWidth::ALL
            .into_iter()
            .rev()
            .find(|width| width.matches(at_end, layout.compressed, layout.size))
            .map_or(Resume::AtEnd, Resume::After)
    };
    let listing = if local.compressed > 0 {
        Resume::At(layout.data_start.saturating_add(local.compressed))
    } else {
        match exit {
            DescriptorExit::Scan if signed => Resume::After(if local.zip64_extra {
                DescriptorWidth::TwentyFour
            } else {
                DescriptorWidth::Sixteen
            }),
            DescriptorExit::Scan => Resume::Unbounded,
            DescriptorExit::Inflate => Resume::AtEnd,
        }
    };
    extraction.furthest(listing, layout.end)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::xl_type::EntryKind;
    use super::*;
    use crate::error::ZipEntryIndex;

    const PK78: [u8; 4] = DATA_DESCRIPTOR_SIGNATURE;
    const END: u64 = 100;
    const COMPRESSED: u64 = 7;
    const SIZE: u64 = 9;

    fn layout(exit: DescriptorExit) -> EntryLayout {
        EntryLayout {
            entry: ZipEntryIndex::new(0),
            header_start: 40,
            data_start: 93,
            end: END,
            descriptor: Some(exit),
            compressed: COMPRESSED,
            size: SIZE,
            kind: EntryKind::Regular,
        }
    }

    fn descriptor(signed: bool, wide: bool, crc: u32, compressed: u64, size: u64) -> Vec<u8> {
        let mut bytes = if signed { PK78.to_vec() } else { Vec::new() };
        bytes.extend_from_slice(&crc.to_le_bytes());
        if wide {
            bytes.extend_from_slice(&compressed.to_le_bytes());
            bytes.extend_from_slice(&size.to_le_bytes());
        } else {
            bytes.extend_from_slice(&u32::try_from(compressed).unwrap().to_le_bytes());
            bytes.extend_from_slice(&u32::try_from(size).unwrap().to_le_bytes());
        }
        bytes
    }

    fn followed_by_header(mut bytes: Vec<u8>) -> Vec<u8> {
        bytes.extend_from_slice(b"PK\x03\x04");
        bytes.resize(DESCRIPTOR_LOOKAHEAD.max(bytes.len()), 0);
        bytes
    }

    fn local(zip64_extra: bool, compressed: u64) -> LocalFacts {
        LocalFacts {
            zip64_extra,
            compressed,
        }
    }

    #[test]
    fn extraction_matches_every_width_whatever_the_crc() {
        for (signed, wide, width) in [
            (true, true, DescriptorWidth::TwentyFour),
            (false, true, DescriptorWidth::Twenty),
            (true, false, DescriptorWidth::Sixteen),
            (false, false, DescriptorWidth::Twelve),
        ] {
            for crc in [0, 0x1234_5678, u32::from_le_bytes(*b"PK\x01\x02")] {
                let at_end = followed_by_header(descriptor(signed, wide, crc, COMPRESSED, SIZE));
                assert_eq!(
                    streaming_resume(
                        &layout(DescriptorExit::Inflate),
                        DescriptorExit::Inflate,
                        local(false, 0),
                        &at_end
                    ),
                    Resume::After(width),
                    "{signed} {wide} {crc:#x}"
                );
            }
        }
    }

    #[test]
    fn extraction_needs_both_sizes_to_match() {
        for (compressed, size) in [(COMPRESSED + 1, SIZE), (COMPRESSED, SIZE + 1)] {
            let at_end = followed_by_header(descriptor(true, false, 0, compressed, size));
            assert_eq!(
                streaming_resume(
                    &layout(DescriptorExit::Inflate),
                    DescriptorExit::Inflate,
                    local(false, 0),
                    &at_end
                ),
                Resume::AtEnd
            );
        }
    }

    #[test]
    fn a_short_descriptor_followed_by_a_crafted_header_is_read_as_a_longer_one() {
        const MAGIC: u64 = 0x0403_4b50;
        let mut entry = layout(DescriptorExit::Inflate);
        entry.size = MAGIC;
        let mut at_end = descriptor(false, false, 0, COMPRESSED, 0);
        at_end.extend_from_slice(b"PK\x03\x04\0\0\0\0");
        assert_eq!(
            streaming_resume(&entry, DescriptorExit::Inflate, local(false, 0), &at_end),
            Resume::After(DescriptorWidth::Twenty)
        );
    }

    #[test]
    fn truncated_lookahead_matches_nothing() {
        let at_end = descriptor(true, false, 0, COMPRESSED, SIZE);
        for cut in 0..at_end.len() {
            assert_eq!(
                streaming_resume(
                    &layout(DescriptorExit::Inflate),
                    DescriptorExit::Inflate,
                    local(false, 0),
                    &at_end[..cut]
                ),
                Resume::AtEnd
            );
        }
    }

    #[test]
    fn deflated_listing_skips_nothing_or_the_local_compressed_size() {
        let nothing = followed_by_header(Vec::new());
        assert_eq!(
            streaming_resume(
                &layout(DescriptorExit::Inflate),
                DescriptorExit::Inflate,
                local(false, 0),
                &nothing
            ),
            Resume::AtEnd
        );
        assert_eq!(
            streaming_resume(
                &layout(DescriptorExit::Inflate),
                DescriptorExit::Inflate,
                local(true, 3),
                &nothing
            ),
            Resume::AtEnd
        );
        assert_eq!(
            streaming_resume(
                &layout(DescriptorExit::Inflate),
                DescriptorExit::Inflate,
                local(false, 20),
                &nothing
            ),
            Resume::At(113)
        );
    }

    #[test]
    fn scanned_listing_follows_the_signature_and_the_zip64_extra() {
        let signed = followed_by_header(PK78.to_vec());
        assert_eq!(
            streaming_resume(
                &layout(DescriptorExit::Scan),
                DescriptorExit::Scan,
                local(false, 0),
                &signed
            ),
            Resume::After(DescriptorWidth::Sixteen)
        );
        assert_eq!(
            streaming_resume(
                &layout(DescriptorExit::Scan),
                DescriptorExit::Scan,
                local(true, 0),
                &signed
            ),
            Resume::After(DescriptorWidth::TwentyFour)
        );
    }

    #[test]
    fn scanned_listing_skips_the_local_compressed_size_when_there_is_one() {
        let signed = followed_by_header(PK78.to_vec());
        assert_eq!(
            streaming_resume(
                &layout(DescriptorExit::Scan),
                DescriptorExit::Scan,
                local(false, 14),
                &signed
            ),
            Resume::At(107)
        );
        assert_eq!(
            streaming_resume(
                &layout(DescriptorExit::Scan),
                DescriptorExit::Scan,
                local(true, COMPRESSED),
                &signed
            ),
            Resume::AtEnd
        );
        let unsigned = followed_by_header(descriptor(false, false, 0, COMPRESSED, SIZE));
        assert_eq!(
            streaming_resume(
                &layout(DescriptorExit::Scan),
                DescriptorExit::Scan,
                local(false, 14),
                &unsigned
            ),
            Resume::Unbounded
        );
    }

    #[test]
    fn a_local_compressed_size_is_skipped_whatever_the_extraction_finds() {
        let signed = followed_by_header(PK78.to_vec());
        assert_eq!(
            streaming_resume(
                &layout(DescriptorExit::Scan),
                DescriptorExit::Scan,
                local(false, 0),
                &signed
            ),
            Resume::After(DescriptorWidth::Sixteen)
        );
        assert_eq!(
            streaming_resume(
                &layout(DescriptorExit::Scan),
                DescriptorExit::Scan,
                local(false, 30),
                &signed
            ),
            Resume::At(123)
        );
    }

    #[test]
    fn the_furthest_resume_of_the_two_readers_wins() {
        let signed = followed_by_header(descriptor(true, false, 0, COMPRESSED, SIZE));
        assert_eq!(
            streaming_resume(
                &layout(DescriptorExit::Scan),
                DescriptorExit::Scan,
                local(true, 0),
                &signed
            ),
            Resume::After(DescriptorWidth::TwentyFour)
        );
        assert_eq!(
            streaming_resume(
                &layout(DescriptorExit::Inflate),
                DescriptorExit::Inflate,
                local(false, 30),
                &signed
            ),
            Resume::At(123)
        );
        let wide = followed_by_header(descriptor(true, true, 0, COMPRESSED, SIZE));
        assert_eq!(
            streaming_resume(
                &layout(DescriptorExit::Scan),
                DescriptorExit::Scan,
                local(false, 0),
                &wide
            ),
            Resume::After(DescriptorWidth::TwentyFour)
        );
    }

    #[test]
    fn resume_positions_are_measured_from_the_end_of_the_data() {
        assert_eq!(Resume::AtEnd.position(END), Some(100));
        assert_eq!(
            Resume::After(DescriptorWidth::Twenty).position(END),
            Some(120)
        );
        assert_eq!(Resume::At(7).position(END), Some(7));
        assert_eq!(Resume::Unbounded.position(END), None);
    }

    fn header(compressed: u32, size: u32) -> [u8; LFH_FIXED_LEN] {
        let mut header = [0u8; LFH_FIXED_LEN];
        header[..4].copy_from_slice(b"PK\x03\x04");
        header[18..22].copy_from_slice(&compressed.to_le_bytes());
        header[22..26].copy_from_slice(&size.to_le_bytes());
        header
    }

    fn zip64_extra(fields: &[u64]) -> Vec<u8> {
        let mut extra = ZIP64_EXTRA_ID.to_le_bytes().to_vec();
        extra.extend_from_slice(&u16::try_from(fields.len() * 8).unwrap().to_le_bytes());
        for field in fields {
            extra.extend_from_slice(&field.to_le_bytes());
        }
        extra
    }

    #[test]
    fn local_compressed_size_resolves_through_the_zip64_extra_in_reader_order() {
        let sizes = zip64_extra(&[11, 22]);
        let both = LocalFacts::parse(&header(SIZE_ESCAPE, SIZE_ESCAPE), &sizes);
        assert_eq!(both, local(true, 22));
        let only_compressed = LocalFacts::parse(&header(SIZE_ESCAPE, 5), &zip64_extra(&[33]));
        assert_eq!(only_compressed, local(true, 33));
        let only_size = LocalFacts::parse(&header(8, SIZE_ESCAPE), &zip64_extra(&[44]));
        assert_eq!(only_size, local(true, 8));
        let none = LocalFacts::parse(&header(SIZE_ESCAPE, 5), &[]);
        assert_eq!(none, local(false, u64::from(SIZE_ESCAPE)));
    }

    #[test]
    fn a_zip64_extra_without_escapes_still_widens_the_descriptor() {
        let facts = LocalFacts::parse(&header(0, 0), &zip64_extra(&[0, 0]));
        assert_eq!(facts, local(true, 0));
    }

    #[test]
    fn an_extra_field_the_reader_rejects_yields_no_facts() {
        let overflowing = [1, 0, 99, 0, 1, 2];
        assert_eq!(
            LocalFacts::parse(&header(5, 5), &overflowing),
            local(false, 0)
        );
        let short = zip64_extra(&[]);
        assert_eq!(
            LocalFacts::parse(&header(SIZE_ESCAPE, SIZE_ESCAPE), &short),
            local(false, 0)
        );
        let huge = zip64_extra(&[u64::MAX]);
        assert_eq!(
            LocalFacts::parse(&header(5, SIZE_ESCAPE), &huge),
            local(false, 0)
        );
    }

    #[test]
    fn other_extra_fields_are_skipped() {
        let mut extra = vec![0x55, 0x54, 2, 0, 9, 9];
        extra.extend(zip64_extra(&[0, 0]));
        assert_eq!(LocalFacts::parse(&header(0, 0), &extra), local(true, 0));
    }
}
