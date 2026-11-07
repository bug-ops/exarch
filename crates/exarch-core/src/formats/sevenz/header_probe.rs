//! Reads the sizes a 7z header declares, without parsing it.
//!
//! sevenz-rust2 holds the header coder's dictionary and the decoded header to
//! one limit, so a limit low enough to bound the entry table would refuse the
//! 8 MiB and larger header dictionaries some writers use for tiny archives.
//! The sizes that bound the table (the plain header, or the declared output of
//! the one coder that decodes an encoded header) sit at fixed places, so they
//! are read here and checked against their own cap. The probe only tightens:
//! the header is still parsed, and checked, by sevenz-rust2.

use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

use super::SIGNATURE_HEADER_SIZE;
use super::header::SEVENZ_MAGIC;

const SIGNATURE_LEN: usize = 32;
const K_HEADER: u8 = 0x01;
const K_ENCODED_HEADER: u8 = 0x17;
const K_PACK_INFO: u8 = 0x06;
const K_SIZE: u8 = 0x09;
const K_CRC: u8 = 0x0A;
const K_END: u8 = 0x00;
const K_UNPACK_INFO: u8 = 0x07;
const K_FOLDER: u8 = 0x0B;
const K_CODERS_UNPACK_SIZE: u8 = 0x0C;
const CODER_COMPLEX: u8 = 0x10;
const CODER_HAS_PROPERTIES: u8 = 0x20;
const CODER_ID_SIZE_MASK: u8 = 0x0F;
const MAX_RECORD: u64 = 4096;

/// What the signature header and the first bytes of the next header declare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DeclaredHeader {
    /// A header stored as it is, of this many bytes.
    Plain { bytes: u64 },
    /// An encoded header that decodes to this many bytes.
    Encoded { decoded: u64 },
    /// Anything the probe does not recognise; sevenz-rust2 decides.
    Unrecognized,
}

/// Reads the declared header size of the archive in `source`, which must be
/// positioned at its start, and leaves `source` anywhere.
///
/// A read failure is [`DeclaredHeader::Unrecognized`]: sevenz-rust2 reads the
/// same bytes next and classifies the failure.
pub(super) fn probe<R: Read + Seek>(source: &mut R) -> DeclaredHeader {
    probe_io(source).unwrap_or(DeclaredHeader::Unrecognized)
}

fn probe_io<R: Read + Seek>(source: &mut R) -> io::Result<DeclaredHeader> {
    let mut start = [0u8; SIGNATURE_LEN];
    source.read_exact(&mut start)?;
    let le = |at: usize| u64::from_le_bytes(start[at..at + 8].try_into().unwrap_or_default());
    let (offset, size) = (le(12), le(20));
    let Some(at) = SIGNATURE_HEADER_SIZE.checked_add(offset) else {
        return Ok(DeclaredHeader::Unrecognized);
    };
    if start[..6] != SEVENZ_MAGIC || size == 0 {
        return Ok(DeclaredHeader::Unrecognized);
    }
    source.seek(SeekFrom::Start(at))?;
    let mut first = [0u8; 1];
    source.read_exact(&mut first)?;
    Ok(match first[0] {
        K_HEADER => DeclaredHeader::Plain { bytes: size },
        K_ENCODED_HEADER if size <= MAX_RECORD => {
            let mut record = vec![0u8; usize::try_from(size).unwrap_or(0)];
            source.seek(SeekFrom::Start(at))?;
            source.read_exact(&mut record)?;
            decoded_size(&record).map_or(DeclaredHeader::Unrecognized, |decoded| {
                DeclaredHeader::Encoded { decoded }
            })
        }
        _ => DeclaredHeader::Unrecognized,
    })
}

/// The declared output size of the single folder of an encoded-header record
/// with one coder, or `None` for any other layout.
fn decoded_size(record: &[u8]) -> Option<u64> {
    let mut bytes = Bytes(record);
    bytes.expect(K_ENCODED_HEADER)?;
    bytes.expect(K_PACK_INFO)?;
    bytes.number()?;
    let pack_streams = bytes.number()?;
    bytes.expect(K_SIZE)?;
    for _ in 0..pack_streams {
        bytes.number()?;
    }
    let mut next = bytes.byte()?;
    if next == K_CRC {
        bytes.skip_digests(pack_streams)?;
        next = bytes.byte()?;
    }
    (next == K_END).then_some(())?;
    bytes.expect(K_UNPACK_INFO)?;
    bytes.expect(K_FOLDER)?;
    (bytes.number()? == 1).then_some(())?;
    bytes.expect(0)?;
    (bytes.number()? == 1).then_some(())?;
    let flags = bytes.byte()?;
    (flags & CODER_COMPLEX == 0).then_some(())?;
    bytes.skip(usize::from(flags & CODER_ID_SIZE_MASK))?;
    if flags & CODER_HAS_PROPERTIES != 0 {
        let properties = bytes.number()?;
        bytes.skip(usize::try_from(properties).ok()?)?;
    }
    bytes.expect(K_CODERS_UNPACK_SIZE)?;
    bytes.number()
}

struct Bytes<'a>(&'a [u8]);

impl Bytes<'_> {
    fn byte(&mut self) -> Option<u8> {
        let (&first, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(first)
    }

    fn expect(&mut self, wanted: u8) -> Option<()> {
        (self.byte()? == wanted).then_some(())
    }

    fn skip(&mut self, count: usize) -> Option<()> {
        self.0 = self.0.get(count..)?;
        Some(())
    }

    /// Skips the digests of `count` streams: a defined-flag (or a bit vector
    /// of them) and a 4-byte CRC for each defined stream.
    fn skip_digests(&mut self, count: u64) -> Option<()> {
        let defined = if self.byte()? == 0 {
            let bit_bytes = usize::try_from(count.div_ceil(8)).ok()?;
            let bits = self.0.get(..bit_bytes)?;
            let set: u64 = bits.iter().map(|b| u64::from(b.count_ones())).sum();
            self.skip(bit_bytes)?;
            set
        } else {
            count
        };
        self.skip(usize::try_from(defined.checked_mul(4)?).ok()?)
    }

    /// A 7z number: the leading ones of the first byte count the extra bytes,
    /// which hold the low bits in little-endian order.
    fn number(&mut self) -> Option<u64> {
        let first = self.byte()?;
        let mut value = 0u64;
        for extra in 0..8u32 {
            let mask = 0x80u8 >> extra;
            if first & mask == 0 {
                return Some(value | (u64::from(first & (mask - 1)) << (8 * extra)));
            }
            value |= u64::from(self.byte()?) << (8 * extra);
        }
        Some(value)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const SIMPLE: &[u8] = include_bytes!("../../../../../tests/fixtures/simple.7z");
    const LARGE_FILE: &[u8] = include_bytes!("../../../../../tests/fixtures/large-file.7z");
    const EMPTY: &[u8] = include_bytes!("../../../../../tests/fixtures/empty.7z");

    fn probed(bytes: &[u8]) -> DeclaredHeader {
        probe(&mut Cursor::new(bytes))
    }

    #[test]
    fn an_encoded_header_declares_its_decoded_size() {
        assert!(matches!(
            probed(SIMPLE),
            DeclaredHeader::Encoded { decoded } if decoded > 0 && decoded < 4096
        ));
    }

    #[test]
    fn a_plain_header_declares_its_own_size() {
        let size = u64::from_le_bytes(LARGE_FILE[20..28].try_into().unwrap());
        assert_eq!(probed(LARGE_FILE), DeclaredHeader::Plain { bytes: size });
    }

    #[test]
    fn what_the_probe_does_not_recognise_is_left_to_sevenz_rust2() {
        assert_eq!(probed(EMPTY), DeclaredHeader::Unrecognized);
        assert_eq!(probed(&SIMPLE[..20]), DeclaredHeader::Unrecognized);
        assert_eq!(
            probed(b"not a 7z archive, not at all, no"),
            DeclaredHeader::Unrecognized
        );
        let mut no_magic = SIMPLE.to_vec();
        no_magic[0] ^= 1;
        assert_eq!(probed(&no_magic), DeclaredHeader::Unrecognized);
    }

    #[test]
    fn a_header_offset_past_the_file_is_unrecognized() {
        let mut bytes = SIMPLE.to_vec();
        bytes[12..20].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(probed(&bytes), DeclaredHeader::Unrecognized);
        bytes[12..20].copy_from_slice(&(1u64 << 40).to_le_bytes());
        assert_eq!(probed(&bytes), DeclaredHeader::Unrecognized);
    }

    #[test]
    fn numbers_decode_every_width() {
        let decode = |bytes: &[u8]| Bytes(bytes).number();
        assert_eq!(decode(&[0x7F]), Some(0x7F));
        assert_eq!(decode(&[0x80 | 0x01, 0x23]), Some(0x123));
        assert_eq!(decode(&[0xC0 | 0x01, 0x34, 0x12]), Some(0x01_1234));
        assert_eq!(decode(&[0xFF, 1, 0, 0, 0, 0, 0, 0, 0]), Some(1));
        assert_eq!(decode(&[0xFF, 1]), None);
        assert_eq!(decode(&[]), None);
    }
}
