//! Reads what a 7z header declares, without parsing it.
//!
//! sevenz-rust2 holds the header coder's dictionary and the decoded header to
//! one limit, so a limit low enough to bound the entry table would refuse the
//! 8 MiB and larger header dictionaries some writers use for tiny archives.
//! The sizes that bound the table (the plain header, or the declared output of
//! the coder chain that decodes an encoded header) sit at fixed places, so they
//! are read here and checked against their own cap. The number of entries the
//! header declares is read here too, by walking the header up to its files
//! info (decoding an encoded header through the same coder chain sevenz-rust2
//! builds, for the methods copy, LZMA and LZMA2), so that it can be bounded
//! before sevenz-rust2 builds the entry table. A header whose count cannot be
//! read is reported as such and the caller bounds it more tightly. The probe
//! only tightens: the header is still parsed, and checked, by sevenz-rust2.

use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

use lzma_rust2::Lzma2Reader;
use lzma_rust2::LzmaReader;
use lzma_rust2::lzma_get_memory_usage_by_props;
use lzma_rust2::lzma2_get_memory_usage;

use super::SIGNATURE_HEADER_SIZE;
use super::header::SEVENZ_MAGIC;

const SIGNATURE_LEN: usize = 32;
const K_END: u8 = 0x00;
const K_HEADER: u8 = 0x01;
const K_ARCHIVE_PROPERTIES: u8 = 0x02;
const K_ADDITIONAL_STREAMS_INFO: u8 = 0x03;
const K_MAIN_STREAMS_INFO: u8 = 0x04;
const K_FILES_INFO: u8 = 0x05;
const K_PACK_INFO: u8 = 0x06;
const K_UNPACK_INFO: u8 = 0x07;
const K_SUBSTREAMS_INFO: u8 = 0x08;
const K_SIZE: u8 = 0x09;
const K_CRC: u8 = 0x0A;
const K_FOLDER: u8 = 0x0B;
const K_CODERS_UNPACK_SIZE: u8 = 0x0C;
const K_NUM_UNPACK_STREAM: u8 = 0x0D;
const K_ENCODED_HEADER: u8 = 0x17;
const CODER_ID_SIZE_MASK: u8 = 0x0F;
const CODER_COMPLEX: u8 = 0x10;
const CODER_HAS_PROPERTIES: u8 = 0x20;
const CODER_RESERVED: u8 = 0x80;
const METHOD_COPY: &[u8] = &[0x00];
const METHOD_LZMA: &[u8] = &[0x03, 0x01, 0x01];
const METHOD_LZMA2: &[u8] = &[0x21];
const METHOD_AES: &[u8] = &[0x06, 0xF1, 0x07, 0x01];
/// sevenz-rust2's limits on the coders and input streams of one folder.
const MAX_CODERS: u64 = 64;
const MAX_IN_STREAMS: u64 = 64;

/// What the signature header and the next header declare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DeclaredHeader {
    /// A header stored as it is, of this many bytes.
    Plain { bytes: u64 },
    /// An encoded header that decodes to this many bytes.
    Encoded { decoded: u64 },
    /// Anything the probe does not recognise; sevenz-rust2 decides.
    Unrecognized,
}

/// The number of entries a 7z header declares in its files info.
///
/// Only [`header_entries`] mints one, from the header's own bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DeclaredEntries(u64);

impl DeclaredEntries {
    pub(super) const fn get(self) -> u64 {
        self.0
    }
}

/// Why a header is refused without being parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refusal {
    /// A coder of the header is encryption.
    Encrypted,
    /// A coder of the header needs more than the memory limit.
    Memory,
}

/// What reading the entry count of a header came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HeaderEntries {
    /// The header declares this many entries.
    Declared(DeclaredEntries),
    /// The header is refused for a reason other than its entry count; the
    /// caller returns that refusal without parsing the header.
    Refused(Refusal),
    /// A header is present but the probe cannot read its count (a method it
    /// does not decode, a layout it does not follow); the caller refuses it.
    Unmodelled,
    /// There is no header for the probe to read (not a 7z signature, the valid
    /// empty archive, a read failure, a header over the byte limit);
    /// sevenz-rust2 decides.
    NotApplicable,
}

/// What the signature header says about the next header.
enum NextHeader {
    /// A header of `size` bytes at offset `at`.
    At { at: u64, size: u64 },
    /// A 7z signature header that declares no next header.
    Absent,
    /// Not a 7z signature header the probe models.
    Foreign,
}

fn next_header<R: Read + Seek>(source: &mut R) -> io::Result<NextHeader> {
    let mut start = [0u8; SIGNATURE_LEN];
    source.read_exact(&mut start)?;
    let le = |at: usize| u64::from_le_bytes(start[at..at + 8].try_into().unwrap_or_default());
    let (offset, size) = (le(12), le(20));
    let Some(at) = SIGNATURE_HEADER_SIZE.checked_add(offset) else {
        return Ok(NextHeader::Foreign);
    };
    Ok(if start[..6] != SEVENZ_MAGIC {
        NextHeader::Foreign
    } else if size == 0 {
        NextHeader::Absent
    } else {
        NextHeader::At { at, size }
    })
}

/// Reads the declared header size of the archive in `source`, which must be
/// positioned at its start, and leaves `source` anywhere. An encoded-header
/// record over `max_bytes` is not read.
///
/// A read failure is [`DeclaredHeader::Unrecognized`]: sevenz-rust2 reads the
/// same bytes next and classifies the failure.
pub(super) fn probe<R: Read + Seek>(source: &mut R, max_bytes: u64) -> DeclaredHeader {
    probe_io(source, max_bytes).unwrap_or(DeclaredHeader::Unrecognized)
}

fn probe_io<R: Read + Seek>(source: &mut R, max_bytes: u64) -> io::Result<DeclaredHeader> {
    let NextHeader::At { at, size } = next_header(source)? else {
        return Ok(DeclaredHeader::Unrecognized);
    };
    source.seek(SeekFrom::Start(at))?;
    let mut first = [0u8; 1];
    source.read_exact(&mut first)?;
    Ok(match first[0] {
        K_HEADER => DeclaredHeader::Plain { bytes: size },
        K_ENCODED_HEADER if size <= max_bytes => {
            source.seek(SeekFrom::Start(at))?;
            let record = read_bounded(&mut *source, size)?;
            EncodedRecord::parse(&record)
                .and_then(|record| record.decoded())
                .map_or(DeclaredHeader::Unrecognized, |decoded| {
                    DeclaredHeader::Encoded { decoded }
                })
        }
        _ => DeclaredHeader::Unrecognized,
    })
}

/// Reads the number of entries the header of the archive in `source` declares.
///
/// The count check is coupled to the way sevenz-rust2 walks a header; the
/// differential tests below must be re-run on every sevenz-rust2 upgrade.
///
/// `source` may be anywhere and is left anywhere. A plain header, or an
/// encoded header's decoded size, over `max_bytes` is not read. A coder that
/// needs more than `memory_kib` is not run.
pub(super) fn header_entries<R: Read + Seek>(
    source: &mut R,
    max_bytes: u64,
    memory_kib: usize,
) -> HeaderEntries {
    match read_header(source, max_bytes, memory_kib) {
        Ok(header) => Bytes(&header)
            .header_entries()
            .map_or(HeaderEntries::Unmodelled, HeaderEntries::Declared),
        Err(Stop::Refused(refusal)) => HeaderEntries::Refused(refusal),
        Err(Stop::Unmodelled) => HeaderEntries::Unmodelled,
        Err(Stop::NotApplicable) => HeaderEntries::NotApplicable,
    }
}

/// Why the plain bytes of a header could not be produced.
enum Stop {
    Refused(Refusal),
    Unmodelled,
    NotApplicable,
}

fn read_header<R: Read + Seek>(
    source: &mut R,
    max_bytes: u64,
    memory_kib: usize,
) -> Result<Vec<u8>, Stop> {
    let io = |_| Stop::NotApplicable;
    let length = source.seek(SeekFrom::End(0)).map_err(io)?;
    source.seek(SeekFrom::Start(0)).map_err(io)?;
    let (at, size) = match next_header(source).map_err(io)? {
        NextHeader::At { at, size } => (at, size),
        NextHeader::Absent if length > SIGNATURE_LEN as u64 => return Err(Stop::Unmodelled),
        NextHeader::Absent | NextHeader::Foreign => return Err(Stop::NotApplicable),
    };
    if size > max_bytes {
        return Err(Stop::NotApplicable);
    }
    source.seek(SeekFrom::Start(at)).map_err(io)?;
    let bytes = read_bounded(&mut *source, size).map_err(io)?;
    if (bytes.len() as u64) < size {
        return Err(Stop::NotApplicable);
    }
    match bytes.first() {
        Some(&K_HEADER) => Ok(bytes),
        Some(&K_ENCODED_HEADER) => {
            let record = EncodedRecord::parse(&bytes).ok_or(Stop::Unmodelled)?;
            decode_header(source, &record, max_bytes, memory_kib)
        }
        _ => Err(Stop::NotApplicable),
    }
}

fn read_bounded<R: Read>(source: R, len: u64) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    source.take(len).read_to_end(&mut out)?;
    Ok(out)
}

fn fits(needed_kib: u32, memory_kib: usize) -> Result<(), Stop> {
    match usize::try_from(needed_kib) {
        Ok(needed) if needed <= memory_kib => Ok(()),
        _ => Err(Stop::Refused(Refusal::Memory)),
    }
}

/// The LZMA2 dictionary size a properties byte declares.
fn lzma2_dictionary(property: u8) -> Option<u32> {
    match property {
        0..=39 => Some((2 | u32::from(property & 1)) << (property / 2 + 11)),
        40 => Some(u32::MAX),
        _ => None,
    }
}

/// The bytes `record` decodes to, with its coder held to the same memory
/// check sevenz-rust2 applies to it.
fn decode_header<R: Read + Seek>(
    source: &mut R,
    record: &EncodedRecord<'_>,
    max_bytes: u64,
    memory_kib: usize,
) -> Result<Vec<u8>, Stop> {
    if record.coders.iter().any(|coder| coder.id == METHOD_AES) {
        return Err(Stop::Refused(Refusal::Encrypted));
    }
    let decoded = record.decoded().ok_or(Stop::Unmodelled)?;
    let coder = record.coders[0];
    if decoded > max_bytes {
        return Err(Stop::Unmodelled);
    }
    let start = SIGNATURE_HEADER_SIZE
        .checked_add(record.pack_pos)
        .ok_or(Stop::Unmodelled)?;
    let unmodelled = |_| Stop::Unmodelled;
    source.seek(SeekFrom::Start(start)).map_err(unmodelled)?;
    let packed = source.by_ref().take(record.pack_size);
    let properties = coder.properties;
    match coder.id {
        METHOD_COPY => read_bounded(packed, decoded).map_err(unmodelled),
        METHOD_LZMA => {
            let (&byte, rest) = properties.split_first().ok_or(Stop::Unmodelled)?;
            let dictionary = rest
                .get(..4)
                .and_then(|d| d.try_into().ok())
                .map(u32::from_le_bytes)
                .ok_or(Stop::Unmodelled)?;
            let needed = lzma_get_memory_usage_by_props(dictionary, byte).map_err(unmodelled)?;
            fits(needed, memory_kib)?;
            let reader = LzmaReader::new_with_props(packed, decoded, byte, dictionary, None)
                .map_err(unmodelled)?;
            read_bounded(reader, decoded).map_err(unmodelled)
        }
        METHOD_LZMA2 => {
            let property = *properties.first().ok_or(Stop::Unmodelled)?;
            let dictionary = lzma2_dictionary(property).ok_or(Stop::Unmodelled)?;
            fits(lzma2_get_memory_usage(dictionary), memory_kib)?;
            read_bounded(Lzma2Reader::new(packed, dictionary, None), decoded).map_err(unmodelled)
        }
        _ => Err(Stop::Unmodelled),
    }
}

/// One coder of the first folder of an encoded header, as the record spells
/// it.
#[derive(Debug, Clone, Copy)]
struct Coder<'a> {
    id: &'a [u8],
    properties: &'a [u8],
}

/// An encoded-header record: where its first pack stream is and which coders
/// its first folder holds.
#[derive(Debug, Clone)]
struct EncodedRecord<'a> {
    pack_pos: u64,
    pack_size: u64,
    first_unpack_size: u64,
    coders: Vec<Coder<'a>>,
}

impl<'a> EncodedRecord<'a> {
    /// The record in `bytes`, or `None` for one sevenz-rust2 would refuse or
    /// the probe cannot follow.
    fn parse(bytes: &'a [u8]) -> Option<Self> {
        let mut bytes = Bytes(bytes);
        bytes.expect(K_ENCODED_HEADER)?;
        let streams = bytes.streams_info()?;
        Some(Self {
            pack_pos: streams.pack_pos,
            pack_size: streams.first_pack_size?,
            first_unpack_size: streams.folders.first_unpack_size?,
            coders: streams.folders.first_coders?,
        })
    }

    /// The size the header decodes to, when one coder decodes it.
    fn decoded(&self) -> Option<u64> {
        (self.coders.len() == 1).then_some(self.first_unpack_size)
    }
}

/// What the streams info of a header declares that the probe uses.
struct Streams<'a> {
    pack_pos: u64,
    first_pack_size: Option<u64>,
    folders: Folders<'a>,
}

#[derive(Default)]
struct Folders<'a> {
    count: u64,
    crcs: Digests<'a>,
    first_coders: Option<Vec<Coder<'a>>>,
    first_unpack_size: Option<u64>,
}

/// Which of a list of streams carry a CRC.
#[derive(Clone, Copy, Default)]
enum Digests<'a> {
    #[default]
    Undefined,
    All,
    Bits(&'a [u8]),
}

impl Digests<'_> {
    fn defined(self, index: u64) -> bool {
        match self {
            Self::Undefined => false,
            Self::All => true,
            Self::Bits(bits) => usize::try_from(index / 8)
                .ok()
                .and_then(|byte| bits.get(byte))
                .is_some_and(|byte| byte & (0x80 >> (index % 8)) != 0),
        }
    }
}

struct Bytes<'a>(&'a [u8]);

impl<'a> Bytes<'a> {
    fn byte(&mut self) -> Option<u8> {
        let (&first, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(first)
    }

    fn expect(&mut self, wanted: u8) -> Option<()> {
        (self.byte()? == wanted).then_some(())
    }

    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let (taken, rest) = self.0.split_at_checked(count)?;
        self.0 = rest;
        Some(taken)
    }

    fn skip_numbers(&mut self, count: u64) -> Option<()> {
        (0..count).try_for_each(|_| self.number().map(drop))
    }

    /// The digests of `count` streams, consuming them: a defined-flag (or a
    /// bit vector of them) and a 4-byte CRC for each defined stream.
    fn digests(&mut self, count: u64) -> Option<Digests<'a>> {
        let (digests, defined) = if self.byte()? == 0 {
            let bits = self.take(usize::try_from(count.div_ceil(8)).ok()?)?;
            let set = bits.iter().map(|b| u64::from(b.count_ones())).sum();
            (Digests::Bits(bits), set)
        } else {
            (Digests::All, count)
        };
        self.take(usize::try_from(defined.checked_mul(4)?).ok()?)?;
        Some(digests)
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

    /// The entry count of a plain header, read up to its files info.
    fn header_entries(&mut self) -> Option<DeclaredEntries> {
        self.expect(K_HEADER)?;
        let mut next = self.byte()?;
        if next == K_ARCHIVE_PROPERTIES {
            while self.byte()? != K_END {
                let size = self.number()?;
                self.take(usize::try_from(size).ok()?)?;
            }
            next = self.byte()?;
        }
        if next == K_ADDITIONAL_STREAMS_INFO {
            return None;
        }
        if next == K_MAIN_STREAMS_INFO {
            self.streams_info()?;
            next = self.byte()?;
        }
        match next {
            K_FILES_INFO => self.number().map(DeclaredEntries),
            K_END => Some(DeclaredEntries(0)),
            _ => None,
        }
    }

    /// A streams info, after its introducing id and through its end mark.
    fn streams_info(&mut self) -> Option<Streams<'a>> {
        let mut streams = Streams {
            pack_pos: 0,
            first_pack_size: None,
            folders: Folders::default(),
        };
        let mut next = self.byte()?;
        if next == K_PACK_INFO {
            self.pack_info(&mut streams)?;
            next = self.byte()?;
        }
        if next == K_UNPACK_INFO {
            streams.folders = self.unpack_info()?;
            next = self.byte()?;
        }
        if next == K_SUBSTREAMS_INFO {
            self.substreams_info(&streams.folders)?;
            next = self.byte()?;
        }
        (next == K_END).then_some(streams)
    }

    fn pack_info(&mut self, streams: &mut Streams<'a>) -> Option<()> {
        streams.pack_pos = self.number()?;
        let packs = self.number()?;
        loop {
            match self.byte()? {
                K_END => return Some(()),
                K_SIZE => {
                    if packs > 0 {
                        streams.first_pack_size = Some(self.number()?);
                    }
                    self.skip_numbers(packs.saturating_sub(1))?;
                }
                K_CRC => {
                    self.digests(packs)?;
                }
                _ => return None,
            }
        }
    }

    fn unpack_info(&mut self) -> Option<Folders<'a>> {
        self.expect(K_FOLDER)?;
        let mut folders = Folders {
            count: self.number()?,
            ..Folders::default()
        };
        self.expect(0)?;
        let mut out_streams = 0u64;
        for index in 0..folders.count {
            let coders = self.folder()?;
            out_streams = out_streams.checked_add(coders.len() as u64)?;
            if index == 0 {
                folders.first_coders = Some(coders);
            }
        }
        self.expect(K_CODERS_UNPACK_SIZE)?;
        for index in 0..out_streams {
            let size = self.number()?;
            if index == 0 {
                folders.first_unpack_size = Some(size);
            }
        }
        let mut next = self.byte()?;
        if next == K_CRC {
            folders.crcs = self.digests(folders.count)?;
            next = self.byte()?;
        }
        (next == K_END).then_some(folders)
    }

    /// One folder, as sevenz-rust2 reads it: coders with one output stream
    /// each, bind pairs, and the packed streams. Returns the coders.
    fn folder(&mut self) -> Option<Vec<Coder<'a>>> {
        let count = self.number()?;
        (count <= MAX_CODERS).then_some(())?;
        let mut coders = Vec::new();
        let mut in_streams = 0u64;
        for _ in 0..count {
            let flags = self.byte()?;
            (flags & CODER_RESERVED == 0).then_some(())?;
            let id = self.take(usize::from(flags & CODER_ID_SIZE_MASK))?;
            let (ins, outs) = if flags & CODER_COMPLEX != 0 {
                (self.number()?, self.number()?)
            } else {
                (1, 1)
            };
            (outs == 1).then_some(())?;
            in_streams = in_streams.checked_add(ins)?;
            (in_streams <= MAX_IN_STREAMS).then_some(())?;
            let properties = if flags & CODER_HAS_PROPERTIES != 0 {
                let size = self.number()?;
                self.take(usize::try_from(size).ok()?)?
            } else {
                &[]
            };
            coders.push(Coder { id, properties });
        }
        let bind_count = count.checked_sub(1)?;
        self.skip_numbers(bind_count.checked_mul(2)?)?;
        let packed = in_streams.checked_sub(bind_count)?;
        (packed > 0).then_some(())?;
        if packed > 1 {
            self.skip_numbers(packed)?;
        }
        Some(coders)
    }

    fn substreams_info(&mut self, folders: &Folders<'_>) -> Option<()> {
        let mut sizes = 0u64;
        let mut digests = (0..folders.count)
            .filter(|&index| !folders.crcs.defined(index))
            .count() as u64;
        let mut next = self.byte()?;
        if next == K_NUM_UNPACK_STREAM {
            (sizes, digests) = (0, 0);
            for index in 0..folders.count {
                let streams = self.number()?;
                sizes = sizes.checked_add(streams.saturating_sub(1))?;
                if streams != 1 || !folders.crcs.defined(index) {
                    digests = digests.checked_add(streams)?;
                }
            }
            next = self.byte()?;
        }
        if next == K_SIZE {
            self.skip_numbers(sizes)?;
            next = self.byte()?;
        }
        while next != K_END {
            (next == K_CRC).then_some(())?;
            self.digests(digests)?;
            next = self.byte()?;
        }
        Some(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use sevenz_rust2::Archive;
    use sevenz_rust2::ArchiveEntry;
    use sevenz_rust2::ArchiveWriter;
    use sevenz_rust2::Password;
    use sevenz_rust2::SourceReader;
    use std::assert_matches;
    use std::io::Cursor;
    use std::path::PathBuf;

    const SIMPLE: &[u8] = include_bytes!("../../../../../tests/fixtures/simple.7z");
    const LARGE_FILE: &[u8] = include_bytes!("../../../../../tests/fixtures/large-file.7z");
    const EMPTY: &[u8] = include_bytes!("../../../../../tests/fixtures/empty.7z");
    const ROOMY: u64 = 1 << 20;
    const MEMORY_KIB: usize = 1 << 20;

    fn probed(bytes: &[u8]) -> DeclaredHeader {
        probe(&mut Cursor::new(bytes), ROOMY)
    }

    fn read(bytes: &[u8], max_bytes: u64, memory_kib: usize) -> HeaderEntries {
        header_entries(&mut Cursor::new(bytes), max_bytes, memory_kib)
    }

    fn entries(bytes: &[u8]) -> HeaderEntries {
        read(bytes, ROOMY, MEMORY_KIB)
    }

    fn declared(count: u64) -> HeaderEntries {
        HeaderEntries::Declared(DeclaredEntries(count))
    }

    fn parsed_entries(bytes: &[u8]) -> u64 {
        let archive = Archive::read(&mut Cursor::new(bytes), &Password::empty()).unwrap();
        archive.files.len() as u64
    }

    #[test]
    fn an_encoded_header_declares_its_decoded_size() {
        assert_matches!(
            probed(SIMPLE),
            DeclaredHeader::Encoded { decoded } if decoded > 0 && decoded < 4096
        );
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
    fn an_encoded_record_over_the_byte_limit_is_not_read() {
        let size = u64::from_le_bytes(SIMPLE[20..28].try_into().unwrap());
        let at = |max| probe(&mut Cursor::new(SIMPLE), max);
        assert_eq!(at(size - 1), DeclaredHeader::Unrecognized);
        assert_matches!(at(size), DeclaredHeader::Encoded { .. });
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

    #[test]
    fn an_encoded_header_declares_the_entries_of_its_decoded_bytes() {
        assert_eq!(entries(SIMPLE), declared(parsed_entries(SIMPLE)));
    }

    #[test]
    fn a_plain_header_declares_its_entries() {
        assert_eq!(entries(LARGE_FILE), declared(parsed_entries(LARGE_FILE)));
    }

    #[test]
    fn every_fixture_sevenz_rust2_parses_declares_the_count_it_builds() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
        let mut walked = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|ext| ext != "7z") {
                continue;
            }
            let bytes = std::fs::read(&path).unwrap();
            let Ok(archive) = Archive::read(&mut Cursor::new(&bytes), &Password::empty()) else {
                continue;
            };
            if bytes[20..28] == [0; 8] {
                continue;
            }
            assert_eq!(
                entries(&bytes),
                declared(archive.files.len() as u64),
                "{path:?}"
            );
            walked += 1;
        }
        assert!(walked > 10, "only {walked} fixtures walked");
    }

    fn written_archive(files: usize, dirs: usize, solid: bool) -> Vec<u8> {
        let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
        let mut entries = Vec::new();
        let mut readers = Vec::new();
        for i in 0..files {
            let mut entry = ArchiveEntry::new_file(&format!("dir/file-{i}.txt"));
            entry.has_stream = true;
            entry.size = 9;
            entries.push(entry);
            readers.push(SourceReader::from(Cursor::new(b"some data".to_vec())));
        }
        for i in 0..dirs {
            entries.push(ArchiveEntry::new_directory(&format!("d{i}")));
        }
        if solid {
            let streamed = entries.iter().filter(|e| e.has_stream).count();
            assert_eq!(streamed, readers.len());
            let (with, without): (Vec<_>, Vec<_>) = entries.into_iter().partition(|e| e.has_stream);
            writer.push_archive_entries(with, readers).unwrap();
            for entry in without {
                writer
                    .push_archive_entry::<Cursor<Vec<u8>>>(entry, None)
                    .unwrap();
            }
        } else {
            let mut readers = readers.into_iter();
            for entry in entries {
                let reader = entry.has_stream.then(|| readers.next().unwrap());
                writer.push_archive_entry(entry, reader).unwrap();
            }
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn a_large_entry_count_is_read_as_declared() {
        let mut header = vec![K_HEADER, K_FILES_INFO, 0xFF];
        header.extend(u64::MAX.to_le_bytes());
        assert_eq!(
            Bytes(&header).header_entries().map(DeclaredEntries::get),
            Some(u64::MAX)
        );
    }

    #[test]
    fn a_header_without_files_info_declares_no_entries() {
        let header = [K_HEADER, K_END];
        assert_eq!(
            Bytes(&header).header_entries().map(DeclaredEntries::get),
            Some(0)
        );
    }

    #[test]
    fn a_header_the_walker_does_not_model_declares_nothing() {
        let additional = [K_HEADER, K_ADDITIONAL_STREAMS_INFO, K_END];
        assert!(Bytes(&additional).header_entries().is_none());
        let truncated = [K_HEADER, K_MAIN_STREAMS_INFO, K_PACK_INFO, 0x00];
        assert!(Bytes(&truncated).header_entries().is_none());
        let junk = [K_HEADER, 0x7E];
        assert!(Bytes(&junk).header_entries().is_none());
    }

    fn byte(value: usize) -> u8 {
        u8::try_from(value).unwrap()
    }

    /// An encoded-header record whose first folder holds `coders`, each given
    /// as `(id, properties)`, bound in a chain.
    fn record_of(coders: &[(&[u8], &[u8])], pack_size: u8, decoded: u8) -> Vec<u8> {
        let mut record = vec![
            K_ENCODED_HEADER,
            K_PACK_INFO,
            0,
            1,
            K_SIZE,
            pack_size,
            K_END,
        ];
        record.extend([K_UNPACK_INFO, K_FOLDER, 1, 0, byte(coders.len())]);
        for (id, properties) in coders {
            let props = if properties.is_empty() {
                0
            } else {
                CODER_HAS_PROPERTIES
            };
            record.push(byte(id.len()) | props);
            record.extend(*id);
            if !properties.is_empty() {
                record.push(byte(properties.len()));
                record.extend(*properties);
            }
        }
        for coder in 1..coders.len() {
            record.extend([byte(coder - 1), byte(coder)]);
        }
        record.push(K_CODERS_UNPACK_SIZE);
        record.extend(vec![decoded; coders.len()]);
        record.extend([K_END, K_END]);
        record
    }

    #[test]
    fn a_record_with_one_coder_has_a_decoded_size() {
        let record = record_of(&[(METHOD_LZMA2, &[1])], 7, 5);
        assert_eq!(EncodedRecord::parse(&record).unwrap().decoded(), Some(5));
    }

    #[test]
    fn a_record_with_several_coders_has_no_single_decoded_size() {
        let record = record_of(&[(METHOD_COPY, &[]), (METHOD_LZMA2, &[1])], 7, 5);
        let parsed = EncodedRecord::parse(&record).unwrap();
        assert_eq!(parsed.coders.len(), 2);
        assert_eq!(parsed.decoded(), None);
        assert_eq!(probed_record(&record), DeclaredHeader::Unrecognized);
    }

    /// The archive made of `record` as its next header, with `packed` bytes
    /// before it.
    fn archive_with_record(packed: &[u8], record: &[u8]) -> Vec<u8> {
        let mut bytes = SEVENZ_MAGIC.to_vec();
        bytes.extend([0, 4, 0, 0, 0, 0]);
        bytes.extend((packed.len() as u64).to_le_bytes());
        bytes.extend((record.len() as u64).to_le_bytes());
        bytes.extend([0u8; 4]);
        bytes.extend(packed);
        bytes.extend(record);
        bytes
    }

    fn probed_record(record: &[u8]) -> DeclaredHeader {
        probed(&archive_with_record(&[], record))
    }

    #[test]
    fn a_header_with_several_coders_is_unmodelled() {
        let record = record_of(&[(METHOD_COPY, &[]), (METHOD_LZMA2, &[1])], 4, 4);
        let bytes = archive_with_record(&[0; 4], &record);
        assert_eq!(entries(&bytes), HeaderEntries::Unmodelled);
    }

    #[test]
    fn an_encryption_coder_anywhere_in_the_folder_is_refused_as_encrypted() {
        let on_chain = record_of(&[(METHOD_LZMA, &[0; 5]), (METHOD_AES, &[0; 4])], 4, 4);
        let single = record_of(&[(METHOD_AES, &[0; 4])], 4, 4);
        let mut off_chain = record_of(&[(METHOD_AES, &[0; 4]), (METHOD_LZMA, &[0; 5])], 4, 4);
        let at = off_chain
            .windows(3)
            .position(|w| w == [0, 1, K_CODERS_UNPACK_SIZE])
            .unwrap();
        off_chain[at + 1] = 0;
        for record in [on_chain, single, off_chain] {
            let bytes = archive_with_record(&[0; 4], &record);
            assert_eq!(
                entries(&bytes),
                HeaderEntries::Refused(Refusal::Encrypted),
                "{record:?}"
            );
        }
    }

    #[test]
    fn a_coder_the_probe_does_not_decode_is_unmodelled() {
        let mut bytes = SIMPLE.to_vec();
        let at = bytes.windows(3).position(|w| w == METHOD_LZMA).unwrap();
        bytes[at] = 0x7E;
        assert_eq!(entries(&bytes), HeaderEntries::Unmodelled);
    }

    #[test]
    fn an_archive_without_a_header_to_read_is_left_to_sevenz_rust2() {
        let mut truncated = SIMPLE.to_vec();
        truncated.truncate(SIMPLE.len() - 8);
        assert_eq!(entries(&truncated), HeaderEntries::NotApplicable);
        assert_eq!(entries(EMPTY), HeaderEntries::NotApplicable);
        assert_eq!(entries(&SIMPLE[..20]), HeaderEntries::NotApplicable);
        let mut no_magic = SIMPLE.to_vec();
        no_magic[0] ^= 1;
        assert_eq!(entries(&no_magic), HeaderEntries::NotApplicable);
    }

    #[test]
    fn a_missing_start_header_on_a_longer_file_is_unmodelled() {
        let mut bytes = EMPTY.to_vec();
        bytes.extend([0x01, 0x00]);
        assert_eq!(entries(&bytes), HeaderEntries::Unmodelled);
    }

    #[test]
    fn a_coder_over_the_memory_limit_is_refused_for_memory() {
        assert_eq!(
            read(SIMPLE, ROOMY, 1),
            HeaderEntries::Refused(Refusal::Memory)
        );
        assert_matches!(read(SIMPLE, ROOMY, MEMORY_KIB), HeaderEntries::Declared(_));
    }

    /// Every fixture sevenz-rust2 parses, with a next header to mutate: plain
    /// and encoded headers both.
    static FIXTURE_SEEDS: std::sync::LazyLock<Vec<Vec<u8>>> = std::sync::LazyLock::new(|| {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
        let mut seeds: Vec<Vec<u8>> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "7z"))
            .map(|path| std::fs::read(path).unwrap())
            .filter(|bytes| bytes[20..28] != [0; 8])
            .filter(|bytes| Archive::read(&mut Cursor::new(bytes), &Password::empty()).is_ok())
            .collect();
        seeds.sort();
        seeds
    });

    #[test]
    fn the_seeds_hold_plain_and_encoded_headers() {
        let first_ids: Vec<u8> = FIXTURE_SEEDS
            .iter()
            .map(|bytes| {
                let offset =
                    usize::try_from(u64::from_le_bytes(bytes[12..20].try_into().unwrap())).unwrap();
                bytes[32 + offset]
            })
            .collect();
        assert!(first_ids.contains(&K_HEADER));
        assert!(first_ids.contains(&K_ENCODED_HEADER));
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut crc = flate2::Crc::new();
        crc.update(data);
        crc.sum()
    }

    /// `bytes` with the byte at `at` of its next header replaced and both
    /// checksums refreshed, so that only the header's content is wrong.
    fn with_mutated_header(bytes: &[u8], at: usize, value: u8) -> Vec<u8> {
        let mut out = bytes.to_vec();
        let offset = usize::try_from(u64::from_le_bytes(out[12..20].try_into().unwrap())).unwrap();
        let start = 32 + offset;
        let at = start + at % (out.len() - start);
        out[at] = value;
        let header_crc = crc32(&out[start..]);
        out[28..32].copy_from_slice(&header_crc.to_le_bytes());
        let start_crc = crc32(&out[12..32]);
        out[8..12].copy_from_slice(&start_crc.to_le_bytes());
        out
    }

    proptest::proptest! {

        #[test]
        fn a_changed_header_never_declares_fewer_entries_than_sevenz_rust2_builds(
            files in 1usize..30,
            dirs in 0usize..30,
            solid in proptest::prelude::any::<bool>(),
            at in 0usize..4096,
            value in proptest::prelude::any::<u8>(),
        ) {
            let bytes = with_mutated_header(&written_archive(files, dirs, solid), at, value);
            if let Ok(archive) = Archive::read(&mut Cursor::new(&bytes), &Password::empty()) {
                let built = archive.files.len() as u64;
                match entries(&bytes) {
                    HeaderEntries::Declared(count) => {
                        proptest::prop_assert!(count.get() >= built, "{} < {built}", count.get());
                    }
                    HeaderEntries::NotApplicable => proptest::prop_assert_eq!(built, 0),
                    HeaderEntries::Refused(_) | HeaderEntries::Unmodelled => {}
                }
            }
        }

        #[test]
        fn a_changed_fixture_header_never_declares_fewer_entries_than_sevenz_rust2_builds(
            fixture in 0usize..1024,
            at in 0usize..4096,
            value in proptest::prelude::any::<u8>(),
        ) {
            let source = &FIXTURE_SEEDS[fixture % FIXTURE_SEEDS.len()];
            let bytes = with_mutated_header(source, at, value);
            if let Ok(archive) = Archive::read(&mut Cursor::new(&bytes), &Password::empty()) {
                let built = archive.files.len() as u64;
                match entries(&bytes) {
                    HeaderEntries::Declared(count) => {
                        proptest::prop_assert!(count.get() >= built);
                    }
                    HeaderEntries::NotApplicable => proptest::prop_assert_eq!(built, 0),
                    HeaderEntries::Refused(_) | HeaderEntries::Unmodelled => {}
                }
            }
        }

        #[test]
        fn the_declared_count_is_the_count_sevenz_rust2_builds(
            files in 0usize..60,
            dirs in 0usize..60,
            solid in proptest::prelude::any::<bool>(),
        ) {
            let bytes = written_archive(files, dirs, solid);
            proptest::prop_assert_eq!(entries(&bytes), declared(parsed_entries(&bytes)));
        }
    }

    /// An archive whose plain header skips `padding` bytes of archive
    /// properties and then declares `entries` entries.
    fn padded_plain_archive(padding: usize, entries: u8) -> Vec<u8> {
        let mut header = vec![K_HEADER, K_ARCHIVE_PROPERTIES, 0x7F];
        header.extend([0xC0 | u8::try_from(padding >> 16).unwrap()]);
        header.extend(u16::try_from(padding & 0xFFFF).unwrap().to_le_bytes());
        header.extend(vec![0u8; padding]);
        header.extend([K_END, K_FILES_INFO, entries, K_END]);
        let mut bytes = SEVENZ_MAGIC.to_vec();
        bytes.extend([0, 4, 0, 0, 0, 0]);
        bytes.extend(0u64.to_le_bytes());
        bytes.extend((header.len() as u64).to_le_bytes());
        bytes.extend([0u8; 4]);
        bytes.extend(header);
        bytes
    }

    #[test]
    fn archive_properties_are_skipped_on_the_way_to_the_files_info() {
        assert_eq!(entries(&padded_plain_archive(10, 3)), declared(3));
    }

    #[test]
    fn a_header_over_the_byte_limit_is_not_read() {
        let bytes = padded_plain_archive(5000, 3);
        let size = u64::from_le_bytes(bytes[20..28].try_into().unwrap());
        assert_eq!(
            read(&bytes, size - 1, MEMORY_KIB),
            HeaderEntries::NotApplicable
        );
        assert_eq!(read(&bytes, size, MEMORY_KIB), declared(3));
    }
}
