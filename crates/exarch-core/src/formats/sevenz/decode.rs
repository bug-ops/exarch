//! Block decoding: walks the entries of a parsed archive in archive order and
//! hands each to a callback, decoding blocks sequentially or on worker threads.

use super::SIGNATURE_HEADER_SIZE;
use super::admit::block_span;
use super::admit::lzma2_dict_size;
use super::header::BlockIndex;
use super::header::SevenZHeader;
use super::lzma2::DecodeKnobs;
use super::lzma2::Lzma2Stream;
use super::lzma2::with_parallel_reader;
use crate::ParallelDecode;
use sevenz_rust2::BlockDecoder;
use sevenz_rust2::Password;
use std::io;
use std::io::Read;
use std::io::Seek;

/// Result of an entry callback, as sevenz-rust2 defines it.
pub(super) type EntryResult = std::result::Result<bool, sevenz_rust2::Error>;

/// Verifies the CRC32 of the bytes read through it once `remaining` of them
/// were read, with the error sevenz-rust2 raises for a mismatch.
pub(super) struct CrcChecked<R> {
    inner: R,
    crc: flate2::Crc,
    expected: u64,
    remaining: u64,
}

impl<R: Read> CrcChecked<R> {
    fn new(inner: R, remaining: u64, expected: u64) -> Self {
        Self {
            inner,
            crc: flate2::Crc::new(),
            expected,
            remaining,
        }
    }
}

impl<R: Read> Read for CrcChecked<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let size = self.inner.read(buf)?;
        self.crc.update(&buf[..size]);
        self.remaining = self.remaining.saturating_sub(size as u64);
        if self.remaining == 0 && u64::from(self.crc.sum()) != self.expected {
            return Err(io::Error::other(
                sevenz_rust2::Error::ChecksumVerificationFailed,
            ));
        }
        Ok(size)
    }
}

/// Decodes the files of one block and hands each to `each`.
///
/// Blocks that hold a single LZMA2 stream with enough independent runs are
/// decoded ahead on worker threads within the `parallel` lookahead budget;
/// every other block, and every block under `ParallelDecode::Sequential`,
/// goes through sevenz-rust2's single-threaded `BlockDecoder`. Both paths hand
/// `each` the same bytes for a valid stream. For a corrupt one both deliver
/// every byte decoded before the failure, so the same file fails with the same
/// error kind; only how many leading bytes that file received can differ.
///
/// Returns `Ok(false)` when `each` stopped the walk.
pub(super) fn decode_block_entries<R: Read + Seek>(
    source: &mut R,
    header: &SevenZHeader,
    block_index: BlockIndex,
    parallel: ParallelDecode,
    knobs: DecodeKnobs,
    each: &mut impl FnMut(&sevenz_rust2::ArchiveEntry, &mut dyn Read) -> EntryResult,
) -> EntryResult {
    let password = Password::empty();
    let archive = header.archive();
    let span = block_span(header, block_index);
    let (first, count) = (span.start, span.len());
    let plan = match parallel {
        ParallelDecode::Bounded(lookahead) if knobs.threads.get() > 1 => {
            parallel_stream(header, block_index, first..first + count, knobs.min_unit)
                .map(|stream| (stream, lookahead))
        }
        _ => None,
    };
    let Some((stream, lookahead)) = plan else {
        return BlockDecoder::new(1, block_index.get(), archive, &password, source)
            .for_each_entries(each);
    };

    // The dry run fails exactly as the sequential path would on a coder graph
    // or property it rejects, before any thread starts.
    BlockDecoder::new(1, block_index.get(), archive, &password, &mut *source)
        .for_each_entries(&mut |_, _| Ok(false))?;
    let block = header.block(block_index);

    with_parallel_reader(&mut *source, stream, knobs, lookahead.get(), |reader| {
        let mut block_reader: Box<dyn Read + '_> = if block.has_crc {
            Box::new(CrcChecked::new(reader, block.get_unpack_size(), block.crc))
        } else {
            Box::new(reader)
        };
        for file in &header.files()[first..first + count] {
            if is_sevenz_payload(file) {
                let mut decoder: Box<dyn Read + '_> = Box::new((&mut block_reader).take(file.size));
                if file.has_crc {
                    decoder = Box::new(CrcChecked::new(decoder, file.size, file.crc));
                }
                if !each(file, &mut decoder)? {
                    return Ok(false);
                }
            } else {
                let empty: &mut dyn Read = &mut io::empty();
                if !each(file, empty)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    })
}

/// The LZMA2 stream of a block that can be decoded in parallel, or `None`.
///
/// Eligible blocks are one LZMA2 coder over one pack stream whose files (the
/// `files` span the decoder walks) account for the whole output, with room for
/// at least two runs of `min_unit`.
pub(super) fn parallel_stream(
    header: &SevenZHeader,
    block_index: BlockIndex,
    files: std::ops::Range<usize>,
    min_unit: u64,
) -> Option<Lzma2Stream> {
    use sevenz_rust2::EncoderMethod;

    let archive = header.archive();
    let block = header.block(block_index);
    let [coder] = block.coders.as_slice() else {
        return None;
    };
    if coder.encoder_method_id() != EncoderMethod::ID_LZMA2 {
        return None;
    }
    let first_pack = header.block_first_pack(block_index);
    let end_pack = header
        .next_block_first_pack(block_index)
        .unwrap_or_else(|| archive.pack_sizes().len());
    if end_pack.checked_sub(first_pack) != Some(1) {
        return None;
    }
    let output_len = block.get_unpack_size();
    if output_len < min_unit.saturating_mul(2) {
        return None;
    }
    let files_len = header
        .files()
        .get(files)?
        .iter()
        .filter(|file| is_sevenz_payload(file))
        .try_fold(0u64, |sum, file| sum.checked_add(file.size))?;
    if files_len != output_len {
        return None;
    }
    let offset = SIGNATURE_HEADER_SIZE
        .checked_add(archive.pack_pos())?
        .checked_add(*header.pack_stream_offsets().get(first_pack)?)?;
    Some(Lzma2Stream {
        offset,
        len: *archive.pack_sizes().get(first_pack)?,
        output_len,
        dict_size: lzma2_dict_size(coder.properties())?,
    })
}

/// The span of `block` once checked against the file-to-block map: every file
/// the decoder would hand out must be mapped to the block.
///
/// Admission refuses a block whose span differs from its mapped files before
/// anything is decoded; this is the same rule at the point of use.
pub(super) fn mapped_block_span(
    header: &SevenZHeader,
    block: BlockIndex,
) -> std::result::Result<std::ops::Range<usize>, sevenz_rust2::Error> {
    let span = block_span(header, block);
    let mapped = span
        .clone()
        .all(|file| header.file_block(file) == Some(block));
    if mapped {
        Ok(span)
    } else {
        Err(sevenz_rust2::Error::Other(
            "7z block decodes files other than the ones mapped to it".into(),
        ))
    }
}

/// Hands each entry to `each` in archive order.
///
/// A file without data is handed over where it stands; the first file of a
/// block decodes the whole block, which hands over the block's files, so the
/// archive's own order is what every other operation (`list`, `verify`,
/// TAR, ZIP) uses. Blocks without files are decoded as they come, to keep
/// their errors; a block no file maps to is never decoded.
///
/// Returns an error when the entries handed over are not exactly the entries
/// of the archive, once each.
pub(super) fn decode_archive_entries<R: Read + Seek>(
    source: &mut R,
    header: &SevenZHeader,
    parallel: ParallelDecode,
    knobs: DecodeKnobs,
    each: &mut impl FnMut(&sevenz_rust2::ArchiveEntry, &mut dyn Read) -> EntryResult,
) -> std::result::Result<(), sevenz_rust2::Error> {
    let mut next_block = 0;
    let mut handed = 0usize;
    for (index, file) in header.files().iter().enumerate() {
        match header.file_block(index) {
            None => {
                let empty: &mut dyn Read = &mut io::empty();
                if !each(file, empty)? {
                    return Ok(());
                }
                handed += 1;
            }
            Some(block) if block.get() >= next_block => {
                for fileless in header
                    .block_indices()
                    .skip(next_block)
                    .take(block.get() - next_block)
                {
                    if !block_span(header, fileless).is_empty() {
                        return Err(sevenz_rust2::Error::Other(
                            "7z block with streams is skipped by the file order".into(),
                        ));
                    }
                    decode_block_entries(source, header, fileless, parallel, knobs, each)?;
                }
                let span = mapped_block_span(header, block)?;
                if !decode_block_entries(source, header, block, parallel, knobs, each)? {
                    return Ok(());
                }
                handed += span.len();
                next_block = block.get() + 1;
            }
            Some(_) => {}
        }
    }
    if handed == header.files().len() {
        Ok(())
    } else {
        Err(sevenz_rust2::Error::Other(
            "7z entries were not handed over exactly once".into(),
        ))
    }
}

/// Reads past a payload file that has no integrity slot (an entry the listing
/// dropped) so the rest of its solid block stays aligned; returns whether the
/// scan can continue.
pub(super) fn skip_payload(file: &sevenz_rust2::ArchiveEntry, reader: &mut dyn Read) -> bool {
    std::io::copy(&mut reader.take(file.size), &mut std::io::sink()).is_ok()
}

pub(super) fn is_sevenz_payload(file: &sevenz_rust2::ArchiveEntry) -> bool {
    file.has_stream && file.size > 0
}
