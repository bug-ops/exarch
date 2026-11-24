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
use super::turn_gate::TurnGate;
use crate::ParallelDecode;
use crate::encryption::kdf::AesTurn;
use crate::formats::bounded_read::read_prefix;
use crate::formats::source_fault::is_sevenz_checksum;
use sevenz_rust2::BlockDecoder;
use std::cell::Cell;
use std::cell::RefCell;
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
        let filled = read_prefix(&mut self.inner, buf)?;
        self.crc.update(filled);
        let size = filled.len();
        self.remaining = self.remaining.saturating_sub(size as u64);
        if self.remaining == 0 && u64::from(self.crc.sum()) != self.expected {
            return Err(io::Error::other(
                sevenz_rust2::Error::ChecksumVerificationFailed,
            ));
        }
        Ok(size)
    }
}

/// A checksum mismatch a callback saw while reading entry `entry`.
#[derive(Debug, PartialEq, Eq)]
struct SeenMismatch {
    entry: usize,
    message: String,
}

/// Reader that records, against the entry being read, the checksum mismatch it
/// failed a read with, when `arms` is set.
struct FailureTap<'a, R> {
    inner: R,
    entry: usize,
    arms: bool,
    mismatch: &'a RefCell<Option<SeenMismatch>>,
}

impl<R: Read> Read for FailureTap<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf).inspect_err(|e| {
            if self.arms && is_sevenz_checksum(e) {
                *self.mismatch.borrow_mut() = Some(SeenMismatch {
                    entry: self.entry,
                    message: e.to_string(),
                });
            }
        })
    }
}

fn handover_violation() -> sevenz_rust2::Error {
    sevenz_rust2::Error::Other("7z entries were not handed over exactly once".into())
}

/// Decodes one block through sevenz-rust2's `BlockDecoder`, checking each
/// entry's CRC here so a mismatch does not end the block (see
/// [`SevenZHeader::unchecked_crc_archive`]).
///
/// When it drains an entry after the callback, the decoder repeats a checksum
/// mismatch the callback already saw, as a plain I/O error that has lost its
/// type but keeps its message. That repeat, and only that, is swallowed:
/// `each` handled the mismatch of that same entry. A mismatch armed the
/// swallow when the decoder raised it, or when this module's own entry check
/// raised it on the block's last entry, where the decoder's repeat can only
/// concern that entry. A different error, a
/// mismatch of another entry or one the callback never saw, and any error
/// `each` returned itself still propagate.
fn sequential_block<R: Read + Seek>(
    source: &mut R,
    header: &SevenZHeader,
    block_index: BlockIndex,
    password: &sevenz_rust2::Password,
    each: &mut impl FnMut(&sevenz_rust2::ArchiveEntry, &mut dyn Read) -> EntryResult,
) -> EntryResult {
    // The turn covers the decoder set-up, where an AES key is derived. The
    // gate gives it up before the decoder first calls the source when the key
    // is derived before that; otherwise it is given up before the first entry
    // reaches user code.
    let turn = RefCell::new(
        (header.is_block_encrypted(block_index) && block_has_streams(header, block_index))
            .then(AesTurn::acquire),
    );
    if let Some(held) = turn.borrow_mut().as_mut()
        && let Err(error) = header.enter_aes_block(held, block_index, password)
    {
        // The set-up already recorded this block's key; no decoder is built.
        held.forget_slot_key();
        return Err(sevenz_rust2::Error::from(error));
    }
    let mismatch = RefCell::new(None);
    let callback_failed = Cell::new(false);
    let last_entry = Cell::new(0);
    let last_streamed = block_span(header, block_index)
        .rev()
        .find(|&i| header.files().get(i).is_some_and(|file| file.has_stream));
    let mut next_file = header.block_first_file(block_index);
    let mut gate = TurnGate::new(source, &turn, header.aes_coder_leads_block(block_index));
    let result = BlockDecoder::new(
        1,
        block_index.get(),
        header.unchecked_crc_archive(),
        password,
        &mut gate,
    )
    .for_each_entries(&mut |_, reader| {
        drop(turn.borrow_mut().take());
        let index = next_file;
        let file = header.files().get(index).ok_or_else(handover_violation)?;
        next_file = next_file.saturating_add(1);
        last_entry.set(index);
        let below = FailureTap {
            inner: reader,
            entry: index,
            arms: true,
            mismatch: &mismatch,
        };
        let mut entry: Box<dyn Read + '_> = if file.has_stream && file.has_crc {
            Box::new(CrcChecked::new(below, file.size, file.crc))
        } else {
            Box::new(below)
        };
        let mut tapped = FailureTap {
            inner: entry.as_mut(),
            entry: index,
            arms: last_streamed == Some(index),
            mismatch: &mismatch,
        };
        each(file, &mut tapped).inspect_err(|_| callback_failed.set(true))
    });
    if let Some(held) = turn.borrow_mut().as_mut()
        && result.is_err()
    {
        // The decoder was never built, so the key it would have derived is
        // not the one the slot holds.
        held.forget_slot_key();
    }
    drop(turn);
    match result {
        Err(sevenz_rust2::Error::Io(e, _))
            if !callback_failed.get()
                && mismatch.borrow().as_ref().is_some_and(|seen| {
                    seen.entry == last_entry.get() && seen.message == e.to_string()
                }) =>
        {
            Ok(true)
        }
        other => other,
    }
}

/// Whether the decoder builds anything for the block: sevenz-rust2 skips a
/// block that declares no sub-streams, and then derives no key. Its stream map
/// gives such a block an empty file span and every block that declares
/// sub-streams a first file that has a stream, so the two tests agree.
fn block_has_streams(header: &SevenZHeader, block_index: BlockIndex) -> bool {
    block_span(header, block_index).any(|i| header.files().get(i).is_some_and(|f| f.has_stream))
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
    let password = header.block_password();
    let archive = header.archive();
    let span = block_span(header, block_index);
    let (first, count) = (span.start, span.len());
    let end = first.saturating_add(count);
    let plan = match parallel {
        ParallelDecode::Bounded(lookahead) if knobs.threads.get() > 1 => {
            parallel_stream(header, block_index, first..end, knobs.min_unit)
                .map(|stream| (stream, lookahead))
        }
        _ => None,
    };
    let Some((stream, lookahead)) = plan else {
        return sequential_block(source, header, block_index, &password, each);
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
        for file in header
            .files()
            .get(first..end)
            .ok_or_else(handover_violation)?
        {
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

/// Where a decode failure that did not come from the entry callback arose.
#[derive(Debug)]
pub(super) enum DecodeFailure {
    /// While decoding or draining `block`.
    Block {
        block: BlockIndex,
        error: sevenz_rust2::Error,
    },
    /// In the walk itself: entries not handed over exactly once.
    Handover(sevenz_rust2::Error),
}

#[cfg(test)]
impl DecodeFailure {
    pub(super) fn into_error(self) -> sevenz_rust2::Error {
        match self {
            Self::Block { error, .. } | Self::Handover(error) => error,
        }
    }
}

/// Hands each entry to `each` in archive order.
///
/// A file without data is handed over where it stands; the first file of a
/// block decodes the whole block, which hands over the block's files, so the
/// archive's own order is what every other operation (`list`, `verify`,
/// TAR, ZIP) uses. Blocks without sub-streams are decoded as they come, to keep
/// their errors; a block no file maps to is never decoded, and admission
/// refuses one that holds data.
///
/// Returns an error when the entries handed over are not exactly the entries
/// of the archive, once each.
pub(super) fn decode_archive_entries<R: Read + Seek>(
    source: &mut R,
    header: &SevenZHeader,
    parallel: ParallelDecode,
    knobs: DecodeKnobs,
    each: &mut impl FnMut(&sevenz_rust2::ArchiveEntry, &mut dyn Read) -> EntryResult,
) -> std::result::Result<(), DecodeFailure> {
    let mut next_block = 0;
    let mut handed = 0usize;
    for (index, file) in header.files().iter().enumerate() {
        match header.file_block(index) {
            None => {
                let empty: &mut dyn Read = &mut io::empty();
                if !each(file, empty).map_err(DecodeFailure::Handover)? {
                    return Ok(());
                }
                handed = handed.saturating_add(1);
            }
            Some(block) if block.get() >= next_block => {
                for fileless in header
                    .block_indices()
                    .skip(next_block)
                    .take(block.get().saturating_sub(next_block))
                {
                    decode_block_entries(source, header, fileless, parallel, knobs, each).map_err(
                        |error| DecodeFailure::Block {
                            block: fileless,
                            error,
                        },
                    )?;
                }
                let span = block_span(header, block);
                let walked = decode_block_entries(source, header, block, parallel, knobs, each)
                    .map_err(|error| DecodeFailure::Block { block, error })?;
                if !walked {
                    return Ok(());
                }
                handed = handed.saturating_add(span.len());
                next_block = block.get().saturating_add(1);
            }
            Some(_) => {}
        }
    }
    (handed == header.files().len()).ok_or_else(|| DecodeFailure::Handover(handover_violation()))
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

#[cfg(test)]
#[cfg(feature = "encryption")]
mod tests {
    use super::super::header::HeaderLimit;
    use super::super::header::open_sevenz_header;
    use super::*;
    use crate::encryption::Credentials;
    use sevenz_rust2::ArchiveEntry;
    use sevenz_rust2::ArchiveWriter;
    use sevenz_rust2::EncoderMethod;
    use sevenz_rust2::encoder_options::AesEncoderOptions;
    use std::io::Cursor;
    use std::io::SeekFrom;
    use std::sync::Arc;

    struct TurnWatchingSource {
        inner: Cursor<Vec<u8>>,
        calls_under_turn: usize,
        calls_outside_turn: usize,
    }

    impl TurnWatchingSource {
        fn note(&mut self) {
            if AesTurn::held_by_current_thread() {
                self.calls_under_turn += 1;
            } else {
                self.calls_outside_turn += 1;
            }
        }
    }

    impl Read for TurnWatchingSource {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.note();
            self.inner.read(buf)
        }
    }

    impl Seek for TurnWatchingSource {
        fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
            self.note();
            self.inner.seek(to)
        }
    }

    fn aes() -> sevenz_rust2::EncoderConfiguration {
        let mut options = AesEncoderOptions::new(sevenz_rust2::Password::new("pw"));
        options.num_cycles_power = 8;
        options.into()
    }

    /// What decoding the only block of an archive made with `methods` showed.
    struct Decoded {
        aes_leads: bool,
        body: Vec<u8>,
        calls_outside_turn: usize,
        calls_under_turn: usize,
    }

    fn decode_with(methods: Vec<sevenz_rust2::EncoderConfiguration>) -> Decoded {
        let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
        writer.set_encrypt_header(false);
        writer.set_content_methods(methods);
        let mut entry = ArchiveEntry::new_file("a");
        entry.has_stream = true;
        entry.size = 4;
        writer
            .push_archive_entry(entry, Some(Cursor::new(b"data".to_vec())))
            .unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        let credentials = Credentials::new(Some(Arc::new(
            crate::Password::new(b"pw".to_vec()).unwrap(),
        )));
        let header = open_sevenz_header(
            &mut Cursor::new(bytes.clone()),
            HeaderLimit::UNLIMITED,
            &credentials,
        )
        .unwrap();
        let block = header.block_indices().next().unwrap();
        let mut source = TurnWatchingSource {
            inner: Cursor::new(bytes),
            calls_under_turn: 0,
            calls_outside_turn: 0,
        };
        let mut body = Vec::new();

        decode_block_entries(
            &mut source,
            &header,
            block,
            ParallelDecode::Sequential,
            DecodeKnobs::new(1024, 1),
            &mut |_, reader| {
                reader.read_to_end(&mut body)?;
                Ok(true)
            },
        )
        .unwrap();

        Decoded {
            aes_leads: header.aes_coder_leads_block(block),
            body,
            calls_outside_turn: source.calls_outside_turn,
            calls_under_turn: source.calls_under_turn,
        }
    }

    #[test]
    fn decoding_an_aes_block_runs_no_source_code_under_the_turn() {
        let decoded = decode_with(vec![aes(), EncoderMethod::COPY.into()]);

        assert!(decoded.aes_leads);
        assert_eq!(decoded.body, b"data");
        assert!(decoded.calls_outside_turn > 0, "the source was read");
        assert_eq!(decoded.calls_under_turn, 0);
    }

    #[test]
    fn an_aes_block_over_lzma2_reads_the_source_outside_the_turn() {
        let decoded = decode_with(vec![aes(), EncoderMethod::LZMA2.into()]);

        assert!(decoded.aes_leads);
        assert_eq!(decoded.body, b"data");
        assert!(decoded.calls_outside_turn > 0, "the source was read");
        assert_eq!(decoded.calls_under_turn, 0);
    }

    #[test]
    fn layouts_without_a_leading_aes_coder_keep_the_turn_during_set_up() {
        for methods in [
            vec![EncoderMethod::COPY.into(), aes()],
            vec![aes(), aes(), EncoderMethod::COPY.into()],
        ] {
            let decoded = decode_with(methods);

            assert!(!decoded.aes_leads);
            assert_eq!(decoded.body, b"data");
            assert!(
                decoded.calls_under_turn > 0,
                "the set-up calls the source under the turn"
            );
        }
    }
}
