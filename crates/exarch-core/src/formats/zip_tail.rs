//! Search for an unmapped entry in the declared range of a compressed entry.
//!
//! The central directory gives such an entry's compressed size, but a
//! streaming reader ends it where its compressed stream ends and then reads a
//! descriptor (when the entry has one) and the next local header. Bytes between
//! the stream end and the declared end are therefore invisible to a
//! random-access reader and readable by a streaming one. Telling where the
//! stream ends takes decoding, so the check runs with an integrity pass, after
//! the entry has decoded cleanly through the `zip` crate. The census also
//! decodes deflated entries itself within a fixed budget (see [`stream_end`]),
//! which the integrity pass completes; bzip2 and zstd descriptor entries are
//! decoded by the census the same way. A streaming reader scans stored
//! descriptor entries, and some readers the bzip2 and zstd ones, for a
//! descriptor signature instead, which the census searches for too (see
//! [`judge_first_signature`]).

use std::cell::Cell;
use std::cell::RefCell;
use std::io::BufReader;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::Path;
use std::rc::Rc;

use zip::ZipArchive as ZipReader;
use zip::read::ZipFile;

use super::chunk_search::ChunkPlan;
use super::chunk_search::ChunkSource;
use super::chunk_search::Flow;
use super::chunk_search::search_chunks;
use super::zip::ZipMethod;
use super::zip_reuse::Capture;
use super::zip_structure::CDFH_SIGNATURE;
use super::zip_structure::EOCD_SIGNATURE;
use super::zip_structure::LFH_FIXED_LEN;
use super::zip_structure::LFH_SIGNATURE;
use super::zip_structure::ZIP64_END_SIGNATURE;
use super::zip_structure::le16;
use super::zip_structure::le32;
use crate::ArchiveError;
use crate::HiddenRegion;
use crate::Malformation;
use crate::Result;
use crate::ZipConsistencyPolicy;
use crate::ZipInconsistency;
use crate::inspection::integrity::IntegrityPass;
use crate::inspection::integrity::Slot;
use crate::inspection::report::UnverifiedReason;
use crate::inspection::report::VerificationIssue;

pub(super) const SCAN_CHUNK: usize = 64 * 1024;

/// Methods whose stream end takes decoding to find.
#[derive(Debug, Clone, Copy)]
pub(super) enum Compressed {
    Deflate,
    Bzip2,
    Zstd,
}

impl Compressed {
    /// `None` for stored data, which has no stream end to find.
    pub(super) const fn of(method: ZipMethod) -> Option<Self> {
        match method {
            ZipMethod::Stored => None,
            ZipMethod::Deflate => Some(Self::Deflate),
            ZipMethod::Bzip2 => Some(Self::Bzip2),
            ZipMethod::Zstd => Some(Self::Zstd),
        }
    }
}

/// What the tail check needs to know about a data-descriptor entry; taken
/// while the entry is open and used once it is closed.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DescriptorTail {
    method: Compressed,
    data_start: u64,
    compressed: u64,
    size: u64,
}

impl DescriptorTail {
    /// The entry's layout, or `None` when it has no data descriptor, so its
    /// compressed stream ends at the declared size by construction, or when it
    /// is stored, which the census covers.
    pub(crate) fn of<R: Read>(entry: &ZipFile<'_, R>) -> Option<Self> {
        if !entry.flags().is_using_data_descriptor() {
            return None;
        }
        let method = Compressed::of(ZipMethod::try_from(entry.compression()).ok()?)?;
        Some(Self {
            method,
            data_start: entry.data_start()?,
            compressed: entry.compressed_size(),
            size: entry.size(),
        })
    }

    /// Looks for a local header behind the end of the entry's data and
    /// records it as an issue of the entry.
    ///
    /// Does nothing under `--zip-consistency ignore`. A tail the budget
    /// cannot cover, or whose raw decode disagrees with the `zip` crate's, is
    /// listed by path as unverified (`DescriptorTail`) instead of being passed
    /// over silently. A header the census already `reported` is not recorded
    /// a second time.
    ///
    /// # Errors
    ///
    /// Returns the I/O error of a failing disk read.
    pub(crate) fn check<R: Read + Seek>(
        self,
        archive: &mut ZipReader<R>,
        index: usize,
        pass: &mut IntegrityPass<'_>,
        slot: Slot,
        path: &Path,
        reported: &[ZipInconsistency],
    ) -> Result<()> {
        if pass.config().zip_consistency != ZipConsistencyPolicy::Enforce {
            return Ok(());
        }
        if !pass.try_charge(self.size) {
            pass.mark_unverified(UnverifiedReason::DescriptorTail, path);
            return Ok(());
        }
        let raw = archive.by_index_raw(index).map_err(|e| {
            ArchiveError::from(Malformation::ZipEntryRereadFailed {
                index,
                detail: e.to_string().into(),
            })
        })?;
        let found = match self.find_hidden(raw)? {
            Tail::Clean => return Ok(()),
            Tail::Undecided => {
                pass.mark_unverified(UnverifiedReason::DescriptorTail, path);
                return Ok(());
            }
            Tail::Hidden(found) => found,
        };
        let hidden = ZipInconsistency::HiddenLocalHeader {
            offset: self.data_start.saturating_add(found),
            region: HiddenRegion::DescriptorTail,
        };
        if reported.contains(&hidden) {
            return Ok(());
        }
        let finding = ArchiveError::ZipInconsistency(hidden);
        pass.push_issue(
            slot,
            VerificationIssue::from_error(&finding, Some(path.to_path_buf())),
        );
        Ok(())
    }

    fn decode_stream<R: Read>(
        self,
        raw: R,
        capture: Option<&mut Capture<'_>>,
    ) -> Result<Decoded<R>> {
        let source = Rc::new(Source::default());
        let raw = BufReader::new(Counted {
            inner: raw,
            state: Rc::clone(&source),
        });
        let (drained, rest) = match self.method {
            Compressed::Deflate => {
                let mut decoder = flate2::bufread::DeflateDecoder::new(raw);
                let drained = drain(&mut decoder, self.size, &source, capture)?;
                (drained, decoder.into_inner())
            }
            Compressed::Bzip2 => {
                let mut decoder = bzip2::bufread::BzDecoder::new(raw);
                let drained = drain(&mut decoder, self.size, &source, capture)?;
                (drained, decoder.into_inner())
            }
            Compressed::Zstd => {
                let mut decoder = zstd::stream::read::Decoder::with_buffer(raw)
                    .map_err(ArchiveError::Io)?
                    .single_frame();
                let drained = drain(&mut decoder, self.size, &source, capture)?;
                (drained, decoder.finish())
            }
        };
        Ok(match drained {
            Drained::Within(produced) => {
                let unread = u64::try_from(rest.buffer().len()).unwrap_or(u64::MAX);
                Decoded::Ended {
                    stream_end: source.consumed.get().saturating_sub(unread),
                    rest,
                    produced,
                }
            }
            Drained::OverCap(produced) => Decoded::OverCap { produced },
            Drained::Failed(produced) => Decoded::Failed { produced },
        })
    }

    fn find_hidden(self, raw: impl Read) -> Result<Tail> {
        let Decoded::Ended {
            mut rest,
            stream_end,
            ..
        } = self.decode_stream(raw, None)?
        else {
            return Ok(Tail::Undecided);
        };
        let slack = self.compressed.saturating_sub(stream_end);
        let found = scan(&mut rest, slack, LFH_SIGNATURE, judge_header_in_slack)?;
        Ok(found.map_or(Tail::Clean, |at| Tail::Hidden(stream_end + at)))
    }
}

/// Where the compressed stream of an entry ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StreamEnd {
    /// Absolute offset of the first byte behind the stream.
    At(u64),
    /// The declared range does not hold one stream that decodes to at most the
    /// declared size, so a streaming reader ends the entry somewhere else.
    Undecided,
    /// The stream decodes to more than the decode budget has left, so its end
    /// is unknown.
    OverBudget,
}

/// Decodes the declared range of a compressed entry, `compressed` bytes at
/// `data_start`, producing at most `size` bytes, to find where its stream
/// ends. The bytes produced are taken from `budget` whatever the outcome, and
/// an entry that finds the budget spent is not decoded at all.
///
/// A `capture` receives the bytes produced and keeps them when the stream
/// ends within the declared range.
///
/// # Errors
///
/// Returns the I/O error of a failing read.
pub(super) fn stream_end<R: Read + Seek>(
    reader: &mut R,
    method: Compressed,
    data_start: u64,
    compressed: u64,
    size: u64,
    budget: &mut u64,
    mut capture: Option<Capture<'_>>,
) -> Result<StreamEnd> {
    if *budget == 0 && size > 0 {
        return Ok(StreamEnd::OverBudget);
    }
    reader.seek(SeekFrom::Start(data_start))?;
    let cap = size.min(*budget);
    let tail = DescriptorTail {
        method,
        data_start,
        compressed,
        size: cap,
    };
    let raw = Read::take(&mut *reader, compressed);
    Ok(match tail.decode_stream(raw, capture.as_mut())? {
        Decoded::Ended {
            stream_end,
            produced,
            ..
        } => {
            *budget = budget.saturating_sub(produced);
            if let Some(capture) = capture {
                capture.finish(produced);
            }
            StreamEnd::At(data_start.saturating_add(stream_end))
        }
        Decoded::OverCap { produced } => {
            *budget = budget.saturating_sub(produced);
            if cap < size {
                StreamEnd::OverBudget
            } else {
                StreamEnd::Undecided
            }
        }
        Decoded::Failed { produced } => {
            *budget = budget.saturating_sub(produced);
            StreamEnd::Undecided
        }
    })
}

/// How decoding one stream ended.
enum Decoded<R> {
    Ended {
        /// What the decoder did not consume of the buffered input.
        rest: BufReader<Counted<R>>,
        /// Compressed bytes the stream occupies.
        stream_end: u64,
        /// Bytes the stream decoded to.
        produced: u64,
    },
    /// The stream decodes to more than the cap.
    OverCap {
        /// Bytes decoded before the cap stopped it.
        produced: u64,
    },
    /// The decoder rejected the bytes.
    Failed {
        /// Bytes decoded before the decoder gave up.
        produced: u64,
    },
}

/// Whether the bytes at the start of `bytes` are a record a streaming reader
/// acts on, by the rules the gap search applies inside the budget: a local
/// header the reader takes something from, or the bare signature of a central
/// directory or end record, which stops its listing.
fn starts_reader_record(bytes: &[u8]) -> bool {
    let Some(signature) = bytes.first_chunk::<4>() else {
        return false;
    };
    match *signature {
        LFH_SIGNATURE => bytes
            .first_chunk::<LFH_FIXED_LEN>()
            .is_some_and(is_reachable_header),
        CDFH_SIGNATURE | EOCD_SIGNATURE | ZIP64_END_SIGNATURE => true,
        _ => false,
    }
}

/// Whether the `compressed` bytes at `data_start` hold a record a streaming
/// reader resuming inside the data would act on, judged on the real bytes
/// including those behind the declared end, so a record that starts inside the
/// range and ends past it counts.
///
/// Compressed data spells a signature by chance about once per gigabyte, so a
/// hit is a reason to check the entry again, not a verdict.
///
/// # Errors
///
/// Returns the I/O error of a failing read.
pub(super) fn holds_reader_record<R: Read + Seek>(
    reader: &mut R,
    data_start: u64,
    compressed: u64,
) -> Result<bool> {
    reader.seek(SeekFrom::Start(data_start))?;
    let mut data = Read::take(
        &mut *reader,
        compressed.saturating_add(LFH_FIXED_LEN as u64),
    );
    let mut buf = vec![0u8; SCAN_CHUNK + LFH_FIXED_LEN];
    let (mut filled, mut base) = (0usize, 0u64);
    loop {
        let read = data.read(&mut buf[filled..])?;
        filled += read;
        let at_end = read == 0;
        let judged = if at_end {
            filled
        } else {
            filled.saturating_sub(LFH_FIXED_LEN)
        };
        let in_range = usize::try_from(compressed.saturating_sub(base)).unwrap_or(usize::MAX);
        let limit = judged.min(in_range);
        let mut at = 0;
        while let Some(found) = buf[at..limit].iter().position(|&b| b == b'P') {
            at += found;
            if starts_reader_record(&buf[at..filled]) {
                return Ok(true);
            }
            at += 1;
        }
        if limit < judged || at_end {
            return Ok(false);
        }
        buf.copy_within(judged..filled, 0);
        base += judged as u64;
        filled -= judged;
    }
}

/// What the tail check concluded about one entry.
enum Tail {
    Clean,
    /// A hidden header, at this offset from the data start.
    Hidden(u64),
    /// The raw decode did not end one stream within the declared size, so the
    /// stream end is unknown.
    Undecided,
}

/// Decodes one stream of `decoder`, producing at most `declared` bytes.
///
/// The output length is not compared with the declared size: the entry already
/// passed that check through the `zip` crate, and a decoder that stops after
/// the first stream of a multi-stream entry (zstd frames, bzip2 streams) ends
/// short while the rest of the declared range is still data to search.
/// An error the underlying reader raised is returned as such.
fn drain(
    decoder: &mut impl Read,
    declared: u64,
    source: &Source,
    capture: Option<&mut Capture<'_>>,
) -> Result<Drained> {
    let mut limited = decoder.take(declared.saturating_add(1));
    let mut produced = Produced { count: 0, capture };
    let copied = copy_chunked(&mut limited, &mut produced, declared);
    if let Some(failure) = source.failure.take() {
        return Err(ArchiveError::Io(failure));
    }
    let produced = produced.count;
    Ok(match copied {
        Ok(()) if produced <= declared => Drained::Within(produced),
        Ok(()) => Drained::OverCap(produced),
        Err(_) => Drained::Failed(produced),
    })
}

/// Largest chunk the census decodes into at once; the 8 KiB of `io::copy`
/// costs a quarter of the decode time on large entries in call overhead.
const DECODE_CHUNK: usize = 256 * 1024;

/// Copies `reader` into `sink` in chunks sized for an entry of up to `declared`
/// bytes, so a small entry does not pay for a large buffer.
fn copy_chunked(
    reader: &mut impl Read,
    sink: &mut impl std::io::Write,
    declared: u64,
) -> std::io::Result<()> {
    let len = usize::try_from(declared.saturating_add(1))
        .unwrap_or(DECODE_CHUNK)
        .clamp(8 * 1024, DECODE_CHUNK);
    let mut chunk = vec![0u8; len];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(n) => sink.write_all(&chunk[..n])?,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// A sink that counts, so the bytes a failing decoder produced are known as
/// well, and hands the bytes to a capture when there is one.
struct Produced<'c, 's> {
    count: u64,
    capture: Option<&'c mut Capture<'s>>,
}

#[cfg(test)]
thread_local! {
    /// Bytes every decode on this thread has produced, for the tests that
    /// bound the work an archive can cost.
    pub(super) static DECODED: Cell<u64> = const { Cell::new(0) };
}

impl std::io::Write for Produced<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.count = self.count.saturating_add(buf.len() as u64);
        if let Some(capture) = self.capture.as_deref_mut() {
            capture.write_all(buf)?;
        }
        #[cfg(test)]
        DECODED.with(|total| total.set(total.get() + buf.len() as u64));
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// How draining a decoder ended.
enum Drained {
    /// The stream ended after this many bytes.
    Within(u64),
    /// The stream produced more than the cap; holds the bytes produced.
    OverCap(u64),
    /// The decoder rejected the bytes or the input ended early; holds the
    /// bytes produced.
    Failed(u64),
}

/// What the raw reader behind a decoder has done: how much it handed out and
/// the first error it raised, which tells a failing disk from bytes the
/// decoder cannot parse (a truncated stream is an unexpected end, not an error
/// of the reader).
#[derive(Default)]
struct Source {
    consumed: Cell<u64>,
    failure: RefCell<Option<std::io::Error>>,
}

/// Reports what the wrapped reader hands out to a [`Source`].
struct Counted<R> {
    inner: R,
    state: Rc<Source>,
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.inner.read(buf) {
            Ok(n) => {
                self.state
                    .consumed
                    .set(self.state.consumed.get().saturating_add(n as u64));
                Ok(n)
            }
            Err(e) => {
                let mut failure = self.state.failure.borrow_mut();
                failure.get_or_insert_with(|| std::io::Error::new(e.kind(), e.to_string()));
                Err(e)
            }
        }
    }
}

/// Verdict on one signature hit.
pub(super) enum Judgement {
    /// A hidden header; the offset is relative to the hit.
    Hit(u64),
    Miss,
    /// The bytes after the hit do not cover what the judgement needs.
    NeedMore,
}

/// Judges a header signature in the bytes behind a compressed stream: a header
/// with a name, or a nameless one that still makes a streaming reader skip its
/// compressed size. The name may run past the declared range, since a reader
/// takes the bytes after it as part of the name.
fn judge_header_in_slack(bytes: &[u8], _: u64, _: u64) -> Judgement {
    let Some(header) = bytes.first_chunk::<LFH_FIXED_LEN>() else {
        return Judgement::NeedMore;
    };
    if is_reachable_header(header) {
        Judgement::Hit(0)
    } else {
        Judgement::Miss
    }
}

/// Whether a streaming reader takes something from this local header: a name,
/// a name in an extra field (the Unicode Path field names a header without
/// one), or a compressed size to skip.
pub(super) fn is_reachable_header(header: &[u8; LFH_FIXED_LEN]) -> bool {
    le16::<26, LFH_FIXED_LEN>(header) > 0
        || le16::<28, LFH_FIXED_LEN>(header) > 0
        || le32::<18, LFH_FIXED_LEN>(header) > 0
}

/// Accepts the first signature hit: a streaming reader ends a stored entry, or
/// a compressed entry it cannot decode, at the first descriptor signature in
/// its data and resynchronises from there.
pub(super) const fn judge_first_signature(_: &[u8], _: u64, _: u64) -> Judgement {
    Judgement::Hit(0)
}

/// Streams `data` (`total` bytes) in bounded chunks and returns the offset
/// the first accepted hit of `signature` resolves to.
pub(super) fn scan(
    data: &mut impl Read,
    total: u64,
    signature: [u8; 4],
    judge: fn(&[u8], u64, u64) -> Judgement,
) -> Result<Option<u64>> {
    let plan = ChunkPlan {
        range: 0..total,
        chunk: SCAN_CHUNK,
        signature_len: signature.len(),
        max_lookahead: LFH_FIXED_LEN,
    };
    let mut found = None;
    search_chunks(
        &mut Sequential(data),
        &plan,
        |bytes| {
            bytes
                .array_windows::<4>()
                .position(|w| *w == signature)
                .map(|at| (at, ()))
        },
        |_, hit| {
            Ok(match judge(hit.bytes, hit.offset, total) {
                Judgement::Hit(delta) => {
                    found = Some(hit.offset + delta);
                    Flow::Stop
                }
                Judgement::NeedMore => Flow::NeedMore,
                Judgement::Miss => Flow::Next,
            })
        },
    )?;
    Ok(found)
}

/// A reader that is read from front to back whatever position is asked for.
struct Sequential<'a, R>(&'a mut R);

impl<R: Read> ChunkSource for Sequential<'_, R> {
    fn read_chunk(&mut self, _: u64, buf: &mut [u8]) -> Result<usize> {
        let mut filled = 0;
        while filled < buf.len() {
            match self.0.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(ArchiveError::Io(e)),
            }
        }
        Ok(filled)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::assert_matches;
    use std::io::Cursor;

    use super::*;

    fn deflate(payload: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, payload).unwrap();
        encoder.finish().unwrap()
    }

    fn drained(raw: impl Read, declared: u64) -> Result<Option<()>> {
        let source = Rc::new(Source::default());
        let raw = BufReader::new(Counted {
            inner: raw,
            state: Rc::clone(&source),
        });
        let mut decoder = flate2::bufread::DeflateDecoder::new(raw);
        Ok(match drain(&mut decoder, declared, &source, None)? {
            Drained::Within(_) => Some(()),
            Drained::OverCap(_) | Drained::Failed(_) => None,
        })
    }

    #[test]
    fn truncated_stream_is_undecided_not_an_io_error() {
        let stream = deflate(&vec![b'x'; 10_000]);
        let truncated = &stream[..stream.len() / 2];
        assert_matches!(drained(Cursor::new(truncated), 10_000), Ok(None));
        assert_matches!(drained(Cursor::new(stream), 10_000), Ok(Some(())));
    }

    #[test]
    fn undecided_tail_is_listed_with_its_own_reason() {
        use crate::DecompressionBudget;
        use crate::SecurityConfig;
        use crate::raw_zip::RawEntry;
        use crate::raw_zip::RawZip;

        let payload = vec![b'x'; 200];
        let mut entry = RawEntry::stored("a.txt", &payload).with_descriptor(true, false);
        entry.method = 8;
        entry.data = deflate(&payload);
        let compressed = entry.data.len() as u64;
        let built = RawZip::new(vec![entry]).build();
        let mut archive = ZipReader::new(Cursor::new(built.bytes)).unwrap();

        let tail = DescriptorTail {
            method: Compressed::Deflate,
            data_start: 0,
            compressed,
            size: payload.len() as u64 - 1,
        };
        let config = SecurityConfig::default();
        let mut pass = IntegrityPass::new(&config, DecompressionBudget::DEFAULT);
        let slot = pass.begin_entry(0, &crate::EntryCompression::Unknown);
        tail.check(&mut archive, 0, &mut pass, slot, Path::new("a.txt"), &[])
            .unwrap();

        let gaps = pass.finish().gaps;
        assert_eq!(gaps.count(UnverifiedReason::DescriptorTail), 1);
        assert_eq!(gaps.entries()[0].path(), Path::new("a.txt"));
    }

    struct Failing;

    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::PermissionDenied.into())
        }
    }

    #[test]
    fn error_of_the_reader_is_an_io_error() {
        assert_matches!(
            drained(Failing, 10),
            Err(ArchiveError::Io(e)) if e.kind() == std::io::ErrorKind::PermissionDenied
        );
    }
}
