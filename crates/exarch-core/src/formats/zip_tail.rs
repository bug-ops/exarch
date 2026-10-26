//! Search for an entry hidden in the declared range of a data-descriptor entry.
//!
//! The central directory gives such an entry's compressed size, but a
//! streaming reader ends it where its compressed stream ends and then reads a
//! descriptor and the next local header. Bytes between the stream end and the
//! declared end are therefore invisible to a random-access reader and
//! readable by a streaming one. Telling where the stream ends takes decoding,
//! so the check runs only with an integrity pass, after the entry has decoded
//! cleanly through the `zip` crate. Stored entries need no decoding and are
//! searched by the census instead (see [`judge_first_signature`]).

use std::cell::Cell;
use std::cell::RefCell;
use std::io::BufReader;
use std::io::Read;
use std::io::Seek;
use std::io::sink;
use std::path::Path;
use std::rc::Rc;

use zip::ZipArchive as ZipReader;
use zip::read::ZipFile;

use super::chunk_search::ChunkPlan;
use super::chunk_search::ChunkSource;
use super::chunk_search::Flow;
use super::chunk_search::search_chunks;
use super::zip::ZipMethod;
use super::zip_structure::LFH_FIXED_LEN;
use super::zip_structure::LFH_SIGNATURE;
use super::zip_structure::le16;
use crate::ArchiveError;
use crate::HiddenRegion;
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
enum Compressed {
    Deflate,
    Bzip2,
    Zstd,
}

impl Compressed {
    /// `None` for stored data, which has no stream end to find.
    const fn of(method: ZipMethod) -> Option<Self> {
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
pub struct DescriptorTail {
    method: Compressed,
    data_start: u64,
    compressed: u64,
    size: u64,
}

impl DescriptorTail {
    /// The entry's layout, or `None` when it has no data descriptor, so its
    /// compressed stream ends at the declared size by construction, or when it
    /// is stored, which the census covers.
    pub fn of<R: Read>(entry: &ZipFile<'_, R>) -> Option<Self> {
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
    /// over silently.
    ///
    /// # Errors
    ///
    /// Returns the I/O error of a failing disk read.
    pub fn check<R: Read + Seek>(
        self,
        archive: &mut ZipReader<R>,
        index: usize,
        pass: &mut IntegrityPass<'_>,
        slot: Slot,
        path: &Path,
    ) -> Result<()> {
        if pass.config().zip_consistency != ZipConsistencyPolicy::Enforce {
            return Ok(());
        }
        if !pass.try_charge(self.size) {
            pass.mark_unverified(UnverifiedReason::DescriptorTail, path);
            return Ok(());
        }
        let raw = archive.by_index_raw(index).map_err(|e| {
            ArchiveError::InvalidArchive(format!("failed to re-read ZIP entry {index}: {e}"))
        })?;
        let found = match self.find_hidden(raw)? {
            Tail::Clean => return Ok(()),
            Tail::Undecided => {
                pass.mark_unverified(UnverifiedReason::DescriptorTail, path);
                return Ok(());
            }
            Tail::Hidden(found) => found,
        };
        let finding = ArchiveError::ZipInconsistency(ZipInconsistency::HiddenLocalHeader {
            offset: self.data_start.saturating_add(found),
            region: HiddenRegion::DescriptorTail,
        });
        pass.push_issue(
            slot,
            VerificationIssue::from_error(&finding, Some(path.to_path_buf())),
        );
        Ok(())
    }

    fn find_hidden(self, raw: impl Read) -> Result<Tail> {
        let source = Rc::new(Source::default());
        let raw = BufReader::new(Counted {
            inner: raw,
            state: Rc::clone(&source),
        });
        let decoded = match self.method {
            Compressed::Deflate => {
                let mut decoder = flate2::bufread::DeflateDecoder::new(raw);
                drain(&mut decoder, self.size, &source)?.map(|()| decoder.into_inner())
            }
            Compressed::Bzip2 => {
                let mut decoder = bzip2::bufread::BzDecoder::new(raw);
                drain(&mut decoder, self.size, &source)?.map(|()| decoder.into_inner())
            }
            Compressed::Zstd => {
                let mut decoder = zstd::stream::read::Decoder::with_buffer(raw)
                    .map_err(ArchiveError::Io)?
                    .single_frame();
                drain(&mut decoder, self.size, &source)?.map(|()| decoder.finish())
            }
        };
        let Some(mut rest) = decoded else {
            return Ok(Tail::Undecided);
        };
        let unread = u64::try_from(rest.buffer().len()).unwrap_or(u64::MAX);
        let stream_end = source.consumed.get().saturating_sub(unread);
        let slack = self.compressed.saturating_sub(stream_end);
        let found = scan(&mut rest, slack, LFH_SIGNATURE, judge_header_in_slack)?;
        Ok(found.map_or(Tail::Clean, |at| Tail::Hidden(stream_end + at)))
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
/// `None` means the decoder rejected the bytes or overran the declared size; an
/// error the underlying reader raised is returned as such.
fn drain(decoder: &mut impl Read, declared: u64, source: &Source) -> Result<Option<()>> {
    let mut limited = decoder.take(declared.saturating_add(1));
    let copied = std::io::copy(&mut limited, &mut sink());
    if let Some(failure) = source.failure.take() {
        return Err(ArchiveError::Io(failure));
    }
    Ok(match copied {
        Ok(produced) if produced <= declared => Some(()),
        Ok(_) | Err(_) => None,
    })
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
/// with a name that fits in the rest of the declared range.
fn judge_header_in_slack(bytes: &[u8], at: u64, total: u64) -> Judgement {
    let Some(header) = bytes.first_chunk::<LFH_FIXED_LEN>() else {
        return Judgement::NeedMore;
    };
    let name_len = u64::from(le16::<26, LFH_FIXED_LEN>(header));
    let extra_len = u64::from(le16::<28, LFH_FIXED_LEN>(header));
    if name_len > 0 && at + LFH_FIXED_LEN as u64 + name_len + extra_len <= total {
        Judgement::Hit(0)
    } else {
        Judgement::Miss
    }
}

/// Accepts the first signature hit: a streaming reader ends a stored entry at
/// the first descriptor signature in its data and resynchronises from there.
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
        drain(&mut decoder, declared, &source)
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
        let config = SecurityConfig::default().validate().unwrap();
        let mut pass = IntegrityPass::new(&config, DecompressionBudget::DEFAULT);
        let slot = pass.begin_entry(0, &crate::EntryCompression::Unknown);
        tail.check(&mut archive, 0, &mut pass, slot, Path::new("a.txt"))
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
