//! Search for an entry hidden in the declared range of a data-descriptor entry.
//!
//! The central directory gives such an entry's compressed size, but a
//! streaming reader ends it where its compressed stream ends and then reads a
//! descriptor and the next local header. Bytes between the stream end and the
//! declared end are therefore invisible to a random-access reader and
//! readable by a streaming one. Telling where the stream ends takes decoding,
//! so the check runs only with an integrity pass, after the entry has decoded
//! cleanly through the `zip` crate.

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

use super::zip::ZipMethod;
use super::zip_structure::DATA_DESCRIPTOR_SIGNATURE;
use super::zip_structure::LFH_FIXED_LEN;
use super::zip_structure::LFH_SIGNATURE;
use super::zip_structure::le_u16;
use super::zip_structure::le_u32;
use super::zip_structure::le_u64;
use crate::ArchiveError;
use crate::HiddenRegion;
use crate::Result;
use crate::ZipConsistencyPolicy;
use crate::ZipInconsistency;
use crate::inspection::integrity::IntegrityPass;
use crate::inspection::integrity::Slot;
use crate::inspection::report::UnverifiedReason;
use crate::inspection::report::VerificationIssue;

const DESCRIPTOR_LEN: usize = 16;
const ZIP64_DESCRIPTOR_LEN: usize = 24;
const SCAN_CHUNK: usize = 64 * 1024;

/// What the tail check needs to know about a data-descriptor entry; taken
/// while the entry is open and used once it is closed.
#[derive(Debug, Clone, Copy)]
pub struct DescriptorTail {
    method: ZipMethod,
    data_start: u64,
    compressed: u64,
    size: u64,
}

impl DescriptorTail {
    /// The entry's layout, or `None` when it has no data descriptor, so its
    /// compressed stream ends at the declared size by construction.
    pub fn of<R: Read>(entry: &ZipFile<'_, R>) -> Option<Self> {
        if !entry.flags().is_using_data_descriptor() {
            return None;
        }
        Some(Self {
            method: ZipMethod::try_from(entry.compression()).ok()?,
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
        let cost = match self.method {
            ZipMethod::Stored => self.compressed,
            _ => self.size,
        };
        if !pass.try_charge(cost) {
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
            ZipMethod::Stored => {
                let mut raw = raw;
                let found = scan(
                    &mut raw,
                    self.compressed,
                    DATA_DESCRIPTOR_SIGNATURE,
                    judge_descriptor_in_stored,
                )?;
                return Ok(found.map_or(Tail::Clean, Tail::Hidden));
            }
            ZipMethod::Deflate => {
                let mut decoder = flate2::bufread::DeflateDecoder::new(raw);
                drain(&mut decoder, self.size, &source)?.map(|()| decoder.into_inner())
            }
            ZipMethod::Bzip2 => {
                let mut decoder = bzip2::bufread::BzDecoder::new(raw);
                drain(&mut decoder, self.size, &source)?.map(|()| decoder.into_inner())
            }
            ZipMethod::Zstd => {
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
enum Judgement {
    /// A hidden header; the offset is relative to the hit.
    Hit(u64),
    Miss,
    /// The bytes after the hit do not cover what the judgement needs.
    NeedMore,
}

/// Judges a header signature in the bytes behind a compressed stream: a header
/// with a name that fits in the rest of the declared range.
fn judge_header_in_slack(bytes: &[u8], at: u64, total: u64) -> Judgement {
    let Some(header) = bytes.get(..LFH_FIXED_LEN) else {
        return Judgement::NeedMore;
    };
    let name_len = u64::from(le_u16(header, 26));
    let extra_len = u64::from(le_u16(header, 28));
    if name_len > 0 && at + LFH_FIXED_LEN as u64 + name_len + extra_len <= total {
        Judgement::Hit(0)
    } else {
        Judgement::Miss
    }
}

/// Judges a descriptor signature inside stored data: a descriptor whose size
/// field equals its distance from the data start ends the entry for a
/// streaming reader, and the header behind it starts the next one.
fn judge_descriptor_in_stored(bytes: &[u8], at: u64, total: u64) -> Judgement {
    let remaining = total - at;
    let mut need_more = false;
    for width in [DESCRIPTOR_LEN, ZIP64_DESCRIPTOR_LEN] {
        if remaining < (width + LFH_FIXED_LEN) as u64 {
            continue;
        }
        let Some(window) = bytes.get(..width + LFH_FIXED_LEN) else {
            need_more = true;
            continue;
        };
        let size = if width == DESCRIPTOR_LEN {
            u64::from(le_u32(window, 8))
        } else {
            le_u64(window, 8)
        };
        if size != at || window[width..width + 4] != LFH_SIGNATURE {
            continue;
        }
        let name_len = u64::from(le_u16(window, width + 26));
        let extra_len = u64::from(le_u16(window, width + 28));
        if name_len > 0 && (width + LFH_FIXED_LEN) as u64 + name_len + extra_len <= remaining {
            return Judgement::Hit(width as u64);
        }
    }
    if need_more {
        Judgement::NeedMore
    } else {
        Judgement::Miss
    }
}

/// Streams `data` (`total` bytes) in bounded chunks and returns the offset
/// the first accepted hit of `signature` resolves to.
fn scan(
    data: &mut impl Read,
    total: u64,
    signature: [u8; 4],
    judge: fn(&[u8], u64, u64) -> Judgement,
) -> Result<Option<u64>> {
    let mut buf = vec![0u8; SCAN_CHUNK];
    let mut held = 0;
    let mut base = 0u64;
    loop {
        let read = data.read(&mut buf[held..]).map_err(ArchiveError::Io)?;
        let end = held + read;
        let last = read == 0;
        let mut keep_from = end.saturating_sub(signature.len() - 1);
        let mut next = 0;
        while let Some(relative) = buf[next..end].windows(4).position(|w| w == signature) {
            let at = next + relative;
            next = at + 1;
            match judge(&buf[at..end], base + at as u64, total) {
                Judgement::Hit(delta) => return Ok(Some(base + at as u64 + delta)),
                Judgement::NeedMore if !last => {
                    keep_from = keep_from.min(at);
                    break;
                }
                Judgement::NeedMore | Judgement::Miss => {}
            }
        }
        if last {
            return Ok(None);
        }
        buf.copy_within(keep_from..end, 0);
        held = end - keep_from;
        base += keep_from as u64;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
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
        assert!(matches!(drained(Cursor::new(truncated), 10_000), Ok(None)));
        assert!(matches!(drained(Cursor::new(stream), 10_000), Ok(Some(()))));
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
            method: ZipMethod::Deflate,
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
        assert!(matches!(
            drained(Failing, 10),
            Err(ArchiveError::Io(e)) if e.kind() == std::io::ErrorKind::PermissionDenied
        ));
    }
}
