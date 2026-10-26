//! Chunked signature search over a byte range.
//!
//! The ZIP census searches the prefix and the gaps between entries for local
//! header signatures, and the descriptor tail check searches the bytes behind a
//! compressed stream. All three read in bounded chunks and must see a hit that
//! straddles two chunks exactly once. [`search_chunks`] owns that boundary
//! arithmetic; what a hit means stays with the caller's judge.

use std::ops::Range;

use crate::Result;

/// Where the bytes of a search come from.
pub(super) trait ChunkSource {
    /// Fills `buf` with the bytes at `position` and returns how many it filled.
    ///
    /// A positional source fills the whole buffer or fails; a sequential one
    /// ignores `position` and returns fewer bytes only at its end.
    fn read_chunk(&mut self, position: u64, buf: &mut [u8]) -> Result<usize>;
}

/// Whether more bytes follow the chunk a hit was found in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ChunkEnd {
    More,
    /// The search range ends with the bytes the hit was found in.
    Last,
}

/// What a judge decides about one hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Flow {
    /// Go on with the next hit.
    Next,
    /// The bytes after the hit do not cover what the judgement needs: judge it
    /// again with more bytes. Taken as [`Flow::Next`] when nothing more can
    /// follow.
    NeedMore,
    /// End the search now.
    Stop,
    /// Judge the remaining hits of this chunk, then end the search.
    Finish,
}

/// One signature hit handed to a judge.
#[derive(Debug)]
pub(super) struct Hit<'a, K> {
    /// Position of the hit in the source.
    pub(super) offset: u64,
    /// The bytes from the hit to the end of the buffered chunk.
    pub(super) bytes: &'a [u8],
    /// What the finder recognised.
    pub(super) kind: K,
    pub(super) end: ChunkEnd,
}

/// Shape of a search.
#[derive(Debug, Clone)]
pub(super) struct ChunkPlan {
    /// Positions to search.
    pub(super) range: Range<u64>,
    /// Bytes read per request.
    pub(super) chunk: usize,
    /// Length of the signatures the finder recognises.
    pub(super) signature_len: usize,
    /// Most bytes after the end of a signature a judge may ask for. Bounds the
    /// bytes carried across chunks.
    pub(super) max_lookahead: usize,
}

/// Calls `judge` once for every hit `find` reports in `plan.range`, in order,
/// reading `plan.chunk` bytes at a time.
///
/// `find` returns the first hit in the slice it gets, as an offset into it. A
/// hit that starts in the last `signature_len - 1` bytes of a chunk is found
/// in the next one; a hit the judge asks to see with more bytes is judged
/// again, with the buffer carried over to start at it. The judge gets the
/// source back so it can read on its own.
///
/// # Errors
///
/// Returns the source's or the judge's error.
pub(super) fn search_chunks<S, K>(
    source: &mut S,
    plan: &ChunkPlan,
    mut find: impl FnMut(&[u8]) -> Option<(usize, K)>,
    mut judge: impl FnMut(&mut S, Hit<'_, K>) -> Result<Flow>,
) -> Result<()>
where
    S: ChunkSource + ?Sized,
{
    let range = &plan.range;
    if range.end.saturating_sub(range.start) < plan.signature_len as u64 {
        return Ok(());
    }
    let chunk = plan.chunk.max(1);
    let carried_signature = plan.signature_len.saturating_sub(1);
    let mut buf: Vec<u8> = Vec::new();
    let mut base = range.start;
    loop {
        let held = buf.len();
        let read_from = base + held as u64;
        let want =
            usize::try_from(range.end.saturating_sub(read_from)).map_or(chunk, |n| n.min(chunk));
        buf.resize(held + want, 0);
        let got = source.read_chunk(read_from, &mut buf[held..])?;
        buf.truncate(held + got);
        let last = got < want || read_from + got as u64 >= range.end;
        let end = if last { ChunkEnd::Last } else { ChunkEnd::More };

        let mut keep_from = buf.len().saturating_sub(carried_signature);
        let mut finish = false;
        let mut next = 0;
        while let Some((relative, kind)) = find(&buf[next..]) {
            let index = next + relative;
            next = index + 1;
            let hit = Hit {
                offset: base + index as u64,
                bytes: &buf[index..],
                kind,
                end,
            };
            match judge(source, hit)? {
                Flow::Next => {}
                Flow::NeedMore => {
                    if !last && buf.len() - index < plan.max_lookahead + plan.signature_len {
                        keep_from = keep_from.min(index);
                        break;
                    }
                }
                Flow::Stop => return Ok(()),
                Flow::Finish => finish = true,
            }
        }
        if last || finish {
            return Ok(());
        }
        buf.drain(..keep_from);
        base += keep_from as u64;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    struct Memory<'a>(&'a [u8]);

    impl ChunkSource for Memory<'_> {
        fn read_chunk(&mut self, position: u64, buf: &mut [u8]) -> Result<usize> {
            let start = usize::try_from(position).unwrap();
            let end = start + buf.len();
            buf.copy_from_slice(&self.0[start..end]);
            Ok(buf.len())
        }
    }

    const SIGNATURES: [[u8; 4]; 2] = [*b"PK\x03\x04", *b"PK\x01\x02"];

    fn find(bytes: &[u8]) -> Option<(usize, usize)> {
        bytes.windows(4).enumerate().find_map(|(index, w)| {
            SIGNATURES
                .iter()
                .position(|s| w == s)
                .map(|which| (index, which))
        })
    }

    /// Every hit and the verdict a lookahead of `need` bytes gives it.
    fn naive(data: &[u8], need: usize) -> Vec<(u64, usize)> {
        let mut hits = Vec::new();
        let mut at = 0;
        while let Some((relative, which)) = find(&data[at..]) {
            let index = at + relative;
            if data.len() - index >= need {
                hits.push((index as u64, which));
            }
            at = index + 1;
        }
        hits
    }

    fn chunked(data: &[u8], chunk: usize, need: usize) -> Vec<(u64, usize)> {
        let plan = ChunkPlan {
            range: 0..data.len() as u64,
            chunk,
            signature_len: 4,
            max_lookahead: need,
        };
        let mut hits = Vec::new();
        search_chunks(&mut Memory(data), &plan, find, |_, hit| {
            if hit.bytes.len() < need {
                return Ok(if hit.end == ChunkEnd::Last {
                    Flow::Next
                } else {
                    Flow::NeedMore
                });
            }
            hits.push((hit.offset, hit.kind));
            Ok(Flow::Next)
        })
        .unwrap();
        hits
    }

    fn stream() -> impl Strategy<Value = Vec<u8>> {
        let piece = prop_oneof![
            Just(b"PK\x03\x04".to_vec()),
            Just(b"PK\x01\x02".to_vec()),
            Just(b"PK\x03PK\x03\x04".to_vec()),
            Just(b"PK".to_vec()),
            prop::collection::vec(any::<u8>(), 0..24),
        ];
        prop::collection::vec(piece, 0..8).prop_map(|pieces| pieces.concat())
    }

    proptest! {
        #[test]
        fn chunked_hits_equal_the_unchunked_scan(
            data in stream(),
            chunk in 1usize..=64,
            need in prop::sample::select(vec![4usize, 30, 100]),
        ) {
            prop_assert_eq!(chunked(&data, chunk, need), naive(&data, need));
        }
    }

    #[test]
    fn a_signature_is_found_at_every_offset_around_a_chunk_end() {
        let chunk = 64;
        for offset in chunk - 40..chunk + 40 {
            let mut data = vec![0u8; 200];
            data[offset..offset + 4].copy_from_slice(&SIGNATURES[0]);
            assert_eq!(
                chunked(&data, chunk, 30),
                vec![(offset as u64, 0)],
                "{offset}"
            );
        }
    }

    #[test]
    fn an_empty_or_short_range_reads_nothing() {
        struct Never;
        impl ChunkSource for Never {
            fn read_chunk(&mut self, _: u64, _: &mut [u8]) -> Result<usize> {
                Err(crate::ArchiveError::InvalidArchive(
                    "unexpected read".into(),
                ))
            }
        }
        let plan = ChunkPlan {
            range: 5..8,
            chunk: 16,
            signature_len: 4,
            max_lookahead: 30,
        };
        search_chunks(&mut Never, &plan, find, |_, _| Ok(Flow::Next)).unwrap();
    }
}
