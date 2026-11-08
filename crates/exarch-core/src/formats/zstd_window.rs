//! Zstandard window sizes: the limit a memory budget implies and the walk that
//! reads the windows a ZIP archive declares.
//!
//! libzstd allocates the whole window a frame header declares before it
//! decodes a byte, so a few bytes of input can ask for 128 MiB or more. A TAR
//! stream is bounded by handing the decoder a window limit
//! ([`ZstdWindowLog`]). The `zip` crate builds its own decoders, so for ZIP the
//! windows are read from the frame headers instead ([`walk`]) and the archive
//! is refused before any entry is listed or extracted.

use std::io;
use std::io::Read;
use std::io::Seek;
use std::num::NonZeroU64;

use crate::config::SecurityConfig;

const FRAME_MAGIC: u32 = 0xFD2F_B528;
const SKIPPABLE_MAGIC: u32 = 0x184D_2A50;
const SKIPPABLE_MASK: u32 = 0xFFFF_FFF0;
/// Whether `magic` starts a frame of one of the zstd formats before v0.8.
///
/// libzstd decodes them, with no window check, only when built with `legacy`
/// support; the walk gives such a frame an unbounded window so no limit admits
/// it whether or not that feature is on.
const fn is_legacy_magic(magic: u32) -> bool {
    magic == 0xFD2F_B51E || (magic >= 0xFD2F_B522 && magic <= 0xFD2F_B527)
}

/// The base-2 logarithm of the largest window a decoder accepts.
///
/// The invariant is `10..=27`: libzstd's smallest settable limit and its
/// default, which the `zip` crate's decoders keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ZstdWindowLog(u32);

impl ZstdWindowLog {
    /// The limit libzstd applies when none is set.
    pub(crate) const LIBZSTD_DEFAULT: Self = Self(Self::MAX);
    const MAX: u32 = 27;
    const MIN: u32 = 10;

    /// The limit `config.max_decoder_memory` implies.
    pub(crate) fn of(config: &SecurityConfig) -> Self {
        Self::for_memory(config.max_decoder_memory)
    }

    /// The largest power of two at or below `memory`, clamped to the range the
    /// decoder supports.
    pub(crate) fn for_memory(memory: NonZeroU64) -> Self {
        Self(memory.ilog2().clamp(Self::MIN, Self::MAX))
    }

    /// The base-2 logarithm of the limit.
    pub(crate) const fn get(self) -> u32 {
        self.0
    }

    /// Whether a frame declaring `window` decodes under this limit.
    pub(crate) const fn admits(self, window: ZstdWindow) -> bool {
        window.0 <= 1u64 << self.0
    }
}

/// A window size in bytes, never below libzstd's 1 KiB minimum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ZstdWindow(u64);

impl ZstdWindow {
    const MIN: Self = Self(1 << ZstdWindowLog::MIN);

    /// The window of `bytes`, raised to the 1 KiB minimum.
    pub(crate) fn of_bytes(bytes: u64) -> Self {
        Self(bytes.max(Self::MIN.0))
    }

    #[cfg(test)]
    pub(crate) const fn bytes(self) -> u64 {
        self.0
    }
}

/// What a walk over the zstd entries of an archive found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ZstdWindows {
    /// The archive has no zstd entry.
    NoZstdEntries,
    /// The largest window any frame in the entries declares.
    Largest(ZstdWindow),
    /// The walk stopped at its budget and the windows are unknown. Defensive:
    /// the declared-size budget of the open already bounds the ranges to the
    /// same extent, so honest and crafted archives alike stay within it.
    OverBudget,
}

/// Byte range of one zstd entry's data.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ZstdRange {
    /// Offset of the first byte of the entry's data.
    pub data_start: u64,
    /// Offset one past the last byte of the entry's data.
    pub end: u64,
}

/// Reads the frame headers of every range and returns the largest window.
///
/// Each range is parsed frame by frame the way libzstd does, stopping at the
/// first byte sequence that is not a frame, so a range is never judged
/// more leniently than the decoder would read it. Block payloads are skipped,
/// not read.
///
/// `budget` bounds the bytes all ranges together may cover. A range is charged
/// the bytes the parse consumed, clamped to the range, so overlapping entries
/// that share frames, or a huge declared skippable-frame size, cannot make the
/// walk longer than the budget. An honest archive's ranges are disjoint and sum
/// to less than its extent.
pub(crate) fn walk<R: Read + Seek>(
    reader: &mut R,
    ranges: impl IntoIterator<Item = ZstdRange>,
    budget: u64,
) -> io::Result<ZstdWindows> {
    let mut remaining = budget;
    let mut largest: Option<ZstdWindow> = None;
    for range in ranges {
        let window = largest.get_or_insert(ZstdWindow::MIN);
        if range.end <= range.data_start {
            continue;
        }
        if remaining == 0 {
            return Ok(ZstdWindows::OverBudget);
        }
        let limit = range.end.min(range.data_start.saturating_add(remaining));
        let mut cursor = Cursor::new(reader, range.data_start, limit);
        while let Some(frame) = cursor.next_frame()? {
            if let Frame::Zstd(w) = frame {
                *window = (*window).max(w);
            }
        }
        if limit < range.end && cursor.cut {
            return Ok(ZstdWindows::OverBudget);
        }
        remaining = remaining.saturating_sub(cursor.consumed());
    }
    Ok(largest.map_or(ZstdWindows::NoZstdEntries, ZstdWindows::Largest))
}

enum Frame {
    Zstd(ZstdWindow),
    Skippable,
}

/// The content size a frame header declares.
enum ContentSize {
    Absent,
    Declared(u64),
    /// The header ends inside the field.
    Cut,
}

/// Walks one range through the caller's reader. Skipping only moves the
/// position; the reader is positioned again before the next read, which the
/// reader's window cache makes cheap, so a walk allocates and reads nothing
/// beyond the header bytes it parses.
struct Cursor<'a, R: Read + Seek> {
    reader: &'a mut R,
    start: u64,
    pos: u64,
    end: u64,
    /// Whether the reader is at `pos`.
    synced: bool,
    broken: bool,
    /// The parse needed more bytes than the limit leaves.
    cut: bool,
}

impl<'a, R: Read + Seek> Cursor<'a, R> {
    fn new(reader: &'a mut R, start: u64, end: u64) -> Self {
        Self {
            reader,
            start,
            pos: start,
            end,
            synced: false,
            broken: false,
            cut: false,
        }
    }

    const fn consumed(&self) -> u64 {
        self.pos.saturating_sub(self.start)
    }

    fn array<const N: usize>(&mut self) -> io::Result<Option<[u8; N]>> {
        let width = u64::try_from(N).unwrap_or(u64::MAX);
        if self
            .end
            .checked_sub(self.pos)
            .is_none_or(|left| left < width)
        {
            self.cut = true;
            return Ok(None);
        }
        if !self.synced {
            self.reader.seek(io::SeekFrom::Start(self.pos))?;
            self.synced = true;
        }
        let mut bytes = [0u8; N];
        match self.reader.read_exact(&mut bytes) {
            Ok(()) => {
                self.pos = self.pos.saturating_add(width);
                Ok(Some(bytes))
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                self.synced = false;
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    fn skip(&mut self, len: u64) -> bool {
        if self.end.checked_sub(self.pos).is_none_or(|left| left < len) {
            self.cut = true;
            return false;
        }
        self.pos = self.pos.saturating_add(len);
        self.synced = len == 0 && self.synced;
        true
    }

    /// The next frame, or `None` at the end of the frames.
    fn next_frame(&mut self) -> io::Result<Option<Frame>> {
        if self.broken {
            return Ok(None);
        }
        let Some(magic) = self.array::<4>()?.map(u32::from_le_bytes) else {
            return Ok(None);
        };
        if magic & SKIPPABLE_MASK == SKIPPABLE_MAGIC {
            let Some(len) = self.array::<4>()?.map(u32::from_le_bytes) else {
                return Ok(None);
            };
            if !self.skip(u64::from(len)) {
                self.broken = true;
                return Ok(None);
            }
            return Ok(Some(Frame::Skippable));
        }
        if is_legacy_magic(magic) {
            return Ok(Some(Frame::Zstd(ZstdWindow::of_bytes(u64::MAX))));
        }
        if magic != FRAME_MAGIC {
            return Ok(None);
        }
        let Some((window, checksum)) = self.header()? else {
            return Ok(None);
        };
        if self.blocks()? && checksum && !self.skip(4) {
            self.broken = true;
        }
        Ok(Some(Frame::Zstd(window)))
    }

    fn header(&mut self) -> io::Result<Option<(ZstdWindow, bool)>> {
        let Some([descriptor]) = self.array::<1>()? else {
            return Ok(None);
        };
        let content_size_flag = descriptor >> 6;
        let single_segment = descriptor & 0x20 != 0;
        let reserved = descriptor & 0x08 != 0;
        if reserved {
            self.broken = true;
            return Ok(None);
        }
        let window_byte = if single_segment {
            None
        } else {
            let Some([byte]) = self.array::<1>()? else {
                self.broken = true;
                return Ok(None);
            };
            Some(byte)
        };
        let dictionary_width = match descriptor & 3 {
            0 => 0,
            1 => 1,
            2 => 2,
            _ => 4,
        };
        if !self.skip(dictionary_width) {
            self.broken = true;
            return Ok(None);
        }
        let content_size = self.content_size(content_size_flag, single_segment)?;
        let window = match (window_byte, content_size) {
            (Some(byte), _) => window_of_descriptor(byte),
            (None, ContentSize::Declared(size)) => ZstdWindow::of_bytes(size),
            (None, ContentSize::Absent) => ZstdWindow::MIN,
            (None, ContentSize::Cut) => {
                self.broken = true;
                return Ok(None);
            }
        };
        Ok(Some((window, descriptor & 0x04 != 0)))
    }

    fn content_size(&mut self, flag: u8, single_segment: bool) -> io::Result<ContentSize> {
        let width = match (flag, single_segment) {
            (0, false) => return Ok(ContentSize::Absent),
            (0, true) => 1,
            (1, _) => 2,
            (2, _) => 4,
            _ => 8,
        };
        let mut bytes = [0u8; 8];
        for slot in bytes.iter_mut().take(width) {
            let Some([byte]) = self.array::<1>()? else {
                return Ok(ContentSize::Cut);
            };
            *slot = byte;
        }
        let value = u64::from_le_bytes(bytes);
        Ok(ContentSize::Declared(if flag == 1 {
            value.saturating_add(256)
        } else {
            value
        }))
    }

    /// Skips the blocks of a frame; `false` when the frame is cut off or
    /// malformed.
    fn blocks(&mut self) -> io::Result<bool> {
        loop {
            let Some([a, b, c]) = self.array::<3>()? else {
                self.broken = true;
                return Ok(false);
            };
            let header = u32::from_le_bytes([a, b, c, 0]);
            let last = header & 1 == 1;
            let payload = match (header >> 1) & 3 {
                0 | 2 => u64::from(header >> 3),
                1 => 1,
                _ => {
                    self.broken = true;
                    return Ok(false);
                }
            };
            if !self.skip(payload) {
                self.broken = true;
                return Ok(false);
            }
            if last {
                return Ok(true);
            }
        }
    }
}

fn window_of_descriptor(byte: u8) -> ZstdWindow {
    let base = 1u64 << (10 + u32::from(byte >> 3));
    ZstdWindow::of_bytes(base.saturating_add((base >> 3).saturating_mul(u64::from(byte & 7))))
}

#[cfg(test)]
mod tests;
