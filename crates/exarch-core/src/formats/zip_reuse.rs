//! Output of the structural census, kept so a compressed entry is decoded once.
//!
//! The census decodes every deflate, bzip2 and zstd entry to find where its
//! stream ends, and extraction used to decode it again. A [`ReuseStore`] keeps
//! what the census decoded, in memory or in an unnamed temporary file, and
//! extraction writes those bytes instead. Each kept entry is handed over once,
//! when extraction reaches it, so the store shrinks as extraction proceeds.
//!
//! Keeping the output is an optimisation only:
//!
//! - an entry is kept only when the census decoded exactly its declared size
//!   and the CRC-32 of the bytes equals the one the central directory states;
//! - the bytes are checked against that CRC-32 and the length again when they
//!   are handed over, and a mismatch fails the entry like the `zip` crate does
//!   for a damaged one;
//! - whether an entry is replayed is decided once, in [`ReuseStore::take`],
//!   before extraction reads a byte. Without a kept entry, extraction decodes
//!   from the archive as it always did.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::BufWriter;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Take;
use std::io::Write;

use flate2::Crc;

use super::zip::ZIP_INVALID_CHECKSUM;
use crate::DecodeReuse;
use crate::SecurityConfig;
use crate::config::Validated;
use crate::security::zipbomb::Compressed;
use crate::security::zipbomb::Uncompressed;
use crate::security::zipbomb::ratio_admitted;
use crate::sink::SinkUsage;

const SPOOL_BUFFER: usize = 64 * 1024;

/// A [`DecodeReuse`] mode with the limits of the config it runs under.
///
/// The kept bytes never exceed the smallest of the mode's limit,
/// `max_decoder_memory` and `max_total_size`, and an entry that the size or
/// ratio limits would refuse at extraction is not kept at all.
#[derive(Debug, Clone, Copy)]
pub struct ReusePlan {
    mode: DecodeReuse,
    limit: u64,
    max_entry: u64,
    max_ratio: f64,
}

impl ReusePlan {
    /// Keep nothing.
    pub(crate) const OFF: Self = Self {
        mode: DecodeReuse::Off,
        limit: 0,
        max_entry: 0,
        max_ratio: 0.0,
    };

    /// `mode` under the limits of `config`.
    pub(crate) fn of(mode: DecodeReuse, config: &SecurityConfig<Validated>) -> Self {
        let configured = match mode {
            DecodeReuse::Off => 0,
            DecodeReuse::Memory(limit) | DecodeReuse::TempFile(limit) => limit.get(),
        };
        Self {
            mode,
            limit: configured
                .min(config.max_decoder_memory.get())
                .min(config.max_total_size.ceiling()),
            max_entry: config.max_file_size.ceiling(),
            max_ratio: config.max_compression_ratio.get(),
        }
    }

    fn admits(&self, key: &RetainKey) -> bool {
        key.size.0 <= self.max_entry && ratio_admitted(key.compressed, key.size, self.max_ratio)
    }
}

/// What identifies an entry's decoded output: where its compressed data is,
/// what the central directory declares for it, and its checksum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RetainKey {
    pub(crate) data_start: u64,
    pub(crate) compressed: Compressed,
    pub(crate) size: Uncompressed,
    pub(crate) crc32: u32,
}

/// An entry's kept output where the store holds it.
#[derive(Debug)]
enum Kept {
    Memory(Box<[u8]>),
    Spooled { offset: u64, len: u64 },
}

#[derive(Debug)]
struct Slot {
    sequence: u64,
    kept: Kept,
}

/// The kept output of one entry, taken out of the store.
#[derive(Debug)]
pub struct Taken(Kept);

/// Kept output ready to be written: owned bytes, or a reader over the spool.
pub enum Retained<'s> {
    /// Bytes checked against the entry's length and CRC-32.
    Bytes(Vec<u8>),
    /// A reader that checks them at its end.
    Spooled(ReplayReader<Take<&'s File>>),
}

/// The memory an extraction into a sink holds, which the store shares the
/// limit with.
#[derive(Debug)]
struct SinkBudget {
    usage: SinkUsage,
    limit: u64,
}

struct SpoolFile {
    writer: BufWriter<File>,
    len: u64,
}

impl SpoolFile {
    fn truncate_to(&mut self, len: u64) -> io::Result<()> {
        self.writer.flush()?;
        self.writer.get_ref().set_len(len)?;
        self.writer.seek(SeekFrom::Start(len))?;
        self.len = len;
        Ok(())
    }
}

enum Backend {
    Memory,
    Spool(SpoolFile),
    Dead,
}

/// Decoded deflate output of a census, by entry.
pub struct ReuseStore {
    plan: ReusePlan,
    limit: u64,
    used: u64,
    backend: Backend,
    index: HashMap<RetainKey, Slot>,
    order: BTreeMap<u64, RetainKey>,
    next_sequence: u64,
    sink: Option<SinkBudget>,
    #[cfg(test)]
    replays: std::sync::atomic::AtomicUsize,
}

impl fmt::Debug for ReuseStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReuseStore")
            .field("limit", &self.limit)
            .field("used", &self.used)
            .field("entries", &self.index.len())
            .finish_non_exhaustive()
    }
}

impl ReuseStore {
    /// A store for `mode`, or `None` when nothing is to be kept (`Off`, or a
    /// temporary file that cannot be had).
    pub(crate) fn new(plan: ReusePlan) -> Option<Self> {
        let backend = match plan.mode {
            DecodeReuse::Memory(_) => Backend::Memory,
            DecodeReuse::TempFile(_) => {
                let writer = BufWriter::with_capacity(SPOOL_BUFFER, super::common::open_spool()?);
                Backend::Spool(SpoolFile { writer, len: 0 })
            }
            DecodeReuse::Off => return None,
        };
        Some(Self {
            plan,
            limit: plan.limit,
            used: 0,
            backend,
            index: HashMap::new(),
            order: BTreeMap::new(),
            next_sequence: 0,
            sink: None,
            #[cfg(test)]
            replays: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn disable(&mut self) {
        self.backend = Backend::Dead;
        self.index.clear();
        self.order.clear();
        self.used = 0;
    }

    /// Shares `limit` with the sink behind `usage`: before each entry,
    /// [`Self::make_room`] evicts kept output until what is kept plus what the
    /// sink holds fits.
    pub(crate) fn share_limit_with_sink(&mut self, usage: SinkUsage, limit: u64) {
        self.sink = Some(SinkBudget { usage, limit });
    }

    /// Evicts the most recently kept entries, which extraction reaches last,
    /// until at most `room` bytes are kept in memory. An evicted entry is
    /// decoded again from the archive.
    fn fit(&mut self, room: u64) {
        if !matches!(self.backend, Backend::Memory) {
            return;
        }
        while self.used > room {
            let Some((_, key)) = self.order.pop_last() else {
                return;
            };
            if let Some(Slot {
                kept: Kept::Memory(bytes),
                ..
            }) = self.index.remove(&key)
            {
                self.used = self.used.saturating_sub(bytes.len() as u64);
            }
        }
    }

    /// Makes room for an entry of `charge` bytes in the sink: what is kept
    /// plus what the sink holds plus `charge` stays within the shared limit.
    /// Does nothing when no sink shares the limit.
    pub(crate) fn make_room(&mut self, charge: u64) {
        let Some(budget) = &self.sink else {
            return;
        };
        let room = budget
            .limit
            .saturating_sub(budget.usage.get().saturating_add(charge));
        self.fit(room);
    }

    /// Starts keeping the output of the entry `key` names, or `None` when it
    /// cannot be kept: no store left, nothing to keep, or no room for it.
    pub(crate) fn capture(&mut self, key: RetainKey) -> Option<Capture<'_>> {
        if key.size.0 == 0
            || !self.plan.admits(&key)
            || self.index.contains_key(&key)
            || self.used.checked_add(key.size.0)? > self.limit
        {
            return None;
        }
        let start = match &self.backend {
            Backend::Memory => 0,
            Backend::Spool(spool) => spool.len,
            Backend::Dead => return None,
        };
        let buffer = if matches!(self.backend, Backend::Memory) {
            Vec::with_capacity(usize::try_from(key.size.0).unwrap_or(0))
        } else {
            Vec::new()
        };
        Some(Capture {
            store: self,
            key,
            crc: Crc::new(),
            buffer,
            start,
            written: 0,
            open: true,
        })
    }

    /// Makes everything captured readable; call once after the census.
    pub(crate) fn seal(&mut self) {
        let flushed = match &mut self.backend {
            Backend::Spool(spool) => spool.writer.flush().is_ok(),
            Backend::Memory | Backend::Dead => true,
        };
        if !flushed {
            self.disable();
        }
    }

    /// Hands over the kept output of the entry `key` names, or `None` when
    /// extraction must decode from the archive. A memory-kept entry leaves the
    /// store, which frees its bytes from the shared limit.
    pub(crate) fn take(&mut self, key: &RetainKey) -> Option<Taken> {
        let slot = self.index.remove(key)?;
        self.order.remove(&slot.sequence);
        if let Kept::Memory(bytes) = &slot.kept {
            self.used = self.used.saturating_sub(bytes.len() as u64);
        }
        #[cfg(test)]
        self.replays
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(Taken(slot.kept))
    }

    /// Prepares what [`Self::take`] handed over for writing.
    ///
    /// # Errors
    ///
    /// Returns the checksum or length mismatch of damaged kept bytes, or the
    /// I/O error of reaching the spool.
    pub(crate) fn retained(&self, taken: Taken, key: &RetainKey) -> io::Result<Retained<'_>> {
        match (taken.0, &self.backend) {
            (Kept::Memory(bytes), _) => {
                check_kept(&bytes, key)?;
                Ok(Retained::Bytes(bytes.into_vec()))
            }
            (Kept::Spooled { offset, len }, Backend::Spool(spool)) => {
                let mut file = spool.writer.get_ref();
                file.seek(SeekFrom::Start(offset))?;
                Ok(Retained::Spooled(ReplayReader::new(file.take(len), *key)))
            }
            (Kept::Spooled { .. }, Backend::Memory | Backend::Dead) => {
                Err(io::ErrorKind::NotFound.into())
            }
        }
    }

    /// Entries opened for replay, for the tests that prove a single decode.
    #[cfg(test)]
    pub(crate) fn replays(&self) -> usize {
        self.replays.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether the entry `key` names is kept, for the tests.
    #[cfg(test)]
    pub(crate) fn holds(&self, key: &RetainKey) -> bool {
        self.index.contains_key(key)
    }

    /// Bytes kept, for the tests that bound the store.
    #[cfg(test)]
    pub(crate) const fn used(&self) -> u64 {
        self.used
    }

    /// Flips a bit in the first kept entry, so a test can see the replay refuse
    /// it.
    #[cfg(test)]
    pub(crate) fn corrupt(&mut self) {
        for slot in self.index.values_mut() {
            if let Kept::Memory(bytes) = &mut slot.kept {
                bytes[0] ^= 1;
                return;
            }
        }
    }
}

/// The census output of one entry while it is being decoded.
///
/// Dropped without [`Capture::finish`], it releases what it took, so a failed
/// or oversized decode leaves nothing behind.
pub struct Capture<'s> {
    store: &'s mut ReuseStore,
    key: RetainKey,
    crc: Crc,
    buffer: Vec<u8>,
    start: u64,
    written: u64,
    open: bool,
}

impl Capture<'_> {
    fn release(&mut self) {
        if !std::mem::replace(&mut self.open, false) {
            return;
        }
        self.store.used = self.store.used.saturating_sub(self.written);
        if let Backend::Spool(spool) = &mut self.store.backend
            && self.written > 0
            && spool.truncate_to(self.start).is_err()
        {
            self.store.disable();
        }
    }

    /// Keeps the output when the entry decoded to exactly its declared size
    /// and checksum. `produced` is what the decoder yielded.
    pub(crate) fn finish(mut self, produced: u64) {
        let complete = self.open
            && produced == self.key.size.0
            && self.written == self.key.size.0
            && self.crc.sum() == self.key.crc32;
        if !complete {
            return;
        }
        self.open = false;
        let kept = if matches!(self.store.backend, Backend::Memory) {
            Kept::Memory(std::mem::take(&mut self.buffer).into_boxed_slice())
        } else {
            Kept::Spooled {
                offset: self.start,
                len: self.written,
            }
        };
        let sequence = self.store.next_sequence;
        self.store.next_sequence += 1;
        self.store.order.insert(sequence, self.key);
        self.store.index.insert(self.key, Slot { sequence, kept });
    }
}

impl Drop for Capture<'_> {
    fn drop(&mut self) {
        self.release();
    }
}

impl Write for Capture<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.open {
            return Ok(buf.len());
        }
        let n = buf.len() as u64;
        if self.written.saturating_add(n) > self.key.size.0
            || self.store.used.saturating_add(n) > self.store.limit
        {
            self.release();
            return Ok(buf.len());
        }
        let kept = match &mut self.store.backend {
            Backend::Memory => {
                self.buffer.extend_from_slice(buf);
                true
            }
            Backend::Spool(spool) => {
                let ok = spool.writer.write_all(buf).is_ok();
                if ok {
                    spool.len += n;
                }
                ok
            }
            Backend::Dead => false,
        };
        if kept {
            self.store.used += n;
            self.written += n;
            self.crc.update(buf);
        } else {
            self.open = false;
            self.store.disable();
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Checks kept bytes against the entry's declared length and CRC-32.
fn check_kept(bytes: &[u8], key: &RetainKey) -> io::Result<()> {
    if bytes.len() as u64 != key.size.0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    let mut crc = Crc::new();
    crc.update(bytes);
    if crc.sum() != key.crc32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            ZIP_INVALID_CHECKSUM,
        ));
    }
    Ok(())
}

/// Reads kept bytes and checks them against the entry's declared length and
/// CRC-32 at the end, failing as the `zip` crate does for a damaged entry.
pub struct ReplayReader<S> {
    inner: S,
    crc: Crc,
    key: RetainKey,
    read: u64,
}

impl<S: Read> ReplayReader<S> {
    fn new(inner: S, key: RetainKey) -> Self {
        Self {
            inner,
            crc: Crc::new(),
            key,
            read: 0,
        }
    }
}

impl<S: Read> Read for ReplayReader<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.crc.update(&buf[..n]);
            self.read += n as u64;
        } else if !buf.is_empty() {
            if self.read != self.key.size.0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            if self.crc.sum() != self.key.crc32 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    ZIP_INVALID_CHECKSUM,
                ));
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests;
