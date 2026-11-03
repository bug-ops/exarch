//! Output of the structural census, kept so a deflate entry is decoded once.
//!
//! The census decodes every deflate entry to find where its stream ends, and
//! extraction used to decode it again. A [`ReuseStore`] keeps what the census
//! decoded, in memory or in an unnamed temporary file, and extraction writes
//! those bytes instead.
//!
//! Keeping the output is an optimisation only:
//!
//! - an entry is kept only when the census decoded exactly its declared size
//!   and the CRC-32 of the bytes equals the one the central directory states;
//! - the bytes are checked against that CRC-32 and the length again when read
//!   back, and a mismatch fails the read like the `zip` crate does for a
//!   damaged entry;
//! - whether an entry is replayed is decided once, in [`ReuseStore::open`],
//!   before extraction reads a byte. Without a kept entry, extraction decodes
//!   from the archive as it always did.

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
use crate::security::zipbomb::ratio_admitted;

const SPOOL_BUFFER: usize = 64 * 1024;

/// A [`DecodeReuse`] mode with the limits of the config it runs under.
///
/// The kept bytes never exceed the smallest of the mode's limit,
/// `max_decoder_memory` and `max_total_size`, and an entry that the size or
/// ratio limits would refuse at extraction is not kept at all.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReusePlan {
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
                .min(config.max_decoder_memory)
                .min(config.max_total_size),
            max_entry: config.max_file_size,
            max_ratio: config.max_compression_ratio,
        }
    }

    fn admits(&self, key: &RetainKey) -> bool {
        key.size <= self.max_entry && ratio_admitted(key.compressed, key.size, self.max_ratio)
    }
}

/// What identifies an entry's decoded output: where its compressed data is,
/// what the central directory declares for it, and its checksum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RetainKey {
    pub(crate) data_start: u64,
    pub(crate) compressed: u64,
    pub(crate) size: u64,
    pub(crate) crc32: u32,
}

#[derive(Debug)]
enum Kept {
    Memory(Box<[u8]>),
    Spooled { offset: u64, len: u64 },
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
    index: HashMap<RetainKey, Kept>,
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

#[cfg(not(target_os = "wasi"))]
fn open_spool() -> Option<File> {
    tempfile::tempfile().ok()
}

// std's `temp_dir` panics on WASI, so no temporary file is attempted there.
#[cfg(target_os = "wasi")]
const fn open_spool() -> Option<File> {
    None
}

impl ReuseStore {
    /// A store for `mode`, or `None` when nothing is to be kept (`Off`, or a
    /// temporary file that cannot be had).
    pub(crate) fn new(plan: ReusePlan) -> Option<Self> {
        let backend = match plan.mode {
            DecodeReuse::Memory(_) => Backend::Memory,
            DecodeReuse::TempFile(_) => {
                let writer = BufWriter::with_capacity(SPOOL_BUFFER, open_spool()?);
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
            #[cfg(test)]
            replays: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn disable(&mut self) {
        self.backend = Backend::Dead;
        self.index.clear();
        self.used = 0;
    }

    /// Starts keeping the output of the entry `key` names, or `None` when it
    /// cannot be kept: no store left, nothing to keep, or no room for it.
    pub(crate) fn capture(&mut self, key: RetainKey) -> Option<Capture<'_>> {
        if key.size == 0
            || !self.plan.admits(&key)
            || self.index.contains_key(&key)
            || self.used.checked_add(key.size)? > self.limit
        {
            return None;
        }
        let start = match &self.backend {
            Backend::Memory => 0,
            Backend::Spool(spool) => spool.len,
            Backend::Dead => return None,
        };
        Some(Capture {
            store: self,
            key,
            crc: Crc::new(),
            buffer: Vec::new(),
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

    /// The kept output of the entry `key` names, ready to read from its first
    /// byte, or `None` when extraction must decode from the archive.
    pub(crate) fn open(&self, key: &RetainKey) -> Option<ReplayReader<Stored<'_>>> {
        let source = match (self.index.get(key)?, &self.backend) {
            (Kept::Memory(bytes), _) => Stored::Memory(bytes),
            (Kept::Spooled { offset, len }, Backend::Spool(spool)) => {
                let mut file = spool.writer.get_ref();
                file.seek(SeekFrom::Start(*offset)).ok()?;
                Stored::Spool(file.take(*len))
            }
            (Kept::Spooled { .. }, Backend::Memory | Backend::Dead) => return None,
        };
        #[cfg(test)]
        self.replays
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(ReplayReader::new(source, *key))
    }

    /// Entries opened for replay, for the tests that prove a single decode.
    #[cfg(test)]
    pub(crate) fn replays(&self) -> usize {
        self.replays.load(std::sync::atomic::Ordering::Relaxed)
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
        for kept in self.index.values_mut() {
            if let Kept::Memory(bytes) = kept {
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
            && produced == self.key.size
            && self.written == self.key.size
            && self.crc.sum() == self.key.crc32;
        if !complete {
            return;
        }
        self.open = false;
        let kept = if matches!(self.store.backend, Backend::Memory) {
            let mut bytes = std::mem::take(&mut self.buffer);
            bytes.shrink_to_fit();
            Kept::Memory(bytes.into_boxed_slice())
        } else {
            Kept::Spooled {
                offset: self.start,
                len: self.written,
            }
        };
        self.store.index.insert(self.key, kept);
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
        if self.written.saturating_add(n) > self.key.size
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

/// Where kept bytes are read from.
pub enum Stored<'s> {
    Memory(&'s [u8]),
    Spool(Take<&'s File>),
}

impl Read for Stored<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Memory(bytes) => bytes.read(buf),
            Self::Spool(file) => file.read(buf),
        }
    }
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
            if self.read != self.key.size {
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
