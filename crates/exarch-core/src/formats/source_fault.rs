//! Meters the raw archive bytes a decoder pulls from its source.
//!
//! A [`SourceRead`] sits between the file and the decoder of a TAR stream and
//! counts every byte it hands over into a [`SourceTap`]. The count is the
//! compressed input consumed so far, which lets a skipped entry's decoded size
//! be judged against the input that produced it.

use std::io;
use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

/// Shared view of the raw bytes read from an archive source.
///
/// Cheap to clone; every clone observes the same counter.
#[derive(Debug, Clone, Default)]
pub struct SourceTap {
    consumed: Arc<AtomicU64>,
}

impl SourceTap {
    /// Raw bytes read from the source so far.
    pub fn consumed(&self) -> u64 {
        self.consumed.load(Ordering::Relaxed)
    }
}

/// Read wrapper that records the bytes it returns into a [`SourceTap`].
///
/// Never alters, buffers or reorders the bytes, and returns every error
/// unchanged.
pub struct SourceRead<R> {
    inner: R,
    tap: SourceTap,
}

impl<R> SourceRead<R> {
    /// Wraps `inner`, recording into `tap`.
    pub const fn new(inner: R, tap: SourceTap) -> Self {
        Self { inner, tap }
    }
}

impl<R: Read> Read for SourceRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.tap.consumed.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

/// The raw source behind a TAR byte stream, as the read budget sees it.
#[derive(Debug, Clone)]
pub enum TapSource {
    /// Core built the stream and metered its input.
    Tapped(SourceTap),
    /// The caller supplied an already-decoded reader; core cannot see how much
    /// input produced it.
    Opaque,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn counts_bytes_across_clones() {
        let tap = SourceTap::default();
        let mut reader = SourceRead::new(&b"abcdef"[..], tap.clone());
        let mut buf = [0u8; 4];
        assert_eq!(reader.read(&mut buf).unwrap(), 4);
        assert_eq!(tap.consumed(), 4);
        assert_eq!(reader.read(&mut buf).unwrap(), 2);
        assert_eq!(tap.consumed(), 6);
        assert_eq!(reader.read(&mut buf).unwrap(), 0);
        assert_eq!(tap.consumed(), 6);
    }
}
