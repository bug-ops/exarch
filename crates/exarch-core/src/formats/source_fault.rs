//! Meters the raw archive bytes a decoder pulls from its source and remembers
//! the source's own I/O faults.
//!
//! A [`SourceRead`] sits between the file and the decoder of a TAR stream. It
//! counts every byte it hands over into a [`SourceTap`], which lets a skipped
//! entry's decoded size be judged against the input that produced it, and it
//! records the first I/O error the source raised in a [`FaultSlot`]. The `tar`
//! crate reports a reader fault and a malformed header alike as an error from
//! its own call; the slot is what tells them apart, so a failing disk is never
//! reported as a corrupt archive.

use std::io;
use std::io::Read;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

/// An I/O error as the source raised it: kind, errno and message.
#[derive(Debug, Clone)]
struct RecordedFault {
    kind: io::ErrorKind,
    raw_os_error: Option<i32>,
    message: String,
}

impl RecordedFault {
    fn of(error: &io::Error) -> Self {
        Self {
            kind: error.kind(),
            raw_os_error: error.raw_os_error(),
            message: error.to_string(),
        }
    }

    /// Rebuilds the error, keeping the errno when the source gave one.
    fn rebuild(&self) -> io::Error {
        self.raw_os_error.map_or_else(
            || io::Error::new(self.kind, self.message.clone()),
            io::Error::from_raw_os_error,
        )
    }
}

/// The first I/O error a source raised, shared between the reader that saw it
/// and the code that classifies a failure further up the stack.
///
/// An [`io::ErrorKind::Interrupted`] error is a retry request, not a fault,
/// and is never recorded. Cheap to clone; every clone sees the same slot.
#[derive(Debug, Clone, Default)]
pub struct FaultSlot(Arc<Mutex<Option<RecordedFault>>>);

impl FaultSlot {
    fn lock(&self) -> MutexGuard<'_, Option<RecordedFault>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Remembers `error` unless a fault is already held or it is a retry
    /// request.
    pub fn record(&self, error: &io::Error) {
        if error.kind() == io::ErrorKind::Interrupted {
            return;
        }
        self.lock().get_or_insert_with(|| RecordedFault::of(error));
    }

    /// The recorded fault, rebuilt as an [`io::Error`], leaving it in place.
    #[must_use]
    pub fn get(&self) -> Option<io::Error> {
        self.lock().as_ref().map(RecordedFault::rebuild)
    }

    /// Forgets the recorded fault: the stream read on successfully, so it is
    /// aligned again and a later failure is not the fault's doing.
    pub fn clear(&self) {
        self.lock().take();
    }
}

/// Shared view of the raw bytes read from an archive source and of the faults
/// it raised.
///
/// Cheap to clone; every clone observes the same counter and slot.
#[derive(Debug, Clone, Default)]
pub struct SourceTap {
    consumed: Arc<AtomicU64>,
    fault: FaultSlot,
}

impl SourceTap {
    /// Raw bytes read from the source so far.
    #[must_use]
    pub fn consumed(&self) -> u64 {
        self.consumed.load(Ordering::Relaxed)
    }

    /// The I/O fault the source raised, if one is pending.
    #[must_use]
    pub fn fault(&self) -> Option<io::Error> {
        self.fault.get()
    }
}

/// Read wrapper that records the bytes it returns and the faults it raises into
/// a [`SourceTap`].
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
        match self.inner.read(buf) {
            Ok(n) => {
                if n > 0 {
                    self.tap.fault.clear();
                }
                self.tap.consumed.fetch_add(n as u64, Ordering::Relaxed);
                Ok(n)
            }
            Err(e) => {
                self.tap.fault.record(&e);
                Err(e)
            }
        }
    }
}

/// The raw source behind a TAR byte stream, as the read budget sees it.
#[derive(Debug, Clone)]
pub enum TapSource {
    /// Core built the stream and metered its input.
    Tapped(SourceTap),
    /// The caller supplied an already-decoded reader; core cannot see how much
    /// input produced it or which errors came from its source, so it records
    /// no faults and its I/O errors keep their existing classification.
    Opaque,
}

impl TapSource {
    /// The I/O fault the source raised, if one is pending.
    #[must_use]
    pub fn fault(&self) -> Option<io::Error> {
        match self {
            Self::Tapped(tap) => tap.fault(),
            Self::Opaque => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    struct Scripted(Vec<io::Result<usize>>);

    impl Read for Scripted {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            self.0.remove(0)
        }
    }

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

    #[test]
    fn keeps_the_errno_of_the_first_fault() {
        let tap = SourceTap::default();
        let mut reader = SourceRead::new(
            Scripted(vec![
                Err(io::Error::from_raw_os_error(5)),
                Err(io::Error::from_raw_os_error(28)),
            ]),
            tap.clone(),
        );
        let mut buf = [0u8; 4];
        reader.read(&mut buf).unwrap_err();
        reader.read(&mut buf).unwrap_err();
        assert_eq!(tap.fault().unwrap().raw_os_error(), Some(5));
    }

    #[test]
    fn rebuilds_a_fault_without_errno_from_kind_and_message() {
        let tap = SourceTap::default();
        let mut reader = SourceRead::new(
            Scripted(vec![Err(io::Error::new(io::ErrorKind::TimedOut, "slow"))]),
            tap.clone(),
        );
        reader.read(&mut [0u8; 4]).unwrap_err();
        let fault = tap.fault().unwrap();
        assert_eq!(fault.kind(), io::ErrorKind::TimedOut);
        assert_eq!(fault.raw_os_error(), None);
        assert!(fault.to_string().contains("slow"));
    }

    #[test]
    fn a_retry_request_is_not_a_fault() {
        let tap = SourceTap::default();
        let mut reader = SourceRead::new(
            Scripted(vec![Err(io::ErrorKind::Interrupted.into())]),
            tap.clone(),
        );
        reader.read(&mut [0u8; 4]).unwrap_err();
        assert!(tap.fault().is_none());
    }

    #[test]
    fn a_later_successful_read_clears_the_fault() {
        let tap = SourceTap::default();
        let mut reader = SourceRead::new(
            Scripted(vec![Err(io::Error::from_raw_os_error(5)), Ok(3), Ok(0)]),
            tap.clone(),
        );
        let mut buf = [0u8; 4];
        reader.read(&mut buf).unwrap_err();
        assert!(tap.fault().is_some());
        assert_eq!(reader.read(&mut buf).unwrap(), 3);
        assert!(tap.fault().is_none());
    }
}
