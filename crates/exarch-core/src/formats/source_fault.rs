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
use std::io::Seek;
use std::io::SeekFrom;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use super::tar_metadata_limit::budget_violation;
use crate::ArchiveError;
use crate::Malformation;
use crate::copy::CopyError;

/// The decoder family that reads an entry's bytes, which decides how a failed
/// read is classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadFamily {
    /// A TAR stream.
    Tar,
    /// A ZIP archive.
    Zip,
    /// A 7z archive.
    SevenZ,
    /// A reader none of whose errors is a decoder error: every read failure is
    /// an I/O failure of its source, as for a spool core wrote itself or a
    /// caller-supplied decoded stream.
    Opaque,
}

/// What a copy of one entry's bytes knows about its source, so a failed read
/// can be told from a failed write and a decoder error from a disk fault.
///
/// Passed through every
/// [`ExtractTarget::file`](super::target::ExtractTarget::file) to the copy that
/// reads the entry, which hands a failure to [`classify`](Self::classify).
#[derive(Debug, Clone, Copy)]
pub struct ReadFaults<'a> {
    tap: Option<&'a SourceTap>,
    family: ReadFamily,
}

impl<'a> ReadFaults<'a> {
    /// The faults of an entry read by `family`, with the source's tap when it
    /// has one.
    #[must_use]
    pub const fn new(family: ReadFamily, tap: Option<&'a SourceTap>) -> Self {
        Self { tap, family }
    }

    /// The faults of a TAR entry read from `source`.
    ///
    /// A stream whose source core cannot see has no way to tell a decoder
    /// error from a disk fault, so its read errors stay I/O errors.
    #[must_use]
    pub const fn of_tar(source: &'a TapSource) -> Self {
        match source {
            TapSource::Tapped(tap) | TapSource::Replay(tap) => {
                Self::new(ReadFamily::Tar, Some(tap))
            }
            #[cfg(test)]
            TapSource::Opaque => Self::new(ReadFamily::Opaque, None),
        }
    }

    pub(crate) fn pending_fault(self) -> Option<io::Error> {
        self.tap.and_then(SourceTap::fault)
    }

    /// Maps the failure of a copy to the error extraction reports.
    ///
    /// A failed write is always [`ArchiveError::Io`]: the destination is not
    /// the archive. A failed read is a budget refusal when the stream hit one,
    /// an I/O error when the source raised a fault, and otherwise a malformed
    /// archive: the decoder rejected the bytes it was given. A short entry
    /// after a source fault is that fault; a short TAR entry without one is a
    /// truncated archive; every other size mismatch and every overrun keeps
    /// the declared-size classification.
    #[must_use]
    pub fn classify(self, error: CopyError) -> ArchiveError {
        match error {
            CopyError::Read(error) => self.classify_read(error),
            CopyError::Short { declared, actual } => match self.pending_fault() {
                Some(fault) => ArchiveError::Io(fault),
                None if self.family == ReadFamily::Tar => {
                    ArchiveError::from(Malformation::TarEntryTruncated { declared, actual })
                }
                None => ArchiveError::from(CopyError::Short { declared, actual }),
            },
            other => ArchiveError::from(other),
        }
    }

    /// Classifies the error of a read that is not part of a copy, such as
    /// draining the rest of an entry.
    #[must_use]
    pub fn classify_read(self, error: io::Error) -> ArchiveError {
        let verdict = classify_decoder_read(error, self.pending_fault());
        if self.family == ReadFamily::Zip && matches!(verdict, ReadVerdict::DeclaredSizeOverrun(_))
        {
            // The entry's caller knows the declared size and types it as a
            // security violation.
            return ArchiveError::Io(DeclaredSizeCeiling::into_io());
        }
        match verdict.into_decoder_error() {
            Ok(error) => self.unreadable(error),
            Err(verdict) => verdict,
        }
    }

    /// Classifies the error of reading a stored symlink target: a source
    /// fault is I/O, anything else leaves the target unreadable.
    #[must_use]
    pub fn classify_symlink_read(self, error: io::Error) -> ArchiveError {
        match classify_decoder_read(error, self.pending_fault()).into_decoder_error() {
            Ok(error) => ArchiveError::from(Malformation::SymlinkTargetUnreadable {
                detail: error.to_string().into(),
            }),
            Err(verdict) => verdict,
        }
    }

    fn unreadable(self, error: io::Error) -> ArchiveError {
        let detail: Box<str> = error.to_string().into();
        match self.family {
            ReadFamily::Opaque => ArchiveError::Io(error),
            ReadFamily::Tar => ArchiveError::from(Malformation::TarEntryUnreadable { detail }),
            ReadFamily::Zip => ArchiveError::from(Malformation::ZipEntryDataUnreadable { detail }),
            ReadFamily::SevenZ => {
                ArchiveError::from(Malformation::SevenZEntryDataUnreadable { detail })
            }
        }
    }
}

/// What a failed decoder read means, decided once for extract, list and
/// verify.
///
/// Every variant but [`Budget`](Self::Budget) keeps the error that was read,
/// so a front end can quote its detail.
#[derive(Debug)]
pub(crate) enum ReadVerdict {
    /// A decoder memory, member-count or compression-ratio refusal.
    Budget(ArchiveError),
    /// The source's own I/O failure: a recorded fault, or an errno no decoder
    /// raises.
    SourceFault(io::Error),
    /// The entry's checksum did not match its bytes.
    Checksum(io::Error),
    /// The entry decoded past its declared size.
    DeclaredSizeOverrun(io::Error),
    /// The stream ended before the entry did.
    Truncated(io::Error),
    /// The decoder rejected the bytes it was given.
    Malformed(io::Error),
}

impl ReadVerdict {
    /// The error of a decoder verdict, or the finished [`ArchiveError`] of a
    /// budget refusal or source fault.
    fn into_decoder_error(self) -> Result<io::Error, ArchiveError> {
        match self {
            Self::Budget(error) => Err(error),
            Self::SourceFault(error) => Err(ArchiveError::Io(error)),
            Self::Checksum(error)
            | Self::DeclaredSizeOverrun(error)
            | Self::Truncated(error)
            | Self::Malformed(error) => Ok(error),
        }
    }
}

/// Decides what the failed read `error` means: the one chain behind
/// extraction, listing and verification.
///
/// A budget refusal wins, then the source's recorded `fault`, then any errno
/// (a decoder never raises one, so it is the disk's), then the decoder's own
/// checksum, declared-size and truncation errors.
pub(crate) fn classify_decoder_read(error: io::Error, fault: Option<io::Error>) -> ReadVerdict {
    if let Some(violation) = budget_violation(&error) {
        return ReadVerdict::Budget(violation);
    }
    if let Some(fault) = fault {
        return ReadVerdict::SourceFault(fault);
    }
    if error.raw_os_error().is_some() {
        return ReadVerdict::SourceFault(error);
    }
    if is_checksum_failure(&error) {
        return ReadVerdict::Checksum(error);
    }
    if zip_crate_failure(&error) == Some(ZipCrateFailure::DeclaredSizeExceeded) {
        return ReadVerdict::DeclaredSizeOverrun(error);
    }
    if error.kind() == io::ErrorKind::UnexpectedEof {
        return ReadVerdict::Truncated(error);
    }
    ReadVerdict::Malformed(error)
}

/// Core's own replay failure: the replayed bytes do not match the entry's
/// CRC-32. Found by downcast, never by message.
#[derive(Debug, thiserror::Error)]
#[error("Invalid checksum")]
pub(crate) struct ReplayChecksumMismatch;

impl ReplayChecksumMismatch {
    pub(crate) fn into_io() -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, Self)
    }

    /// Whether `error` was built by [`into_io`](Self::into_io).
    pub(crate) fn is(error: &io::Error) -> bool {
        error
            .get_ref()
            .is_some_and(<dyn std::error::Error + Send + Sync>::is::<Self>)
    }
}

/// An entry decoded past its declared size, typed so the entry's caller can
/// raise a security violation.
#[derive(Debug, thiserror::Error)]
#[error("entry data exceeds its declared size")]
pub(crate) struct DeclaredSizeCeiling;

impl DeclaredSizeCeiling {
    pub(crate) fn into_io() -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, Self)
    }

    /// Whether `error` was built by [`into_io`](Self::into_io).
    pub(crate) fn is(error: &io::Error) -> bool {
        error
            .get_ref()
            .is_some_and(<dyn std::error::Error + Send + Sync>::is::<Self>)
    }
}

/// A failure the `zip` crate reports as a plain-text `io::Error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZipCrateFailure {
    InvalidChecksum,
    DeclaredSizeExceeded,
}

/// The only place core recognizes the `zip` crate's own read errors, which it
/// raises as untyped `InvalidData` strings ("Invalid checksum" and "File is
/// larger than its declared uncompressed size" in zip 9.4).
///
/// Matches keywords rather than the exact text so that a rewording within the
/// supported range keeps its meaning; `zip_crate_contract_holds` drives the
/// real crate and fails loudly when a release changes either error.
fn zip_crate_failure(error: &io::Error) -> Option<ZipCrateFailure> {
    if error.kind() != io::ErrorKind::InvalidData || error.get_ref().is_none() {
        return None;
    }
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("declared") && message.contains("size") {
        Some(ZipCrateFailure::DeclaredSizeExceeded)
    } else if message.contains("checksum") {
        Some(ZipCrateFailure::InvalidChecksum)
    } else {
        None
    }
}

fn is_checksum_failure(error: &io::Error) -> bool {
    let sevenz = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<sevenz_rust2::Error>())
        .is_some_and(|e| matches!(e, sevenz_rust2::Error::ChecksumVerificationFailed));
    ReplayChecksumMismatch::is(error)
        || sevenz
        || zip_crate_failure(error) == Some(ZipCrateFailure::InvalidChecksum)
}

/// Reports a source `fault` as [`ArchiveError::Io`] in place of a verdict on
/// the bytes the failing read would have delivered: a malformed archive, or a
/// corrupt or truncated stream at the end of a TAR.
///
/// A budget, security or ambiguity refusal is about bytes that were read, and
/// stays as it is.
pub(crate) fn prefer_fault(error: ArchiveError, fault: Option<io::Error>) -> ArchiveError {
    use crate::error::TarTrailerRefusal;
    use crate::error::TrailerCorruption;
    match (&error, fault) {
        (
            ArchiveError::InvalidArchive(_)
            | ArchiveError::TarTrailer(
                TarTrailerRefusal::Truncated
                | TarTrailerRefusal::Corrupt {
                    cause: TrailerCorruption::Decoder,
                    ..
                },
            ),
            Some(fault),
        ) => ArchiveError::Io(fault),
        _ => error,
    }
}

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
    /// A tap over an existing fault `slot`, for a source that records its own
    /// faults.
    #[must_use]
    pub(crate) fn over(slot: FaultSlot) -> Self {
        Self {
            consumed: Arc::default(),
            fault: slot,
        }
    }

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

impl<R: Seek> Seek for SourceRead<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner
            .seek(pos)
            .inspect_err(|error| self.tap.fault.record(error))
    }
}

/// The raw source behind a TAR byte stream, as the read budget sees it.
#[derive(Debug, Clone)]
pub enum TapSource {
    /// Core built the stream and metered its input.
    Tapped(SourceTap),
    /// Core replays the decoded stream a list pass spooled to a file: the
    /// spool's read faults are recorded, but its bytes are already decoded, so
    /// they say nothing about the input that produced them.
    Replay(SourceTap),
    /// The caller supplied an already-decoded reader; core cannot see how much
    /// input produced it or which errors came from its source, so it records
    /// no faults and its I/O errors keep their existing classification.
    #[cfg(test)]
    Opaque,
}

impl TapSource {
    /// The I/O fault the source raised, if one is pending.
    #[must_use]
    pub fn fault(&self) -> Option<io::Error> {
        match self {
            Self::Tapped(tap) | Self::Replay(tap) => tap.fault(),
            #[cfg(test)]
            Self::Opaque => None,
        }
    }
}

/// Real `zip` crate archives and read errors, for tests that pin how the
/// crate's own failures are classified.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod zip_fixtures {
    use std::io;

    pub(crate) fn stored_zip(data: &[u8]) -> Vec<u8> {
        let mut writer = zip::write::ZipWriter::new(io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer.start_file("a", options).unwrap();
        io::Write::write_all(&mut writer, data).unwrap();
        writer.finish().unwrap().into_inner()
    }

    pub(crate) fn forged_size_zip() -> Vec<u8> {
        let mut bytes = stored_zip(&[b'z'; 64]);
        for (signature, offset) in [
            ([0x50, 0x4B, 0x03, 0x04], 22),
            ([0x50, 0x4B, 0x01, 0x02], 24),
        ] {
            let at = bytes.windows(4).position(|w| w == signature).unwrap();
            bytes[at + offset..at + offset + 4].copy_from_slice(&8u32.to_le_bytes());
        }
        bytes
    }

    pub(crate) fn bad_crc_zip() -> Vec<u8> {
        let mut bytes = stored_zip(b"MARKER");
        let at = bytes.windows(6).position(|w| w == b"MARKER").unwrap();
        bytes[at] ^= 1;
        bytes
    }

    pub(crate) fn zip_read_error(bytes: &[u8]) -> io::Error {
        let mut archive = zip::ZipArchive::new(io::Cursor::new(bytes.to_vec())).unwrap();
        let mut entry = archive.by_index(0).unwrap();
        io::copy(&mut entry, &mut io::sink()).unwrap_err()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::assert_matches;

    use super::zip_fixtures::bad_crc_zip;
    use super::zip_fixtures::forged_size_zip;
    use super::zip_fixtures::zip_read_error;
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

    fn tap_with_fault() -> SourceTap {
        let tap = SourceTap::default();
        tap.fault.record(&io::Error::from_raw_os_error(5));
        tap
    }

    fn decoder_error() -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, "lzma data error")
    }

    #[test]
    fn a_decoder_error_without_a_source_fault_is_a_malformed_entry() {
        let tap = SourceTap::default();
        for (family, expected) in [
            (
                ReadFamily::Tar,
                Malformation::TarEntryUnreadable {
                    detail: "lzma data error".into(),
                },
            ),
            (
                ReadFamily::Zip,
                Malformation::ZipEntryDataUnreadable {
                    detail: "lzma data error".into(),
                },
            ),
            (
                ReadFamily::SevenZ,
                Malformation::SevenZEntryDataUnreadable {
                    detail: "lzma data error".into(),
                },
            ),
        ] {
            let error =
                ReadFaults::new(family, Some(&tap)).classify(CopyError::Read(decoder_error()));
            assert_matches!(error, ArchiveError::InvalidArchive(ref m) if *m == expected, "{family:?}");
        }
    }

    #[test]
    fn a_recorded_source_fault_wins_over_the_decoder_verdict() {
        let tap = tap_with_fault();
        for family in [ReadFamily::Tar, ReadFamily::Zip, ReadFamily::SevenZ] {
            let error =
                ReadFaults::new(family, Some(&tap)).classify(CopyError::Read(decoder_error()));
            assert_matches!(error, ArchiveError::Io(ref e) if e.raw_os_error() == Some(5), "{family:?}");
        }
    }

    #[test]
    fn an_errno_is_the_disks_even_without_a_recorded_fault() {
        let error = ReadFaults::new(ReadFamily::Zip, None)
            .classify(CopyError::Read(io::Error::from_raw_os_error(28)));
        assert_matches!(error, ArchiveError::Io(ref e) if e.raw_os_error() == Some(28));
    }

    #[test]
    fn an_opaque_reader_keeps_every_read_error_as_io() {
        let error =
            ReadFaults::new(ReadFamily::Opaque, None).classify(CopyError::Read(decoder_error()));
        assert_matches!(error, ArchiveError::Io(ref e) if e.kind() == io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_budget_refusal_wins_over_a_recorded_fault() {
        let exceeded =
            io::Error::other(super::super::tar_metadata_limit::DecoderMemoryExceeded { max: 7 });
        let tap = tap_with_fault();
        let error =
            ReadFaults::new(ReadFamily::Tar, Some(&tap)).classify(CopyError::Read(exceeded));
        assert_matches!(error, ArchiveError::QuotaExceeded { .. });
    }

    #[test]
    fn the_zip_size_ceiling_is_left_for_the_entry_to_type() {
        let ceiling = io::Error::new(io::ErrorKind::InvalidData, "ceiling");
        let error = ReadFaults::new(ReadFamily::Zip, None).classify(CopyError::Read(ceiling));
        assert_matches!(error, ArchiveError::InvalidArchive(_));

        let ceiling = zip_read_error(&forged_size_zip());
        let error = ReadFaults::new(ReadFamily::Zip, None).classify(CopyError::Read(ceiling));
        assert_matches!(error, ArchiveError::Io(ref e) if DeclaredSizeCeiling::is(e));
    }

    #[test]
    fn zip_crate_contract_holds() {
        assert_eq!(
            zip_crate_failure(&zip_read_error(&bad_crc_zip())),
            Some(ZipCrateFailure::InvalidChecksum),
            "the zip crate changed its checksum error; update zip_crate_failure"
        );
        assert_eq!(
            zip_crate_failure(&zip_read_error(&forged_size_zip())),
            Some(ZipCrateFailure::DeclaredSizeExceeded),
            "the zip crate changed its declared-size error; update zip_crate_failure"
        );
    }

    #[test]
    fn the_verdict_chain_orders_its_causes() {
        let exceeded =
            io::Error::other(super::super::tar_metadata_limit::DecoderMemoryExceeded { max: 7 });
        assert_matches!(
            classify_decoder_read(exceeded, Some(io::Error::from_raw_os_error(5))),
            ReadVerdict::Budget(_)
        );
        assert_matches!(
            classify_decoder_read(
                zip_read_error(&bad_crc_zip()),
                Some(io::Error::other("eio"))
            ),
            ReadVerdict::SourceFault(_)
        );
        assert_matches!(
            classify_decoder_read(io::Error::from_raw_os_error(28), None),
            ReadVerdict::SourceFault(_)
        );
        assert_matches!(
            classify_decoder_read(zip_read_error(&bad_crc_zip()), None),
            ReadVerdict::Checksum(_)
        );
        assert_matches!(
            classify_decoder_read(ReplayChecksumMismatch::into_io(), None),
            ReadVerdict::Checksum(_)
        );
        assert_matches!(
            classify_decoder_read(
                io::Error::other(sevenz_rust2::Error::ChecksumVerificationFailed),
                None
            ),
            ReadVerdict::Checksum(_)
        );
        assert_matches!(
            classify_decoder_read(zip_read_error(&forged_size_zip()), None),
            ReadVerdict::DeclaredSizeOverrun(_)
        );
        assert_matches!(
            classify_decoder_read(io::ErrorKind::UnexpectedEof.into(), None),
            ReadVerdict::Truncated(_)
        );
        assert_matches!(
            classify_decoder_read(decoder_error(), None),
            ReadVerdict::Malformed(_)
        );
    }

    #[test]
    fn a_plain_error_with_checksum_text_is_not_a_zip_failure_without_a_payload() {
        let bare = io::Error::from(io::ErrorKind::InvalidData);
        assert_eq!(zip_crate_failure(&bare), None);
    }

    #[test]
    fn a_failed_write_is_io_whatever_the_source_did() {
        let tap = tap_with_fault();
        let error = ReadFaults::new(ReadFamily::Tar, Some(&tap))
            .classify(CopyError::Write(io::Error::from_raw_os_error(28)));
        assert_matches!(error, ArchiveError::Io(ref e) if e.raw_os_error() == Some(28));
    }

    #[test]
    fn a_short_tar_entry_is_truncated_unless_the_source_failed() {
        let short = || CopyError::Short {
            declared: 10,
            actual: 4,
        };
        let clean = SourceTap::default();
        assert_matches!(
            ReadFaults::new(ReadFamily::Tar, Some(&clean)).classify(short()),
            ArchiveError::InvalidArchive(Malformation::TarEntryTruncated {
                declared: 10,
                actual: 4
            })
        );
        let faulty = tap_with_fault();
        for family in [ReadFamily::Tar, ReadFamily::Zip, ReadFamily::SevenZ] {
            assert_matches!(
                ReadFaults::new(family, Some(&faulty)).classify(short()),
                ArchiveError::Io(ref e) if e.raw_os_error() == Some(5),
                "{family:?}"
            );
        }
    }

    #[test]
    fn a_short_zip_or_7z_entry_and_every_overrun_keep_the_declared_size_verdict() {
        for family in [ReadFamily::Zip, ReadFamily::SevenZ, ReadFamily::Opaque] {
            let faults = ReadFaults::new(family, None);
            assert_matches!(
                faults.classify(CopyError::Short {
                    declared: 10,
                    actual: 4
                }),
                ArchiveError::SecurityViolation { .. },
                "{family:?}"
            );
        }
        for family in [ReadFamily::Tar, ReadFamily::Zip, ReadFamily::SevenZ] {
            assert_matches!(
                ReadFaults::new(family, None).classify(CopyError::Overrun { declared: 3 }),
                ArchiveError::SecurityViolation { .. },
                "{family:?}"
            );
        }
    }

    #[test]
    fn a_tar_source_picks_its_tap_and_an_opaque_one_reads_as_io() {
        let tap = tap_with_fault();
        let replay = TapSource::Replay(tap);
        assert_matches!(
            ReadFaults::of_tar(&replay).classify(CopyError::Read(decoder_error())),
            ArchiveError::Io(_)
        );
        assert_matches!(
            ReadFaults::of_tar(&TapSource::Opaque).classify(CopyError::Read(decoder_error())),
            ArchiveError::Io(_)
        );
        assert_matches!(
            ReadFaults::of_tar(&TapSource::Tapped(SourceTap::default()))
                .classify(CopyError::Read(decoder_error())),
            ArchiveError::InvalidArchive(_)
        );
    }

    #[test]
    fn a_symlink_target_read_is_io_after_a_source_fault_and_unreadable_otherwise() {
        let faulty = tap_with_fault();
        assert_matches!(
            ReadFaults::new(ReadFamily::Zip, Some(&faulty)).classify_symlink_read(decoder_error()),
            ArchiveError::Io(_)
        );
        let clean = SourceTap::default();
        assert_matches!(
            ReadFaults::new(ReadFamily::Zip, Some(&clean)).classify_symlink_read(decoder_error()),
            ArchiveError::InvalidArchive(Malformation::SymlinkTargetUnreadable { .. })
        );
    }

    #[test]
    fn a_failed_seek_is_a_recorded_fault() {
        struct NoSeek;
        impl Read for NoSeek {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Ok(0)
            }
        }
        impl Seek for NoSeek {
            fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
                Err(io::Error::from_raw_os_error(5))
            }
        }
        let tap = SourceTap::default();
        let mut reader = SourceRead::new(NoSeek, tap.clone());
        reader.seek(SeekFrom::Start(1)).unwrap_err();
        assert_eq!(tap.fault().unwrap().raw_os_error(), Some(5));
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
