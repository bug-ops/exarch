//! How extraction classifies a failed read of entry data (issues #964, #965):
//! a decoder or checksum failure and a truncated stream are a malformed
//! archive, a fault of the archive's source or of the destination is
//! `ArchiveError::Io`, and the declared-size ceiling keeps its security
//! verdict, in every container.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod sink_support;

use std::assert_matches;
use std::io;
use std::io::Cursor;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use exarch_core::AdmittedSize;
use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::CheckedLinkTarget;
use exarch_core::CompressionCodec;
use exarch_core::EntrySink;
use exarch_core::Malformation;
use exarch_core::MemoryLimit;
use exarch_core::MemorySink;
use exarch_core::SafePath;
use exarch_core::SanitizedMode;
use exarch_core::SecurityConfig;
use exarch_core::SeekableFormat;
use exarch_core::SinkExtractRequest;
use exarch_core::SinkOptions;
use exarch_testkit::raw_zip::RawEntry;
use flate2::Compression;
use flate2::write::GzEncoder;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use sevenz_rust2::EncoderMethod;
use sink_support::RecordingSink;
use sink_support::tar_archive;
use sink_support::tar_file;
use sink_support::zip_archive;

const EIO: i32 = 5;
const ENOSPC: i32 = 28;
const PAYLOAD_LEN: usize = 3000;

/// Bytes a compressor cannot shrink and that no header can be mistaken for.
fn payload() -> Vec<u8> {
    let mut state: u32 = 0x9E37_79B9;
    (0..PAYLOAD_LEN)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state.to_le_bytes()[0]
        })
        .collect()
}

fn root(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction(partial) => root(partial.cause()),
        other => other,
    }
}

fn extract_into(
    reader: ArchiveReader<'static>,
    sink: &mut impl EntrySink,
) -> Result<(), ArchiveError> {
    SinkExtractRequest::new(&SecurityConfig::default())
        .with_options(SinkOptions::default())
        .extract(reader, sink)
        .map(drop)
}

fn extract(reader: ArchiveReader<'static>) -> Result<(), ArchiveError> {
    extract_into(reader, &mut MemorySink::new(MemoryLimit::DEFAULT))
}

fn tar_bytes() -> Vec<u8> {
    tar_archive(&[tar_file("a.bin", &payload()), tar_file("b.txt", b"tail")])
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn xz(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = liblzma::write::XzEncoder::new(Vec::new(), 1);
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn zip_bytes() -> Vec<u8> {
    zip_archive(vec![
        RawEntry::stored("a.bin", &payload()),
        RawEntry::deflated("c.bin", &payload()).unwrap(),
    ])
}

/// Stored entries larger than the window the ZIP reader serves headers from,
/// so extraction reads the source again after the structural check.
fn large_zip_bytes() -> Vec<u8> {
    let big = payload().repeat(40);
    zip_archive(vec![
        RawEntry::stored("a.bin", &big),
        RawEntry::stored("b.bin", &big),
    ])
}

fn sevenz_bytes() -> Vec<u8> {
    let mut buffer = Cursor::new(Vec::new());
    let mut writer = ArchiveWriter::new(&mut buffer).unwrap();
    writer.set_content_methods(vec![EncoderMethod::COPY.into()]);
    writer
        .push_archive_entry(ArchiveEntry::new_file("a.bin"), Some(&payload()[..]))
        .unwrap();
    writer.finish().unwrap();
    buffer.into_inner()
}

fn flip_in_payload(bytes: &mut [u8]) {
    let payload = payload();
    let at = bytes
        .windows(64)
        .position(|window| window == &payload[..64])
        .expect("the payload is stored verbatim");
    bytes[at + 1000] ^= 0x40;
}

fn zip_reader(bytes: Vec<u8>) -> ArchiveReader<'static> {
    ArchiveReader::seekable(Cursor::new(bytes), SeekableFormat::Zip)
}

fn sevenz_reader(bytes: Vec<u8>) -> ArchiveReader<'static> {
    ArchiveReader::seekable(Cursor::new(bytes), SeekableFormat::SevenZ)
}

#[test]
fn a_zip_checksum_failure_is_a_malformed_archive() {
    let mut bytes = zip_bytes();
    flip_in_payload(&mut bytes);
    let error = extract(zip_reader(bytes)).unwrap_err();
    assert_matches!(
        root(&error),
        ArchiveError::InvalidArchive(Malformation::ZipEntryDataUnreadable { .. }),
        "{error:?}"
    );
}

#[test]
fn a_corrupt_deflate_stream_is_a_malformed_archive() {
    let mut corrupt = RawEntry::deflated("c.bin", &payload()).unwrap();
    let middle = corrupt.data.len() / 2;
    corrupt.data[middle] ^= 0xFF;
    corrupt.data[middle + 1] ^= 0xFF;
    let error = extract(zip_reader(zip_archive(vec![corrupt]))).unwrap_err();
    assert_matches!(
        root(&error),
        ArchiveError::InvalidArchive(_) | ArchiveError::SecurityViolation { .. },
        "{error:?}"
    );
    assert!(!matches!(root(&error), ArchiveError::Io(_)), "{error:?}");
}

#[test]
fn a_7z_checksum_failure_is_a_malformed_archive() {
    let mut bytes = sevenz_bytes();
    flip_in_payload(&mut bytes);
    let error = extract(sevenz_reader(bytes)).unwrap_err();
    assert_matches!(
        root(&error),
        ArchiveError::InvalidArchive(Malformation::SevenZEntryDataUnreadable { .. }),
        "{error:?}"
    );
}

#[test]
fn a_corrupt_compressed_tar_is_a_malformed_archive() {
    for (codec, mut bytes) in [
        (CompressionCodec::Gzip, gzip(&tar_bytes())),
        (CompressionCodec::Xz, xz(&tar_bytes())),
    ] {
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0xFF;
        bytes[middle + 1] ^= 0xFF;
        let error = extract(ArchiveReader::tar(Cursor::new(bytes), Some(codec))).unwrap_err();
        assert_matches!(
            root(&error),
            ArchiveError::InvalidArchive(_) | ArchiveError::TarTrailer(_),
            "{codec:?}: {error:?}"
        );
    }
}

#[test]
fn a_truncated_tar_is_a_truncated_archive_not_a_size_violation() {
    let bytes = tar_bytes();
    let cut = 512 + PAYLOAD_LEN / 2;
    let error = extract(ArchiveReader::tar(Cursor::new(bytes[..cut].to_vec()), None)).unwrap_err();
    assert_matches!(
        root(&error),
        ArchiveError::InvalidArchive(Malformation::TarEntryTruncated { declared: 3000, .. }),
        "{error:?}"
    );
}

#[test]
fn a_truncated_compressed_tar_is_a_malformed_archive() {
    for (codec, bytes) in [
        (CompressionCodec::Gzip, gzip(&tar_bytes())),
        (CompressionCodec::Xz, xz(&tar_bytes())),
    ] {
        let cut = bytes.len() * 2 / 3;
        let error = extract(ArchiveReader::tar(
            Cursor::new(bytes[..cut].to_vec()),
            Some(codec),
        ))
        .unwrap_err();
        assert_matches!(
            root(&error),
            ArchiveError::InvalidArchive(_),
            "{codec:?}: {error:?}"
        );
    }
}

#[test]
fn a_truncated_zip_or_7z_is_a_malformed_archive() {
    for (name, error) in [
        (
            "zip",
            extract(zip_reader(zip_bytes()[..PAYLOAD_LEN].to_vec())).unwrap_err(),
        ),
        (
            "7z",
            extract(sevenz_reader(sevenz_bytes()[..PAYLOAD_LEN].to_vec())).unwrap_err(),
        ),
    ] {
        assert_matches!(
            root(&error),
            ArchiveError::InvalidArchive(_),
            "{name}: {error:?}"
        );
    }
}

/// The error a failing source raises: with an errno, as a file does, or
/// without one, as a caller's reader or an FFI-backed one does.
#[derive(Clone, Copy, Debug)]
enum Fault {
    Errno,
    Other,
}

const OTHER_MESSAGE: &str = "injected source fault";

impl Fault {
    fn raise(self) -> io::Error {
        match self {
            Self::Errno => io::Error::from_raw_os_error(EIO),
            Self::Other => io::Error::other(OTHER_MESSAGE),
        }
    }

    fn is_raised_by(self, error: &io::Error) -> bool {
        match self {
            Self::Errno => error.raw_os_error() == Some(EIO),
            Self::Other => error.raw_os_error().is_none() && error.to_string() == OTHER_MESSAGE,
        }
    }
}

/// Fails every read from the `fail_from`-th on, counting into `reads`.
struct Flaky {
    inner: Cursor<Vec<u8>>,
    reads: Arc<AtomicUsize>,
    fail_from: usize,
    fault: Fault,
}

impl Read for Flaky {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.reads.fetch_add(1, Ordering::Relaxed) >= self.fail_from {
            return Err(self.fault.raise());
        }
        self.inner.read(buf)
    }
}

impl Seek for Flaky {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// Sweeps a source fault over every read of an archive: each position ends in
/// success or in `Io` carrying the injected error, never in a malformed-archive
/// verdict, and at least one fault lands after the sink has started a file.
fn assert_source_faults_are_io(
    label: &str,
    bytes: &[u8],
    open: impl Fn(Flaky) -> ArchiveReader<'static>,
) {
    for fault in [Fault::Errno, Fault::Other] {
        let run = |fail_from: usize| {
            let reads = Arc::new(AtomicUsize::new(0));
            let reader = open(Flaky {
                inner: Cursor::new(bytes.to_vec()),
                reads: Arc::clone(&reads),
                fail_from,
                fault,
            });
            let mut sink = RecordingSink::default();
            let result = extract_into(reader, &mut sink);
            (
                result,
                reads.load(Ordering::Relaxed),
                !sink.modes.is_empty(),
            )
        };
        let (clean, total, _) = run(usize::MAX);
        clean.unwrap();
        let mut during_extraction = 0;
        for fail_from in 0..=total {
            let (result, _, started) = run(fail_from);
            if let Err(error) = result {
                assert_matches!(
                    root(&error),
                    ArchiveError::Io(io) if fault.is_raised_by(io),
                    "{label} {fault:?} fault from read {fail_from}: {error:?}"
                );
                during_extraction += usize::from(started);
            }
        }
        assert!(
            during_extraction > 0,
            "{label} {fault:?}: no fault reached the entry data"
        );
    }
}

#[test]
fn a_zip_source_fault_is_io_wherever_it_lands() {
    assert_source_faults_are_io("zip", &large_zip_bytes(), |source| {
        ArchiveReader::seekable(source, SeekableFormat::Zip)
    });
}

#[test]
fn a_7z_source_fault_is_io_wherever_it_lands() {
    assert_source_faults_are_io("7z", &sevenz_bytes(), |source| {
        ArchiveReader::seekable(source, SeekableFormat::SevenZ)
    });
}

fn large_tar_bytes() -> Vec<u8> {
    let big = payload().repeat(40);
    tar_archive(&[tar_file("a.bin", &big), tar_file("b.bin", &big)])
}

#[test]
fn a_tar_source_fault_is_io_wherever_it_lands() {
    assert_source_faults_are_io("tar", &large_tar_bytes(), |source| {
        ArchiveReader::tar(source, None)
    });
    assert_source_faults_are_io("tar.gz", &gzip(&large_tar_bytes()), |source| {
        ArchiveReader::tar(source, Some(CompressionCodec::Gzip))
    });
    assert_source_faults_are_io("tar.xz", &xz(&large_tar_bytes()), |source| {
        ArchiveReader::tar(source, Some(CompressionCodec::Xz))
    });
}

#[test]
fn a_zip_symlink_target_source_fault_is_io() {
    let bytes = zip_archive(vec![
        RawEntry::stored("big.bin", &payload().repeat(40)),
        sink_support::zip_symlink("l", &"t".repeat(500)),
    ]);
    let config = SecurityConfig::default().with_allow_symlinks(true);
    let mut seen_io = 0;
    for fault in [Fault::Errno, Fault::Other] {
        let total = {
            let reads = Arc::new(AtomicUsize::new(0));
            let reader = ArchiveReader::seekable(
                Flaky {
                    inner: Cursor::new(bytes.clone()),
                    reads: Arc::clone(&reads),
                    fail_from: usize::MAX,
                    fault,
                },
                SeekableFormat::Zip,
            );
            SinkExtractRequest::new(&config)
                .with_options(SinkOptions::default())
                .extract(reader, &mut RecordingSink::default())
                .unwrap();
            reads.load(Ordering::Relaxed)
        };
        for fail_from in 0..=total {
            let reader = ArchiveReader::seekable(
                Flaky {
                    inner: Cursor::new(bytes.clone()),
                    reads: Arc::new(AtomicUsize::new(0)),
                    fail_from,
                    fault,
                },
                SeekableFormat::Zip,
            );
            let result = SinkExtractRequest::new(&config)
                .with_options(SinkOptions::default())
                .extract(reader, &mut RecordingSink::default());
            if let Err(error) = result {
                assert_matches!(
                    root(&error),
                    ArchiveError::Io(io) if fault.is_raised_by(io),
                    "{fault:?} fault from read {fail_from}: {error:?}"
                );
                seen_io += 1;
            }
        }
    }
    assert!(seen_io > 0);
}

/// A sink whose storage is full.
struct FullSink;

struct FullDisk;

impl Write for FullDisk {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(ENOSPC))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl EntrySink for FullSink {
    type File = FullDisk;

    fn create_directory(&mut self, _: &SafePath) -> io::Result<()> {
        Ok(())
    }

    fn create_file(
        &mut self,
        _: &SafePath,
        _: Option<SanitizedMode>,
        _: AdmittedSize,
    ) -> io::Result<FullDisk> {
        Ok(FullDisk)
    }

    fn finish_file(&mut self, _: &SafePath, _: FullDisk) -> io::Result<()> {
        Ok(())
    }

    fn create_symlink(&mut self, _: &SafePath, _: CheckedLinkTarget<'_>) -> io::Result<()> {
        Ok(())
    }

    fn create_hardlink(&mut self, _: &SafePath, _: &SafePath) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_full_destination_stays_io_in_every_container() {
    let readers: [(&str, ArchiveReader<'static>); 5] = [
        ("tar", ArchiveReader::tar(Cursor::new(tar_bytes()), None)),
        (
            "tar.gz",
            ArchiveReader::tar(
                Cursor::new(gzip(&tar_bytes())),
                Some(CompressionCodec::Gzip),
            ),
        ),
        ("zip", zip_reader(zip_bytes())),
        (
            "zip single entry",
            zip_reader(zip_archive(vec![RawEntry::stored("a", &payload())])),
        ),
        ("7z", sevenz_reader(sevenz_bytes())),
    ];
    for (name, reader) in readers {
        let error = extract_into(reader, &mut FullSink).unwrap_err();
        assert_matches!(
            root(&error),
            ArchiveError::Io(io) if io.raw_os_error() == Some(ENOSPC),
            "{name}: {error:?}"
        );
    }
}

/// A 7z archive of two LZMA2 files in separate blocks, the first of text that
/// compresses well.
fn sevenz_two_blocks() -> Vec<u8> {
    let text: Vec<u8> = (0..20_000u32).map(|i| b'a' + (i % 7) as u8).collect();
    let mut buffer = Cursor::new(Vec::new());
    let mut writer = ArchiveWriter::new(&mut buffer).unwrap();
    writer
        .push_archive_entry(ArchiveEntry::new_file("skipped.bin"), Some(&text[..]))
        .unwrap();
    writer
        .push_archive_entry(ArchiveEntry::new_file("kept.txt"), Some(&b"kept"[..]))
        .unwrap();
    writer.finish().unwrap();
    buffer.into_inner()
}

/// The decoder of a block an extension filter skips is drained outside the
/// per-entry callback: its data errors are decoder verdicts, never `Io`.
#[test]
fn a_7z_decoder_error_while_draining_a_skipped_entry_is_a_malformed_archive() {
    let config = SecurityConfig::default()
        .try_add_allowed_extension("txt")
        .unwrap();
    let clean = sevenz_two_blocks();
    let mut malformed = 0;
    for at in 33..120 {
        let mut bytes = clean.clone();
        bytes[at] ^= 0xFF;
        let result = SinkExtractRequest::new(&config)
            .with_options(SinkOptions::default())
            .extract(
                sevenz_reader(bytes),
                &mut MemorySink::new(MemoryLimit::DEFAULT),
            );
        match result.as_ref().map_err(root) {
            Err(ArchiveError::Io(error)) => panic!("byte {at}: {error:?}"),
            Err(ArchiveError::InvalidArchive(_)) => malformed += 1,
            _ => {}
        }
    }
    assert!(malformed > 0);
}
