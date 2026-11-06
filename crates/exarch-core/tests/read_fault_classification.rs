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

/// Fails every read from the `fail_from`-th on, counting into `reads`.
struct Flaky {
    inner: Cursor<Vec<u8>>,
    reads: Arc<AtomicUsize>,
    fail_from: usize,
}

impl Read for Flaky {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.reads.fetch_add(1, Ordering::Relaxed) >= self.fail_from {
            return Err(io::Error::from_raw_os_error(EIO));
        }
        self.inner.read(buf)
    }
}

impl Seek for Flaky {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// Sweeps a source fault over every read of a seekable archive: each position
/// ends in success or in `Io` carrying the injected errno, never in a
/// malformed-archive verdict, and at least one fault lands after the sink has
/// started a file.
fn assert_source_faults_are_io(bytes: &[u8], format: SeekableFormat) {
    let run = |fail_from: usize| {
        let reads = Arc::new(AtomicUsize::new(0));
        let reader = ArchiveReader::seekable(
            Flaky {
                inner: Cursor::new(bytes.to_vec()),
                reads: Arc::clone(&reads),
                fail_from,
            },
            format,
        );
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
        match result {
            Ok(()) => {}
            Err(error) => {
                assert_matches!(
                    root(&error),
                    ArchiveError::Io(io) if io.raw_os_error() == Some(EIO),
                    "{format:?} fault from read {fail_from}: {error:?}"
                );
                during_extraction += usize::from(started);
            }
        }
    }
    assert!(
        during_extraction > 0,
        "{format:?}: no fault reached the entry data"
    );
}

#[test]
fn a_zip_source_fault_is_io_wherever_it_lands() {
    assert_source_faults_are_io(&large_zip_bytes(), SeekableFormat::Zip);
}

#[test]
fn a_7z_source_fault_is_io_wherever_it_lands() {
    assert_source_faults_are_io(&sevenz_bytes(), SeekableFormat::SevenZ);
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
