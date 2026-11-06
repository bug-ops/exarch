//! `ArchiveReader::detect` and `detect_stream` pick the same format as the
//! path-based detection, and fail with a typed reason where they cannot.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

mod sink_support;

use std::assert_matches;
use std::io::Cursor;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;

use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::ArchiveType;
use exarch_core::CompressionCodec;
use exarch_core::ListOptions;
use exarch_core::ListRequest;
use exarch_core::ReaderFormatError;
use exarch_core::SecurityConfig;
use exarch_core::SeekableFormat;
use exarch_core::detect_format;
use sink_support::tar_archive;
use sink_support::tar_file;
use sink_support::zip_archive;
use sink_support::zip_file;
use tempfile::TempDir;

/// A source that can only read.
struct ReadOnly<R>(R);

impl<R: Read> Read for ReadOnly<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

/// A source that hands out one byte per read.
struct OneByte<R>(R);

impl<R: Read> Read for OneByte<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let take = buf.len().min(1);
        self.0.read(&mut buf[..take])
    }
}

fn plain_tar() -> Vec<u8> {
    tar_archive(&[tar_file("a.txt", b"alpha")])
}

fn compress(codec: CompressionCodec, data: &[u8]) -> Vec<u8> {
    match codec {
        CompressionCodec::Gzip => {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            e.write_all(data).unwrap();
            e.finish().unwrap()
        }
        CompressionCodec::Bzip2 => {
            let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
            e.write_all(data).unwrap();
            e.finish().unwrap()
        }
        CompressionCodec::Xz => {
            let mut e = liblzma::write::XzEncoder::new(Vec::new(), 1);
            e.write_all(data).unwrap();
            e.finish().unwrap()
        }
        CompressionCodec::Zstd => zstd::encode_all(data, 1).unwrap(),
        _ => unreachable!("every codec is covered"),
    }
}

fn seven_z() -> Vec<u8> {
    let mut writer = sevenz_rust2::ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    let mut entry = sevenz_rust2::ArchiveEntry::new_file("a.txt");
    entry.has_stream = true;
    entry.size = 5;
    writer
        .push_archive_entry(entry, Some(Cursor::new(b"alpha".to_vec())))
        .unwrap();
    writer.finish().unwrap().into_inner()
}

fn zip() -> Vec<u8> {
    zip_archive(vec![zip_file("a.txt", b"alpha")])
}

fn every_format() -> Vec<(ArchiveType, Vec<u8>)> {
    vec![
        (ArchiveType::Tar, plain_tar()),
        (
            ArchiveType::TarGz,
            compress(CompressionCodec::Gzip, &plain_tar()),
        ),
        (
            ArchiveType::TarBz2,
            compress(CompressionCodec::Bzip2, &plain_tar()),
        ),
        (
            ArchiveType::TarXz,
            compress(CompressionCodec::Xz, &plain_tar()),
        ),
        (
            ArchiveType::TarZst,
            compress(CompressionCodec::Zstd, &plain_tar()),
        ),
        (ArchiveType::Zip, zip()),
        (ArchiveType::SevenZ, seven_z()),
    ]
}

fn reader_format_error(result: exarch_core::Result<ArchiveReader<'_>>) -> ReaderFormatError {
    match result.unwrap_err() {
        ArchiveError::ReaderFormat(reason) => reason,
        other => panic!("expected a reader format error, got {other:?}"),
    }
}

fn path_format(bytes: &[u8]) -> ArchiveType {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("archive.bin");
    std::fs::write(&path, bytes).unwrap();
    detect_format(&path).unwrap()
}

fn listing(reader: ArchiveReader<'_>) -> String {
    let manifest = ListRequest::new(&SecurityConfig::default())
        .with_options(ListOptions::default())
        .list_reader(reader);
    format!("{:?}", manifest.unwrap())
}

#[test]
fn detect_recognizes_every_format_from_a_cursor() {
    for (expected, bytes) in every_format() {
        let reader = ArchiveReader::detect(Cursor::new(bytes)).unwrap();
        assert_eq!(reader.format(), expected);
    }
}

#[test]
fn detect_stream_recognizes_every_tar_variant_from_a_read_only_source() {
    for (expected, bytes) in every_format().into_iter().take(5) {
        let reader = ArchiveReader::detect_stream(ReadOnly(Cursor::new(bytes))).unwrap();
        assert_eq!(reader.format(), expected);
    }
}

#[test]
fn detect_stream_needs_a_seekable_source_for_containers() {
    let zip = ArchiveReader::detect_stream(ReadOnly(Cursor::new(zip())));
    assert_eq!(
        reader_format_error(zip),
        ReaderFormatError::NeedsSeek(SeekableFormat::Zip)
    );
    let seven_z = ArchiveReader::detect_stream(ReadOnly(Cursor::new(seven_z())));
    assert_eq!(
        reader_format_error(seven_z),
        ReaderFormatError::NeedsSeek(SeekableFormat::SevenZ)
    );
}

#[test]
fn empty_and_unrecognized_input_is_unrecognized() {
    for bytes in [Vec::new(), b"hello, world".to_vec(), vec![0; 1024]] {
        assert_eq!(
            reader_format_error(ArchiveReader::detect(Cursor::new(bytes.clone()))),
            ReaderFormatError::Unrecognized
        );
        assert_eq!(
            reader_format_error(ArchiveReader::detect_stream(ReadOnly(Cursor::new(bytes)))),
            ReaderFormatError::Unrecognized
        );
    }
}

#[test]
fn detect_stream_replays_only_the_bytes_it_read() {
    let bytes = compress(CompressionCodec::Gzip, &plain_tar());
    assert!(
        bytes.len() < 512,
        "the fixture must be shorter than the peek window"
    );
    let expected = listing(ArchiveReader::tar(
        Cursor::new(bytes.clone()),
        Some(CompressionCodec::Gzip),
    ));
    let detected = ArchiveReader::detect_stream(ReadOnly(Cursor::new(bytes))).unwrap();
    assert_eq!(listing(detected), expected);
}

#[test]
fn detect_stream_survives_one_byte_reads() {
    let bytes = plain_tar();
    let expected = listing(ArchiveReader::tar(Cursor::new(bytes.clone()), None));
    let detected = ArchiveReader::detect_stream(OneByte(Cursor::new(bytes))).unwrap();
    assert_eq!(listing(detected), expected);
}

#[test]
fn detect_then_list_equals_the_explicit_constructor() {
    for (format, bytes) in every_format() {
        let explicit = listing(ArchiveReader::of_type(Cursor::new(bytes.clone()), format));
        let detected = listing(ArchiveReader::detect(Cursor::new(bytes)).unwrap());
        assert_eq!(detected, explicit, "{format}");
    }
}

#[test]
fn detect_leaves_the_reader_where_it_was() {
    let mut cursor = Cursor::new(plain_tar());
    cursor.seek(SeekFrom::Start(0)).unwrap();
    drop(ArchiveReader::detect(&mut cursor).unwrap());
    assert_eq!(cursor.position(), 0);
}

#[test]
fn a_tar_may_start_past_offset_zero() {
    let mut bytes = vec![0xAA; 10];
    bytes.extend(plain_tar());
    let mut cursor = Cursor::new(bytes);
    cursor.set_position(10);
    let reader = ArchiveReader::detect(cursor).unwrap();
    assert_eq!(reader.format(), ArchiveType::Tar);
    assert_eq!(
        listing(reader),
        listing(ArchiveReader::tar(Cursor::new(plain_tar()), None))
    );
}

#[test]
fn a_container_past_offset_zero_is_not_at_start() {
    for (format, seekable) in [
        (ArchiveType::Zip, SeekableFormat::Zip),
        (ArchiveType::SevenZ, SeekableFormat::SevenZ),
    ] {
        let bytes = every_format()
            .into_iter()
            .find_map(|(t, b)| (t == format).then_some(b))
            .unwrap();
        let mut padded = vec![0xAA; 10];
        padded.extend(bytes);
        let mut cursor = Cursor::new(padded);
        cursor.set_position(10);
        assert_eq!(
            reader_format_error(ArchiveReader::detect(cursor)),
            ReaderFormatError::NotAtStart(seekable)
        );
    }
}

#[test]
fn broken_checksum_header_with_zip_magic_is_zip_by_path_and_seekable_detection() {
    let mut bytes = plain_tar();
    bytes[..4].copy_from_slice(b"PK\x03\x04");
    assert_eq!(path_format(&bytes), ArchiveType::Zip);
    assert_eq!(
        ArchiveReader::detect(Cursor::new(bytes.clone()))
            .unwrap()
            .format(),
        ArchiveType::Zip
    );
    assert_eq!(
        reader_format_error(ArchiveReader::detect_stream(ReadOnly(Cursor::new(bytes)))),
        ReaderFormatError::NeedsSeek(SeekableFormat::Zip)
    );
}

#[test]
fn broken_checksum_header_with_gzip_magic_is_tar_gz_everywhere() {
    let mut bytes = plain_tar();
    bytes[..2].copy_from_slice(b"\x1f\x8b");
    assert_eq!(path_format(&bytes), ArchiveType::TarGz);
    assert_eq!(
        ArchiveReader::detect(Cursor::new(bytes.clone()))
            .unwrap()
            .format(),
        ArchiveType::TarGz
    );
    assert_eq!(
        ArchiveReader::detect_stream(ReadOnly(Cursor::new(bytes)))
            .unwrap()
            .format(),
        ArchiveType::TarGz
    );
}

#[test]
fn reader_format_errors_map_to_ffi_kinds() {
    use exarch_core::ErrorCode;

    let unrecognized = ArchiveError::ReaderFormat(ReaderFormatError::Unrecognized);
    assert_eq!(unrecognized.error_code(), ErrorCode::UnknownFormat);
    for reason in [
        ReaderFormatError::NeedsSeek(SeekableFormat::Zip),
        ReaderFormatError::NotAtStart(SeekableFormat::SevenZ),
    ] {
        let error = ArchiveError::ReaderFormat(reason);
        assert_matches!(error.error_code(), ErrorCode::InvalidConfiguration);
        assert_eq!(error.redacted_path(), None);
    }
}

/// A plain TAR whose first member name starts with `prefix`, checksum sealed.
fn tar_named_with_prefix(prefix: &[u8]) -> Vec<u8> {
    let mut bytes = plain_tar();
    bytes[..prefix.len()].copy_from_slice(prefix);
    let mut header = tar::Header::new_gnu();
    header.as_mut_bytes().copy_from_slice(&bytes[..512]);
    header.set_cksum();
    bytes[..512].copy_from_slice(header.as_bytes());
    bytes
}

#[test]
fn valid_tar_with_a_bzh_name_is_tar_everywhere() {
    let bytes = tar_named_with_prefix(b"BZhfoo");
    for name in ["x.tar", "x.bz2", "x.tar.gz", "x.zst", "x"] {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(name);
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::Tar, "{name}");
    }
    assert_eq!(
        ArchiveReader::detect(Cursor::new(bytes.clone()))
            .unwrap()
            .format(),
        ArchiveType::Tar
    );
    let streamed = ArchiveReader::detect_stream(ReadOnly(Cursor::new(bytes.clone()))).unwrap();
    assert_eq!(streamed.format(), ArchiveType::Tar);
    let expected = listing(ArchiveReader::tar(Cursor::new(bytes.clone()), None));
    assert_eq!(listing(streamed), expected);
    assert_eq!(
        listing(ArchiveReader::detect(Cursor::new(bytes)).unwrap()),
        expected
    );
}

#[test]
fn a_sealed_ustar_block_does_not_override_gzip_zstd_or_xz() {
    let cases: [(&[u8], ArchiveType); 3] = [
        (b"\x1f\x8b", ArchiveType::TarGz),
        (b"\x28\xb5\x2f\xfd", ArchiveType::TarZst),
        (b"\xfd7zXZ\x00", ArchiveType::TarXz),
    ];
    for (prefix, expected) in cases {
        let bytes = tar_named_with_prefix(prefix);
        assert_eq!(path_format(&bytes), expected, "{prefix:?}");
        assert_eq!(
            ArchiveReader::detect(Cursor::new(bytes.clone()))
                .unwrap()
                .format(),
            expected
        );
        assert_eq!(
            ArchiveReader::detect_stream(ReadOnly(Cursor::new(bytes)))
                .unwrap()
                .format(),
            expected
        );
    }
}

/// A gzip stream whose FEXTRA field swallows a checksum-valid ustar block.
fn gzip_hiding_a_ustar_block() -> Vec<u8> {
    let mut header = tar::Header::new_ustar();
    let name = &mut header.as_old_mut().name;
    name[..12].copy_from_slice(b"\x1f\x8b\x08\x04\0\0\0\0\0\xff\xf4\x01");
    header.set_size(0);
    header.set_cksum();
    let inner = compress(CompressionCodec::Gzip, &plain_tar());
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(&inner[10..]);
    bytes
}

#[test]
fn a_gzip_hiding_a_ustar_block_stays_gzip_in_every_entry_point() {
    let bytes = gzip_hiding_a_ustar_block();
    assert_eq!(path_format(&bytes), ArchiveType::TarGz);
    assert_eq!(
        ArchiveReader::detect(Cursor::new(bytes.clone()))
            .unwrap()
            .format(),
        ArchiveType::TarGz
    );
    let streamed = ArchiveReader::detect_stream(ReadOnly(Cursor::new(bytes))).unwrap();
    assert_eq!(streamed.format(), ArchiveType::TarGz);
    assert!(listing(streamed).contains("a.txt"));
}

#[test]
fn valid_tar_with_container_magic_name_stays_a_container() {
    let zip = tar_named_with_prefix(b"PK\x03\x04");
    assert_eq!(path_format(&zip), ArchiveType::Zip);
    assert_eq!(
        ArchiveReader::detect(Cursor::new(zip)).unwrap().format(),
        ArchiveType::Zip
    );
    let seven_z = tar_named_with_prefix(b"7z\xbc\xaf\x27\x1c");
    assert_eq!(path_format(&seven_z), ArchiveType::SevenZ);
    assert_eq!(
        ArchiveReader::detect(Cursor::new(seven_z))
            .unwrap()
            .format(),
        ArchiveType::SevenZ
    );
}

#[test]
fn compressed_streams_are_still_detected_as_compressed() {
    for (expected, bytes) in every_format().into_iter().skip(1).take(4) {
        assert_eq!(path_format(&bytes), expected);
        assert_eq!(
            ArchiveReader::detect_stream(ReadOnly(Cursor::new(bytes)))
                .unwrap()
                .format(),
            expected
        );
    }
}
