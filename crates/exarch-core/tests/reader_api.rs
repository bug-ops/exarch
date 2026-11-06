//! `list_reader` and `verify_reader` give the same answer as the path-based
//! API for every format, and work on a source that cannot seek.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

mod sink_support;

use std::assert_matches;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;

use exarch_core::ArchiveReader;
use exarch_core::CompressionCodec;
use exarch_core::DecompressionBudget;
use exarch_core::IntegrityCheck;
use exarch_core::ListOptions;
use exarch_core::ListRequest;
use exarch_core::SecurityConfig;
use exarch_core::SeekableFormat;
use exarch_core::VerificationOptions;
use exarch_core::VerificationStatus;
use exarch_core::VerifyRequest;
use exarch_core::list_archive;
use sink_support::tar_archive;
use sink_support::tar_dir;
use sink_support::tar_file;
use sink_support::zip_archive;
use sink_support::zip_dir;
use sink_support::zip_file;
use tempfile::TempDir;

/// A source that can only read.
struct ReadOnly<R>(R);

impl<R: Read> Read for ReadOnly<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

fn plain_tar() -> Vec<u8> {
    tar_archive(&[
        tar_dir("d/"),
        tar_file("d/a.txt", b"alpha"),
        tar_file("b.txt", b"bravo"),
    ])
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

struct Case {
    file_name: &'static str,
    bytes: Vec<u8>,
    make: fn(Vec<u8>) -> ArchiveReader<'static>,
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            file_name: "a.tar",
            bytes: plain_tar(),
            make: |b| ArchiveReader::tar(ReadOnly(Cursor::new(b)), None),
        },
        Case {
            file_name: "a.tar.gz",
            bytes: compress(CompressionCodec::Gzip, &plain_tar()),
            make: |b| ArchiveReader::tar(ReadOnly(Cursor::new(b)), Some(CompressionCodec::Gzip)),
        },
        Case {
            file_name: "a.tar.bz2",
            bytes: compress(CompressionCodec::Bzip2, &plain_tar()),
            make: |b| ArchiveReader::tar(ReadOnly(Cursor::new(b)), Some(CompressionCodec::Bzip2)),
        },
        Case {
            file_name: "a.tar.xz",
            bytes: compress(CompressionCodec::Xz, &plain_tar()),
            make: |b| ArchiveReader::tar(ReadOnly(Cursor::new(b)), Some(CompressionCodec::Xz)),
        },
        Case {
            file_name: "a.tar.zst",
            bytes: compress(CompressionCodec::Zstd, &plain_tar()),
            make: |b| ArchiveReader::tar(ReadOnly(Cursor::new(b)), Some(CompressionCodec::Zstd)),
        },
        Case {
            file_name: "a.zip",
            bytes: zip_archive(vec![
                zip_dir("d/"),
                zip_file("d/a.txt", b"alpha"),
                zip_file("b.txt", b"bravo"),
            ]),
            make: |b| ArchiveReader::seekable(Cursor::new(b), SeekableFormat::Zip),
        },
        Case {
            file_name: "a.7z",
            bytes: seven_z(),
            make: |b| ArchiveReader::seekable(Cursor::new(b), SeekableFormat::SevenZ),
        },
    ]
}

fn write(dir: &TempDir, case: &Case) -> std::path::PathBuf {
    let path = dir.path().join(case.file_name);
    std::fs::write(&path, &case.bytes).unwrap();
    path
}

#[test]
fn list_reader_matches_list_archive() {
    let config = SecurityConfig::default();
    for case in cases() {
        let dir = TempDir::new().unwrap();
        let path = write(&dir, &case);
        let expected = list_archive(&path, &config).unwrap();
        let actual = ListRequest::new(&config)
            .with_options(ListOptions::default())
            .list_reader((case.make)(case.bytes.clone()))
            .unwrap();
        assert_eq!(
            format!("{actual:?}"),
            format!("{expected:?}"),
            "{}",
            case.file_name
        );
    }
}

#[test]
fn verify_reader_matches_verify_archive_for_skip_and_decode_to_eof() {
    let config = SecurityConfig::default();
    let skip = VerificationOptions::default();
    let decode = VerificationOptions::default()
        .with_integrity(IntegrityCheck::DecodeToEof(DecompressionBudget::DEFAULT));
    for case in cases() {
        let dir = TempDir::new().unwrap();
        let path = write(&dir, &case);
        for options in [skip, decode] {
            let expected = VerifyRequest::new(&config)
                .with_options(options)
                .verify(&path)
                .unwrap();
            let actual = VerifyRequest::new(&config)
                .with_options(options)
                .verify_reader((case.make)(case.bytes.clone()))
                .unwrap();
            assert_eq!(
                format!("{actual:?}"),
                format!("{expected:?}"),
                "{}",
                case.file_name
            );
            assert_eq!(
                actual.status(),
                VerificationStatus::Pass,
                "{}",
                case.file_name
            );
        }
    }
}

#[test]
fn reader_format_reports_the_declared_type() {
    use exarch_core::ArchiveType;
    let formats: Vec<_> = cases()
        .iter()
        .map(|c| (c.make)(Vec::new()).format())
        .collect();
    assert_eq!(
        formats,
        [
            ArchiveType::Tar,
            ArchiveType::TarGz,
            ArchiveType::TarBz2,
            ArchiveType::TarXz,
            ArchiveType::TarZst,
            ArchiveType::Zip,
            ArchiveType::SevenZ,
        ]
    );
}

#[test]
fn list_reader_rejects_a_traversal_name_like_the_path_api() {
    let bytes = tar_archive(&[tar_file("../evil", b"x")]);
    let reader = ArchiveReader::tar(Cursor::new(bytes), None);
    let error = ListRequest::new(&SecurityConfig::default())
        .with_options(ListOptions::default())
        .list_reader(reader)
        .unwrap_err();
    assert_matches!(
        error,
        exarch_core::ArchiveError::PathTraversal { .. },
        "{error}"
    );
}
