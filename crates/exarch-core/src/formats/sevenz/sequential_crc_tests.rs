//! The sequential block path checks entry CRCs itself (`sequential_block`):
//! a mismatch does not end the block, the decoder's repeat of a mismatch the
//! callback saw is swallowed, and every other error still propagates.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::decode::decode_block_entries;
use super::header::BlockIndex;
use super::header::HeaderLimit;
use super::header::SevenZHeader;
use super::lzma2::DecodeKnobs;
use super::read_sevenz_header;
use crate::ParallelDecode;
use crate::test_utils::flip_first;
use sevenz_rust2::Archive;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use sevenz_rust2::EncoderConfiguration;
use sevenz_rust2::EncoderMethod;
use sevenz_rust2::Error;
use sevenz_rust2::Password;
use sevenz_rust2::SourceReader;
use std::io::Cursor;
use std::io::Read;

const A: &[u8] = b"AAAAAAAAAAAA";
const B: &[u8] = b"BBBBBBBBBBBB";
const C: &[u8] = b"CCCCCCCCCCCC";

fn solid_copy(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    writer.set_content_methods(vec![EncoderConfiguration::new(EncoderMethod::COPY)]);
    let entries = files
        .iter()
        .map(|(name, data)| {
            let mut entry = ArchiveEntry::new_file(name);
            entry.has_stream = true;
            entry.size = data.len() as u64;
            entry
        })
        .collect();
    let readers = files
        .iter()
        .map(|(_, data)| SourceReader::from(Cursor::new(data.to_vec())))
        .collect();
    writer.push_archive_entries(entries, readers).unwrap();
    writer.finish().unwrap().into_inner()
}

fn crc32(data: &[u8]) -> u64 {
    let mut crc = flate2::Crc::new();
    crc.update(data);
    u64::from(crc.sum())
}

/// How the callback reads an entry before returning to the decoder.
#[derive(Clone, Copy)]
enum Read_ {
    /// To its end, so a checksum raised at the end of the block reaches it.
    ToEof,
    /// Exactly the declared size, never probing past it.
    Declared,
}

#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Data(Vec<u8>),
    Checksum,
    Other,
}

fn run(
    header: &SevenZHeader,
    source: Vec<u8>,
    read: Read_,
    fail_last_with: Option<fn() -> Error>,
) -> (Vec<Seen>, Result<bool, Error>) {
    let mut seen = Vec::new();
    let total = header.files().len();
    let result = decode_block_entries(
        &mut Cursor::new(source),
        header,
        BlockIndex::first(),
        ParallelDecode::Sequential,
        DecodeKnobs::production(),
        &mut |file, reader| {
            let mut data = Vec::new();
            let outcome = match read {
                Read_::ToEof => read_in_steps(reader, &mut data),
                Read_::Declared => reader.take(file.size).read_to_end(&mut data),
            };
            seen.push(match outcome {
                Ok(_) => Seen::Data(data),
                Err(e) if super::links::is_entry_checksum_error(&e) => Seen::Checksum,
                Err(_) => Seen::Other,
            });
            match fail_last_with {
                Some(make) if seen.len() == total => Err(make()),
                _ => Ok(true),
            }
        },
    );
    (seen, result)
}

/// Reads `reader` to its end in 5-byte steps, so the last data read and the
/// read that finds the end are separate calls.
fn read_in_steps(reader: &mut dyn Read, data: &mut Vec<u8>) -> std::io::Result<usize> {
    let mut step = [0u8; 5];
    loop {
        match reader.read(&mut step)? {
            0 => return Ok(data.len()),
            n => data.extend_from_slice(&step[..n]),
        }
    }
}

fn parsed(bytes: &[u8]) -> SevenZHeader {
    read_sevenz_header(&mut Cursor::new(bytes), HeaderLimit::UNLIMITED).unwrap()
}

/// A header whose block carries `block_crc`, whatever the data, and whose
/// files carry none unless `file_crcs` lists them.
fn with_block_crc(bytes: &[u8], block_crc: u64, file_crcs: &[u64]) -> SevenZHeader {
    let mut archive = Archive::read(&mut Cursor::new(bytes), &Password::empty()).unwrap();
    archive.blocks[0].has_crc = true;
    archive.blocks[0].crc = block_crc;
    for (file, crc) in archive.files.iter_mut().zip(file_crcs) {
        file.has_crc = true;
        file.crc = *crc;
    }
    SevenZHeader::assume_checked(archive)
}

fn checksum_looking_error() -> Error {
    Error::Io(
        std::io::Error::other(Error::ChecksumVerificationFailed),
        "callback".into(),
    )
}

#[test]
fn a_corrupt_entry_does_not_hide_the_entries_after_it() {
    let mut bytes = solid_copy(&[("a", A), ("b", B), ("c", C)]);
    flip_first(&mut bytes, A);
    let header = parsed(&bytes);

    let (seen, result) = run(&header, bytes, Read_::ToEof, None);

    assert_eq!(
        seen,
        [
            Seen::Checksum,
            Seen::Data(B.to_vec()),
            Seen::Data(C.to_vec())
        ]
    );
    assert!(result.unwrap());
}

#[test]
fn a_truncated_stream_after_a_mismatch_still_fails_the_block() {
    let mut bytes = solid_copy(&[("a", A), ("b", B), ("c", C)]);
    let header = parsed(&bytes);
    flip_first(&mut bytes, A);
    let cut = 32 + A.len() + B.len() + 3;
    bytes.truncate(cut);

    let (seen, result) = run(&header, bytes, Read_::ToEof, None);

    assert_eq!(seen[0], Seen::Checksum);
    assert_eq!(seen[2], Seen::Other);
    assert!(result.is_err(), "{result:?}");
}

#[test]
fn a_block_checksum_mismatch_the_callback_never_saw_stays_an_error() {
    let bytes = solid_copy(&[("a", A), ("b", B)]);
    let wrong = crc32(&[A, B].concat()) ^ 1;
    let header = with_block_crc(&bytes, wrong, &[]);

    let (seen, result) = run(&header, bytes, Read_::Declared, None);

    assert_eq!(seen, [Seen::Data(A.to_vec()), Seen::Data(B.to_vec())]);
    assert!(result.is_err(), "{result:?}");
}

#[test]
fn a_callback_error_that_looks_like_a_checksum_failure_propagates() {
    let mut bytes = solid_copy(&[("a", A)]);
    let crc = crc32(A);
    let header = with_block_crc(&bytes, crc, &[crc]);
    flip_first(&mut bytes, A);

    let (seen, result) = run(&header, bytes, Read_::ToEof, Some(checksum_looking_error));

    assert_eq!(seen, [Seen::Checksum]);
    assert!(result.is_err(), "{result:?}");
}

#[test]
fn a_mismatch_of_one_entry_does_not_excuse_a_block_mismatch_drained_on_another() {
    let mut bytes = solid_copy(&[("a", A), ("b", B)]);
    let wrong = crc32(&[A, B].concat()) ^ 1;
    let header = with_block_crc(&bytes, wrong, &[crc32(A)]);
    flip_first(&mut bytes, A);

    let (seen, result) = run(&header, bytes, Read_::Declared, None);

    assert_eq!(seen[0], Seen::Checksum);
    assert!(result.is_err(), "{result:?}");
}

#[test]
fn a_folder_checksum_that_is_also_the_entry_checksum_is_reported_once() {
    let mut bytes = solid_copy(&[("a", A)]);
    let crc = crc32(A);
    let header = with_block_crc(&bytes, crc, &[crc]);
    flip_first(&mut bytes, A);

    let (seen, result) = run(&header, bytes, Read_::ToEof, None);

    assert_eq!(seen, [Seen::Checksum]);
    assert!(result.unwrap());
}
