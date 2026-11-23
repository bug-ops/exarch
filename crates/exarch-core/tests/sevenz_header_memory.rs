//! An AES-encrypted 7z header is held to the same limits as a plain one, and a
//! quota refusal is never reported as a wrong password (#1262): an archive
//! written by `sevenz-rust2` with its defaults opens at the default limits, a
//! header that is too large for the configured limits is refused as a quota
//! error, and a wrong password is still `wrong_password_or_corrupt`.

#![cfg(feature = "encryption")]
#![expect(clippy::disallowed_methods, reason = "test fixture setup")]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]

mod common;

use std::assert_matches;
use std::io::Cursor;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use common::crc32;
use common::number;
use exarch_core::ArchiveError;
use exarch_core::EncryptionRefusal;
use exarch_core::ExtractRequest;
use exarch_core::ListRequest;
use exarch_core::Password;
use exarch_core::QuotaResource;
use exarch_core::SecurityConfig;
use exarch_core::VerifyRequest;
use exarch_core::Violation;
use exarch_core::non_zero;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use sevenz_rust2::EncoderConfiguration;
use sevenz_rust2::EncoderMethod;
use sevenz_rust2::SourceReader;
use sevenz_rust2::encoder_options::AesEncoderOptions;
use tempfile::TempDir;

const SECRET: &[u8] = b"pw";
const MIB: u64 = 1024 * 1024;

fn password(bytes: &[u8]) -> Arc<Password> {
    Arc::new(Password::new(bytes.to_vec()).unwrap())
}

/// Three small AES-encrypted files with the writer's default header
/// encryption, whose header coder declares about 8 MiB of decoder memory.
fn default_writer_archive() -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    writer.set_content_methods(vec![
        AesEncoderOptions::new(sevenz_rust2::Password::new("pw")).into(),
        EncoderConfiguration::new(EncoderMethod::COPY),
    ]);
    for name in ["a.txt", "b.txt", "c.txt"] {
        let mut entry = ArchiveEntry::new_file(name);
        entry.has_stream = true;
        entry.size = 5;
        writer
            .push_archive_entry(
                entry,
                Some(SourceReader::from(Cursor::new(b"hello".to_vec()))),
            )
            .unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn read_number(bytes: &[u8]) -> (u64, usize) {
    let first = bytes[0];
    let mut value = 0u64;
    let mut mask = 0x80u8;
    for i in 0..8usize {
        if first & mask == 0 {
            value += u64::from(first & (mask - 1)) << (8 * i);
            return (value, i + 1);
        }
        value |= u64::from(bytes[1 + i]) << (8 * i);
        mask >>= 1;
    }
    (value, 9)
}

/// `archive` with the two unpack sizes of its encoded-header folder (the AES
/// coder's output, then the LZMA coder's output) replaced. The record and
/// start-header CRCs are refreshed, so the archive still opens up to the
/// header limits.
fn with_header_unpack_sizes(archive: &[u8], aes_out: usize, lzma_out: usize) -> Vec<u8> {
    let field = |at: usize| {
        usize::try_from(u64::from_le_bytes(*archive[at..at + 8].as_array().unwrap())).unwrap()
    };
    let packed_len = field(12);
    let record_at = 32 + packed_len;
    let record = &archive[record_at..record_at + field(20)];

    let folder = record
        .windows(4)
        .position(|w| w == [0x07, 0x0B, 0x01, 0x00])
        .unwrap()
        + 4;
    let (coders, used) = read_number(&record[folder..]);
    assert_eq!(coders, 2, "expected the AES coder and the LZMA coder");
    let mut at = folder + used;
    for _ in 0..coders {
        let flags = record[at];
        at += 1 + usize::from(flags & 0x0F);
        assert_eq!(flags & 0x10, 0, "complex coder");
        if flags & 0x20 != 0 {
            let (props, used) = read_number(&record[at..]);
            at += used + usize::try_from(props).unwrap();
        }
    }
    for _ in 0..2 {
        at += read_number(&record[at..]).1;
    }
    assert_eq!(record[at], 0x0C, "unpack sizes marker");
    at += 1;
    let sizes_end = (0..coders).fold(at, |end, _| end + read_number(&record[end..]).1);

    let mut patched = record[..at].to_vec();
    patched.extend(number(aes_out));
    patched.extend(number(lzma_out));
    patched.extend_from_slice(&record[sizes_end..]);

    let mut start = Vec::new();
    start.extend((packed_len as u64).to_le_bytes());
    start.extend((patched.len() as u64).to_le_bytes());
    start.extend(crc32(&patched).to_le_bytes());
    let mut out = vec![b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
    out.extend(crc32(&start).to_le_bytes());
    out.extend(start);
    out.extend_from_slice(&archive[32..record_at]);
    out.extend(patched);
    out
}

fn write(dir: &TempDir, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join("archive.7z");
    std::fs::write(&path, bytes).unwrap();
    path
}

fn cause(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    }
}

fn list(path: &Path, config: &SecurityConfig, secret: &[u8]) -> exarch_core::Result<usize> {
    ListRequest::new(config)
        .with_password(Some(password(secret)))
        .list(path)
        .map(|listed| listed.entries().len())
}

fn verify(path: &Path, config: &SecurityConfig, secret: &[u8]) -> exarch_core::Result<()> {
    VerifyRequest::new(config)
        .with_password(Some(password(secret)))
        .verify(path)
        .map(drop)
}

fn extract(path: &Path, config: &SecurityConfig, secret: &[u8]) -> exarch_core::Result<()> {
    let dest = TempDir::new().unwrap();
    ExtractRequest::new(config)
        .with_password(Some(password(secret)))
        .extract(path, dest.path())
        .map(drop)
}

fn assert_header_size(error: &ArchiveError, context: &str) {
    assert_matches!(
        cause(error),
        ArchiveError::QuotaExceeded {
            resource: QuotaResource::HeaderSize { .. }
        },
        "{context}: {error:?}"
    );
}

#[test]
fn list_of_a_default_writer_header_encrypted_archive_opens_at_default_limits() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, &default_writer_archive());
    let config = SecurityConfig::default();

    assert_eq!(list(&path, &config, SECRET).unwrap(), 3);
    verify(&path, &config, SECRET).unwrap();
    extract(&path, &config, SECRET).unwrap();
}

#[test]
fn list_of_a_default_writer_header_opens_under_the_permissive_config() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, &default_writer_archive());

    assert_eq!(
        list(&path, &SecurityConfig::permissive(), SECRET).unwrap(),
        3
    );
}

#[test]
fn list_of_a_default_writer_header_opens_with_a_small_max_file_count() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, &default_writer_archive());
    let config = SecurityConfig::default().with_max_file_count(non_zero!(10));

    assert_eq!(list(&path, &config, SECRET).unwrap(), 3);
}

#[test]
fn list_of_a_default_writer_header_over_a_small_decoder_memory_is_a_quota_refusal() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, &default_writer_archive());
    let config = SecurityConfig::default().with_max_decoder_memory(non_zero!(MIB));

    for (name, result) in [
        ("list", list(&path, &config, SECRET).map(drop)),
        ("verify", verify(&path, &config, SECRET)),
        ("extract", extract(&path, &config, SECRET)),
    ] {
        let error = result.unwrap_err();

        assert_matches!(
            cause(&error),
            ArchiveError::QuotaExceeded {
                resource: QuotaResource::DecoderMemory { max }
            } if *max == MIB,
            "{name}: {error:?}"
        );
    }
}

#[test]
fn list_of_a_default_writer_header_with_a_wrong_password_is_wrong_password_or_corrupt() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, &default_writer_archive());

    let error = list(&path, &SecurityConfig::default(), b"not-the-password").unwrap_err();

    assert_matches!(
        cause(&error),
        ArchiveError::SecurityViolation {
            kind: Violation::Encrypted {
                reason: EncryptionRefusal::WrongPasswordOrCorrupt,
                ..
            },
            ..
        },
        "{error:?}"
    );
}

#[test]
fn list_of_an_encrypted_header_declaring_a_huge_decoded_size_is_header_size() {
    let dir = TempDir::new().unwrap();
    let huge = usize::try_from(64 * MIB).unwrap();
    let archive = default_writer_archive();
    let config = SecurityConfig::default();

    for (shape, sizes) in [
        ("final output", (110, huge)),
        ("first coder output", (huge, 231)),
        ("every coder output", (huge, huge)),
    ] {
        let path = write(&dir, &with_header_unpack_sizes(&archive, sizes.0, sizes.1));

        for (name, result) in [
            ("list", list(&path, &config, SECRET).map(drop)),
            ("verify", verify(&path, &config, SECRET)),
            ("extract", extract(&path, &config, SECRET)),
        ] {
            assert_header_size(&result.unwrap_err(), &format!("{shape} {name}"));
        }
    }
}

#[test]
fn list_of_an_encrypted_header_declaring_a_huge_decoded_size_is_header_size_with_a_wrong_password()
{
    let dir = TempDir::new().unwrap();
    let huge = usize::try_from(64 * MIB).unwrap();
    let path = write(
        &dir,
        &with_header_unpack_sizes(&default_writer_archive(), 110, huge),
    );

    let error = list(&path, &SecurityConfig::default(), b"not-the-password").unwrap_err();

    assert_header_size(&error, "wrong password over an oversized header");
}
