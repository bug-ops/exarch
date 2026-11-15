//! Acceptance contract of #1241 (and the approved callback passwords):
//! `MemoryExtractRequest::with_password` lets in-memory and callback
//! extraction decrypt, and `Debug` never shows the secret.

#![cfg(feature = "encryption")]
#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

mod sevenz_patch;

use std::assert_matches;
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::Arc;

use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::CallbackEntry;
use exarch_core::CallbackError;
use exarch_core::EncryptionRefusal;
use exarch_core::MemoryEntry;
use exarch_core::MemoryExtractRequest;
use exarch_core::NoopProgress;
use exarch_core::Password;
use exarch_core::Violation;
use exarch_core::extract_reader_to_callback;
use exarch_core::extract_reader_to_memory;
use sevenz_patch::fixture_bytes;

const RIGHT: &[u8] = b"correct-horse";
const NOT_UTF8: &[u8] = &[0xFF, 0xFE, b'x'];

fn secret(bytes: &[u8]) -> Arc<Password> {
    Arc::new(Password::new(bytes.to_vec()).unwrap())
}

fn files_in_memory(
    archive: &str,
    request: &MemoryExtractRequest,
) -> Result<BTreeMap<PathBuf, Vec<u8>>, ArchiveError> {
    let reader = ArchiveReader::from_bytes(fixture_bytes(archive), None).unwrap();
    let (_report, sink) = extract_reader_to_memory(reader, request, &mut NoopProgress)?;
    Ok(sink
        .into_entries()
        .into_iter()
        .filter_map(|(path, entry)| match entry {
            MemoryEntry::File { data, .. } => Some((path, data)),
            _ => None,
        })
        .collect())
}

fn files_by_callback(
    archive: &str,
    request: &MemoryExtractRequest,
) -> Result<BTreeMap<PathBuf, Vec<u8>>, CallbackError<Infallible>> {
    let reader = ArchiveReader::from_bytes(fixture_bytes(archive), None).unwrap();
    let mut files = BTreeMap::new();
    extract_reader_to_callback(
        reader,
        request,
        |path, entry| {
            if let CallbackEntry::Stored(MemoryEntry::File { data, .. }) = entry {
                files.insert(path.as_path().to_path_buf(), data);
            }
            Ok(())
        },
        &mut NoopProgress,
    )?;
    Ok(files)
}

fn reason(error: &ArchiveError) -> EncryptionRefusal {
    match error {
        ArchiveError::SecurityViolation {
            kind: Violation::Encrypted { reason, .. },
            ..
        } => *reason,
        other => panic!("expected an encryption refusal, got {other}"),
    }
}

#[test]
fn extract_reader_to_memory_with_the_password_equals_the_plaintext_twin() {
    let request = MemoryExtractRequest::default().with_password(secret(RIGHT));
    for (encrypted, twin) in [
        ("aes256.zip", "plain.zip"),
        ("content.7z", "plain.7z"),
        ("header.7z", "plain.7z"),
    ] {
        let decrypted = files_in_memory(encrypted, &request).unwrap();
        let plain = files_in_memory(twin, &MemoryExtractRequest::default()).unwrap();

        assert_eq!(decrypted, plain, "{encrypted}");
        assert_eq!(
            decrypted
                .get(&PathBuf::from("hello.txt"))
                .map(Vec::as_slice),
            Some(&b"hello encrypted\n"[..]),
            "{encrypted}"
        );
    }
}

#[test]
fn extract_reader_to_memory_without_a_password_is_password_required() {
    for archive in ["aes256.zip", "content.7z", "header.7z"] {
        let error = files_in_memory(archive, &MemoryExtractRequest::default()).unwrap_err();

        let cause = match &error {
            ArchiveError::PartialExtraction(partial) => partial.cause(),
            other => other,
        };
        assert_eq!(
            reason(cause),
            EncryptionRefusal::PasswordRequired,
            "{archive}"
        );
    }
}

#[test]
fn extract_reader_to_memory_with_a_wrong_password_is_wrong_password() {
    let request = MemoryExtractRequest::default().with_password(secret(b"wrong-horse"));

    let error = files_in_memory("aes256.zip", &request).unwrap_err();

    let cause = match &error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    };
    assert_eq!(reason(cause), EncryptionRefusal::WrongPassword);
}

#[test]
fn extract_reader_to_callback_with_the_password_delivers_the_decrypted_files() {
    let request = MemoryExtractRequest::default().with_password(secret(RIGHT));
    for (encrypted, twin) in [("aes256.zip", "plain.zip"), ("content.7z", "plain.7z")] {
        let decrypted = files_by_callback(encrypted, &request).unwrap();
        let plain = files_by_callback(twin, &MemoryExtractRequest::default()).unwrap();

        assert_eq!(decrypted, plain, "{encrypted}");
        assert!(!decrypted.is_empty(), "{encrypted}");
    }
}

#[test]
fn extract_reader_to_callback_without_a_password_is_password_required() {
    let error = files_by_callback("aes256.zip", &MemoryExtractRequest::default()).unwrap_err();

    assert_matches!(error, CallbackError::Archive(_));
}

#[test]
fn a_non_utf8_password_cannot_open_a_7z_in_memory() {
    let request = MemoryExtractRequest::default().with_password(secret(NOT_UTF8));

    let error = files_in_memory("content.7z", &request).unwrap_err();

    let cause = match &error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    };
    assert_eq!(reason(cause), EncryptionRefusal::UnusablePassword);
}

#[test]
fn debug_of_a_request_with_a_password_never_shows_the_secret() {
    let marker = "s3cr3t-horse-value";
    let request = MemoryExtractRequest::default().with_password(secret(marker.as_bytes()));

    let text = format!("{request:?}");

    assert!(!text.contains(marker), "{text}");
}
