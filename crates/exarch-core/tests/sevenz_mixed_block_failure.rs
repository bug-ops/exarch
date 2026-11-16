//! Acceptance contract of #1240: in a non-solid 7z with one plain block and one
//! AES block, a decode failure is classified by the block it happened in. The
//! fixture `mixed-blocks.7z` holds `plain.txt` (plain block 0) and
//! `sealed.txt` (AES block 1, password `correct-horse`).

#![cfg(feature = "encryption")]
#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

mod sevenz_patch;

use std::path::Path;
use std::sync::Arc;

use exarch_core::ArchiveError;
use exarch_core::EncryptionRefusal;
use exarch_core::ExtractRequest;
use exarch_core::Password;
use exarch_core::SecurityConfig;
use exarch_core::Violation;
use sevenz_patch::fixture_bytes;
use sevenz_patch::flipped;
use sevenz_patch::packed_streams_end;
use sevenz_patch::written;
use tempfile::TempDir;

const RIGHT: &[u8] = b"correct-horse";
const FIRST_PACKED_BYTE: usize = 32;

fn extract(archive: &Path, with_password: bool) -> Result<(), ArchiveError> {
    let dest = TempDir::new().unwrap();
    let config = SecurityConfig::default();
    let request = ExtractRequest::new(&config);
    let request = if with_password {
        request.with_password(Some(Arc::new(Password::new(RIGHT.to_vec()).unwrap())))
    } else {
        request
    };
    request.extract(archive, dest.path()).map(drop)
}

fn encryption_reason(error: &ArchiveError) -> Option<EncryptionRefusal> {
    let cause = match error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    };
    match cause {
        ArchiveError::SecurityViolation {
            kind: Violation::Encrypted { reason, .. },
            ..
        } => Some(*reason),
        _ => None,
    }
}

#[test]
fn the_untouched_mixed_fixture_extracts_with_the_password() {
    let dir = TempDir::new().unwrap();
    let archive = written(dir.path(), "m.7z", &fixture_bytes("mixed-blocks.7z"));

    extract(&archive, true).unwrap();
}

#[test]
fn a_corrupt_plain_block_is_not_classified_as_an_encryption_failure() {
    let dir = TempDir::new().unwrap();
    let archive = written(
        dir.path(),
        "m.7z",
        &flipped(fixture_bytes("mixed-blocks.7z"), FIRST_PACKED_BYTE + 8),
    );

    let error = extract(&archive, true).unwrap_err();

    assert_eq!(encryption_reason(&error), None, "{error}");
}

#[test]
fn a_corrupt_plain_block_fails_like_the_same_corruption_in_an_all_plain_archive() {
    let dir = TempDir::new().unwrap();
    let mixed = written(
        dir.path(),
        "mixed.7z",
        &flipped(fixture_bytes("mixed-blocks.7z"), FIRST_PACKED_BYTE + 8),
    );
    let plain = written(
        dir.path(),
        "plain.7z",
        &flipped(fixture_bytes("plain.7z"), FIRST_PACKED_BYTE + 8),
    );

    let mixed_error = extract(&mixed, true).unwrap_err();
    let plain_error = extract(&plain, false).unwrap_err();

    assert_eq!(mixed_error.error_code(), plain_error.error_code());
    assert_eq!(mixed_error.sub_code(), plain_error.sub_code());
}

#[test]
fn a_corrupt_encrypted_block_stays_wrong_password_or_corrupt() {
    let bytes = fixture_bytes("mixed-blocks.7z");
    let last_ciphertext_byte = packed_streams_end(&bytes) - 1;
    let dir = TempDir::new().unwrap();
    let archive = written(dir.path(), "m.7z", &flipped(bytes, last_ciphertext_byte));

    let error = extract(&archive, true).unwrap_err();

    assert_eq!(
        encryption_reason(&error),
        Some(EncryptionRefusal::WrongPasswordOrCorrupt),
        "{error}"
    );
}
