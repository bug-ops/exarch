//! Invariant: for an encrypted 7z, `verify` fails exactly where `extract`
//! refuses at admission, with the same encryption refusal. The one deliberate
//! exception, no password, is covered by `verify_encrypted_sevenz.rs`.

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
use exarch_core::VerificationStatus;
use exarch_core::VerifyRequest;
use exarch_core::Violation;
use sevenz_patch::fixture_bytes;
use sevenz_patch::fixture_path;
use sevenz_patch::with_raw_key_aes_coders;
use sevenz_patch::written;
use tempfile::TempDir;

fn password(bytes: &[u8]) -> Arc<Password> {
    Arc::new(Password::new(bytes.to_vec()).unwrap())
}

fn cause(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    }
}

fn refusal(error: &ArchiveError) -> Option<EncryptionRefusal> {
    match cause(error) {
        ArchiveError::SecurityViolation {
            kind: Violation::Encrypted { reason, .. },
            ..
        } => Some(*reason),
        _ => None,
    }
}

fn assert_agree(archive: &Path, password: &Arc<Password>, expected: EncryptionRefusal) {
    let config = SecurityConfig::default();
    let dest = TempDir::new().unwrap();
    let extracted = ExtractRequest::new(&config)
        .with_password(password.clone())
        .extract(archive, dest.path())
        .unwrap_err();
    assert_eq!(refusal(&extracted), Some(expected));

    let report = VerifyRequest::new(&config)
        .with_password(password.clone())
        .verify(archive)
        .unwrap();
    assert_eq!(
        report.status(),
        VerificationStatus::Fail,
        "{}",
        archive.display()
    );
    let message = Violation::Encrypted {
        reason: expected,
        name: None,
    }
    .to_string();
    assert!(
        report
            .issues()
            .iter()
            .any(|issue| issue.message().contains(&message)),
        "{:?}",
        report.issues()
    );
}

#[test]
fn a_raw_key_block_fails_verify_and_extract_alike() {
    let dir = TempDir::new().unwrap();
    let archive = written(
        dir.path(),
        "raw.7z",
        &with_raw_key_aes_coders(fixture_bytes("content.7z")),
    );

    assert_agree(
        &archive,
        &password(b"correct-horse"),
        EncryptionRefusal::WeakEncryptionRefused,
    );
}

#[test]
fn a_non_utf8_password_fails_verify_and_extract_alike() {
    assert_agree(
        &fixture_path("content.7z"),
        &password(&[0xFF, 0xFE, b'x']),
        EncryptionRefusal::UnusablePassword,
    );
}
