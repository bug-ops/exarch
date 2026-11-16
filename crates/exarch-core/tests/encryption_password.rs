//! Acceptance contract of #1023 (spec 024): a supplied `Password` decrypts
//! `WinZip` AES ZIP entries and 7z AES content and headers; every other outcome
//! is a typed `EncryptionRefusal` under `SECURITY_VIOLATION` / `ENCRYPTED`.
//!
//! Fixtures are in `tests/data/encryption/` (see its README).

#![cfg(feature = "encryption")]
#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

mod sink_support;

use std::num::NonZeroU64;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use exarch_core::ArchiveError;
use exarch_core::EncryptionRefusal;
use exarch_core::ErrorCode;
use exarch_core::ExtractRequest;
use exarch_core::ListRequest;
use exarch_core::Password;
use exarch_core::SecurityConfig;
use exarch_core::SecurityViolationSubCode;
use exarch_core::SubCode;
use exarch_core::VerifyRequest;
use exarch_core::Violation;
use sink_support::Tree;
use sink_support::walk;
use tempfile::TempDir;

const RIGHT: &[u8] = b"correct-horse";
const WRONG: &[u8] = b"wrong-horse";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/encryption")
        .join(name)
}

fn password(bytes: &[u8]) -> Arc<Password> {
    Arc::new(Password::new(bytes.to_vec()).unwrap())
}

fn cause(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    }
}

fn refusal(error: &ArchiveError) -> EncryptionRefusal {
    match cause(error) {
        ArchiveError::SecurityViolation {
            kind: Violation::Encrypted { reason, .. },
            ..
        } => *reason,
        other => panic!("expected an encryption refusal, got {other}"),
    }
}

fn extract(
    archive: &str,
    password: Option<Arc<Password>>,
    config: &SecurityConfig,
) -> (TempDir, Result<(), ArchiveError>) {
    let dest = TempDir::new().unwrap();
    let request = ExtractRequest::new(config);
    let request = request.with_password(password);
    let result = request.extract(fixture(archive), dest.path()).map(drop);
    (dest, result)
}

fn tree(dest: &TempDir) -> Tree {
    walk(dest.path())
}

#[test]
fn extract_with_the_right_password_equals_the_plaintext_twin() {
    for (encrypted, twin) in [
        ("aes256.zip", "plain.zip"),
        ("content.7z", "plain.7z"),
        ("header.7z", "plain.7z"),
    ] {
        let (decrypted, result) =
            extract(encrypted, Some(password(RIGHT)), &SecurityConfig::default());
        result.unwrap();
        let (plain, result) = extract(twin, None, &SecurityConfig::default());
        result.unwrap();

        assert_eq!(tree(&decrypted), tree(&plain), "{encrypted}");
        assert_eq!(
            std::fs::read(decrypted.path().join("hello.txt")).unwrap(),
            b"hello encrypted\n"
        );
    }
}

#[test]
fn extract_without_a_password_is_password_required_and_writes_nothing() {
    for archive in ["aes256.zip", "content.7z", "header.7z"] {
        let (dest, result) = extract(archive, None, &SecurityConfig::default());

        let error = result.unwrap_err();

        assert_eq!(
            error.error_code(),
            ErrorCode::SecurityViolation,
            "{archive}"
        );
        assert_eq!(
            error.sub_code(),
            Some(SubCode::SecurityViolation(
                SecurityViolationSubCode::Encrypted
            )),
            "{archive}"
        );
        assert_eq!(
            refusal(&error),
            EncryptionRefusal::PasswordRequired,
            "{archive}"
        );
        assert_eq!(
            std::fs::read_dir(dest.path()).unwrap().count(),
            0,
            "{archive}"
        );
    }
}

#[test]
fn extract_zip_with_a_wrong_password_is_wrong_password() {
    let (dest, result) = extract(
        "aes256.zip",
        Some(password(WRONG)),
        &SecurityConfig::default(),
    );

    let error = result.unwrap_err();

    assert_eq!(refusal(&error), EncryptionRefusal::WrongPassword);
    assert_eq!(std::fs::read_dir(dest.path()).unwrap().count(), 0);
}

#[test]
fn extract_sevenz_with_a_wrong_password_is_wrong_password_or_corrupt() {
    for archive in ["content.7z", "header.7z"] {
        let (_dest, result) = extract(archive, Some(password(WRONG)), &SecurityConfig::default());

        let error = result.unwrap_err();

        assert_eq!(
            refusal(&error),
            EncryptionRefusal::WrongPasswordOrCorrupt,
            "{archive}"
        );
    }
}

#[test]
fn extract_zipcrypto_is_weak_encryption_refused_even_with_a_password() {
    for supplied in [None, Some(password(RIGHT))] {
        let (_dest, result) = extract("zipcrypto.zip", supplied, &SecurityConfig::default());

        let error = result.unwrap_err();

        assert_eq!(refusal(&error), EncryptionRefusal::WeakEncryptionRefused);
    }
}

#[test]
fn extract_sevenz_over_the_kdf_budget_is_kdf_cost_exceeded_before_any_write() {
    let config = SecurityConfig::default().with_max_kdf_work(NonZeroU64::new(1).unwrap());
    for archive in ["content.7z", "header.7z"] {
        let (dest, result) = extract(archive, Some(password(RIGHT)), &config);

        let error = result.unwrap_err();

        assert_eq!(
            refusal(&error),
            EncryptionRefusal::KdfCostExceeded,
            "{archive}"
        );
        assert_eq!(
            std::fs::read_dir(dest.path()).unwrap().count(),
            0,
            "{archive}"
        );
    }
}

#[test]
fn extract_with_a_needless_password_ignores_it() {
    for archive in ["plain.zip", "plain.7z"] {
        let (with, result) = extract(archive, Some(password(RIGHT)), &SecurityConfig::default());
        result.unwrap();
        let (without, result) = extract(archive, None, &SecurityConfig::default());
        result.unwrap();

        assert_eq!(tree(&with), tree(&without), "{archive}");
    }
}

#[test]
fn list_and_verify_with_the_right_password_work_like_the_twin() {
    let config = SecurityConfig::default();
    for archive in ["aes256.zip", "content.7z", "header.7z"] {
        let listed = ListRequest::new(&config)
            .with_password(Some(password(RIGHT)))
            .list(fixture(archive))
            .unwrap();
        let report = VerifyRequest::new(&config)
            .with_password(Some(password(RIGHT)))
            .verify(fixture(archive))
            .unwrap();

        assert!(
            listed
                .entries()
                .iter()
                .any(|e| e.path.ends_with("inner.txt")),
            "{archive}"
        );
        assert!(
            report.issues().is_empty(),
            "{archive}: {:?}",
            report.issues()
        );
    }
}

#[test]
fn list_of_an_encrypted_zip_without_a_password_shows_the_plaintext_names() {
    let listed = ListRequest::new(&SecurityConfig::default())
        .list(fixture("aes256.zip"))
        .unwrap();

    assert!(
        listed
            .entries()
            .iter()
            .any(|e| e.path.ends_with("inner.txt"))
    );
}

#[test]
fn list_of_a_header_encrypted_sevenz_without_a_password_is_password_required() {
    let error = ListRequest::new(&SecurityConfig::default())
        .list(fixture("header.7z"))
        .unwrap_err();

    assert_eq!(refusal(&error), EncryptionRefusal::PasswordRequired);
}

#[test]
fn password_new_accepts_one_to_1024_bytes_only() {
    assert!(Password::new(Vec::new()).is_err());
    assert!(Password::new(vec![b'a'; 1025]).is_err());
    assert!(Password::new(vec![b'a']).is_ok());
    assert!(Password::new(vec![b'a'; 1024]).is_ok());
}

#[test]
fn password_debug_never_prints_the_secret() {
    let secret = Password::new(b"s3cr3t-value".to_vec()).unwrap();

    let debug = format!("{secret:?}");

    assert_eq!(debug, "Password(..)");
    assert!(!debug.contains("s3cr3t"));
}

#[test]
fn encryption_errors_never_carry_the_password() {
    let supplied = Password::new(b"s3cr3t-value".to_vec()).unwrap();
    let (_dest, result) = extract(
        "aes256.zip",
        Some(Arc::new(supplied)),
        &SecurityConfig::default(),
    );

    let error = result.unwrap_err();

    assert!(!format!("{error} {error:?}").contains("s3cr3t"));
}

#[test]
fn security_config_debug_has_no_password_field() {
    let debug = format!("{:?}", SecurityConfig::default());

    assert!(!debug.to_lowercase().contains("password"));
}
