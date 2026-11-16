//! Acceptance contract of #1246 and #1239: a 7z password that is not UTF-8 is
//! refused as `unusable_password` and a raw-key encrypted header is refused as
//! `weak_encryption_refused` before it is parsed, with one precedence on the
//! content path and the header path: `password_required`, `unusable_password`,
//! `weak_encryption_refused`, `kdf_cost_exceeded`.

#![cfg(feature = "encryption")]
#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

mod sevenz_patch;

use std::num::NonZeroU64;
use std::path::Path;
use std::sync::Arc;

use exarch_core::ArchiveError;
use exarch_core::EncryptionRefusal;
use exarch_core::ExtractRequest;
use exarch_core::ListRequest;
use exarch_core::Password;
use exarch_core::SecurityConfig;
use exarch_core::VerifyRequest;
use exarch_core::Violation;
use sevenz_patch::fixture_bytes;
use sevenz_patch::fixture_path;
use sevenz_patch::with_raw_key_aes_coders;
use sevenz_patch::written;
use tempfile::TempDir;

const RIGHT: &[u8] = b"correct-horse";
const NOT_UTF8: &[u8] = &[0xFF, 0xFE, b'x'];

fn password(bytes: &[u8]) -> Arc<Password> {
    Arc::new(Password::new(bytes.to_vec()).unwrap())
}

fn refusal(error: &ArchiveError) -> EncryptionRefusal {
    let cause = match error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    };
    match cause {
        ArchiveError::SecurityViolation {
            kind: Violation::Encrypted { reason, .. },
            ..
        } => *reason,
        other => panic!("expected an encryption refusal, got {other}"),
    }
}

fn tight() -> SecurityConfig {
    SecurityConfig::default().with_max_kdf_work(NonZeroU64::new(1).unwrap())
}

/// The refusal that extract, list and verify give for `archive`; `None` for a
/// surface that succeeded.
fn outcomes(
    archive: &Path,
    password: Option<Arc<Password>>,
    config: &SecurityConfig,
) -> [Option<EncryptionRefusal>; 3] {
    let dest = TempDir::new().unwrap();
    let extract = ExtractRequest::new(config).with_password(password.clone());
    let list = ListRequest::new(config).with_password(password.clone());
    let verify = VerifyRequest::new(config).with_password(password);
    [
        extract
            .extract(archive, dest.path())
            .err()
            .map(|e| refusal(&e)),
        list.list(archive).err().map(|e| refusal(&e)),
        verify.verify(archive).err().map(|e| refusal(&e)),
    ]
}

fn raw_key(name: &str, dir: &TempDir) -> std::path::PathBuf {
    written(
        dir.path(),
        &format!("raw-{name}"),
        &with_raw_key_aes_coders(fixture_bytes(name)),
    )
}

#[test]
fn extract_of_a_7z_with_a_non_utf8_password_is_unusable_password() {
    for name in ["content.7z", "header.7z"] {
        let dest = TempDir::new().unwrap();

        let error = ExtractRequest::new(&SecurityConfig::default())
            .with_password(Some(password(NOT_UTF8)))
            .extract(fixture_path(name), dest.path())
            .unwrap_err();

        assert_eq!(
            refusal(&error),
            EncryptionRefusal::UnusablePassword,
            "{name}"
        );
        assert_eq!(std::fs::read_dir(dest.path()).unwrap().count(), 0, "{name}");
    }
}

#[test]
fn list_and_verify_of_an_encrypted_header_with_a_non_utf8_password_are_unusable_password() {
    let [_, listed, verified] = outcomes(
        &fixture_path("header.7z"),
        Some(password(NOT_UTF8)),
        &SecurityConfig::default(),
    );

    assert_eq!(listed, Some(EncryptionRefusal::UnusablePassword));
    assert_eq!(verified, Some(EncryptionRefusal::UnusablePassword));
}

#[test]
fn extract_of_an_aes_zip_with_a_non_utf8_password_is_not_unusable_password() {
    let dest = TempDir::new().unwrap();

    let error = ExtractRequest::new(&SecurityConfig::default())
        .with_password(Some(password(NOT_UTF8)))
        .extract(fixture_path("aes256.zip"), dest.path())
        .unwrap_err();

    assert_eq!(refusal(&error), EncryptionRefusal::WrongPassword);
}

#[test]
fn unusable_password_has_the_token_unusable_password() {
    assert_eq!(
        EncryptionRefusal::UnusablePassword.as_str(),
        "unusable_password"
    );
}

#[test]
fn extract_of_a_7z_without_a_password_stays_password_required_before_unusable_password() {
    for name in ["content.7z", "header.7z"] {
        let [extracted, ..] = outcomes(&fixture_path(name), None, &SecurityConfig::default());

        assert_eq!(
            extracted,
            Some(EncryptionRefusal::PasswordRequired),
            "{name}"
        );
    }
}

#[test]
fn a_non_utf8_password_is_refused_before_the_kdf_budget_on_both_paths() {
    for name in ["content.7z", "header.7z"] {
        let [extracted, ..] = outcomes(&fixture_path(name), Some(password(NOT_UTF8)), &tight());

        assert_eq!(
            extracted,
            Some(EncryptionRefusal::UnusablePassword),
            "{name}"
        );
    }
}

#[test]
fn a_non_utf8_password_is_refused_before_a_raw_key_coder_on_both_paths() {
    let dir = TempDir::new().unwrap();
    for name in ["content.7z", "header.7z"] {
        let archive = raw_key(name, &dir);

        let [extracted, ..] = outcomes(
            &archive,
            Some(password(NOT_UTF8)),
            &SecurityConfig::default(),
        );

        assert_eq!(
            extracted,
            Some(EncryptionRefusal::UnusablePassword),
            "{name}"
        );
    }
}

#[test]
fn a_raw_key_encrypted_header_is_weak_encryption_refused_by_every_surface() {
    let dir = TempDir::new().unwrap();
    let archive = raw_key("header.7z", &dir);

    let refusals = outcomes(&archive, Some(password(RIGHT)), &SecurityConfig::default());

    assert_eq!(
        refusals,
        [Some(EncryptionRefusal::WeakEncryptionRefused); 3]
    );
}

#[test]
fn a_raw_key_encrypted_header_without_a_password_stays_password_required() {
    let dir = TempDir::new().unwrap();
    let archive = raw_key("header.7z", &dir);

    let refusals = outcomes(&archive, None, &SecurityConfig::default());

    assert_eq!(refusals, [Some(EncryptionRefusal::PasswordRequired); 3]);
}

#[test]
fn a_raw_key_is_refused_before_the_kdf_budget_on_both_paths() {
    let dir = TempDir::new().unwrap();
    for name in ["content.7z", "header.7z"] {
        let archive = raw_key(name, &dir);

        let [extracted, ..] = outcomes(&archive, Some(password(RIGHT)), &tight());

        assert_eq!(
            extracted,
            Some(EncryptionRefusal::WeakEncryptionRefused),
            "{name}"
        );
    }
}

#[test]
fn a_derived_key_over_the_budget_is_still_kdf_cost_exceeded_on_both_paths() {
    for name in ["content.7z", "header.7z"] {
        let [extracted, ..] = outcomes(&fixture_path(name), Some(password(RIGHT)), &tight());

        assert_eq!(
            extracted,
            Some(EncryptionRefusal::KdfCostExceeded),
            "{name}"
        );
    }
}
