//! `verify` with an integrity check of an AES 7z under a wrong password
//! reports the encryption refusal `extract` raises,
//! `wrong_password_or_corrupt`, never corrupt data (#1248); the right password
//! still verifies clean.

#![cfg(feature = "encryption")]
#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use exarch_core::DecompressionBudget;
use exarch_core::EncryptionRefusal;
use exarch_core::IntegrityCheck;
use exarch_core::IntegrityStatus;
use exarch_core::IssueCategory;
use exarch_core::Password;
use exarch_core::SecurityConfig;
use exarch_core::SecurityViolationSubCode;
use exarch_core::SubCode;
use exarch_core::VerificationOptions;
use exarch_core::VerificationReport;
use exarch_core::VerificationStatus;
use exarch_core::VerifyRequest;
use exarch_core::Violation;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/encryption")
        .join(name)
}

fn password(bytes: &[u8]) -> Arc<Password> {
    Arc::new(Password::new(bytes.to_vec()).unwrap())
}

fn verify(name: &str, secret: &[u8], integrity: bool) -> VerificationReport {
    let options = if integrity {
        VerificationOptions::default()
            .with_integrity(IntegrityCheck::DecodeToEof(DecompressionBudget::DEFAULT))
    } else {
        VerificationOptions::default()
    };
    VerifyRequest::new(&SecurityConfig::default())
        .with_options(options)
        .with_password(Some(password(secret)))
        .verify(fixture(name))
        .unwrap()
}

fn assert_wrong_password(report: &VerificationReport, context: &str) {
    let message = Violation::Encrypted {
        reason: EncryptionRefusal::WrongPasswordOrCorrupt,
        name: None,
    }
    .to_string();

    assert_eq!(report.status(), VerificationStatus::Fail, "{context}");
    assert!(
        report.issues().iter().any(|issue| {
            issue.message().contains(&message)
                && issue.sub_code()
                    == Some(SubCode::SecurityViolation(
                        SecurityViolationSubCode::Encrypted,
                    ))
        }),
        "{context}: {:?}",
        report.issues()
    );
    assert!(
        report
            .issues()
            .iter()
            .all(|issue| issue.category() != IssueCategory::CorruptData),
        "{context}: {:?}",
        report.issues()
    );
    assert_ne!(
        report.integrity_status(),
        IntegrityStatus::Pass,
        "{context}"
    );
}

#[test]
fn verify_check_integrity_of_aes_content_7z_with_a_wrong_password_is_wrong_password_or_corrupt() {
    let report = verify("content.7z", b"wrong-horse", true);

    assert_wrong_password(&report, "content.7z");
}

#[test]
fn verify_check_integrity_of_a_mixed_block_7z_with_a_wrong_password_names_the_encrypted_block() {
    let report = verify("mixed-blocks.7z", b"wrong-horse", true);

    assert_wrong_password(&report, "mixed-blocks.7z");
}

#[test]
fn verify_check_integrity_of_aes_content_7z_with_the_right_password_passes() {
    let report = verify("content.7z", b"correct-horse", true);

    assert_eq!(report.status(), VerificationStatus::Pass);
    assert_eq!(report.integrity_status(), IntegrityStatus::Pass);
    assert!(report.issues().is_empty(), "{:?}", report.issues());
}
