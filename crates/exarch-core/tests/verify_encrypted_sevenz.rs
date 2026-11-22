//! Acceptance contract of #1243: without a password, a 7z with encrypted
//! content under a plain header verifies like an AES ZIP: its files are
//! unverified with reason `encrypted`, a warning and not a failure. `extract`
//! keeps refusing.

#![cfg(feature = "encryption")]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]

mod sevenz_patch;

use std::assert_matches;

use exarch_core::ArchiveError;
use exarch_core::DecompressionBudget;
use exarch_core::EncryptionRefusal;
use exarch_core::ExtractRequest;
use exarch_core::IntegrityCheck;
use exarch_core::IntegrityStatus;
use exarch_core::IssueSeverity;
use exarch_core::SecurityConfig;
use exarch_core::UnverifiedReason;
use exarch_core::VerificationOptions;
use exarch_core::VerificationReport;
use exarch_core::VerificationStatus;
use exarch_core::VerifyRequest;
use exarch_core::Violation;
use sevenz_patch::fixture_path;
use tempfile::TempDir;

fn verify(name: &str, options: VerificationOptions) -> VerificationReport {
    VerifyRequest::new(&SecurityConfig::default())
        .with_options(options)
        .verify(fixture_path(name))
        .unwrap()
}

fn with_integrity() -> VerificationOptions {
    VerificationOptions::default()
        .with_integrity(IntegrityCheck::DecodeToEof(DecompressionBudget::DEFAULT))
}

#[test]
fn verify_check_integrity_of_aes_content_7z_equals_the_aes_zip_outcome() {
    let zip = verify("aes256.zip", with_integrity());
    let sevenz = verify("content.7z", with_integrity());

    assert_eq!(sevenz.status(), zip.status());
    assert_eq!(sevenz.integrity_status(), zip.integrity_status());
    assert_eq!(sevenz.status(), VerificationStatus::Warning);
    assert_eq!(sevenz.integrity_status(), IntegrityStatus::Incomplete);
}

#[test]
fn verify_check_integrity_of_aes_content_7z_counts_each_file_unverified_as_encrypted() {
    let report = verify("content.7z", with_integrity());

    let gaps = report.integrity_gaps().unwrap();

    assert_eq!(gaps.count(UnverifiedReason::Encrypted), 2);
    assert!(
        gaps.entries()
            .iter()
            .any(|entry| entry.path().ends_with("inner.txt"))
    );
}

#[test]
fn verify_of_aes_content_7z_reports_no_high_severity_issue() {
    for options in [VerificationOptions::default(), with_integrity()] {
        let report = verify("content.7z", options);

        assert!(
            report
                .issues()
                .iter()
                .all(|issue| issue.severity() != IssueSeverity::High),
            "{:?}",
            report.issues()
        );
    }
}

#[test]
fn verify_without_integrity_of_aes_content_7z_has_the_status_of_the_aes_zip() {
    let zip = verify("aes256.zip", VerificationOptions::default());
    let sevenz = verify("content.7z", VerificationOptions::default());

    assert_eq!(sevenz.status(), zip.status());
    assert_eq!(sevenz.integrity_status(), zip.integrity_status());
}

#[test]
fn extract_of_aes_content_7z_without_a_password_is_still_password_required() {
    let dest = TempDir::new().unwrap();

    let error = ExtractRequest::new(&SecurityConfig::default())
        .extract(fixture_path("content.7z"), dest.path())
        .unwrap_err();

    let cause = match &error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    };
    assert_matches!(
        cause,
        ArchiveError::SecurityViolation {
            kind: Violation::Encrypted {
                reason: EncryptionRefusal::PasswordRequired,
                ..
            },
            ..
        }
    );
    assert_eq!(std::fs::read_dir(dest.path()).unwrap().count(), 0);
}
