//! Acceptance contract of #1205: `verify` reports a directory entry over an
//! earlier archive file as the typed Medium `InvalidArchive` refusal (FR-045),
//! an entry below an archive file stays High, and a file over an archive
//! directory stays the Low note (FR-044).

#![expect(clippy::disallowed_methods, reason = "test fixture setup")]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]

mod sink_support;

use exarch_core::IssueCategory;
use exarch_core::IssueSeverity;
use exarch_core::SecurityConfig;
use exarch_core::VerificationIssue;
use exarch_core::VerificationReport;
use exarch_core::VerifyRequest;
use sink_support::tar_archive;
use sink_support::tar_dir;
use sink_support::tar_file;
use sink_support::zip_archive;
use sink_support::zip_dir;
use sink_support::zip_file;
use tempfile::TempDir;

fn verify(name: &str, bytes: &[u8]) -> VerificationReport {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    VerifyRequest::new(&SecurityConfig::default())
        .verify(&path)
        .unwrap()
}

fn issue_for<'a>(report: &'a VerificationReport, entry: &str) -> &'a VerificationIssue {
    report
        .issues()
        .iter()
        .find(|i| {
            i.entry_path()
                .is_some_and(|p| p.to_str().unwrap().trim_end_matches('/') == entry)
        })
        .unwrap_or_else(|| panic!("no issue for {entry}: {:?}", report.issues()))
}

fn directory_after_file() -> [(&'static str, Vec<u8>); 2] {
    [
        (
            "a.tar",
            tar_archive(&[tar_file("x", b"n\n"), tar_dir("x/")]),
        ),
        (
            "a.zip",
            zip_archive(vec![zip_file("x", b"n\n"), zip_dir("x/")]),
        ),
    ]
}

#[test]
fn verify_directory_over_an_earlier_file_is_the_typed_medium_refusal() {
    for (name, bytes) in directory_after_file() {
        let report = verify(name, &bytes);

        let issue = issue_for(&report, "x");
        assert_eq!(issue.severity(), IssueSeverity::Medium, "{name}");
        assert_eq!(issue.category(), IssueCategory::InvalidArchive, "{name}");
        let message = issue.message();
        assert!(
            message.contains("refusing to replace the existing file at x"),
            "{name}: {message}"
        );
        assert!(!message.contains("I/O error"), "{name}: {message}");
    }
}

#[test]
fn verify_entry_below_an_earlier_file_stays_high() {
    let report = verify(
        "a.tar",
        &tar_archive(&[tar_file("x", b"n\n"), tar_file("x/a", b"y\n")]),
    );

    let issue = issue_for(&report, "x/a");
    assert_eq!(issue.severity(), IssueSeverity::High);
    assert_eq!(issue.category(), IssueCategory::InvalidArchive);
}

#[test]
fn verify_file_over_an_earlier_directory_stays_a_low_note() {
    let report = verify(
        "a.tar",
        &tar_archive(&[tar_dir("x/"), tar_file("x", b"n\n")]),
    );

    let issue = issue_for(&report, "x");
    assert_eq!(issue.severity(), IssueSeverity::Low);
}
