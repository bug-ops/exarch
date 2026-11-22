//! `verify` reports a repeated ZIP name under `RepeatedPaths::Refuse` as the
//! refusal extract and list raise, whatever `zip_consistency` says (#1201).

#![expect(clippy::disallowed_methods, reason = "test fixture setup")]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]

mod sink_support;

use exarch_core::FfiKind;
use exarch_core::Finding;
use exarch_core::RepeatedPaths;
use exarch_core::SecurityConfig;
use exarch_core::SecurityViolationSubCode;
use exarch_core::VerificationIssue;
use exarch_core::VerifyRequest;
use exarch_core::ZipConsistencyPolicy;
use sink_support::zip_archive;
use sink_support::zip_file;
use tempfile::TempDir;

fn issues(repeats: RepeatedPaths, consistency: ZipConsistencyPolicy) -> Vec<VerificationIssue> {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("dup.zip");
    std::fs::write(
        &archive,
        zip_archive(vec![zip_file("a", b"first\n"), zip_file("a", b"last\n")]),
    )
    .unwrap();
    let config = SecurityConfig::default()
        .with_repeated_paths(repeats)
        .with_zip_consistency(consistency);
    VerifyRequest::new(&config)
        .verify(&archive)
        .unwrap()
        .issues()
        .to_vec()
}

fn is_repeated_path(issue: &VerificationIssue) -> bool {
    matches!(
        issue.finding(),
        Finding::Refusal {
            kind: FfiKind::SecurityViolation {
                sub_code: SecurityViolationSubCode::RepeatedPath,
                ..
            },
            ..
        }
    )
}

#[test]
fn refuse_reports_the_repeated_name_once_under_both_consistency_policies() {
    for consistency in [ZipConsistencyPolicy::Enforce, ZipConsistencyPolicy::Ignore] {
        let found = issues(RepeatedPaths::Refuse, consistency);

        assert_eq!(
            found.iter().filter(|i| is_repeated_path(i)).count(),
            1,
            "{consistency:?}: {found:?}"
        );
        assert!(
            !found
                .iter()
                .any(|i| i.message().contains("duplicate entry name")),
            "{consistency:?}: the structure finding was reported as well"
        );
    }
}

#[test]
fn keep_first_keeps_todays_reports() {
    let enforced = issues(RepeatedPaths::KeepFirst, ZipConsistencyPolicy::Enforce);
    let ignored = issues(RepeatedPaths::KeepFirst, ZipConsistencyPolicy::Ignore);

    assert!(
        enforced
            .iter()
            .any(|i| i.message().contains("duplicate entry name"))
    );
    assert!(!enforced.iter().any(is_repeated_path));
    assert!(ignored.is_empty(), "{ignored:?}");
}
