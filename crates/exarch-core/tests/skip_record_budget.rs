//! `by` of a refusal under `ExistingFiles::Skip` is exact for the first 16384
//! landings of a run and `existing` after that (the diagnostic record budget);
//! Refuse keeps the full budget on the same archive. The exact boundary and
//! the policy mapping are pinned in `formats::run_record`'s unit tests, below
//! the budget `by` is pinned by the occupant parity tests; two runs of 16 Ki
//! entries keep this test to a few seconds.

#![expect(clippy::disallowed_methods, reason = "test fixture setup")]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]

mod sink_support;

use std::num::NonZeroUsize;

use exarch_core::ArchiveError;
use exarch_core::ExistingFiles;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::OccupiedBy;
use exarch_core::SecurityConfig;
use sink_support::tar_archive;
use sink_support::tar_file;
use tempfile::TempDir;

const BUDGET: usize = 16 * 1024;

/// Extracts `x`, then `fillers` empty files, then `x/a`, and returns who the
/// refusal says made `x`.
fn maker_of_x(policy: ExistingFiles, fillers: usize) -> OccupiedBy {
    let mut entries = vec![tar_file("x", b"1")];
    entries.extend((0..fillers).map(|index| tar_file(&format!("f{index}"), b"")));
    entries.push(tar_file("x/a", b"2"));
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.tar");
    std::fs::write(&archive, tar_archive(&entries)).unwrap();
    let dest = dir.path().join("out");
    let config = SecurityConfig::default().with_max_file_count(NonZeroUsize::new(1 << 20).unwrap());

    let error = ExtractRequest::new(&config)
        .with_options(ExtractionOptions::default().with_existing_files(policy))
        .extract(&archive, &dest)
        .unwrap_err();

    let cause = match &error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    };
    match cause {
        ArchiveError::DestinationOccupied { by, .. } => *by,
        other => panic!("{policy:?} {fillers}: expected DestinationOccupied, got {other}"),
    }
}

#[test]
fn skip_reports_existing_past_the_budget_while_refuse_keeps_attributing() {
    assert_eq!(
        maker_of_x(ExistingFiles::Skip, BUDGET),
        OccupiedBy::Existing
    );
    assert_eq!(
        maker_of_x(ExistingFiles::Refuse, BUDGET),
        OccupiedBy::Archive
    );
}
