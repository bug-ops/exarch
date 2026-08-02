//! Regression tests for issue #426: hardlink quota bypass.
//!
//! Before the fix, `TarArchive::create_hardlink` copied a hardlink target's
//! bytes to a brand-new inode via `std::fs::copy` without ever routing the
//! copied size through `QuotaTracker`. A small archive containing one
//! legitimate file followed by many hardlink entries pointing at it could
//! inflate to an arbitrary multiple of the declared archive size with no
//! `max_file_size`, `max_file_count`, or `max_total_size` enforcement — a
//! classic hardlink-bomb bypass of the same class as decompression bombs.
//!
//! The fix adds `EntryValidator::record_hardlink`, which charges each
//! hardlink's on-disk target size against the *same* `QuotaTracker` instance
//! used for regular files, called before the parent-dir/duplicate checks and
//! before `std::fs::copy` runs.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use exarch_core::ArchiveError;
use exarch_core::ExtractionOptions;
use exarch_core::NoopProgress;
use exarch_core::QuotaResource;
use exarch_core::SecurityConfig;
use exarch_core::formats::ArchiveFormat;
use exarch_core::formats::TarArchive;
use std::assert_matches;
use std::io::Cursor;
use tempfile::TempDir;

struct TarTestBuilder {
    builder: tar::Builder<Vec<u8>>,
}

impl TarTestBuilder {
    fn new() -> Self {
        Self {
            builder: tar::Builder::new(Vec::new()),
        }
    }

    fn add_file(mut self, path: &str, data: &[u8]) -> Self {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        self.builder.append_data(&mut header, path, data).unwrap();
        self
    }

    fn add_hardlink(mut self, path: &str, target: &str) -> Self {
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Link);
        header.set_link_name(target).unwrap();
        header.set_cksum();
        self.builder
            .append_data(&mut header, path, std::io::empty())
            .unwrap();
        self
    }

    /// Adds `count` hardlink entries named `{prefix}{i}` all pointing at
    /// `target`, simulating a hardlink-bomb archive: many small entries that
    /// each materialize a full copy of the same target file.
    fn add_hardlink_bomb(mut self, prefix: &str, target: &str, count: usize) -> Self {
        for i in 0..count {
            self = self.add_hardlink(&format!("{prefix}{i}"), target);
        }
        self
    }

    fn build(self) -> Vec<u8> {
        self.builder.into_inner().unwrap()
    }
}

/// Counts regular files directly inside `dir` (non-recursive; these fixtures
/// are all flat).
fn count_entries(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir).unwrap().count()
}

/// Extraction failures surface as `ArchiveError::PartialExtraction { source,
/// report }`, wrapping the triggering error together with a report of what
/// was written before it fired. Unwraps to `(quota_error, files_extracted)`.
fn quota_failure(err: &ArchiveError) -> (&ArchiveError, usize) {
    match err {
        ArchiveError::PartialExtraction { source, report } => {
            (source.as_ref(), report.files_extracted)
        }
        other => panic!("expected PartialExtraction, got: {other:?}"),
    }
}

// ── #426: total-size bypass ───────────────────────────────────────────────
//
// One legitimate file within quota, followed by many hardlinks to it, where
// N * target_size exceeds max_total_size. Pre-fix, this extracted silently
// with N full copies on disk and no quota error.

#[test]
fn test_hardlink_bomb_exceeds_total_size() {
    let target_size = 5_000usize;
    let tar_data = TarTestBuilder::new()
        .add_file("target.txt", &vec![b'A'; target_size])
        .add_hardlink_bomb("link", "target.txt", 20)
        .build();

    let temp = TempDir::new().unwrap();
    let config = SecurityConfig::default()
        .with_allow_hardlinks(true)
        .with_max_file_size(target_size as u64 + 1)
        .with_max_total_size(20_000) // room for target + 3 links, not 4
        .with_max_file_count(1_000);

    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut NoopProgress,
    );

    let err = result.expect_err("hardlink bomb exceeding max_total_size must be rejected");
    let (quota_err, files_extracted) = quota_failure(&err);
    assert_matches!(
        quota_err,
        ArchiveError::QuotaExceeded {
            resource: QuotaResource::TotalSize { .. }
        },
        "expected TotalSize quota error, got: {quota_err:?}"
    );

    // Must have stopped well short of all 20 hardlinks (target + at most 3 links).
    assert!(
        files_extracted <= 4,
        "extraction must stop at the quota boundary, not write all hardlinks; wrote {files_extracted}"
    );
    let written = count_entries(temp.path());
    assert_eq!(
        written, files_extracted,
        "disk contents must match the reported partial extraction count"
    );
}

// ── #426: file-count bypass ───────────────────────────────────────────────
//
// Many small hardlinks whose combined bytes are trivial but whose count
// alone exceeds max_file_count.

#[test]
fn test_hardlink_bomb_exceeds_file_count() {
    let tar_data = TarTestBuilder::new()
        .add_file("target.txt", b"x")
        .add_hardlink_bomb("link", "target.txt", 10)
        .build();

    let temp = TempDir::new().unwrap();
    let config = SecurityConfig::default()
        .with_allow_hardlinks(true)
        .with_max_file_size(1_000_000)
        .with_max_total_size(1_000_000)
        .with_max_file_count(3); // target.txt + 2 hardlinks allowed, 3rd rejected

    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut NoopProgress,
    );

    let err = result.expect_err("hardlink count alone exceeding max_file_count must be rejected");
    let (quota_err, files_extracted) = quota_failure(&err);
    assert_matches!(
        quota_err,
        ArchiveError::QuotaExceeded {
            resource: QuotaResource::FileCount { .. }
        },
        "expected FileCount quota error, got: {quota_err:?}"
    );

    assert!(
        files_extracted <= 3,
        "extraction must stop at the file-count boundary; wrote {files_extracted}"
    );
    let written = count_entries(temp.path());
    assert_eq!(
        written, files_extracted,
        "disk contents must match the reported partial extraction count"
    );
}

// ── #426: positive case — legitimate hardlinks within all quotas ─────────
//
// A small, well-behaved number of hardlinks to a small target must still
// extract successfully; the fix must not regress the legitimate path.

#[test]
fn test_legitimate_hardlinks_within_quota_succeed() {
    let tar_data = TarTestBuilder::new()
        .add_file("target.txt", b"hello world")
        .add_hardlink_bomb("link", "target.txt", 3)
        .build();

    let temp = TempDir::new().unwrap();
    let config = SecurityConfig::default().with_allow_hardlinks(true);

    let mut archive = TarArchive::new(Cursor::new(tar_data));
    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut NoopProgress,
    );

    assert!(
        result.is_ok(),
        "legitimate hardlinks well within quota must succeed, got: {result:?}"
    );
    let report = result.unwrap();
    assert_eq!(report.files_extracted, 4); // target.txt + 3 hardlinks

    for i in 0..3 {
        let linked = std::fs::read(temp.path().join(format!("link{i}"))).unwrap();
        assert_eq!(linked, b"hello world");
    }
}
