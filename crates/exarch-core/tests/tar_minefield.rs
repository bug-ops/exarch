//! Replays the S06-S17 and F-series cases of the tar-minefield corpus of
//! ambiguous tar archives (#1209).
//!
//! The cases are vendored under `tests/data/tar-minefield/` with the upstream
//! MIT licence; see the README there for the pinned upstream commit. Two
//! properties are checked separately: the containment guarantee on every case
//! (nothing written outside the destination, no panic, no hang), and the
//! pinned outcome kind of each case, which is allowed to change on purpose.

#![expect(clippy::disallowed_methods, reason = "test fixture setup")]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]

use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use exarch_core::ArchiveError;
use exarch_core::ExistingFiles;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::SecurityConfig;
use exarch_core::Staging;
use tempfile::TempDir;

const CASE_TIMEOUT: Duration = Duration::from_secs(60);

/// How one case ends, ignoring the wording of the error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Extracted,
    Malformed,
    Ambiguous,
    Trailer,
    Security,
    Other,
}

use Outcome::Ambiguous;
use Outcome::Extracted;
use Outcome::Malformed;
use Outcome::Other;
use Outcome::Security;
use Outcome::Trailer;

/// Outcome kind of every vendored case under the default policy.
const PINNED: &[(&str, Outcome)] = &[
    ("F01-number-leading-space", Extracted),
    ("F02-end-data-after", Extracted),
    ("F03-end-lone-zero-block", Extracted),
    ("F04-end-missing", Extracted),
    ("F05-magic-version-nuls", Extracted),
    ("F06-checksum-signed", Malformed),
    ("F07-end-archive-after", Extracted),
    ("F08-end-truncated-in-member", Malformed),
    ("F09-end-zero-block-then-member", Extracted),
    ("F10-extended-pax-size-before-gnu-long", Ambiguous),
    ("F11-magic-odd-version", Extracted),
    ("F12-number-size-gap", Malformed),
    ("F13-pax-newline-in-path", Ambiguous),
    ("F14-pax-size-disagrees", Extracted),
    ("F15-pax-size-on-dir", Ambiguous),
    ("F16-type-unknown", Security),
    ("F17-pax-global-comment", Extracted),
    ("F18-pax-global-comment-after-members", Extracted),
    ("F19-pax-global-between-extended-and-member", Ambiguous),
    ("F20-pax-global-size", Ambiguous),
    ("F21-pax-size-empty", Ambiguous),
    ("F22-pax-size-negative", Ambiguous),
    ("F23-pax-size-plus", Ambiguous),
    ("F24-pax-size-leading-space", Ambiguous),
    ("F25-pax-size-not-ascii-digits", Ambiguous),
    ("F26-pax-size-leading-zero", Extracted),
    ("F27-pax-size-too-large", Ambiguous),
    ("F28-pax-newline-in-comment", Ambiguous),
    ("F29-number-size-base256-negative", Malformed),
    ("F30-number-size-base256-too-large", Ambiguous),
    ("F31-pax-xattr-not-utf8", Extracted),
    ("F32-checksum-leading-space", Extracted),
    ("F33-size-on-dir", Ambiguous),
    ("F34-size-on-hardlink", Ambiguous),
    ("F35-pax-size-on-hardlink", Ambiguous),
    ("F36-pax-record-length-short", Ambiguous),
    ("F37-number-size-not-octal", Malformed),
    ("F38-size-on-hardlink-without-pax", Ambiguous),
    ("F39-format-pax-after-v7", Extracted),
    ("F40-number-size-no-terminator", Extracted),
    ("F41-number-size-leading-nul", Malformed),
    ("F42-pax-comment-not-utf8", Extracted),
    ("F43-pax-global-comment-not-utf8", Extracted),
    ("F44-pax-global-size-empty", Ambiguous),
    ("F45-type-gnu-sparse", Ambiguous),
    ("F46-pax-size-on-symlink", Ambiguous),
    ("F47-checksum-wrong-after-first-member", Malformed),
    ("F48-pax-record-length-plus", Ambiguous),
    ("F49-pax-record-empty-line", Ambiguous),
    ("F50-pax-size-underscore", Ambiguous),
    ("F51-number-size-plus", Ambiguous),
    ("F52-type-gnu-volume-label", Security),
    ("F53-type-gnu-old-long-name", Security),
    ("F54-format-pax-header-without-magic", Ambiguous),
    ("F55-type-contiguous", Extracted),
    ("F56-number-size-base256", Extracted),
    ("F57-pax-newline-in-comment-path", Ambiguous),
    ("F58-pax-newline-in-comment-then-size", Ambiguous),
    ("F59-pax-nul-in-xattr", Extracted),
    ("F60-trailing-slash-file-with-size", Ambiguous),
    ("S06-hardlink-to-symlink", Security),
    ("S07-tree-duplicate-file-differs", Extracted),
    ("S08-tree-duplicate-file-dir", Other),
    ("S09-tree-duplicate-file-identical", Extracted),
    ("S10-tree-symlink-then-file", Security),
    ("S11-tree-through-symlink", Security),
    ("S12-tree-under-file", Other),
    ("S13-hardlink-empty-target", Malformed),
    ("S14-tree-symlink-then-dir", Security),
    ("S15-tree-file-then-hardlink", Security),
    ("S16-hardlink-target-spelled-differently", Security),
    ("S17-hardlink-then-file-again", Security),
];

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/tar-minefield")
}

fn case_archives() -> Vec<(String, PathBuf)> {
    let mut cases: Vec<(String, PathBuf)> = std::fs::read_dir(corpus_dir())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "tar"))
        .map(|path| {
            let id = path.file_stem().unwrap().to_string_lossy().into_owned();
            (id, path)
        })
        .collect();
    cases.sort();
    cases
}

fn refusal_cause(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    }
}

/// Whether the case was stopped by the symlink or hardlink policy itself.
fn refused_by_link_policy(result: &Result<(), ArchiveError>) -> bool {
    result.as_ref().err().is_some_and(|error| {
        let error = refusal_cause(error);
        error.is_security_violation()
            && matches!(
                error.context().as_deref(),
                Some("symlinks not allowed" | "hardlinks not allowed")
            )
    })
}

fn classify(result: &Result<(), ArchiveError>) -> Outcome {
    let error = match result {
        Ok(()) => return Extracted,
        Err(error) => refusal_cause(error),
    };
    match error {
        ArchiveError::InvalidArchive(_) => Malformed,
        ArchiveError::TarAmbiguity(_) => Ambiguous,
        ArchiveError::TarTrailer(_) => Trailer,
        other if other.is_security_violation() => Security,
        _ => Other,
    }
}

/// A way of extracting a case. `Default` is the pinned policy; the others lift
/// the link policy so the link-escape cases get past it and containment is
/// exercised on the paths that reach the filesystem.
#[derive(Debug, Clone, Copy)]
enum Policy {
    Default,
    LinksAllowed,
    LinksAllowedOverwrite,
    LinksAllowedAtomic,
}

impl Policy {
    const ALL: [Self; 4] = [
        Self::Default,
        Self::LinksAllowed,
        Self::LinksAllowedOverwrite,
        Self::LinksAllowedAtomic,
    ];

    fn config(self) -> SecurityConfig {
        match self {
            Self::Default => SecurityConfig::default(),
            _ => SecurityConfig::default()
                .with_allow_symlinks(true)
                .with_allow_hardlinks(true),
        }
    }

    fn options(self) -> ExtractionOptions {
        let mut options = ExtractionOptions::default();
        match self {
            Self::LinksAllowedOverwrite => options.existing_files = ExistingFiles::Overwrite,
            Self::LinksAllowedAtomic => options.staging = Staging::Atomic,
            Self::Default | Self::LinksAllowed => {}
        }
        options
    }
}

/// Extracts one case three directories deep in its own sandbox, on a thread so
/// that a panic or a hang is reported against the case.
fn extract_in_sandbox(
    archive: &Path,
    policy: Policy,
) -> (TempDir, PathBuf, Result<(), ArchiveError>) {
    let sandbox = TempDir::new().unwrap();
    let dest = sandbox.path().join("a").join("b").join("dest");
    std::fs::create_dir_all(&dest).unwrap();

    let (sender, receiver) = mpsc::channel();
    let archive = archive.to_path_buf();
    let thread_dest = dest.clone();
    let worker = std::thread::spawn(move || {
        let config = policy.config();
        let result = ExtractRequest::new(&config)
            .with_options(policy.options())
            .extract(&archive, &thread_dest)
            .map(drop);
        let _ = sender.send(result);
    });
    let result = match receiver.recv_timeout(CASE_TIMEOUT) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("extraction did not finish within {CASE_TIMEOUT:?}")
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => panic!("extraction panicked"),
    };
    worker.join().unwrap();
    (sandbox, dest, result)
}

/// Every path in the sandbox, relative to it, that is not inside `dest`.
fn paths_outside(sandbox: &Path, dest: &Path) -> Vec<PathBuf> {
    let mut outside = Vec::new();
    let mut pending = vec![sandbox.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path == dest {
                continue;
            }
            if path.is_dir() && !path.is_symlink() && dest.starts_with(&path) {
                pending.push(path);
            } else {
                outside.push(path.strip_prefix(sandbox).unwrap().to_path_buf());
            }
        }
    }
    outside
}

#[test]
fn the_corpus_is_vendored_in_full() {
    let ids: Vec<String> = case_archives().into_iter().map(|(id, _)| id).collect();
    assert_eq!(ids.iter().filter(|id| id.starts_with('F')).count(), 60);
    let s_series: Vec<&str> = ids
        .iter()
        .map(String::as_str)
        .filter(|id| id.starts_with('S'))
        .map(|id| &id[..3])
        .collect();
    let expected: Vec<String> = (6..=17).map(|n| format!("S{n:02}")).collect();
    assert_eq!(s_series, expected);
    for id in &ids {
        assert!(corpus_dir().join(format!("{id}.json")).is_file(), "{id}");
    }
}

#[test]
fn no_case_writes_outside_the_destination_or_hangs_or_panics() {
    for (id, archive) in case_archives() {
        for policy in Policy::ALL {
            let (sandbox, dest, _result) = extract_in_sandbox(&archive, policy);
            let outside = paths_outside(sandbox.path(), &dest);
            assert!(
                outside.is_empty(),
                "{id} under {policy:?} wrote outside: {outside:?}"
            );
        }
    }
}

#[test]
fn every_case_has_its_pinned_outcome() {
    let pinned_ids: BTreeSet<&str> = PINNED.iter().map(|(id, _)| *id).collect();
    let vendored: Vec<(String, PathBuf)> = case_archives();
    let vendored_ids: BTreeSet<&str> = vendored.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(pinned_ids, vendored_ids, "the table and the corpus differ");

    for (id, archive) in &vendored {
        let (_sandbox, _dest, result) = extract_in_sandbox(archive, Policy::Default);
        let expected = PINNED.iter().find(|(pinned, _)| pinned == id).unwrap().1;
        assert_eq!(
            classify(&result),
            expected,
            "{id}: {:?}",
            result.as_ref().err().map(ToString::to_string)
        );
    }
}

/// Cases that the default policy stops at the link policy, so only a sweep
/// with links allowed puts their containment to the test.
const STOPPED_BY_LINK_POLICY: &[&str] = &[
    "S06-hardlink-to-symlink",
    "S10-tree-symlink-then-file",
    "S11-tree-through-symlink",
    "S14-tree-symlink-then-dir",
    "S15-tree-file-then-hardlink",
    "S16-hardlink-target-spelled-differently",
    "S17-hardlink-then-file-again",
];

#[test]
fn the_links_allowed_sweep_gets_past_the_link_policy() {
    for (id, archive) in case_archives() {
        if !STOPPED_BY_LINK_POLICY.contains(&id.as_str()) {
            continue;
        }
        let (_sandbox, _dest, default) = extract_in_sandbox(&archive, Policy::Default);
        assert!(refused_by_link_policy(&default), "{id}: {default:?}");
        for policy in [
            Policy::LinksAllowed,
            Policy::LinksAllowedOverwrite,
            Policy::LinksAllowedAtomic,
        ] {
            let (_sandbox, _dest, result) = extract_in_sandbox(&archive, policy);
            assert!(
                !refused_by_link_policy(&result),
                "{id} under {policy:?} still stops at the link policy: {result:?}"
            );
        }
    }
}
