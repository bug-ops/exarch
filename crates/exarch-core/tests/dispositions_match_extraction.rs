//! `ArchiveManifest::dispositions` agrees with what extraction does to each
//! entry, under `ExistingFiles::Refuse`, for a corpus of entries that share a
//! path.
//!
//! Each archive is listed and extracted four ways: in place into an absent
//! destination, in place into an empty one, atomically, and into a
//! `MemorySink` that validates with the host path model. For every way the
//! outcome must be the one the dispositions predict: a refused entry fails the
//! run; otherwise the extracted files and symlinks are exactly the landings the
//! dispositions name, and the entries they skip as duplicates are the ones
//! extraction counts and samples.
//!
//! Core defaults are `ExistingFiles::Skip`, so every leg asks for `Refuse`
//! explicitly.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

mod common;
mod sink_support;

use std::collections::BTreeSet;
use std::io::Cursor;
use std::path::Path;
use std::path::PathBuf;

use common::RawEntry as SevenZEntry;
use common::solid_copy_7z;
use exarch_core::ArchiveError;
use exarch_core::ArchiveManifest;
use exarch_core::ArchiveReader;
use exarch_core::Disposition;
use exarch_core::ExistingFiles;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::ExtractionReport;
use exarch_core::ListOptions;
use exarch_core::ListRequest;
use exarch_core::ManifestEntryKind;
use exarch_core::MemoryEntryKind;
use exarch_core::MemorySink;
use exarch_core::PathModel;
use exarch_core::SecurityConfig;
use exarch_core::SeekableFormat;
use exarch_core::SinkExtractRequest;
use exarch_core::SinkOptions;
use exarch_core::SkipKind;
use exarch_core::Staging;
use exarch_core::StoredTargets;
use sink_support::tar_archive;
use sink_support::tar_dir;
use sink_support::tar_file;
use sink_support::tar_hardlink;
use sink_support::tar_symlink;
use sink_support::walk;
use sink_support::zip_archive;
use sink_support::zip_dir;
use sink_support::zip_file;
use sink_support::zip_symlink;
use tempfile::TempDir;

/// One archive member, spelled the same way for every format.
#[derive(Debug, Clone, Copy)]
enum Item {
    File(&'static str),
    Dir(&'static str),
    Sym(&'static str, &'static str),
    Hard(&'static str, &'static str),
}

const TARGET: &str = "t";

/// The four kinds the ordered-pair corpus puts at one path.
const KINDS: [fn(&'static str) -> Item; 4] = [
    Item::File,
    Item::Dir,
    |path| Item::Sym(path, TARGET),
    |path| Item::Hard(path, TARGET),
];

fn payload(index: usize) -> Vec<u8> {
    format!("data-{index}").into_bytes()
}

fn tar_bytes(items: &[Item]) -> Vec<u8> {
    let entries: Vec<_> = items
        .iter()
        .enumerate()
        .map(|(index, item)| match *item {
            Item::File(path) => tar_file(path, &payload(index)),
            Item::Dir(path) => tar_dir(path),
            Item::Sym(path, target) => tar_symlink(path, target),
            Item::Hard(path, target) => tar_hardlink(path, target),
        })
        .collect();
    tar_archive(&entries)
}

/// `None` when the format cannot express an item.
fn zip_bytes(items: &[Item]) -> Option<Vec<u8>> {
    let entries: Option<Vec<_>> = items
        .iter()
        .enumerate()
        .map(|(index, item)| match *item {
            Item::File(path) => Some(zip_file(path, &payload(index))),
            Item::Dir(path) => Some(zip_dir(&format!("{path}/"))),
            Item::Sym(path, target) => Some(zip_symlink(path, target)),
            Item::Hard(..) => None,
        })
        .collect();
    entries.map(zip_archive)
}

fn sevenz_bytes(items: &[Item]) -> Option<Vec<u8>> {
    let payloads: Vec<_> = (0..items.len()).map(payload).collect();
    let entries: Option<Vec<_>> = items
        .iter()
        .zip(&payloads)
        .map(|(item, data)| match *item {
            Item::File(path) => Some(SevenZEntry::File(path, data)),
            Item::Dir(path) => Some(SevenZEntry::Dir(path)),
            Item::Sym(path, target) => Some(SevenZEntry::Link(path, target.as_bytes())),
            Item::Hard(..) => None,
        })
        .collect();
    entries.map(|entries| solid_copy_7z(&entries))
}

struct Case {
    name: String,
    items: Vec<Item>,
}

fn case(name: impl Into<String>, items: &[Item]) -> Case {
    Case {
        name: name.into(),
        items: items.to_vec(),
    }
}

fn kind_name(item: &Item) -> &'static str {
    match item {
        Item::File(_) => "file",
        Item::Dir(_) => "dir",
        Item::Sym(..) => "symlink",
        Item::Hard(..) => "hardlink",
    }
}

/// Every ordered pair of kinds at `x` after a target file, then the shapes
/// where list and extraction have disagreed.
fn corpus() -> Vec<Case> {
    let mut cases = Vec::new();
    for first in KINDS {
        for second in KINDS {
            let (a, b) = (first("x"), second("x"));
            cases.push(case(
                format!("{} then {}", kind_name(&a), kind_name(&b)),
                &[Item::File(TARGET), a, b],
            ));
        }
    }
    cases.extend([
        case(
            "file, hardlink to it, file again",
            &[Item::File("x"), Item::Hard("h", "x"), Item::File("x")],
        ),
        case(
            "two symlinks with different targets",
            &[
                Item::File(TARGET),
                Item::Sym("x", TARGET),
                Item::Sym("x", "u"),
            ],
        ),
        case(
            "names that differ in case",
            &[Item::File(TARGET), Item::File("x"), Item::File("X")],
        ),
        case(
            "file below a symlinked directory",
            &[
                Item::Dir("sub"),
                Item::Sym("d", "sub"),
                Item::File("sub/x"),
                Item::File("d/x"),
            ],
        ),
        case(
            "file over an implicit parent",
            &[Item::File(TARGET), Item::File("x/a"), Item::File("x")],
        ),
        case(
            "regular file named twice",
            &[Item::File("x"), Item::File("x")],
        ),
    ]);
    cases
}

/// What the dispositions say extraction does.
struct Expected {
    refused: bool,
    landed: BTreeSet<PathBuf>,
    files: usize,
    symlinks: usize,
    duplicates: Vec<PathBuf>,
    extracted: usize,
}

fn expectation(manifest: &ArchiveManifest, config: &SecurityConfig) -> Expected {
    let mut expected = Expected {
        refused: false,
        landed: BTreeSet::new(),
        files: 0,
        symlinks: 0,
        duplicates: Vec::new(),
        extracted: 0,
    };
    for (entry, disposition) in manifest.dispositions(config) {
        match disposition {
            Disposition::Refuse => expected.refused = true,
            Disposition::Skip(SkipKind::Duplicate) => expected.duplicates.push(entry.path.clone()),
            Disposition::Skip(other) => {
                panic!("unexpected skip {other:?} for {}", entry.path.display())
            }
            Disposition::Extract(landing) => {
                expected.extracted += 1;
                match entry.kind {
                    ManifestEntryKind::File { .. } | ManifestEntryKind::Hardlink { .. } => {
                        expected.files += 1;
                        expected.landed.insert(landing.into_path_buf());
                    }
                    ManifestEntryKind::Symlink { .. } => {
                        expected.symlinks += 1;
                        expected.landed.insert(landing.into_path_buf());
                    }
                    _ => {}
                }
            }
            _ => panic!("unknown disposition for {}", entry.path.display()),
        }
    }
    expected.duplicates.sort();
    expected
}

/// What a leg left behind: the report and every non-directory it created.
type Outcome = Result<(ExtractionReport, BTreeSet<PathBuf>), ArchiveError>;

fn refusing() -> ExtractionOptions {
    ExtractionOptions::default().with_existing_files(ExistingFiles::Refuse)
}

fn non_directories(root: &Path) -> BTreeSet<PathBuf> {
    let tree = walk(root);
    tree.files
        .into_keys()
        .chain(tree.symlinks.into_keys())
        .collect()
}

fn on_disk(
    archive: &Path,
    config: &SecurityConfig,
    options: ExtractionOptions,
    existing_destination: bool,
) -> Outcome {
    let out = TempDir::new().unwrap();
    let dest = out.path().join("out");
    if existing_destination {
        std::fs::create_dir(&dest).unwrap();
    }
    let report = ExtractRequest::new(config)
        .with_options(options)
        .extract(archive, &dest)?;
    Ok((report, non_directories(&dest)))
}

fn in_memory(bytes: &[u8], format: Format, config: &SecurityConfig) -> Outcome {
    let reader = match format {
        Format::Tar => ArchiveReader::tar(Cursor::new(bytes.to_vec()), None),
        Format::Zip => ArchiveReader::seekable(Cursor::new(bytes.to_vec()), SeekableFormat::Zip),
        Format::SevenZ => {
            ArchiveReader::seekable(Cursor::new(bytes.to_vec()), SeekableFormat::SevenZ)
        }
    };
    let mut sink = MemorySink::default().with_path_model(PathModel::Host);
    let options = SinkOptions::try_from(&refusing())?;
    let report = SinkExtractRequest::new(config)
        .with_options(options)
        .extract(reader, &mut sink)?;
    let landed = sink
        .iter()
        .filter(|(_, entry)| entry.kind() != MemoryEntryKind::Directory)
        .map(|(path, _)| path.to_path_buf())
        .collect();
    Ok((report, landed))
}

#[derive(Clone, Copy)]
enum Format {
    Tar,
    Zip,
    SevenZ,
}

impl Format {
    const fn file_name(self) -> &'static str {
        match self {
            Self::Tar => "a.tar",
            Self::Zip => "a.zip",
            Self::SevenZ => "a.7z",
        }
    }
}

fn config() -> SecurityConfig {
    SecurityConfig::default()
        .with_allow_symlinks(true)
        .with_allow_hardlinks(true)
        .with_allow_solid_archives(true)
}

/// How the archives of one format fared, for the non-vacuity floors.
#[derive(Default)]
struct Tally {
    ran: usize,
    list_refused: usize,
    inexpressible: usize,
    duplicates: usize,
    refused: usize,
    without_extract: usize,
}

fn assert_leg(label: &str, expected: &Expected, outcome: Outcome) {
    if expected.refused {
        assert!(outcome.is_err(), "{label}: dispositions refuse, run ok");
        return;
    }
    let (report, landed) = outcome.unwrap_or_else(|e| panic!("{label}: dispositions accept: {e}"));
    assert_eq!(landed, expected.landed, "{label}: landings");
    assert_eq!(report.files_extracted, expected.files, "{label}: files");
    assert_eq!(
        report.symlinks_created, expected.symlinks,
        "{label}: symlinks"
    );
    assert_eq!(
        report.skipped.count(SkipKind::Duplicate),
        expected.duplicates.len(),
        "{label}: duplicates"
    );
    assert_eq!(
        report.files_skipped(),
        expected.duplicates.len(),
        "{label}: skips of any other kind"
    );
    let mut sampled: Vec<_> = report
        .skipped
        .sample()
        .iter()
        .filter(|skip| skip.kind == SkipKind::Duplicate)
        .map(|skip| skip.path.clone())
        .collect();
    sampled.sort();
    assert_eq!(sampled, expected.duplicates, "{label}: skipped paths");
}

/// Runs one archive through every leg and compares each with the dispositions;
/// returns the index of the first refused entry.
fn check(label: &str, format: Format, bytes: &[u8], tally: &mut Tally) -> Option<usize> {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join(format.file_name());
    std::fs::write(&archive, bytes).unwrap();
    let config = config();
    let listing = ListRequest::new(&config)
        .with_options(ListOptions::default().with_stored_targets(StoredTargets::Read))
        .list(&archive);
    let Ok(manifest) = listing else {
        for (leg, outcome) in [
            (
                "in place, absent",
                on_disk(&archive, &config, refusing(), false),
            ),
            ("memory", in_memory(bytes, format, &config)),
        ] {
            assert!(outcome.is_err(), "{label} / {leg}: list refuses, run ok");
        }
        tally.list_refused += 1;
        return None;
    };
    let expected = expectation(&manifest, &config);

    let atomic = refusing().with_staging(Staging::Atomic);
    assert_leg(
        &format!("{label} / in place, absent"),
        &expected,
        on_disk(&archive, &config, refusing(), false),
    );
    assert_leg(
        &format!("{label} / in place, empty"),
        &expected,
        on_disk(&archive, &config, refusing(), true),
    );
    assert_leg(
        &format!("{label} / atomic"),
        &expected,
        on_disk(&archive, &config, atomic, false),
    );
    assert_leg(
        &format!("{label} / memory"),
        &expected,
        in_memory(bytes, format, &config),
    );

    tally.ran += 1;
    tally.duplicates += expected.duplicates.len();
    tally.refused += manifest
        .dispositions(&config)
        .filter(|(_, d)| matches!(d, Disposition::Refuse))
        .count();
    tally.without_extract += usize::from(expected.extracted == 0);
    manifest
        .dispositions(&config)
        .position(|(_, d)| matches!(d, Disposition::Refuse))
}

/// Checks a case. Where an entry is refused, the entries before it must run
/// clean as an archive of their own, and, with no hardlink (which extraction
/// defers) to move the failure, the archive through that entry must fail: so
/// the entry the dispositions refuse first is the one extraction fails at.
fn check_case(format: Format, case: &Case, tally: &mut Tally) {
    let build = |items: &[Item]| match format {
        Format::Tar => Some(tar_bytes(items)),
        Format::Zip => zip_bytes(items),
        Format::SevenZ => sevenz_bytes(items),
    };
    let Some(bytes) = build(&case.items) else {
        tally.inexpressible += 1;
        return;
    };
    let Some(first) = check(&case.name, format, &bytes, tally) else {
        return;
    };
    let mut scratch = Tally::default();
    let before = build(&case.items[..first]).unwrap();
    let label = format!("{} (first {first})", case.name);
    assert_eq!(
        check(&label, format, &before, &mut scratch),
        None,
        "{label}: refused before the first refused entry"
    );
    if !case.items.iter().any(|item| matches!(item, Item::Hard(..))) {
        let through = build(&case.items[..=first]).unwrap();
        let label = format!("{} (through {first})", case.name);
        let list_refused = scratch.list_refused;
        let refused = check(&label, format, &through, &mut scratch);
        assert!(
            refused.is_some() || scratch.list_refused > list_refused,
            "{label}: the first refused entry does not fail the run"
        );
    }
}

fn run_corpus(format: Format) -> Tally {
    let mut tally = Tally::default();
    for case in &corpus() {
        check_case(format, case, &mut tally);
    }
    assert_eq!(
        tally.ran + tally.list_refused + tally.inexpressible,
        corpus().len()
    );
    tally
}

#[test]
fn tar_dispositions_match_extraction() {
    let tally = run_corpus(Format::Tar);
    assert_eq!(tally.ran, corpus().len());
    assert_eq!(tally.without_extract, 0, "every archive extracts something");
    #[cfg(unix)]
    {
        assert!(tally.duplicates >= 10, "duplicates: {}", tally.duplicates);
        assert!(tally.refused >= 7, "refused: {}", tally.refused);
    }
}

#[test]
fn zip_dispositions_match_extraction() {
    let tally = run_corpus(Format::Zip);
    // A ZIP that repeats a name is refused at listing, so only the names that
    // differ (`x`/`x/`, links, the case alias) reach the legs.
    assert!(tally.ran >= 6, "ran: {}", tally.ran);
    assert!(
        tally.list_refused >= 6,
        "list refused: {}",
        tally.list_refused
    );
    assert!(tally.refused >= 5, "refused: {}", tally.refused);
    assert_eq!(tally.without_extract, 0, "every archive extracts something");
}

#[test]
fn sevenz_dispositions_match_extraction() {
    let tally = run_corpus(Format::SevenZ);
    assert_eq!(tally.list_refused, 0);
    assert_eq!(tally.ran, 14, "every archive without a hardlink runs");
    // `X` repeats `x` only on a case-insensitive volume.
    let duplicates = if cfg!(target_os = "macos") { 8 } else { 7 };
    assert!(
        tally.duplicates >= duplicates,
        "duplicates: {}",
        tally.duplicates
    );
    assert!(tally.refused >= 5, "refused: {}", tally.refused);
    assert_eq!(tally.without_extract, 0, "every archive extracts something");
}
