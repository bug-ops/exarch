//! Entry selection and leading-component stripping behave the same in TAR,
//! ZIP and 7z, on a directory and in memory, and `list` and `verify` judge
//! them as `extract` does.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

mod common;
mod sink_support;

use std::assert_matches;
use std::io::Cursor;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::ConfigProblem;
use exarch_core::ConfigSetting;
use exarch_core::Disposition;
use exarch_core::DispositionKind;
use exarch_core::ExistingFiles;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::ExtractionReport;
use exarch_core::MemoryLimit;
use exarch_core::MemorySink;
use exarch_core::PathRewrite;
use exarch_core::QuotaResource;
use exarch_core::SecurityConfig;
use exarch_core::SinkExtractRequest;
use exarch_core::SinkOptions;
use exarch_core::SkipKind;
use exarch_core::Staging;
use exarch_core::StripComponents;
use exarch_core::VerificationStatus;
use exarch_core::Violation;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use sink_support::Tree;
use tempfile::TempDir;

#[derive(Debug, Clone, Copy)]
enum Format {
    Tar,
    Zip,
    SevenZ,
}

const FORMATS: [Format; 3] = [Format::Tar, Format::Zip, Format::SevenZ];

/// An entry of a fixture archive.
#[derive(Clone, Copy)]
enum Item<'a> {
    File(&'a str, &'a [u8]),
    Dir(&'a str),
    Symlink(&'a str, &'a str),
    Hardlink(&'a str, &'a str),
}

impl Format {
    const fn file_name(self) -> &'static str {
        match self {
            Self::Tar => "a.tar",
            Self::Zip => "a.zip",
            Self::SevenZ => "a.7z",
        }
    }

    fn build(self, items: &[Item<'_>]) -> Vec<u8> {
        match self {
            Self::Tar => sink_support::tar_archive(
                &items
                    .iter()
                    .map(|item| match *item {
                        Item::File(name, data) => sink_support::tar_file(name, data),
                        Item::Dir(name) => sink_support::tar_dir(name),
                        Item::Symlink(name, target) => sink_support::tar_symlink(name, target),
                        Item::Hardlink(name, target) => sink_support::tar_hardlink(name, target),
                    })
                    .collect::<Vec<_>>(),
            ),
            Self::Zip => sink_support::zip_archive(
                items
                    .iter()
                    .map(|item| match *item {
                        Item::File(name, data) => sink_support::zip_file(name, data),
                        Item::Dir(name) => sink_support::zip_dir(name),
                        Item::Symlink(name, target) => sink_support::zip_symlink(name, target),
                        Item::Hardlink(..) => panic!("ZIP has no hardlinks"),
                    })
                    .collect(),
            ),
            Self::SevenZ => common::solid_copy_7z(
                &items
                    .iter()
                    .map(|item| match *item {
                        Item::File(name, data) => common::RawEntry::File(name, data),
                        Item::Dir(name) => common::RawEntry::Dir(name),
                        Item::Symlink(name, target) => {
                            common::RawEntry::Link(name, target.as_bytes())
                        }
                        Item::Hardlink(..) => panic!("7z has no hardlinks"),
                    })
                    .collect::<Vec<_>>(),
            ),
        }
    }

    fn write(self, dir: &Path, items: &[Item<'_>]) -> PathBuf {
        let path = dir.join(self.file_name());
        std::fs::write(&path, self.build(items)).unwrap();
        path
    }
}

/// Renders a relative path with `/` separators on every platform.
fn slashed(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn base() -> SecurityConfig {
    SecurityConfig::default()
        .with_allow_solid_archives(true)
        .with_allow_symlinks(true)
        .with_allow_hardlinks(true)
}

fn strip(count: u64) -> PathRewrite {
    let config = SecurityConfig::default();
    PathRewrite::Strip(
        StripComponents::new(count.try_into().unwrap(), config.max_path_depth).unwrap(),
    )
}

fn root(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction(partial) => root(partial.cause()),
        other => other,
    }
}

struct Run {
    work: TempDir,
    archive: PathBuf,
    dest: PathBuf,
    result: Result<ExtractionReport, ArchiveError>,
}

impl Run {
    fn tree(&self) -> Tree {
        if self.dest.exists() {
            sink_support::walk(&self.dest)
        } else {
            Tree::default()
        }
    }

    fn files(&self) -> Vec<String> {
        self.tree().files.keys().map(|path| slashed(path)).collect()
    }

    fn report(&self) -> &ExtractionReport {
        self.result.as_ref().unwrap()
    }

    fn error(&self) -> &ArchiveError {
        root(self.result.as_ref().unwrap_err())
    }
}

fn extract_with(
    format: Format,
    items: &[Item<'_>],
    config: &SecurityConfig,
    options: ExtractionOptions,
) -> Run {
    let work = TempDir::new().unwrap();
    let archive = format.write(work.path(), items);
    let dest = work.path().join("out");
    let result = ExtractRequest::new(config)
        .with_options(options)
        .extract(&archive, &dest);
    Run {
        work,
        archive,
        dest,
        result,
    }
}

fn extract(format: Format, items: &[Item<'_>], config: &SecurityConfig) -> Run {
    extract_with(format, items, config, ExtractionOptions::default())
}

fn wrapped() -> Vec<Item<'static>> {
    vec![
        Item::Dir("project-1.2.3/"),
        Item::File("project-1.2.3/README", b"readme"),
        Item::Dir("project-1.2.3/src/"),
        Item::File("project-1.2.3/src/main.rs", b"main"),
    ]
}

#[test]
fn strip_one_unwraps_a_release_wrapper() {
    for format in FORMATS {
        let config = base().with_path_rewrite(strip(1));
        let run = extract(format, &wrapped(), &config);

        let report = run.report();
        assert_eq!(run.files(), ["README", "src/main.rs"], "{format:?}");
        assert!(!run.dest.join("project-1.2.3").exists(), "{format:?}");
        assert_eq!(
            report.skipped.count(SkipKind::StrippedAway),
            1,
            "{format:?}"
        );
        assert_eq!(report.files_extracted, 2, "{format:?}");
    }
}

#[test]
fn strip_beyond_every_entry_extracts_nothing_and_succeeds() {
    for format in FORMATS {
        let config = base().with_path_rewrite(strip(5));
        let run = extract(format, &wrapped(), &config);

        let report = run.report();
        assert!(run.files().is_empty(), "{format:?}");
        assert_eq!(
            report.skipped.count(SkipKind::StrippedAway),
            4,
            "{format:?}"
        );
    }
}

#[test]
fn an_entry_with_exactly_the_stripped_components_is_stripped_away() {
    for format in FORMATS {
        let config = base().with_path_rewrite(strip(2));
        let run = extract(
            format,
            &[Item::File("a/b", b"x"), Item::File("a/b/c", b"y")],
            &config,
        );

        assert_eq!(run.files(), ["c"], "{format:?}");
        assert_eq!(
            run.report().skipped.count(SkipKind::StrippedAway),
            1,
            "{format:?}"
        );
    }
}

#[test]
fn dot_slash_and_backslash_names_strip_like_plain_ones() {
    let config = base().with_path_rewrite(strip(1));
    let tar = extract(
        Format::Tar,
        &[Item::File("./top/x", b"1"), Item::File("./top/sub/y", b"2")],
        &config,
    );
    assert_eq!(tar.files(), ["sub/y", "x"]);

    let zip = extract(Format::Zip, &[Item::File("top\\x", b"1")], &config);
    assert_eq!(zip.files(), ["x"]);
}

#[test]
fn include_selects_a_subtree_and_counts_what_it_leaves_out() {
    for format in FORMATS {
        let config = base().try_add_include("a/b").unwrap();
        let run = extract(
            format,
            &[Item::File("a/b/c.txt", b"c"), Item::File("a/d.txt", b"d")],
            &config,
        );

        let report = run.report();
        assert_eq!(run.files(), ["a/b/c.txt"], "{format:?}");
        assert_eq!(report.skipped.count(SkipKind::NotSelected), 1, "{format:?}");
    }
}

#[test]
fn an_exclude_removes_a_subtree_and_wins_over_an_include() {
    for format in FORMATS {
        let config = base().try_add_exclude("docs").unwrap();
        let run = extract(
            format,
            &[
                Item::File("src/main.rs", b"m"),
                Item::File("docs/guide.md", b"g"),
                Item::Dir("docs/"),
            ],
            &config,
        );
        assert_eq!(run.files(), ["src/main.rs"], "{format:?}");
        assert!(!run.dest.join("docs").exists(), "{format:?}");

        let config = base()
            .try_add_include("src")
            .unwrap()
            .try_add_exclude("src/generated")
            .unwrap();
        let run = extract(
            format,
            &[
                Item::File("src/main.rs", b"m"),
                Item::File("src/generated/x.rs", b"x"),
            ],
            &config,
        );
        assert_eq!(run.files(), ["src/main.rs"], "{format:?}");
    }
}

fn glob_tree() -> Vec<Item<'static>> {
    vec![
        Item::File("src/lib.rs", b"1"),
        Item::File("src/c/one.rs", b"2"),
        Item::File("src/c/two.rs", b"3"),
        Item::File("src/c/two.txt", b"4"),
        Item::File("src/c/deep/three.rs", b"5"),
        Item::File("src/d/two.rs", b"6"),
        Item::File("docs/readme.md", b"7"),
        Item::File("apple", b"8"),
        Item::File("dog", b"9"),
    ]
}

#[test]
fn glob_include_patterns_select_as_bsdtar_would() {
    let cases: [(&str, &[&str]); 6] = [
        ("src/c/*.rs", &["src/c/one.rs", "src/c/two.rs"]),
        (
            "src/**/*.rs",
            &[
                "src/c/deep/three.rs",
                "src/c/one.rs",
                "src/c/two.rs",
                "src/d/two.rs",
                "src/lib.rs",
            ],
        ),
        ("src/*/two.rs", &["src/c/two.rs", "src/d/two.rs"]),
        ("src/c/t?o.rs", &["src/c/two.rs"]),
        (
            "[a-c]*",
            &[
                "apple",
                "src/c/deep/three.rs",
                "src/c/one.rs",
                "src/c/two.rs",
                "src/c/two.txt",
            ],
        ),
        ("*.md", &["docs/readme.md"]),
    ];
    for format in FORMATS {
        for (pattern, expected) in cases {
            let config = base().try_add_include(pattern).unwrap();
            let run = extract(format, &glob_tree(), &config);
            assert_eq!(run.files(), expected, "{format:?} {pattern}");
        }
    }
}

#[test]
fn a_glob_exclude_wins_over_a_glob_include() {
    for format in FORMATS {
        let config = base()
            .try_add_include("src/**/*.rs")
            .unwrap()
            .try_add_exclude("deep")
            .unwrap()
            .try_add_exclude("two.rs")
            .unwrap();
        let run = extract(format, &glob_tree(), &config);
        assert_eq!(run.files(), ["src/c/one.rs", "src/lib.rs"], "{format:?}");
    }
}

#[test]
fn an_unmatched_glob_include_is_reported_by_its_text() {
    for format in FORMATS {
        let config = base().try_add_include("src/**/*.go").unwrap();
        let run = extract(format, &glob_tree(), &config);

        let ArchiveError::UnmatchedInclude { patterns } = run.error() else {
            panic!("{format:?}: {:?}", run.error());
        };
        let named: Vec<_> = patterns.iter().map(ToString::to_string).collect();
        assert_eq!(named, ["src/**/*.go"], "{format:?}");
    }
}

#[test]
fn patterns_are_case_sensitive_and_match_before_stripping() {
    for format in FORMATS {
        let config = base()
            .try_add_include("top/README")
            .unwrap()
            .with_path_rewrite(strip(1));
        let run = extract(
            format,
            &[
                Item::File("top/README", b"r"),
                Item::File("top/readme", b"l"),
                Item::File("README", b"x"),
            ],
            &config,
        );
        assert_eq!(run.files(), ["README"], "{format:?}");
        assert_eq!(
            std::fs::read(run.dest.join("README")).unwrap(),
            b"r",
            "{format:?}"
        );
    }
}

#[test]
fn an_include_that_matches_nothing_fails_after_the_scan_naming_every_pattern() {
    for format in FORMATS {
        let config = base()
            .try_add_include("a/b")
            .unwrap()
            .try_add_include("zzz")
            .unwrap()
            .try_add_include("nothing")
            .unwrap();
        let run = extract(format, &[Item::File("a/b/c.txt", b"c")], &config);

        let ArchiveError::UnmatchedInclude { patterns } = run.error() else {
            panic!("{format:?}: {:?}", run.error());
        };
        let named: Vec<_> = patterns.iter().map(ToString::to_string).collect();
        assert_eq!(named, ["zzz", "nothing"], "{format:?}");
        assert_eq!(run.files(), ["a/b/c.txt"], "{format:?}: a late error keeps");
    }
}

#[test]
fn an_exclude_that_matches_nothing_is_not_an_error() {
    for format in FORMATS {
        let config = base().try_add_exclude("nothing").unwrap();
        let run = extract(format, &[Item::File("a.txt", b"a")], &config);
        assert_eq!(run.files(), ["a.txt"], "{format:?}");
    }
}

#[test]
fn an_empty_archive_with_an_include_fails() {
    for format in FORMATS {
        let config = base().try_add_include("a").unwrap();
        let run = extract(format, &[], &config);
        assert_matches!(
            run.error(),
            ArchiveError::UnmatchedInclude { .. },
            "{format:?}"
        );
    }
}

#[test]
fn an_unmatched_include_rolls_an_atomic_extraction_back() {
    for format in FORMATS {
        let config = base().try_add_include("zzz").unwrap();
        let options = ExtractionOptions::default().with_staging(Staging::Atomic);
        let run = extract_with(format, &[Item::File("a.txt", b"a")], &config, options);

        assert_matches!(run.error(), ArchiveError::UnmatchedInclude { .. });
        assert!(!run.dest.exists(), "{format:?}: nothing is committed");
    }
}

#[test]
fn replacing_a_destination_with_a_subset_is_refused_before_the_archive_is_opened() {
    let work = TempDir::new().unwrap();
    let dest = work.path().join("out");
    std::fs::create_dir(&dest).unwrap();
    std::fs::write(dest.join("keep.txt"), b"keep").unwrap();
    let options = ExtractionOptions::default().with_staging(Staging::AtomicReplace);

    for config in [
        base().try_add_include("a").unwrap(),
        base().try_add_exclude("a").unwrap(),
        base().with_path_rewrite(strip(1)),
    ] {
        let error = ExtractRequest::new(&config)
            .with_options(options.clone())
            .extract(work.path().join("missing.tar"), &dest)
            .unwrap_err();
        assert_matches!(
            error,
            ArchiveError::InvalidConfiguration {
                setting: ConfigSetting::EntrySelection,
                problem: ConfigProblem::NotSupported,
            }
        );
        assert!(dest.join("keep.txt").is_file());
    }
}

#[test]
fn a_refused_original_path_stays_refused_under_every_selection() {
    for format in FORMATS {
        for config in [
            base().try_add_include("a.txt").unwrap(),
            base().with_path_rewrite(strip(1)),
            base().try_add_exclude("x").unwrap(),
        ] {
            let run = extract(
                format,
                &[Item::File("top/a.txt", b"a"), Item::File("../x", b"escape")],
                &config,
            );
            assert_matches!(
                run.error(),
                ArchiveError::PathTraversal { .. },
                "{format:?}"
            );
            assert!(!run.work.path().join("x").exists(), "{format:?}");
        }
    }
}

/// Every archive the plain extraction refuses stays refused when its names
/// sit below a stripped wrapper, under a pattern that selects the entry and
/// under flatten (spec 022 SC-006, NFR-002).
#[test]
fn archives_refused_plainly_stay_refused_under_every_selection() {
    let hostile: Vec<(&str, Vec<Item<'_>>)> = vec![
        ("traversal", vec![Item::File("../x", b"x")]),
        ("nested traversal", vec![Item::File("a/../../x", b"x")]),
        ("absolute", vec![Item::File("/abs/x", b"x")]),
        ("symlink escape", vec![Item::Symlink("l", "../../outside")]),
        (
            "symlink chain",
            vec![Item::Symlink("l1", "l2"), Item::Symlink("l2", "..")],
        ),
        (
            "hardlink escape",
            vec![Item::File("f", b"f"), Item::Hardlink("h", "../x")],
        ),
        (
            "hardlink absolute",
            vec![Item::File("f", b"f"), Item::Hardlink("h", "/etc/passwd")],
        ),
    ];
    let wrapped_under = |items: &[Item<'_>], prefix: &str| -> Vec<Vec<u8>> {
        items
            .iter()
            .map(|item| match *item {
                Item::File(name, data) => sink_support::tar_file(&format!("{prefix}{name}"), data),
                Item::Symlink(name, target) => {
                    sink_support::tar_symlink(&format!("{prefix}{name}"), target)
                }
                Item::Hardlink(name, target) => {
                    sink_support::tar_hardlink(&format!("{prefix}{name}"), target)
                }
                Item::Dir(name) => sink_support::tar_dir(&format!("{prefix}{name}")),
            })
            .collect()
    };

    for (label, items) in hostile {
        let plain = extract(Format::Tar, &items, &base());
        assert!(plain.result.is_err(), "{label}: refused plainly");

        let run = |config: &SecurityConfig, prefix: &str| {
            let work = TempDir::new().unwrap();
            let archive = work.path().join("a.tar");
            std::fs::write(
                &archive,
                sink_support::tar_archive(&wrapped_under(&items, prefix)),
            )
            .unwrap();
            let dest = work.path().join("out");
            let result = ExtractRequest::new(config).extract(&archive, &dest);
            (work, dest, result)
        };

        // A wrapper in front of an absolute name makes it a relative one.
        if label != "absolute" {
            let stripped = base().with_path_rewrite(strip(1));
            let (work, _, result) = run(&stripped, "top/");
            assert!(result.is_err(), "{label}: stripped");
            assert!(!work.path().join("x").exists(), "{label}: stripped write");
        }

        let included = base().try_add_exclude("nothing").unwrap();
        let (work, _, result) = run(&included, "");
        assert!(result.is_err(), "{label}: filtered");
        assert!(!work.path().join("x").exists(), "{label}: filtered write");
    }
}

#[test]
fn a_name_that_would_leave_the_destination_after_stripping_is_refused() {
    for format in FORMATS {
        let config = base().with_path_rewrite(strip(1));
        let run = extract(format, &[Item::File("top/../../etc/x", b"escape")], &config);
        assert_matches!(
            run.error(),
            ArchiveError::PathTraversal { .. },
            "{format:?}"
        );
        assert!(!run.work.path().join("etc").exists(), "{format:?}");
    }
}

#[test]
fn colliding_names_after_stripping_follow_the_existing_files_policy() {
    let items = [Item::File("a/x", b"first"), Item::File("b/x", b"second")];
    for format in FORMATS {
        let config = base().with_path_rewrite(strip(1));
        for (policy, expected, duplicates) in [
            (ExistingFiles::Skip, "first", 1),
            (ExistingFiles::Refuse, "first", 1),
            (ExistingFiles::Overwrite, "second", 0),
        ] {
            let options = ExtractionOptions::default().with_existing_files(policy);
            let run = extract_with(format, &items, &config, options);

            let report = run.report();
            assert_eq!(
                std::fs::read(run.dest.join("x")).unwrap(),
                expected.as_bytes(),
                "{format:?} {policy:?}"
            );
            assert_eq!(
                report.skipped.count(SkipKind::Duplicate),
                duplicates,
                "{format:?} {policy:?}"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn a_symlink_target_is_never_rewritten() {
    for format in FORMATS {
        let config = base().with_path_rewrite(strip(1));
        let escaping = extract(
            format,
            &[Item::Dir("top/"), Item::Symlink("top/link", "../other/x")],
            &config,
        );
        assert_matches!(
            escaping.error(),
            ArchiveError::SymlinkEscape { .. },
            "{format:?}"
        );

        let inside = extract(
            format,
            &[
                Item::Dir("top/"),
                Item::Dir("top/bin/"),
                Item::Symlink("top/bin/t", "../lib/x"),
            ],
            &config,
        );
        let report = inside.report();
        assert_eq!(report.symlinks_created, 1, "{format:?}");
        assert_eq!(
            std::fs::read_link(inside.dest.join("bin/t")).unwrap(),
            Path::new("../lib/x"),
            "{format:?}"
        );
    }
}

fn hardlinked() -> Vec<Item<'static>> {
    vec![
        Item::Dir("top/"),
        Item::File("top/orig", b"payload"),
        Item::Hardlink("top/l", "top/orig"),
    ]
}

#[test]
fn a_hardlink_whose_target_is_not_selected_is_refused() {
    let config = base().try_add_include("top/l").unwrap();
    let run = extract(Format::Tar, &hardlinked(), &config);

    assert_matches!(
        run.error(),
        ArchiveError::SecurityViolation {
            kind: Violation::HardlinkTargetNotExtracted { .. },
            ..
        }
    );
    assert!(!run.dest.join("top/orig").exists());
}

#[test]
fn a_hardlink_whose_target_is_stripped_away_is_refused() {
    let config = base().with_path_rewrite(strip(1));
    let run = extract(
        Format::Tar,
        &[Item::Dir("top/"), Item::Hardlink("top/l", "top")],
        &config,
    );

    assert_matches!(
        run.error(),
        ArchiveError::SecurityViolation {
            kind: Violation::HardlinkTargetNotExtracted { .. },
            ..
        }
    );
}

#[test]
fn a_hardlink_and_its_target_both_selected_land_together() {
    let config = base().with_path_rewrite(strip(1));
    let run = extract(Format::Tar, &hardlinked(), &config);

    assert_eq!(run.files(), ["l", "orig"]);
    assert_eq!(std::fs::read(run.dest.join("l")).unwrap(), b"payload");
}

#[test]
fn a_skipped_file_is_not_charged_to_the_size_quotas_and_creates_no_directory() {
    for format in FORMATS {
        let config = base()
            .try_add_include("keep")
            .unwrap()
            .with_max_file_size(exarch_core::non_zero!(100))
            .with_max_total_size(exarch_core::non_zero!(100));
        let run = extract(
            format,
            &[
                Item::File("keep/a.txt", b"hi"),
                Item::File("deep/dir/big.bin", &[7; 2_000]),
            ],
            &config,
        );

        assert_eq!(run.files(), ["keep/a.txt"], "{format:?}");
        assert!(!run.dest.join("deep").exists(), "{format:?}");
    }
}

#[test]
fn list_counts_a_skipped_entry_toward_the_file_limit_only() {
    for format in FORMATS {
        let work = TempDir::new().unwrap();
        let items = [
            Item::File("keep/a.txt", b"hi"),
            Item::File("big.bin", &[7; 2_000]),
            Item::File("other.txt", b"yo"),
        ];
        let archive = format.write(work.path(), &items);
        let config = base()
            .try_add_include("keep")
            .unwrap()
            .with_max_file_size(exarch_core::non_zero!(100))
            .with_max_total_size(exarch_core::non_zero!(100));

        let manifest = list_archive(&archive, &config).unwrap();
        assert_eq!(manifest.entries().len(), 3, "{format:?}");

        let tight = config.with_max_file_count(exarch_core::non_zero!(2));
        assert_matches!(
            list_archive(&archive, &tight),
            Err(ArchiveError::QuotaExceeded {
                resource: QuotaResource::FileCount { .. }
            }),
            "{format:?}"
        );
    }
}

#[test]
fn verify_charges_a_skipped_file_to_the_file_count_alone() {
    for format in FORMATS {
        let work = TempDir::new().unwrap();
        let archive = format.write(
            work.path(),
            &[
                Item::File("keep/a.txt", b"hi"),
                Item::File("big.bin", &[7; 2_000]),
            ],
        );
        let tight = |config: SecurityConfig| {
            config
                .with_max_file_size(exarch_core::non_zero!(100))
                .with_max_total_size(exarch_core::non_zero!(100))
        };
        for config in [
            tight(base().try_add_include("keep").unwrap()),
            tight(base().try_add_allowed_extension("txt").unwrap()),
        ] {
            let report = verify_archive(&archive, &config).unwrap();
            assert_eq!(report.status(), VerificationStatus::Pass, "{format:?}");
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CountOutcome {
    Within,
    Exceeded,
}

fn count_outcome<T>(result: Result<T, ArchiveError>) -> CountOutcome {
    match result {
        Ok(_) => CountOutcome::Within,
        Err(error) => {
            assert_matches!(
                root(&error),
                ArchiveError::QuotaExceeded {
                    resource: QuotaResource::FileCount { .. }
                },
                "{error:?}"
            );
            CountOutcome::Exceeded
        }
    }
}

fn verify_count_outcome(archive: &Path, config: &SecurityConfig) -> CountOutcome {
    match verify_archive(archive, config) {
        Ok(report) if report.status() == VerificationStatus::Pass => CountOutcome::Within,
        Ok(report) => {
            assert!(
                report
                    .issues()
                    .iter()
                    .any(|issue| issue.message().contains("file count")),
                "{:?}",
                report.issues()
            );
            CountOutcome::Exceeded
        }
        Err(error) => count_outcome::<()>(Err(error)),
    }
}

/// Extract, list and verify all pass at `limit_at` entries and all fail one
/// below.
fn assert_every_command_counts(
    format: Format,
    items: &[Item<'_>],
    config: &SecurityConfig,
    limit_at: usize,
) {
    let work = TempDir::new().unwrap();
    let archive = format.write(work.path(), items);
    let expected = |max: usize| {
        if max >= limit_at {
            CountOutcome::Within
        } else {
            CountOutcome::Exceeded
        }
    };
    for max in [limit_at, limit_at - 1] {
        let config = config
            .clone()
            .with_max_file_count(std::num::NonZeroUsize::new(max).unwrap());
        let dest = work.path().join(format!("out{max}"));
        let extracted = ExtractRequest::new(&config).extract(&archive, &dest);
        assert_eq!(
            count_outcome(extracted),
            expected(max),
            "{format:?} extract {max}"
        );
        assert_eq!(
            count_outcome(list_archive(&archive, &config)),
            expected(max),
            "{format:?} list {max}"
        );
        assert_eq!(
            verify_count_outcome(&archive, &config),
            expected(max),
            "{format:?} verify {max}"
        );
    }
}

#[test]
fn every_entry_counts_toward_the_file_limit_in_every_format_and_command() {
    let items = [
        Item::Dir("a/"),
        Item::File("a/1", b"1"),
        Item::Dir("b/"),
        Item::File("b/1", b"2"),
        Item::Dir("c/"),
        Item::File("c/1", b"3"),
    ];
    for format in FORMATS {
        assert_every_command_counts(format, &items, &base(), 6);
        assert_every_command_counts(format, &items, &base().try_add_include("a").unwrap(), 6);
        assert_every_command_counts(
            format,
            &items,
            &base().try_add_allowed_extension("zzz").unwrap(),
            6,
        );
    }
}

#[test]
fn a_skipped_duplicate_counts_toward_the_file_limit() {
    let items = [
        Item::File("d", b"1"),
        Item::File("d", b"2"),
        Item::Dir("x/"),
        Item::File("x/f", b"3"),
    ];
    for format in [Format::Tar, Format::SevenZ] {
        assert_every_command_counts(format, &items, &base(), 4);
    }
}

#[test]
fn list_refuses_an_unmatched_include_and_verify_reports_it() {
    for format in FORMATS {
        let work = TempDir::new().unwrap();
        let archive = format.write(
            work.path(),
            &[
                Item::Dir("a/"),
                Item::File("a/b", b"x"),
                Item::File("q", b"y"),
            ],
        );
        let config = base()
            .try_add_include("a")
            .unwrap()
            .try_add_include("zzz")
            .unwrap();

        let listed = list_archive(&archive, &config);
        let Err(ArchiveError::UnmatchedInclude { patterns }) = listed else {
            panic!("{format:?}: {listed:?}");
        };
        assert_eq!(patterns.len(), 1, "{format:?}");

        let report = verify_archive(&archive, &config).unwrap();
        assert_eq!(report.status(), VerificationStatus::Fail, "{format:?}");

        let matched = base().try_add_include("a").unwrap();
        assert!(list_archive(&archive, &matched).is_ok(), "{format:?}");
    }
}

#[test]
fn an_entry_that_cannot_be_placed_is_reported_as_refused() {
    for format in [Format::Tar, Format::Zip] {
        let work = TempDir::new().unwrap();
        let archive = format.write(
            work.path(),
            &[Item::File("f", b"x"), Item::File("f/g", b"y")],
        );
        let manifest = list_archive(&archive, &base()).unwrap();

        let dispositions: Vec<_> = manifest
            .dispositions(&base())
            .map(|(_, disposition)| disposition.kind())
            .collect();
        assert_eq!(
            dispositions,
            [DispositionKind::Extract, DispositionKind::Refuse],
            "{format:?}"
        );
        assert_eq!(manifest.landing_paths(&base()).count(), 1, "{format:?}");
    }
}

/// Glob selection stays linear on deep paths and stacked wildcards: no
/// recursion in member selection with long paths (node-tar GHSA-r292).
///
/// The bound is far above the observed debug-build time (milliseconds), so it
/// trips only on a super-linear or recursive matcher, never on a slow host.
#[test]
fn glob_selection_is_linear_on_deep_paths_and_stacked_wildcards() {
    const DEPTH: usize = 2_000;
    const BOUND: std::time::Duration = std::time::Duration::from_secs(20);
    let deep = vec!["a"; DEPTH].join("/");
    let work = TempDir::new().unwrap();
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(1);
    header.set_mode(0o644);
    builder.append_data(&mut header, &deep, &b"x"[..]).unwrap();
    let archive = work.path().join("deep.tar");
    std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();
    let depth = std::num::NonZeroUsize::new(DEPTH * 2).unwrap();
    let limits = || base().with_max_path_depth(depth);

    for text in [
        "**/a/**/a/**/a/**/a/**/a/**/b",
        "*a*a*a*a*a*a*a*a*a*a*b",
        "**/**/**/**/**/**/**/**/b",
    ] {
        let config = limits().try_add_include(text).unwrap();
        let started = std::time::Instant::now();
        let listed = list_archive(&archive, &config);
        let elapsed = started.elapsed();
        assert_matches!(listed, Err(ArchiveError::UnmatchedInclude { .. }), "{text}");
        assert!(elapsed < BOUND, "{text}: {elapsed:?}");
    }

    let config = limits()
        .try_add_exclude("**/a/**/a/**/a/**/a/**/a")
        .unwrap();
    let started = std::time::Instant::now();
    list_archive(&archive, &config).unwrap();
    assert!(started.elapsed() < BOUND);
}

#[test]
fn the_manifest_keeps_its_selection_and_reports_each_disposition() {
    let work = TempDir::new().unwrap();
    let archive = Format::Tar.write(
        work.path(),
        &[
            Item::Dir("top/"),
            Item::File("top/keep/a.txt", b"a"),
            Item::File("top/skip/b.txt", b"b"),
        ],
    );
    let config = base()
        .try_add_include("top/keep")
        .unwrap()
        .with_path_rewrite(strip(1));

    let manifest = list_archive(&archive, &config).unwrap();
    assert_eq!(manifest.selection(), &config.selection);

    let dispositions: Vec<_> = manifest
        .dispositions(&base())
        .map(|(entry, disposition)| (entry.path.to_string_lossy().into_owned(), disposition))
        .collect();
    assert_eq!(dispositions.len(), 3);
    assert_eq!(
        dispositions[0],
        ("top/".to_owned(), Disposition::Skip(SkipKind::NotSelected))
    );
    assert_matches!(
        &dispositions[1],
        (name, Disposition::Extract(landing))
            if name == "top/keep/a.txt" && landing.as_path() == Path::new("keep/a.txt")
    );
    assert_eq!(dispositions[2].1, Disposition::Skip(SkipKind::NotSelected));

    let other = base().try_add_include("nothing").unwrap();
    let landed: Vec<_> = manifest
        .landing_paths(&other)
        .map(|(_, landing)| landing.into_path_buf())
        .collect();
    assert_eq!(landed, [PathBuf::from("keep/a.txt")]);
    assert_eq!(manifest.total_size(), 2);
}

#[test]
fn landings_equal_what_extract_wrote() {
    for format in FORMATS {
        let config = base().with_path_rewrite(strip(1));
        let items = wrapped();
        let run = extract(format, &items, &config);
        assert!(run.result.is_ok(), "{format:?}");

        let manifest = list_archive(&run.archive, &config).unwrap();
        let mut landed: Vec<String> = manifest
            .landing_paths(&config)
            .filter(|(entry, _)| matches!(entry.kind, exarch_core::ManifestEntryKind::File { .. }))
            .map(|(_, landing)| slashed(landing.as_path()))
            .collect();
        landed.sort();
        assert_eq!(landed, run.files(), "{format:?}");
    }
}

#[test]
fn verify_models_the_selected_extraction() {
    for format in FORMATS {
        let work = TempDir::new().unwrap();
        let archive = format.write(work.path(), &wrapped());
        let config = base().with_path_rewrite(strip(1));

        let report = verify_archive(&archive, &config).unwrap();
        assert_eq!(report.status(), VerificationStatus::Pass, "{format:?}");
    }
}

#[test]
fn verify_reports_an_unmatched_include_and_a_hardlink_to_a_skipped_target() {
    let work = TempDir::new().unwrap();
    let archive = Format::Tar.write(work.path(), &hardlinked());

    let unmatched = base().try_add_include("zzz").unwrap();
    let report = verify_archive(&archive, &unmatched).unwrap();
    assert_eq!(report.status(), VerificationStatus::Fail);

    let dangling = base().try_add_include("top/l").unwrap();
    let report = verify_archive(&archive, &dangling).unwrap();
    assert_eq!(report.status(), VerificationStatus::Fail);
    assert!(
        report
            .issues()
            .iter()
            .any(|issue| issue.message().contains("does not extract")),
        "{:?}",
        report.issues()
    );

    let fine = base().with_path_rewrite(strip(1));
    let report = verify_archive(&archive, &fine).unwrap();
    assert_eq!(report.status(), VerificationStatus::Pass);
}

#[test]
fn verify_validates_the_original_path_of_an_unselected_entry() {
    for format in [Format::Tar, Format::Zip] {
        let work = TempDir::new().unwrap();
        let archive = format.write(
            work.path(),
            &[Item::File("a.txt", b"a"), Item::File("../x", b"escape")],
        );
        let config = base().try_add_include("a.txt").unwrap();

        let outcome = verify_archive(&archive, &config);
        let refused = outcome.map_or_else(
            |error| matches!(error, ArchiveError::PathTraversal { .. }),
            |report| report.status() == VerificationStatus::Fail,
        );
        assert!(refused, "{format:?}");
    }
}

#[test]
fn a_memory_sink_applies_the_same_selection() {
    for format in [Format::Tar, Format::Zip] {
        let config = base()
            .try_add_include("project-1.2.3/src")
            .unwrap()
            .with_path_rewrite(strip(1));
        let bytes = format.build(&wrapped());
        let reader = match format {
            Format::Tar => ArchiveReader::tar(Cursor::new(bytes), None),
            Format::Zip => {
                ArchiveReader::seekable(Cursor::new(bytes), exarch_core::SeekableFormat::Zip)
            }
            Format::SevenZ => unreachable!(),
        };
        let mut sink = MemorySink::new(MemoryLimit::DEFAULT);

        let report = SinkExtractRequest::new(&config)
            .with_options(SinkOptions::default())
            .extract(reader, &mut sink)
            .unwrap();

        let stored: Vec<_> = sink.iter().map(|(path, _)| slashed(path)).collect();
        assert_eq!(stored, ["src", "src/main.rs"], "{format:?}");
        assert_eq!(report.skipped.count(SkipKind::NotSelected), 2, "{format:?}");
    }
}

#[test]
fn a_memory_sink_reports_an_unmatched_include() {
    let config = base().try_add_include("zzz").unwrap();
    let bytes = Format::Tar.build(&wrapped());
    let mut sink = MemorySink::new(MemoryLimit::DEFAULT);

    let error = SinkExtractRequest::new(&config)
        .with_options(SinkOptions::default())
        .extract(ArchiveReader::tar(Cursor::new(bytes), None), &mut sink)
        .unwrap_err();

    assert_matches!(root(&error), ArchiveError::UnmatchedInclude { .. });
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn a_selected_out_compressed_entry_is_bounded_like_an_allowlist_skip() {
    let mib = 1024 * 1024;
    let tar = sink_support::tar_archive(&[
        sink_support::tar_file("big.bin", &vec![0; 8 * mib]),
        sink_support::tar_file("after.txt", b"hello"),
    ]);
    let config = SecurityConfig::default()
        .try_add_include("after.txt")
        .unwrap()
        .with_max_file_size(exarch_core::non_zero!(2 * 1024 * 1024))
        .with_max_compression_ratio(exarch_core::ratio_limit!(10.0));
    let mut sink = MemorySink::new(MemoryLimit::DEFAULT);

    let error = SinkExtractRequest::new(&config)
        .with_options(SinkOptions::default())
        .extract(
            ArchiveReader::tar(
                Cursor::new(gzip(&tar)),
                Some(exarch_core::CompressionCodec::Gzip),
            ),
            &mut sink,
        )
        .unwrap_err();

    assert_matches!(
        root(&error),
        ArchiveError::ZipBomb(details) if details.scope() == exarch_core::ZipBombScope::SkippedEntries
    );
}

#[test]
fn the_boundary_refuses_a_strip_count_beyond_the_path_depth() {
    let max = SecurityConfig::default().max_path_depth;
    let count = |n: usize| std::num::NonZeroU64::new(u64::try_from(n).unwrap()).unwrap();
    assert!(StripComponents::new(count(max.get()), max).is_ok());
    assert_matches!(
        StripComponents::new(count(max.get() + 1), max),
        Err(ArchiveError::InvalidConfiguration {
            setting: ConfigSetting::StripComponents,
            problem: ConfigProblem::TooLarge { .. },
        })
    );
}

#[test]
fn a_refused_pattern_names_its_setting() {
    assert_matches!(
        SecurityConfig::default().try_add_include("a**b"),
        Err(ArchiveError::InvalidConfiguration {
            setting: ConfigSetting::EntryInclude,
            ..
        })
    );
    assert_matches!(
        SecurityConfig::default().try_add_exclude("a,b"),
        Err(ArchiveError::InvalidConfiguration {
            setting: ConfigSetting::EntryExclude,
            ..
        })
    );
}

fn flatten() -> SecurityConfig {
    base().with_path_rewrite(PathRewrite::Flatten)
}

#[test]
fn flatten_lands_each_file_by_its_final_component_and_skips_directories() {
    for format in FORMATS {
        let run = extract(format, &wrapped(), &flatten());

        let report = run.report();
        assert_eq!(run.files(), ["README", "main.rs"], "{format:?}");
        assert!(run.tree().dirs.is_empty(), "{format:?}");
        assert_eq!(
            report.skipped.count(SkipKind::StrippedAway),
            2,
            "{format:?}"
        );
    }
}

#[test]
fn flatten_collisions_follow_the_existing_files_policy_and_count_a_duplicate() {
    let items = [Item::File("a/x", b"first"), Item::File("b/x", b"second")];
    for format in FORMATS {
        for (policy, expected, duplicates) in [
            (ExistingFiles::Skip, "first", 1),
            (ExistingFiles::Refuse, "first", 1),
            (ExistingFiles::Overwrite, "second", 0),
        ] {
            let options = ExtractionOptions::default().with_existing_files(policy);
            let run = extract_with(format, &items, &flatten(), options);

            let report = run.report();
            assert_eq!(
                std::fs::read(run.dest.join("x")).unwrap(),
                expected.as_bytes(),
                "{format:?} {policy:?}"
            );
            assert_eq!(
                report.skipped.count(SkipKind::Duplicate),
                duplicates,
                "{format:?} {policy:?}"
            );
        }
    }
}

#[test]
fn flatten_collides_names_a_portable_destination_treats_as_one() {
    let bytes = Format::Tar.build(&[Item::File("a/X", b"first"), Item::File("b/x", b"second")]);
    let mut sink =
        MemorySink::new(MemoryLimit::DEFAULT).with_path_model(exarch_core::PathModel::Portable);

    let report = SinkExtractRequest::new(&flatten())
        .with_options(SinkOptions::default())
        .extract(ArchiveReader::tar(Cursor::new(bytes), None), &mut sink)
        .unwrap();

    assert_eq!(report.skipped.count(SkipKind::Duplicate), 1);
    assert_eq!(sink.iter().count(), 1);
}

#[test]
fn flatten_refuses_a_link_entry_it_would_have_to_move() {
    for format in FORMATS {
        let run = extract(
            format,
            &[Item::File("a/x", b"x"), Item::Symlink("a/link", "x")],
            &flatten(),
        );
        assert_matches!(
            run.error(),
            ArchiveError::SecurityViolation {
                kind: Violation::LinkUnderFlatten { .. },
                ..
            },
            "{format:?}"
        );
    }

    let run = extract(Format::Tar, &hardlinked(), &flatten());
    assert_matches!(
        run.error(),
        ArchiveError::SecurityViolation {
            kind: Violation::LinkUnderFlatten { .. },
            ..
        }
    );
}

#[test]
fn flatten_skips_a_link_the_selection_leaves_out() {
    let config = flatten().try_add_include("a/x").unwrap();
    let run = extract(
        Format::Tar,
        &[Item::File("a/x", b"x"), Item::Symlink("a/link", "x")],
        &config,
    );

    assert_eq!(run.files(), ["x"]);
    assert_eq!(run.report().skipped.count(SkipKind::NotSelected), 1);
}

#[test]
fn flatten_is_modelled_by_list_and_verify() {
    let work = TempDir::new().unwrap();
    let archive = Format::Tar.write(work.path(), &wrapped());

    let manifest = list_archive(&archive, &flatten()).unwrap();
    let kinds: Vec<_> = manifest
        .dispositions(&flatten())
        .map(|(_, disposition)| disposition)
        .collect();
    assert_matches!(kinds[0], Disposition::Skip(SkipKind::StrippedAway));
    assert_matches!(
        &kinds[1],
        Disposition::Extract(landing) if landing.as_path() == Path::new("README")
    );
    assert_matches!(kinds[2], Disposition::Skip(SkipKind::StrippedAway));
    assert_matches!(
        &kinds[3],
        Disposition::Extract(landing) if landing.as_path() == Path::new("main.rs")
    );

    let report = verify_archive(&archive, &flatten()).unwrap();
    assert_eq!(report.status(), VerificationStatus::Pass);

    let linked = Format::Tar.write(
        work.path(),
        &[Item::File("a/x", b"x"), Item::Symlink("a/link", "x")],
    );
    let report = verify_archive(&linked, &flatten()).unwrap();
    assert_eq!(report.status(), VerificationStatus::Fail);
}

#[test]
fn replacing_a_destination_is_refused_for_flatten_too() {
    let work = TempDir::new().unwrap();
    let options = ExtractionOptions::default().with_staging(Staging::AtomicReplace);
    let error = ExtractRequest::new(&flatten())
        .with_options(options)
        .extract(work.path().join("missing.tar"), work.path())
        .unwrap_err();
    assert_matches!(
        error,
        ArchiveError::InvalidConfiguration {
            setting: ConfigSetting::EntrySelection,
            ..
        }
    );
}

fn colliding_hardlink() -> Vec<Item<'static>> {
    vec![
        Item::File("x/f", b"one"),
        Item::File("y/f", b"two"),
        Item::Hardlink("z/l", "y/f"),
    ]
}

#[test]
fn a_hardlink_to_an_entry_that_collided_after_stripping_is_refused() {
    let config = base().with_path_rewrite(strip(1));
    for policy in [
        ExistingFiles::Skip,
        ExistingFiles::Refuse,
        ExistingFiles::Overwrite,
    ] {
        let options = ExtractionOptions::default().with_existing_files(policy);
        let run = extract_with(Format::Tar, &colliding_hardlink(), &config, options);
        assert_matches!(
            run.error(),
            ArchiveError::SecurityViolation {
                kind: Violation::HardlinkTargetAmbiguous { .. },
                ..
            },
            "{policy:?}"
        );
        assert!(!run.dest.join("l").exists(), "{policy:?}");
    }
}

#[test]
fn a_hardlink_to_an_unambiguous_target_still_lands_next_to_a_collision() {
    let config = base().with_path_rewrite(strip(1));
    let run = extract(
        Format::Tar,
        &[
            Item::File("x/f", b"one"),
            Item::File("y/f", b"two"),
            Item::File("x/g", b"other"),
            Item::Hardlink("z/l", "x/g"),
        ],
        &config,
    );
    assert_eq!(std::fs::read(run.dest.join("l")).unwrap(), b"other");
}

#[test]
fn a_memory_sink_and_verify_refuse_the_same_ambiguous_hardlink() {
    let config = base().with_path_rewrite(strip(1));
    let bytes = Format::Tar.build(&colliding_hardlink());
    let mut sink = MemorySink::new(MemoryLimit::DEFAULT);
    let error = SinkExtractRequest::new(&config)
        .with_options(SinkOptions::default())
        .extract(ArchiveReader::tar(Cursor::new(bytes), None), &mut sink)
        .unwrap_err();
    assert_matches!(
        root(&error),
        ArchiveError::SecurityViolation {
            kind: Violation::HardlinkTargetAmbiguous { .. },
            ..
        }
    );

    let work = TempDir::new().unwrap();
    let archive = Format::Tar.write(work.path(), &colliding_hardlink());
    let report = verify_archive(&archive, &config).unwrap();
    assert_eq!(report.status(), VerificationStatus::Fail);
}
