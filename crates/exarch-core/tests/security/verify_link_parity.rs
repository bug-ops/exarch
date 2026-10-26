//! `verify` must reach the same verdict as `extract` for archives whose links
//! interact with earlier entries (symlink chains, dangling hardlinks).

#![cfg(unix)]

use exarch_core::IssueCategory;
use exarch_core::SecurityConfig;
use exarch_core::VerificationStatus;
use exarch_core::extract_archive;
use exarch_core::verify_archive;
use proptest::prelude::*;
use tempfile::TempDir;

#[derive(Clone, Debug)]
enum Item {
    Dir(String),
    File(String),
    Sym(String, String),
    Hard(String, String),
}

fn build_tar(items: &[Item]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for item in items {
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o644);
        match item {
            Item::Dir(path) => {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_mode(0o755);
                header.set_cksum();
                builder
                    .append_data(&mut header, format!("{path}/"), &[] as &[u8])
                    .expect("append dir");
            }
            Item::File(path) => {
                let data = b"data";
                header.set_size(data.len() as u64);
                header.set_cksum();
                builder
                    .append_data(&mut header, path, &data[..])
                    .expect("append file");
            }
            Item::Sym(path, target) | Item::Hard(path, target) => {
                header.set_entry_type(if matches!(item, Item::Sym(..)) {
                    tar::EntryType::Symlink
                } else {
                    tar::EntryType::Link
                });
                header.set_cksum();
                builder
                    .append_link(&mut header, path, target)
                    .expect("append link");
            }
        }
    }
    builder.into_inner().expect("finish tar")
}

fn link_config() -> SecurityConfig {
    SecurityConfig::default()
        .with_allow_symlinks(true)
        .with_allow_hardlinks(true)
}

struct Outcome {
    categories: Vec<IssueCategory>,
    status: VerificationStatus,
    extracted: exarch_core::Result<exarch_core::ExtractionReport>,
    base: TempDir,
}

impl Outcome {
    fn dest(&self) -> std::path::PathBuf {
        self.base.path().join("x/out")
    }
}

/// Verifies and extracts the archive into `<base>/x/out`; `plant` runs first
/// so callers can place files outside the destination.
fn run_verify_and_extract(items: &[Item], plant: impl FnOnce(&std::path::Path)) -> Outcome {
    let base = TempDir::new().expect("tempdir");
    plant(base.path());
    let archive = base.path().join("a.tar");
    std::fs::write(&archive, build_tar(items)).expect("write archive");
    let dest = base.path().join("x/out");
    std::fs::create_dir_all(&dest).expect("dest");

    let config = link_config();
    let report = verify_archive(&archive, &config).expect("verify report");
    let extracted = extract_archive(&archive, &dest, &config);
    Outcome {
        categories: report.issues().iter().map(|i| i.category).collect(),
        status: report.status(),
        extracted,
        base,
    }
}

/// Verifies and extracts the archive; asserts both reach the same verdict and
/// returns the categories verify reported.
fn assert_verify_agrees_with_extract(items: &[Item]) -> Vec<IssueCategory> {
    let outcome = run_verify_and_extract(items, |_| {});
    assert_eq!(
        outcome.extracted.is_ok(),
        outcome.status == VerificationStatus::Pass,
        "verdicts differ for {items:?}: extract={:?} verify={:?}",
        outcome.extracted,
        outcome.categories
    );
    outcome.categories
}

fn dir(p: &str) -> Item {
    Item::Dir(p.into())
}
fn file(p: &str) -> Item {
    Item::File(p.into())
}
fn sym(p: &str, t: &str) -> Item {
    Item::Sym(p.into(), t.into())
}
fn hard(p: &str, t: &str) -> Item {
    Item::Hard(p.into(), t.into())
}

/// Extraction can fail (or skip the link) at a link placed over a directory or
/// below a dangling link, so `verify` reports it as a security finding.
fn assert_link_placement_is_a_security_finding(items: &[Item]) -> Outcome {
    let outcome = run_verify_and_extract(items, |_| {});
    assert_eq!(outcome.status, VerificationStatus::Fail, "{items:?}");
    assert!(
        outcome.categories.contains(&IssueCategory::SecurityPolicy),
        "{items:?}: {:?}",
        outcome.categories
    );
    outcome
}

/// Overwriting cannot replace a directory with a symlink, so `--force` fails
/// closed there; default extraction skips the link, so verify only notes it.
fn assert_overwrite_note(items: &[Item]) {
    let outcome = run_verify_and_extract(items, |_| {});
    assert_eq!(outcome.status, VerificationStatus::Pass, "{items:?}");
    assert!(outcome.extracted.is_ok(), "{items:?}");
    assert_eq!(
        outcome.categories,
        [IssueCategory::InvalidArchive],
        "{items:?}"
    );
}

#[test]
fn symlink_over_earlier_directory_is_an_overwrite_note() {
    assert_overwrite_note(&[dir("sub"), dir("d"), sym("d", "sub")]);
}

#[test]
fn symlink_over_implicit_directory_is_an_overwrite_note() {
    assert_overwrite_note(&[dir("sub"), file("d/f"), sym("d", "sub")]);
}

#[test]
fn entry_below_dangling_symlink_is_a_security_finding() {
    let outcome =
        assert_link_placement_is_a_security_finding(&[sym("d", "sub"), file("d/f"), dir("sub")]);
    assert!(outcome.extracted.is_err());
}

#[test]
fn hardlink_below_dangling_symlink_is_a_security_finding() {
    let outcome = assert_link_placement_is_a_security_finding(&[
        sym("d", "sub"),
        file("t"),
        hard("d/h", "t"),
    ]);
    assert!(outcome.extracted.is_err());
}

#[test]
fn directory_over_earlier_file_stays_a_structural_issue() {
    let outcome = run_verify_and_extract(&[file("a"), dir("a")], |_| {});
    assert_eq!(outcome.status, VerificationStatus::Fail);
    assert!(
        !outcome.categories.contains(&IssueCategory::SecurityPolicy),
        "{:?}",
        outcome.categories
    );
}

#[test]
fn hardlink_target_through_symlink_leaving_root_fails() {
    let cats = assert_verify_agrees_with_extract(&[
        dir("e"),
        sym("a/b/c/d", "../../../e"),
        hard("h", "a/b/c/d/../../secret.txt"),
    ]);
    assert!(cats.contains(&IssueCategory::HardlinkEscape), "{cats:?}");
}

#[test]
fn symlink_target_through_symlink_leaving_root_fails() {
    let cats = assert_verify_agrees_with_extract(&[
        dir("e"),
        sym("a/b/c/d", "../../../e"),
        sym("s", "a/b/c/d/../../x"),
    ]);
    assert!(cats.contains(&IssueCategory::SymlinkEscape), "{cats:?}");
}

#[test]
fn symlink_target_through_dangling_symlink_fails() {
    let cats = assert_verify_agrees_with_extract(&[sym("a", "b"), sym("c", "a/x")]);
    assert!(cats.contains(&IssueCategory::SymlinkEscape), "{cats:?}");
}

#[test]
fn file_entry_does_not_replace_earlier_symlink() {
    let cats = assert_verify_agrees_with_extract(&[sym("y", "."), file("y"), sym("d", "y/..")]);
    assert!(cats.contains(&IssueCategory::SymlinkEscape), "{cats:?}");
}

#[test]
fn symlink_over_earlier_file_is_checked_as_replacement() {
    let tmp = TempDir::new().expect("tempdir");
    let archive = tmp.path().join("a.tar");
    let items = [file("y"), sym("y", "."), sym("d", "y/..")];
    std::fs::write(&archive, build_tar(&items)).expect("write archive");
    let report = verify_archive(&archive, &link_config()).expect("verify report");
    assert_eq!(report.status(), VerificationStatus::Fail);
    assert!(
        report
            .issues()
            .iter()
            .any(|i| i.category == IssueCategory::SymlinkEscape)
    );
}

#[test]
fn symlink_over_file_then_link_through_it_fails() {
    let outcome = run_verify_and_extract(
        &[file("a/x"), sym("c", "a/x"), sym("a/x", "a"), sym("c", "a")],
        |_| {},
    );
    // Default extraction skips the replacing links; overwriting would replace
    // the file, so verify reports it.
    assert!(outcome.extracted.is_ok());
    assert_eq!(outcome.status, VerificationStatus::Fail);
    assert!(outcome.categories.contains(&IssueCategory::SecurityPolicy));
}

#[test]
fn duplicate_symlink_with_the_same_target_is_not_noted() {
    for items in [
        [file("f"), sym("s", "f"), sym("s", "f")],
        [file("f"), sym("s", "missing"), sym("s", "missing")],
    ] {
        let cats = assert_verify_agrees_with_extract(&items);
        assert!(cats.is_empty(), "{items:?}: {cats:?}");
    }
}

#[test]
fn duplicate_symlink_with_another_target_is_skipped_and_noted() {
    let cats = assert_verify_agrees_with_extract(&[file("f"), sym("s", "f"), sym("s", "g")]);
    assert_eq!(cats, [IssueCategory::InvalidArchive]);
}

#[test]
fn entry_under_file_fails() {
    let cats = assert_verify_agrees_with_extract(&[file("x"), file("x/y")]);
    assert!(!cats.is_empty());
}

#[test]
fn hardlink_to_directory_fails() {
    let cats = assert_verify_agrees_with_extract(&[dir("dd"), hard("h", "dd")]);
    assert!(!cats.is_empty());
}

#[test]
fn symlink_cycle_fails() {
    let cats = assert_verify_agrees_with_extract(&[sym("a", "b"), sym("b", "a")]);
    assert!(cats.contains(&IssueCategory::SymlinkEscape), "{cats:?}");
}

#[test]
fn in_root_symlink_chain_is_accepted() {
    let cats = assert_verify_agrees_with_extract(&[
        dir("real"),
        sym("a", "real"),
        sym("b", "a"),
        file("b/f"),
        hard("h", "b/f"),
    ]);
    assert!(cats.is_empty(), "{cats:?}");
}

#[test]
fn hardlink_parent_symlink_created_earlier_is_accepted() {
    let cats = assert_verify_agrees_with_extract(&[
        dir("real"),
        sym("alias", "real"),
        file("real/t"),
        hard("alias/h", "real/t"),
    ]);
    assert!(cats.is_empty(), "{cats:?}");
}

#[test]
fn hardlink_to_symlinked_file_is_accepted() {
    let cats = assert_verify_agrees_with_extract(&[
        file("real.txt"),
        sym("s", "real.txt"),
        hard("h", "s"),
    ]);
    assert!(cats.is_empty(), "{cats:?}");
}

// GHSA-9mc4-rqmq-h467 / CVE-2026-11940: a hardlink whose target is a relative
// symlink stored deeper than the hardlink must resolve that symlink against
// its own directory, not the hardlink's.
#[test]
fn hardlink_to_deeper_symlink_leaving_root_is_rejected_at_the_symlink() {
    let outcome = run_verify_and_extract(
        &[
            dir("d"),
            dir("d/e"),
            sym("d/e/s", "../../../SECRET"),
            hard("h", "d/e/s"),
        ],
        |base| {
            std::fs::create_dir_all(base.join("x")).expect("x");
            std::fs::write(base.join("x/SECRET"), b"secret").expect("plant");
        },
    );

    let error = outcome.extracted.as_ref().expect_err("extract must fail");
    assert!(error.is_security_violation(), "{error:?}");
    assert_eq!(outcome.status, VerificationStatus::Fail);
    assert!(
        outcome.categories.contains(&IssueCategory::SymlinkEscape),
        "{:?}",
        outcome.categories
    );
    assert!(!outcome.dest().join("h").exists());
    let secret = outcome.base.path().join("x/SECRET");
    assert_eq!(std::fs::read(secret).expect("secret"), b"secret");
}

// `../../SECRET` stays inside from `d/e` (`<dest>/SECRET`) but leaves the root
// when resolved from the hardlink's directory, so only a resolver that starts
// from the symlink's own directory accepts it and links the inside file.
#[test]
fn hardlink_to_deeper_symlink_resolves_from_the_symlink_directory() {
    let outcome = run_verify_and_extract(
        &[
            file("SECRET"),
            dir("d"),
            dir("d/e"),
            sym("d/e/s", "../../SECRET"),
            hard("h", "d/e/s"),
        ],
        |base| std::fs::write(base.join("SECRET"), b"outside").expect("plant"),
    );

    outcome.extracted.as_ref().expect("extract must succeed");
    assert_eq!(outcome.status, VerificationStatus::Pass);
    let link = outcome.dest().join("h");
    assert!(
        std::fs::symlink_metadata(&link)
            .expect("h exists")
            .file_type()
            .is_file()
    );
    assert_eq!(std::fs::read(&link).expect("read h"), b"data");
    let outside = outcome.base.path().join("SECRET");
    assert_eq!(std::fs::read(outside).expect("outside"), b"outside");
}

#[test]
fn hardlink_to_deeper_symlink_staying_inside_is_an_independent_file() {
    use std::os::unix::fs::MetadataExt;

    let outcome = run_verify_and_extract(
        &[
            dir("d"),
            dir("d/e"),
            file("d/real.txt"),
            sym("d/e/s", "../real.txt"),
            hard("h", "d/e/s"),
        ],
        |_| {},
    );

    outcome.extracted.as_ref().expect("extract must succeed");
    assert_eq!(outcome.status, VerificationStatus::Pass);
    assert!(outcome.categories.is_empty(), "{:?}", outcome.categories);
    let link = outcome.dest().join("h");
    let meta = std::fs::symlink_metadata(&link).expect("h exists");
    assert!(meta.file_type().is_file(), "h must not be a symlink");
    assert_eq!(std::fs::read(&link).expect("read h"), b"data");
    let real = std::fs::metadata(outcome.dest().join("d/real.txt")).expect("real");
    assert_ne!(meta.ino(), real.ino());
}

#[test]
fn dangling_hardlink_target_fails() {
    let cats = assert_verify_agrees_with_extract(&[hard("h", "missing.txt")]);
    assert!(cats.contains(&IssueCategory::InvalidArchive), "{cats:?}");
}

#[test]
fn hardlink_target_appearing_later_is_accepted() {
    let cats = assert_verify_agrees_with_extract(&[hard("h", "later.txt"), file("later.txt")]);
    assert!(cats.is_empty(), "{cats:?}");
}

#[test]
fn disallowed_hardlink_is_reported_once() {
    let tmp = TempDir::new().expect("tempdir");
    let archive = tmp.path().join("a.tar");
    std::fs::write(&archive, build_tar(&[file("t"), hard("h", "t")])).expect("write");
    let report = verify_archive(&archive, &SecurityConfig::default()).expect("report");
    assert_eq!(report.status(), VerificationStatus::Fail);
    assert_eq!(
        report
            .issues()
            .iter()
            .filter(|i| i.category == IssueCategory::SecurityPolicy)
            .count(),
        1
    );
}

// Hardlinks are appended after the other entries; they name only files or a
// missing target.
const NAMES: [&str; 4] = ["a", "b", "c", "d"];
const SYM_TARGETS: [&str; 8] = ["a", "b", "c", "d", ".", "a/x", "../a", "d/."];

fn plain_items() -> impl Strategy<Value = Vec<Item>> {
    let kind = (0..3usize, 0..SYM_TARGETS.len());
    proptest::collection::vec(kind, 0..=4).prop_map(|kinds| {
        kinds
            .into_iter()
            .zip(NAMES)
            .map(|((kind, target), name)| match kind {
                0 => Item::Dir(name.into()),
                1 => Item::File(name.into()),
                _ => Item::Sym(name.into(), SYM_TARGETS[target].into()),
            })
            .collect()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn verify_agrees_with_extract_on_small_link_graphs(
        mut items in plain_items(),
        hard_targets in proptest::collection::vec(0..5usize, 0..=2),
    ) {
        let files: Vec<String> = items
            .iter()
            .filter_map(|i| match i {
                Item::File(p) => Some(p.clone()),
                _ => None,
            })
            .collect();
        for (n, pick) in hard_targets.into_iter().enumerate() {
            let target = files.get(pick).map_or("ghost", String::as_str);
            items.push(Item::Hard(format!("h{n}"), target.into()));
        }
        assert_verify_agrees_with_extract(&items);
    }
}

const WIDE_PATHS: [&str; 5] = ["a", "b", "c", "a/x", "b/x"];
const WIDE_TARGETS: [&str; 13] = [
    "a", "b", "c", ".", "a/x", "a/..", "b/..", "c/..", "a/../b", "a/x/..", "b/x/..", "../a", "b/.",
];

fn wide_items() -> impl Strategy<Value = Vec<Item>> {
    let entry = (0..3usize, 0..WIDE_PATHS.len(), 0..WIDE_TARGETS.len());
    proptest::collection::vec(entry, 1..=6).prop_map(|entries| {
        entries
            .into_iter()
            .map(|(kind, path, target)| match kind {
                0 => Item::Dir(WIDE_PATHS[path].into()),
                1 => Item::File(WIDE_PATHS[path].into()),
                _ => Item::Sym(WIDE_PATHS[path].into(), WIDE_TARGETS[target].into()),
            })
            .collect()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    // Names repeat and targets traverse `name/..` and symlinked parents. Only
    // the unsafe direction is asserted: verify must not PASS an archive whose
    // extraction fails with a security error. The reverse direction is
    // allowed to differ because a host `realpath` may tolerate `file/..`
    // (macOS) where the model reports ENOTDIR.
    #[test]
    fn verify_never_passes_what_extract_rejects_as_unsafe(items in wide_items()) {
        let tmp = TempDir::new().expect("tempdir");
        let archive = tmp.path().join("a.tar");
        std::fs::write(&archive, build_tar(&items)).expect("write archive");
        let dest = TempDir::new().expect("dest");
        let config = link_config();

        let report = verify_archive(&archive, &config).expect("verify report");
        if let Err(e) = extract_archive(&archive, dest.path(), &config)
            && e.is_security_violation()
        {
            prop_assert_ne!(
                report.status(),
                VerificationStatus::Pass,
                "extract rejected {:?} with {:?} but verify passed",
                items,
                e
            );
        }
    }
}
