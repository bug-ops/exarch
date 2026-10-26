//! A 7z entry whose Unix mode (`S_IFLNK`) marks it as a symlink is read and
//! validated through the symlink policy: `list` reports the target on request,
//! `verify` validates it under an integrity check, and `extract` validates it
//! as it creates the link, only under `allow_symlinks`.
//!
//! Entries are handed to the extractor in archive order, as for TAR, so a
//! directory entry of the archive exists when a later link is validated.

#![allow(clippy::unwrap_used)]
#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use std::assert_matches;
use std::io::Cursor;
use std::path::Path;
use std::path::PathBuf;

use common::flip_first;
use exarch_core::ArchiveError;
use exarch_core::ArchiveManifest;
use exarch_core::CheckStatus;
use exarch_core::DecompressionBudget;
#[cfg(unix)]
use exarch_core::ExtractionOptions;
use exarch_core::IntegrityCheck;
use exarch_core::IntegrityStatus;
use exarch_core::IssueCategory;
use exarch_core::LinkTarget;
use exarch_core::ListOptions;
use exarch_core::ManifestEntryKind;
use exarch_core::SecurityConfig;
use exarch_core::StoredTargets;
use exarch_core::VerificationOptions;
use exarch_core::VerificationReport;
use exarch_core::VerificationStatus;
use exarch_core::extract_archive;
#[cfg(unix)]
use exarch_core::extract_archive_with_options;
use exarch_core::list_archive;
use exarch_core::list_archive_with_options;
use exarch_core::verify_archive;
use exarch_core::verify_archive_with_options;
use sevenz_rust2::Archive;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use sevenz_rust2::EncoderConfiguration;
use sevenz_rust2::EncoderMethod;
use sevenz_rust2::Password;
use sevenz_rust2::SourceReader;
use tempfile::TempDir;

mod common;

const UNIX_EXTENSION: u32 = 0x8000;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;
const S_IFLNK: u32 = 0o12_0000;
const S_IFREG: u32 = 0o10_0000;

#[derive(Clone, Copy)]
enum Item<'a> {
    File(&'a str, &'a [u8]),
    Dir(&'a str),
    Link(&'a str, &'a [u8]),
    LinkDir(&'a str),
}

impl Item<'_> {
    fn entry(self) -> (ArchiveEntry, &'static [u8]) {
        let unix = |mode: u32| UNIX_EXTENSION | (mode << 16);
        let streamed = |name: &str, data: &[u8], attributes: u32| {
            let mut entry = ArchiveEntry::new_file(name);
            entry.has_stream = !data.is_empty();
            entry.size = data.len() as u64;
            entry.has_windows_attributes = true;
            entry.windows_attributes = attributes;
            entry
        };
        match self {
            Item::File(name, data) => (
                streamed(name, data, unix(S_IFREG | 0o644)),
                Box::leak(data.to_vec().into_boxed_slice()),
            ),
            Item::Link(name, target) => (
                streamed(name, target, unix(S_IFLNK | 0o777)),
                Box::leak(target.to_vec().into_boxed_slice()),
            ),
            Item::Dir(name) => (ArchiveEntry::new_directory(name), &[]),
            Item::LinkDir(name) => {
                let mut entry = ArchiveEntry::new_directory(name);
                entry.has_windows_attributes = true;
                entry.windows_attributes = FILE_ATTRIBUTE_DIRECTORY | unix(S_IFLNK | 0o777);
                (entry, &[])
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Layout {
    OneBlockEach,
    Solid,
    /// One solid block of the middle entries; a stream-less entry at either
    /// end is pushed on its own, so the writer does not count it as a
    /// sub-stream of the block.
    SolidAroundDirs,
}

fn build(items: &[Item<'_>], layout: Layout, stored: bool) -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    if stored {
        writer.set_content_methods(vec![EncoderConfiguration::new(EncoderMethod::COPY)]);
    }
    let pairs: Vec<_> = items.iter().map(|item| item.entry()).collect();
    match layout {
        Layout::OneBlockEach => {
            for (entry, data) in pairs {
                let reader = entry.has_stream.then(|| Cursor::new(data.to_vec()));
                writer.push_archive_entry(entry, reader).unwrap();
            }
        }
        Layout::Solid => {
            let (entries, readers): (Vec<_>, Vec<_>) = pairs
                .into_iter()
                .map(|(entry, data)| (entry, SourceReader::from(Cursor::new(data))))
                .unzip();
            writer.push_archive_entries(entries, readers).unwrap();
        }
        Layout::SolidAroundDirs => {
            let mut leading = pairs;
            let trailing = leading.split_off(
                leading.len()
                    - leading
                        .iter()
                        .rev()
                        .take_while(|(entry, _)| !entry.has_stream)
                        .count(),
            );
            let leading_len = leading
                .iter()
                .take_while(|(entry, _)| !entry.has_stream)
                .count();
            let middle = leading.split_off(leading_len);
            for (entry, _) in leading {
                writer
                    .push_archive_entry(entry, None::<Cursor<Vec<u8>>>)
                    .unwrap();
            }
            let (entries, readers): (Vec<_>, Vec<_>) = middle
                .into_iter()
                .map(|(entry, data)| (entry, SourceReader::from(Cursor::new(data))))
                .unzip();
            if !entries.is_empty() {
                writer.push_archive_entries(entries, readers).unwrap();
            }
            for (entry, _) in trailing {
                writer
                    .push_archive_entry(entry, None::<Cursor<Vec<u8>>>)
                    .unwrap();
            }
        }
    }
    writer.finish().unwrap().into_inner()
}

fn archive_of(dir: &TempDir, items: &[Item<'_>]) -> PathBuf {
    let path = dir.path().join("links.7z");
    std::fs::write(&path, build(items, Layout::OneBlockEach, false)).unwrap();
    path
}

fn stored_archive_of(dir: &TempDir, items: &[Item<'_>]) -> PathBuf {
    let path = dir.path().join("stored.7z");
    std::fs::write(&path, build(items, Layout::OneBlockEach, true)).unwrap();
    path
}

fn allow_symlinks() -> SecurityConfig {
    SecurityConfig::default().with_allow_symlinks(true)
}

fn dir_is_empty(dir: &TempDir) -> bool {
    std::fs::read_dir(dir.path()).unwrap().count() == 0
}

fn link_target(path: &Path, config: &SecurityConfig) -> LinkTarget {
    let options = ListOptions::default().with_stored_targets(StoredTargets::Read);
    first_link_target(&list_archive_with_options(path, config, &options).unwrap())
}

fn default_link_target(path: &Path, config: &SecurityConfig) -> LinkTarget {
    first_link_target(&list_archive(path, config).unwrap())
}

fn first_link_target(manifest: &ArchiveManifest) -> LinkTarget {
    manifest
        .entries()
        .iter()
        .find_map(|entry| match &entry.kind {
            ManifestEntryKind::Symlink { target } => Some(target.clone()),
            _ => None,
        })
        .unwrap()
}

/// A destination one level below a fresh directory, so a write that escapes
/// it by one level shows up in the container.
fn nested_dest() -> (TempDir, PathBuf) {
    let container = TempDir::new().unwrap();
    let out = container.path().join("out");
    std::fs::create_dir(&out).unwrap();
    (container, out)
}

fn assert_nothing_outside(container: &TempDir, label: &str) {
    let mut names: Vec<_> = std::fs::read_dir(container.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    names.sort();
    assert_eq!(names, ["out"], "{label}: nothing may be written outside");
}

fn partial_source(err: ArchiveError) -> ArchiveError {
    match err {
        ArchiveError::PartialExtraction { source, .. } => *source,
        other => panic!("expected PartialExtraction, got {other:?}"),
    }
}

fn issue_categories(report: &VerificationReport) -> Vec<IssueCategory> {
    report.issues().iter().map(|i| i.category).collect()
}

fn integrity(budget: u64) -> VerificationOptions {
    VerificationOptions::default().with_integrity(IntegrityCheck::DecodeToEof(
        DecompressionBudget::try_from_bytes(budget).unwrap(),
    ))
}

#[test]
fn list_reports_the_stored_target_whatever_the_policy() {
    let dir = TempDir::new().unwrap();
    let path = archive_of(
        &dir,
        &[Item::File("a.txt", b"hi"), Item::Link("l", b"a.txt")],
    );

    for config in [SecurityConfig::default(), allow_symlinks()] {
        assert_eq!(
            link_target(&path, &config),
            LinkTarget::Recorded(PathBuf::from("a.txt"))
        );
        assert_eq!(default_link_target(&path, &config), LinkTarget::Unread);
    }
}

#[test]
fn list_skips_targets_on_request() {
    let dir = TempDir::new().unwrap();
    let path = archive_of(&dir, &[Item::Link("l", b"a.txt")]);
    let options = ListOptions::default().with_stored_targets(StoredTargets::Skip);

    let manifest = list_archive_with_options(&path, &SecurityConfig::default(), &options).unwrap();

    assert_matches!(
        &manifest.entries()[0].kind,
        ManifestEntryKind::Symlink {
            target: LinkTarget::Unread
        }
    );
}

#[test]
fn list_rejects_empty_and_oversized_targets_like_zip() {
    let dir = TempDir::new().unwrap();
    let oversized = vec![b'a'; 70_000];
    for (item, expect) in [
        (Item::LinkDir("l"), "symlink target is empty"),
        (Item::Link("l", &oversized), "symlink target too large"),
    ] {
        let path = archive_of(&dir, &[item]);
        assert_matches!(
            list_archive(&path, &SecurityConfig::default()),
            Err(ArchiveError::SecurityViolation { reason }) if reason.contains(expect)
        );
    }
}

#[cfg(unix)]
#[test]
fn list_marks_a_target_with_a_corrupt_checksum_unreadable() {
    let dir = TempDir::new().unwrap();
    let mut bytes = build(
        &[Item::Link("l", b"TARGETTARGET")],
        Layout::OneBlockEach,
        true,
    );
    flip_first(&mut bytes, b"TARGETTARGET");
    let path = dir.path().join("corrupt.7z");
    std::fs::write(&path, bytes).unwrap();

    assert_eq!(
        link_target(&path, &SecurityConfig::default()),
        LinkTarget::Unreadable
    );
    assert_matches!(
        extract_archive(&path, TempDir::new().unwrap().path(), &allow_symlinks()),
        Err(ArchiveError::InvalidArchive(reason)) if reason.contains("failed to read 7z symlink target")
    );
}

#[test]
fn verify_fails_a_link_when_symlinks_are_not_allowed() {
    let dir = TempDir::new().unwrap();
    let path = archive_of(&dir, &[Item::Link("link", b"a.txt")]);

    let report = verify_archive(&path, &SecurityConfig::default()).unwrap();

    assert_eq!(report.status(), VerificationStatus::Fail);
    assert!(
        report.issues().iter().any(|i| {
            i.category == IssueCategory::SecurityPolicy
                && i.entry_path.as_deref() == Some(Path::new("link"))
                && i.message.contains("symlinks not allowed")
        }),
        "{:?}",
        report.issues()
    );
}

#[test]
fn verify_validates_the_target_when_symlinks_are_allowed() {
    let dir = TempDir::new().unwrap();
    let inside = archive_of(
        &dir,
        &[Item::File("a.txt", b"hi"), Item::Link("link", b"a.txt")],
    );
    let report =
        verify_archive_with_options(&inside, &allow_symlinks(), &integrity(1 << 20)).unwrap();
    assert_eq!(
        report.status(),
        VerificationStatus::Pass,
        "{:?}",
        report.issues()
    );

    for target in [&b"/etc/passwd"[..], b"../x", b"a/../../x"] {
        let path = archive_of(&dir, &[Item::Link("link", target)]);
        let report =
            verify_archive_with_options(&path, &allow_symlinks(), &integrity(1 << 20)).unwrap();
        assert_eq!(report.status(), VerificationStatus::Fail, "{target:?}");
        assert!(
            issue_categories(&report).contains(&IssueCategory::SymlinkEscape),
            "{target:?}: {:?}",
            report.issues()
        );
    }
}

#[test]
fn verify_without_integrity_warns_that_targets_were_not_validated() {
    let dir = TempDir::new().unwrap();
    for target in [&b"a.txt"[..], b"../../x"] {
        let path = archive_of(
            &dir,
            &[Item::File("a.txt", b"hi"), Item::Link("link", target)],
        );

        let report = verify_archive(&path, &allow_symlinks()).unwrap();

        assert_eq!(report.status(), VerificationStatus::Warning, "{target:?}");
        assert_eq!(
            issue_categories(&report),
            [IssueCategory::SecurityPolicy],
            "{:?}",
            report.issues()
        );
        let issue = &report.issues()[0];
        assert_eq!(issue.entry_path, None);
        assert!(
            issue.message.contains("1 symlink target was not read"),
            "{}",
            issue.message
        );
    }
}

#[test]
fn verify_without_integrity_still_fails_entries_beneath_an_unread_link() {
    let dir = TempDir::new().unwrap();
    let cases: [(&str, Vec<Item<'_>>); 2] = [
        (
            "beneath",
            vec![Item::Link("d", b"sub"), Item::File("d/f", b"x")],
        ),
        (
            "name fold",
            vec![Item::File("x", b"x"), Item::Link("X", b"sub")],
        ),
    ];
    for (label, items) in cases {
        let path = archive_of(&dir, &items);

        let report = verify_archive(&path, &allow_symlinks()).unwrap();

        let fails = report.status() == VerificationStatus::Fail;
        // `X` collides with `x` only where the host folds case.
        let expected =
            label != "name fold" || cfg!(any(target_os = "macos", target_os = "windows"));
        assert_eq!(fails, expected, "{label}: {:?}", report.issues());
    }
}

#[test]
fn verify_fails_a_target_that_runs_through_a_link_the_budget_left_unread() {
    let filler = vec![b'f'; 20_000];
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    writer.set_content_methods(vec![EncoderConfiguration::new(EncoderMethod::COPY)]);
    let (filler_entry, _) = Item::File("filler", &filler).entry();
    let (d_entry, d_data) = Item::Link("d", b"sub").entry();
    writer
        .push_archive_entries(
            vec![filler_entry, d_entry],
            vec![
                SourceReader::from(Cursor::new(filler)),
                SourceReader::from(Cursor::new(d_data.to_vec())),
            ],
        )
        .unwrap();
    let (l2_entry, l2_data) = Item::Link("l2", b"d/x").entry();
    writer
        .push_archive_entry(l2_entry, Some(Cursor::new(l2_data.to_vec())))
        .unwrap();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("two-blocks.7z");
    std::fs::write(&path, writer.finish().unwrap().into_inner()).unwrap();

    let report = verify_archive_with_options(&path, &solid_config(), &integrity(10_000)).unwrap();

    assert_eq!(report.status(), VerificationStatus::Fail);
    assert!(
        issue_categories(&report).contains(&IssueCategory::SymlinkEscape),
        "{:?}",
        report.issues()
    );
}

#[test]
fn verify_integrity_checks_the_link_in_the_same_decode() {
    let dir = TempDir::new().unwrap();
    let clean = archive_of(
        &dir,
        &[Item::File("a.txt", b"hi"), Item::Link("link", b"a.txt")],
    );
    let report =
        verify_archive_with_options(&clean, &allow_symlinks(), &integrity(1 << 20)).unwrap();
    assert_eq!(report.integrity_status(), IntegrityStatus::Pass);
    assert_eq!(
        report.status(),
        VerificationStatus::Pass,
        "{:?}",
        report.issues()
    );

    let mut bytes = build(
        &[Item::Link("link", b"TARGETTARGET")],
        Layout::OneBlockEach,
        true,
    );
    flip_first(&mut bytes, b"TARGETTARGET");
    let corrupt = dir.path().join("corrupt.7z");
    std::fs::write(&corrupt, bytes).unwrap();
    let report =
        verify_archive_with_options(&corrupt, &allow_symlinks(), &integrity(1 << 20)).unwrap();
    assert_eq!(report.integrity_status(), IntegrityStatus::Fail);
    assert!(issue_categories(&report).contains(&IssueCategory::CorruptData));
    assert!(
        report.issues().iter().all(|i| !i.message.contains("empty")),
        "{:?}",
        report.issues()
    );
    assert!(
        report
            .issues()
            .iter()
            .any(|i| i.message.contains("could not be read")),
        "{:?}",
        report.issues()
    );
}

#[test]
fn verify_integrity_leaves_a_link_unread_when_the_budget_cannot_decode_it() {
    let dir = TempDir::new().unwrap();
    let path = archive_of(&dir, &[Item::Link("link", b"a.txt")]);

    let report = verify_archive_with_options(&path, &allow_symlinks(), &integrity(1)).unwrap();

    assert_eq!(report.status(), VerificationStatus::Warning);
    assert_eq!(report.integrity_status(), IntegrityStatus::Incomplete);
    assert!(
        report
            .issues()
            .iter()
            .any(|i| i.message.contains("1 symlink target was not read")),
        "{:?}",
        report.issues()
    );
}

#[test]
fn verify_integrity_marks_the_links_of_a_refused_solid_block_unreadable() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("solid.7z");
    std::fs::write(
        &path,
        build(
            &[Item::File("a.txt", b"hi"), Item::Link("l", b"a.txt")],
            Layout::Solid,
            false,
        ),
    )
    .unwrap();

    let report =
        verify_archive_with_options(&path, &allow_symlinks(), &integrity(1 << 20)).unwrap();

    assert_eq!(report.status(), VerificationStatus::Fail);
    assert!(
        report
            .issues()
            .iter()
            .any(|i| i.message.contains("could not be read")),
        "{:?}",
        report.issues()
    );
    assert!(
        report
            .issues()
            .iter()
            .all(|i| !i.message.contains("symlink target was not read")),
        "{:?}",
        report.issues()
    );
}

#[test]
fn extract_refuses_a_link_unless_symlinks_are_allowed() {
    let dir = TempDir::new().unwrap();
    let path = archive_of(
        &dir,
        &[Item::File("a.txt", b"hi"), Item::Link("l", b"a.txt")],
    );
    let out = TempDir::new().unwrap();

    assert_matches!(
        extract_archive(&path, out.path(), &SecurityConfig::default()),
        Err(ArchiveError::SecurityViolation { reason }) if reason.contains("symlinks not allowed")
    );
    assert!(dir_is_empty(&out));
}

#[cfg(unix)]
#[test]
fn extract_creates_the_link_under_allow_symlinks() {
    let dir = TempDir::new().unwrap();
    let path = archive_of(
        &dir,
        &[
            Item::File("a.txt", b"hi"),
            Item::Link("l", b"a.txt"),
            Item::Link("sub/l2", b"../a.txt"),
            Item::Link("a/b/l3", b"../../a.txt"),
        ],
    );
    let out = TempDir::new().unwrap();

    let report = extract_archive(&path, out.path(), &allow_symlinks()).unwrap();

    assert_eq!(report.symlinks_created, 3);
    assert_eq!(
        std::fs::read_link(out.path().join("l")).unwrap(),
        Path::new("a.txt")
    );
    for linked in ["sub/l2", "a/b/l3"] {
        assert_eq!(
            std::fs::read_to_string(out.path().join(linked)).unwrap(),
            "hi"
        );
    }
}

#[cfg(unix)]
#[test]
fn extract_refuses_an_escaping_target() {
    let cases: [(&str, Vec<Item<'_>>); 5] = [
        ("absolute", vec![Item::Link("l", b"/etc/passwd")]),
        ("parent", vec![Item::Link("l", b"../../x")]),
        (
            "chain",
            vec![
                Item::Dir("sub"),
                Item::Link("l1", b"sub"),
                Item::Link("l2", b"l1/../../x"),
            ],
        ),
        (
            "write through",
            vec![Item::Link("d", b".."), Item::File("d/f", b"payload")],
        ),
        ("dot dot", vec![Item::Link("l", b"..")]),
    ];
    for (label, items) in cases {
        let dir = TempDir::new().unwrap();
        let mut all = vec![Item::File("a.txt", b"hi")];
        all.extend(items);
        let path = archive_of(&dir, &all);
        let (container, out) = nested_dest();

        let err = extract_archive(&path, &out, &allow_symlinks()).unwrap_err();

        assert_matches!(
            partial_source(err),
            ArchiveError::SymlinkEscape { .. },
            "{label}"
        );
        assert!(out.join("a.txt").exists(), "{label}");
        assert_nothing_outside(&container, label);
    }
}

#[cfg(unix)]
#[test]
fn extract_refuses_a_destination_symlink_in_the_parent_chain_or_a_target_hop() {
    use std::os::unix::fs::symlink;

    for items in [
        vec![Item::Link("hop/l", b"x")],
        vec![Item::Link("l", b"hop/x")],
    ] {
        let dir = TempDir::new().unwrap();
        let path = archive_of(&dir, &items);
        let outside = TempDir::new().unwrap();
        let out = TempDir::new().unwrap();
        symlink(outside.path(), out.path().join("hop")).unwrap();

        let err = extract_archive(&path, out.path(), &allow_symlinks()).unwrap_err();

        assert_matches!(
            err,
            ArchiveError::SymlinkEscape { .. } | ArchiveError::PathTraversal { .. }
        );
        assert!(dir_is_empty(&outside));
    }
}

#[cfg(unix)]
#[test]
fn existing_destination_symlink_is_not_replaced() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new().unwrap();
    let path = archive_of(&dir, &[Item::Link("a", b"x/.."), Item::Link("x", b".")]);

    for skip_duplicates in [true, false] {
        let out = TempDir::new().unwrap();
        std::fs::create_dir_all(out.path().join("p/q")).unwrap();
        symlink("p/q", out.path().join("x")).unwrap();
        let options = ExtractionOptions::default().with_skip_duplicates(skip_duplicates);
        let result = extract_archive_with_options(&path, out.path(), &allow_symlinks(), &options);

        if skip_duplicates {
            result.unwrap();
        } else {
            assert_symlink_refused(result.unwrap_err());
        }
        assert_eq!(
            std::fs::read_link(out.path().join("x")).unwrap(),
            Path::new("p/q"),
            "skip_duplicates={skip_duplicates}"
        );
        // `a -> x/..` resolves to `p` and is created before `x` is reached.
        assert_eq!(
            std::fs::canonicalize(out.path().join("a")).unwrap(),
            std::fs::canonicalize(out.path().join("p")).unwrap()
        );
    }
}

#[cfg(unix)]
fn assert_symlink_refused(error: ArchiveError) {
    let error = match error {
        ArchiveError::PartialExtraction { source, .. } => *source,
        other => other,
    };
    let ArchiveError::Io(io) = &error else {
        panic!("expected Io, got {error:?}");
    };
    assert_eq!(
        io.kind(),
        std::io::Error::from_raw_os_error(libc::ELOOP).kind()
    );
    assert!(
        io.to_string()
            .contains("refusing to replace the existing symlink"),
        "{io}"
    );
}

#[cfg(unix)]
#[test]
fn dangling_link_at_the_link_path_is_skipped_or_refused_by_policy() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new().unwrap();
    let path = archive_of(&dir, &[Item::Link("l", b"other")]);

    for skip_duplicates in [true, false] {
        let out = TempDir::new().unwrap();
        symlink("gone", out.path().join("l")).unwrap();
        let options = ExtractionOptions::default().with_skip_duplicates(skip_duplicates);

        let result = extract_archive_with_options(&path, out.path(), &allow_symlinks(), &options);

        if skip_duplicates {
            result.unwrap();
        } else {
            assert_symlink_refused(result.unwrap_err());
        }
        assert_eq!(
            std::fs::read_link(out.path().join("l")).unwrap(),
            Path::new("gone")
        );
    }
}

#[cfg(unix)]
#[test]
fn extract_rejects_an_oversized_non_utf8_or_empty_target() {
    let oversized = vec![b'a'; 70_000];
    let cases: [(Item<'_>, &str); 3] = [
        (Item::Link("l", &oversized), "symlink target too large"),
        (Item::Link("l", &[0xFF, 0xFE]), "not valid UTF-8"),
        (Item::LinkDir("l"), "symlink target is empty"),
    ];
    for (item, expect) in cases {
        let dir = TempDir::new().unwrap();
        let path = stored_archive_of(&dir, &[Item::File("a.txt", b"hi"), item]);
        let out = TempDir::new().unwrap();

        let err = extract_archive(&path, out.path(), &allow_symlinks()).unwrap_err();

        let header_refusal = !matches!(err, ArchiveError::PartialExtraction { .. });
        let err = if header_refusal {
            err
        } else {
            partial_source(err)
        };
        assert!(err.to_string().contains(expect), "{expect}: {err}");
        // Empty and oversized targets are refused from the header before any
        // write; a target that is not UTF-8 needs a decode.
        assert_eq!(header_refusal, expect != "not valid UTF-8", "{expect}");
        assert_eq!(dir_is_empty(&out), header_refusal, "{expect}");
    }
}

#[cfg(unix)]
#[test]
fn solid_block_with_a_link_follows_the_solid_policy() {
    let dir = TempDir::new().unwrap();
    let bytes = build(
        &[Item::File("a.txt", b"hi"), Item::Link("l", b"a.txt")],
        Layout::Solid,
        false,
    );
    let path = dir.path().join("solid.7z");
    std::fs::write(&path, bytes).unwrap();

    let refused = SecurityConfig::default().with_allow_symlinks(true);
    assert_eq!(link_target(&path, &refused), LinkTarget::Unreadable);
    let report = verify_archive(&path, &refused).unwrap();
    assert_eq!(report.status(), VerificationStatus::Fail);
    assert!(extract_archive(&path, TempDir::new().unwrap().path(), &refused).is_err());

    let allowed = allow_symlinks()
        .with_allow_solid_archives(true)
        .with_max_solid_block_memory(100 * 1024 * 1024);
    assert_eq!(
        link_target(&path, &allowed),
        LinkTarget::Recorded(PathBuf::from("a.txt"))
    );
    let out = TempDir::new().unwrap();
    let report = extract_archive(&path, out.path(), &allowed).unwrap();
    assert_eq!(report.symlinks_created, usize::from(cfg!(unix)));
}

#[cfg(unix)]
#[test]
fn unresolvable_parent_components_are_refused_in_both_orders() {
    let orders: [[Item<'_>; 2]; 2] = [
        [Item::Link("a", b"d/.."), Item::Link("d", b".")],
        [Item::Link("d", b"."), Item::Link("a", b"d/..")],
    ];
    for (order, items) in orders.into_iter().enumerate() {
        let dir = TempDir::new().unwrap();
        let path = archive_of(&dir, &items);
        let out = TempDir::new().unwrap();

        let err = extract_archive(&path, out.path(), &allow_symlinks()).unwrap_err();

        if order == 0 {
            assert_matches!(err, ArchiveError::SymlinkEscape { .. });
            assert!(dir_is_empty(&out));
        } else {
            assert_matches!(partial_source(err), ArchiveError::SymlinkEscape { .. });
            assert!(std::fs::symlink_metadata(out.path().join("d")).is_ok());
        }
        let report =
            verify_archive_with_options(&path, &allow_symlinks(), &integrity(1 << 20)).unwrap();
        assert_eq!(report.security_status(), CheckStatus::Fail);
    }
}

#[cfg(unix)]
#[test]
fn a_target_through_a_directory_of_the_same_archive_resolves_like_tar() {
    let dir = TempDir::new().unwrap();
    let path = archive_of(&dir, &[Item::Dir("t"), Item::Link("t2", b"t/../x")]);
    let out = TempDir::new().unwrap();

    extract_archive(&path, out.path(), &allow_symlinks()).unwrap();

    let link = std::fs::read_link(out.path().join("t2")).unwrap();
    assert_eq!(link, Path::new("t/../x"));
    assert!(!out.path().join("x").exists());
    let report =
        verify_archive_with_options(&path, &allow_symlinks(), &integrity(1 << 20)).unwrap();
    assert_eq!(report.security_status(), CheckStatus::Pass);
}

#[cfg(unix)]
#[test]
fn a_target_with_two_unresolvable_parent_components_is_refused_before_any_write() {
    let dir = TempDir::new().unwrap();
    let path = archive_of(&dir, &[Item::Link("a", b"d/e/../../f"), Item::Dir("d/e")]);
    let out = TempDir::new().unwrap();

    let err = extract_archive(&path, out.path(), &allow_symlinks()).unwrap_err();

    assert_matches!(err, ArchiveError::SymlinkEscape { .. });
    assert!(dir_is_empty(&out));
}

#[test]
fn a_link_over_the_ratio_limit_is_a_zip_bomb_before_any_write() {
    let dir = TempDir::new().unwrap();
    let target = vec![b'a'; 900];
    let path = archive_of(
        &dir,
        &[Item::File("a.txt", b"hi"), Item::Link("l", &target)],
    );
    let config = allow_symlinks().with_max_compression_ratio(2.0);
    let out = TempDir::new().unwrap();

    let err = extract_archive(&path, out.path(), &config).unwrap_err();

    assert_eq!(err.error_code(), "ZIP_BOMB", "{err}");
    assert!(dir_is_empty(&out));
}

#[test]
fn symlink_policy_is_refused_before_link_data_is_read() {
    let dir = TempDir::new().unwrap();
    let mut corrupt = build(
        &[Item::File("a.txt", b"hi"), Item::Link("l", b"TARGETTARGET")],
        Layout::OneBlockEach,
        true,
    );
    flip_first(&mut corrupt, b"TARGETTARGET");
    let corrupt_path = dir.path().join("corrupt.7z");
    std::fs::write(&corrupt_path, corrupt).unwrap();
    let oversized = vec![b'a'; 70_000];
    let oversized_path = {
        let path = dir.path().join("oversized.7z");
        std::fs::write(
            &path,
            build(
                &[Item::File("a.txt", b"hi"), Item::Link("l", &oversized)],
                Layout::OneBlockEach,
                true,
            ),
        )
        .unwrap();
        path
    };

    for path in [corrupt_path, oversized_path] {
        let out = TempDir::new().unwrap();

        assert_matches!(
            extract_archive(&path, out.path(), &SecurityConfig::default()),
            Err(ArchiveError::SecurityViolation { reason }) if reason.contains("symlinks not allowed")
        );
        assert!(dir_is_empty(&out));
    }
}

#[test]
fn links_count_against_the_entry_limit_in_list_and_verify() {
    let dir = TempDir::new().unwrap();
    let path = archive_of(&dir, &[Item::Link("l1", b"a"), Item::Link("l2", b"b")]);
    let config = allow_symlinks().with_max_file_count(1);

    assert_matches!(
        list_archive(&path, &config),
        Err(ArchiveError::QuotaExceeded { .. })
    );
    assert_matches!(
        verify_archive(&path, &config),
        Err(ArchiveError::QuotaExceeded { .. })
    );
}

fn solid_config() -> SecurityConfig {
    allow_symlinks()
        .with_allow_solid_archives(true)
        .with_max_solid_block_memory(100 * 1024 * 1024)
}

#[cfg(unix)]
#[test]
fn an_escaping_link_inside_a_solid_block_is_refused() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("solid.7z");
    std::fs::write(
        &path,
        build(
            &[
                Item::File("a.txt", b"hi"),
                Item::Link("ok", b"a.txt"),
                Item::Link("evil", b"../../x"),
            ],
            Layout::Solid,
            false,
        ),
    )
    .unwrap();
    let (container, out) = nested_dest();

    let err = extract_archive(&path, &out, &solid_config()).unwrap_err();

    assert_matches!(partial_source(err), ArchiveError::SymlinkEscape { .. });
    assert!(out.join("a.txt").exists());
    assert!(std::fs::symlink_metadata(out.join("ok")).is_ok());
    assert!(std::fs::symlink_metadata(out.join("evil")).is_err());
    assert_nothing_outside(&container, "solid escape");
}

#[cfg(unix)]
#[test]
fn a_corrupt_link_inside_a_solid_block_fails_extract() {
    let dir = TempDir::new().unwrap();
    let mut bytes = build(
        &[
            Item::File("a.txt", b"hi"),
            Item::Link("l1", b"FIRSTFIRST"),
            Item::Link("l2", b"a.txt"),
        ],
        Layout::Solid,
        true,
    );
    flip_first(&mut bytes, b"FIRSTFIRST");
    let path = dir.path().join("solid.7z");
    std::fs::write(&path, bytes).unwrap();
    let (container, out) = nested_dest();

    let err = extract_archive(&path, &out, &solid_config()).unwrap_err();

    assert_matches!(
        partial_source(err),
        ArchiveError::InvalidArchive(reason) if reason.contains("failed to read 7z symlink target")
    );
    assert!(out.join("a.txt").exists());
    assert!(std::fs::symlink_metadata(out.join("l1")).is_err());
    assert_nothing_outside(&container, "solid corrupt");
    assert_eq!(
        link_target(&path, &solid_config()),
        LinkTarget::Unreadable,
        "the corrupt link is unreadable in a listing"
    );
}

/// `symlink-snl.7z` was written by 7-Zip 26.05 with `-snl` (see
/// `tests/fixtures/generate_7z_fixtures.sh`). The link carries `S_IFLNK` in the
/// Unix extension and no Windows reparse-point bit, so it is a Unix symlink
/// for exarch and not a refused reparse point. Fixtures from p7zip on Linux and
/// from 7-Zip for Windows are tracked in #727.
#[cfg(unix)]
#[test]
fn a_link_written_by_7zip_with_snl_is_a_unix_symlink_not_a_reparse_point() {
    const REPARSE_POINT: u32 = 0x0400;
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/symlink-snl.7z");

    let archive = Archive::read(
        &mut Cursor::new(std::fs::read(&path).unwrap()),
        &Password::empty(),
    )
    .unwrap();
    let link = archive.files.iter().find(|f| f.name == "link.txt").unwrap();
    assert!(link.has_windows_attributes);
    let attributes = link.windows_attributes;
    assert_ne!(attributes & UNIX_EXTENSION, 0);
    assert_eq!((attributes >> 16) & 0o17_0000, S_IFLNK);
    assert_eq!(attributes & REPARSE_POINT, 0);

    assert_eq!(
        default_link_target(&path, &allow_symlinks()),
        LinkTarget::Unread
    );
    assert_eq!(
        link_target(&path, &allow_symlinks()),
        LinkTarget::Recorded(PathBuf::from("target.txt"))
    );
    let report =
        verify_archive_with_options(&path, &allow_symlinks(), &integrity(1 << 20)).unwrap();
    assert_eq!(report.security_status(), CheckStatus::Pass);

    let refused = TempDir::new().unwrap();
    assert_matches!(
        extract_archive(&path, refused.path(), &SecurityConfig::default()),
        Err(ArchiveError::SecurityViolation { reason }) if reason.contains("symlinks not allowed")
    );
    assert!(dir_is_empty(&refused));

    let out = TempDir::new().unwrap();
    extract_archive(&path, out.path(), &allow_symlinks()).unwrap();
    assert_eq!(
        std::fs::read_link(out.path().join("link.txt")).unwrap(),
        Path::new("target.txt")
    );
    assert_eq!(
        std::fs::read(out.path().join("target.txt")).unwrap(),
        b"snl target\n"
    );
}

/// Marks file `file` of a two-file archive stored with a plain header as
/// stream-less (a directory), leaving every block as it was.
///
/// The block of the file then keeps its stream count but no file maps to it.
/// The patch is built here from the header layout: 6 signature bytes, 2
/// version bytes, the start header CRC, then the next header's offset, size
/// and CRC.
fn mark_stream_less(bytes: &[u8], file: usize) -> Vec<u8> {
    const K_FILES_INFO: u8 = 0x05;
    const K_EMPTY_STREAM: u8 = 0x0E;
    let crc = |data: &[u8]| {
        let mut crc = flate2::Crc::new();
        crc.update(data);
        crc.sum().to_le_bytes()
    };
    let field = |at: usize| {
        usize::try_from(u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())).unwrap()
    };
    let start = 32 + field(12);
    let header = &bytes[start..start + field(20)];
    assert_eq!(start + header.len(), bytes.len());
    assert_eq!(header[0], 0x01, "the header must be stored plain");

    for at in (0..header.len() - 1).filter(|&at| header[at..at + 2] == [K_FILES_INFO, 2]) {
        let mut patched = header[..at + 2].to_vec();
        patched.extend_from_slice(&[K_EMPTY_STREAM, 1, 0x80 >> file]);
        patched.extend_from_slice(&header[at + 2..]);

        let mut out = bytes[..start].to_vec();
        out[20..28].copy_from_slice(&(patched.len() as u64).to_le_bytes());
        out[28..32].copy_from_slice(&crc(&patched));
        let start_crc = crc(&out[12..32]);
        out[8..12].copy_from_slice(&start_crc);
        out.extend_from_slice(&patched);

        let parsed = Archive::read(&mut Cursor::new(out.clone()), &Password::empty());
        if parsed.is_ok_and(|a| a.blocks.len() == 2 && !a.files[file].has_stream) {
            return out;
        }
    }
    panic!("no FilesInfo found to patch");
}

/// Two one-file blocks, one of whose files is then marked stream-less.
fn orphan_block_archive(dir: &TempDir, stream_less: usize) -> PathBuf {
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    writer.set_content_methods(vec![EncoderConfiguration::new(EncoderMethod::COPY)]);
    for (name, data) in [("a", b"AAAA"), ("b", b"BBBB")] {
        let mut entry = ArchiveEntry::new_file(name);
        entry.has_stream = true;
        entry.size = data.len() as u64;
        writer
            .push_archive_entry(entry, Some(Cursor::new(data.to_vec())))
            .unwrap();
    }
    let plain = writer.finish().unwrap().into_inner();
    let bytes = mark_stream_less(&plain, stream_less);
    let path = dir.path().join("orphan.7z");
    std::fs::write(&path, bytes).unwrap();
    path
}

/// An orphan block keeps its stream count and the first-file index 0, so it
/// would decode over the first files of the archive with its own data. It is
/// refused where the archive is admitted, by `extract` before any write and by
/// `verify`, which never decodes it, and `list` reports only what the header
/// holds.
fn assert_orphan_block_refused(path: &Path, mapping: [Option<usize>; 2]) {
    let archive = Archive::read(
        &mut Cursor::new(std::fs::read(path).unwrap()),
        &Password::empty(),
    )
    .unwrap();
    assert_eq!(archive.blocks.len(), 2);
    assert_eq!(archive.stream_map.file_block_index, mapping);

    let out = TempDir::new().unwrap();
    std::fs::write(out.path().join("a"), b"sentinel").unwrap();
    std::fs::write(out.path().join("b"), b"sentinel").unwrap();
    let err = extract_archive(path, out.path(), &SecurityConfig::default()).unwrap_err();
    assert_matches!(
        err,
        ArchiveError::InvalidArchive(reason) if reason.contains("other than the ones mapped")
    );
    for name in ["a", "b"] {
        assert_eq!(std::fs::read(out.path().join(name)).unwrap(), b"sentinel");
    }
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 2);

    let report =
        verify_archive_with_options(path, &SecurityConfig::default(), &integrity(1 << 20)).unwrap();
    assert_eq!(report.status(), VerificationStatus::Fail);
    assert_eq!(
        issue_categories(&report)
            .into_iter()
            .filter(|c| *c == IssueCategory::InvalidArchive)
            .count(),
        1,
        "{:?}",
        report.issues()
    );

    let manifest = list_archive(path, &SecurityConfig::default()).unwrap();
    assert_eq!(manifest.total_entries(), 2);
}

#[test]
fn an_orphan_trailing_block_is_refused_before_it_can_redeliver_the_first_file() {
    let dir = TempDir::new().unwrap();
    let path = orphan_block_archive(&dir, 1);

    assert_orphan_block_refused(&path, [Some(0), None]);
}

#[test]
fn a_block_whose_span_covers_a_stream_less_entry_is_refused() {
    let dir = TempDir::new().unwrap();
    let path = orphan_block_archive(&dir, 0);

    assert_orphan_block_refused(&path, [None, Some(0)]);
}

#[cfg(unix)]
fn tree_of(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let kind = entry.file_type().unwrap();
            let rel = path.strip_prefix(root).unwrap().display().to_string();
            if kind.is_symlink() {
                out.push(format!(
                    "{rel}->{}",
                    std::fs::read_link(&path).unwrap().display()
                ));
            } else if kind.is_dir() {
                out.push(format!("{rel}/"));
                stack.push(path);
            } else {
                out.push(rel);
            }
        }
    }
    out.sort();
    out
}

/// How `extract` ended: extracted, refused as invalid before any write, or
/// failed part-way.
#[cfg(unix)]
fn extract_class(path: &Path, config: &SecurityConfig, skip_duplicates: bool) -> &'static str {
    let out = TempDir::new().unwrap();
    let options = ExtractionOptions::default().with_skip_duplicates(skip_duplicates);
    match extract_archive_with_options(path, out.path(), config, &options) {
        Ok(_) => "extracted",
        Err(ArchiveError::InvalidArchive(_)) => {
            assert!(dir_is_empty(&out), "a refusal writes nothing");
            "refused"
        }
        Err(_) => "failed",
    }
}

/// How `verify --check-integrity` ended: `pass`, `fail` (a security finding)
/// or `refused`.
#[cfg(unix)]
fn verify_class(path: &Path, config: &SecurityConfig) -> &'static str {
    match verify_archive_with_options(path, config, &integrity(1 << 20)) {
        Ok(report) if report.status() == VerificationStatus::Pass => "pass",
        Ok(report) => {
            assert_ne!(report.security_status(), CheckStatus::Pass, "{report:?}");
            "fail"
        }
        Err(ArchiveError::InvalidArchive(_)) => "refused",
        Err(other) => panic!("unexpected verify error: {other}"),
    }
}

/// Extraction follows the archive's entry order, so `verify` (which simulates
/// entries in that order) and `extract` agree for every order of a directory
/// `S`, a link `L` to it and a file `F` below the link, with one block per
/// entry and with the files in one solid block (`S` at either end of the
/// block is pushed apart from it, so the writer does not count it as a
/// sub-stream; `S` in the middle makes the block interleaved and is refused at
/// admission by both). The stream map of every case is pinned. Parity holds
/// under an integrity check only: a plain `verify` leaves 7z link targets
/// unread.
///
/// In `SLF` and `LSF` the file `d/f` is written through the archive's own link
/// `d` into `sub/f`, as TAR does.
///
/// `verify` reports a link whose placement can make extraction fail under some
/// option set: a link that dangles when `d/f` is written (`LFS`, which fails
/// extract with or without `skip_duplicates`), or that lands on the directory
/// `d/` created by `d/f` (`SFL`, `FSL`, `FLS`, which fail extract without
/// `skip_duplicates`). The default extract drops that last link silently and so
/// only looks like `extracted`; `verify` stays conservative and fails.
#[cfg(unix)]
#[test]
fn verify_and_extract_agree_for_every_order_of_a_directory_a_link_and_a_file() {
    const N: Option<usize> = None;
    let (s, l, f) = (
        Item::Dir("sub"),
        Item::Link("d", b"sub"),
        Item::File("d/f", b"x"),
    );
    // (order, items, layout, stream map, extract with skip_duplicates,
    // extract without it, verify)
    #[rustfmt::skip]
    let table = [
        ("SLF", [s, l, f], Layout::OneBlockEach, [N, Some(0), Some(1)], "extracted", "extracted", "pass"),
        ("LSF", [l, s, f], Layout::OneBlockEach, [Some(0), N, Some(1)], "extracted", "extracted", "pass"),
        ("SFL", [s, f, l], Layout::OneBlockEach, [N, Some(0), Some(1)], "extracted", "failed", "pass"),
        ("FSL", [f, s, l], Layout::OneBlockEach, [Some(0), N, Some(1)], "extracted", "failed", "pass"),
        ("LFS", [l, f, s], Layout::OneBlockEach, [Some(0), Some(1), N], "failed", "failed", "fail"),
        ("FLS", [f, l, s], Layout::OneBlockEach, [Some(0), Some(1), N], "extracted", "failed", "pass"),
        ("SLF", [s, l, f], Layout::SolidAroundDirs, [N, Some(0), Some(0)], "extracted", "extracted", "pass"),
        ("LSF", [l, s, f], Layout::SolidAroundDirs, [Some(0), Some(0), Some(0)], "refused", "refused", "fail"),
        ("SFL", [s, f, l], Layout::SolidAroundDirs, [N, Some(0), Some(0)], "extracted", "failed", "pass"),
        ("FSL", [f, s, l], Layout::SolidAroundDirs, [Some(0), Some(0), Some(0)], "refused", "refused", "fail"),
        ("LFS", [l, f, s], Layout::SolidAroundDirs, [Some(0), Some(0), N], "failed", "failed", "fail"),
        ("FLS", [f, l, s], Layout::SolidAroundDirs, [Some(0), Some(0), N], "extracted", "failed", "pass"),
    ];
    let config = allow_symlinks().with_allow_solid_archives(true);
    for (order, items, layout, map, skipping, keeping, verify) in table {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("m.7z");
        let bytes = build(&items, layout, false);
        std::fs::write(&path, &bytes).unwrap();
        let label = format!(
            "{order} {}",
            if layout == Layout::OneBlockEach {
                "each"
            } else {
                "solid"
            }
        );

        let archive = Archive::read(&mut Cursor::new(bytes), &Password::empty()).unwrap();
        assert_eq!(archive.stream_map.file_block_index, map, "{label} map");
        assert_eq!(
            extract_class(&path, &config, true),
            skipping,
            "{label} extract"
        );
        assert_eq!(
            extract_class(&path, &config, false),
            keeping,
            "{label} extract without skip_duplicates"
        );
        assert_eq!(verify_class(&path, &config), verify, "{label} verify");

        if matches!(order, "SLF" | "LSF") && layout == Layout::OneBlockEach
            || order == "SLF" && layout == Layout::SolidAroundDirs
        {
            let (container, out) = nested_dest();
            extract_archive(&path, &out, &config).unwrap();
            assert_eq!(tree_of(&out), ["d->sub", "sub/", "sub/f"], "{label} tree");
            assert_eq!(std::fs::read(out.join("sub/f")).unwrap(), b"x", "{label}");
            assert_nothing_outside(&container, &label);
        }
    }
}

#[cfg(not(unix))]
#[test]
fn a_link_is_refused_before_any_write_on_a_host_without_symlinks() {
    let dir = TempDir::new().unwrap();
    let path = archive_of(
        &dir,
        &[Item::File("a.txt", b"hi"), Item::Link("l", b"a.txt")],
    );
    let out = TempDir::new().unwrap();

    assert_matches!(
        extract_archive(&path, out.path(), &allow_symlinks()),
        Err(ArchiveError::SecurityViolation { reason }) if reason.contains("not supported on this platform")
    );
    assert!(dir_is_empty(&out));
}
