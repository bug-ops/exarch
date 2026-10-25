//! A 7z entry whose Unix mode (`S_IFLNK`) marks it as a symlink is read and
//! validated through the symlink policy: `list` reports the target, `verify`
//! validates it, and `extract` creates the link only under `allow_symlinks`.

#![allow(clippy::unwrap_used)]
#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use std::assert_matches;
use std::io::Cursor;
use std::path::Path;
use std::path::PathBuf;

use common::flip_first;
use exarch_core::ArchiveError;
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
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use sevenz_rust2::EncoderConfiguration;
use sevenz_rust2::EncoderMethod;
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
    let manifest = list_archive(path, config).unwrap();
    manifest
        .entries()
        .iter()
        .find_map(|entry| match &entry.kind {
            ManifestEntryKind::Symlink { target } => Some(target.clone()),
            _ => None,
        })
        .unwrap()
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
fn list_leaves_a_target_with_a_corrupt_checksum_unread() {
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
        LinkTarget::Unread
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
    let report = verify_archive(&inside, &allow_symlinks()).unwrap();
    assert_eq!(
        report.status(),
        VerificationStatus::Pass,
        "{:?}",
        report.issues()
    );

    for target in [&b"/etc/passwd"[..], b"../x", b"a/../../x"] {
        let path = archive_of(&dir, &[Item::Link("link", target)]);
        let report = verify_archive(&path, &allow_symlinks()).unwrap();
        assert_eq!(report.status(), VerificationStatus::Fail, "{target:?}");
        assert!(
            issue_categories(&report).contains(&IssueCategory::SymlinkEscape),
            "{target:?}: {:?}",
            report.issues()
        );
    }
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
            .any(|i| i.message.contains("was not read")),
        "{:?}",
        report.issues()
    );
}

#[test]
fn verify_integrity_leaves_a_link_unread_when_the_budget_cannot_decode_it() {
    let dir = TempDir::new().unwrap();
    let path = archive_of(&dir, &[Item::Link("link", b"a.txt")]);

    let report = verify_archive_with_options(&path, &allow_symlinks(), &integrity(1)).unwrap();

    assert_eq!(report.status(), VerificationStatus::Fail);
    assert!(
        report
            .issues()
            .iter()
            .any(|i| i.message.contains("was not read")),
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
fn extract_refuses_an_escaping_target_before_any_write() {
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
        let out = TempDir::new().unwrap();

        let err = extract_archive(&path, out.path(), &allow_symlinks()).unwrap_err();

        assert_matches!(err, ArchiveError::SymlinkEscape { .. }, "{label}");
        assert!(dir_is_empty(&out), "{label}: nothing may be written");
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
    let out = TempDir::new().unwrap();
    std::fs::create_dir_all(out.path().join("p/q")).unwrap();
    symlink("p/q", out.path().join("x")).unwrap();

    for skip_duplicates in [true, false] {
        let options = ExtractionOptions::default().with_skip_duplicates(skip_duplicates);
        let result = extract_archive_with_options(&path, out.path(), &allow_symlinks(), &options);

        assert_matches!(
            result,
            Err(ArchiveError::SymlinkEscape { .. }),
            "skip_duplicates={skip_duplicates}"
        );
        assert_eq!(
            std::fs::read_link(out.path().join("x")).unwrap(),
            Path::new("p/q")
        );
        assert!(std::fs::symlink_metadata(out.path().join("a")).is_err());
    }
}

#[cfg(unix)]
#[test]
fn dangling_link_at_the_link_path_is_skipped_or_replaced_by_policy() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new().unwrap();
    let path = archive_of(&dir, &[Item::Link("l", b"other")]);

    for (skip_duplicates, expected) in [(true, "gone"), (false, "other")] {
        let out = TempDir::new().unwrap();
        symlink("gone", out.path().join("l")).unwrap();
        let options = ExtractionOptions::default().with_skip_duplicates(skip_duplicates);

        extract_archive_with_options(&path, out.path(), &allow_symlinks(), &options).unwrap();

        assert_eq!(
            std::fs::read_link(out.path().join("l")).unwrap(),
            Path::new(expected)
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

        assert!(err.to_string().contains(expect), "{expect}: {err}");
        assert!(dir_is_empty(&out), "{expect}");
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
    assert_eq!(link_target(&path, &refused), LinkTarget::Unread);
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
    for items in orders {
        let dir = TempDir::new().unwrap();
        let path = archive_of(&dir, &items);
        let out = TempDir::new().unwrap();

        let err = extract_archive(&path, out.path(), &allow_symlinks()).unwrap_err();

        assert_matches!(err, ArchiveError::SymlinkEscape { .. });
        assert!(dir_is_empty(&out));
        let report = verify_archive(&path, &allow_symlinks()).unwrap();
        assert_eq!(report.security_status(), CheckStatus::Fail);
    }
}

#[cfg(unix)]
#[test]
fn a_target_through_a_directory_of_the_same_archive_is_refused_before_any_write() {
    let dir = TempDir::new().unwrap();
    let path = archive_of(&dir, &[Item::Dir("t"), Item::Link("t2", b"t/../x")]);
    let out = TempDir::new().unwrap();

    let err = extract_archive(&path, out.path(), &allow_symlinks()).unwrap_err();

    assert_matches!(err, ArchiveError::SymlinkEscape { .. });
    assert!(dir_is_empty(&out));
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
fn an_escaping_link_inside_a_solid_block_is_refused_before_any_write() {
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
    let out = TempDir::new().unwrap();

    let err = extract_archive(&path, out.path(), &solid_config()).unwrap_err();

    assert_matches!(err, ArchiveError::SymlinkEscape { .. });
    assert!(dir_is_empty(&out));
}

#[cfg(unix)]
#[test]
fn a_corrupt_link_inside_a_solid_block_fails_extract_before_any_write() {
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
    let out = TempDir::new().unwrap();

    let err = extract_archive(&path, out.path(), &solid_config()).unwrap_err();

    assert_matches!(err, ArchiveError::InvalidArchive(reason) if reason.contains("failed to read 7z symlink target"));
    assert!(dir_is_empty(&out));
    assert_eq!(
        link_target(&path, &solid_config()),
        LinkTarget::Unread,
        "the corrupt link stays unread in a listing"
    );
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
