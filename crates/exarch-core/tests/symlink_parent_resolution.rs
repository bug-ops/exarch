//! Symlink and hardlink targets whose `..` components cannot be resolved
//! against the extracted tree are rejected by extract and verify in TAR and
//! ZIP. A symlink that resolves to something at the link's own path is not
//! replaced by another entry; a dangling one is skipped or replaced by policy.

#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use std::io::Cursor;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::CheckStatus;
use exarch_core::ExtractionOptions;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive_with_options;
use exarch_core::verify_archive;
use tempfile::TempDir;
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;
use zip::write::ZipWriter;

#[derive(Clone, Copy)]
enum Node {
    Dir(&'static str),
    File(&'static str),
    Link(&'static str, &'static str),
    Hardlink(&'static str, &'static str),
}

use Node::Dir;
use Node::File;
use Node::Hardlink;
use Node::Link;

#[derive(Clone, Copy, Debug)]
enum Format {
    Tar,
    Zip,
}

const FORMATS: [Format; 2] = [Format::Tar, Format::Zip];
// The `zip` writer refuses two entries with one name, so duplicate layouts are
// TAR only.
const TAR_ONLY: [Format; 1] = [Format::Tar];

fn tar_of(nodes: &[Node]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for node in nodes {
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o755);
        match *node {
            Dir(name) => {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_cksum();
                builder
                    .append_data(&mut header, name, std::io::empty())
                    .unwrap();
            }
            File(name) => {
                header.set_entry_type(tar::EntryType::Regular);
                header.set_cksum();
                builder
                    .append_data(&mut header, name, std::io::empty())
                    .unwrap();
            }
            Link(name, target) => {
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_cksum();
                builder.append_link(&mut header, name, target).unwrap();
            }
            Hardlink(name, target) => {
                header.set_entry_type(tar::EntryType::Link);
                header.set_cksum();
                builder.append_link(&mut header, name, target).unwrap();
            }
        }
    }
    builder.into_inner().unwrap()
}

fn zip_of(nodes: &[Node]) -> Vec<u8> {
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .unix_permissions(0o755);
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    for node in nodes {
        match *node {
            Dir(name) => zip.add_directory(name, options).unwrap(),
            File(name) => zip.start_file(name, options).unwrap(),
            Link(name, target) => zip.add_symlink(name, target, options).unwrap(),
            Hardlink(..) => unreachable!("ZIP has no hardlink entries"),
        }
    }
    zip.finish().unwrap().into_inner()
}

struct Fixture {
    root: TempDir,
    archive: PathBuf,
}

impl Fixture {
    fn new(format: Format, nodes: &[Node]) -> Self {
        let root = TempDir::new().unwrap();
        let (name, bytes) = match format {
            Format::Tar => ("a.tar", tar_of(nodes)),
            Format::Zip => ("a.zip", zip_of(nodes)),
        };
        let archive = root.path().join(name);
        std::fs::write(&archive, bytes).unwrap();
        std::fs::create_dir(root.path().join("out")).unwrap();
        Self { root, archive }
    }

    fn out(&self) -> PathBuf {
        self.root.path().join("out")
    }

    fn extract(&self, skip_duplicates: bool) -> exarch_core::Result<exarch_core::ExtractionReport> {
        let config = SecurityConfig::default()
            .with_allow_symlinks(true)
            .with_allow_hardlinks(true);
        let options = ExtractionOptions::default().with_skip_duplicates(skip_duplicates);
        extract_archive_with_options(&self.archive, self.out(), &config, &options)
    }

    fn verify_report(&self) -> Option<exarch_core::VerificationReport> {
        let config = SecurityConfig::default()
            .with_allow_symlinks(true)
            .with_allow_hardlinks(true);
        verify_archive(&self.archive, &config).ok()
    }

    fn verify_status(&self) -> Option<CheckStatus> {
        self.verify_report().map(|report| report.security_status())
    }

    fn assert_dest_only(&self) {
        let mut siblings: Vec<_> = std::fs::read_dir(self.root.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        siblings.sort();
        assert_eq!(siblings.len(), 2, "{siblings:?}");
        assert_links_resolve_in_dest(&self.out());
    }
}

fn assert_links_resolve_in_dest(out: &Path) {
    let canonical_out = std::fs::canonicalize(out).unwrap();
    let mut pending = vec![out.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let meta = std::fs::symlink_metadata(&path).unwrap();
            if meta.file_type().is_symlink() {
                if let Ok(resolved) = std::fs::canonicalize(&path) {
                    assert!(
                        resolved.starts_with(&canonical_out),
                        "{} resolves outside the destination",
                        path.display()
                    );
                }
            } else if meta.is_dir() {
                pending.push(path);
            }
        }
    }
}

fn code(result: exarch_core::Result<exarch_core::ExtractionReport>) -> &'static str {
    result.unwrap_err().error_code()
}

#[test]
fn symlink_target_with_unresolvable_parent_component_is_rejected() {
    for format in FORMATS {
        let fixture = Fixture::new(format, &[Link("a", "d/.."), Link("d", ".")]);
        assert_eq!(code(fixture.extract(true)), "SYMLINK_ESCAPE", "{format:?}");
        fixture.assert_dest_only();
        assert_ne!(
            fixture.verify_status(),
            Some(CheckStatus::Pass),
            "{format:?}"
        );
    }
}

#[test]
fn symlink_target_leaving_dest_through_link_is_rejected() {
    for format in FORMATS {
        let fixture = Fixture::new(format, &[Link("d", "."), Link("a", "d/..")]);
        assert_eq!(code(fixture.extract(true)), "SYMLINK_ESCAPE", "{format:?}");
        fixture.assert_dest_only();
        assert_ne!(
            fixture.verify_status(),
            Some(CheckStatus::Pass),
            "{format:?}"
        );
    }
}

#[test]
fn symlink_target_with_two_unresolvable_parent_components_is_rejected() {
    for format in FORMATS {
        let fixture = Fixture::new(format, &[Link("a", "d/e/../../f"), Dir("d/e/")]);
        assert_eq!(code(fixture.extract(true)), "SYMLINK_ESCAPE", "{format:?}");
        assert_ne!(
            fixture.verify_status(),
            Some(CheckStatus::Pass),
            "{format:?}"
        );
    }
}

#[test]
fn hardlink_target_with_unresolvable_parent_component_is_rejected() {
    for format in TAR_ONLY {
        let fixture = Fixture::new(format, &[File("f"), Hardlink("h", "d/../f"), Dir("d/")]);
        assert_eq!(code(fixture.extract(true)), "HARDLINK_ESCAPE", "{format:?}");
        assert_ne!(
            fixture.verify_status(),
            Some(CheckStatus::Pass),
            "{format:?}"
        );
    }
}

#[test]
fn hardlink_target_through_existing_directory_extracts() {
    for format in TAR_ONLY {
        let fixture = Fixture::new(format, &[File("f"), Dir("d/"), Hardlink("h", "d/../f")]);
        fixture.extract(true).unwrap();
        assert!(fixture.out().join("h").exists(), "{format:?}");
    }
}

#[test]
fn symlink_target_through_existing_directory_extracts() {
    for format in FORMATS {
        let fixture = Fixture::new(format, &[Dir("d/"), Link("x", "d/../f")]);
        let report = fixture.extract(true).unwrap();
        assert_eq!(report.symlinks_created, 1, "{format:?}");
        assert_eq!(
            std::fs::read_link(fixture.out().join("x")).unwrap(),
            Path::new("d/../f")
        );
        assert_eq!(
            fixture.verify_status(),
            Some(CheckStatus::Pass),
            "{format:?}"
        );
    }
}

#[test]
fn symlink_target_parent_component_must_resolve_in_entry_order() {
    for format in FORMATS {
        let fixture = Fixture::new(format, &[Link("x", "d/../f"), Dir("d/")]);
        assert_eq!(code(fixture.extract(true)), "SYMLINK_ESCAPE", "{format:?}");
        assert_ne!(
            fixture.verify_status(),
            Some(CheckStatus::Pass),
            "{format:?}"
        );
    }
}

#[test]
fn symlink_target_leaving_own_parent_directories_extracts() {
    for format in FORMATS {
        let fixture = Fixture::new(format, &[Link("sub/l", "../x"), Link("a/b/l", "../../x")]);
        let report = fixture.extract(true).unwrap();
        assert_eq!(report.symlinks_created, 2, "{format:?}");
        assert_eq!(
            fixture.verify_status(),
            Some(CheckStatus::Pass),
            "{format:?}"
        );
    }
}

/// Extraction with overwrite stops at a symlink entry whose path holds a
/// symlink, instead of re-pointing a link an earlier entry already resolved
/// through.
fn assert_symlink_refused(result: exarch_core::Result<exarch_core::ExtractionReport>) {
    let error = result.unwrap_err();
    let exarch_core::ArchiveError::PartialExtraction { source, .. } = &error else {
        panic!("expected PartialExtraction, got {error:?}");
    };
    let exarch_core::ArchiveError::Io(io) = &**source else {
        panic!("expected Io, got {source:?}");
    };
    assert_eq!(
        io.kind(),
        std::io::Error::from_raw_os_error(libc::ELOOP).kind()
    );
}

fn assert_issue_note(fixture: &Fixture, needle: &str) {
    let report = fixture.verify_report().unwrap();
    assert_eq!(report.security_status(), CheckStatus::Pass, "{report:?}");
    let note = report
        .issues()
        .iter()
        .find(|i| i.category == exarch_core::IssueCategory::InvalidArchive)
        .unwrap_or_else(|| panic!("no overwrite note: {:?}", report.issues()));
    assert_eq!(note.severity, exarch_core::IssueSeverity::Low);
    assert!(note.message.contains(needle), "{}", note.message);
}

fn resolves_to(fixture: &Fixture, link: &str, expected: &str) {
    assert_eq!(
        std::fs::canonicalize(fixture.out().join(link)).unwrap(),
        std::fs::canonicalize(fixture.out().join(expected)).unwrap(),
        "{link}"
    );
}

#[test]
fn existing_symlink_at_link_path_is_not_replaced() {
    for format in TAR_ONLY {
        for skip_duplicates in [true, false] {
            let fixture = Fixture::new(
                format,
                &[
                    Dir("p/"),
                    Dir("p/q/"),
                    Link("x", "p/q"),
                    Link("a", "x/.."),
                    Link("x", "."),
                ],
            );
            let result = fixture.extract(skip_duplicates);
            if skip_duplicates {
                result.unwrap();
            } else {
                assert_symlink_refused(result);
            }
            assert_links_resolve_in_dest(&fixture.out());
            resolves_to(&fixture, "x", "p/q");
            resolves_to(&fixture, "a", "p");
            assert_issue_note(&fixture, "fails at x");
        }
    }
}

#[test]
fn existing_symlink_in_chain_is_not_replaced() {
    for format in TAR_ONLY {
        for skip_duplicates in [true, false] {
            let fixture = Fixture::new(
                format,
                &[
                    Dir("p/"),
                    Link("y", "p"),
                    Link("x", "y"),
                    Link("a", "x/.."),
                    Link("y", "."),
                ],
            );
            let result = fixture.extract(skip_duplicates);
            if skip_duplicates {
                result.unwrap();
            } else {
                assert_symlink_refused(result);
            }
            assert_links_resolve_in_dest(&fixture.out());
            resolves_to(&fixture, "y", "p");
            assert_issue_note(&fixture, "fails at y");
        }
    }
}

/// Re-pointing `d` after `e -> d/../..` was validated would make `e` leave the
/// destination, so the second `d` is skipped by default and refused when
/// overwriting, in every spelling.
#[test]
fn repointing_a_link_that_an_earlier_link_resolved_through_is_refused() {
    let archives: [(&str, &[Node]); 4] = [
        (
            "plain",
            &[
                Dir("sub/"),
                Dir("sub/deep/"),
                Link("d", "sub/deep"),
                Link("e", "d/../.."),
                Link("d", "sub"),
            ],
        ),
        (
            "trailing slash",
            &[
                Dir("sub/"),
                Dir("sub/deep/"),
                Link("d", "sub/deep"),
                Link("e", "d/../.."),
                Link("d/", "sub"),
            ],
        ),
        (
            "through a link",
            &[
                Dir("sub/"),
                Dir("sub/deep/"),
                Link("d", "sub/deep"),
                Link("c", "d"),
                Link("e", "c/../.."),
                Link("c", "sub"),
            ],
        ),
        (
            "over a directory",
            &[
                Dir("sub/"),
                Dir("sub/deep/"),
                Link("d", "sub/deep"),
                Link("e", "d/../.."),
                Dir("d/"),
                Link("d", "sub"),
            ],
        ),
    ];
    for (name, nodes) in archives {
        for skip_duplicates in [true, false] {
            let fixture = Fixture::new(Format::Tar, nodes);
            let result = fixture.extract(skip_duplicates);
            let label = format!("{name} skip_duplicates={skip_duplicates}");
            if skip_duplicates {
                assert!(result.is_ok(), "{label}: {result:?}");
            } else {
                assert!(result.is_err(), "{label}");
            }
            assert_links_resolve_in_dest(&fixture.out());
            resolves_to(&fixture, "d", "sub/deep");
            assert_eq!(fixture.verify_status(), Some(CheckStatus::Pass), "{label}");
        }
    }
}

/// The `zip` writer refuses two entries with one name, so the duplicate is
/// made by renaming a same-length name in the written bytes.
#[test]
fn zip_repointing_through_an_earlier_link_never_escapes() {
    let nodes = [
        Dir("sub/"),
        Dir("sub/deep/"),
        Link("dQ", "sub/deep"),
        Link("e", "dQ/../.."),
        Link("dR", "sub"),
    ];
    for skip_duplicates in [true, false] {
        let fixture = Fixture::new(Format::Zip, &nodes);
        let mut bytes = std::fs::read(&fixture.archive).unwrap();
        let mut renamed = 0;
        for at in 0..bytes.len() - 1 {
            if &bytes[at..at + 2] == b"dR" {
                bytes[at + 1] = b'Q';
                renamed += 1;
            }
        }
        assert!(renamed >= 2, "local header and central directory");
        std::fs::write(&fixture.archive, bytes).unwrap();

        let _ = fixture.extract(skip_duplicates);
        assert_links_resolve_in_dest(&fixture.out());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn existing_symlink_with_differently_cased_name_is_not_replaced() {
    let probe = TempDir::new().unwrap();
    std::fs::write(probe.path().join("probe"), b"").unwrap();
    if !probe.path().join("PROBE").exists() {
        return;
    }
    for format in TAR_ONLY {
        for skip_duplicates in [true, false] {
            let fixture = Fixture::new(
                format,
                &[
                    Dir("p/"),
                    Dir("p/q/"),
                    Link("x", "p/q"),
                    Link("a", "x/.."),
                    Link("X", "."),
                ],
            );
            let _ = fixture.extract(skip_duplicates);
            assert_links_resolve_in_dest(&fixture.out());
            resolves_to(&fixture, "x", "p/q");
            assert_ne!(
                fixture.verify_status(),
                Some(CheckStatus::Pass),
                "{format:?}"
            );
        }
    }
}

#[test]
fn rerun_with_overwrite_keeps_unchanged_symlinks() {
    for target in ["missing.so.1", "f"] {
        let fixture = Fixture::new(Format::Tar, &[File("f"), Link("lib.so", target)]);
        fixture.extract(false).unwrap();
        fixture.extract(false).unwrap();
        assert_eq!(
            std::fs::read_link(fixture.out().join("lib.so")).unwrap(),
            Path::new(target)
        );
    }
}

#[test]
fn hardlink_over_an_earlier_link_is_refused_and_keeps_the_link() {
    for skip_duplicates in [true, false] {
        let fixture = Fixture::new(
            Format::Tar,
            &[
                Dir("p/"),
                Dir("p/q/"),
                Link("x", "p/q"),
                Link("a", "x/.."),
                File("t"),
                Hardlink("x", "t"),
            ],
        );
        let _ = fixture.extract(skip_duplicates);
        assert_links_resolve_in_dest(&fixture.out());
        resolves_to(&fixture, "x", "p/q");
        resolves_to(&fixture, "a", "p");
    }
}

#[cfg(target_os = "macos")]
#[test]
fn normalization_variant_of_an_existing_symlink_is_not_replaced() {
    let probe = TempDir::new().unwrap();
    std::fs::write(probe.path().join("caf\u{e9}"), b"").unwrap();
    if !probe.path().join("cafe\u{301}").exists() {
        return;
    }
    for skip_duplicates in [true, false] {
        let fixture = Fixture::new(
            Format::Tar,
            &[
                Dir("p/"),
                Dir("p/q/"),
                Link("caf\u{e9}", "p/q"),
                Link("a", "caf\u{e9}/.."),
                Link("cafe\u{301}", "."),
            ],
        );
        let _ = fixture.extract(skip_duplicates);
        assert_links_resolve_in_dest(&fixture.out());
        resolves_to(&fixture, "caf\u{e9}", "p/q");
        assert_ne!(fixture.verify_status(), Some(CheckStatus::Pass));
    }
}

#[test]
fn dangling_symlink_at_link_path_is_skipped_or_refused_by_policy() {
    for format in TAR_ONLY {
        let skipped = Fixture::new(format, &[Link("x", "gone"), Link("x", "other")]);
        let report = skipped.extract(true).unwrap();
        assert_eq!(report.symlinks_created, 1, "{format:?}");
        assert_eq!(
            std::fs::read_link(skipped.out().join("x")).unwrap(),
            Path::new("gone")
        );

        let refused = Fixture::new(format, &[Link("x", "gone"), Link("x", "other")]);
        assert_symlink_refused(refused.extract(false));
        assert_eq!(
            std::fs::read_link(refused.out().join("x")).unwrap(),
            Path::new("gone")
        );
    }
}
