//! Acceptance contract of #1232: on Windows a file over an escaping existing
//! junction or directory symlink gets the occupant kind in tar, zip and 7z, as
//! on unix, and nothing is written below the link target.

#![cfg(windows)]
#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

mod sink_support;

use std::os::windows::fs::symlink_dir;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use exarch_core::ArchiveError;
use exarch_core::ExistingFiles;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::OccupiedBy;
use exarch_core::SecurityConfig;
use exarch_core::Violation;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use sink_support::tar_archive;
use sink_support::tar_file;
use sink_support::zip_archive;
use sink_support::zip_file;
use tempfile::TempDir;

#[derive(Clone, Copy, Debug)]
enum LinkKind {
    Junction,
    DirSymlink,
}

fn config() -> SecurityConfig {
    SecurityConfig::default().with_allow_symlinks(true)
}

fn required() -> bool {
    std::env::var_os("EXARCH_REQUIRE_PRIVILEGED_TESTS").is_some()
}

fn plant(kind: LinkKind, link: &Path, target: &Path) -> bool {
    match kind {
        LinkKind::Junction => Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .is_ok_and(|out| out.status.success()),
        LinkKind::DirSymlink => symlink_dir(target, link).is_ok(),
    }
}

fn write(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn archives(dir: &TempDir, name: &str) -> [PathBuf; 3] {
    let seven = dir.path().join("a.7z");
    let mut writer = ArchiveWriter::new(std::fs::File::create(&seven).unwrap()).unwrap();
    writer
        .push_archive_entry(ArchiveEntry::new_file(name), Some(&b"ok"[..]))
        .unwrap();
    writer.finish().unwrap();
    [
        write(dir, "n.tar", &tar_archive(&[tar_file(name, b"n\n")])),
        write(dir, "n.zip", &zip_archive(vec![zip_file(name, b"n\n")])),
        seven,
    ]
}

fn cause(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    }
}

fn run(archive: &Path, dest: &Path, policy: ExistingFiles) -> Result<(), ArchiveError> {
    ExtractRequest::new(&config())
        .with_options(ExtractionOptions::default().with_existing_files(policy))
        .extract(archive, dest)
        .map(drop)
}

fn for_each_leaf_link(name: &str, check: impl Fn(&Path, &Path, &Path, ExistingFiles)) {
    for kind in [LinkKind::Junction, LinkKind::DirSymlink] {
        for policy in [
            ExistingFiles::Skip,
            ExistingFiles::Refuse,
            ExistingFiles::Overwrite,
        ] {
            let dir = TempDir::new().unwrap();
            for archive in archives(&dir, name) {
                let root = TempDir::new().unwrap();
                let dest = root.path().join("out");
                let outside = root.path().join("outside");
                std::fs::create_dir(&dest).unwrap();
                std::fs::create_dir(&outside).unwrap();
                std::fs::create_dir_all(dest.join(name).parent().unwrap()).unwrap();
                if !plant(kind, &dest.join(name), &outside) {
                    assert!(
                        !required(),
                        "{kind:?} not creatable but EXARCH_REQUIRE_PRIVILEGED_TESTS is set"
                    );
                    return;
                }
                check(&archive, &dest, &outside, policy);
            }
        }
    }
}

#[test]
fn extract_file_over_an_escaping_junction_or_dir_symlink_is_the_occupant_kind() {
    for_each_leaf_link("l", |archive, dest, outside, policy| {
        let result = run(archive, dest, policy);

        match (policy, result) {
            (ExistingFiles::Skip, Ok(())) => {}
            (ExistingFiles::Refuse, Err(error)) => match cause(&error) {
                ArchiveError::DestinationOccupied { by, .. } => {
                    assert_eq!(*by, OccupiedBy::Existing, "{}", archive.display());
                }
                other => panic!(
                    "{}: expected DestinationOccupied, got {other}",
                    archive.display()
                ),
            },
            (ExistingFiles::Overwrite, Err(error)) => match cause(&error) {
                ArchiveError::SecurityViolation {
                    kind: Violation::ReplacesSymlink { by, .. },
                    ..
                } => assert_eq!(*by, OccupiedBy::Existing, "{}", archive.display()),
                other => panic!(
                    "{}: expected ReplacesSymlink, got {other}",
                    archive.display()
                ),
            },
            (policy, other) => panic!("{policy:?} {}: unexpected {other:?}", archive.display()),
        }
        assert_eq!(
            std::fs::read_dir(outside).unwrap().count(),
            0,
            "{policy:?} {}: wrote through the link",
            archive.display()
        );
    });
}

#[test]
fn extract_nested_file_over_an_escaping_junction_or_dir_symlink_is_the_occupant_kind() {
    for_each_leaf_link("d\\l", |archive, dest, outside, policy| {
        let result = run(archive, dest, policy);

        assert!(
            matches!(
                (policy, result.as_ref().map_err(cause)),
                (ExistingFiles::Skip, Ok(()))
                    | (
                        ExistingFiles::Refuse,
                        Err(ArchiveError::DestinationOccupied { .. })
                    )
                    | (
                        ExistingFiles::Overwrite,
                        Err(ArchiveError::SecurityViolation {
                            kind: Violation::ReplacesSymlink { .. },
                            ..
                        })
                    )
            ),
            "{policy:?} {}: {result:?}",
            archive.display()
        );
        assert_eq!(std::fs::read_dir(outside).unwrap().count(), 0);
    });
}
