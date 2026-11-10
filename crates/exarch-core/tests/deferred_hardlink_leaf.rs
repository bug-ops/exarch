//! `list` and `verify` judge a hardlink the way extraction does: the path is
//! validated at the entry's own position and the link is created after every
//! other entry, so a symlink that a later entry puts at its path is a
//! duplicate, never a path to resolve.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]
#![cfg(unix)]

mod sink_support;

use std::assert_matches;
use std::path::Path;

use exarch_core::Disposition;
use exarch_core::ExtractRequest;
use exarch_core::ManifestEntryKind;
use exarch_core::SecurityConfig;
use exarch_core::SkipKind;
use exarch_core::VerificationStatus;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use sink_support::tar_archive;
use sink_support::tar_file;
use sink_support::tar_hardlink;
use sink_support::tar_symlink;
use tempfile::TempDir;

fn config() -> SecurityConfig {
    SecurityConfig::default()
        .with_allow_symlinks(true)
        .with_allow_hardlinks(true)
}

fn write(entries: &[Vec<u8>]) -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.tar");
    std::fs::write(&archive, tar_archive(entries)).unwrap();
    (dir, archive)
}

fn hardlink_disposition(archive: &Path, config: &SecurityConfig) -> Disposition {
    let manifest = list_archive(archive, config).unwrap();
    manifest
        .dispositions(config)
        .find(|(entry, _)| matches!(entry.kind, ManifestEntryKind::Hardlink { .. }))
        .map(|(_, disposition)| disposition)
        .unwrap()
}

#[test]
fn a_hardlink_followed_by_a_self_pointing_symlink_is_a_duplicate_everywhere() {
    for (file, link) in [("b", "h"), ("d/b", "d/h")] {
        let leaf = Path::new(link).file_name().unwrap().to_str().unwrap();
        let (dir, archive) = write(&[
            tar_file(file, b"x\n"),
            tar_hardlink(link, file),
            tar_symlink(link, leaf),
        ]);
        let config = config();

        assert_matches!(
            hardlink_disposition(&archive, &config),
            Disposition::Skip(SkipKind::Duplicate),
            "{link}"
        );
        let report = verify_archive(&archive, &config).unwrap();
        assert_ne!(report.status(), VerificationStatus::Fail, "{link}");
        let report = ExtractRequest::new(&config)
            .extract(&archive, dir.path().join("out"))
            .unwrap();
        assert_eq!(report.files_skipped(), 1, "{link}");
    }
}

#[test]
fn a_self_pointing_symlink_before_the_hardlink_stays_refused_everywhere() {
    let (dir, archive) = write(&[
        tar_file("b", b"x\n"),
        tar_symlink("h", "h"),
        tar_hardlink("h", "b"),
    ]);
    let config = config();

    assert_matches!(hardlink_disposition(&archive, &config), Disposition::Refuse);
    let report = verify_archive(&archive, &config).unwrap();
    assert_eq!(report.status(), VerificationStatus::Fail);
    assert!(
        ExtractRequest::new(&config)
            .extract(&archive, dir.path().join("out"))
            .is_err()
    );
}

#[test]
fn a_later_symlinked_parent_refuses_the_hardlink_everywhere() {
    let (dir, archive) = write(&[
        tar_file("b", b"x\n"),
        tar_hardlink("d/h", "b"),
        tar_symlink("d", "elsewhere"),
    ]);
    let config = config();

    assert_matches!(hardlink_disposition(&archive, &config), Disposition::Refuse);
    let report = verify_archive(&archive, &config).unwrap();
    assert_eq!(report.status(), VerificationStatus::Fail);
    assert!(
        ExtractRequest::new(&config)
            .extract(&archive, dir.path().join("out"))
            .is_err()
    );
}

#[test]
fn a_later_symlinked_parent_inside_the_root_lands_the_hardlink_below_its_target() {
    use exarch_core::ArchiveReader;
    use exarch_core::ExistingFiles;
    use exarch_core::ExtractionOptions;
    use exarch_core::MemoryEntry;
    use exarch_core::MemoryExtractRequest;
    use exarch_core::NoopProgress;
    use exarch_core::Staging;
    use exarch_core::extract_reader_to_memory;

    let entries = [
        tar_file("b", b"x\n"),
        sink_support::tar_dir("e/"),
        tar_hardlink("d/h", "b"),
        tar_symlink("d", "e"),
    ];
    let (dir, archive) = write(&entries);
    let config = config();

    let landing = match hardlink_disposition(&archive, &config) {
        Disposition::Extract(landing) => landing,
        other => panic!("expected a landing, got {other:?}"),
    };
    assert_eq!(landing.as_path(), Path::new("e/h"));
    let report = verify_archive(&archive, &config).unwrap();
    assert_ne!(report.status(), VerificationStatus::Fail);

    for (name, staging) in [("plain", Staging::InPlace), ("atomic", Staging::Atomic)] {
        let out = dir.path().join(name);
        let options = ExtractionOptions::default()
            .with_staging(staging)
            .with_existing_files(ExistingFiles::Refuse);
        ExtractRequest::new(&config)
            .with_options(options)
            .extract(&archive, &out)
            .unwrap();
        assert_eq!(std::fs::read(out.join("e/h")).unwrap(), b"x\n", "{name}");
    }

    let request = MemoryExtractRequest::default().with_config(config);
    let (_, sink) = extract_reader_to_memory(
        ArchiveReader::from_bytes(tar_archive(&entries), None).unwrap(),
        &request,
        &mut NoopProgress,
    )
    .unwrap();
    assert_matches!(sink.get(Path::new("e/h")), Some(MemoryEntry::File { .. }));
}
