//! `max_file_count` bounds symlinks and hardlinks as well as files in
//! `extract` (issue #719), in every format, as `list` and `verify` already did.
//!
//! A hardlink is counted in the first pass and charged its bytes in the
//! second, so a link flood is refused before any copy and an entry is never
//! counted twice.

#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use std::assert_matches;
use std::io::Cursor;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::ExtractionOptions;
use exarch_core::QuotaResource;
use exarch_core::SecurityConfig;
use exarch_core::VerificationStatus;
use exarch_core::extract_archive;
use exarch_core::extract_archive_with_options;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use sevenz_rust2::SourceReader;
use tempfile::TempDir;
use zip::CompressionMethod;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

const UNIX_EXTENSION: u32 = 0x8000;
const S_IFLNK: u32 = 0o12_0000;

fn link_names(count: usize) -> Vec<String> {
    (0..count).map(|i| format!("link{i}")).collect()
}

fn tar_with_symlinks(count: usize) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for name in link_names(count) {
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o777);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_cksum();
        builder.append_link(&mut header, name, "target").unwrap();
    }
    builder.into_inner().unwrap()
}

fn zip_with_symlinks(count: usize) -> Vec<u8> {
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    for name in link_names(count) {
        zip.add_symlink(name, "target", options).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

fn sevenz_with_symlinks(count: usize, solid: bool) -> Vec<u8> {
    let entries_and_data: Vec<_> = link_names(count)
        .into_iter()
        .map(|name| {
            let mut entry = ArchiveEntry::new_file(&name);
            entry.has_stream = true;
            entry.size = 6;
            entry.has_windows_attributes = true;
            entry.windows_attributes = UNIX_EXTENSION | ((S_IFLNK | 0o777) << 16);
            (entry, b"target".to_vec())
        })
        .collect();
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    if solid {
        let (entries, readers): (Vec<_>, Vec<_>) = entries_and_data
            .into_iter()
            .map(|(entry, data)| (entry, SourceReader::from(Cursor::new(data))))
            .unzip();
        writer.push_archive_entries(entries, readers).unwrap();
    } else {
        for (entry, data) in entries_and_data {
            writer
                .push_archive_entry(entry, Some(Cursor::new(data)))
                .unwrap();
        }
    }
    writer.finish().unwrap().into_inner()
}

fn sevenz_with_targets(targets: &[Vec<u8>]) -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    for (i, target) in targets.iter().enumerate() {
        let mut entry = ArchiveEntry::new_file(&format!("link{i}"));
        entry.has_stream = !target.is_empty();
        entry.size = target.len() as u64;
        entry.has_windows_attributes = true;
        entry.windows_attributes = UNIX_EXTENSION | ((S_IFLNK | 0o777) << 16);
        let data = entry.has_stream.then(|| Cursor::new(target.clone()));
        writer.push_archive_entry(entry, data).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn tar_append_file(builder: &mut tar::Builder<Vec<u8>>) {
    let mut header = tar::Header::new_gnu();
    header.set_size(4);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append_data(&mut header, "t", &b"data"[..]).unwrap();
}

fn tar_append_link(builder: &mut tar::Builder<Vec<u8>>, kind: tar::EntryType, name: &str) {
    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_mode(0o644);
    header.set_entry_type(kind);
    header.set_cksum();
    builder.append_link(&mut header, name, "t").unwrap();
}

fn tar_with_file_and_hardlinks(hardlinks: usize) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    tar_append_file(&mut builder);
    for i in 0..hardlinks {
        tar_append_link(&mut builder, tar::EntryType::Link, &format!("h{i}"));
    }
    builder.into_inner().unwrap()
}

fn tar_with_file_symlink_and_hardlink() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    tar_append_file(&mut builder);
    tar_append_link(&mut builder, tar::EntryType::Symlink, "s");
    tar_append_link(&mut builder, tar::EntryType::Link, "h");
    builder.into_inner().unwrap()
}

fn write_archive(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn link_config(max_file_count: usize) -> SecurityConfig {
    SecurityConfig::default()
        .with_allow_symlinks(true)
        .with_allow_hardlinks(true)
        .with_allow_solid_archives(true)
        .with_max_file_count(max_file_count)
}

fn root_cause(error: ArchiveError) -> ArchiveError {
    match error {
        ArchiveError::PartialExtraction { source, .. } => *source,
        other => other,
    }
}

fn assert_file_count(result: Result<impl std::fmt::Debug, ArchiveError>, max: usize) {
    let error = root_cause(result.unwrap_err());
    assert_matches!(
        error,
        ArchiveError::QuotaExceeded {
            resource: QuotaResource::FileCount { max: m, .. }
        } if m == max,
        "got: {error:?}"
    );
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn tar_symlinks_over_the_limit_are_refused() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, "a.tar", &tar_with_symlinks(3));
    let out = dir.path().join("out");

    assert_file_count(extract_archive(&archive, &out, &link_config(2)), 2);
}

#[test]
fn zip_symlinks_over_the_limit_are_refused() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, "a.zip", &zip_with_symlinks(3));
    let out = dir.path().join("out");

    assert_file_count(extract_archive(&archive, &out, &link_config(2)), 2);
}

#[test]
fn sevenz_symlinks_over_the_limit_are_refused_before_any_write() {
    for solid in [false, true] {
        let dir = TempDir::new().unwrap();
        let archive = write_archive(&dir, "a.7z", &sevenz_with_symlinks(3, solid));
        let out = dir.path().join("out");
        std::fs::create_dir(&out).unwrap();

        assert_file_count(extract_archive(&archive, &out, &link_config(2)), 2);
        assert!(names_in(&out).is_empty(), "solid={solid}");
    }
}

#[test]
fn symlinks_at_the_limit_are_extracted() {
    let dir = TempDir::new().unwrap();
    let tar = write_archive(&dir, "a.tar", &tar_with_symlinks(2));
    let zip = write_archive(&dir, "a.zip", &zip_with_symlinks(2));
    let sevenz = write_archive(&dir, "a.7z", &sevenz_with_symlinks(2, false));

    for archive in [tar, zip, sevenz] {
        let out = TempDir::new().unwrap();
        extract_archive(&archive, out.path(), &link_config(2)).unwrap();
        assert_eq!(names_in(out.path()), ["link0", "link1"], "{archive:?}");
    }
}

#[test]
fn list_verify_and_extract_agree_on_a_link_flood() {
    let dir = TempDir::new().unwrap();
    let config = link_config(2);
    let archives = [
        write_archive(&dir, "a.tar", &tar_with_symlinks(3)),
        write_archive(&dir, "a.zip", &zip_with_symlinks(3)),
        write_archive(&dir, "a.7z", &sevenz_with_symlinks(3, false)),
        write_archive(&dir, "solid.7z", &sevenz_with_symlinks(3, true)),
        write_archive(&dir, "hard.tar", &tar_with_file_and_hardlinks(2)),
    ];

    for archive in archives {
        let out = TempDir::new().unwrap();
        assert_file_count(list_archive(&archive, &config), 2);
        assert_file_count(extract_archive(&archive, out.path(), &config), 2);
        let report = verify_archive(&archive, &config);
        match report {
            Ok(report) => assert_eq!(report.status(), VerificationStatus::Fail, "{archive:?}"),
            Err(error) => assert_file_count(Err::<(), _>(error), 2),
        }
    }
}

#[test]
fn tar_hardlink_is_counted_once() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, "a.tar", &tar_with_file_and_hardlinks(1));
    let out = dir.path().join("out");

    let report = extract_archive(&archive, &out, &link_config(2)).unwrap();

    assert_eq!(names_in(&out), ["h0", "t"]);
    assert_eq!(report.files_extracted, 2);
}

#[test]
fn tar_hardlinks_over_the_limit_are_refused_before_any_copy() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, "a.tar", &tar_with_file_and_hardlinks(2));
    let out = dir.path().join("out");

    assert_file_count(extract_archive(&archive, &out, &link_config(2)), 2);
    assert_eq!(names_in(&out), ["t"]);
}

#[test]
fn skipped_duplicate_hardlink_keeps_its_count_slot() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, "a.tar", &tar_with_file_and_hardlinks(1));
    let options = ExtractionOptions::default().with_skip_duplicates(true);

    let out = TempDir::new().unwrap();
    std::fs::write(out.path().join("h0"), b"old").unwrap();
    extract_archive_with_options(&archive, out.path(), &link_config(2), &options).unwrap();
    assert_eq!(std::fs::read(out.path().join("h0")).unwrap(), b"old");

    let out = TempDir::new().unwrap();
    std::fs::write(out.path().join("h0"), b"old").unwrap();
    assert_file_count(
        extract_archive_with_options(&archive, out.path(), &link_config(1), &options),
        1,
    );
}

#[test]
fn a_file_a_symlink_and_a_hardlink_count_together() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, "a.tar", &tar_with_file_symlink_and_hardlink());

    let out = TempDir::new().unwrap();
    extract_archive(&archive, out.path(), &link_config(3)).unwrap();
    assert_eq!(names_in(out.path()), ["h", "s", "t"]);

    let out = TempDir::new().unwrap();
    assert_file_count(extract_archive(&archive, out.path(), &link_config(2)), 2);
}

#[test]
fn a_skipped_duplicate_symlink_keeps_its_count_slot() {
    let dir = TempDir::new().unwrap();
    let options = ExtractionOptions::default().with_skip_duplicates(true);
    let zip = write_archive(&dir, "a.zip", &zip_with_symlinks(2));
    let sevenz = write_archive(&dir, "a.7z", &sevenz_with_symlinks(2, false));

    for archive in [zip, sevenz] {
        for (max, accepted) in [(2, true), (1, false)] {
            let out = TempDir::new().unwrap();
            std::fs::write(out.path().join("link0"), b"old").unwrap();

            let result =
                extract_archive_with_options(&archive, out.path(), &link_config(max), &options);

            if accepted {
                result.unwrap();
            } else {
                assert_file_count(result, max);
            }
        }
    }
}

#[test]
fn sevenz_policy_and_target_errors_win_over_the_file_count() {
    let dir = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    let archive = write_archive(&dir, "a.7z", &sevenz_with_symlinks(3, false));
    let disallowed = SecurityConfig::default().with_max_file_count(1);
    assert_matches!(
        extract_archive(&archive, out.path(), &disallowed),
        Err(ArchiveError::SecurityViolation { reason }) if reason.contains("symlinks not allowed")
    );
    assert!(names_in(out.path()).is_empty());

    let cases = [
        (vec![b'a'; 70_000], "symlink target too large"),
        (Vec::new(), "symlink target is empty"),
    ];
    for (target, expect) in cases {
        let archive = write_archive(
            &dir,
            "targets.7z",
            &sevenz_with_targets(&[b"target".to_vec(), target]),
        );
        let out = TempDir::new().unwrap();

        let error = extract_archive(
            &archive,
            out.path(),
            &link_config(1).with_max_compression_ratio(10_000.0),
        )
        .unwrap_err();

        assert!(error.to_string().contains(expect), "{expect}: {error}");
        assert!(names_in(out.path()).is_empty(), "{expect}");
    }
}
