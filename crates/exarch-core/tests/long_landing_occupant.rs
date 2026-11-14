//! A directory entry over a file is the typed `DestinationOccupied` refusal
//! even when the host path of the landing is past `PATH_MAX`, where a lookup
//! by path fails with `InvalidFilename` instead of finding the occupant
//! (#1193).

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

use std::assert_matches;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::ErrorCode;
use exarch_core::ExistingFiles;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::OccupiedBy;
use exarch_core::PathOccupant;
use exarch_core::SecurityConfig;
use tempfile::TempDir;

/// The longest entry path the platform admits once a directory entry adds its
/// trailing separator, so that any destination in front of it takes the host
/// path past `PATH_MAX`.
const ENTRY_LEN: usize = if cfg!(target_os = "macos") {
    1022
} else {
    4094
};

fn long_entry() -> String {
    let mut name = String::new();
    while name.len() < ENTRY_LEN {
        if !name.is_empty() {
            name.push('/');
        }
        let room = ENTRY_LEN - name.len();
        name.push_str(&"n".repeat(room.min(200)));
    }
    assert_eq!(name.len(), ENTRY_LEN);
    name
}

fn tar_of(entries: &[(&str, tar::EntryType)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, kind) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(*kind);
        header.set_mode(0o644);
        let data: &[u8] = if kind.is_file() { b"ok" } else { b"" };
        header.set_size(data.len() as u64);
        header.set_cksum();
        builder.append_data(&mut header, name, data).unwrap();
    }
    builder.into_inner().unwrap()
}

fn write_archive(dir: &TempDir, name: &str, entries: &[(&str, tar::EntryType)]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, tar_of(entries)).unwrap();
    path
}

fn extract_refusing(archive: &Path, dest: &Path) -> Result<(), ArchiveError> {
    ExtractRequest::new(&SecurityConfig::default())
        .with_options(ExtractionOptions::default().with_existing_files(ExistingFiles::Refuse))
        .extract(archive, dest)
        .map(drop)
}

fn assert_refused_as_a_file(error: &ArchiveError, expected_by: OccupiedBy, entry: &str) {
    let error = match error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    };
    assert_matches!(
        error,
        ArchiveError::DestinationOccupied { by, conflicts, .. }
            if *by == expected_by
                && matches!(
                    &conflicts[..],
                    [conflict] if conflict.path == Path::new(entry)
                        && conflict.occupant == Some(PathOccupant::File)
                ),
        "{error}"
    );
    assert_eq!(error.error_code(), ErrorCode::OutputExists);
}

#[test]
fn a_directory_over_a_file_is_typed_past_path_max() {
    let entry = long_entry();
    let work = TempDir::new().unwrap();
    let dir_entry = format!("{entry}/");
    let archive = write_archive(
        &work,
        "a.tar",
        &[
            (&entry, tar::EntryType::Regular),
            (&dir_entry, tar::EntryType::Directory),
        ],
    );
    let out = TempDir::new().unwrap();

    let error = extract_refusing(&archive, out.path()).unwrap_err();

    assert_refused_as_a_file(&error, OccupiedBy::Archive, &entry);
}
