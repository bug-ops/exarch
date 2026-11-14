//! A file at a directory landing and a directory at a file landing are one
//! typed refusal, `DestinationOccupied` naming the entry and the kind of its
//! occupant, on every surface: the host write phase (in place and staged), the
//! in-memory sink, the list model and the destination pre-check (#1181,
//! #1183, #1184).

#![allow(clippy::unwrap_used, clippy::needless_pass_by_value)]
#![allow(clippy::disallowed_methods)]

mod sink_support;

use std::io::Cursor;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::DecodeReuse;
use exarch_core::DestinationCheck;
use exarch_core::DispositionKind;
use exarch_core::ExistingFiles;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::ListRequest;
use exarch_core::OccupiedBy;
use exarch_core::PathOccupant;
use exarch_core::SecurityConfig;
use exarch_core::SeekableFormat;
use exarch_core::SinkExtractRequest;
use exarch_core::SinkOptions;
use exarch_core::Staging;
use sink_support::RecordingSink;
use sink_support::tar_archive;
use sink_support::tar_dir;
use sink_support::tar_file;
use sink_support::zip_archive;
use sink_support::zip_dir;
use sink_support::zip_file;
use tempfile::TempDir;

#[derive(Clone, Copy, Debug)]
enum Format {
    Tar,
    Zip,
    SevenZ,
}

const ALL_FORMATS: [Format; 3] = [Format::Tar, Format::Zip, Format::SevenZ];
const STREAMED_FORMATS: [Format; 2] = [Format::Tar, Format::Zip];
const ALL_POLICIES: [ExistingFiles; 3] = [
    ExistingFiles::Skip,
    ExistingFiles::Refuse,
    ExistingFiles::Overwrite,
];
const REFUSING_POLICIES: [ExistingFiles; 2] = [ExistingFiles::Refuse, ExistingFiles::Overwrite];

#[derive(Clone, Copy)]
enum Member {
    File(&'static str),
    Dir(&'static str),
}

fn archive_bytes(format: Format, members: &[Member]) -> Vec<u8> {
    match format {
        Format::Tar => tar_archive(
            &members
                .iter()
                .map(|member| match member {
                    Member::File(name) => tar_file(name, b"x"),
                    Member::Dir(name) => tar_dir(name),
                })
                .collect::<Vec<_>>(),
        ),
        Format::Zip => zip_archive(
            members
                .iter()
                .map(|member| match member {
                    Member::File(name) => zip_file(name, b"x"),
                    Member::Dir(name) => zip_dir(name),
                })
                .collect(),
        ),
        Format::SevenZ => sevenz_bytes(members),
    }
}

fn sevenz_bytes(members: &[Member]) -> Vec<u8> {
    use sevenz_rust2::ArchiveEntry;
    use sevenz_rust2::ArchiveWriter;

    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    for member in members {
        match member {
            Member::File(name) => {
                let mut entry = ArchiveEntry::new_file(name);
                entry.has_stream = true;
                entry.size = 1;
                writer.push_archive_entry(entry, Some(&b"x"[..])).unwrap();
            }
            Member::Dir(name) => {
                let entry = ArchiveEntry::new_directory(name.trim_end_matches('/'));
                writer.push_archive_entry::<&[u8]>(entry, None).unwrap();
            }
        }
    }
    writer.finish().unwrap().into_inner()
}

fn write_archive(format: Format, members: &[Member]) -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let name = match format {
        Format::Tar => "a.tar",
        Format::Zip => "a.zip",
        Format::SevenZ => "a.7z",
    };
    let path = dir.path().join(name);
    std::fs::write(&path, archive_bytes(format, members)).unwrap();
    (dir, path)
}

fn config(allow_symlinks: bool) -> SecurityConfig {
    SecurityConfig::default().with_allow_symlinks(allow_symlinks)
}

fn cause(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction(partial) => partial.cause(),
        other => other,
    }
}

fn host(
    format: Format,
    members: &[Member],
    dest: &Path,
    policy: ExistingFiles,
    staging: Staging,
    config: &SecurityConfig,
) -> Result<(), ArchiveError> {
    let (_dir, archive) = write_archive(format, members);
    ExtractRequest::new(config)
        .with_options(
            ExtractionOptions::default()
                .with_existing_files(policy)
                .with_staging(staging),
        )
        .extract(&archive, dest)
        .map(drop)
}

fn sink(
    format: Format,
    members: &[Member],
    policy: ExistingFiles,
    config: &SecurityConfig,
) -> Result<(), ArchiveError> {
    let bytes = archive_bytes(format, members);
    let reader = match format {
        Format::Tar => ArchiveReader::tar(Cursor::new(bytes), None),
        Format::Zip => ArchiveReader::seekable(Cursor::new(bytes), SeekableFormat::Zip),
        Format::SevenZ => ArchiveReader::seekable(Cursor::new(bytes), SeekableFormat::SevenZ),
    };
    let mut recorder = RecordingSink::default();
    SinkExtractRequest::new(config)
        .with_options(SinkOptions::default().with_existing_files(policy))
        .extract(reader, &mut recorder)
        .map(drop)
}

fn list_dispositions(
    format: Format,
    members: &[Member],
    config: &SecurityConfig,
) -> Vec<DispositionKind> {
    let (_dir, archive) = write_archive(format, members);
    let listed = ListRequest::new(config)
        .for_extraction(&archive, DecodeReuse::default())
        .unwrap();
    listed
        .manifest()
        .dispositions(config)
        .map(|(_, disposition)| disposition.kind())
        .collect()
}

fn assert_list_refuses_the_second_entry(
    format: Format,
    members: &[Member],
    config: &SecurityConfig,
    context: &str,
) {
    assert_eq!(
        list_dispositions(format, members, config),
        [DispositionKind::Extract, DispositionKind::Refuse],
        "{context}: list model"
    );
}

fn pre_check(
    format: Format,
    members: &[Member],
    dest: &Path,
    check: DestinationCheck,
    config: &SecurityConfig,
) -> Result<(), ArchiveError> {
    let (_dir, archive) = write_archive(format, members);
    ListRequest::new(config)
        .for_extraction(&archive, DecodeReuse::default())
        .unwrap()
        .check_destination(dest, check)
}

fn refusal(result: Result<(), ArchiveError>, context: &str) -> ArchiveError {
    match result {
        Ok(()) => panic!("{context}: expected a refusal, got success"),
        Err(error) => error,
    }
}

/// Asserts a single-conflict `DestinationOccupied` and returns its destination.
fn assert_occupied(
    error: &ArchiveError,
    path: &str,
    occupant: PathOccupant,
    by: OccupiedBy,
    context: &str,
) -> Option<PathBuf> {
    let ArchiveError::DestinationOccupied {
        destination,
        conflicts,
        by: seen_by,
    } = cause(error)
    else {
        panic!("{context}: expected DestinationOccupied, got {error}");
    };
    assert_eq!(conflicts.len(), 1, "{context}: {error}");
    assert_eq!(conflicts[0].path, Path::new(path), "{context}");
    assert_eq!(conflicts[0].occupant, Some(occupant), "{context}");
    assert_eq!(*seen_by, by, "{context}");
    destination.clone()
}

fn assert_caller_destination(seen: Option<PathBuf>, caller: &Path, context: &str) {
    let seen = seen.unwrap_or_else(|| panic!("{context}: the destination is missing"));
    assert_eq!(
        std::fs::canonicalize(&seen).unwrap(),
        std::fs::canonicalize(caller).unwrap(),
        "{context}: {}",
        seen.display()
    );
}

#[test]
fn dir_over_a_preexisting_file_is_one_typed_refusal_in_the_write_phase_and_the_pre_check() {
    for format in ALL_FORMATS {
        for policy in ALL_POLICIES {
            for allow_symlinks in [false, true] {
                let context = format!("{format:?} {policy:?} symlinks={allow_symlinks}");
                let config = config(allow_symlinks);
                let members = [Member::Dir("f/")];
                let dest = TempDir::new().unwrap();
                std::fs::write(dest.path().join("f"), b"keep").unwrap();

                let written = refusal(
                    host(
                        format,
                        &members,
                        dest.path(),
                        policy,
                        Staging::InPlace,
                        &config,
                    ),
                    &context,
                );
                let seen = assert_occupied(
                    &written,
                    "f",
                    PathOccupant::File,
                    OccupiedBy::Existing,
                    &context,
                );
                assert_caller_destination(seen, dest.path(), &context);
                assert_eq!(std::fs::read(dest.path().join("f")).unwrap(), b"keep");

                for check in [DestinationCheck::Vacant, DestinationCheck::Replaceable] {
                    let checked = refusal(
                        pre_check(format, &members, dest.path(), check, &config),
                        &context,
                    );
                    assert_occupied(
                        &checked,
                        "f",
                        PathOccupant::File,
                        OccupiedBy::Existing,
                        &format!("{context} {check:?}"),
                    );
                }
            }
        }
    }
}

#[test]
fn dir_over_a_file_of_the_run_is_one_typed_refusal_on_every_surface() {
    let members = [Member::File("f"), Member::Dir("f/")];
    for format in STREAMED_FORMATS {
        for policy in ALL_POLICIES {
            for allow_symlinks in [false, true] {
                let context = format!("{format:?} {policy:?} symlinks={allow_symlinks}");
                let config = config(allow_symlinks);

                let dest = TempDir::new().unwrap();
                let written = refusal(
                    host(
                        format,
                        &members,
                        dest.path(),
                        policy,
                        Staging::InPlace,
                        &config,
                    ),
                    &context,
                );
                // Skip keeps no run record, so the maker of the file is
                // unknown.
                let maker = if policy == ExistingFiles::Skip {
                    OccupiedBy::Existing
                } else {
                    OccupiedBy::Archive
                };
                let seen = assert_occupied(&written, "f", PathOccupant::File, maker, &context);
                assert_caller_destination(seen, dest.path(), &context);

                let sunk = refusal(sink(format, &members, policy, &config), &context);
                let seen = assert_occupied(
                    &sunk,
                    "f",
                    PathOccupant::File,
                    OccupiedBy::Archive,
                    &context,
                );
                assert_eq!(seen, None, "{context}: the sink has no host destination");

                assert_list_refuses_the_second_entry(format, &members, &config, &context);
            }
        }
    }
}

#[test]
fn a_staged_run_names_the_callers_destination_not_a_staging_path() {
    let members = [Member::File("f"), Member::Dir("f/")];
    for format in STREAMED_FORMATS {
        let config = config(false);

        let root = TempDir::new().unwrap();
        let fresh = root.path().join("fresh");
        let atomic = refusal(
            host(
                format,
                &members,
                &fresh,
                ExistingFiles::Refuse,
                Staging::Atomic,
                &config,
            ),
            &format!("{format:?} atomic"),
        );
        let seen = assert_occupied(
            &atomic,
            "f",
            PathOccupant::File,
            OccupiedBy::Archive,
            "atomic",
        );
        let seen = seen.unwrap();
        assert_eq!(seen.file_name(), fresh.file_name(), "{seen:?}");
        assert!(!fresh.exists());

        let existing = root.path().join("existing");
        std::fs::create_dir(&existing).unwrap();
        std::fs::write(existing.join("keep"), b"keep").unwrap();
        let replace = refusal(
            host(
                format,
                &members,
                &existing,
                ExistingFiles::Refuse,
                Staging::AtomicReplace,
                &config,
            ),
            &format!("{format:?} atomic replace"),
        );
        let seen = assert_occupied(
            &replace,
            "f",
            PathOccupant::File,
            OccupiedBy::Archive,
            "atomic replace",
        );
        assert_caller_destination(seen, &existing, "atomic replace");
        assert_eq!(std::fs::read(existing.join("keep")).unwrap(), b"keep");
    }
}

#[test]
fn file_over_a_preexisting_directory_names_the_directory_in_the_write_phase_and_the_pre_check() {
    for format in ALL_FORMATS {
        for policy in REFUSING_POLICIES {
            let context = format!("{format:?} {policy:?}");
            let config = config(false);
            let members = [Member::File("d")];
            let dest = TempDir::new().unwrap();
            std::fs::create_dir(dest.path().join("d")).unwrap();

            let written = refusal(
                host(
                    format,
                    &members,
                    dest.path(),
                    policy,
                    Staging::InPlace,
                    &config,
                ),
                &context,
            );
            let seen = assert_occupied(
                &written,
                "d",
                PathOccupant::Directory,
                OccupiedBy::Existing,
                &context,
            );
            assert_caller_destination(seen, dest.path(), &context);
            assert!(dest.path().join("d").is_dir());

            for check in [DestinationCheck::Vacant, DestinationCheck::Replaceable] {
                let checked = refusal(
                    pre_check(format, &members, dest.path(), check, &config),
                    &context,
                );
                assert_occupied(
                    &checked,
                    "d",
                    PathOccupant::Directory,
                    OccupiedBy::Existing,
                    &format!("{context} {check:?}"),
                );
            }
        }
    }
}

#[test]
fn file_over_a_directory_of_the_run_names_the_directory_on_every_surface() {
    let members = [Member::Dir("d/"), Member::File("d")];
    for format in STREAMED_FORMATS {
        for policy in REFUSING_POLICIES {
            let context = format!("{format:?} {policy:?}");
            let config = config(false);

            let dest = TempDir::new().unwrap();
            let written = refusal(
                host(
                    format,
                    &members,
                    dest.path(),
                    policy,
                    Staging::InPlace,
                    &config,
                ),
                &context,
            );
            let seen = assert_occupied(
                &written,
                "d",
                PathOccupant::Directory,
                OccupiedBy::Archive,
                &context,
            );
            assert_caller_destination(seen, dest.path(), &context);

            let sunk = refusal(sink(format, &members, policy, &config), &context);
            let seen = assert_occupied(
                &sunk,
                "d",
                PathOccupant::Directory,
                OccupiedBy::Archive,
                &context,
            );
            assert_eq!(seen, None, "{context}");

            assert_list_refuses_the_second_entry(format, &members, &config, &context);
        }
    }
}

#[test]
fn a_pre_check_over_mixed_occupants_names_each_kind_in_path_order() {
    let members = [Member::File("a"), Member::Dir("b/")];
    let dest = TempDir::new().unwrap();
    std::fs::create_dir(dest.path().join("a")).unwrap();
    std::fs::write(dest.path().join("b"), b"keep").unwrap();

    let error = refusal(
        pre_check(
            Format::Tar,
            &members,
            dest.path(),
            DestinationCheck::Replaceable,
            &config(false),
        ),
        "mixed",
    );

    let ArchiveError::DestinationOccupied { conflicts, by, .. } = &error else {
        panic!("expected DestinationOccupied, got {error}");
    };
    assert_eq!(*by, OccupiedBy::Existing);
    let seen: Vec<_> = conflicts
        .iter()
        .map(|conflict| (conflict.path.as_path(), conflict.occupant))
        .collect();
    assert_eq!(
        seen,
        [
            (Path::new("a"), Some(PathOccupant::Directory)),
            (Path::new("b"), Some(PathOccupant::File)),
        ]
    );
    assert!(
        error
            .to_string()
            .ends_with("already holds 2 of the paths to extract, first: directory at a"),
        "{error}"
    );
}

#[test]
fn a_sevenz_pre_pass_names_the_callers_destination_for_each_occupant() {
    let config = config(false);
    let dest = TempDir::new().unwrap();
    std::fs::write(dest.path().join("f"), b"keep").unwrap();
    std::fs::create_dir(dest.path().join("d")).unwrap();

    for (policy, member, name, occupant) in [
        (
            ExistingFiles::Refuse,
            Member::File("f"),
            "f",
            PathOccupant::File,
        ),
        (
            ExistingFiles::Overwrite,
            Member::File("d"),
            "d",
            PathOccupant::Directory,
        ),
    ] {
        let context = format!("7z {policy:?} {name}");
        let written = refusal(
            host(
                Format::SevenZ,
                &[member],
                dest.path(),
                policy,
                Staging::InPlace,
                &config,
            ),
            &context,
        );
        let seen = assert_occupied(&written, name, occupant, OccupiedBy::Existing, &context);
        assert_caller_destination(seen, dest.path(), &context);
    }
}

#[test]
fn a_staged_sevenz_run_names_the_callers_destination_not_a_staging_path() {
    let members = [Member::File("f"), Member::Dir("f")];
    let config = config(false);
    let root = TempDir::new().unwrap();

    let fresh = root.path().join("fresh");
    let atomic = refusal(
        host(
            Format::SevenZ,
            &members,
            &fresh,
            ExistingFiles::Refuse,
            Staging::Atomic,
            &config,
        ),
        "7z atomic",
    );
    let seen = assert_occupied(
        &atomic,
        "f",
        PathOccupant::File,
        OccupiedBy::Archive,
        "7z atomic",
    )
    .unwrap();
    assert_eq!(seen.file_name(), fresh.file_name(), "{seen:?}");
    assert!(!fresh.exists());

    let existing = root.path().join("existing");
    std::fs::create_dir(&existing).unwrap();
    std::fs::write(existing.join("keep"), b"keep").unwrap();
    let replace = refusal(
        host(
            Format::SevenZ,
            &members,
            &existing,
            ExistingFiles::Refuse,
            Staging::AtomicReplace,
            &config,
        ),
        "7z atomic replace",
    );
    let seen = assert_occupied(
        &replace,
        "f",
        PathOccupant::File,
        OccupiedBy::Archive,
        "7z atomic replace",
    );
    assert_caller_destination(seen, &existing, "7z atomic replace");
    assert_eq!(std::fs::read(existing.join("keep")).unwrap(), b"keep");
}
