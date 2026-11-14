//! The typed shape of an occupied-path refusal (#1183): each conflict carries
//! its occupant kind, the symlink refusal carries the maker, and the text and
//! the binding detail name the occupant.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

use std::assert_matches;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::ErrorCode;
use exarch_core::FfiDetail;
use exarch_core::FfiKind;
use exarch_core::OccupiedBy;
use exarch_core::OccupiedPath;
use exarch_core::PathOccupant;
use exarch_core::SecurityViolationSubCode;
use exarch_core::Violation;

fn occupied(
    destination: Option<&str>,
    conflicts: &[(&str, Option<PathOccupant>)],
    by: OccupiedBy,
) -> ArchiveError {
    ArchiveError::DestinationOccupied {
        destination: destination.map(PathBuf::from),
        conflicts: conflicts
            .iter()
            .map(|(path, occupant)| OccupiedPath::new(PathBuf::from(path), *occupant))
            .collect(),
        by,
    }
}

#[test]
fn occupied_path_new_keeps_the_path_and_the_occupant() {
    let known = OccupiedPath::new(PathBuf::from("a/b"), Some(PathOccupant::Directory));
    assert_eq!(known.path, PathBuf::from("a/b"));
    assert_eq!(known.occupant, Some(PathOccupant::Directory));

    let vanished = OccupiedPath::new(PathBuf::from("c"), None);
    assert_eq!(vanished.occupant, None);
}

#[test]
fn path_occupant_as_str_names_the_kind() {
    for (occupant, noun) in [
        (PathOccupant::File, "file"),
        (PathOccupant::Directory, "directory"),
        (PathOccupant::Symlink, "symlink"),
    ] {
        assert_eq!(occupant.as_str(), noun);
    }
}

#[test]
fn destination_occupied_one_conflict_names_the_occupant_at_the_entry() {
    for (occupant, noun) in [
        (Some(PathOccupant::File), "file"),
        (Some(PathOccupant::Directory), "directory"),
        (Some(PathOccupant::Symlink), "symlink"),
        (None, "entry"),
    ] {
        let error = occupied(None, &[("a/b", occupant)], OccupiedBy::Existing);
        let expected = format!("refusing to replace the existing {noun} at a/b");
        assert_eq!(error.to_string(), expected);
        assert_eq!(error.into_ffi_message().description, expected);
    }
}

#[test]
fn destination_occupied_one_conflict_leads_with_the_destination() {
    let error = occupied(
        Some("/srv/dest"),
        &[("a", Some(PathOccupant::File))],
        OccupiedBy::Existing,
    );
    assert_eq!(
        error.to_string(),
        "destination /srv/dest: refusing to replace the existing file at a"
    );
}

#[test]
fn destination_occupied_many_conflicts_count_them_and_name_the_first() {
    let error = occupied(
        Some("/srv/dest"),
        &[
            ("a", Some(PathOccupant::Directory)),
            ("b", Some(PathOccupant::File)),
        ],
        OccupiedBy::Existing,
    );
    assert_eq!(
        error.to_string(),
        "destination /srv/dest already holds 2 of the paths to extract, first: directory at a"
    );

    let none = occupied(
        None,
        &[("a", None), ("b", Some(PathOccupant::File))],
        OccupiedBy::Existing,
    );
    assert!(
        none.to_string()
            .ends_with("already holds 2 of the paths to extract, first: entry at a"),
        "{none}"
    );
}

#[test]
fn destination_occupied_ffi_detail_carries_each_occupant_and_the_maker() {
    let error = occupied(
        None,
        &[
            ("a", Some(PathOccupant::Directory)),
            ("b", Some(PathOccupant::File)),
            ("c", None),
        ],
        OccupiedBy::Archive,
    );
    assert_eq!(error.error_code(), ErrorCode::OutputExists);

    let FfiDetail::Occupied { conflicts, by } = error.into_ffi_message().detail else {
        panic!("expected the occupied detail");
    };
    assert_eq!(by, OccupiedBy::Archive);
    let seen: Vec<_> = conflicts
        .iter()
        .map(|conflict| (conflict.path.as_str(), conflict.occupant))
        .collect();
    assert_eq!(
        seen,
        [
            ("a", Some(PathOccupant::Directory)),
            ("b", Some(PathOccupant::File)),
            ("c", None),
        ]
    );
}

#[test]
fn replaces_symlink_carries_the_maker_into_the_ffi_detail() {
    for by in [OccupiedBy::Existing, OccupiedBy::Archive] {
        assert_replaces_symlink_detail(by);
    }
}

fn assert_replaces_symlink_detail(by: OccupiedBy) {
    let error: ArchiveError = Violation::ReplacesSymlink {
        rel: "l".into(),
        by,
    }
    .into();

    assert_eq!(
        error.to_string(),
        "operation denied by security policy: refusing to replace the existing symlink at l"
    );
    assert_matches!(
        error.ffi_kind(),
        FfiKind::SecurityViolation {
            sub_code: SecurityViolationSubCode::ExistingSymlink,
            ..
        }
    );
    assert_eq!(
        error.into_ffi_message().detail,
        FfiDetail::ExistingSymlink { by }
    );
}

#[test]
fn replaces_symlink_detail_survives_a_partial_extraction() {
    use exarch_core::ExtractionReport;
    use exarch_core::Partial;
    use exarch_core::PartialWrites;

    let cause: ArchiveError = Violation::ReplacesSymlink {
        rel: "l".into(),
        by: OccupiedBy::Archive,
    }
    .into();
    let wrapped = ArchiveError::PartialExtraction(Partial::new(
        cause,
        ExtractionReport::default(),
        PartialWrites::Kept,
    ));

    let message = wrapped.into_ffi_message();
    assert_eq!(
        message.detail,
        FfiDetail::ExistingSymlink {
            by: OccupiedBy::Archive
        }
    );
    assert!(message.partial.is_some());
}

#[test]
fn destination_occupied_ffi_detail_survives_a_partial_extraction() {
    use exarch_core::ExtractionReport;
    use exarch_core::Partial;
    use exarch_core::PartialWrites;

    let cause = occupied(
        None,
        &[("d", Some(PathOccupant::Directory))],
        OccupiedBy::Existing,
    );
    let wrapped = ArchiveError::PartialExtraction(Partial::new(
        cause,
        ExtractionReport::default(),
        PartialWrites::Kept,
    ));

    let FfiDetail::Occupied { conflicts, .. } = wrapped.into_ffi_message().detail else {
        panic!("expected the occupied detail");
    };
    assert_eq!(conflicts[0].occupant, Some(PathOccupant::Directory));
}
