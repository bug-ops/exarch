//! Acceptance contract of #1198 and the core part of #1197: a non-empty list of
//! occupied paths, one `occupancy()` accessor for the occupancy detail, the
//! maker on every existing-symlink violation, and a closed `DestinationStep`
//! whose tokens reach the FFI detail.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::ClosedEnum;
use exarch_core::DestinationStep;
use exarch_core::ExtractionReport;
use exarch_core::FfiDetail;
use exarch_core::OccupancyDetail;
use exarch_core::OccupiedBy;
use exarch_core::OccupiedPath;
use exarch_core::OccupiedPaths;
use exarch_core::Partial;
use exarch_core::PartialWrites;
use exarch_core::PathOccupant;
use exarch_core::Violation;

fn path(name: &str, occupant: Option<PathOccupant>) -> OccupiedPath {
    OccupiedPath::new(PathBuf::from(name), occupant)
}

fn occupied(by: OccupiedBy) -> ArchiveError {
    ArchiveError::DestinationOccupied {
        destination: None,
        conflicts: OccupiedPaths::from_vec(vec![
            path("a", Some(PathOccupant::File)),
            path("b", Some(PathOccupant::Directory)),
        ])
        .unwrap(),
        by,
    }
}

#[test]
fn occupied_paths_from_vec_empty_is_none() {
    assert!(OccupiedPaths::from_vec(Vec::new()).is_none());
}

#[test]
fn occupied_paths_from_vec_keeps_order_and_counts_every_path() {
    let paths = OccupiedPaths::from_vec(vec![
        path("c", None),
        path("a", Some(PathOccupant::Symlink)),
        path("b", Some(PathOccupant::File)),
    ])
    .unwrap();

    assert_eq!(paths.len().get(), 3);
    let seen: Vec<_> = paths.iter().map(|p| p.path.to_str().unwrap()).collect();
    assert_eq!(seen, ["c", "a", "b"]);
}

#[test]
fn occupied_paths_one_holds_exactly_that_path() {
    let paths = OccupiedPaths::one(path("only", Some(PathOccupant::Directory)));

    assert_eq!(paths.len().get(), 1);
    let first = paths.iter().next().unwrap();
    assert_eq!(first.path, PathBuf::from("only"));
    assert_eq!(first.occupant, Some(PathOccupant::Directory));
    assert_eq!(paths.iter().count(), 1);
}

#[test]
fn occupancy_destination_occupied_names_conflicts_and_maker() {
    for by in [OccupiedBy::Existing, OccupiedBy::Archive] {
        let error = occupied(by);

        let Some(OccupancyDetail::Occupied {
            conflicts,
            by: seen,
        }) = error.occupancy()
        else {
            panic!("expected the occupied detail");
        };
        assert_eq!(seen, by);
        assert_eq!(conflicts.len().get(), 2);
    }
}

#[test]
fn occupancy_existing_symlink_violations_carry_the_maker() {
    for by in [OccupiedBy::Existing, OccupiedBy::Archive] {
        let violations = [
            Violation::ReplacesSymlink {
                rel: "l".into(),
                by,
            },
            Violation::SymlinkParent {
                entry: "d/e/f".into(),
                parent: "d".into(),
                by,
            },
            Violation::SymlinkComponent {
                walked: "d".into(),
                by,
            },
        ];
        for violation in violations {
            let error: ArchiveError = violation.into();

            assert!(
                matches!(
                    error.occupancy(),
                    Some(OccupancyDetail::ExistingSymlink { by: seen }) if seen == by
                ),
                "{error}"
            );
            assert_eq!(
                error.into_ffi_message().detail,
                FfiDetail::ExistingSymlink { by }
            );
        }
    }
}

#[test]
fn occupancy_looks_through_a_partial_extraction() {
    let wrapped = ArchiveError::PartialExtraction(Partial::new(
        occupied(OccupiedBy::Archive),
        ExtractionReport::default(),
        PartialWrites::Kept,
    ));

    assert!(matches!(
        wrapped.occupancy(),
        Some(OccupancyDetail::Occupied {
            by: OccupiedBy::Archive,
            ..
        })
    ));
}

#[test]
fn occupancy_is_none_for_errors_without_occupant_detail() {
    let errors = [
        ArchiveError::PathTraversal {
            path: "../x".into(),
        },
        Violation::LinkTargetUnreadable(exarch_core::LinkKind::Symlink).into(),
        ArchiveError::Cancelled,
    ];
    for error in errors {
        assert!(error.occupancy().is_none(), "{error}");
    }
}

#[test]
fn destination_step_names_are_the_stable_tokens_in_declaration_order() {
    assert_eq!(
        DestinationStep::NAMES,
        &["resolve", "create", "open", "list", "write_access", "stage"]
    );
    assert_eq!(DestinationStep::ALL.len(), DestinationStep::NAMES.len());
}

#[test]
fn destination_step_display_is_the_token() {
    for step in DestinationStep::ALL {
        assert_eq!(step.to_string(), step.as_str());
    }
}

#[test]
fn destination_not_accessible_ffi_detail_carries_the_step() {
    for step in DestinationStep::ALL {
        let error = ArchiveError::DestinationNotAccessible {
            path: PathBuf::from("dest"),
            step: *step,
            error: std::io::Error::from_raw_os_error(2),
        };

        assert_eq!(
            error.into_ffi_message().detail,
            FfiDetail::Destination { step: *step }
        );
    }
}
