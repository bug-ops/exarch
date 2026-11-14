//! `SafePath` validation of a directory entry spelled with a trailing
//! separator judges the link the entry names, not the path below it (#1186).
//!
//! A link to a file inside the destination passes validation and is refused
//! later as an existing symlink; a link that leaves the destination is a path
//! traversal on every OS; an absolute entry is judged at its stripped place
//! under the destination.

#![cfg(unix)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

use std::assert_matches;
use std::os::unix::fs::symlink;
use std::path::Path;

use exarch_core::ArchiveError;
use exarch_core::DestDir;
use exarch_core::SafePath;
use exarch_core::SecurityConfig;
use tempfile::TempDir;

struct Fixture {
    _root: TempDir,
    dest: DestDir,
    outside: std::path::PathBuf,
}

fn fixture() -> Fixture {
    let root = TempDir::new().unwrap();
    let dest_path = std::fs::canonicalize(root.path()).unwrap().join("dest");
    let outside = std::fs::canonicalize(root.path()).unwrap().join("outside");
    std::fs::create_dir(&dest_path).unwrap();
    std::fs::create_dir(&outside).unwrap();
    let dest = DestDir::new(dest_path).unwrap();
    Fixture {
        _root: root,
        dest,
        outside,
    }
}

fn config() -> SecurityConfig {
    SecurityConfig::default().with_allow_symlinks(true)
}

#[test]
fn validate_a_trailing_separator_over_a_link_to_a_file_inside_the_destination_passes() {
    let fixture = fixture();
    std::fs::write(fixture.dest.as_path().join("f"), b"x").unwrap();
    symlink("f", fixture.dest.as_path().join("l")).unwrap();

    let path = SafePath::validate(Path::new("l/"), &fixture.dest, &config());

    assert_matches!(path, Ok(_), "{path:?}");
}

#[test]
fn validate_a_trailing_separator_over_a_link_to_a_directory_inside_the_destination_passes() {
    let fixture = fixture();
    std::fs::create_dir(fixture.dest.as_path().join("d")).unwrap();
    symlink("d", fixture.dest.as_path().join("l")).unwrap();

    let path = SafePath::validate(Path::new("l/"), &fixture.dest, &config());

    assert_matches!(path, Ok(_), "{path:?}");
}

#[test]
fn validate_a_trailing_separator_over_a_link_to_an_outside_directory_escapes() {
    let fixture = fixture();
    symlink(&fixture.outside, fixture.dest.as_path().join("l")).unwrap();

    let path = SafePath::validate(Path::new("l/"), &fixture.dest, &config());

    assert_matches!(path, Err(ArchiveError::PathTraversal { .. }), "{path:?}");
}

#[test]
fn validate_a_trailing_separator_over_a_link_to_an_outside_file_escapes_not_io() {
    let fixture = fixture();
    let file = fixture.outside.join("f");
    std::fs::write(&file, b"x").unwrap();
    symlink(&file, fixture.dest.as_path().join("l")).unwrap();

    let path = SafePath::validate(Path::new("l/"), &fixture.dest, &config());

    assert_matches!(path, Err(ArchiveError::PathTraversal { .. }), "{path:?}");
}

#[test]
fn validate_an_absolute_directory_entry_is_judged_under_the_destination() {
    let fixture = fixture();
    let host_file = fixture.outside.join("f");
    std::fs::write(&host_file, b"x").unwrap();
    let entry = format!("{}/", host_file.display());
    let config = config().with_allow_absolute_paths(true);

    let path = SafePath::validate(Path::new(&entry), &fixture.dest, &config).unwrap();

    assert!(!path.as_path().is_absolute(), "{:?}", path.as_path());
    assert!(
        path.as_path().ends_with("outside/f"),
        "{:?}",
        path.as_path()
    );
    assert_eq!(
        std::fs::read(&host_file).unwrap(),
        b"x",
        "the host file is untouched"
    );
}
