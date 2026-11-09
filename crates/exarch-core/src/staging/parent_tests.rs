use std::os::unix::fs::symlink;
use std::path::Path;
use std::path::PathBuf;

use tempfile::TempDir;

use super::AtomicDestination;
use super::StagedOutputKind;
use super::StagingPlace;
use super::replace::locate;
use super::staging_place;
use crate::STAGING_PREFIX;
use crate::creation::staged::StagedOutput;
use crate::request::Durability;
use crate::request::OutputPolicy;

fn directory_place(output: &Path) -> StagingPlace {
    staging_place(output, StagedOutputKind::Directory).unwrap()
}

fn assert_matches_atomic(output: &Path) {
    let place = directory_place(output);
    let atomic = AtomicDestination::resolve(output).unwrap();
    assert_eq!(place.parent(), atomic.parent);
    assert_eq!(place.target(), atomic.parent.join(&atomic.name));
}

fn assert_matches_replace(output: &Path) {
    let place = directory_place(output);
    let (parent, name) = locate(output).unwrap().unwrap();
    assert_eq!(place.parent(), parent.canonicalize().unwrap());
    assert_eq!(place.target(), parent.canonicalize().unwrap().join(&name));
}

fn scratch() -> (TempDir, PathBuf) {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    (tmp, root)
}

#[test]
fn an_existing_directory_matches_both_directory_resolvers() {
    let (_tmp, root) = scratch();
    let out = root.join("out");
    std::fs::create_dir(&out).unwrap();
    assert_matches_atomic(&out);
    assert_matches_replace(&out);
    assert_eq!(directory_place(&out).parent(), root);
}

#[test]
fn a_trailing_parent_component_names_the_directory_it_reaches() {
    let (_tmp, root) = scratch();
    std::fs::create_dir_all(root.join("a/b")).unwrap();
    let output = root.join("a/b/..");
    assert_matches_replace(&output);
    assert_eq!(directory_place(&output).target(), root.join("a"));
}

#[test]
fn a_trailing_current_directory_component_matches_both_resolvers() {
    let (_tmp, root) = scratch();
    std::fs::create_dir(root.join("out")).unwrap();
    let output = root.join("out/.");
    assert_matches_atomic(&output);
    assert_matches_replace(&output);
}

#[test]
fn a_symlinked_atomic_destination_resolves_to_its_target() {
    let (_tmp, root) = scratch();
    std::fs::create_dir(root.join("real")).unwrap();
    symlink(root.join("real"), root.join("link")).unwrap();
    let output = root.join("link");
    assert_matches_atomic(&output);
    assert_eq!(directory_place(&output).target(), root.join("real"));
}

#[test]
fn an_absent_destination_with_an_existing_parent_matches_atomic() {
    let (_tmp, root) = scratch();
    let output = root.join("fresh");
    assert_matches_atomic(&output);
    assert_eq!(directory_place(&output).target(), output);
}

#[test]
fn an_absent_destination_in_a_missing_parent_is_not_found() {
    let (_tmp, root) = scratch();
    let error = staging_place(&root.join("no/such/out"), StagedOutputKind::Directory).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn a_file_target_matches_the_staged_output() {
    let (_tmp, root) = scratch();
    let output = root.join("archive.tar");
    let place = staging_place(&output, StagedOutputKind::File).unwrap();
    let staged = StagedOutput::begin(&output, OutputPolicy::CreateNew).unwrap();
    let entries: Vec<_> = std::fs::read_dir(place.parent())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].to_string_lossy().starts_with(STAGING_PREFIX));
    staged.commit(Durability::Unsynced).unwrap();
    assert!(place.target().is_file());
}

#[test]
fn a_file_target_that_is_a_symlink_keeps_the_link_name() {
    let (_tmp, root) = scratch();
    std::fs::write(root.join("real.tar"), b"x").unwrap();
    symlink(root.join("real.tar"), root.join("link.tar")).unwrap();
    let output = root.join("link.tar");
    let place = staging_place(&output, StagedOutputKind::File).unwrap();
    assert_eq!(place.target(), output);
    let _staged = StagedOutput::begin(&output, OutputPolicy::Replace).unwrap();
    let staged_here = std::fs::read_dir(place.parent()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(STAGING_PREFIX)
    });
    assert!(staged_here);
}

#[test]
fn an_output_without_a_name_is_invalid_input() {
    for kind in [StagedOutputKind::Directory, StagedOutputKind::File] {
        for output in ["/", ""] {
            let error = staging_place(Path::new(output), kind).unwrap_err();
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::InvalidInput,
                "{kind:?} {output:?}"
            );
        }
    }
}
