use std::fs;
use std::path::Path;
use std::path::PathBuf;

use tempfile::TempDir;

use crate::ExtractRequest;
use crate::ExtractionOptions;
use crate::ExtractionReport;
use crate::ExtractionWarning;
use crate::NarrowingReason;
use crate::SecurityConfig;
use crate::Staging;
use crate::formats::pinned_dir::DirRead;
use crate::formats::pinned_dir::LeafBuf;
use crate::formats::pinned_dir::RootDacl;
use crate::formats::pinned_dir::VettedDir;
use crate::formats::pinned_dir::dacl_probe;
use crate::test_utils::create_test_tar;

fn extract_report(dest: &Path, archive: &Path, staging: Staging) -> ExtractionReport {
    ExtractRequest::new(&SecurityConfig::default())
        .with_options(ExtractionOptions::default().with_staging(staging))
        .extract(archive, dest)
        .unwrap()
}

fn extract(dest: &Path, archive: &Path, staging: Staging) {
    drop(extract_report(dest, archive, staging));
}

fn narrowings(report: &ExtractionReport) -> Vec<NarrowingReason> {
    report
        .warnings
        .iter()
        .filter_map(|warning| match warning {
            ExtractionWarning::RootAccessNarrowed { reason } => Some(*reason),
            _ => None,
        })
        .collect()
}

fn archive_in(temp: &TempDir) -> PathBuf {
    let archive = temp.path().join("a.tar");
    fs::write(&archive, create_test_tar(vec![("dir/file.txt", b"hello")])).unwrap();
    archive
}

fn assert_inherits(path: &Path) {
    let dacl = dacl_probe::read(path);
    let shown = path.display();
    assert!(!dacl.protected, "{shown} still ignores its parent's DACL");
    assert!(!dacl.aces.is_empty(), "{shown} has an empty DACL");
    assert!(dacl.aces.iter().all(dacl_probe::Ace::inherited));
}

fn assert_owner_only(path: &Path) {
    let dacl = dacl_probe::read(path);
    let shown = path.display();
    assert!(
        dacl.protected,
        "{shown} does not ignore its parent's DACL: {:?}",
        dacl.aces
    );
    let [ace] = dacl.aces.as_slice() else {
        panic!("{shown}: expected exactly one entry, got {:?}", dacl.aces);
    };
    assert!(ace.allows);
    assert_eq!(ace.sid, dacl_probe::current_user());
}

#[test]
fn a_published_fresh_root_inherits_the_parent_dacl_like_any_new_directory() {
    let temp = TempDir::new().unwrap();
    let archive = archive_in(&temp);
    let dest = temp.path().join("out");

    extract(&dest, &archive, Staging::Atomic);

    assert_inherits(&dest);
    assert_inherits(&dest.join("dir"));
    assert_inherits(&dest.join("dir").join("file.txt"));
    assert_eq!(
        fs::read(dest.join("dir").join("file.txt")).unwrap(),
        b"hello"
    );
}

#[test]
fn a_published_replacement_root_inherits_the_parent_dacl() {
    let temp = TempDir::new().unwrap();
    let archive = archive_in(&temp);
    let dest = temp.path().join("out");
    fs::create_dir(&dest).unwrap();

    extract(&dest, &archive, Staging::AtomicReplace);

    assert_inherits(&dest);
    assert_inherits(&dest.join("dir").join("file.txt"));
}

#[test]
fn a_parent_without_inheritable_entries_leaves_the_root_owner_only_and_readable() {
    let temp = TempDir::new().unwrap();
    let archive = archive_in(&temp);
    let parent = temp.path().join("closed");
    fs::create_dir(&parent).unwrap();
    dacl_probe::restrict_to_current_user_without_inheritance(&parent);
    let dest = parent.join("out");

    extract(&dest, &archive, Staging::Atomic);

    assert_owner_only(&dest);
    assert_eq!(
        fs::read(dest.join("dir").join("file.txt")).unwrap(),
        b"hello"
    );
}

/// The DACLs of a directory and of a file made in place under a directory that
/// was given `sddl`: what the published tree must reproduce.
fn made_in_place(temp: &TempDir, sddl: &str) -> (dacl_probe::Dacl, dacl_probe::Dacl) {
    let parent = temp.path().join("oracle");
    fs::create_dir(&parent).unwrap();
    dacl_probe::set_dacl_from_sddl(&parent, sddl);
    fs::create_dir(parent.join("dir")).unwrap();
    fs::write(parent.join("dir").join("file.txt"), b"hello").unwrap();
    (
        dacl_probe::read(&parent.join("dir")),
        dacl_probe::read(&parent.join("dir").join("file.txt")),
    )
}

fn assert_replace_reproduces_in_place_creation(sddl: &str) {
    let temp = TempDir::new().unwrap();
    let archive = archive_in(&temp);
    let dest = temp.path().join("out");
    fs::create_dir(&dest).unwrap();
    dacl_probe::set_dacl_from_sddl(&dest, sddl);
    let before = dacl_probe::read(&dest);
    let (dir, file) = made_in_place(&temp, sddl);

    let report = extract_report(&dest, &archive, Staging::AtomicReplace);

    assert_eq!(narrowings(&report), []);
    let root = dacl_probe::read(&dest);
    assert!(
        root.same_as(&before),
        "root {root:?} differs from {before:?}"
    );
    let published_dir = dacl_probe::read(&dest.join("dir"));
    assert!(published_dir.same_as(&dir), "{published_dir:?} vs {dir:?}");
    let published_file = dacl_probe::read(&dest.join("dir").join("file.txt"));
    assert!(
        published_file.same_as(&file),
        "{published_file:?} vs {file:?}"
    );
}

#[test]
fn a_protected_destination_dacl_is_copied_and_its_children_derive_from_it() {
    let me = dacl_probe::current_user();

    assert_replace_reproduces_in_place_creation(&format!("D:P(A;OICI;FA;;;{me})(A;OICI;FR;;;BU)"));
}

#[test]
fn an_unprotected_destination_dacl_is_copied_with_its_inherited_entries() {
    let me = dacl_probe::current_user();

    assert_replace_reproduces_in_place_creation(&format!("D:AI(A;OICI;FA;;;{me})(A;OICI;FR;;;BU)"));
}

#[test]
fn a_creator_owner_entry_resolves_for_each_child_as_it_does_in_place() {
    let me = dacl_probe::current_user();

    assert_replace_reproduces_in_place_creation(&format!(
        "D:P(A;OICI;FA;;;{me})(A;OICIIO;FA;;;CO)"
    ));
}

#[test]
fn a_null_destination_dacl_is_copied_as_a_null_dacl() {
    let temp = TempDir::new().unwrap();
    let dest = temp.path().join("out");
    fs::create_dir(&dest).unwrap();
    dacl_probe::set_dacl_from_sddl(&dest, "D:PNO_ACCESS_CONTROL");
    assert!(dacl_probe::read(&dest).null, "the fixture has a DACL");

    assert_replace_reproduces_in_place_creation("D:PNO_ACCESS_CONTROL");

    let archive = archive_in(&temp);
    extract(&dest, &archive, Staging::AtomicReplace);
    assert!(dacl_probe::read(&dest).null);
}

#[test]
fn the_walk_rewrites_a_junction_itself_and_never_follows_it() {
    let temp = TempDir::new().unwrap();
    let parent = temp.path().canonicalize().unwrap();
    let outside = parent.join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("secret.txt"), b"x").unwrap();
    dacl_probe::restrict_to_current_user_without_inheritance(&outside);
    let outside_dir = dacl_probe::read(&outside);
    let outside_file = dacl_probe::read(&outside.join("secret.txt"));
    let root = parent.join("root");
    fs::create_dir_all(root.join("real")).unwrap();
    fs::write(root.join("real").join("file.txt"), b"x").unwrap();
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(root.join("link"))
        .arg(&outside)
        .status()
        .unwrap();
    assert!(status.success(), "mklink /J failed");
    let me = dacl_probe::current_user();
    dacl_probe::set_dacl_from_sddl(&root, &format!("D:P(A;OICI;FA;;;{me})(A;OICI;FR;;;BU)"));
    let pin = VettedDir::open_path(&parent).unwrap();
    let name = LeafBuf::of(&root).unwrap();
    let identity = pin.status(name.as_leaf()).unwrap().unwrap().identity;
    let dacl = pin.open_dir_for_dacl(name.as_leaf(), identity).unwrap();
    let DirRead::Read(own) = pin.read_dir_security(name.as_leaf(), identity).unwrap() else {
        panic!("the root was replaced");
    };

    dacl.rewrite(&RootDacl::Copy(own)).unwrap();

    let granted = |dacl: &dacl_probe::Dacl| dacl.aces.iter().any(|ace| ace.sid == "S-1-5-32-545");
    assert!(granted(&dacl_probe::read(
        &root.join("real").join("file.txt")
    )));
    assert!(granted(&dacl_probe::read_itself(&root.join("link"))));
    assert!(dacl_probe::read(&outside).same_as(&outside_dir));
    assert!(dacl_probe::read(&outside.join("secret.txt")).same_as(&outside_file));
}

#[test]
fn an_atomic_extraction_succeeds_under_thread_impersonation() {
    let temp = TempDir::new().unwrap();
    let archive = archive_in(&temp);
    let dest = temp.path().join("out");
    let _impersonation = dacl_probe::Impersonation::start();

    extract(&dest, &archive, Staging::Atomic);

    assert_inherits(&dest);
    assert_eq!(
        fs::read(dest.join("dir").join("file.txt")).unwrap(),
        b"hello"
    );
}
