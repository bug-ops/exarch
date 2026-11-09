use std::fs;
use std::path::Path;
use std::path::PathBuf;

use tempfile::TempDir;

use crate::ExtractRequest;
use crate::ExtractionOptions;
use crate::SecurityConfig;
use crate::Staging;
use crate::formats::pinned_dir::dacl_probe;
use crate::test_utils::create_test_tar;

fn extract(dest: &Path, archive: &Path, staging: Staging) {
    ExtractRequest::new(&SecurityConfig::default())
        .with_options(ExtractionOptions::default().with_staging(staging))
        .extract(archive, dest)
        .unwrap();
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
