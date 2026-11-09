//! macOS ACL helpers for the unit tests of the staging module: entries are
//! written with `chmod +a` and read back from `ls -led`, the way a user sees
//! them.

use std::path::Path;
use std::process::Command;

/// Adds the entry `ace` to the ACL of `path`.
pub(super) fn add_ace(path: &Path, ace: &str) {
    let status = Command::new("/bin/chmod")
        .args(["+a", ace])
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success(), "chmod +a {ace:?}");
}

/// The entries `ls -led` prints for `path`, without their index.
pub(super) fn aces_of(path: &Path) -> Vec<String> {
    let output = Command::new("/bin/ls")
        .args(["-led"])
        .arg(path)
        .output()
        .unwrap();
    assert!(output.status.success(), "ls -led");
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .skip(1)
        .map(|line| line.trim().split_once(": ").unwrap().1.to_owned())
        .collect()
}

/// Removes every ACL below the directory on drop, so deny entries cannot keep
/// a temporary directory from being deleted.
pub(super) struct AclCleanup<'a>(pub(super) &'a Path);

impl Drop for AclCleanup<'_> {
    fn drop(&mut self) {
        let _ = Command::new("/bin/chmod")
            .args(["-R", "-N"])
            .arg(self.0)
            .status();
    }
}
