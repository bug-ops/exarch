//! Filesystem primitives for the `--atomic --force` destination swap.
//!
//! `run_atomic_force_extraction` (in `extract.rs`) renames a pre-existing
//! destination directory aside, moves freshly extracted content into its
//! place, and rolls back on failure — three renames plus one
//! reservation-clearing `remove_dir`, all sharing the same parent directory.
//! Resolving those operations by path re-walks `parent`'s components on
//! every call, so replacing an intermediate component with a symlink
//! between two of those calls silently redirects the swap (issue #526, a
//! TOCTOU race). [`PinnedDir`] closes that window on Unix by opening
//! `parent` once and performing every subsequent operation `*at`-relative
//! to that file descriptor: once opened, the descriptor identifies an
//! inode, not a path, so no later rename of an intermediate component can
//! retarget it.

use std::ffi::OsStr;
use std::io;
use std::path::Path;

/// A directory pinned by an open file descriptor.
///
/// See the module docs for why path-relative operations are unsafe here.
///
/// Opening `parent` this way requires read permission on `parent` itself,
/// not just search (execute) permission — a stricter requirement than the
/// path-based `rename`/`remove_dir` calls this replaces, which needed only
/// write+execute on `parent` and nothing on the destination entry. This is
/// inherent to obtaining a real directory file descriptor portably (Linux's
/// permission-free `O_PATH` has no Unix-wide equivalent), not a bug; see the
/// `parent_without_read_permission_is_rejected` test below for the pinned
/// failure mode.
#[cfg(unix)]
pub(super) struct PinnedDir(std::fs::File);

#[cfg(unix)]
impl PinnedDir {
    /// Opens `parent` and pins it for the lifetime of `self`.
    ///
    /// Fails closed (`NOFOLLOW`) if `parent` is itself a symlink at the
    /// moment of the call. This is the one unavoidable path-based
    /// resolution left in the swap (the `canonicalize` → `open` gap is
    /// microseconds wide); every operation after this point is
    /// fd-relative.
    pub(super) fn open(parent: &Path) -> io::Result<Self> {
        let fd = rustix::fs::open(
            parent,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )?;
        Ok(Self(std::fs::File::from(fd)))
    }

    /// Returns the `(dev, ino)` identity of the directory entry `name`
    /// inside the pinned directory.
    ///
    /// Uses `statat` rather than `openat` + `fstat` deliberately: `statat`
    /// only needs search permission on the pinned directory (already
    /// established by [`open`](Self::open)), whereas opening `name` itself
    /// would additionally require read permission on the destination entry
    /// — a requirement the previous path-based flow never had. `NOFOLLOW`
    /// makes this fail closed if `name` has become a symlink since it was
    /// last checked, rather than silently resolving through it; the explicit
    /// `FileType` check right after does the same for `name` having become
    /// any *other* non-directory (regular file, FIFO, etc.), restoring the
    /// guarantee the old `openat(O_DIRECTORY)` implementation gave for free
    /// — `statat` alone happily returns an identity for any entry type.
    // `st_dev`/`st_ino` are platform-native integer types: `i32`/`u64` on
    // macOS, `u64`/`u64` on 64-bit glibc Linux. `try_from` is therefore a
    // genuine conversion on macOS's `st_dev` but a same-type no-op for
    // everything else on these two targets — clippy's `useless_conversion`
    // fires on both lines on Linux and on the `st_ino` line on macOS.
    // Allowed here rather than split into per-target code for a lint, not a
    // correctness issue. Fails closed (rather than collapsing out-of-range
    // values to a shared sentinel) on conversion failure: a real
    // device/inode number is never negative so this is not expected to
    // trigger in practice, but a sentinel fallback would make two different
    // unrepresentable values compare equal to each other, silently
    // defeating the identity check this feeds.
    #[allow(clippy::useless_conversion)]
    pub(super) fn entry_identity(&self, name: &OsStr) -> io::Result<(u64, u64)> {
        let stat = rustix::fs::statat(&self.0, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory {
            return Err(rustix::io::Errno::NOTDIR.into());
        }
        let dev =
            u64::try_from(stat.st_dev).map_err(|_| io::Error::other("unrepresentable st_dev"))?;
        let ino =
            u64::try_from(stat.st_ino).map_err(|_| io::Error::other("unrepresentable st_ino"))?;
        Ok((dev, ino))
    }

    /// Renames `from` to `to`, both resolved relative to the pinned
    /// directory.
    pub(super) fn rename(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        rustix::fs::renameat(&self.0, from, &self.0, to)?;
        Ok(())
    }

    /// Removes the empty directory `name`, resolved relative to the pinned
    /// directory.
    pub(super) fn remove_dir(&self, name: &OsStr) -> io::Result<()> {
        rustix::fs::unlinkat(&self.0, name, rustix::fs::AtFlags::REMOVEDIR)?;
        Ok(())
    }
}

/// Non-Unix fallback: plain path-based operations.
///
/// This does not close the TOCTOU window issue #526 addresses — it is a
/// documented residual, not a claimed guarantee. Symlink creation is a
/// privileged operation on Windows (unlike Unix), which substantially
/// narrows who can plant the redirect in the first place; fully closing the
/// window there would need a distinct, Windows-specific mechanism and is
/// out of scope for this fix.
#[cfg(not(unix))]
pub(super) struct PinnedDir {
    parent: std::path::PathBuf,
}

#[cfg(not(unix))]
impl PinnedDir {
    // Kept fallible to match the Unix impl's signature so callers never
    // need to branch on platform; this platform's implementation just
    // never happens to fail.
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn open(parent: &Path) -> io::Result<Self> {
        Ok(Self {
            parent: parent.to_path_buf(),
        })
    }

    /// Always reports a matching identity: verifying without re-walking
    /// the path is exactly the capability this platform lacks, so the
    /// check is a no-op here rather than a false guarantee.
    // `&self` is part of the shared signature with the Unix impl, which
    // does need it; this stub simply doesn't.
    #[allow(clippy::unused_self)]
    pub(super) fn entry_identity(&self, _name: &OsStr) -> io::Result<(u64, u64)> {
        Ok((0, 0))
    }

    pub(super) fn rename(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        std::fs::rename(self.parent.join(from), self.parent.join(to))
    }

    pub(super) fn remove_dir(&self, name: &OsStr) -> io::Result<()> {
        std::fs::remove_dir(self.parent.join(name))
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::PinnedDir;
    use std::ffi::OsStr;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;

    #[test]
    fn rename_follows_the_pinned_inode_not_a_planted_symlink() {
        let root = tempfile::tempdir().expect("tempdir");
        let real_parent = root.path().join("real_parent");
        std::fs::create_dir(&real_parent).expect("create real_parent");
        std::fs::write(real_parent.join("payload"), b"original").expect("write payload");

        let pin = PinnedDir::open(&real_parent).expect("pin real_parent");

        // Redirect the path `real_parent` used to name: move the real
        // directory aside and put a symlink to a decoy in its place.
        let decoy = root.path().join("decoy");
        std::fs::create_dir(&decoy).expect("create decoy");
        let moved_real = root.path().join("real_parent_moved");
        std::fs::rename(&real_parent, &moved_real).expect("move real parent aside");
        symlink(&decoy, &real_parent).expect("plant symlink at the old path");

        pin.rename(OsStr::new("payload"), OsStr::new("payload_renamed"))
            .expect("rename via pinned fd");

        assert!(
            moved_real.join("payload_renamed").exists(),
            "rename must land in the original pinned inode"
        );
        assert!(
            !decoy.join("payload_renamed").exists(),
            "rename must not follow the planted symlink into the decoy"
        );
    }

    #[test]
    fn entry_identity_mismatch_is_detectable_after_destination_is_swapped() {
        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).expect("create parent");
        let dest = parent.join("dest");
        std::fs::create_dir(&dest).expect("create dest");

        let pin = PinnedDir::open(&parent).expect("pin parent");
        let name = OsStr::new("dest");
        let snapshot = pin.entry_identity(name).expect("snapshot identity");

        let moved_aside = parent.join("dest.old");
        std::fs::rename(&dest, &moved_aside).expect("move dest aside");
        std::fs::create_dir(&dest).expect("create replacement dest");

        let recheck = pin.entry_identity(name).expect("recheck identity");
        assert_ne!(
            snapshot, recheck,
            "identity must change when the destination entry is swapped for a new one"
        );
    }

    /// Regression test for the R1 finding: `statat` alone happily returns an
    /// identity for any entry type, so `entry_identity` must reject a
    /// non-directory entry explicitly rather than silently treating it like
    /// a directory — restoring the guarantee the old `openat(O_DIRECTORY)`
    /// implementation gave for free.
    #[test]
    fn entry_identity_rejects_non_directory_entry() {
        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).expect("create parent");
        std::fs::write(parent.join("not_a_dir"), b"x").expect("create regular file");

        let pin = PinnedDir::open(&parent).expect("pin parent");
        let err = pin
            .entry_identity(OsStr::new("not_a_dir"))
            .expect_err("a regular file must be rejected, not silently identified");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::NotADirectory,
            "expected a not-a-directory failure specifically, got: {err}"
        );
    }

    /// Regression test for the S1 finding: `entry_identity` must not require
    /// read permission on the destination entry itself — only search
    /// permission on the pinned parent, which `PinnedDir::open` already
    /// established. Before switching from `openat`+`fstat` to `statat`,
    /// this failed with `EACCES` on a destination with no read bit set.
    #[test]
    fn entry_identity_does_not_require_read_permission_on_the_entry() {
        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).expect("create parent");
        let dest = parent.join("dest");
        std::fs::create_dir(&dest).expect("create dest");
        // Write+execute only, no read bit: `entry_identity` must still work.
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o311))
            .expect("restrict dest permissions");

        let pin = PinnedDir::open(&parent).expect("pin parent");
        let result = pin.entry_identity(OsStr::new("dest"));

        // Restore permissions before any panic-driven cleanup runs.
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
            .expect("restore dest permissions");

        result.expect("entry_identity must succeed without read permission on the entry");
    }

    /// Pins the accepted residual noted in [`PinnedDir::open`]'s doc
    /// comment: obtaining a directory file descriptor portably still
    /// requires read permission on `parent` itself, unlike the path-based
    /// `rename`/`remove_dir` calls it replaces. This is not something the
    /// fix can avoid (no Unix-wide `O_PATH` equivalent), so the test exists
    /// to keep the failure mode documented and stable rather than to
    /// demand it change.
    #[test]
    fn parent_without_read_permission_is_rejected() {
        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).expect("create parent");
        // Write+execute only, no read bit.
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o333))
            .expect("restrict parent permissions");

        let result = PinnedDir::open(&parent);

        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755))
            .expect("restore parent permissions");

        match result {
            Ok(_) => {
                // DAC permission checks don't apply to root, so this
                // assertion is meaningless under a privileged test runner
                // rather than false — same reasoning as the mode-000 skip in
                // the Python/Node binding test suites
                // (`test_error_redaction.py`, `error-redaction.test.js`).
                eprintln!(
                    "skipping: opening a read-restricted directory unexpectedly succeeded \
                     (running as root?)"
                );
            }
            Err(err) => assert_eq!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied,
                "expected a permission-denied failure specifically, got: {err}"
            ),
        }
    }
}
