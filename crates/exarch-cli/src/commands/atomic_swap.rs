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
//! retarget it. [`PinnedDir::entry_status`]'s [`DestEntryKind`]
//! classification closes the complementary *final*-component vector
//! (GHSA-x8wr-7ww2-c94x) on every platform: the destination entry itself
//! being a symlink or junction is rejected rather than followed.

use std::ffi::OsStr;
use std::io;
use std::path::Path;

/// Classification of a directory entry inspected by
/// [`PinnedDir::entry_status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DestEntryKind {
    /// The entry is a directory — the only kind `--atomic --force` may swap.
    Directory,
    /// The entry is a symlink (or, on Windows, a junction or other reparse
    /// point) — always rejected, regardless of what it points at.
    Symlink,
    /// Neither a directory nor a symlink (a regular file, FIFO, etc.).
    Other,
}

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
                | rustix::fs::OFlags::NOFOLLOW
                // `O_DIRECTORY` alone rejects a non-directory, but on some
                // platforms a FIFO planted at `parent` can still stall the
                // open itself waiting for a writer before that rejection is
                // reached; `NONBLOCK` makes the open fail immediately
                // instead of hanging the process.
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )?;
        Ok(Self(std::fs::File::from(fd)))
    }

    /// Classifies the directory entry `name` inside the pinned directory and
    /// returns its `(dev, ino)` identity, in the same syscall.
    ///
    /// Uses `statat` rather than `openat` + `fstat` deliberately: `statat`
    /// only needs search permission on the pinned directory (already
    /// established by [`open`](Self::open)), whereas opening `name` itself
    /// would additionally require read permission on the destination entry
    /// — a requirement the previous path-based flow never had. `NOFOLLOW`
    /// makes this fail closed if `name` has become a symlink since it was
    /// last checked, rather than silently resolving through it: unlike the
    /// identity-only check this replaces, a symlink is reported as
    /// [`DestEntryKind::Symlink`] rather than an error — the kind is
    /// returned, never used here to decide anything, so callers decide what
    /// to do with it.
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
    pub(super) fn entry_status(&self, name: &OsStr) -> io::Result<(DestEntryKind, (u64, u64))> {
        let stat = rustix::fs::statat(&self.0, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
        let kind = match rustix::fs::FileType::from_raw_mode(stat.st_mode) {
            rustix::fs::FileType::Directory => DestEntryKind::Directory,
            rustix::fs::FileType::Symlink => DestEntryKind::Symlink,
            _ => DestEntryKind::Other,
        };
        let dev =
            u64::try_from(stat.st_dev).map_err(|_| io::Error::other("unrepresentable st_dev"))?;
        let ino =
            u64::try_from(stat.st_ino).map_err(|_| io::Error::other("unrepresentable st_ino"))?;
        Ok((kind, (dev, ino)))
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

    /// Opens the directory entry `name`, resolved relative to the pinned
    /// directory, and returns an owned handle to it.
    ///
    /// Used by callers that need [`current_path`] on the specific entry
    /// `name` identifies — resolving *its* current location in the
    /// filesystem namespace, not `parent`'s — rather than anything this type
    /// exposes about `name` itself. `NOFOLLOW` matches every other lookup in
    /// this type: a symlink at `name` is rejected, not followed.
    pub(super) fn open_entry(&self, name: &OsStr) -> io::Result<std::fs::File> {
        let fd = rustix::fs::openat(
            &self.0,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )?;
        Ok(std::fs::File::from(fd))
    }
}

/// Best-effort: `fd`'s current path in the filesystem namespace, resolved
/// directly from the descriptor rather than any stored string — so it
/// reflects wherever the entry actually is *now*, unaffected by a redirect
/// of any ancestor path component since `fd` was opened. Used to disclose an
/// accurate, walkable location for content [`PinnedDir::entry_status`] has
/// already confirmed survives (issue #530): that confirmation alone doesn't
/// guarantee the *logical* path built from `parent`'s (possibly still
/// redirected) display path actually leads there — this does.
///
/// Returns `None` if this platform has no fd-to-path facility implemented
/// here (anything other than Linux or macOS); callers must have a fallback,
/// such as naming the logical path with a caveat, for that case.
#[cfg(target_os = "linux")]
pub(super) fn current_path(fd: &std::fs::File) -> Option<std::path::PathBuf> {
    use std::os::fd::AsRawFd;
    std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).ok()
}

/// macOS implementation of [`current_path`] via `fcntl(fd, F_GETPATH)`, the
/// platform's direct fd-to-path facility (Linux's `/proc/self/fd` has no
/// macOS equivalent).
#[cfg(target_os = "macos")]
pub(super) fn current_path(fd: &std::fs::File) -> Option<std::path::PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    rustix::fs::getpath(fd)
        .ok()
        .map(|c_path| std::path::PathBuf::from(std::ffi::OsStr::from_bytes(c_path.as_bytes())))
}

/// Fallback for Unix targets with no fd-to-path facility implemented here:
/// no accurate current path is available.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub(super) fn current_path(_fd: &std::fs::File) -> Option<std::path::PathBuf> {
    None
}

/// Non-Unix fallback: plain path-based operations.
///
/// This does not close the TOCTOU window issue #526 addresses on an
/// *intermediate* path component — it is a documented residual, not a
/// claimed guarantee; fully closing it there would need a distinct,
/// Windows-specific fd-pinning mechanism and is out of scope for this fix.
/// The *final* component — the destination itself being a symlink or
/// junction — is closed on this platform too, by
/// [`entry_status`](PinnedDir::entry_status)'s reparse-point check below.
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

    /// Classifies the directory entry `name` and reports its identity.
    ///
    /// Identity is always `(0, 0)`: verifying without re-walking the path is
    /// exactly the capability this platform lacks, so the check is a no-op
    /// here rather than a false guarantee. The *kind* classification is
    /// real, though — [`is_reparse_point`] checks
    /// `FILE_ATTRIBUTE_REPARSE_POINT` tag-agnostically on Windows, so
    /// junctions and any other reparse point are reported as
    /// [`DestEntryKind::Symlink`], not just true symlinks.
    // `&self` is part of the shared signature with the Unix impl, which
    // does need it; this stub simply doesn't.
    #[allow(clippy::unused_self)]
    pub(super) fn entry_status(&self, name: &OsStr) -> io::Result<(DestEntryKind, (u64, u64))> {
        let metadata = std::fs::symlink_metadata(self.parent.join(name))?;
        let kind = if is_reparse_point(&metadata) {
            DestEntryKind::Symlink
        } else if metadata.is_dir() {
            DestEntryKind::Directory
        } else {
            DestEntryKind::Other
        };
        Ok((kind, (0, 0)))
    }

    pub(super) fn rename(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        std::fs::rename(self.parent.join(from), self.parent.join(to))
    }

    pub(super) fn remove_dir(&self, name: &OsStr) -> io::Result<()> {
        std::fs::remove_dir(self.parent.join(name))
    }

    /// Opens the directory entry `name`, resolved by joining `self.parent`.
    ///
    /// Path-based, same residual as every other operation on this platform's
    /// `PinnedDir`. Kept for signature parity with the Unix impl so callers
    /// never need to branch on platform; its result feeds into
    /// [`current_path`], which always returns `None` on this platform
    /// regardless of whether this call succeeds.
    pub(super) fn open_entry(&self, name: &OsStr) -> io::Result<std::fs::File> {
        std::fs::File::open(self.parent.join(name))
    }
}

/// Non-Unix fallback for [`current_path`]: no fd-to-path facility is
/// implemented here, so this always returns `None` — the same "documented
/// residual, not a false guarantee" pattern as [`PinnedDir`]'s non-Unix
/// `entry_status` always reporting `(0, 0)`. Callers fall back to naming the
/// logical path instead.
#[cfg(not(unix))]
pub(super) fn current_path(_fd: &std::fs::File) -> Option<std::path::PathBuf> {
    None
}

/// Reports whether `metadata` carries `FILE_ATTRIBUTE_REPARSE_POINT`.
///
/// Deliberately tag-agnostic: it does not distinguish a true symlink from a
/// junction or any other reparse tag, so it covers junctions — the
/// practical Windows redirect primitive, which (unlike a true symlink)
/// needs no elevation to create — without depending on which specific tag
/// an attacker used.
#[cfg(windows)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Non-Windows, non-Unix fallback: this platform has no reparse-point
/// concept, so a true symlink is the only redirect primitive to check for.
#[cfg(all(not(unix), not(windows)))]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::DestEntryKind;
    use super::PinnedDir;
    use super::current_path;
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
    fn entry_status_identity_mismatch_is_detectable_after_destination_is_swapped() {
        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).expect("create parent");
        let dest = parent.join("dest");
        std::fs::create_dir(&dest).expect("create dest");

        let pin = PinnedDir::open(&parent).expect("pin parent");
        let name = OsStr::new("dest");
        let (kind, snapshot) = pin.entry_status(name).expect("snapshot identity");
        assert_eq!(kind, DestEntryKind::Directory);

        let moved_aside = parent.join("dest.old");
        std::fs::rename(&dest, &moved_aside).expect("move dest aside");
        std::fs::create_dir(&dest).expect("create replacement dest");

        let (kind, recheck) = pin.entry_status(name).expect("recheck identity");
        assert_eq!(kind, DestEntryKind::Directory);
        assert_ne!(
            snapshot, recheck,
            "identity must change when the destination entry is swapped for a new one"
        );
    }

    /// Unit-level pin (v3 spec) that `entry_status` classifies a symlink
    /// entry as `DestEntryKind::Symlink`, distinct from `Directory` for a
    /// real directory entry — the classification `resolve_atomic_force_replace`
    /// relies on to reject a symlinked destination.
    #[test]
    fn entry_status_returns_symlink_kind_for_a_planted_symlink() {
        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).expect("create parent");
        let real_dir = root.path().join("real_dir");
        std::fs::create_dir(&real_dir).expect("create real_dir");
        let link = parent.join("link");
        symlink(&real_dir, &link).expect("plant symlink");

        let pin = PinnedDir::open(&parent).expect("pin parent");
        let (kind, _) = pin
            .entry_status(OsStr::new("link"))
            .expect("a symlink entry must be classified, not rejected as an error");
        assert_eq!(
            kind,
            DestEntryKind::Symlink,
            "expected a symlink to be classified as Symlink"
        );
    }

    /// Unit-level pin (v3 spec) that a missing entry fails with `NotFound`,
    /// distinguishable from the `Symlink`/`Other` success-path values above
    /// — callers must be able to tell "nothing here yet" from "something
    /// here that must be rejected" without inspecting the error message.
    #[test]
    fn entry_status_on_missing_entry_is_not_found() {
        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).expect("create parent");

        let pin = PinnedDir::open(&parent).expect("pin parent");
        let err = pin
            .entry_status(OsStr::new("does_not_exist"))
            .expect_err("a missing entry must be an error, not a classified value");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::NotFound,
            "expected a not-found failure specifically, got: {err}"
        );
    }

    /// Regression test for the R1 finding, reshaped for `entry_status`
    /// (E4): `statat` alone happily returns an identity for any entry type,
    /// so a non-directory entry must be classified as
    /// `DestEntryKind::Other` on the success path rather than silently
    /// treated like a directory — restoring the guarantee the old
    /// `openat(O_DIRECTORY)` implementation gave for free. Unlike the
    /// superseded `entry_identity`, this is no longer an error: `Other` is
    /// a value the caller inspects and rejects itself.
    #[test]
    fn entry_status_returns_other_kind_for_non_directory_entry() {
        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).expect("create parent");
        std::fs::write(parent.join("not_a_dir"), b"x").expect("create regular file");

        let pin = PinnedDir::open(&parent).expect("pin parent");
        let (kind, _) = pin
            .entry_status(OsStr::new("not_a_dir"))
            .expect("a regular file must be classified, not rejected as an error");
        assert_eq!(
            kind,
            DestEntryKind::Other,
            "expected a regular file to be classified as Other"
        );
    }

    /// Regression test for the S1 finding: `entry_status` must not require
    /// read permission on the destination entry itself — only search
    /// permission on the pinned parent, which `PinnedDir::open` already
    /// established. Before switching from `openat`+`fstat` to `statat`,
    /// this failed with `EACCES` on a destination with no read bit set.
    #[test]
    fn entry_status_does_not_require_read_permission_on_the_entry() {
        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).expect("create parent");
        let dest = parent.join("dest");
        std::fs::create_dir(&dest).expect("create dest");
        // Write+execute only, no read bit: `entry_status` must still work.
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o311))
            .expect("restrict dest permissions");

        let pin = PinnedDir::open(&parent).expect("pin parent");
        let result = pin.entry_status(OsStr::new("dest"));

        // Restore permissions before any panic-driven cleanup runs.
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
            .expect("restore dest permissions");

        result.expect("entry_status must succeed without read permission on the entry");
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

    /// Regression test for issue #530, round 3: `current_path` must resolve
    /// an entry's *current* location from its own fd, not the path used to
    /// open it. Proven directly here — no timing race needed, since the
    /// redirect only has to happen *between* `open_entry` and `current_path`,
    /// not concurrently with either — by the same
    /// move-aside-and-symlink-over technique
    /// `rename_follows_the_pinned_inode_not_a_planted_symlink` uses for
    /// `rename`. This is the property `survival_clause` (in `extract.rs`)
    /// depends on to disclose the real surviving location instead of a
    /// decoy or nothing.
    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn current_path_resolves_through_a_redirected_parent() {
        let root = tempfile::tempdir().expect("tempdir");
        let real_parent = root.path().join("real_parent");
        std::fs::create_dir(&real_parent).expect("create real_parent");
        std::fs::create_dir(real_parent.join("entry")).expect("create entry");

        let pin = PinnedDir::open(&real_parent).expect("pin real_parent");
        let fd = pin
            .open_entry(OsStr::new("entry"))
            .expect("open entry via pinned fd");

        // Redirect the path `real_parent` used to name: move the real
        // directory aside and put a symlink to a decoy in its place.
        let decoy = root.path().join("decoy");
        std::fs::create_dir(&decoy).expect("create decoy");
        let moved_real_parent = root.path().join("real_parent_moved");
        std::fs::rename(&real_parent, &moved_real_parent).expect("move real parent aside");
        symlink(&decoy, &real_parent).expect("plant symlink at the old path");

        let resolved = current_path(&fd).expect("current_path must resolve on this platform");

        // `current_path` resolves through every symlink in the filesystem
        // (e.g. macOS's `/tmp` -> `/private/tmp`), so the expected side must
        // be canonicalized the same way before comparing — the property
        // under test is "reflects the real, moved location", not "matches
        // the exact string `root.path()` happened to be built from".
        let expected = moved_real_parent
            .join("entry")
            .canonicalize()
            .expect("canonicalize expected path");
        assert_eq!(
            resolved, expected,
            "current_path must reflect the entry's real, moved location, not the stale logical \
             path or the decoy"
        );
    }

    /// `open_entry` must fail closed (`NOFOLLOW`) rather than follow a
    /// symlink planted at `name`, the same rejection `entry_status` already
    /// applies to its own lookup. An fd opened by following a symlink here
    /// would make `current_path` resolve to wherever the symlink's target
    /// currently is, not the entry `disclose_if_orphaned` is actually
    /// tracking.
    #[test]
    fn open_entry_rejects_a_planted_symlink() {
        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).expect("create parent");
        let real_dir = root.path().join("real_dir");
        std::fs::create_dir(&real_dir).expect("create real_dir");
        let link = parent.join("link");
        symlink(&real_dir, &link).expect("plant symlink");

        let pin = PinnedDir::open(&parent).expect("pin parent");
        let err = pin
            .open_entry(OsStr::new("link"))
            .expect_err("a symlink entry must be rejected, not followed");
        // The specific errno is platform-dependent: combined with
        // `O_DIRECTORY`, Linux's `open(2)` still reports `ELOOP` for a
        // `NOFOLLOW`'d symlink, while macOS/BSD report `ENOTDIR` instead
        // (`io::ErrorKind::FilesystemLoop` itself is also still unstable —
        // `io_error_more`, rust-lang/rust#86442 — hence comparing the raw
        // errno rather than the `ErrorKind`). Either is acceptable here: what
        // matters is that the open fails closed rather than following the
        // symlink into a real, followable directory fd.
        let raw = err.raw_os_error();
        assert!(
            raw == Some(rustix::io::Errno::LOOP.raw_os_error())
                || raw == Some(rustix::io::Errno::NOTDIR.raw_os_error()),
            "expected NOFOLLOW to reject the symlink with ELOOP or ENOTDIR, got: {err}"
        );
    }
}
