//! Filesystem view used by path, symlink and hardlink validation.
//!
//! Extraction validates against the real destination ([`HostFs`]); `verify`
//! validates against an in-memory model of what extraction would create
//! ([`VirtualTree`]) so that an untrusted archive never causes a write.
//!
//! # Limitations
//!
//! [`VirtualTree`] models only the archive's own entries. It cannot account
//! for files, directories or links already present in the extraction
//! destination, so a verification PASS does not guarantee that extraction into
//! a non-empty destination succeeds. Further differences from the host
//! filesystem:
//!
//! - symlink chains are cut off after [`MAX_SYMLINK_HOPS`] hops, a per-OS
//!   constant that matches `std::fs::canonicalize` on the supported hosts
//!   (macOS 33, glibc 40, musl 39, Windows 63 unverified, other Unix 32); a
//!   different filesystem or kernel configuration can still disagree;
//! - name lengths use per-OS limits ([`MAX_COMPONENT_LEN`], [`MAX_PATH_LEN`]:
//!   Linux 4095, macOS and other Unix 1023, Windows 32767 UTF-16 units); a
//!   symlink target is checked against [`MAX_SYMLINK_TARGET_LEN`] only (Windows
//!   4091 UTF-16 units). A filesystem with tighter limits can still refuse a
//!   name the model accepts;
//! - on macOS names are compared after NFD and a per-character
//!   upper/lower/upper case fold, on Windows after the same fold without
//!   normalisation, and elsewhere exactly. The fold is an approximation of the
//!   host's table: two names it merges but the host keeps apart (for example
//!   `i` and dotless `ı`) are reported as a name collision, never silently
//!   merged;
//! - [`PathModel::Portable`] replaces the per-OS rules with the strictest of
//!   them on every host (see its docs). `zip.rs` still strips drive-relative
//!   names under `allow_absolute_paths` by the host's rules, so a Portable sink
//!   on Linux refuses what Windows would strip: it fails closed;
//! - a path that leaves the root and re-enters it is reported as an escape
//!   (`Containment::Escapes`), although the host would resolve it inside;
//! - only extraction that skips an existing entry is modelled; with overwrite
//!   semantics extraction keeps the last entry at a path, which cannot be
//!   modelled here;
//! - the first entry at a path wins, mirroring extraction that skips an
//!   existing file; the one exception is a symlink over an earlier file, which
//!   replaces it so that verification stays conservative for extraction that
//!   overwrites existing files.

use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use crate::ArchiveError;
use crate::QuotaResource;
use crate::SecurityConfig;
use crate::Violation;
use crate::closed_enum::closed_enum;
use crate::formats::handle_resolution::LinkCursor;
use crate::formats::pinned_dir::PinnedRoot;
use crate::types::DestDir;
use crate::types::SafePath;
use crate::types::safe_path::ParentCheck;

/// Maximum number of symlinks followed while resolving a single path, as the
/// host's `realpath` allows it.
#[cfg(target_os = "macos")]
pub(crate) const MAX_SYMLINK_HOPS: usize = 33;

/// Maximum number of symlinks followed while resolving a single path, as the
/// host's `realpath` allows it.
#[cfg(all(target_os = "linux", target_env = "musl"))]
pub(crate) const MAX_SYMLINK_HOPS: usize = 39;

/// Maximum number of symlinks followed while resolving a single path, as the
/// host's `realpath` allows it.
#[cfg(all(target_os = "linux", not(target_env = "musl")))]
pub(crate) const MAX_SYMLINK_HOPS: usize = 40;

/// Maximum number of symlinks followed while resolving a single path, as the
/// host's `realpath` allows it.
#[cfg(target_os = "windows")]
pub(crate) const MAX_SYMLINK_HOPS: usize = 63;

/// Maximum number of symlinks followed while resolving a single path. A low
/// guess can only turn a PASS into a false FAIL.
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub(crate) const MAX_SYMLINK_HOPS: usize = 32;

/// Longest single path component the host accepts (`NAME_MAX`), in bytes, or
/// in UTF-16 units on Windows.
pub(crate) const MAX_COMPONENT_LEN: usize = 255;

/// Longest relative path the host accepts (`PATH_MAX` less the terminator), in
/// bytes.
#[cfg(target_os = "linux")]
pub(crate) const MAX_PATH_LEN: usize = 4095;

/// Longest relative path the host accepts, in UTF-16 units.
///
/// 32767 is the documented limit of an extended-length path. A symlink target
/// is bounded much lower, see [`MAX_SYMLINK_TARGET_LEN`].
#[cfg(target_os = "windows")]
pub(crate) const MAX_PATH_LEN: usize = 32767;

/// Longest relative path the host accepts (`PATH_MAX` less the terminator), in
/// bytes. A low guess can only turn a PASS into a false FAIL.
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub(crate) const MAX_PATH_LEN: usize = 1023;

/// Longest symlink target the host accepts, in UTF-16 units.
///
/// `CreateSymbolicLinkW` stores the substitute and print names in a 16 KiB
/// reparse buffer after a 20-byte header. Extraction only creates relative
/// targets (a `Prefix` or `RootDir` component is rejected), where both names
/// are equal, so `2 * 2n <= 16384 - 20` gives `n <= 4091`. Absolute targets
/// (`\??\` prefix) would allow fewer units but are never created.
#[cfg(target_os = "windows")]
pub(crate) const MAX_SYMLINK_TARGET_LEN: usize = 4091;

/// Longest symlink target the host accepts (`PATH_MAX` less the terminator),
/// in bytes.
#[cfg(not(target_os = "windows"))]
pub(crate) const MAX_SYMLINK_TARGET_LEN: usize = MAX_PATH_LEN;

/// Longest symlink target in bytes that can pass the
/// [`MAX_SYMLINK_TARGET_LEN`] check; the read and allocation cap for targets
/// stored as bytes.
///
/// On Windows a UTF-16 unit takes at most 3 UTF-8 bytes, so a byte cap never
/// rejects a target the unit check accepts.
#[cfg(target_os = "windows")]
pub(crate) const MAX_SYMLINK_TARGET_BYTES: usize = MAX_SYMLINK_TARGET_LEN * 3;

/// Longest symlink target in bytes that can pass the
/// [`MAX_SYMLINK_TARGET_LEN`] check; the read and allocation cap for targets
/// stored as bytes.
#[cfg(not(target_os = "windows"))]
pub(crate) const MAX_SYMLINK_TARGET_BYTES: usize = MAX_SYMLINK_TARGET_LEN;

closed_enum! {
    /// The kind of link a target belongs to; the host limits them differently.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::LinkKind;
    ///
    /// assert_eq!(LinkKind::Symlink.as_str(), "symlink");
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum LinkKind {
        /// A symbolic link; `symlink(2)` bounds only the whole target
        Symlink => "symlink",
        /// A hard link; the target is resolved as a path, so components count too
        Hardlink => "hardlink",
    }
}

closed_enum! {
    /// The path semantics an [`EntrySink`](crate::EntrySink) is validated
    /// against.
    ///
    /// `Host` applies the rules of the platform running the extraction. On a
    /// Windows host that means the component rules of `Portable` (every
    /// character Windows refuses, reserved names, `:`, trailing dot or space);
    /// on other hosts component names are not restricted.
    /// `Portable` applies the strictest rules of every supported platform, on
    /// every host, for a sink whose storage is read elsewhere:
    ///
    /// - names fold as on macOS (canonical decomposition plus a case fold), so
    ///   two spellings of one name are one name;
    /// - a component with a backslash, one of `<>"|?*`, a control character, a
    ///   `:`, a trailing dot or space, a reserved Windows device name (unless
    ///   `windows_reserved_names` is allowed) or bytes that are not UTF-8 is
    ///   refused;
    /// - a component is at most 255 and a path or symlink target at most 1023,
    ///   counted in UTF-8 bytes and in UTF-16 units alike, and a symlink chain
    ///   is cut off after 32 hops.
    ///
    /// On a Windows host `\` already separates the components of an entry
    /// name when the path is parsed, so it is split there and not refused as a
    /// backslash; every other host refuses it. Not modelled: 8.3 short names
    /// and the legacy 260-unit `MAX_PATH`.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::PathModel;
    ///
    /// assert_eq!(PathModel::default(), PathModel::Host);
    /// assert_eq!(PathModel::Portable.as_str(), "portable");
    /// ```
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum PathModel {
        /// The rules of the platform running the extraction.
        #[default]
        Host => "host",
        /// The strictest rules of every supported platform.
        Portable => "portable",
    }
}

/// The length limits of a [`PathModel`].
#[derive(Debug, Clone, Copy)]
struct NameLimits {
    component: usize,
    path: usize,
    symlink_target: usize,
    hops: usize,
}

impl PathModel {
    const fn limits(self) -> NameLimits {
        match self {
            Self::Host => NameLimits {
                component: MAX_COMPONENT_LEN,
                path: MAX_PATH_LEN,
                symlink_target: MAX_SYMLINK_TARGET_LEN,
                hops: MAX_SYMLINK_HOPS,
            },
            Self::Portable => NameLimits {
                component: 255,
                path: 1023,
                symlink_target: 1023,
                hops: 32,
            },
        }
    }

    fn name_len(self, name: &OsStr) -> usize {
        match self {
            Self::Host => name_len(name),
            Self::Portable => portable_name_len(name),
        }
    }

    /// Rejects entry names this model refuses with `ENAMETOOLONG`.
    ///
    /// # Errors
    ///
    /// Returns an error if the path or any of its components is too long.
    pub(crate) fn check_name_lengths(self, path: &Path) -> io::Result<()> {
        let limits = self.limits();
        let too_long = self.name_len(path.as_os_str()) > limits.path
            || path
                .components()
                .any(|c| self.name_len(c.as_os_str()) > limits.component);
        if too_long {
            return Err(name_too_long());
        }
        Ok(())
    }

    /// Rejects a link target this model refuses with `ENAMETOOLONG`.
    ///
    /// # Errors
    ///
    /// Returns an error if the target is too long for `kind`.
    pub(crate) fn check_link_target_length(self, target: &Path, kind: LinkKind) -> io::Result<()> {
        match kind {
            LinkKind::Symlink
                if self.name_len(target.as_os_str()) > self.limits().symlink_target =>
            {
                Err(name_too_long())
            }
            LinkKind::Symlink => Ok(()),
            LinkKind::Hardlink => self.check_name_lengths(target),
        }
    }
}

/// `base` extended by `tail`; an empty `tail` adds no trailing separator, which
/// would count one byte against the host path limit.
pub(crate) fn joined(base: &Path, tail: &Path) -> PathBuf {
    if tail.is_empty() {
        base.to_path_buf()
    } else {
        base.join(tail)
    }
}

/// Refuses a landing that `model` cannot hold once `tail` is appended.
///
/// The single length rule for a projected landing, shared by the virtual tree
/// and the directory walker so `verify`, the sinks and host extraction cannot
/// disagree.
///
/// # Errors
///
/// Returns the name-too-long error when the joined path or a component exceeds
/// the model's limits.
pub(crate) fn projected_landing_within_limits(
    model: PathModel,
    landing: &Path,
    tail: &Path,
) -> io::Result<()> {
    model.check_name_lengths(&joined(landing, tail))
}

/// A name's length in UTF-8 bytes, which is never below its length in UTF-16
/// units, so one limit holds in both.
fn portable_name_len(name: &OsStr) -> usize {
    name.to_string_lossy().len()
}

#[cfg(windows)]
fn name_len(name: &OsStr) -> usize {
    std::os::windows::ffi::OsStrExt::encode_wide(name).count()
}

#[cfg(not(windows))]
fn name_len(name: &OsStr) -> usize {
    name.as_encoded_bytes().len()
}

/// Rejects entry names the host would refuse with `ENAMETOOLONG`.
///
/// # Errors
///
/// Returns an error if the path or any of its components is too long.
#[cfg(test)]
pub(crate) fn check_name_lengths(path: &Path) -> io::Result<()> {
    PathModel::Host.check_name_lengths(path)
}

/// Rejects a link target the host would refuse with `ENAMETOOLONG`.
///
/// A symlink target is checked against [`MAX_SYMLINK_TARGET_LEN`] only, as
/// `symlink(2)` does; a hardlink target is checked like an entry name.
///
/// # Errors
///
/// Returns an error if the target is too long for `kind`.
pub(crate) fn check_link_target_length(target: &Path, kind: LinkKind) -> io::Result<()> {
    PathModel::Host.check_link_target_length(target, kind)
}

/// The error for a name beyond the host's limits.
#[must_use]
pub(crate) fn name_too_long() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidFilename, "file name too long")
}

/// A root directory that a validator resolves entry paths against.
///
/// Implemented only by [`DestDir`] (the real destination) and [`VirtualRoot`]
/// (the in-memory model), and tied to its [`FsView`] through
/// [`FsView::Root`], so a root can never be paired with the wrong view.
pub(crate) trait ModelRoot {
    /// The root as a path.
    fn as_path(&self) -> &Path;
}

impl ModelRoot for DestDir {
    fn as_path(&self) -> &Path {
        Self::as_path(self)
    }
}

#[cfg(windows)]
const VIRTUAL_ROOT: &str = r"C:\exarch-virtual-root";
#[cfg(not(windows))]
const VIRTUAL_ROOT: &str = "/exarch-virtual-root";

/// The root of a [`VirtualTree`]: a fixed path that is never touched on disk.
///
/// Distinct from [`DestDir`], which promises an existing, canonical, writable
/// directory, so a virtual root can never reach a helper that writes to the
/// host filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VirtualRoot(PathBuf);

impl VirtualRoot {
    /// Creates the fixed virtual root.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self(PathBuf::from(VIRTUAL_ROOT))
    }

    #[cfg(test)]
    pub(crate) fn at(path: &str) -> Self {
        Self(PathBuf::from(path))
    }
}

impl Default for VirtualRoot {
    fn default() -> Self {
        Self::new()
    }
}

impl ModelRoot for VirtualRoot {
    fn as_path(&self) -> &Path {
        &self.0
    }
}

/// Where a canonicalized path ended up relative to the root of its view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Containment {
    /// Inside the root, at this canonical path.
    Within(PathBuf),
    /// Outside the root, or not provably inside it.
    Escapes,
}

/// What the target of a link is relative to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkBase {
    /// The directory the link sits in (a symlink target); the parents of the
    /// link are vetted as well.
    LinkDirectory,
    /// The root itself (a hardlink target).
    Destination,
}

/// Filesystem probes needed while validating archive entries.
pub(crate) trait FsView {
    /// The root type a validator resolves paths against in this view.
    type Root: ModelRoot;

    /// The path semantics validation applies in this view.
    fn path_model(&self) -> PathModel;

    /// Returns `true` if `path` exists, following symlinks.
    fn exists(&self, path: &Path) -> bool;

    /// Returns `true` if `path` exists and is a directory, following symlinks.
    fn is_dir(&self, path: &Path) -> bool;

    /// Returns whether `path` itself is a symlink, without following it.
    ///
    /// # Errors
    ///
    /// Returns an error if `path` cannot be inspected (for example, it does
    /// not exist).
    fn is_symlink(&self, path: &Path) -> io::Result<bool>;

    /// Resolves `path` to its canonical form and says whether that lies inside
    /// `root`.
    ///
    /// # Errors
    ///
    /// Returns an error if a component is missing or the chain cannot be
    /// resolved.
    fn canonicalize(&self, path: &Path, root: &Self::Root) -> io::Result<Containment>;

    /// Resolves the target of the link at `link` (relative to `root`) through
    /// the links this view already holds, and returns where it lands.
    ///
    /// For [`LinkBase::LinkDirectory`] the parents of `link` are vetted first:
    /// an existing symlink among them is refused. Every probe that fails for a
    /// reason other than absence refuses the link.
    ///
    /// The default resolves by path through [`FsView::is_symlink`] and
    /// [`FsView::canonicalize`]; a view that can hold directory handles
    /// overrides it.
    ///
    /// # Errors
    ///
    /// Returns `SymlinkEscape` when the target leaves `root`, runs through a
    /// link that dangles or loops, or cannot be inspected, and an I/O error for
    /// a name past the host's limits.
    fn resolve_link_target(
        &self,
        link: &Path,
        target: &Path,
        base: LinkBase,
        root: &Self::Root,
    ) -> crate::Result<PathBuf>
    where
        Self: Sized,
    {
        crate::types::safe_symlink::resolve_link_target_by_path(self, link, target, base, root)
    }
}

/// Case-insensitive path prefix check for macOS/Windows.
///
/// On case-insensitive filesystems (macOS, Windows), attackers can bypass
/// path validation using different case (e.g., `../../USERS/victim/.ssh/`).
///
/// Compares `path` and `base` component-by-component rather than as raw
/// strings, so a shared name prefix without a component boundary (e.g. base
/// `/tmp/dest` against sibling `/tmp/destevil`) is correctly rejected. See
/// GHSA-wcmx-7f9h-5mv5.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn paths_start_with(path: &Path, base: &Path) -> bool {
    strip_prefix_folded(path, base).is_some()
}

/// What follows `base` in `path` when `base` is a component-wise,
/// case-insensitive prefix of it; the rule [`paths_start_with`] applies.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn strip_prefix_folded<'p>(path: &'p Path, base: &Path) -> Option<&'p Path> {
    let fold = |component: Component<'_>| component.as_os_str().to_string_lossy().to_lowercase();
    let mut rest = path.components();
    for base_component in base.components() {
        if fold(rest.next()?) != fold(base_component) {
            return None;
        }
    }
    Some(rest.as_path())
}

/// Case-sensitive path prefix check for Unix (not macOS).
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub(crate) fn paths_start_with(path: &Path, base: &Path) -> bool {
    path.starts_with(base)
}

/// The real filesystem.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct HostFs;

impl FsView for HostFs {
    type Root = DestDir;

    fn path_model(&self) -> PathModel {
        PathModel::Host
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn is_dir(&self, path: &Path) -> bool {
        path.is_dir()
    }

    fn is_symlink(&self, path: &Path) -> io::Result<bool> {
        std::fs::symlink_metadata(path).map(|m| m.file_type().is_symlink())
    }

    fn canonicalize(&self, path: &Path, root: &DestDir) -> io::Result<Containment> {
        std::fs::canonicalize(path).map(|canonical| contain(canonical, root.as_path()))
    }

    fn resolve_link_target(
        &self,
        link: &Path,
        target: &Path,
        base: LinkBase,
        root: &DestDir,
    ) -> crate::Result<PathBuf> {
        resolve_pinned(&PinnedRoot::open(root.clone())?, link, target, base)
    }
}

fn resolve_pinned(
    root: &PinnedRoot,
    link: &Path,
    target: &Path,
    base: LinkBase,
) -> crate::Result<PathBuf> {
    LinkCursor::for_target(root, link, base, target)
        .map(|resolved| root.dest().as_path().join(resolved))
        .map_err(|refusal| refusal.into_error(link))
}

/// The real filesystem, with link targets resolved against the destination
/// handle an extraction already holds.
///
/// Behaves like [`HostFs`] except that links are resolved
/// handle-relatively from the extraction's [`PinnedRoot`], the same descriptor
/// every write goes through. [`HostFs`] opens the destination by path on every
/// call instead, so only an extraction should rely on the pinned form.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PinnedHostFs<'r> {
    root: &'r PinnedRoot,
}

impl<'r> PinnedHostFs<'r> {
    /// Resolves link targets against `root`, the handle the extraction writes
    /// through.
    pub(crate) const fn new(root: &'r PinnedRoot) -> Self {
        Self { root }
    }
}

impl FsView for PinnedHostFs<'_> {
    type Root = DestDir;

    fn path_model(&self) -> PathModel {
        HostFs.path_model()
    }

    fn exists(&self, path: &Path) -> bool {
        HostFs.exists(path)
    }

    fn is_dir(&self, path: &Path) -> bool {
        HostFs.is_dir(path)
    }

    fn is_symlink(&self, path: &Path) -> io::Result<bool> {
        HostFs.is_symlink(path)
    }

    fn canonicalize(&self, path: &Path, root: &DestDir) -> io::Result<Containment> {
        HostFs.canonicalize(path, root)
    }

    fn resolve_link_target(
        &self,
        link: &Path,
        target: &Path,
        base: LinkBase,
        _root: &DestDir,
    ) -> crate::Result<PathBuf> {
        resolve_pinned(self.root, link, target, base)
    }
}

/// Classifies a canonical path against the canonical `root` by exact,
/// case-sensitive components.
///
/// Both come from `realpath`, which reports the on-disk case, so a
/// case-insensitive comparison is never needed and would let a sibling that
/// differs only in case (`out` and `OUT` on a case-sensitive volume) pass as
/// inside.
fn contain(canonical: PathBuf, root: &Path) -> Containment {
    #[cfg(unix)]
    let inside = canonical.starts_with(root);
    #[cfg(not(unix))]
    let inside = paths_start_with(&canonical, root);
    if inside {
        Containment::Within(canonical)
    } else {
        Containment::Escapes
    }
}

/// How two colliding names differ, which sets how serious the collision is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollisionKind {
    /// Both are directories and neither holds anything in the archive, so the
    /// merge changes nothing
    Directories,
    /// Both are directories and at least one holds entries, which then land in
    /// one directory and can overwrite each other
    DirectoriesWithContents,
    /// Both are files, so one silently replaces or is skipped for the other
    Files,
    /// The kinds differ or a symlink is involved, so later entries can
    /// resolve differently than the archive intends
    Mixed,
}

/// Two entry names that differ exactly but are one name on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NameCollision {
    /// Path of the node that was there first
    pub existing: PathBuf,
    /// Path of the entry that hit it
    pub incoming: PathBuf,
    /// How the two differ
    pub kind: CollisionKind,
}

impl CollisionKind {
    fn of(existing: &Node, incoming: &Node, existing_has_contents: bool) -> Self {
        match (existing, incoming) {
            (Node::Dir, Node::Dir) if existing_has_contents => Self::DirectoriesWithContents,
            (Node::Dir, Node::Dir) => Self::Directories,
            (Node::File, Node::File) => Self::Files,
            _ => Self::Mixed,
        }
    }
}

/// What already occupies a path an insert collided with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Occupant {
    /// A regular file or materialized hardlink.
    File,
    /// A directory.
    Directory,
    /// A symlink, readable or opaque.
    Symlink,
}

impl Occupant {
    /// The noun used in reports.
    pub(crate) const fn noun(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
        }
    }

    /// The text of a refusal to replace this occupant at `rel`, shared by the
    /// host extraction error and the `verify` model so both name the entry and
    /// the occupant in the same words.
    pub(crate) fn refusal(self, rel: &Path) -> String {
        format!(
            "refusing to replace the existing {} at {}",
            self.noun(),
            normalized_display(rel)
        )
    }
}

/// Spells `path` with its components re-joined, so `./a//b` reads `a/b`, and
/// injectively ([`path_text`](fn@crate::path_text)), so two names never read
/// alike.
pub(crate) fn normalized_display(path: &Path) -> String {
    crate::path_text(&path.components().collect::<PathBuf>())
}

/// What stops an entry's parent chain from being a directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParentBlocker {
    /// A parent component is a file.
    File,
    /// A parent component is a symlink that dangles, loops or does not resolve
    /// to a directory.
    Symlink,
    /// A parent component is a symlink that resolves outside the root.
    Escape,
}

impl ParentBlocker {
    /// The error for creating `entry` under the blocking component `parent`;
    /// the single source of text and category for extraction and `verify`.
    pub(crate) fn error(self, entry: &Path, parent: &Path) -> ArchiveError {
        let parent: PathBuf = parent.components().collect();
        let refusal = |noun: &str| {
            format!(
                "refusing to create {} under the existing {noun} at {}",
                normalized_display(entry),
                normalized_display(&parent)
            )
        };
        match self {
            Self::File => ArchiveError::Io(io::Error::new(
                io::ErrorKind::NotADirectory,
                refusal(Occupant::File.noun()),
            )),
            Self::Symlink => ArchiveError::from(Violation::SymlinkParent {
                entry: normalized_display(entry).into(),
                parent: normalized_display(&parent).into(),
            }),
            Self::Escape => ArchiveError::SymlinkEscape { path: parent },
        }
    }
}

/// A parent component that stopped an entry from being placed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BlockedParent {
    entry: PathBuf,
    parent: PathBuf,
    blocker: ParentBlocker,
}

impl BlockedParent {
    pub(crate) fn error(&self) -> ArchiveError {
        self.blocker.error(&self.entry, &self.parent)
    }
}

/// What a symlink at some path turns out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LinkClass {
    /// A link to a directory inside the root, at this canonical path.
    InsideDir(PathBuf),
    /// A link nothing may be written through.
    Blocked(ParentBlocker),
}

/// Classifies the symlink at `link` by resolving it.
///
/// Resolving the link can trigger an automount lookup, so callers apply it
/// only to a path already known to be a symlink.
pub(crate) fn classify_link<V: FsView>(view: &V, link: &Path, root: &V::Root) -> LinkClass {
    match view.canonicalize(link, root) {
        Ok(Containment::Within(resolved)) if view.is_dir(&resolved) => {
            LinkClass::InsideDir(resolved)
        }
        Ok(Containment::Escapes) => LinkClass::Blocked(ParentBlocker::Escape),
        Ok(Containment::Within(_)) | Err(_) => LinkClass::Blocked(ParentBlocker::Symlink),
    }
}

/// The first parent of `rel` that is not a directory `rel` can be created in,
/// looked up through `view`. `None` when no parent is to blame, including a
/// parent that cannot be inspected.
pub(crate) fn first_blocking_ancestor<V: FsView>(
    view: &V,
    root: &V::Root,
    rel: &Path,
) -> Option<(PathBuf, ParentBlocker)> {
    let mut prefix = PathBuf::new();
    for component in rel.parent()?.components() {
        prefix.push(component);
        let full = root.as_path().join(&prefix);
        let blocker = if view.is_symlink(&full).ok()? {
            match classify_link(view, &full, root) {
                LinkClass::InsideDir(_) => continue,
                LinkClass::Blocked(blocker) => blocker,
            }
        } else if view.is_dir(&full) {
            continue;
        } else if view.exists(&full) {
            ParentBlocker::File
        } else {
            return None;
        };
        return Some((prefix, blocker));
    }
    None
}

/// The refusal for `rel` when [`first_blocking_ancestor`] finds a parent to
/// blame for a failed probe of `rel`.
pub(crate) fn blocked_parent_error<V: FsView>(
    view: &V,
    root: &V::Root,
    rel: &Path,
) -> Option<ArchiveError> {
    first_blocking_ancestor(view, root, rel).map(|(parent, blocker)| blocker.error(rel, &parent))
}

/// Whether a projected landing is held to the model's name limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LandingLimits {
    /// The landing must fit the model.
    Enforced,
    /// The entry is never created (a regular file the extension allowlist
    /// skips), so its name cannot be refused.
    Exempt,
}

/// A failed [`VirtualTree::project_landing`].
#[derive(Debug)]
pub(crate) struct Conflict {
    /// The error `insert` would report.
    pub(crate) error: io::Error,
    /// `None` when the failure is in the parent chain, not at the path itself.
    pub(crate) occupant: Option<Occupant>,
    /// Set when a parent component blocks the entry.
    pub(crate) blocked: Option<BlockedParent>,
}

impl Conflict {
    pub(crate) fn already_exists(occupant: Occupant) -> Self {
        Self {
            error: io::Error::from(io::ErrorKind::AlreadyExists),
            occupant: Some(occupant),
            blocked: None,
        }
    }

    /// [`already_exists`](Self::already_exists) whose error names `rel` and
    /// the occupant.
    pub(crate) fn already_exists_at(occupant: Occupant, rel: &Path) -> Self {
        Self {
            error: io::Error::new(io::ErrorKind::AlreadyExists, occupant.refusal(rel)),
            occupant: Some(occupant),
            blocked: None,
        }
    }

    fn blocked_parent(
        error: io::Error,
        entry: &Path,
        parent: &Path,
        blocker: ParentBlocker,
    ) -> Self {
        Self {
            error,
            occupant: None,
            blocked: Some(BlockedParent {
                entry: entry.to_path_buf(),
                parent: parent.to_path_buf(),
                blocker,
            }),
        }
    }

    /// The error extraction reports: the entry-naming refusal for a blocked
    /// parent, the plain I/O error otherwise.
    pub(crate) fn into_archive_error(self) -> ArchiveError {
        match self.blocked {
            Some(blocked) => blocked.error(),
            None => ArchiveError::Io(self.error),
        }
    }
}

impl From<io::Error> for Conflict {
    fn from(error: io::Error) -> Self {
        Self {
            error,
            occupant: None,
            blocked: None,
        }
    }
}

/// Bound on the names a [`VirtualTree`] stores.
///
/// A name is charged when a node is added and when a differently spelled
/// alias of a node is remembered, whatever the kind of the entry, so a flood
/// of directory entries or case variants cannot grow the tree without limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NodeBudget {
    max: usize,
    used: usize,
}

impl NodeBudget {
    /// A budget of `max_file_count * max_path_depth + 1` names: enough for
    /// `max_file_count` files, each at the deepest allowed path with no name
    /// shared. Explicit directory entries and aliases spend it too although
    /// `max_file_count` does not count directories, so an archive of many
    /// directories can exhaust it while within the file limit; raise
    /// `max_file_count` or `max_path_depth` to allow more. Unbounded when
    /// `max_file_count` is [`Limit::Unbounded`](crate::Limit::Unbounded); a
    /// product that overflows saturates at `usize::MAX`.
    #[must_use]
    pub(crate) fn from_config(config: &SecurityConfig) -> Self {
        let max = match config.max_file_count {
            crate::Limit::Bounded(count) => count
                .get()
                .saturating_mul(config.max_path_depth.get())
                .saturating_add(1),
            crate::Limit::Unbounded => usize::MAX,
        };
        Self { max, used: 0 }
    }

    #[cfg(test)]
    pub(crate) const fn unbounded() -> Self {
        Self {
            max: usize::MAX,
            used: 0,
        }
    }

    #[cfg(test)]
    pub(crate) const fn with_max(max: usize) -> Self {
        Self { max, used: 0 }
    }

    fn charge(&mut self) -> Result<(), NodeBudgetExceeded> {
        if self.used >= self.max {
            return Err(NodeBudgetExceeded { max: self.max });
        }
        self.used += 1;
        Ok(())
    }
}

/// A [`NodeBudget`] that ran out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeBudgetExceeded {
    max: usize,
}

impl From<NodeBudgetExceeded> for ArchiveError {
    fn from(exceeded: NodeBudgetExceeded) -> Self {
        Self::QuotaExceeded {
            resource: QuotaResource::TreeNodes { max: exceeded.max },
        }
    }
}

/// Whether a [`VirtualTree`] keeps the name collisions it detects.
///
/// `verify` reports them; a sink only needs the merged path, so recording
/// there would grow memory with every case variant for nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CollisionRecording {
    /// Keep collisions for [`VirtualTree::take_collisions`] and
    /// [`VirtualTree::take_empty_merges`].
    Record,
    /// Merge the names and forget that they collided.
    Discard,
}

/// Why a [`VirtualTree`] refused to place a node.
#[derive(Debug)]
pub(crate) enum PlaceError {
    /// Extraction would fail or change what a path resolves to.
    Conflict(Conflict),
    /// The tree is full.
    Budget(NodeBudgetExceeded),
    /// The node landed at a path the model cannot hold.
    LandingTooLong,
}

impl PlaceError {
    #[cfg(test)]
    pub(crate) fn into_conflict(self) -> Conflict {
        match self {
            Self::Conflict(conflict) => conflict,
            other => panic!("unexpected placement error: {other:?}"),
        }
    }
}

impl From<Conflict> for PlaceError {
    fn from(conflict: Conflict) -> Self {
        Self::Conflict(conflict)
    }
}

impl From<io::Error> for PlaceError {
    fn from(error: io::Error) -> Self {
        Self::Conflict(error.into())
    }
}

impl From<NodeBudgetExceeded> for PlaceError {
    fn from(exceeded: NodeBudgetExceeded) -> Self {
        Self::Budget(exceeded)
    }
}

type FoldFn = for<'a> fn(&'a OsStr) -> Cow<'a, OsStr>;

/// The kind of a node in the in-memory tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Node {
    /// A directory.
    Dir,
    /// A regular file or materialized hardlink.
    File,
    /// A symlink with its target exactly as stored in the archive.
    Symlink(PathBuf),
    /// A symlink whose target was not read, so nothing can be resolved through
    /// it: it exists, but a path that runs through it or lands on it while
    /// being resolved is an error.
    OpaqueSymlink,
}

#[derive(Debug)]
struct TreeNode {
    kind: Node,
    /// The component exactly as the archive spells it.
    name: OsString,
    /// The directory holding this node; the root is its own parent.
    parent: usize,
    /// Only populated for directories; every spelling seen so far (the node's
    /// own and its aliases) mapped to the child, so a repeated spelling is
    /// found without folding it.
    children: HashMap<OsString, usize>,
    /// Folded component to child; empty on hosts that compare names exactly.
    folded: HashMap<OsString, usize>,
    /// Pairs of spellings of this directory that merged while it was empty: if
    /// it later gains an entry the merge stops being harmless.
    empty_merges: Vec<(PathBuf, PathBuf)>,
}

impl TreeNode {
    fn new(kind: Node, name: &OsStr, parent: usize) -> Self {
        Self {
            kind,
            name: name.to_os_string(),
            parent,
            children: HashMap::new(),
            folded: HashMap::new(),
            empty_merges: Vec::new(),
        }
    }
}

const ROOT: usize = 0;

enum Resolved {
    Inside { rel: PathBuf, id: usize },
    Outside,
}

/// Where an insert put its node.
struct Landed {
    parent: usize,
    /// The node that already held the name, if any.
    existing: Option<usize>,
}

/// A child found by name.
#[derive(Clone, Copy)]
struct Found {
    id: usize,
    /// Found only through the fold: the archive spells it differently.
    alias: bool,
}

/// In-memory model of the destination directory built from archive entries.
///
/// Stored as a per-directory component trie, so a lookup or insert costs
/// O(bytes of the path) regardless of how many entries share a prefix. A name
/// is folded only the first time it is seen; repeats, such as the parents of
/// every entry in a directory, hit the exact-spelling map.
///
/// Every name it stores is charged to a [`NodeBudget`].
pub(crate) struct VirtualTree {
    root: PathBuf,
    nodes: Vec<TreeNode>,
    model: PathModel,
    fold: FoldFn,
    budget: NodeBudget,
    recording: CollisionRecording,
    collisions: Vec<NameCollision>,
    /// Directories holding at least one empty merge.
    empty_merge_nodes: Vec<usize>,
    /// Whether any symlink was ever stored: until one is, no path can land
    /// anywhere but where it is spelled.
    links_seen: bool,
    /// Whether any name was ever found under another spelling.
    aliases_seen: bool,
}

impl VirtualTree {
    /// Creates an empty tree rooted at `root` that applies `model`.
    pub(crate) fn new(
        root: &VirtualRoot,
        model: PathModel,
        budget: NodeBudget,
        recording: CollisionRecording,
    ) -> Self {
        let fold = match model {
            PathModel::Host => fold,
            PathModel::Portable => portable_fold,
        };
        Self::build(root, model, fold, budget, recording)
    }

    #[cfg(test)]
    pub(crate) fn for_test(root: &VirtualRoot) -> Self {
        Self::with_fold(root, fold)
    }

    #[cfg(test)]
    pub(crate) fn with_fold(root: &VirtualRoot, fold: FoldFn) -> Self {
        Self::build(
            root,
            PathModel::Host,
            fold,
            NodeBudget::unbounded(),
            CollisionRecording::Record,
        )
    }

    fn build(
        root: &VirtualRoot,
        model: PathModel,
        fold: FoldFn,
        budget: NodeBudget,
        recording: CollisionRecording,
    ) -> Self {
        Self {
            root: root.as_path().to_path_buf(),
            nodes: vec![TreeNode::new(Node::Dir, OsStr::new(""), ROOT)],
            model,
            fold,
            budget,
            recording,
            collisions: Vec::new(),
            empty_merge_nodes: Vec::new(),
            links_seen: false,
            aliases_seen: false,
        }
    }

    /// Records `node` at `rel` (relative to the root), creating missing
    /// parents as directories and following in-root symlinked parents the way
    /// `create_dir_all` does.
    ///
    /// Names that differ exactly but fold to one key are one name on the host.
    /// Each such pair is recorded once as a [`NameCollision`] (see
    /// [`take_collisions`](Self::take_collisions)) and then handled like an
    /// exact repeat, so a merge is never silent.
    ///
    /// The first node at a path wins, matching extraction that skips an
    /// existing entry. A symlink over a file is ambiguous (extraction skips
    /// it by default but replaces the file when overwriting): the file is
    /// replaced so later entries are checked against the riskier tree, and an
    /// error is returned so the archive is never reported as safe. A symlink
    /// over a directory or a symlink with a different target is refused the
    /// same way, but the existing node stays; a symlink with the same target is
    /// an unchanged duplicate.
    ///
    /// # Errors
    ///
    /// Returns a conflict where extraction can fail: a parent that is a file or
    /// a dangling symlink, a parent chain that loops or leaves the root, a
    /// directory entry over an existing non-directory, a symlink over an
    /// earlier file, directory or symlink with another target, or a file over
    /// an earlier directory (`IsADirectory`) or symlink.
    ///
    /// A failure also names what already occupies the path, so a caller can
    /// tell what overwriting would do. A tree that is out of budget refuses
    /// with [`PlaceError::Budget`].
    #[cfg(test)]
    pub(crate) fn try_insert(&mut self, rel: &Path, node: Node) -> Result<(), PlaceError> {
        self.insert_node(rel, node).map(drop)
    }

    /// Places `node` at `rel` and returns where it landed, with every symlinked
    /// parent resolved and every component spelled as the tree first stored it,
    /// so two spellings of one name give one path.
    ///
    /// The one projection of a landing: the sink and `verify` both judge an
    /// entry by it. The entry's own name was checked before it was resolved
    /// through earlier symlinks, and the path it lands at can be longer, so the
    /// landing is checked against the model's name limits here.
    ///
    /// The returned path is relative, normalized and built only from names the
    /// tree stored from validated entries. It is not re-checked against
    /// `max_path_depth`: a landing reached through a link can be deeper than
    /// the entry's own path.
    ///
    /// # Errors
    ///
    /// Returns a conflict where extraction can fail (a parent that is a file or
    /// a dangling symlink, a chain that loops or leaves the root, or an
    /// occupant the node cannot replace; the failure names what occupies the
    /// path), [`PlaceError::Budget`] when the tree is full, or
    /// [`PlaceError::LandingTooLong`] when the landing exceeds the model's
    /// limits and `limits` is [`LandingLimits::Enforced`].
    pub(crate) fn project_landing<P: ParentCheck>(
        &mut self,
        rel: &SafePath<P>,
        node: Node,
        limits: LandingLimits,
    ) -> Result<SafePath, PlaceError> {
        self.guard_landing(rel.as_path(), limits)?;
        let landed = self.place_path(rel.as_path(), node)?;
        if limits == LandingLimits::Enforced {
            self.model
                .check_name_lengths(&landed)
                .map_err(|_| PlaceError::LandingTooLong)?;
        }
        Ok(SafePath::from_normalized(landed)?)
    }

    /// [`project_landing`](Self::project_landing) for a caller that only needs
    /// the verdict, such as `verify`.
    ///
    /// While no symlink was ever stored and no name was found under another
    /// spelling, every path lands where it is spelled, so the one walk of the
    /// path by the length check before the insert settles it and the landing is
    /// never built. Any symlink or alias in the tree takes the full projection.
    ///
    /// # Errors
    ///
    /// Same as [`project_landing`](Self::project_landing).
    pub(crate) fn check_landing<P: ParentCheck>(
        &mut self,
        rel: &SafePath<P>,
        node: Node,
        limits: LandingLimits,
    ) -> Result<(), PlaceError> {
        let links_before = self.links_seen;
        self.guard_landing(rel.as_path(), limits)?;
        let landed = self.insert_node(rel.as_path(), node)?;
        if limits == LandingLimits::Enforced && (links_before || self.aliases_seen) {
            let landing = self.landing_path(rel.as_path(), landed);
            self.model
                .check_name_lengths(&landing)
                .map_err(|_| PlaceError::LandingTooLong)?;
        }
        Ok(())
    }

    /// Refuses, before anything is inserted, a landing the model cannot hold.
    fn guard_landing(&self, rel: &Path, limits: LandingLimits) -> Result<(), PlaceError> {
        if limits != LandingLimits::Enforced {
            return Ok(());
        }
        let too_long = if self.links_seen {
            self.projected_landing(rel)
                .is_some_and(|landing| self.model.check_name_lengths(&landing).is_err())
        } else {
            self.model.check_name_lengths(rel).is_err()
        };
        if too_long {
            return Err(PlaceError::LandingTooLong);
        }
        Ok(())
    }

    /// Where `rel` would land, read from the tree without inserting anything:
    /// the longest existing parent resolved through its links, then the rest of
    /// the path as spelled. `None` when the parents do not resolve (a conflict
    /// the insert reports itself).
    ///
    /// Names are taken as `rel` spells them, so a folded alias of different
    /// byte length is only caught by the check after the insert.
    fn projected_landing(&self, rel: &Path) -> Option<PathBuf> {
        let name = rel.file_name()?;
        let parent = rel.parent().unwrap_or_else(|| Path::new(""));
        let mut missing = Vec::new();
        let mut existing = parent;
        loop {
            match self.resolve(&self.root.join(existing)) {
                Ok(Resolved::Inside { rel: base, .. }) => {
                    let mut landing = base;
                    landing.extend(missing.iter().rev());
                    landing.push(name);
                    return Some(landing);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    missing.push(existing.file_name()?);
                    existing = existing.parent()?;
                }
                Ok(Resolved::Outside) | Err(_) => return None,
            }
        }
    }

    fn place_path(&mut self, rel: &Path, node: Node) -> Result<PathBuf, PlaceError> {
        let landed = self.insert_node(rel, node)?;
        Ok(self.landing_path(rel, landed))
    }

    /// The path an insert landed at, spelled by the stored names.
    fn landing_path(&self, rel: &Path, landed: Option<Landed>) -> PathBuf {
        landed.map_or_else(PathBuf::new, |landed| {
            let leaf = landed.existing.map_or_else(
                || rel.file_name(),
                |id| Some(self.node(id).name.as_os_str()),
            );
            let mut resolved = self.path_of(landed.parent);
            resolved.extend(leaf);
            resolved
        })
    }

    /// The path of node `id` relative to the root, spelled by the stored names.
    fn path_of(&self, mut id: usize) -> PathBuf {
        let mut names = Vec::new();
        while id != ROOT {
            let node = self.node(id);
            names.push(node.name.as_os_str());
            id = node.parent;
        }
        names.into_iter().rev().collect()
    }

    fn insert_node(&mut self, rel: &Path, node: Node) -> Result<Option<Landed>, PlaceError> {
        let Some(name) = rel.file_name() else {
            return Ok(None);
        };
        let parent = self.ensure_dir(rel.parent().unwrap_or_else(|| Path::new("")), rel)?;
        let existing = self.lookup(parent, name);
        if let Some(found) = existing {
            self.settle_alias(parent, found, name, &node, rel, false)?;
        }
        let existing = existing.map(|f| f.id);
        let outcome = match (existing, node) {
            (None, node) => {
                self.add_child(parent, name, node)?;
                Ok(())
            }
            (Some(id), Node::Dir) => match self.node(id).kind {
                Node::Dir => Ok(()),
                Node::File => Err(Conflict::already_exists_at(Occupant::File, rel)),
                Node::OpaqueSymlink => Err(Conflict::already_exists_at(Occupant::Symlink, rel)),
                Node::Symlink(_) => self
                    .resolves_to_dir(&self.root.join(rel))
                    .ok_or_else(|| Conflict::already_exists_at(Occupant::Symlink, rel)),
            },
            (Some(id), node @ (Node::Symlink(_) | Node::OpaqueSymlink)) => {
                match self.node(id).kind {
                    Node::File => {
                        self.node_mut(id).kind = node;
                        self.links_seen = true;
                        Err(Conflict::already_exists(Occupant::File))
                    }
                    Node::Dir => Err(Conflict::already_exists(Occupant::Directory)),
                    Node::Symlink(ref kept) if matches!(&node, Node::Symlink(t) if t == kept) => {
                        Ok(())
                    }
                    Node::Symlink(_) | Node::OpaqueSymlink => {
                        Err(Conflict::already_exists(Occupant::Symlink))
                    }
                }
            }
            (Some(id), Node::File) => match self.node(id).kind {
                Node::File => Ok(()),
                Node::Dir => Err(Conflict {
                    error: io::Error::from(io::ErrorKind::IsADirectory),
                    occupant: Some(Occupant::Directory),
                    blocked: None,
                }),
                Node::Symlink(_) | Node::OpaqueSymlink => {
                    Err(Conflict::already_exists(Occupant::Symlink))
                }
            },
        };
        outcome
            .map(|()| Some(Landed { parent, existing }))
            .map_err(PlaceError::Conflict)
    }

    #[cfg(test)]
    pub(crate) fn insert(&mut self, rel: &Path, node: Node) -> io::Result<()> {
        self.try_insert(rel, node)
            .map_err(|err| err.into_conflict().error)
    }

    /// What an earlier entry left at `rel`, without following a link at the
    /// path itself; a parent link is followed as extraction would.
    pub(crate) fn occupant(&self, rel: &Path) -> Option<Occupant> {
        let name = rel.file_name()?;
        let parent = match self.resolve(&self.root.join(rel.parent()?)) {
            Ok(Resolved::Inside { id, .. }) if self.node(id).kind == Node::Dir => id,
            _ => return None,
        };
        let found = self.lookup(parent, name)?;
        Some(match self.node(found.id).kind {
            Node::Dir => Occupant::Directory,
            Node::File => Occupant::File,
            Node::Symlink(_) | Node::OpaqueSymlink => Occupant::Symlink,
        })
    }

    /// Returns `true` if `path` resolves, through symlinks, to a directory.
    pub(crate) fn resolves_to_dir(&self, path: &Path) -> bool {
        matches!(
            self.resolve(path),
            Ok(Resolved::Inside { id, .. }) if self.node(id).kind == Node::Dir
        )
    }

    /// Drains the name collisions recorded by inserts since the last call.
    ///
    /// Merges of directories that hold nothing are not included: they are
    /// harmless unless an entry lands in the directory later, so they wait for
    /// [`take_empty_merges`](Self::take_empty_merges).
    pub(crate) fn take_collisions(&mut self) -> Vec<NameCollision> {
        std::mem::take(&mut self.collisions)
    }

    /// Drains the merges of directories that are still empty.
    pub(crate) fn take_empty_merges(&mut self) -> Vec<NameCollision> {
        let nodes = std::mem::take(&mut self.empty_merge_nodes);
        nodes
            .into_iter()
            .flat_map(|id| std::mem::take(&mut self.node_mut(id).empty_merges))
            .map(|(existing, incoming)| NameCollision {
                existing,
                incoming,
                kind: CollisionKind::Directories,
            })
            .collect()
    }

    /// Handles a child found by a differently spelled name: remembers the
    /// spelling, so the pair is reported once, and records the collision.
    ///
    /// `incoming_has_contents` is true when the spelling is used as the parent
    /// of an entry, which makes a directory merge harmful at once; an empty
    /// merge is flagged so it is upgraded if the directory gains an entry.
    fn settle_alias(
        &mut self,
        parent: usize,
        found: Found,
        name: &OsStr,
        incoming_node: &Node,
        incoming: &Path,
        incoming_has_contents: bool,
    ) -> Result<(), NodeBudgetExceeded> {
        if !found.alias {
            return Ok(());
        }
        self.aliases_seen = true;
        self.budget.charge()?;
        self.node_mut(parent)
            .children
            .insert(name.to_os_string(), found.id);
        if self.recording == CollisionRecording::Discard {
            return Ok(());
        }
        let existing = self.node(found.id);
        let has_contents = incoming_has_contents || !existing.children.is_empty();
        let kind = CollisionKind::of(&existing.kind, incoming_node, has_contents);
        let existing_path = incoming.with_file_name(&existing.name);
        if kind == CollisionKind::Directories {
            let node = self.node_mut(found.id);
            node.empty_merges
                .push((existing_path, incoming.to_path_buf()));
            self.empty_merge_nodes.push(found.id);
            return Ok(());
        }
        self.collisions.push(NameCollision {
            existing: existing_path,
            incoming: incoming.to_path_buf(),
            kind,
        });
        Ok(())
    }

    fn node(&self, id: usize) -> &TreeNode {
        &self.nodes[id]
    }

    fn node_mut(&mut self, id: usize) -> &mut TreeNode {
        &mut self.nodes[id]
    }

    fn lookup(&self, parent: usize, name: &OsStr) -> Option<Found> {
        if self.model.name_len(name) > self.model.limits().component {
            return None;
        }
        let node = self.node(parent);
        if let Some(&id) = node.children.get(name) {
            return Some(Found { id, alias: false });
        }
        match (self.fold)(name) {
            Cow::Borrowed(_) => None,
            Cow::Owned(key) => node.folded.get(&key).map(|&id| Found { id, alias: true }),
        }
    }

    fn child(&self, parent: usize, name: &OsStr) -> Option<usize> {
        self.lookup(parent, name).map(|found| found.id)
    }

    /// Adds a node under `parent`.
    fn add_child(
        &mut self,
        parent: usize,
        name: &OsStr,
        kind: Node,
    ) -> Result<usize, NodeBudgetExceeded> {
        self.budget.charge()?;
        self.links_seen |= matches!(kind, Node::Symlink(_) | Node::OpaqueSymlink);
        let id = self.nodes.len();
        self.nodes.push(TreeNode::new(kind, name, parent));
        let key = match (self.fold)(name) {
            Cow::Borrowed(_) => None,
            Cow::Owned(key) => Some(key),
        };
        let upgrade = {
            let parent_node = self.node_mut(parent);
            parent_node.children.insert(name.to_os_string(), id);
            if let Some(key) = key {
                parent_node.folded.insert(key, id);
            }
            std::mem::take(&mut parent_node.empty_merges)
        };
        for (existing, incoming) in upgrade {
            self.collisions.push(NameCollision {
                existing,
                incoming,
                kind: CollisionKind::DirectoriesWithContents,
            });
        }
        Ok(id)
    }

    fn ensure_dir(&mut self, dir: &Path, entry: &Path) -> Result<usize, PlaceError> {
        let mut current = ROOT;
        let mut walked = PathBuf::new();
        for component in dir.components() {
            let name = match component {
                Component::Normal(name) => name,
                Component::CurDir => continue,
                _ => return Err(io::Error::from(io::ErrorKind::InvalidInput).into()),
            };
            walked.push(name);
            let blocked = |kind: io::ErrorKind, blocker: ParentBlocker| {
                PlaceError::Conflict(Conflict::blocked_parent(
                    io::Error::from(kind),
                    entry,
                    &walked,
                    blocker,
                ))
            };
            current = match self.lookup(current, name) {
                None => self.add_child(current, name, Node::Dir)?,
                Some(found) => {
                    self.settle_alias(current, found, name, &Node::Dir, &walked, true)?;
                    match self.node(found.id).kind {
                        Node::Dir => found.id,
                        Node::File => {
                            return Err(blocked(io::ErrorKind::NotADirectory, ParentBlocker::File));
                        }
                        Node::OpaqueSymlink => return Err(unread_target_error().into()),
                        Node::Symlink(_) => match self.resolve(&self.root.join(&walked)) {
                            Ok(Resolved::Inside { id, .. }) if self.node(id).kind == Node::Dir => {
                                id
                            }
                            Ok(Resolved::Inside { .. }) => {
                                return Err(blocked(
                                    io::ErrorKind::NotADirectory,
                                    ParentBlocker::Symlink,
                                ));
                            }
                            Err(e) => return Err(blocked(e.kind(), ParentBlocker::Symlink)),
                            Ok(Resolved::Outside) => {
                                return Err(
                                    io::Error::other("path leaves the extraction root").into()
                                );
                            }
                        },
                    }
                }
            };
        }
        Ok(current)
    }

    fn resolve(&self, path: &Path) -> io::Result<Resolved> {
        let Ok(rel) = path.strip_prefix(&self.root) else {
            return Ok(Resolved::Outside);
        };
        let mut pending: VecDeque<Component<'_>> = rel.components().collect();
        let mut stack = vec![ROOT];
        let mut current = PathBuf::new();
        let mut hops = 0;

        while let Some(component) = pending.pop_front() {
            match component {
                Component::CurDir => {}
                Component::ParentDir => {
                    if stack.len() == 1 {
                        return Ok(Resolved::Outside);
                    }
                    stack.pop();
                    current.pop();
                }
                Component::Normal(name) => {
                    let top = stack.last().copied().unwrap_or(ROOT);
                    let Some(id) = self.child(top, name) else {
                        return Err(io::Error::from(io::ErrorKind::NotFound));
                    };
                    match &self.node(id).kind {
                        Node::Dir => {
                            stack.push(id);
                            current.push(&self.node(id).name);
                        }
                        Node::File => {
                            if !pending.is_empty() {
                                return Err(io::Error::from(io::ErrorKind::NotADirectory));
                            }
                            stack.push(id);
                            current.push(&self.node(id).name);
                        }
                        Node::OpaqueSymlink => {
                            if !pending.is_empty() {
                                return Err(unread_target_error());
                            }
                            stack.push(id);
                            current.push(&self.node(id).name);
                        }
                        Node::Symlink(target) => {
                            hops += 1;
                            if hops > self.model.limits().hops {
                                return Err(io::Error::other("too many levels of symbolic links"));
                            }
                            if target.has_root()
                                || target.components().next().is_some_and(is_prefix)
                            {
                                return Ok(Resolved::Outside);
                            }
                            for part in target.components().rev() {
                                pending.push_front(part);
                            }
                        }
                    }
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Ok(Resolved::Outside);
                }
            }
        }
        Ok(Resolved::Inside {
            rel: current,
            id: stack.last().copied().unwrap_or(ROOT),
        })
    }
}

impl FsView for VirtualTree {
    type Root = VirtualRoot;

    fn path_model(&self) -> PathModel {
        self.model
    }

    fn exists(&self, path: &Path) -> bool {
        matches!(self.resolve(path), Ok(Resolved::Inside { .. }))
    }

    fn is_dir(&self, path: &Path) -> bool {
        self.resolves_to_dir(path)
    }

    fn is_symlink(&self, path: &Path) -> io::Result<bool> {
        let not_found = || io::Error::from(io::ErrorKind::NotFound);
        let Ok(rel) = path.strip_prefix(&self.root) else {
            return Err(not_found());
        };
        let Some(name) = rel.file_name() else {
            return Ok(false);
        };
        let parent = self
            .root
            .join(rel.parent().unwrap_or_else(|| Path::new("")));
        let Resolved::Inside { id: parent, .. } = self.resolve(&parent)? else {
            return Err(not_found());
        };
        let id = self.child(parent, name).ok_or_else(not_found)?;
        Ok(matches!(
            self.node(id).kind,
            Node::Symlink(_) | Node::OpaqueSymlink
        ))
    }

    fn canonicalize(&self, path: &Path, _: &VirtualRoot) -> io::Result<Containment> {
        match self.resolve(path)? {
            Resolved::Inside { id, .. } if self.node(id).kind == Node::OpaqueSymlink => {
                Err(unread_target_error())
            }
            Resolved::Inside { rel, .. } => Ok(Containment::Within(self.root.join(rel))),
            Resolved::Outside => Ok(Containment::Escapes),
        }
    }
}

fn unread_target_error() -> io::Error {
    io::Error::other("path runs through a symlink whose target was not read")
}

fn is_prefix(component: Component<'_>) -> bool {
    matches!(component, Component::Prefix(_))
}

/// Compares names the way the host does, as far as it can be modelled.
///
/// A name that is not valid UTF-8 is kept as it is: a lossy fold would give two
/// different byte strings one key and report a collision that is not one.
#[cfg(target_os = "macos")]
fn fold(name: &OsStr) -> Cow<'_, OsStr> {
    portable_fold(name)
}

#[cfg(target_os = "windows")]
fn fold(name: &OsStr) -> Cow<'_, OsStr> {
    let Some(text) = name.to_str() else {
        return Cow::Borrowed(name);
    };
    let folded = if text.is_ascii() {
        text.to_ascii_uppercase()
    } else {
        fold_unicode(text)
    };
    Cow::Owned(OsString::from(folded))
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn fold(name: &OsStr) -> Cow<'_, OsStr> {
    Cow::Borrowed(name)
}

/// The fold of [`PathModel::Portable`], the same on every host: the key
/// macOS uses.
fn portable_fold(name: &OsStr) -> Cow<'_, OsStr> {
    let Some(text) = name.to_str() else {
        return Cow::Borrowed(name);
    };
    let folded = if text.is_ascii() {
        text.to_ascii_uppercase()
    } else {
        decomposed_fold(text)
    };
    Cow::Owned(OsString::from(folded))
}

/// APFS compares canonically decomposed names case-insensitively.
fn decomposed_fold(text: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    upper_lower_upper(text.nfd())
}

/// NTFS compares names case-insensitively without normalisation.
#[cfg(target_os = "windows")]
fn fold_unicode(text: &str) -> String {
    upper_lower_upper(text.chars())
}

/// Full per-character case folding built from the standard library only.
///
/// Upper-casing first merges `ß` with `ẞ`, lower-casing merges the final
/// sigma and `ϴ` with `θ`, and the last upper-casing makes the key stable.
fn upper_lower_upper(chars: impl Iterator<Item = char>) -> String {
    chars
        .flat_map(char::to_uppercase)
        .flat_map(char::to_lowercase)
        .flat_map(char::to_uppercase)
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::assert_matches;

    fn tree() -> VirtualTree {
        VirtualTree::with_fold(&VirtualRoot::at("/dest"), fold)
    }

    fn put(t: &mut VirtualTree, path: &str, node: Node) {
        t.insert(Path::new(path), node).unwrap();
    }

    fn canon(t: &VirtualTree, path: &str) -> io::Result<Containment> {
        t.canonicalize(Path::new(path), &VirtualRoot::at("/dest"))
    }

    fn within(t: &VirtualTree, path: &str) -> PathBuf {
        match canon(t, path).unwrap() {
            Containment::Within(p) => p,
            Containment::Escapes => panic!("{path} escapes"),
        }
    }

    fn sym(target: &str) -> Node {
        Node::Symlink(PathBuf::from(target))
    }

    #[test]
    fn insert_creates_implicit_parents() {
        let mut t = tree();
        put(&mut t, "a/b/c.txt", Node::File);
        assert!(t.exists(Path::new("/dest/a/b")));
        assert!(t.exists(Path::new("/dest/a/b/c.txt")));
        assert!(!t.exists(Path::new("/dest/a/x")));
    }

    #[test]
    fn missing_component_is_not_found() {
        let t = tree();
        let err = canon(&t, "/dest/nope").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn in_root_chain_resolves_to_final_location() {
        let mut t = tree();
        put(&mut t, "real", Node::Dir);
        put(&mut t, "b", sym("real"));
        put(&mut t, "a", sym("b"));
        assert_eq!(within(&t, "/dest/a"), PathBuf::from("/dest/real"));
    }

    #[test]
    fn chain_leaving_root_escapes() {
        let mut t = tree();
        put(&mut t, "y", sym("."));
        put(&mut t, "d", sym("y/.."));
        put(&mut t, "e", sym("d/.."));
        assert_eq!(canon(&t, "/dest/e/secret").unwrap(), Containment::Escapes);
    }

    #[test]
    fn a_path_that_leaves_the_root_and_reenters_it_still_escapes() {
        let mut t = VirtualTree::for_test(&VirtualRoot::new());
        put(&mut t, "up", sym(".."));
        put(&mut t, "abs", sym("/exarch-virtual-root/x"));
        let root = VirtualRoot::new();
        for target in [
            "/exarch-virtual-root/up/exarch-virtual-root/x",
            "/exarch-virtual-root/abs",
        ] {
            assert_eq!(
                t.canonicalize(Path::new(target), &root).unwrap(),
                Containment::Escapes,
                "{target}"
            );
        }
    }

    #[test]
    fn symlink_loop_is_an_error() {
        let mut t = tree();
        put(&mut t, "a", sym("b"));
        put(&mut t, "b", sym("a"));
        assert!(canon(&t, "/dest/a").is_err());
    }

    #[test]
    fn long_chain_hits_hop_limit() {
        let mut t = tree();
        put(&mut t, "l0", Node::Dir);
        for i in 1..=MAX_SYMLINK_HOPS + 1 {
            put(&mut t, &format!("l{i}"), sym(&format!("l{}", i - 1)));
        }
        let over = format!("/dest/l{}", MAX_SYMLINK_HOPS + 1);
        let at = format!("/dest/l{MAX_SYMLINK_HOPS}");
        assert!(canon(&t, &over).is_err());
        assert!(canon(&t, &at).is_ok());
    }

    #[cfg(any(unix, windows))]
    fn make_symlink(target: &str, link: &Path) -> io::Result<()> {
        #[cfg(unix)]
        return std::os::unix::fs::symlink(target, link);
        #[cfg(windows)]
        return std::os::windows::fs::symlink_dir(target, link);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn hop_limit_matches_host_canonicalize() {
        let temp = tempfile::TempDir::new().unwrap();
        // The temp dir itself may sit behind a symlink (/var on macOS), which
        // would spend one hop of the chain below.
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("l0")).unwrap();

        let mut resolvable = 0;
        for i in 1..=MAX_SYMLINK_HOPS + 8 {
            let linked = make_symlink(&format!("l{}", i - 1), &root.join(format!("l{i}")));
            assert!(linked.is_ok(), "cannot create symlinks here: {linked:?}");
            if std::fs::canonicalize(root.join(format!("l{i}"))).is_err() {
                break;
            }
            resolvable = i;
        }
        assert_eq!(resolvable, MAX_SYMLINK_HOPS, "host and model limits differ");

        let mut t = tree();
        put(&mut t, "l0", Node::Dir);
        for i in 1..=resolvable + 1 {
            put(&mut t, &format!("l{i}"), sym(&format!("l{}", i - 1)));
        }
        assert!(canon(&t, &format!("/dest/l{resolvable}")).is_ok());
        assert!(canon(&t, &format!("/dest/l{}", resolvable + 1)).is_err());
    }

    fn ascii_upper(name: &OsStr) -> Cow<'_, OsStr> {
        Cow::Owned(OsString::from(name.to_string_lossy().to_ascii_uppercase()))
    }

    #[cfg(unix)]
    #[test]
    fn names_that_are_not_utf8_keep_distinct_fold_keys() {
        use std::os::unix::ffi::OsStrExt;

        let a = OsStr::from_bytes(b"a\xffb");
        let b = OsStr::from_bytes(b"a\xfeb");
        assert_ne!(portable_fold(a), portable_fold(b));
        assert_eq!(portable_fold(a), portable_fold(a));
    }

    #[cfg(unix)]
    #[test]
    fn parent_refusals_of_names_differing_in_invalid_bytes_differ() {
        use std::os::unix::ffi::OsStrExt;

        let name = |bytes: &[u8]| PathBuf::from(OsStr::from_bytes(bytes));
        for blocker in [ParentBlocker::File, ParentBlocker::Symlink] {
            let message = |entry: &[u8]| {
                let parent = name(entry);
                blocker.error(&parent.join("f"), &parent).to_string()
            };
            let (a, b) = (message(b"d\xe9"), message(b"d\xe8"));
            assert_ne!(a, b, "{blocker:?}");
            assert!(!a.contains('\u{FFFD}'), "{a}");
        }
    }

    fn folding_tree() -> VirtualTree {
        VirtualTree::with_fold(&VirtualRoot::at("/dest"), ascii_upper)
    }

    #[test]
    fn place_resolves_in_root_symlinked_parents() {
        let mut t = tree();
        put(&mut t, "real", Node::Dir);
        put(&mut t, "alias", sym("real"));
        let placed = t.place_path(Path::new("alias/f"), Node::File).unwrap();
        assert_eq!(placed, PathBuf::from("real/f"));
    }

    #[test]
    fn place_spells_a_folded_name_as_first_stored() {
        let mut t = folding_tree();
        assert_eq!(
            t.place_path(Path::new("a/x"), Node::File).unwrap(),
            PathBuf::from("a/x")
        );
        assert_eq!(
            t.place_path(Path::new("A/x"), Node::File).unwrap(),
            PathBuf::from("a/x")
        );
        assert_eq!(within(&t, "/dest/A/X"), PathBuf::from("/dest/a/x"));
    }

    #[test]
    fn place_of_the_root_is_empty_and_conflicts_leave_no_path() {
        let mut t = tree();
        assert_eq!(
            t.place_path(Path::new(""), Node::Dir).unwrap(),
            PathBuf::new()
        );
        put(&mut t, "f", Node::File);
        assert!(t.place_path(Path::new("f"), Node::Dir).is_err());
        assert!(t.place_path(Path::new("f/g"), Node::File).is_err());
    }

    fn lowercase_fold(name: &OsStr) -> Cow<'_, OsStr> {
        let text = name.to_string_lossy();
        let lowered = text.to_lowercase();
        if lowered == text {
            Cow::Borrowed(name)
        } else {
            Cow::Owned(OsString::from(lowered))
        }
    }

    /// What the tree decided and left behind, for either entry point.
    fn decision(
        setup: fn(&mut VirtualTree),
        rel: &str,
        verdict_only: bool,
    ) -> (&'static str, Option<Occupant>) {
        let mut t = VirtualTree::with_fold(&VirtualRoot::at("/dest"), lowercase_fold);
        setup(&mut t);
        let safe = SafePath::for_test(rel);
        let outcome = if verdict_only {
            t.check_landing(&safe, Node::File, LandingLimits::Enforced)
                .map(drop)
        } else {
            t.project_landing(&safe, Node::File, LandingLimits::Enforced)
                .map(drop)
        };
        let tag = match outcome {
            Ok(()) => "accepted",
            Err(PlaceError::LandingTooLong) => "too long",
            Err(PlaceError::Conflict(_)) => "conflict",
            Err(PlaceError::Budget(_)) => "budget",
        };
        (tag, t.occupant(Path::new(rel)))
    }

    type Setup = fn(&mut VirtualTree);

    #[cfg(not(windows))]
    const KELVIN: &str = "\u{212A}";

    #[cfg(not(windows))]
    fn components(spelling: &str, count: usize) -> String {
        vec![spelling.repeat(80); count].join("/")
    }

    /// The entry points are one decision: `check_landing` may skip building
    /// the landing, never change what is accepted, refused or left behind.
    #[test]
    fn check_landing_and_project_landing_decide_alike() {
        let long = "n".repeat(MAX_PATH_LEN);
        let cases: Vec<(&str, Setup, String)> = vec![
            ("no link, short", |_| {}, "a/b".to_owned()),
            ("no link, long", |_| {}, format!("a/{long}")),
            (
                "link, short through it",
                |t| {
                    put(t, "real", Node::Dir);
                    put(t, "alias", sym("real"));
                },
                "alias/f".to_owned(),
            ),
            (
                "link, long through it",
                |t| {
                    put(t, "real", Node::Dir);
                    put(t, "alias", sym("real"));
                },
                format!("alias/{long}"),
            ),
            (
                "link elsewhere, long beside it",
                |t| put(t, "real", Node::Dir),
                format!("real/{long}"),
            ),
            (
                "file replaced by a link, then through it",
                |t| {
                    put(t, "real", Node::Dir);
                    put(t, "x", Node::File);
                    let _ = t.insert(Path::new("x"), sym("real"));
                },
                format!("x/{long}"),
            ),
        ];
        for (name, setup, rel) in cases {
            assert_eq!(
                decision(setup, &rel, true),
                decision(setup, &rel, false),
                "{name}"
            );
        }
        // Windows counts UTF-16 units, and no fold changes the unit count of
        // a name, so a longer spelling of a shorter stored one exists only
        // where the limit counts bytes.
        #[cfg(not(windows))]
        {
            let count = MAX_PATH_LEN / (KELVIN.len() * 80) + 1;
            let stored = components("k", count);
            let alias = components(KELVIN, count);
            assert!(stored.len() <= MAX_PATH_LEN && alias.len() > MAX_PATH_LEN);
            // A spelling that folds onto a shorter stored one: both entry
            // points judge it by the spelling the entry uses.
            let setup: fn(&mut VirtualTree) = |t| {
                let count = MAX_PATH_LEN / (KELVIN.len() * 80) + 1;
                put(t, &components("k", count), Node::Dir);
            };
            let rel = format!("{alias}/f");
            assert_eq!(
                decision(setup, &rel, true),
                decision(setup, &rel, false),
                "alias of another byte length"
            );
            assert_eq!(decision(setup, &rel, true).0, "too long");
            assert_eq!(
                decision(setup, &format!("{stored}/f"), true).0,
                decision(setup, &format!("{stored}/f"), false).0
            );
        }
    }

    #[test]
    fn a_tree_without_links_checks_the_spelled_path_before_inserting() {
        let mut t = tree();
        put(&mut t, "dir", Node::Dir);
        let name = format!("dir/{}", "n".repeat(MAX_PATH_LEN));
        let long = SafePath::for_test(&name);

        let refused = t.check_landing(&long, Node::File, LandingLimits::Enforced);

        assert_matches!(refused, Err(PlaceError::LandingTooLong));
        assert_eq!(t.occupant(Path::new(&name)), None);
        let fits = SafePath::for_test("dir/ok");
        assert!(
            t.check_landing(&fits, Node::File, LandingLimits::Enforced)
                .is_ok()
        );
        assert_eq!(t.occupant(Path::new("dir/ok")), Some(Occupant::File));
        // Once a link is stored, the landing is projected through it.
        put(&mut t, "alias", sym("dir"));
        let through = SafePath::for_test(&format!("alias/{}", "n".repeat(MAX_PATH_LEN)));
        assert_matches!(
            t.check_landing(&through, Node::File, LandingLimits::Enforced),
            Err(PlaceError::LandingTooLong)
        );
    }

    #[test]
    fn project_landing_resolves_through_a_link_and_enforces_the_name_limits() {
        let mut t = tree();
        put(&mut t, "real", Node::Dir);
        put(&mut t, "alias", sym("real"));

        let landed = t
            .project_landing(
                &SafePath::for_test("alias/f"),
                Node::File,
                LandingLimits::Enforced,
            )
            .unwrap();
        assert_eq!(landed.as_path(), Path::new("real/f"));

        let long = SafePath::for_test(&format!("alias/{}", "n".repeat(MAX_PATH_LEN)));
        let refused = t.project_landing(&long, Node::File, LandingLimits::Enforced);
        assert_matches!(refused, Err(PlaceError::LandingTooLong));
        let name = format!("real/{}", "n".repeat(MAX_PATH_LEN));
        assert_eq!(
            t.occupant(Path::new(&name)),
            None,
            "a refused landing leaves no node behind"
        );
        let missing_parents =
            SafePath::for_test(&format!("alias/p/q/{}", "n".repeat(MAX_PATH_LEN)));
        assert_matches!(
            t.project_landing(&missing_parents, Node::File, LandingLimits::Enforced),
            Err(PlaceError::LandingTooLong)
        );
        assert_eq!(t.occupant(Path::new("real/p")), None);
        let exempt = t.project_landing(
            &SafePath::for_test(&format!("alias/{}", "m".repeat(MAX_PATH_LEN))),
            Node::File,
            LandingLimits::Exempt,
        );
        assert!(exempt.is_ok());
    }

    #[test]
    fn projected_landing_limit_is_exact_and_an_empty_tail_adds_no_separator() {
        let at_limit = crate::test_utils::path_of_len(MAX_PATH_LEN);
        let landing = Path::new(&at_limit);
        let check = |landing: &Path, tail: &str| {
            projected_landing_within_limits(PathModel::Host, landing, Path::new(tail))
        };
        assert!(check(landing, "").is_ok());
        assert!(check(landing, "x").is_err());
        let shorter = crate::test_utils::path_of_len(MAX_PATH_LEN - 2);
        assert!(check(Path::new(&shorter), "x").is_ok());
        assert!(check(Path::new(&shorter), "xx").is_err());
    }

    fn budgeted(max: usize, recording: CollisionRecording) -> VirtualTree {
        VirtualTree::build(
            &VirtualRoot::at("/dest"),
            PathModel::Host,
            ascii_upper,
            NodeBudget::with_max(max),
            recording,
        )
    }

    #[test]
    fn node_budget_refuses_the_key_after_the_last() {
        let mut t = budgeted(3, CollisionRecording::Record);
        for name in ["a", "b", "c"] {
            put(&mut t, name, Node::Dir);
        }
        let err = t.try_insert(Path::new("d"), Node::Dir).unwrap_err();
        assert_matches!(err, PlaceError::Budget(NodeBudgetExceeded { max: 3 }));
        assert!(!t.exists(Path::new("/dest/d")));
    }

    #[test]
    fn node_budget_charges_implicit_parents() {
        let mut t = budgeted(2, CollisionRecording::Record);
        let err = t.try_insert(Path::new("a/b/c"), Node::File).unwrap_err();
        assert_matches!(err, PlaceError::Budget(_));
    }

    #[test]
    fn node_budget_charges_alias_spellings_once() {
        let mut t = budgeted(3, CollisionRecording::Discard);
        put(&mut t, "dir", Node::Dir);
        put(&mut t, "Dir", Node::Dir);
        put(&mut t, "Dir", Node::Dir);
        put(&mut t, "DIR", Node::Dir);
        let err = t.try_insert(Path::new("dIr"), Node::Dir).unwrap_err();
        assert_matches!(err, PlaceError::Budget(_));
    }

    #[test]
    fn discard_keeps_no_collision_records_after_a_flood() {
        let mut t = budgeted(usize::MAX, CollisionRecording::Discard);
        put(&mut t, "d/f", Node::File);
        for spelling in ["D", "d", "Dd"] {
            let _ = t.insert(Path::new(spelling), Node::Dir);
        }
        put(&mut t, "D/g", Node::File);
        put(&mut t, "Dir", Node::Dir);
        put(&mut t, "dir", Node::Dir);
        put(&mut t, "dir/x", Node::File);
        assert!(t.take_collisions().is_empty());
        assert!(t.take_empty_merges().is_empty());
        assert!(t.exists(Path::new("/dest/D/f")));
    }

    #[test]
    fn unbounded_config_budget_never_trips() {
        let config = crate::SecurityConfig::default()
            .with_max_file_count(crate::Limit::Unbounded)
            .with_max_path_depth(crate::non_zero!(8));
        let mut t = VirtualTree::build(
            &VirtualRoot::at("/dest"),
            PathModel::Host,
            fold,
            NodeBudget::from_config(&config),
            CollisionRecording::Discard,
        );
        for i in 0..1000 {
            put(&mut t, &format!("d{i}"), Node::Dir);
        }
    }

    #[test]
    fn config_budget_is_files_times_depth_plus_one() {
        let config = crate::SecurityConfig::default()
            .with_max_file_count(crate::non_zero!(10))
            .with_max_path_depth(crate::non_zero!(4));
        assert_eq!(NodeBudget::from_config(&config).max, 41);
    }

    fn collisions_of(t: &mut VirtualTree) -> Vec<(String, String, CollisionKind)> {
        t.take_collisions()
            .into_iter()
            .map(|c| {
                (
                    c.existing.display().to_string().replace('\\', "/"),
                    c.incoming.display().to_string().replace('\\', "/"),
                    c.kind,
                )
            })
            .collect()
    }

    #[test]
    fn exact_repeat_is_not_a_collision() {
        let mut t = folding_tree();
        put(&mut t, "a/f", Node::File);
        put(&mut t, "a/f", Node::File);
        assert!(t.take_collisions().is_empty());
    }

    #[test]
    fn differently_spelled_files_collide() {
        let mut t = folding_tree();
        put(&mut t, "d/a.txt", Node::File);
        put(&mut t, "d/A.txt", Node::File);
        assert_eq!(
            collisions_of(&mut t),
            [("d/a.txt".into(), "d/A.txt".into(), CollisionKind::Files)]
        );
        assert!(t.take_collisions().is_empty());
    }

    #[test]
    fn differently_spelled_parent_directories_collide() {
        let mut t = folding_tree();
        put(&mut t, "Images/x", Node::File);
        put(&mut t, "images/y", Node::File);
        assert_eq!(
            collisions_of(&mut t),
            [(
                "Images".into(),
                "images".into(),
                CollisionKind::DirectoriesWithContents
            )]
        );
    }

    #[test]
    fn a_spelling_is_reported_once_however_many_entries_use_it() {
        let mut t = folding_tree();
        put(&mut t, "Images/a", Node::File);
        for i in 0..100 {
            put(&mut t, &format!("images/f{i}"), Node::File);
        }
        assert_eq!(collisions_of(&mut t).len(), 1);
    }

    #[test]
    fn empty_directories_merge_harmlessly_until_one_gains_an_entry() {
        let mut t = folding_tree();
        put(&mut t, "Dir", Node::Dir);
        put(&mut t, "dir", Node::Dir);
        assert!(collisions_of(&mut t).is_empty());
        put(&mut t, "Dir/f", Node::File);
        put(&mut t, "dir/g", Node::File);
        assert_eq!(
            collisions_of(&mut t),
            [(
                "Dir".into(),
                "dir".into(),
                CollisionKind::DirectoriesWithContents
            )]
        );
    }

    #[test]
    fn empty_merges_are_reported_once_when_nothing_lands_in_them() {
        let mut t = folding_tree();
        put(&mut t, "Dir", Node::Dir);
        put(&mut t, "dir", Node::Dir);
        put(&mut t, "other", Node::File);
        let merges: Vec<_> = t
            .take_empty_merges()
            .into_iter()
            .map(|c| {
                (
                    c.existing.display().to_string(),
                    c.incoming.display().to_string(),
                    c.kind,
                )
            })
            .collect();
        assert_eq!(
            merges,
            [("Dir".into(), "dir".into(), CollisionKind::Directories)]
        );
        assert!(t.take_empty_merges().is_empty());
    }

    #[test]
    fn directory_entry_over_a_directory_with_contents_is_not_harmless() {
        let mut t = folding_tree();
        put(&mut t, "Dir/f", Node::File);
        put(&mut t, "dir", Node::Dir);
        assert_eq!(
            collisions_of(&mut t),
            [(
                "Dir".into(),
                "dir".into(),
                CollisionKind::DirectoriesWithContents
            )]
        );
    }

    #[test]
    fn names_are_folded_once_however_often_they_repeat() {
        use std::sync::atomic::AtomicUsize;
        use std::sync::atomic::Ordering;

        static CALLS: AtomicUsize = AtomicUsize::new(0);
        fn counting(name: &OsStr) -> Cow<'_, OsStr> {
            CALLS.fetch_add(1, Ordering::Relaxed);
            ascii_upper(name)
        }

        let mut t = VirtualTree::with_fold(&VirtualRoot::at("/dest"), counting);
        for i in 0..500 {
            put(&mut t, &format!("a/b/c/d/file{i}"), Node::File);
        }
        // Four directories and 500 files, each folded to look up and to store;
        // a fold per parent per entry would be about 2500 calls.
        assert!(CALLS.load(Ordering::Relaxed) <= 2 * 504 + 8);
    }

    #[test]
    fn collision_across_kinds_or_with_a_symlink_is_mixed() {
        let mut t = folding_tree();
        put(&mut t, "a", Node::File);
        let _ = t.insert(Path::new("A"), Node::Dir);
        put(&mut t, "link", sym("a"));
        let _ = t.insert(Path::new("LINK"), Node::File);
        assert_eq!(
            collisions_of(&mut t),
            [
                ("a".into(), "A".into(), CollisionKind::Mixed),
                ("link".into(), "LINK".into(), CollisionKind::Mixed)
            ]
        );
    }

    #[test]
    fn symlink_over_an_existing_dir_is_refused_and_keeps_the_dir() {
        let mut t = folding_tree();
        put(&mut t, "d/f", Node::File);
        let err = t.insert(Path::new("d"), sym("sub")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        let err = t.insert(Path::new("d"), Node::OpaqueSymlink).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(t.resolves_to_dir(&t.root.join("d")));
    }

    #[test]
    fn collision_is_recorded_when_insert_fails() {
        let mut t = folding_tree();
        put(&mut t, "y", Node::File);
        let err = t.insert(Path::new("Y"), sym(".")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            collisions_of(&mut t),
            [("y".into(), "Y".into(), CollisionKind::Mixed)]
        );
    }

    #[cfg(target_os = "macos")]
    mod macos {
        use super::super::fold;
        use super::*;

        fn key(s: &str) -> OsString {
            fold(OsStr::new(s)).into_owned()
        }

        #[test]
        fn special_case_pairs_fold_equal() {
            assert_eq!(key("\u{df}"), key("\u{1e9e}"));
            assert_eq!(key("\u{3b8}"), key("\u{3f4}"));
            assert_eq!(key("\u{3b8}"), key("\u{3d1}"));
            assert_eq!(key("\u{3c2}"), key("\u{3a3}"));
        }

        #[test]
        fn canonically_equivalent_names_fold_equal() {
            assert_eq!(key("caf\u{e9}"), key("cafe\u{301}"));
            assert_eq!(key("\u{ac00}"), key("\u{1100}\u{1161}"));
        }

        #[test]
        fn nfc_and_nfd_spellings_collide_in_the_tree() {
            let mut t = tree();
            put(&mut t, "caf\u{e9}", Node::File);
            put(&mut t, "cafe\u{301}", Node::File);
            assert_eq!(t.take_collisions().len(), 1);
        }

        #[test]
        fn fold_never_under_merges_what_apfs_treats_as_equal() {
            let temp = tempfile::TempDir::new().unwrap();
            let root = temp.path().canonicalize().unwrap();
            let mut seen = std::collections::HashSet::new();
            let mut under = Vec::new();
            // Blocks with case or normalisation behaviour; the Hangul block is
            // sampled because it decomposes algorithmically.
            let candidates = (0x1..=0x3000)
                .chain((0xAC00..=0xD7A3).step_by(11))
                .chain(0xF900..=0xFFFF)
                .chain(0x1_0400..=0x1_044F)
                .chain(0x1_E900..=0x1_E943);
            for code in candidates {
                let Some(c) = char::from_u32(code).filter(|c| !matches!(c, '/' | '.')) else {
                    continue;
                };
                let name = c.to_string();
                let path = root.join(&name);
                let host_equal = path.symlink_metadata().is_ok();
                if !host_equal && std::fs::File::create_new(&path).is_err() {
                    continue;
                }
                let model_seen = !seen.insert(key(&name));
                if host_equal && !model_seen {
                    under.push(format!("U+{code:04X}"));
                }
            }
            assert!(under.is_empty(), "under-merged: {under:?}");
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn fold_covers_ntfs_simple_uppercase() {
        use std::collections::HashMap;

        let mut by_upper: HashMap<char, OsString> = HashMap::new();
        for code in 0x1..=0x1_FFFFu32 {
            let Some(c) = char::from_u32(code) else {
                continue;
            };
            let mut upper = c.to_uppercase();
            let simple = match (upper.next(), upper.next()) {
                (Some(u), None) => u,
                _ => c,
            };
            let key = fold(OsStr::new(&c.to_string())).into_owned();
            let expected = by_upper.entry(simple).or_insert_with(|| key.clone());
            assert_eq!(*expected, key, "U+{code:04X}");
        }
    }

    #[test]
    fn dangling_symlink_does_not_exist_but_is_a_symlink() {
        let mut t = tree();
        put(&mut t, "d", sym("missing"));
        assert!(!t.exists(Path::new("/dest/d")));
        assert!(t.is_symlink(Path::new("/dest/d")).unwrap());
    }

    #[test]
    fn opaque_symlink_exists_and_is_a_symlink_but_not_a_directory() {
        let mut t = tree();
        put(&mut t, "d", Node::OpaqueSymlink);
        assert!(t.exists(Path::new("/dest/d")));
        assert!(t.is_symlink(Path::new("/dest/d")).unwrap());
        assert!(!t.resolves_to_dir(Path::new("/dest/d")));
    }

    #[test]
    fn nothing_resolves_through_an_opaque_symlink() {
        let mut t = tree();
        put(&mut t, "d", Node::OpaqueSymlink);
        assert!(canon(&t, "/dest/d").is_err());
        assert!(canon(&t, "/dest/d/x").is_err());
        assert!(t.insert(Path::new("d/f"), Node::File).is_err());
    }

    #[test]
    fn a_chain_ending_at_an_opaque_symlink_does_not_resolve() {
        let mut t = tree();
        put(&mut t, "d", Node::OpaqueSymlink);
        put(&mut t, "l", sym("d"));
        assert!(canon(&t, "/dest/l").is_err());
    }

    #[test]
    fn opaque_symlink_keeps_its_place_like_a_symlink() {
        let mut t = tree();
        put(&mut t, "d", Node::OpaqueSymlink);
        assert_eq!(
            t.insert(Path::new("d"), Node::Dir).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            t.insert(Path::new("d"), Node::File).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert!(t.is_symlink(Path::new("/dest/d")).unwrap());

        put(&mut t, "f", Node::File);
        assert!(t.insert(Path::new("f"), Node::OpaqueSymlink).is_err());
        assert!(t.is_symlink(Path::new("/dest/f")).unwrap());
    }

    #[test]
    fn opaque_symlink_collision_is_mixed() {
        let mut t = folding_tree();
        put(&mut t, "link", Node::OpaqueSymlink);
        let _ = t.insert(Path::new("LINK"), Node::File);
        assert_eq!(
            collisions_of(&mut t),
            [("link".into(), "LINK".into(), CollisionKind::Mixed)]
        );
    }

    #[test]
    fn is_symlink_follows_symlinked_parents() {
        let mut t = tree();
        put(&mut t, "real/inner", sym("x"));
        put(&mut t, "alias", sym("real"));
        assert!(t.is_symlink(Path::new("/dest/alias/inner")).unwrap());
        assert!(!t.is_symlink(Path::new("/dest/real")).unwrap());
        assert!(t.is_symlink(Path::new("/dest/none")).is_err());
    }

    #[test]
    fn insert_through_symlinked_parent_lands_at_resolved_location() {
        let mut t = tree();
        put(&mut t, "real", Node::Dir);
        put(&mut t, "alias", sym("real"));
        put(&mut t, "alias/f", Node::File);
        assert!(t.exists(Path::new("/dest/real/f")));
    }

    #[test]
    fn insert_dir_keeps_existing_symlink() {
        let mut t = tree();
        put(&mut t, "real", Node::Dir);
        put(&mut t, "alias", sym("real"));
        put(&mut t, "alias", Node::Dir);
        assert!(t.is_symlink(Path::new("/dest/alias")).unwrap());
    }

    #[test]
    fn file_never_replaces_existing_symlink() {
        let mut t = tree();
        put(&mut t, "y", sym("."));
        let err = t.insert(Path::new("y"), Node::File).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(t.is_symlink(Path::new("/dest/y")).unwrap());
    }

    #[test]
    fn symlink_over_symlink_is_refused_and_keeps_the_first() {
        let mut t = tree();
        put(&mut t, "real", Node::Dir);
        put(&mut t, "d", sym("real"));
        for node in [sym("other"), Node::OpaqueSymlink] {
            let conflict = t
                .try_insert(Path::new("d"), node)
                .unwrap_err()
                .into_conflict();
            assert_eq!(conflict.error.kind(), io::ErrorKind::AlreadyExists);
            assert_eq!(conflict.occupant, Some(Occupant::Symlink));
        }
        assert_eq!(within(&t, "/dest/d"), PathBuf::from("/dest/real"));
    }

    #[test]
    fn symlink_repeating_the_same_target_is_an_unchanged_duplicate() {
        let mut t = tree();
        put(&mut t, "d", sym("real"));
        put(&mut t, "d", sym("real"));
        assert!(t.try_insert(Path::new("d"), Node::OpaqueSymlink).is_err());
    }

    #[test]
    fn file_over_dir_is_refused_with_is_a_directory() {
        let mut t = tree();
        put(&mut t, "d/f", Node::File);
        let conflict = t
            .try_insert(Path::new("d"), Node::File)
            .unwrap_err()
            .into_conflict();
        assert_eq!(conflict.error.kind(), io::ErrorKind::IsADirectory);
        assert_eq!(conflict.occupant, Some(Occupant::Directory));
    }

    #[test]
    fn file_over_file_is_kept_silently() {
        let mut t = tree();
        put(&mut t, "f", Node::File);
        put(&mut t, "f", Node::File);
        assert_eq!(t.occupant(Path::new("f")), Some(Occupant::File));
    }

    #[test]
    fn occupant_names_what_sits_at_the_path_itself() {
        let mut t = tree();
        put(&mut t, "real/f", Node::File);
        put(&mut t, "alias", sym("real"));
        assert_eq!(t.occupant(Path::new("real")), Some(Occupant::Directory));
        assert_eq!(t.occupant(Path::new("alias")), Some(Occupant::Symlink));
        assert_eq!(t.occupant(Path::new("alias/f")), Some(Occupant::File));
        assert_eq!(t.occupant(Path::new("none")), None);
    }

    #[test]
    fn symlink_replaces_earlier_file() {
        let mut t = tree();
        put(&mut t, "y", Node::File);
        let err = t.insert(Path::new("y"), sym(".")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(t.is_symlink(Path::new("/dest/y")).unwrap());
    }

    #[test]
    fn dir_over_file_is_an_error() {
        let mut t = tree();
        put(&mut t, "f", Node::File);
        let err = t.insert(Path::new("f"), Node::Dir).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn insert_under_file_is_an_error() {
        let mut t = tree();
        put(&mut t, "f", Node::File);
        let err = t.insert(Path::new("f/g"), Node::File).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotADirectory);
    }

    #[test]
    fn insert_under_chain_leaving_root_is_an_error() {
        let mut t = tree();
        put(&mut t, "out", sym(".."));
        assert!(t.insert(Path::new("out/f"), Node::File).is_err());
        assert!(!t.exists(Path::new("/dest/out/f")));
    }

    #[test]
    fn resolves_to_dir_distinguishes_files_and_directories() {
        let mut t = tree();
        put(&mut t, "d/f", Node::File);
        put(&mut t, "alias", sym("d"));
        assert!(t.resolves_to_dir(Path::new("/dest/d")));
        assert!(t.resolves_to_dir(Path::new("/dest/alias")));
        assert!(!t.resolves_to_dir(Path::new("/dest/d/f")));
    }

    #[test]
    fn overlong_component_is_never_found() {
        let mut t = tree();
        put(&mut t, "d", Node::Dir);
        let long = "a".repeat(1 << 20);
        let err = canon(&t, &format!("/dest/d/{long}")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn name_length_limits() {
        assert!(check_name_lengths(Path::new("a/b")).is_ok());
        let long_name = "a".repeat(255 + 1);
        assert!(check_name_lengths(Path::new(&long_name)).is_err());
        let long_path = path_of_len(HOST_PATH_LIMIT + 1);
        assert!(check_name_lengths(Path::new(&long_path)).is_err());
        assert!(check_name_lengths(Path::new(&path_of_len(HOST_PATH_LIMIT))).is_ok());
    }

    use crate::test_utils::HOST_PATH_LIMIT;
    use crate::test_utils::path_of_len;

    #[test]
    fn link_target_length_boundaries() {
        let symlink_limit = path_of_len(MAX_SYMLINK_TARGET_LEN);
        let symlink_over = path_of_len(MAX_SYMLINK_TARGET_LEN + 1);
        assert!(check_link_target_length(Path::new(&symlink_limit), LinkKind::Symlink).is_ok());
        assert!(check_link_target_length(Path::new(&symlink_over), LinkKind::Symlink).is_err());

        let at_limit = path_of_len(HOST_PATH_LIMIT);
        assert_eq!(at_limit.len(), HOST_PATH_LIMIT);
        let over = path_of_len(HOST_PATH_LIMIT + 1);
        assert!(check_link_target_length(Path::new(&at_limit), LinkKind::Hardlink).is_ok());
        assert!(check_link_target_length(Path::new(&over), LinkKind::Hardlink).is_err());
    }

    #[test]
    fn symlink_target_limits_match_the_host() {
        assert_eq!(
            MAX_SYMLINK_TARGET_LEN,
            if cfg!(windows) { 4091 } else { HOST_PATH_LIMIT }
        );
        assert_eq!(
            MAX_SYMLINK_TARGET_BYTES,
            if cfg!(windows) {
                4091 * 3
            } else {
                HOST_PATH_LIMIT
            }
        );
    }

    /// Finds the longest relative symlink target the host creates and checks
    /// that [`MAX_SYMLINK_TARGET_LEN`] does not exceed it.
    #[cfg(windows)]
    #[test]
    fn symlink_target_limit_is_accepted_by_the_host() {
        use std::os::windows::fs::symlink_file;

        let temp = tempfile::TempDir::new().unwrap();
        let mut counter = 0_u32;
        let mut creates = |len: usize| -> io::Result<bool> {
            counter += 1;
            let link = temp.path().join(format!("l{counter}"));
            let mut target = "abcdefg\\".repeat((len - 1) / 8);
            target.push_str(&"a".repeat(len - target.len()));
            match symlink_file(&target, &link) {
                Ok(()) => Ok(true),
                Err(e) if e.raw_os_error() == Some(1314) => Err(e),
                Err(_) => Ok(false),
            }
        };

        match creates(1) {
            Ok(_) => {}
            Err(e) => {
                assert!(
                    std::env::var_os("CI").is_none(),
                    "symlink creation needs a privilege on CI: {e}"
                );
                eprintln!("skipped: symlink creation is not permitted: {e}");
                return;
            }
        }

        let (mut ok, mut bad) = (1_usize, 32767_usize);
        while bad - ok > 1 {
            let mid = ok + (bad - ok) / 2;
            if creates(mid).unwrap() {
                ok = mid;
            } else {
                bad = mid;
            }
        }
        eprintln!("largest relative symlink target: {ok} UTF-16 units");
        assert!(MAX_SYMLINK_TARGET_LEN <= ok, "host limit is {ok}");
    }

    #[test]
    fn symlink_target_ignores_component_limit() {
        let long_component = "a".repeat(255 + 45);
        let target = Path::new(&long_component);
        assert!(check_link_target_length(target, LinkKind::Symlink).is_ok());
        assert!(check_link_target_length(target, LinkKind::Hardlink).is_err());
        assert!(check_name_lengths(target).is_err());
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn keys_are_case_insensitive_on_case_folding_hosts() {
        let mut t = tree();
        put(&mut t, "Dir/File", Node::File);
        assert!(t.exists(Path::new("/dest/dir/file")));
    }

    #[test]
    fn host_fs_probes_the_real_filesystem() {
        let temp = tempfile::TempDir::new().unwrap();
        assert!(HostFs.exists(temp.path()));
        assert!(!HostFs.is_symlink(temp.path()).unwrap());
        let root = DestDir::new(temp.path().to_path_buf()).unwrap();
        assert!(
            HostFs
                .canonicalize(&temp.path().join("nope"), &root)
                .is_err()
        );
    }

    fn classified(err: ArchiveError) -> (&'static str, String) {
        match err {
            ArchiveError::Io(e) => ("io", e.to_string()),
            ArchiveError::SecurityViolation { kind } => ("violation", kind.to_string()),
            ArchiveError::SymlinkEscape { path } => ("escape", path.display().to_string()),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn blocker_text_and_category_are_shared() {
        let entry = Path::new("x/./y/z");
        let parent = Path::new("x");

        let (kind, text) = classified(ParentBlocker::File.error(entry, parent));
        assert_eq!(kind, "io");
        assert!(
            text.replace('\\', "/")
                .ends_with("refusing to create x/y/z under the existing file at x")
        );
        let (kind, text) = classified(ParentBlocker::Symlink.error(entry, parent));
        assert_eq!(kind, "violation");
        assert!(
            text.replace('\\', "/")
                .contains("refusing to create x/y/z under the existing symlink at x")
        );
        assert_eq!(
            classified(ParentBlocker::Escape.error(entry, parent)),
            ("escape", "x".to_owned())
        );
    }

    fn blocked_conflict(t: &mut VirtualTree, path: &str) -> Conflict {
        t.try_insert(Path::new(path), Node::File)
            .unwrap_err()
            .into_conflict()
    }

    #[test]
    fn tree_names_a_file_parent() {
        let mut t = tree();
        put(&mut t, "x", Node::File);

        let conflict = blocked_conflict(&mut t, "x/a/f");

        assert_eq!(conflict.occupant, None);
        let (kind, text) = classified(conflict.into_archive_error());
        assert_eq!(kind, "io");
        assert!(
            text.replace('\\', "/")
                .ends_with("refusing to create x/a/f under the existing file at x")
        );
    }

    #[test]
    fn tree_names_a_symlink_parent_that_dangles_loops_or_hits_a_file() {
        for (target, file) in [("t", None), ("x", None), ("t", Some("t"))] {
            let mut t = tree();
            if let Some(file) = file {
                put(&mut t, file, Node::File);
            }
            put(&mut t, "x", sym(target));

            let conflict = blocked_conflict(&mut t, "x/f");

            let (kind, text) = classified(conflict.into_archive_error());
            assert_eq!(kind, "violation", "{target}");
            assert!(
                text.replace('\\', "/")
                    .contains("refusing to create x/f under the existing symlink at x")
            );
        }
    }

    #[test]
    fn tree_keeps_a_parent_that_leaves_the_root_out_of_the_blocker() {
        let mut t = tree();
        put(&mut t, "up", sym(".."));

        assert!(blocked_conflict(&mut t, "up/f").blocked.is_none());
    }

    #[test]
    fn plain_conflict_converts_to_its_io_error() {
        let conflict = Conflict::already_exists(Occupant::File);

        assert_eq!(classified(conflict.into_archive_error()).0, "io");
    }

    #[cfg(unix)]
    mod host_ancestors {
        use super::*;
        use std::os::unix::fs::symlink;

        fn host() -> (tempfile::TempDir, DestDir, PathBuf) {
            let temp = tempfile::TempDir::new().unwrap();
            let dest = temp.path().join("dest");
            let outside = temp.path().join("outside");
            std::fs::create_dir(&dest).unwrap();
            std::fs::create_dir(&outside).unwrap();
            std::fs::write(outside.join("f"), b"x").unwrap();
            let root = DestDir::new(dest).unwrap();
            (temp, root, outside.canonicalize().unwrap())
        }

        fn blocker(root: &DestDir, rel: &str) -> Option<(PathBuf, ParentBlocker)> {
            first_blocking_ancestor(&HostFs, root, Path::new(rel))
        }

        fn found(name: &str, blocker: ParentBlocker) -> (PathBuf, ParentBlocker) {
            (PathBuf::from(name), blocker)
        }

        #[test]
        fn finds_each_kind_of_blocker() {
            let (_temp, root, outside) = host();
            let dest = root.as_path();
            std::fs::write(dest.join("file"), b"x").unwrap();
            std::fs::create_dir(dest.join("real")).unwrap();
            symlink("missing", dest.join("dangling")).unwrap();
            symlink("loop", dest.join("loop")).unwrap();
            symlink("file", dest.join("to_file")).unwrap();
            symlink("real", dest.join("ok")).unwrap();
            symlink(outside.join("f"), dest.join("out_file")).unwrap();
            symlink(&outside, dest.join("out_dir")).unwrap();

            assert_eq!(
                blocker(&root, "file/a/b"),
                Some(found("file", ParentBlocker::File))
            );
            assert_eq!(
                blocker(&root, "dangling/a"),
                Some(found("dangling", ParentBlocker::Symlink))
            );
            assert_eq!(
                blocker(&root, "loop/a/b"),
                Some(found("loop", ParentBlocker::Symlink))
            );
            assert_eq!(
                blocker(&root, "to_file/a"),
                Some(found("to_file", ParentBlocker::Symlink))
            );
            assert_eq!(
                blocker(&root, "out_file/a/b"),
                Some(found("out_file", ParentBlocker::Escape))
            );
            assert_eq!(
                blocker(&root, "out_dir/a/b"),
                Some(found("out_dir", ParentBlocker::Escape))
            );
            assert_eq!(blocker(&root, "ok/a/b"), None);
            assert_eq!(blocker(&root, "real/missing/b"), None);
            assert_eq!(blocker(&root, "missing/a/b"), None);
            assert_eq!(blocker(&root, "top"), None);
        }

        #[test]
        fn an_uninspectable_prefix_blames_nobody() {
            use std::os::unix::fs::PermissionsExt;

            let (_temp, root, _) = host();
            let locked = root.as_path().join("locked");
            std::fs::create_dir(&locked).unwrap();
            std::fs::write(locked.join("f"), b"x").unwrap();
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
            let readable = std::fs::metadata(locked.join("f")).is_ok();

            let result = blocker(&root, "locked/f/x");

            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
            if !readable {
                assert_eq!(result, None);
            }
        }
    }
}

#[cfg(test)]
mod host_fs_tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn containment_is_by_whole_components() {
        let root = Path::new("/mnt/out");

        assert_matches!(
            contain(PathBuf::from("/mnt/out/a"), root),
            Containment::Within(_)
        );
        assert_matches!(
            contain(PathBuf::from("/mnt/outx"), root),
            Containment::Escapes
        );
    }

    #[test]
    #[cfg(unix)]
    fn containment_is_case_sensitive_on_unix() {
        let root = Path::new("/mnt/out");

        assert_matches!(
            contain(PathBuf::from("/mnt/OUT"), root),
            Containment::Escapes
        );
        assert_matches!(
            contain(PathBuf::from("/mnt/OUT/a"), root),
            Containment::Escapes
        );
    }

    #[test]
    #[cfg(not(unix))]
    fn containment_folds_case_off_unix() {
        let root = Path::new("/mnt/out");

        assert_matches!(
            contain(PathBuf::from("/mnt/OUT/a"), root),
            Containment::Within(_)
        );
    }
}

#[cfg(all(test, any(target_os = "macos", target_os = "windows")))]
mod strip_prefix_folded_tests {
    use super::strip_prefix_folded;
    use std::path::Path;

    #[test]
    fn the_remainder_follows_a_case_insensitive_prefix() {
        assert_eq!(
            strip_prefix_folded(Path::new("/Dest/a/b"), Path::new("/dest")),
            Some(Path::new("a/b"))
        );
    }

    #[test]
    fn equal_paths_leave_an_empty_remainder() {
        assert_eq!(
            strip_prefix_folded(Path::new("/dest"), Path::new("/DEST")),
            Some(Path::new(""))
        );
    }

    #[test]
    fn a_base_longer_than_the_path_is_no_prefix() {
        assert_eq!(
            strip_prefix_folded(Path::new("/dest"), Path::new("/dest/a")),
            None
        );
    }

    #[test]
    fn a_sibling_sharing_a_name_prefix_is_no_prefix() {
        assert_eq!(
            strip_prefix_folded(Path::new("/destevil/a"), Path::new("/dest")),
            None
        );
    }
}
