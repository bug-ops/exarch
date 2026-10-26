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

use crate::closed_enum::closed_enum;

/// Maximum number of symlinks followed while resolving a single path, as the
/// host's `realpath` allows it.
#[cfg(target_os = "macos")]
pub const MAX_SYMLINK_HOPS: usize = 33;

/// Maximum number of symlinks followed while resolving a single path, as the
/// host's `realpath` allows it.
#[cfg(all(target_os = "linux", target_env = "musl"))]
pub const MAX_SYMLINK_HOPS: usize = 39;

/// Maximum number of symlinks followed while resolving a single path, as the
/// host's `realpath` allows it.
#[cfg(all(target_os = "linux", not(target_env = "musl")))]
pub const MAX_SYMLINK_HOPS: usize = 40;

/// Maximum number of symlinks followed while resolving a single path, as the
/// host's `realpath` allows it.
#[cfg(target_os = "windows")]
pub const MAX_SYMLINK_HOPS: usize = 63;

/// Maximum number of symlinks followed while resolving a single path. A low
/// guess can only turn a PASS into a false FAIL.
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub const MAX_SYMLINK_HOPS: usize = 32;

/// Longest single path component the host accepts (`NAME_MAX`), in bytes, or
/// in UTF-16 units on Windows.
pub const MAX_COMPONENT_LEN: usize = 255;

/// Longest relative path the host accepts (`PATH_MAX` less the terminator), in
/// bytes.
#[cfg(target_os = "linux")]
pub const MAX_PATH_LEN: usize = 4095;

/// Longest relative path the host accepts, in UTF-16 units.
///
/// 32767 is the documented limit of an extended-length path. A symlink target
/// is bounded much lower, see [`MAX_SYMLINK_TARGET_LEN`].
#[cfg(target_os = "windows")]
pub const MAX_PATH_LEN: usize = 32767;

/// Longest relative path the host accepts (`PATH_MAX` less the terminator), in
/// bytes. A low guess can only turn a PASS into a false FAIL.
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub const MAX_PATH_LEN: usize = 1023;

/// Longest symlink target the host accepts, in UTF-16 units.
///
/// `CreateSymbolicLinkW` stores the substitute and print names in a 16 KiB
/// reparse buffer after a 20-byte header. Extraction only creates relative
/// targets (a `Prefix` or `RootDir` component is rejected), where both names
/// are equal, so `2 * 2n <= 16384 - 20` gives `n <= 4091`. Absolute targets
/// (`\??\` prefix) would allow fewer units but are never created.
#[cfg(target_os = "windows")]
pub const MAX_SYMLINK_TARGET_LEN: usize = 4091;

/// Longest symlink target the host accepts (`PATH_MAX` less the terminator),
/// in bytes.
#[cfg(not(target_os = "windows"))]
pub const MAX_SYMLINK_TARGET_LEN: usize = MAX_PATH_LEN;

/// Longest symlink target in bytes that can pass the
/// [`MAX_SYMLINK_TARGET_LEN`] check; the read and allocation cap for targets
/// stored as bytes.
///
/// On Windows a UTF-16 unit takes at most 3 UTF-8 bytes, so a byte cap never
/// rejects a target the unit check accepts.
#[cfg(target_os = "windows")]
pub const MAX_SYMLINK_TARGET_BYTES: usize = MAX_SYMLINK_TARGET_LEN * 3;

/// Longest symlink target in bytes that can pass the
/// [`MAX_SYMLINK_TARGET_LEN`] check; the read and allocation cap for targets
/// stored as bytes.
#[cfg(not(target_os = "windows"))]
pub const MAX_SYMLINK_TARGET_BYTES: usize = MAX_SYMLINK_TARGET_LEN;

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
pub fn check_name_lengths(path: &Path) -> io::Result<()> {
    let too_long = name_len(path.as_os_str()) > MAX_PATH_LEN
        || path
            .components()
            .any(|c| name_len(c.as_os_str()) > MAX_COMPONENT_LEN);
    if too_long {
        return Err(name_too_long());
    }
    Ok(())
}

/// Rejects a link target the host would refuse with `ENAMETOOLONG`.
///
/// A symlink target is checked against [`MAX_SYMLINK_TARGET_LEN`] only, as
/// `symlink(2)` does; a hardlink target is checked like an entry name.
///
/// # Errors
///
/// Returns an error if the target is too long for `kind`.
pub fn check_link_target_length(target: &Path, kind: LinkKind) -> io::Result<()> {
    match kind {
        LinkKind::Symlink if name_len(target.as_os_str()) > MAX_SYMLINK_TARGET_LEN => {
            Err(name_too_long())
        }
        LinkKind::Symlink => Ok(()),
        LinkKind::Hardlink => check_name_lengths(target),
    }
}

/// The error for a name beyond the host's limits.
#[must_use]
pub fn name_too_long() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidFilename, "file name too long")
}

/// Filesystem probes needed while validating archive entries.
pub trait FsView {
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

    /// Resolves `path` to its canonical form.
    ///
    /// # Errors
    ///
    /// Returns an error if a component is missing or the chain cannot be
    /// resolved.
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf>;
}

/// The real filesystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostFs;

impl FsView for HostFs {
    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn is_dir(&self, path: &Path) -> bool {
        path.is_dir()
    }

    fn is_symlink(&self, path: &Path) -> io::Result<bool> {
        std::fs::symlink_metadata(path).map(|m| m.file_type().is_symlink())
    }

    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        std::fs::canonicalize(path)
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
pub struct NameCollision {
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
}

/// A failed [`VirtualTree::try_insert`].
#[derive(Debug)]
pub struct Conflict {
    /// The error `insert` would report.
    pub(crate) error: io::Error,
    /// `None` when the failure is in the parent chain, not at the path itself.
    pub(crate) occupant: Option<Occupant>,
}

impl Conflict {
    pub(crate) fn already_exists(occupant: Occupant) -> Self {
        Self {
            error: io::Error::from(io::ErrorKind::AlreadyExists),
            occupant: Some(occupant),
        }
    }
}

impl From<io::Error> for Conflict {
    fn from(error: io::Error) -> Self {
        Self {
            error,
            occupant: None,
        }
    }
}

type FoldFn = for<'a> fn(&'a OsStr) -> Cow<'a, OsStr>;

/// The kind of a node in the in-memory tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
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
    fn new(kind: Node, name: &OsStr) -> Self {
        Self {
            kind,
            name: name.to_os_string(),
            children: HashMap::new(),
            folded: HashMap::new(),
            empty_merges: Vec::new(),
        }
    }
}

const ROOT: usize = 0;

enum Resolved {
    Inside { rel: PathBuf, id: usize },
    Outside(PathBuf),
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
pub struct VirtualTree {
    root: PathBuf,
    nodes: Vec<TreeNode>,
    fold: FoldFn,
    collisions: Vec<NameCollision>,
    /// Directories holding at least one empty merge.
    empty_merge_nodes: Vec<usize>,
}

impl VirtualTree {
    /// Creates an empty tree rooted at `root` (the canonical destination).
    pub fn new(root: &Path) -> Self {
        Self::with_fold(root, fold)
    }

    pub(crate) fn with_fold(root: &Path, fold: FoldFn) -> Self {
        Self {
            root: root.to_path_buf(),
            nodes: vec![TreeNode::new(Node::Dir, OsStr::new(""))],
            fold,
            collisions: Vec::new(),
            empty_merge_nodes: Vec::new(),
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
    /// tell what overwriting would do.
    pub(crate) fn try_insert(&mut self, rel: &Path, node: Node) -> Result<(), Conflict> {
        let Some(name) = rel.file_name() else {
            return Ok(());
        };
        let parent = self.ensure_dir(rel.parent().unwrap_or_else(|| Path::new("")))?;
        let existing = self.lookup(parent, name);
        if let Some(found) = existing {
            self.settle_alias(parent, found, name, &node, rel, false);
        }
        match (existing.map(|f| f.id), node) {
            (None, node) => {
                self.add_child(parent, name, node);
                Ok(())
            }
            (Some(id), Node::Dir) => match self.node(id).kind {
                Node::Dir => Ok(()),
                Node::File => Err(Conflict::already_exists(Occupant::File)),
                Node::OpaqueSymlink => Err(Conflict::already_exists(Occupant::Symlink)),
                Node::Symlink(_) => {
                    if self.resolves_to_dir(&self.root.join(rel)) {
                        Ok(())
                    } else {
                        Err(Conflict::already_exists(Occupant::Symlink))
                    }
                }
            },
            (Some(id), node @ (Node::Symlink(_) | Node::OpaqueSymlink)) => {
                match self.node(id).kind {
                    Node::File => {
                        self.node_mut(id).kind = node;
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
                }),
                Node::Symlink(_) | Node::OpaqueSymlink => {
                    Err(Conflict::already_exists(Occupant::Symlink))
                }
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn insert(&mut self, rel: &Path, node: Node) -> io::Result<()> {
        self.try_insert(rel, node)
            .map_err(|conflict| conflict.error)
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
    pub fn resolves_to_dir(&self, path: &Path) -> bool {
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
    ) {
        if !found.alias {
            return;
        }
        self.node_mut(parent)
            .children
            .insert(name.to_os_string(), found.id);
        let existing = self.node(found.id);
        let has_contents = incoming_has_contents || !existing.children.is_empty();
        let kind = CollisionKind::of(&existing.kind, incoming_node, has_contents);
        let existing_path = incoming.with_file_name(&existing.name);
        if kind == CollisionKind::Directories {
            let node = self.node_mut(found.id);
            node.empty_merges
                .push((existing_path, incoming.to_path_buf()));
            self.empty_merge_nodes.push(found.id);
            return;
        }
        self.collisions.push(NameCollision {
            existing: existing_path,
            incoming: incoming.to_path_buf(),
            kind,
        });
    }

    fn node(&self, id: usize) -> &TreeNode {
        &self.nodes[id]
    }

    fn node_mut(&mut self, id: usize) -> &mut TreeNode {
        &mut self.nodes[id]
    }

    fn lookup(&self, parent: usize, name: &OsStr) -> Option<Found> {
        if name_len(name) > MAX_COMPONENT_LEN {
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
    fn add_child(&mut self, parent: usize, name: &OsStr, kind: Node) -> usize {
        let id = self.nodes.len();
        self.nodes.push(TreeNode::new(kind, name));
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
        id
    }

    fn ensure_dir(&mut self, rel: &Path) -> io::Result<usize> {
        let mut current = ROOT;
        let mut walked = PathBuf::new();
        for component in rel.components() {
            let name = match component {
                Component::Normal(name) => name,
                Component::CurDir => continue,
                _ => return Err(io::Error::from(io::ErrorKind::InvalidInput)),
            };
            walked.push(name);
            current = match self.lookup(current, name) {
                None => self.add_child(current, name, Node::Dir),
                Some(found) => {
                    self.settle_alias(current, found, name, &Node::Dir, &walked, true);
                    match self.node(found.id).kind {
                        Node::Dir => found.id,
                        Node::File => return Err(io::Error::from(io::ErrorKind::NotADirectory)),
                        Node::OpaqueSymlink => return Err(unread_target_error()),
                        Node::Symlink(_) => match self.resolve(&self.root.join(&walked))? {
                            Resolved::Inside { id, .. } if self.node(id).kind == Node::Dir => id,
                            Resolved::Inside { .. } => {
                                return Err(io::Error::from(io::ErrorKind::NotADirectory));
                            }
                            Resolved::Outside(_) => {
                                return Err(io::Error::other("path leaves the extraction root"));
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
            return Ok(Resolved::Outside(lexical(path.components())));
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
                        return Ok(Resolved::Outside(self.leave_root(pending)));
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
                            current.push(name);
                        }
                        Node::File => {
                            if !pending.is_empty() {
                                return Err(io::Error::from(io::ErrorKind::NotADirectory));
                            }
                            stack.push(id);
                            current.push(name);
                        }
                        Node::OpaqueSymlink => {
                            if !pending.is_empty() {
                                return Err(unread_target_error());
                            }
                            stack.push(id);
                            current.push(name);
                        }
                        Node::Symlink(target) => {
                            hops += 1;
                            if hops > MAX_SYMLINK_HOPS {
                                return Err(io::Error::other("too many levels of symbolic links"));
                            }
                            if target.has_root()
                                || target.components().next().is_some_and(is_prefix)
                            {
                                return Ok(Resolved::Outside(lexical(
                                    target.components().chain(pending),
                                )));
                            }
                            for part in target.components().rev() {
                                pending.push_front(part);
                            }
                        }
                    }
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Ok(Resolved::Outside(lexical(
                        std::iter::once(component).chain(pending),
                    )));
                }
            }
        }
        Ok(Resolved::Inside {
            rel: current,
            id: stack.last().copied().unwrap_or(ROOT),
        })
    }

    fn leave_root(&self, remaining: VecDeque<Component<'_>>) -> PathBuf {
        let base = self.root.parent().unwrap_or(&self.root);
        let mut out = base.to_path_buf();
        for component in remaining {
            match component {
                Component::ParentDir => {
                    out.pop();
                }
                Component::Normal(name) => out.push(name),
                _ => {}
            }
        }
        out
    }
}

impl FsView for VirtualTree {
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

    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        match self.resolve(path)? {
            Resolved::Inside { id, .. } if self.node(id).kind == Node::OpaqueSymlink => {
                Err(unread_target_error())
            }
            Resolved::Inside { rel, .. } => Ok(self.root.join(rel)),
            Resolved::Outside(path) => Ok(path),
        }
    }
}

fn unread_target_error() -> io::Error {
    io::Error::other("path runs through a symlink whose target was not read")
}

fn is_prefix(component: Component<'_>) -> bool {
    matches!(component, Component::Prefix(_))
}

fn lexical<'a>(components: impl Iterator<Item = Component<'a>>) -> PathBuf {
    let mut out = PathBuf::new();
    for component in components {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

/// Compares names the way the host does, as far as it can be modelled.
///
/// Non-UTF-8 names are folded lossily, which can only merge more names, and a
/// merge of differently spelled names is always reported.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn fold(name: &OsStr) -> Cow<'_, OsStr> {
    let text = name.to_string_lossy();
    let folded = if text.is_ascii() {
        text.to_ascii_uppercase()
    } else {
        fold_unicode(&text)
    };
    Cow::Owned(OsString::from(folded))
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn fold(name: &OsStr) -> Cow<'_, OsStr> {
    Cow::Borrowed(name)
}

/// APFS compares canonically decomposed names case-insensitively.
#[cfg(target_os = "macos")]
fn fold_unicode(text: &str) -> String {
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
#[cfg(any(target_os = "macos", target_os = "windows"))]
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

    fn tree() -> VirtualTree {
        VirtualTree::new(Path::new("/dest"))
    }

    fn put(t: &mut VirtualTree, path: &str, node: Node) {
        t.insert(Path::new(path), node).unwrap();
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
        let err = t.canonicalize(Path::new("/dest/nope")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn in_root_chain_resolves_to_final_location() {
        let mut t = tree();
        put(&mut t, "real", Node::Dir);
        put(&mut t, "b", sym("real"));
        put(&mut t, "a", sym("b"));
        assert_eq!(
            t.canonicalize(Path::new("/dest/a")).unwrap(),
            PathBuf::from("/dest/real")
        );
    }

    #[test]
    fn chain_leaving_root_yields_outside_path() {
        let mut t = tree();
        put(&mut t, "y", sym("."));
        put(&mut t, "d", sym("y/.."));
        put(&mut t, "e", sym("d/.."));
        let resolved = t.canonicalize(Path::new("/dest/e/secret")).unwrap();
        assert!(!resolved.starts_with("/dest"), "{resolved:?}");
    }

    #[test]
    fn symlink_loop_is_an_error() {
        let mut t = tree();
        put(&mut t, "a", sym("b"));
        put(&mut t, "b", sym("a"));
        assert!(t.canonicalize(Path::new("/dest/a")).is_err());
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
        assert!(t.canonicalize(Path::new(&over)).is_err());
        assert!(t.canonicalize(Path::new(&at)).is_ok());
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
        assert!(
            t.canonicalize(Path::new(&format!("/dest/l{resolvable}")))
                .is_ok()
        );
        assert!(
            t.canonicalize(Path::new(&format!("/dest/l{}", resolvable + 1)))
                .is_err()
        );
    }

    fn ascii_upper(name: &OsStr) -> Cow<'_, OsStr> {
        Cow::Owned(OsString::from(name.to_string_lossy().to_ascii_uppercase()))
    }

    fn folding_tree() -> VirtualTree {
        VirtualTree::with_fold(Path::new("/dest"), ascii_upper)
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

        let mut t = VirtualTree::with_fold(Path::new("/dest"), counting);
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
        assert!(t.canonicalize(Path::new("/dest/d")).is_err());
        assert!(t.canonicalize(Path::new("/dest/d/x")).is_err());
        assert!(t.insert(Path::new("d/f"), Node::File).is_err());
    }

    #[test]
    fn a_chain_ending_at_an_opaque_symlink_does_not_resolve() {
        let mut t = tree();
        put(&mut t, "d", Node::OpaqueSymlink);
        put(&mut t, "l", sym("d"));
        assert!(t.canonicalize(Path::new("/dest/l")).is_err());
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
            let conflict = t.try_insert(Path::new("d"), node).unwrap_err();
            assert_eq!(conflict.error.kind(), io::ErrorKind::AlreadyExists);
            assert_eq!(conflict.occupant, Some(Occupant::Symlink));
        }
        assert_eq!(
            t.canonicalize(Path::new("/dest/d")).unwrap(),
            PathBuf::from("/dest/real")
        );
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
        let conflict = t.try_insert(Path::new("d"), Node::File).unwrap_err();
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
        let err = t
            .canonicalize(&Path::new("/dest/d").join(&long))
            .unwrap_err();
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
        assert!(HostFs.canonicalize(&temp.path().join("nope")).is_err());
    }
}
