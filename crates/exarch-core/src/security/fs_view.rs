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
//! - symlink chains are cut off after [`MAX_SYMLINK_HOPS`] hops, which may
//!   differ from the host's own limit;
//! - on macOS and Windows hosts names are matched after lowercasing only; names
//!   the host filesystem treats as equal under Unicode normalisation (NFC/NFD)
//!   or special case folding (final sigma) are not modelled;
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

/// Maximum number of symlinks followed while resolving a single path.
pub const MAX_SYMLINK_HOPS: usize = 40;

/// Longest single path component the host accepts (`NAME_MAX`).
pub const MAX_COMPONENT_BYTES: usize = 255;

/// Longest relative path the host accepts (`PATH_MAX`).
pub const MAX_PATH_BYTES: usize = 4096;

/// Rejects entry names the host would refuse with `ENAMETOOLONG`.
///
/// # Errors
///
/// Returns an error if the path or any of its components is too long.
pub fn check_name_lengths(path: &Path) -> io::Result<()> {
    let too_long = path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES
        || path
            .components()
            .any(|c| c.as_os_str().as_encoded_bytes().len() > MAX_COMPONENT_BYTES);
    if too_long {
        return Err(io::Error::new(
            io::ErrorKind::InvalidFilename,
            "file name too long",
        ));
    }
    Ok(())
}

/// Filesystem probes needed while validating archive entries.
pub trait FsView {
    /// Returns `true` if `path` exists, following symlinks.
    fn exists(&self, path: &Path) -> bool;

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

    fn is_symlink(&self, path: &Path) -> io::Result<bool> {
        std::fs::symlink_metadata(path).map(|m| m.file_type().is_symlink())
    }

    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        std::fs::canonicalize(path)
    }
}

/// The kind of a node in the in-memory tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// A directory.
    Dir,
    /// A regular file or materialized hardlink.
    File,
    /// A symlink with its target exactly as stored in the archive.
    Symlink(PathBuf),
}

#[derive(Debug)]
struct TreeNode {
    kind: Node,
    /// Only populated for directories; keyed by the folded component.
    children: HashMap<OsString, usize>,
}

impl TreeNode {
    fn new(kind: Node) -> Self {
        Self {
            kind,
            children: HashMap::new(),
        }
    }
}

const ROOT: usize = 0;

enum Resolved {
    Inside { rel: PathBuf, id: usize },
    Outside(PathBuf),
}

/// In-memory model of the destination directory built from archive entries.
///
/// Stored as a per-directory component trie, so a lookup or insert costs
/// O(bytes of the path) regardless of how many entries share a prefix.
#[derive(Debug)]
pub struct VirtualTree {
    root: PathBuf,
    nodes: Vec<TreeNode>,
}

impl VirtualTree {
    /// Creates an empty tree rooted at `root` (the canonical destination).
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            nodes: vec![TreeNode::new(Node::Dir)],
        }
    }

    /// Records `node` at `rel` (relative to the root), creating missing
    /// parents as directories and following in-root symlinked parents the way
    /// `create_dir_all` does.
    ///
    /// The first node at a path wins, matching extraction that skips an
    /// existing entry; a symlink over a file replaces it, the conservative
    /// choice when extraction overwrites.
    ///
    /// # Errors
    ///
    /// Returns an error where extraction would fail: a parent that is a file,
    /// a parent chain that loops or leaves the root, or a directory entry over
    /// an existing non-directory.
    pub fn insert(&mut self, rel: &Path, node: Node) -> io::Result<()> {
        let Some(name) = rel.file_name() else {
            return Ok(());
        };
        let parent = self.ensure_dir(rel.parent().unwrap_or_else(|| Path::new("")))?;
        let key = fold(name);
        let existing = self.child(parent, name);
        match (existing, node) {
            (None, node) => {
                let id = self.nodes.len();
                self.nodes.push(TreeNode::new(node));
                self.node_mut(parent).children.insert(key.into_owned(), id);
                Ok(())
            }
            (Some(id), Node::Dir) => match self.node(id).kind {
                Node::Dir => Ok(()),
                Node::File => Err(io::Error::from(io::ErrorKind::AlreadyExists)),
                Node::Symlink(_) => {
                    if self.resolves_to_dir(&self.root.join(rel)) {
                        Ok(())
                    } else {
                        Err(io::Error::from(io::ErrorKind::AlreadyExists))
                    }
                }
            },
            (Some(id), node @ Node::Symlink(_)) => {
                if self.node(id).kind == Node::File {
                    self.node_mut(id).kind = node;
                }
                Ok(())
            }
            (Some(_), _) => Ok(()),
        }
    }

    /// Returns `true` if `path` resolves, through symlinks, to a directory.
    pub fn resolves_to_dir(&self, path: &Path) -> bool {
        matches!(
            self.resolve(path),
            Ok(Resolved::Inside { id, .. }) if self.node(id).kind == Node::Dir
        )
    }

    fn node(&self, id: usize) -> &TreeNode {
        &self.nodes[id]
    }

    fn node_mut(&mut self, id: usize) -> &mut TreeNode {
        &mut self.nodes[id]
    }

    fn child(&self, parent: usize, name: &OsStr) -> Option<usize> {
        if name.as_encoded_bytes().len() > MAX_COMPONENT_BYTES {
            return None;
        }
        self.node(parent).children.get(&*fold(name)).copied()
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
            current = match self.child(current, name) {
                None => {
                    let id = self.nodes.len();
                    self.nodes.push(TreeNode::new(Node::Dir));
                    self.node_mut(current)
                        .children
                        .insert(fold(name).into_owned(), id);
                    id
                }
                Some(id) => match self.node(id).kind {
                    Node::Dir => id,
                    Node::File => return Err(io::Error::from(io::ErrorKind::NotADirectory)),
                    Node::Symlink(_) => match self.resolve(&self.root.join(&walked))? {
                        Resolved::Inside { id, .. } if self.node(id).kind == Node::Dir => id,
                        Resolved::Inside { .. } => {
                            return Err(io::Error::from(io::ErrorKind::NotADirectory));
                        }
                        Resolved::Outside(_) => {
                            return Err(io::Error::other("path leaves the extraction root"));
                        }
                    },
                },
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
        Ok(matches!(self.node(id).kind, Node::Symlink(_)))
    }

    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        match self.resolve(path)? {
            Resolved::Inside { rel, .. } => Ok(self.root.join(rel)),
            Resolved::Outside(path) => Ok(path),
        }
    }
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

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn fold(name: &OsStr) -> Cow<'_, OsStr> {
    Cow::Owned(OsString::from(name.to_string_lossy().to_lowercase()))
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn fold(name: &OsStr) -> Cow<'_, OsStr> {
    Cow::Borrowed(name)
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
        assert!(t.canonicalize(Path::new("/dest/l41")).is_err());
        assert!(t.canonicalize(Path::new("/dest/l40")).is_ok());
    }

    #[test]
    fn dangling_symlink_does_not_exist_but_is_a_symlink() {
        let mut t = tree();
        put(&mut t, "d", sym("missing"));
        assert!(!t.exists(Path::new("/dest/d")));
        assert!(t.is_symlink(Path::new("/dest/d")).unwrap());
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
        put(&mut t, "y", Node::File);
        assert!(t.is_symlink(Path::new("/dest/y")).unwrap());
    }

    #[test]
    fn symlink_replaces_earlier_file() {
        let mut t = tree();
        put(&mut t, "y", Node::File);
        put(&mut t, "y", sym("."));
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
        let long_name = "a".repeat(MAX_COMPONENT_BYTES + 1);
        assert!(check_name_lengths(Path::new(&long_name)).is_err());
        let long_path = vec!["a".repeat(200); 21].join("/");
        assert!(check_name_lengths(Path::new(&long_path)).is_err());
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
