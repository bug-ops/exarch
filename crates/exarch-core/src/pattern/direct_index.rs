//! Matching of the direct patterns of a list in time bounded by the path.
//!
//! A direct pattern is a literal name, a `*suffix`, an anchored literal path
//! or the match-all pattern. Testing them one by one costs entries times
//! patterns; [`DirectIndex`] answers every pattern of the list with one pass
//! over the path whose cost does not depend on the number of patterns.

use super::Engine;
use super::EntryPattern;
use super::Shape;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::ops::ControlFlow;

/// The positions, in the list, of the patterns that share one key.
type Owners = SmallVec<[usize; 1]>;

#[derive(Default)]
struct Node {
    /// Sorted by byte, so a lookup is a binary search.
    edges: Vec<(u8, Self)>,
    owners: Owners,
}

impl Node {
    fn child(&self, byte: u8) -> Option<&Self> {
        self.edges
            .binary_search_by_key(&byte, |(edge, _)| *edge)
            .ok()
            .and_then(|at| self.edges.get(at))
            .map(|(_, node)| node)
    }

    fn child_or_insert(&mut self, byte: u8) -> Option<&mut Self> {
        let at = self.edges.partition_point(|(edge, _)| *edge < byte);
        if self.edges.get(at).is_none_or(|(edge, _)| *edge != byte) {
            self.edges.insert(at, (byte, Self::default()));
        }
        self.edges.get_mut(at).map(|(_, node)| node)
    }
}

/// A byte trie whose nodes own the patterns whose key ends there.
#[derive(Default)]
struct ByteTrie {
    root: Node,
}

impl ByteTrie {
    fn insert(&mut self, key: impl IntoIterator<Item = u8>, owner: usize) {
        let mut node = &mut self.root;
        for byte in key {
            // An edge was just created or found, so `None` cannot happen.
            let Some(next) = node.child_or_insert(byte) else {
                return;
            };
            node = next;
        }
        node.owners.push(owner);
    }
}

fn visit_owners(
    owners: &Owners,
    visit: &mut impl FnMut(usize) -> ControlFlow<()>,
) -> ControlFlow<()> {
    owners.iter().try_for_each(|owner| visit(*owner))
}

/// Every direct pattern of a list, indexed by what it matches.
///
/// Floating and anchored keys never share a structure: `x` selects a
/// component anywhere, `./x` only the first one.
#[derive(Default)]
pub(super) struct DirectIndex {
    /// Literal names, looked up once per path component.
    floating: HashMap<Box<[u8]>, Owners>,
    /// Anchored paths, walked forward over the path.
    anchored: ByteTrie,
    /// `*suffix` names, keyed by the reversed suffix and walked from the end
    /// of each component; the root owns the bare `*`.
    suffixes: ByteTrie,
    match_all: Owners,
}

impl DirectIndex {
    /// Indexes the direct patterns among `patterns`, each with its position in
    /// the list; glob patterns are left to the caller.
    pub(super) fn new<'a>(patterns: impl IntoIterator<Item = (usize, &'a EntryPattern)>) -> Self {
        let mut index = Self::default();
        for (position, pattern) in patterns {
            if !matches!(pattern.engine, Engine::Direct) {
                continue;
            }
            match &pattern.shape {
                Shape::MatchAll => index.match_all.push(position),
                Shape::Floating(name) => match name.as_bytes().strip_prefix(b"*") {
                    Some(suffix) => index
                        .suffixes
                        .insert(suffix.iter().rev().copied(), position),
                    None => index
                        .floating
                        .entry(name.as_bytes().into())
                        .or_default()
                        .push(position),
                },
                Shape::Anchored(path) => {
                    index.anchored.insert(path.bytes(), position);
                }
            }
        }
        index
    }

    /// Calls `visit` with the position of every direct pattern that matches
    /// `path`, a path already reduced by `normalized`, until it breaks. A
    /// pattern may be visited more than once.
    pub(super) fn visit(
        &self,
        path: &[u8],
        mut visit: impl FnMut(usize) -> ControlFlow<()>,
    ) -> ControlFlow<()> {
        visit_owners(&self.match_all, &mut visit)?;
        self.visit_anchored(path, &mut visit)?;
        path.split(|byte| *byte == b'/')
            .try_for_each(|component| self.visit_component(component, &mut visit))
    }

    /// The anchored patterns that equal the path or a leading run of its
    /// components; the walk is bounded by the longest key.
    fn visit_anchored(
        &self,
        path: &[u8],
        visit: &mut impl FnMut(usize) -> ControlFlow<()>,
    ) -> ControlFlow<()> {
        let mut node = &self.anchored.root;
        let mut rest = path;
        loop {
            if rest.first().is_none_or(|byte| *byte == b'/') {
                visit_owners(&node.owners, visit)?;
            }
            let Some((byte, tail)) = rest.split_first() else {
                return ControlFlow::Continue(());
            };
            let Some(next) = node.child(*byte) else {
                return ControlFlow::Continue(());
            };
            node = next;
            rest = tail;
        }
    }

    fn visit_component(
        &self,
        component: &[u8],
        visit: &mut impl FnMut(usize) -> ControlFlow<()>,
    ) -> ControlFlow<()> {
        if let Some(owners) = self.floating.get(component) {
            visit_owners(owners, visit)?;
        }
        let mut node = &self.suffixes.root;
        visit_owners(&node.owners, visit)?;
        for byte in component.iter().rev() {
            let Some(next) = node.child(*byte) else {
                break;
            };
            node = next;
            visit_owners(&node.owners, visit)?;
        }
        ControlFlow::Continue(())
    }
}
