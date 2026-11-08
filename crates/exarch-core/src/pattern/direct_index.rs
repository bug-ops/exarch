//! Matching of the direct patterns of a list in time bounded by the path.
//!
//! A direct pattern is a literal name, a `*suffix`, an anchored literal path
//! or the match-all pattern. Testing them one by one costs entries times
//! patterns; [`DirectIndex`] answers every pattern of the list with hash
//! probes whose number depends on the path and on the distinct key lengths
//! (at most 255), not on the number of patterns. Memory stays proportional to
//! the pattern bytes.

use super::Engine;
use super::EntryPattern;
use super::Shape;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::ops::ControlFlow;

/// The positions, in the list, of the patterns that share one key.
type Owners = SmallVec<[usize; 1]>;

type KeyMap = HashMap<Box<[u8]>, Owners>;

fn add_owner(map: &mut KeyMap, key: &[u8], owner: usize) {
    map.entry(key.into()).or_default().push(owner);
}

fn visit_owners(
    owners: &Owners,
    visit: &mut impl FnMut(usize) -> ControlFlow<()>,
) -> ControlFlow<()> {
    owners.iter().try_for_each(|owner| visit(*owner))
}

/// The distinct key lengths of `map`, ascending.
fn key_lengths(map: &KeyMap) -> Box<[usize]> {
    let mut lengths: Vec<usize> = map.keys().map(|key| key.len()).collect();
    lengths.sort_unstable();
    lengths.dedup();
    lengths.into_boxed_slice()
}

/// Every direct pattern of a list, indexed by what it matches.
///
/// Floating and anchored keys never share a structure: `x` selects a
/// component anywhere, `./x` only the first one.
#[derive(Default)]
pub(super) struct DirectIndex {
    /// Literal names, looked up once per path component.
    floating: KeyMap,
    /// Anchored paths, probed at every `/` boundary of the path and at its
    /// end, never past the longest key.
    anchored: KeyMap,
    longest_anchored: usize,
    /// The suffix of each `*suffix` name; the empty key is the bare `*`.
    suffixes: KeyMap,
    /// The distinct suffix lengths, ascending: the tail of each component is
    /// probed once per length.
    suffix_lengths: Box<[usize]>,
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
                    Some(suffix) => add_owner(&mut index.suffixes, suffix, position),
                    None => add_owner(&mut index.floating, name.as_bytes(), position),
                },
                Shape::Anchored(path) => add_owner(&mut index.anchored, path.as_bytes(), position),
            }
        }
        index.suffix_lengths = key_lengths(&index.suffixes);
        index.longest_anchored = index
            .anchored
            .keys()
            .map(|key| key.len())
            .max()
            .unwrap_or(0);
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
    /// components: the prefixes ending before a `/` or at the end, none longer
    /// than the longest key.
    fn visit_anchored(
        &self,
        path: &[u8],
        visit: &mut impl FnMut(usize) -> ControlFlow<()>,
    ) -> ControlFlow<()> {
        if self.anchored.is_empty() {
            return ControlFlow::Continue(());
        }
        let slashes = path
            .iter()
            .enumerate()
            .take(self.longest_anchored.saturating_add(1))
            .filter(|(_, byte)| **byte == b'/')
            .map(|(at, _)| at);
        let end = (path.len() <= self.longest_anchored).then_some(path.len());
        slashes.chain(end).try_for_each(|boundary| {
            path.get(..boundary)
                .and_then(|prefix| self.anchored.get(prefix))
                .map_or(ControlFlow::Continue(()), |owners| {
                    visit_owners(owners, visit)
                })
        })
    }

    fn visit_component(
        &self,
        component: &[u8],
        visit: &mut impl FnMut(usize) -> ControlFlow<()>,
    ) -> ControlFlow<()> {
        if let Some(owners) = self.floating.get(component) {
            visit_owners(owners, visit)?;
        }
        for length in &self.suffix_lengths {
            let Some(start) = component.len().checked_sub(*length) else {
                break;
            };
            if let Some(owners) = component
                .get(start..)
                .and_then(|suffix| self.suffixes.get(suffix))
            {
                visit_owners(owners, visit)?;
            }
        }
        ControlFlow::Continue(())
    }
}
