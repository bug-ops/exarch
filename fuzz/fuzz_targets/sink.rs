#![no_main]

//! Extraction into a `MemorySink` through `extract_to_sink`.
//!
//! The sink validates against `VirtualTree`, a second implementation of
//! containment, symlink resolution, name folding and duplicate handling. Every
//! run, successful or not, checks what the sink holds against three
//! invariants:
//!
//! 1. no stored path has a proper prefix that is a stored symlink, under the
//!    model's name folding;
//! 2. every stored symlink target, resolved physically from the link's parent
//!    through the other stored links, stays inside the root;
//! 3. no stored path contains `..`, a root, a prefix or an empty component.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::path::Component;
use std::path::Path;

use exarch_core::extract_to_sink;
use exarch_core::ArchiveReader;
use exarch_core::MemoryEntry;
use exarch_core::MemoryLimit;
use exarch_core::MemorySink;
use exarch_core::PathModel;
use exarch_core::SinkOptions;
use libfuzzer_sys::fuzz_target;
use unicode_normalization::UnicodeNormalization;

#[path = "common.rs"]
mod common;

/// The hop bound of `VirtualTree` on the strictest supported host.
const MAX_HOPS: usize = 40;

fuzz_target!(|data: &[u8]| {
    let config = common::config();
    for model in [PathModel::Host, PathModel::Portable] {
        for skip_duplicates in [true, false] {
            let Ok(reader) = ArchiveReader::from_bytes(data, None) else {
                return;
            };
            let mut sink = MemorySink::new(MemoryLimit::from_config(config)).with_path_model(model);
            let options = SinkOptions::default().with_skip_duplicates(skip_duplicates);
            let _ = extract_to_sink(reader, &mut sink, config, &options);
            check_invariants(&sink, model);
        }
    }
});

/// Names are compared the way `PathModel` compares them: exactly on a
/// case-sensitive host, after NFD and a per-character upper/lower/upper fold
/// on macOS and under `Portable`, and without normalisation on Windows.
fn fold(model: PathModel, name: &OsStr) -> String {
    let text = name.to_string_lossy();
    let case_insensitive = model == PathModel::Portable || cfg!(target_os = "macos");
    let windows_host = model == PathModel::Host && cfg!(target_os = "windows");
    if windows_host {
        return upper_lower_upper(text.chars());
    }
    if !case_insensitive {
        return text.into_owned();
    }
    if text.is_ascii() {
        text.to_ascii_uppercase()
    } else {
        upper_lower_upper(text.nfd())
    }
}

fn upper_lower_upper(chars: impl Iterator<Item = char>) -> String {
    chars
        .flat_map(char::to_uppercase)
        .flat_map(char::to_lowercase)
        .flat_map(char::to_uppercase)
        .collect()
}

/// A stored path as its folded components, or `None` when it has a component
/// that is not a plain name (invariant 3).
fn folded_key(model: PathModel, path: &Path) -> Option<Vec<String>> {
    let mut key = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) if !name.is_empty() => key.push(fold(model, name)),
            _ => return None,
        }
    }
    (!key.is_empty()).then_some(key)
}

fn check_invariants(sink: &MemorySink, model: PathModel) {
    let mut symlinks: HashMap<Vec<String>, &Path> = HashMap::new();
    let mut keys: Vec<(Vec<String>, &Path)> = Vec::new();
    for (path, entry) in sink.iter() {
        let Some(key) = folded_key(model, path) else {
            panic!("invariant 3: stored path {path:?} has a non-normal component");
        };
        if let MemoryEntry::Symlink { target } = entry {
            symlinks.insert(key.clone(), target.as_path());
        }
        keys.push((key, path));
    }

    for (key, path) in &keys {
        for end in 1..key.len() {
            assert!(
                !symlinks.contains_key(&key[..end].to_vec()),
                "invariant 1: {path:?} is stored below a stored symlink",
            );
        }
    }

    for (path, entry) in sink.iter() {
        if let MemoryEntry::Symlink { target } = entry {
            check_target_inside(model, path, target, &symlinks);
        }
    }
}

/// Invariant 2: follows `target` from the parent of `link` through the stored
/// symlinks and fails if the walk leaves the root.
fn check_target_inside<'a>(
    model: PathModel,
    link: &Path,
    target: &'a Path,
    symlinks: &HashMap<Vec<String>, &'a Path>,
) {
    let mut current: Vec<OsString> = link
        .parent()
        .map(|parent| {
            parent
                .components()
                .map(|c| c.as_os_str().to_owned())
                .collect()
        })
        .unwrap_or_default();
    let mut pending: Vec<Component<'a>> = target.components().rev().collect();
    let mut hops = 0;

    while let Some(component) = pending.pop() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                assert!(
                    current.pop().is_some(),
                    "invariant 2: symlink {link:?} -> {target:?} leaves the root",
                );
            }
            Component::RootDir | Component::Prefix(_) => {
                panic!("invariant 2: symlink {link:?} -> {target:?} is absolute");
            }
            Component::Normal(name) => {
                current.push(name.to_owned());
                let key: Vec<String> = current.iter().map(|c| fold(model, c)).collect();
                let Some(next) = symlinks.get(&key) else {
                    continue;
                };
                hops += 1;
                if hops > MAX_HOPS {
                    return;
                }
                current.pop();
                pending.extend(next.components().rev());
            }
        }
    }
}
