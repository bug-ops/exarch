//! Shared fixtures and a recording sink for the sink integration tests.

#![allow(dead_code, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::EntrySink;
use exarch_core::SafePath;
use exarch_core::SanitizedMode;
use exarch_testkit::raw_zip::RawEntry;
use exarch_testkit::raw_zip::RawZip;

/// What an extraction left behind, by resolved path.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct Tree {
    pub files: BTreeMap<PathBuf, Vec<u8>>,
    pub symlinks: BTreeMap<PathBuf, PathBuf>,
    pub dirs: BTreeSet<PathBuf>,
}

/// A sink that records every delivery.
#[derive(Default)]
pub struct RecordingSink {
    pub tree: Tree,
    pub modes: BTreeMap<PathBuf, Option<u32>>,
    pub finished: Vec<PathBuf>,
}

impl EntrySink for RecordingSink {
    type File = Vec<u8>;

    fn create_directory(&mut self, path: &SafePath) -> io::Result<()> {
        self.tree.dirs.insert(path.as_path().to_path_buf());
        Ok(())
    }

    fn create_file(
        &mut self,
        path: &SafePath,
        mode: Option<SanitizedMode>,
        _size: u64,
    ) -> io::Result<Vec<u8>> {
        self.modes.insert(
            path.as_path().to_path_buf(),
            mode.map(SanitizedMode::as_u32),
        );
        Ok(Vec::new())
    }

    fn finish_file(&mut self, path: &SafePath, file: Vec<u8>) -> io::Result<()> {
        self.finished.push(path.as_path().to_path_buf());
        self.tree.files.insert(path.as_path().to_path_buf(), file);
        Ok(())
    }

    fn create_symlink(&mut self, link: &SafePath, target: &Path) -> io::Result<()> {
        self.tree.files.remove(link.as_path());
        self.tree
            .symlinks
            .insert(link.as_path().to_path_buf(), target.to_path_buf());
        Ok(())
    }

    fn create_hardlink(&mut self, link: &SafePath, target: &SafePath) -> io::Result<()> {
        let bytes = self
            .tree
            .files
            .get(target.as_path())
            .cloned()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        self.tree.files.insert(link.as_path().to_path_buf(), bytes);
        Ok(())
    }
}

/// Walks `root` without following links.
pub fn walk(root: &Path) -> Tree {
    fn visit(root: &Path, dir: &Path, tree: &mut Tree) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let rel = path.strip_prefix(root).unwrap().to_path_buf();
            let file_type = std::fs::symlink_metadata(&path).unwrap().file_type();
            if file_type.is_symlink() {
                tree.symlinks
                    .insert(rel, std::fs::read_link(&path).unwrap());
            } else if file_type.is_dir() {
                tree.dirs.insert(rel);
                visit(root, &path, tree);
            } else {
                tree.files.insert(rel, std::fs::read(&path).unwrap());
            }
        }
    }
    let mut tree = Tree::default();
    visit(root, root, &mut tree);
    tree
}

/// One TAR member: header block plus padded data.
pub fn tar_entry(name: &str, kind: tar::EntryType, data: &[u8], link: Option<&str>) -> Vec<u8> {
    tar_entry_mode(name, kind, data, link, 0o644)
}

pub fn tar_entry_mode(
    name: &str,
    kind: tar::EntryType,
    data: &[u8],
    link: Option<&str>,
    mode: u32,
) -> Vec<u8> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(kind);
    header.set_mode(mode);
    header.set_size(data.len() as u64);
    header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
    if let Some(link) = link {
        header.set_link_name(link).unwrap();
    }
    header.set_cksum();
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(data);
    bytes.resize(bytes.len().next_multiple_of(512), 0);
    bytes
}

pub fn tar_file(name: &str, data: &[u8]) -> Vec<u8> {
    tar_entry(name, tar::EntryType::Regular, data, None)
}

pub fn tar_dir(name: &str) -> Vec<u8> {
    tar_entry(name, tar::EntryType::Directory, b"", None)
}

pub fn tar_symlink(name: &str, target: &str) -> Vec<u8> {
    tar_entry(name, tar::EntryType::Symlink, b"", Some(target))
}

pub fn tar_hardlink(name: &str, target: &str) -> Vec<u8> {
    tar_entry(name, tar::EntryType::Link, b"", Some(target))
}

pub fn tar_archive(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = entries.concat();
    bytes.resize(bytes.len() + 1024, 0);
    bytes
}

pub fn zip_file(name: &str, data: &[u8]) -> RawEntry {
    RawEntry::stored(name, data)
}

pub fn zip_dir(name: &str) -> RawEntry {
    RawEntry {
        external_attributes: 0o040_755 << 16,
        ..RawEntry::stored(name, b"")
    }
}

pub fn zip_symlink(name: &str, target: &str) -> RawEntry {
    RawEntry {
        external_attributes: 0o120_777 << 16,
        ..RawEntry::stored(name, target.as_bytes())
    }
}

pub fn zip_archive(entries: Vec<RawEntry>) -> Vec<u8> {
    RawZip::new(entries).build().bytes
}

/// A comparable description of a failure: the variant and, where the variant
/// carries one, its cause. An I/O error compares as a variant only: the host
/// reports the errno its syscalls return, the sink the closest kind.
pub fn signature(error: &ArchiveError) -> String {
    match error {
        ArchiveError::PartialExtraction(partial) => signature(partial.cause()),
        ArchiveError::SecurityViolation { kind, .. } => format!("SecurityViolation({kind:?})"),
        ArchiveError::Io(_) => "Io".to_owned(),
        ArchiveError::QuotaExceeded { resource } => format!("QuotaExceeded({resource:?})"),
        other => format!("{:?}", std::mem::discriminant(other)),
    }
}
