//! Where the entries of a listed archive land under the destination.
//!
//! A front end that wants to know which host paths an extraction would write
//! (for a conflict pre-check, say) must not re-implement the entry-to-path
//! mapping: it differs in the details that matter (Windows drive prefixes,
//! `./` and leading separators, symlinked parents, non-file entries). This
//! module derives the landing from the same validation and projection that
//! `verify` and the sink use.

use std::collections::HashSet;
use std::path::Path;
use std::path::PathBuf;

use crate::EntrySelection;
use crate::SecurityConfig;
use crate::SkipKind;
use crate::formats::common::is_extension_allowed;
use crate::inspection::manifest::ArchiveEntry;
use crate::inspection::manifest::ArchiveManifest;
use crate::inspection::manifest::LinkTarget;
use crate::inspection::manifest::ManifestEntryKind;
use crate::security::context::ValidationContext;
use crate::security::fs_view::CollisionRecording;
use crate::security::fs_view::LandingLimits;
use crate::security::fs_view::Node;
use crate::security::fs_view::NodeBudget;
use crate::security::fs_view::PathModel;
use crate::security::fs_view::VirtualRoot;
use crate::security::fs_view::VirtualTree;
use crate::security::validator::Gated;
use crate::security::validator::route_validated;
use crate::types::SafePath;
use crate::types::SafeSymlink;

/// The destination-relative path an entry lands at, derived lexically.
///
/// The path is relative and normalized (no root, drive prefix, `.` or `..`),
/// its name lengths fit the host, and every symlink among the earlier entries
/// it passes through has been resolved. It is a **lexical** answer: it says
/// nothing about what already exists on disk, so it does not claim that
/// writing there stays inside the destination. A caller that acts on the
/// filesystem must still use `symlink_metadata` and the extraction itself for
/// containment.
///
/// # Examples
///
/// ```
/// use exarch_core::ArchiveEntry;
/// use exarch_core::ArchiveManifest;
/// use exarch_core::ArchiveType;
/// use exarch_core::ManifestEntryKind;
/// use exarch_core::SecurityConfig;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut manifest = ArchiveManifest::new(ArchiveType::Tar);
/// manifest.add_entry(ArchiveEntry::new(
///     "./a/b.txt".into(),
///     ManifestEntryKind::Directory,
/// ))?;
/// let config = SecurityConfig::default();
/// let landed: Vec<_> = manifest.landing_paths(&config).collect();
/// assert_eq!(landed[0].1.as_path(), std::path::Path::new("a/b.txt"));
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LandingPath(PathBuf);

impl LandingPath {
    /// The relative path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Consumes the value and returns the relative path.
    #[must_use]
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }
}

impl AsRef<Path> for LandingPath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

/// What extraction does with a listed entry that validation accepts.
///
/// # Examples
///
/// ```
/// use exarch_core::ArchiveEntry;
/// use exarch_core::ArchiveManifest;
/// use exarch_core::ArchiveType;
/// use exarch_core::Disposition;
/// use exarch_core::ManifestEntryKind;
/// use exarch_core::SecurityConfig;
/// use exarch_core::SkipKind;
/// use std::assert_matches;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = SecurityConfig::default().try_add_include("a")?;
/// let mut manifest = ArchiveManifest::with_selection(ArchiveType::Tar, config.selection.clone());
/// manifest.add_entry(ArchiveEntry::new(
///     "a/x".into(),
///     ManifestEntryKind::Directory,
/// ))?;
/// manifest.add_entry(ArchiveEntry::new(
///     "b/y".into(),
///     ManifestEntryKind::Directory,
/// ))?;
/// let dispositions: Vec<_> = manifest.dispositions(&config).map(|(_, d)| d).collect();
/// assert_matches!(dispositions[0], Disposition::Extract(_));
/// assert_matches!(dispositions[1], Disposition::Skip(SkipKind::NotSelected));
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Disposition {
    /// The entry is extracted and lands here.
    Extract(LandingPath),
    /// The entry is validated but not extracted, for this reason.
    Skip(SkipKind),
}

/// What put a path in the landing set.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum LandingKind<'a> {
    /// An archive entry lands here.
    Entry(&'a ArchiveEntry),
    /// No entry names this path, but extraction creates it as a parent
    /// directory of one that lands below it.
    ImplicitParent,
}

/// A path extraction creates, with what put it there.
#[derive(Debug, Clone)]
pub struct Landing<'a> {
    path: LandingPath,
    kind: LandingKind<'a>,
}

impl<'a> Landing<'a> {
    /// Where the path lands.
    #[must_use]
    pub const fn path(&self) -> &LandingPath {
        &self.path
    }

    /// Whether an entry or an implied parent directory lands here.
    #[must_use]
    pub const fn kind(&self) -> LandingKind<'a> {
        self.kind
    }
}

impl ArchiveManifest {
    /// The entries extraction would create, each with where it lands.
    ///
    /// Entries are judged in archive order against a model of what earlier
    /// entries created, so a path through an earlier symlink is resolved the
    /// way extraction resolves it. An entry that extraction would not create
    /// is left out: one the validation refuses (traversal, a banned
    /// component, a symlink or hardlink the config disallows, a symlink whose
    /// target escapes), one that cannot be placed (a conflict with an earlier
    /// entry, a landing longer than the host allows) and a regular file the
    /// extension allowlist skips. Every other kind of entry is covered, not
    /// only regular files.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveEntry;
    /// use exarch_core::ArchiveManifest;
    /// use exarch_core::ArchiveType;
    /// use exarch_core::ManifestEntryKind;
    /// use exarch_core::SecurityConfig;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut manifest = ArchiveManifest::new(ArchiveType::Tar);
    /// manifest.add_entry(ArchiveEntry::new(
    ///     "../evil".into(),
    ///     ManifestEntryKind::Directory,
    /// ))?;
    /// let config = SecurityConfig::default();
    /// assert_eq!(manifest.landing_paths(&config).count(), 0);
    /// # Ok(())
    /// # }
    /// ```
    pub fn landing_paths<'a>(
        &'a self,
        config: &SecurityConfig,
    ) -> impl Iterator<Item = (&'a ArchiveEntry, LandingPath)> + use<'a> {
        self.dispositions(config)
            .filter_map(|(entry, disposition)| match disposition {
                Disposition::Extract(landing) => Some((entry, landing)),
                Disposition::Skip(_) => None,
            })
    }

    /// Every entry that validation accepts, with what extraction does with it:
    /// where it lands, or why it is left out.
    ///
    /// The selection is the one the manifest was listed with
    /// ([`selection`](Self::selection)), never one taken from `config`, so the
    /// answer cannot disagree with the listing; `config` supplies the limits
    /// and policies. An entry the validation refuses or that cannot be placed
    /// is not reported, as in [`landing_paths`](Self::landing_paths), which
    /// is the extracted subset of this.
    ///
    /// An entry is skipped as [`SkipKind::NotSelected`] when the selection
    /// leaves it out, as [`SkipKind::StrippedAway`] when stripping removes its
    /// whole path, and as [`SkipKind::ExtensionNotAllowed`] when it is a
    /// regular file the allowlist excludes, under the first reason that
    /// applies.
    pub fn dispositions<'a>(
        &'a self,
        config: &SecurityConfig,
    ) -> impl Iterator<Item = (&'a ArchiveEntry, Disposition)> + use<'a> {
        let root = VirtualRoot::new();
        let mut tree = VirtualTree::new(
            &root,
            PathModel::Host,
            NodeBudget::from_config(config),
            CollisionRecording::Discard,
        );
        let judged: Vec<_> = self
            .entries()
            .iter()
            .filter_map(|entry| {
                land(entry, self.selection(), config, &root, &mut tree)
                    .map(|disposition| (entry, disposition))
            })
            .collect();
        judged.into_iter()
    }

    /// Everything extraction would create, entries and the directories it
    /// creates for them on its own, in the order they land.
    ///
    /// An archive can hold `a/b.txt` without an `a/` entry; extraction then
    /// creates `a`. Each such parent is reported once, as
    /// [`LandingKind::ImplicitParent`], before the first entry that needs it,
    /// outermost first. A front end that probes the destination for conflicts
    /// probes every landing, so a parent that is a file (or a symlink) in the
    /// destination is found at that parent and not below it.
    ///
    /// The parents are those of the resolved landing, so a path through an
    /// earlier symlink reports the directories it really lands in.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveEntry;
    /// use exarch_core::ArchiveManifest;
    /// use exarch_core::ArchiveType;
    /// use exarch_core::LandingKind;
    /// use exarch_core::ManifestEntryKind;
    /// use exarch_core::SecurityConfig;
    /// use exarch_core::Uncompressed;
    /// use std::assert_matches;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut manifest = ArchiveManifest::new(ArchiveType::Tar);
    /// let file = ManifestEntryKind::File {
    ///     size: Uncompressed(1),
    /// };
    /// manifest.add_entry(ArchiveEntry::new("a/b.txt".into(), file))?;
    /// let config = SecurityConfig::default();
    /// let landings: Vec<_> = manifest.landings(&config).collect();
    /// assert_eq!(landings.len(), 2);
    /// assert_matches!(landings[0].kind(), LandingKind::ImplicitParent);
    /// assert_eq!(landings[0].path().as_path(), std::path::Path::new("a"));
    /// assert_matches!(landings[1].kind(), LandingKind::Entry(_));
    /// # Ok(())
    /// # }
    /// ```
    pub fn landings<'a>(
        &'a self,
        config: &SecurityConfig,
    ) -> impl Iterator<Item = Landing<'a>> + use<'a> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for (entry, landing) in self.landing_paths(config) {
            let ancestors: Vec<_> = landing
                .as_path()
                .ancestors()
                .skip(1)
                .filter(|p| !p.is_empty())
                .map(Path::to_path_buf)
                .collect();
            for parent in ancestors.into_iter().rev() {
                if seen.insert(parent.clone()) {
                    out.push(Landing {
                        path: LandingPath(parent),
                        kind: LandingKind::ImplicitParent,
                    });
                }
            }
            seen.insert(landing.as_path().to_path_buf());
            out.push(Landing {
                path: landing,
                kind: LandingKind::Entry(entry),
            });
        }
        out.into_iter()
    }
}

fn land(
    entry: &ArchiveEntry,
    selection: &EntrySelection,
    config: &SecurityConfig,
    root: &VirtualRoot,
    tree: &mut VirtualTree,
) -> Option<Disposition> {
    let original = SafePath::validate_in(&entry.path, root, config, tree).ok()?;
    let ctx = ValidationContext::<VirtualTree>::new(config.allowed.symlinks.is_allowed());
    let safe = match route_validated(selection, None, original, root, config, &ctx, tree).ok()? {
        Gated::Admit(safe) => safe,
        Gated::Skip(kind) => return Some(Disposition::Skip(kind)),
    };
    let is_file = matches!(entry.kind, ManifestEntryKind::File { .. });
    if is_file && !is_extension_allowed(safe.as_path(), config) {
        return Some(Disposition::Skip(SkipKind::ExtensionNotAllowed));
    }
    let node = match &entry.kind {
        ManifestEntryKind::File { .. } => Node::File,
        ManifestEntryKind::Hardlink { target } => {
            if !config.allowed.hardlinks.is_allowed() {
                return None;
            }
            if let LinkTarget::Recorded(target) = target {
                selection.mapped_link_target(&entry.path, target).ok()?;
            }
            Node::File
        }
        ManifestEntryKind::Directory => Node::Dir,
        ManifestEntryKind::Symlink { target } => {
            if !config.allowed.symlinks.is_allowed() {
                return None;
            }
            match target {
                LinkTarget::Recorded(t) => {
                    SafeSymlink::validate_in(&safe, t, root, config, tree).ok()?;
                    Node::Symlink(t.clone())
                }
                LinkTarget::Unread => Node::OpaqueSymlink,
                LinkTarget::Missing | LinkTarget::Unreadable | LinkTarget::Oversized { .. } => {
                    return None;
                }
            }
        }
    };
    let landed = tree
        .project_landing(&safe, node, LandingLimits::Enforced)
        .ok()?;
    Some(Disposition::Extract(LandingPath(landed.into_path_buf())))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeSet;
    use std::io::Cursor;
    use std::io::Write as _;

    use exarch_testkit::raw_zip::RawEntry;
    use exarch_testkit::raw_zip::RawZip;

    use super::*;
    use crate::extract_archive;
    use crate::list_archive;

    fn config() -> SecurityConfig {
        SecurityConfig::default()
            .with_allow_absolute_paths(true)
            .with_allow_symlinks(true)
    }

    fn tar_entry(
        builder: &mut tar::Builder<Vec<u8>>,
        name: &[u8],
        kind: tar::EntryType,
        link: &str,
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(kind);
        header.set_mode(0o644);
        header.set_size(u64::from(kind == tar::EntryType::Regular));
        header.as_old_mut().name[..name.len()].copy_from_slice(name);
        if !link.is_empty() {
            header.set_link_name(link).unwrap();
        }
        header.set_cksum();
        let data: &[u8] = if kind == tar::EntryType::Regular {
            b"x"
        } else {
            b""
        };
        builder.append(&header, data).unwrap();
    }

    fn non_directories(root: &Path) -> BTreeSet<PathBuf> {
        let mut found = BTreeSet::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for item in std::fs::read_dir(&dir).unwrap() {
                let path = item.unwrap().path();
                if std::fs::symlink_metadata(&path).unwrap().is_dir() {
                    stack.push(path);
                } else {
                    found.insert(path.strip_prefix(root).unwrap().to_path_buf());
                }
            }
        }
        found
    }

    fn every_path(root: &Path) -> BTreeSet<PathBuf> {
        let mut found = BTreeSet::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for item in std::fs::read_dir(&dir).unwrap() {
                let path = item.unwrap().path();
                if std::fs::symlink_metadata(&path).unwrap().is_dir() {
                    stack.push(path.clone());
                }
                found.insert(path.strip_prefix(root).unwrap().to_path_buf());
            }
        }
        found
    }

    /// The landing set of the non-directory entries must be the set of
    /// non-directories extraction really created.
    fn assert_landing_matches_extraction(file_name: &str, bytes: &[u8]) {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join(file_name);
        std::fs::write(&archive, bytes).unwrap();
        let dest = dir.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        let config = config();

        let manifest = list_archive(&archive, &config).unwrap();
        let landed: BTreeSet<PathBuf> = manifest
            .landing_paths(&config)
            .filter(|(entry, _)| !matches!(entry.kind, ManifestEntryKind::Directory))
            .map(|(_, landing)| landing.into_path_buf())
            .collect();
        extract_archive(&archive, &dest, &config).unwrap();

        assert_eq!(landed, non_directories(&dest), "{file_name}");
        let every: BTreeSet<PathBuf> = manifest
            .landings(&config)
            .map(|landing| landing.path().as_path().to_path_buf())
            .collect();
        assert_eq!(every, every_path(&dest), "{file_name}: implicit parents");
        let implicit = manifest
            .landings(&config)
            .filter(|l| matches!(l.kind(), LandingKind::ImplicitParent))
            .count();
        assert!(implicit > 0, "{file_name}: the fixture implies a parent");
        assert!(!landed.is_empty(), "{file_name}");
    }

    #[test]
    fn tar_landing_matches_extraction_for_dot_slash_absolute_and_linked_parents() {
        let mut builder = tar::Builder::new(Vec::new());
        tar_entry(&mut builder, b"./a.txt", tar::EntryType::Regular, "");
        tar_entry(&mut builder, b"/abs.txt", tar::EntryType::Regular, "");
        tar_entry(&mut builder, b"d/", tar::EntryType::Directory, "");
        tar_entry(&mut builder, b"d/sub.txt", tar::EntryType::Regular, "");
        // Windows extraction refuses symlinks, so the linked parent is
        // Unix-only.
        #[cfg(unix)]
        {
            tar_entry(&mut builder, b"link", tar::EntryType::Symlink, "d");
            tar_entry(
                &mut builder,
                b"link/through.txt",
                tar::EntryType::Regular,
                "",
            );
        }
        tar_entry(&mut builder, b"x/y/z.txt", tar::EntryType::Regular, "");
        assert_landing_matches_extraction("a.tar", &builder.into_inner().unwrap());
    }

    #[test]
    fn a_path_through_a_symlink_lands_at_the_resolved_path() {
        let mut builder = tar::Builder::new(Vec::new());
        tar_entry(&mut builder, b"d/", tar::EntryType::Directory, "");
        tar_entry(&mut builder, b"link", tar::EntryType::Symlink, "d");
        tar_entry(&mut builder, b"link/x.txt", tar::EntryType::Regular, "");
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();
        let config = config();

        let manifest = list_archive(&archive, &config).unwrap();
        let landed: Vec<_> = manifest
            .landing_paths(&config)
            .map(|(_, l)| l.into_path_buf())
            .collect();
        assert_eq!(
            landed,
            [
                PathBuf::from("d"),
                PathBuf::from("link"),
                PathBuf::from("d/x.txt")
            ]
        );
    }

    #[test]
    fn zip_landing_matches_extraction_for_backslashes_and_drive_prefixes() {
        let entries = [
            "a\\b.txt",
            "C:\\win.txt",
            "/abs.txt",
            "plain.txt",
            "dir/",
            "p/q/r.txt",
        ]
        .iter()
        .map(|name| RawEntry::stored(name, if name.ends_with('/') { b"" } else { b"x" }))
        .collect();
        let bytes = RawZip::new(entries).build().bytes;
        assert_landing_matches_extraction("a.zip", &bytes);
    }

    #[test]
    fn sevenz_landing_matches_extraction() {
        let mut writer = sevenz_rust2::ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
        for name in ["a.txt", "dir/b.txt", "dir/deeper/c.txt"] {
            writer
                .push_archive_entry(
                    sevenz_rust2::ArchiveEntry::new_file(name),
                    Some(Cursor::new(b"x".to_vec())),
                )
                .unwrap();
        }
        let bytes = writer.finish().unwrap().into_inner();
        assert_landing_matches_extraction("a.7z", &bytes);
    }

    #[test]
    fn refused_and_skipped_entries_do_not_land() {
        let mut builder = tar::Builder::new(Vec::new());
        tar_entry(&mut builder, b"ok.txt", tar::EntryType::Regular, "");
        tar_entry(&mut builder, b"skip.bin", tar::EntryType::Regular, "");
        tar_entry(
            &mut builder,
            b"esc",
            tar::EntryType::Symlink,
            "../../outside",
        );
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();
        let config = config().try_add_allowed_extension("txt").unwrap();

        let manifest = list_archive(&archive, &config).unwrap();
        let landed: Vec<_> = manifest
            .landing_paths(&config)
            .map(|(_, l)| l.into_path_buf())
            .collect();
        assert_eq!(landed, [PathBuf::from("ok.txt")]);
    }

    #[test]
    fn disallowed_links_do_not_land() {
        let mut builder = tar::Builder::new(Vec::new());
        tar_entry(&mut builder, b"s", tar::EntryType::Symlink, "ok.txt");
        tar_entry(&mut builder, b"h", tar::EntryType::Link, "ok.txt");
        let _ = builder.get_mut().flush();
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();
        let config = config();

        let manifest = list_archive(&archive, &config).unwrap();
        let strict = SecurityConfig::default();
        assert_eq!(manifest.landing_paths(&strict).count(), 0);
    }

    #[test]
    fn implicit_parents_are_reported_once_outermost_first() {
        let mut builder = tar::Builder::new(Vec::new());
        tar_entry(&mut builder, b"first.txt", tar::EntryType::Regular, "");
        tar_entry(&mut builder, b"a/b/c.txt", tar::EntryType::Regular, "");
        tar_entry(&mut builder, b"a/d.txt", tar::EntryType::Regular, "");
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();
        let config = config();

        let manifest = list_archive(&archive, &config).unwrap();
        let shape: Vec<_> = manifest
            .landings(&config)
            .map(|l| {
                (
                    l.path().as_path().to_path_buf(),
                    matches!(l.kind(), LandingKind::ImplicitParent),
                )
            })
            .collect();
        assert_eq!(
            shape,
            [
                (PathBuf::from("first.txt"), false),
                (PathBuf::from("a"), true),
                (PathBuf::from("a/b"), true),
                (PathBuf::from("a/b/c.txt"), false),
                (PathBuf::from("a/d.txt"), false),
            ]
        );
    }
}
