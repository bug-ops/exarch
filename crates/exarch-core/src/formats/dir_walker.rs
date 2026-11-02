//! Parent-directory creation that never walks through a link it did not vet.
//!
//! Every component below the destination is inspected with `lstat` on every
//! call and created with a plain `mkdir`, so a symlink planted in the
//! destination is refused instead of followed, and nothing is remembered
//! between entries that a later swap could invalidate.
//!
//! # Residual TOCTOU
//!
//! The check is path-based: a local attacker who can write inside the
//! destination while an entry is being written can still swap a vetted
//! component for a symlink between the check and the `open`/`symlink` that
//! follows it (`O_NOFOLLOW` covers only the last component). Closing that
//! window needs `openat`-relative writes from a pinned directory descriptor.

use std::fs;
use std::io;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use crate::ArchiveError;
use crate::PolicySetting;
use crate::Result;
use crate::SecurityConfig;
use crate::config::Validated;
use crate::security::fs_view::ParentBlocker;
use crate::types::DestDir;

/// What an existing symlink among the parent components may be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkPolicy {
    /// Any symlink component is refused.
    Refuse,
    /// A symlink component is accepted only if it resolves to a directory
    /// inside the destination.
    ContainedOnly,
}

impl LinkPolicy {
    fn of(config: &SecurityConfig<Validated>) -> Self {
        if config.allowed.symlinks {
            Self::ContainedOnly
        } else {
            Self::Refuse
        }
    }
}

/// Creates and vets the directories that archive entries are written into.
#[derive(Debug, Clone, Copy)]
pub struct DirWalker {
    links: LinkPolicy,
}

impl DirWalker {
    /// Builds a walker that applies the symlink policy of `config`.
    pub fn new(config: &SecurityConfig<Validated>) -> Self {
        Self {
            links: LinkPolicy::of(config),
        }
    }

    /// Creates `dest/rel` and every missing ancestor, vetting each component.
    ///
    /// # Errors
    ///
    /// Returns `SecurityViolation` for a symlink component the policy refuses
    /// or one that dangles or does not resolve to a directory, `SymlinkEscape`
    /// for one that leaves `dest`, `PathTraversal` for a non-relative `rel`,
    /// and an I/O error when a component is a file or cannot be created. A
    /// blocking component is reported against `rel` with the same text and
    /// category as `verify`.
    pub fn ensure_dir(self, dest: &DestDir, rel: &Path) -> Result<()> {
        self.walk(dest, rel, rel)
    }

    /// Creates the parent directory of `dest/rel` like [`Self::ensure_dir`].
    ///
    /// # Errors
    ///
    /// Same as [`Self::ensure_dir`].
    pub fn ensure_parent(self, dest: &DestDir, rel: &Path) -> Result<()> {
        rel.parent()
            .map_or(Ok(()), |parent| self.walk(dest, parent, rel))
    }

    fn walk(self, dest: &DestDir, dir: &Path, entry: &Path) -> Result<()> {
        let mut current = dest.as_path().to_path_buf();
        for component in dir.components() {
            match component {
                Component::Normal(name) => current.push(name),
                Component::CurDir => continue,
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(ArchiveError::PathTraversal {
                        path: dir.to_path_buf(),
                    });
                }
            }
            self.vet_or_create(dest, &current, entry)?;
        }
        Ok(())
    }

    fn vet_or_create(self, dest: &DestDir, dir: &Path, entry: &Path) -> Result<()> {
        match fs::symlink_metadata(dir) {
            Ok(meta) => self.vet(dest, dir, entry, meta.file_type()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => match fs::create_dir(dir) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    self.vet(dest, dir, entry, fs::symlink_metadata(dir)?.file_type())
                }
                Err(e) => Err(e.into()),
            },
            Err(e) => Err(e.into()),
        }
    }

    fn vet(self, dest: &DestDir, dir: &Path, entry: &Path, file_type: fs::FileType) -> Result<()> {
        let parent = relative_to(dest, dir);
        if file_type.is_dir() {
            return Ok(());
        }
        if !file_type.is_symlink() {
            return Err(ParentBlocker::File.error(entry, &parent));
        }
        match self.links {
            LinkPolicy::Refuse => Err(ArchiveError::relaxable_violation(
                PolicySetting::Symlinks,
                format!("path component is a symlink: {}", parent.display()),
            )),
            LinkPolicy::ContainedOnly => match fs::canonicalize(dir) {
                Ok(resolved) if !resolved.starts_with(dest.as_path()) => {
                    Err(ParentBlocker::Escape.error(entry, &parent))
                }
                Ok(resolved) if resolved.is_dir() => Ok(()),
                Ok(_) | Err(_) => Err(ParentBlocker::Symlink.error(entry, &parent)),
            },
        }
    }
}

fn relative_to(dest: &DestDir, path: &Path) -> PathBuf {
    path.strip_prefix(dest.as_path())
        .unwrap_or(path)
        .to_path_buf()
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::assert_matches;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    fn walker(allow_symlinks: bool) -> DirWalker {
        let config = SecurityConfig::default()
            .with_allow_symlinks(allow_symlinks)
            .validate()
            .unwrap();
        DirWalker::new(&config)
    }

    fn dest_with_outside() -> (TempDir, DestDir, PathBuf) {
        let root = TempDir::new().unwrap();
        let dest = root.path().join("dest");
        let outside = root.path().join("outside");
        fs::create_dir(&dest).unwrap();
        fs::create_dir(&outside).unwrap();
        (
            root,
            DestDir::new(dest).unwrap(),
            outside.canonicalize().unwrap(),
        )
    }

    #[test]
    fn creates_missing_components_and_is_idempotent() {
        let (_root, dest, _) = dest_with_outside();
        let walker = walker(false);

        walker.ensure_dir(&dest, Path::new("a/b/c")).unwrap();
        walker.ensure_dir(&dest, Path::new("a/b/c")).unwrap();
        walker
            .ensure_parent(&dest, Path::new("a/b/c/f.txt"))
            .unwrap();

        assert!(dest.as_path().join("a/b/c").is_dir());
    }

    #[test]
    fn parent_of_a_top_level_name_is_the_destination() {
        let (_root, dest, _) = dest_with_outside();
        walker(false)
            .ensure_parent(&dest, Path::new("f.txt"))
            .unwrap();
    }

    #[test]
    fn refuses_a_symlink_component_without_creating_below_it() {
        let (_root, dest, outside) = dest_with_outside();
        symlink(&outside, dest.as_path().join("redirect")).unwrap();

        let err = walker(false)
            .ensure_dir(&dest, Path::new("redirect/sub"))
            .unwrap_err();

        assert_matches!(err, ArchiveError::SecurityViolation { .. }, "{err}");
        assert!(!outside.join("sub").exists());
    }

    #[test]
    fn refuses_a_symlink_to_a_file_component() {
        let (_root, dest, outside) = dest_with_outside();
        fs::write(outside.join("f"), b"x").unwrap();
        symlink(outside.join("f"), dest.as_path().join("link")).unwrap();

        assert!(
            walker(false)
                .ensure_dir(&dest, Path::new("link/x"))
                .is_err()
        );
    }

    #[test]
    fn contained_policy_refuses_an_escaping_symlink() {
        let (_root, dest, outside) = dest_with_outside();
        symlink(&outside, dest.as_path().join("redirect")).unwrap();

        let err = walker(true)
            .ensure_dir(&dest, Path::new("redirect/sub"))
            .unwrap_err();

        assert_matches!(err, ArchiveError::SymlinkEscape { .. }, "{err}");
        assert!(!outside.join("sub").exists());
    }

    #[test]
    fn contained_policy_accepts_a_link_to_a_directory_inside_dest() {
        let (_root, dest, _) = dest_with_outside();
        fs::create_dir(dest.as_path().join("real")).unwrap();
        symlink("real", dest.as_path().join("alias")).unwrap();

        walker(true)
            .ensure_dir(&dest, Path::new("alias/sub"))
            .unwrap();

        assert!(dest.as_path().join("real/sub").is_dir());
    }

    #[test]
    fn contained_policy_refuses_a_dangling_symlink() {
        let (_root, dest, _) = dest_with_outside();
        symlink("missing", dest.as_path().join("dangling")).unwrap();

        assert!(
            walker(true)
                .ensure_dir(&dest, Path::new("dangling/x"))
                .is_err()
        );
    }

    #[test]
    fn refuses_a_regular_file_component() {
        let (_root, dest, _) = dest_with_outside();
        fs::write(dest.as_path().join("f"), b"x").unwrap();

        let err = walker(false)
            .ensure_dir(&dest, Path::new("f/x"))
            .unwrap_err();

        assert_matches!(err, ArchiveError::Io(_), "{err}");
    }

    #[test]
    fn refuses_non_relative_paths() {
        let (_root, dest, _) = dest_with_outside();
        for bad in ["../x", "/abs", "a/../../x"] {
            let err = walker(false).ensure_dir(&dest, Path::new(bad)).unwrap_err();
            assert_matches!(err, ArchiveError::PathTraversal { .. }, "{bad}: {err}");
        }
    }

    #[test]
    fn a_swap_after_a_successful_walk_is_caught_by_the_next_one() {
        let (_root, dest, outside) = dest_with_outside();
        let walker = walker(false);
        walker.ensure_dir(&dest, Path::new("d")).unwrap();

        fs::remove_dir(dest.as_path().join("d")).unwrap();
        symlink(&outside, dest.as_path().join("d")).unwrap();

        assert!(walker.ensure_parent(&dest, Path::new("d/f")).is_err());
    }
}
