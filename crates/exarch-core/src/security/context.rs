//! Optimization context for path validation during extraction.

use crate::formats::common::DirCache;
use std::path::Path;

/// Carries optimization state that enables skipping expensive `canonicalize()`
/// syscalls when safety can be proven through other means.
///
/// During extraction, `canonicalize()` is only needed to detect symlinks in
/// path chains. When we KNOW a directory was created by us (tracked in
/// `DirCache`), it cannot be a symlink. When the archive contains no symlinks
/// AND config disallows them, no symlinks can exist in the extraction tree.
pub struct ValidationContext<'a> {
    dir_cache: Option<&'a DirCache>,
    symlink_seen: bool,
    symlinks_allowed: bool,
}

impl<'a> ValidationContext<'a> {
    #[must_use]
    pub fn new(symlinks_allowed: bool) -> Self {
        Self {
            dir_cache: None,
            symlink_seen: false,
            symlinks_allowed,
        }
    }

    #[must_use]
    pub fn with_dir_cache(mut self, cache: &'a DirCache) -> Self {
        self.dir_cache = Some(cache);
        self
    }

    pub fn mark_symlink_seen(&mut self) {
        self.symlink_seen = true;
    }

    /// Returns true if the parent directory was created by us and can be
    /// trusted without `canonicalize()`.
    #[inline]
    pub fn is_trusted_parent(&self, parent: &Path) -> bool {
        self.dir_cache
            .is_some_and(|cache: &DirCache| cache.contains(parent))
    }

    /// Returns true if `canonicalize()` is needed for the full resolved path.
    ///
    /// Can be skipped when symlinks are impossible: config disallows them AND
    /// no symlink entries have been seen in the archive so far.
    #[inline]
    pub fn needs_full_canonicalize(&self) -> bool {
        self.symlinks_allowed || self.symlink_seen
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_context_no_optimizations() {
        let ctx = ValidationContext::new(false);
        assert!(!ctx.is_trusted_parent(Path::new("/some/path")));
        assert!(!ctx.needs_full_canonicalize());
    }

    #[test]
    fn test_context_with_symlinks_allowed() {
        let ctx = ValidationContext::new(true);
        assert!(ctx.needs_full_canonicalize());
    }

    #[test]
    fn test_context_symlink_seen_enables_canonicalize() {
        let mut ctx = ValidationContext::new(false);
        assert!(!ctx.needs_full_canonicalize());
        ctx.mark_symlink_seen();
        assert!(ctx.needs_full_canonicalize());
    }

    #[test]
    fn test_context_trusted_parent_with_dir_cache() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let mut dir_cache = DirCache::new();

        let dir_path = temp.path().join("created_dir");
        dir_cache.ensure_dir(&dir_path).expect("should create dir");

        let ctx = ValidationContext::new(false).with_dir_cache(&dir_cache);
        assert!(ctx.is_trusted_parent(&dir_path));
        assert!(!ctx.is_trusted_parent(&temp.path().join("unknown_dir")));
    }

    #[test]
    fn test_context_no_dir_cache_never_trusted() {
        let ctx = ValidationContext::new(false);
        assert!(!ctx.is_trusted_parent(Path::new("/any/path")));
    }
}
