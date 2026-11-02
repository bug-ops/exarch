//! Optimization context for path validation during extraction.

use crate::security::fs_view::FsView;
use crate::security::fs_view::HostFs;
use std::marker::PhantomData;

/// Carries state that enables skipping the full-path `canonicalize()` syscall
/// when safety can be proven through other means.
///
/// During extraction, `canonicalize()` is only needed to detect symlinks in
/// path chains. When the archive contains no symlinks AND config disallows
/// them, no symlinks can exist in the extraction tree created by this run.
///
/// `V` is the view the context is used against.
pub struct ValidationContext<V: FsView = HostFs> {
    symlink_seen: bool,
    symlinks_allowed: bool,
    view: PhantomData<fn() -> V>,
}

impl<V: FsView> ValidationContext<V> {
    /// Creates a context with no symlink seen yet.
    ///
    /// `symlinks_allowed` is the config's symlink policy.
    #[must_use]
    pub fn new(symlinks_allowed: bool) -> Self {
        Self {
            symlink_seen: false,
            symlinks_allowed,
            view: PhantomData,
        }
    }

    /// Records that the archive contains a symlink, which re-enables the full
    /// `canonicalize()` even when the config disallows them.
    pub fn mark_symlink_seen(&mut self) {
        self.symlink_seen = true;
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
mod tests {
    use super::*;

    #[test]
    fn test_default_context_no_optimizations() {
        let ctx = ValidationContext::<HostFs>::new(false);
        assert!(!ctx.needs_full_canonicalize());
    }

    #[test]
    fn test_context_with_symlinks_allowed() {
        let ctx = ValidationContext::<HostFs>::new(true);
        assert!(ctx.needs_full_canonicalize());
    }

    #[test]
    fn test_context_symlink_seen_enables_canonicalize() {
        let mut ctx = ValidationContext::<HostFs>::new(false);
        assert!(!ctx.needs_full_canonicalize());
        ctx.mark_symlink_seen();
        assert!(ctx.needs_full_canonicalize());
    }
}
