//! Optimization context for path validation during extraction.

#[cfg(any(unix, target_os = "wasi"))]
use crate::formats::pinned_dir::WalkerBacked;
use crate::security::fs_view::FsView;
use crate::security::fs_view::HostFs;
use std::marker::PhantomData;

/// Where the containment of an entry's parent directory is established.
#[derive(Debug, Clone, Copy)]
enum ParentProbe {
    /// The validator resolves the parent itself.
    Here,
    /// The directory walker vets the parent right before the write.
    #[cfg(any(unix, target_os = "wasi"))]
    AtWrite,
}

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
    parent_probe: ParentProbe,
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
            parent_probe: ParentProbe::Here,
            view: PhantomData,
        }
    }

    /// Defers the parent-directory probe to the directory walker that the
    /// proof came from.
    #[cfg(any(unix, target_os = "wasi"))]
    #[must_use]
    pub(crate) fn with_walker(mut self, _proof: WalkerBacked) -> Self {
        self.parent_probe = ParentProbe::AtWrite;
        self
    }

    /// Returns true if the walker vets the parent at write time, so the
    /// validator need not resolve it.
    #[inline]
    pub(crate) fn defers_parent_probe(&self) -> bool {
        match self.parent_probe {
            ParentProbe::Here => false,
            #[cfg(any(unix, target_os = "wasi"))]
            ParentProbe::AtWrite => true,
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

    #[cfg(unix)]
    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_walker_proof_defers_the_parent_probe() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = crate::formats::pinned_dir::PinnedRoot::open_for_test(temp.path()).unwrap();
        let ctx = ValidationContext::<HostFs>::new(false);
        assert!(!ctx.defers_parent_probe());
        assert!(
            ctx.with_walker(root.backs_parent_probe())
                .defers_parent_probe()
        );
    }

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
