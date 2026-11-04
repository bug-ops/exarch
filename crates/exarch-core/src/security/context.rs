//! Optimization context for path validation during extraction.

#[cfg(any(unix, target_os = "wasi"))]
use crate::formats::pinned_dir::WalkerBacked;
use crate::security::fs_view::FsView;
use crate::security::fs_view::HostFs;
use crate::types::safe_path::ParentCheck;
use crate::types::safe_path::Resolved;
#[cfg(any(unix, target_os = "wasi"))]
use crate::types::safe_path::Walked;
use std::marker::PhantomData;

/// Carries state that enables skipping the full-path `canonicalize()` syscall
/// when safety can be proven through other means.
///
/// During extraction, `canonicalize()` is only needed to detect symlinks in
/// path chains. When the archive contains no symlinks AND config disallows
/// them, no symlinks can exist in the extraction tree created by this run.
///
/// `V` is the view the context is used against. `P` is how validated paths
/// have their parent directory vetted: [`Resolved`] by the validator itself,
/// or by a directory walker whose proof the context holds for `'r`.
pub struct ValidationContext<'r, V: FsView = HostFs, P: ParentCheck = Resolved> {
    symlink_seen: bool,
    symlinks_allowed: bool,
    _proof: P::Proof<'r>,
    view: PhantomData<fn() -> V>,
}

impl<V: FsView> ValidationContext<'_, V, Resolved> {
    /// Creates a context with no symlink seen yet.
    ///
    /// `symlinks_allowed` is the config's symlink policy.
    #[must_use]
    pub fn new(symlinks_allowed: bool) -> Self {
        Self {
            symlink_seen: false,
            symlinks_allowed,
            _proof: (),
            view: PhantomData,
        }
    }

    /// Defers the parent-directory probe to the directory walker that the
    /// proof came from; paths validated with the result are `Walked`.
    #[cfg(any(unix, target_os = "wasi"))]
    #[must_use]
    pub(crate) fn with_walker(self, proof: WalkerBacked<'_>) -> ValidationContext<'_, V, Walked> {
        ValidationContext {
            symlink_seen: self.symlink_seen,
            symlinks_allowed: self.symlinks_allowed,
            _proof: proof,
            view: PhantomData,
        }
    }
}

impl<V: FsView, P: ParentCheck> ValidationContext<'_, V, P> {
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
    use crate::types::safe_path::ParentVetting;

    #[cfg(unix)]
    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_walker_proof_keeps_the_symlink_state() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = crate::formats::pinned_dir::PinnedRoot::open_for_test(temp.path()).unwrap();
        let mut ctx = ValidationContext::<HostFs>::new(false);
        ctx.mark_symlink_seen();
        let walked = ctx.with_walker(root.backs_parent_probe());
        assert!(walked.needs_full_canonicalize());
    }

    #[test]
    fn test_parent_probe_is_a_property_of_the_state() {
        const {
            assert!(matches!(Resolved::VETTING, ParentVetting::Validator));
        }
        #[cfg(unix)]
        const {
            assert!(matches!(Walked::VETTING, ParentVetting::Walker));
        }
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
