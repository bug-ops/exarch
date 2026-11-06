//! How the parent directory of a validated path was vetted.
//!
//! The items are public so the public path types can be generic over them,
//! but this module is private and only `Walked` is re-exported, and only with
//! the `testing` feature.

mod sealed {
    pub trait Sealed: std::fmt::Debug + Clone + PartialEq + Eq + std::hash::Hash {}
}

/// How the parent directory of a validated `SafePath` was vetted.
///
/// Sealed and not nameable outside this crate, except `Walked` with the
/// `testing` feature. The typed path-based APIs (`DestDir::join`, and the
/// crate-internal read-only probe) refuse a path whose parent is vetted at
/// write time at compile time, so such a path reaches the filesystem only
/// through a directory-handle writer. `SafePath::as_path` stays a raw read-only
/// escape, and path-based mutators inside `exarch-core` are linted with
/// `clippy::disallowed_methods`.
pub trait ParentCheck: sealed::Sealed {
    /// What validation needs to skip the parent probe.
    #[doc(hidden)]
    type Proof<'r>;

    /// Who vets the parent directory.
    #[doc(hidden)]
    const VETTING: ParentVetting;
}

/// Who vets the parent directory of a validated path.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentVetting {
    /// Validation canonicalizes the parent itself.
    Validator,
    /// A directory walker on a pinned root vets the parent at write time.
    Walker,
}

/// The parent directory was resolved during validation, so the path is safe
/// to join to the destination and use by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Resolved;

impl sealed::Sealed for Resolved {}

impl ParentCheck for Resolved {
    type Proof<'r> = ();

    const VETTING: ParentVetting = ParentVetting::Validator;
}

/// The parent directory is vetted at write time by a directory walker on a
/// pinned root, so the path must be written through that walker.
#[cfg(any(unix, target_os = "wasi"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(not(feature = "testing"), allow(unreachable_pub))]
pub struct Walked;

#[cfg(any(unix, target_os = "wasi"))]
impl sealed::Sealed for Walked {}

#[cfg(any(unix, target_os = "wasi"))]
impl ParentCheck for Walked {
    type Proof<'r> = crate::formats::pinned_dir::WalkerBacked<'r>;

    const VETTING: ParentVetting = ParentVetting::Walker;
}
