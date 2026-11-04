//! Archive entry type enumeration.

use std::path::PathBuf;

/// Type of entry in an archive, as a format handler classifies it before any
/// validation.
///
/// Crate-private: extraction validates each entry through
/// `ValidatorCore`, which hands the target a proof token per kind, so there is
/// no public second pipeline that consumes this type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EntryType {
    /// Regular file entry.
    File,

    /// Directory entry.
    Directory,

    /// Symbolic link entry.
    ///
    /// The `target` field contains the path the symlink points to.
    /// This target has NOT been validated and must be checked before use.
    Symlink {
        /// The symlink target path (not yet validated).
        target: PathBuf,
    },

    /// Hard link entry.
    ///
    /// The `target` field contains the path the hardlink points to.
    /// This target has NOT been validated and must be checked before use.
    Hardlink {
        /// The hardlink target path (not yet validated).
        target: PathBuf,
    },
}
