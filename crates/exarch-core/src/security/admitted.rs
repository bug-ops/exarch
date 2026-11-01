//! The proofs a [`ValidatorCore`](super::validator::ValidatorCore) hands to an
//! extraction target, one per entry kind.
//!
//! The types are only constructed by the validator and consumed inside the
//! crate; the fields are public so the module's visibility is the only seal.

use crate::security::permissions::SanitizedMode;
use crate::security::quota::EntryCount;
use crate::security::quota::QuotaPermit;
use crate::types::SafePath;
use crate::types::SafeSymlink;

/// The declared sizes of one entry, as the validators consume them.
#[derive(Debug, Clone, Copy)]
pub struct EntrySize {
    /// Declared uncompressed size in bytes.
    pub uncompressed: u64,
    /// Declared compressed size, when the format records one.
    pub compressed: Option<u64>,
}

/// A regular file that passed path, quota and ratio validation.
#[derive(Debug)]
pub struct ValidatedFile {
    /// Validated destination-relative path.
    pub path: SafePath,
    /// Proof the file's size was reserved against the quota.
    pub permit: QuotaPermit,
    /// Sanitized permissions, when the format records them.
    pub mode: Option<SanitizedMode>,
}

/// A symlink entry that passed validation, with its own location.
#[derive(Debug)]
pub struct ValidatedSymlink {
    /// Validated location of the link.
    pub link: SafePath,
    /// The validated link and target.
    pub symlink: SafeSymlink,
}

/// A hardlink entry that passed first-pass validation.
#[derive(Debug)]
pub struct ValidatedHardlink {
    /// Validated location of the link.
    pub link: SafePath,
    /// Validated target of the link.
    pub target: SafePath,
    /// Proof the hardlink was counted against `max_file_count`.
    pub counted: EntryCount,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::assert_matches;
    use std::path::Path;

    use tempfile::TempDir;

    use super::*;
    use crate::ArchiveError;
    use crate::SecurityConfig;
    use crate::security::fs_view::HostFs;
    use crate::security::validator::ValidatorCore;
    use crate::types::DestDir;

    fn sizes(uncompressed: u64) -> EntrySize {
        EntrySize {
            uncompressed,
            compressed: None,
        }
    }

    #[test]
    fn a_file_carries_its_path_and_sanitized_mode() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let config = SecurityConfig::default().validate().unwrap();
        let mut core = ValidatorCore::new(&config);
        let ctx = core.context::<HostFs>();

        let file = core
            .validate_file_in(
                Path::new("a.txt"),
                sizes(3),
                Some(0o4755),
                &dest,
                &HostFs,
                &ctx,
            )
            .unwrap();

        assert_eq!(file.path.as_path(), Path::new("a.txt"));
        assert_eq!(
            file.mode.unwrap().as_u32() & 0o6000,
            0,
            "setuid is stripped"
        );
    }

    #[test]
    fn a_refused_file_yields_no_proof() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let config = SecurityConfig::default().validate().unwrap();
        let mut core = ValidatorCore::new(&config);
        let ctx = core.context::<HostFs>();

        assert_matches!(
            core.validate_file_in(Path::new("../x"), sizes(1), None, &dest, &HostFs, &ctx),
            Err(ArchiveError::PathTraversal { .. })
        );
    }

    #[test]
    fn a_directory_symlink_and_hardlink_carry_their_validated_parts() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let config = SecurityConfig::default()
            .with_allow_symlinks(true)
            .with_allow_hardlinks(true)
            .validate()
            .unwrap();
        let mut core = ValidatorCore::new(&config);

        let ctx = core.context::<HostFs>();
        let directory = core
            .validate_directory_in(Path::new("d"), sizes(0), &dest, &HostFs, &ctx)
            .unwrap();
        assert_eq!(directory.as_path(), Path::new("d"));

        let ctx = core.context::<HostFs>();
        let symlink = core
            .validate_symlink_in(
                Path::new("s"),
                Path::new("d"),
                sizes(1),
                &dest,
                &HostFs,
                &ctx,
            )
            .unwrap();
        assert_eq!(symlink.link.as_path(), Path::new("s"));
        assert_eq!(symlink.symlink.target_path(), Path::new("d"));

        let ctx = core.context::<HostFs>();
        let hardlink = core
            .validate_hardlink_in(
                Path::new("h"),
                Path::new("t"),
                sizes(0),
                &dest,
                &HostFs,
                &ctx,
            )
            .unwrap();
        assert_eq!(hardlink.link.as_path(), Path::new("h"));
        assert_eq!(hardlink.target.as_path(), Path::new("t"));
    }
}
