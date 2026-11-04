//! The proofs a [`ValidatorCore`](super::validator::ValidatorCore) hands to an
//! extraction target, one per entry kind.
//!
//! A [`ValidatedFile`] is only built by [`PendingFile::admit`], which is only
//! built by the validator from a validated path, so no target can assemble a
//! proof by hand. The other proofs keep public fields; the module's visibility
//! is their only seal.

use crate::Result;
use crate::SecurityConfig;
use crate::security::hardlink::HardlinkTarget;
use crate::security::permissions::RawMode;
use crate::security::permissions::SanitizedMode;
use crate::security::permissions::sanitize_permissions;
use crate::security::quota::EntryCount;
use crate::security::quota::QuotaPermit;
use crate::security::quota::QuotaTracker;
use crate::security::zipbomb::Compressed;
use crate::security::zipbomb::Uncompressed;
use crate::security::zipbomb::validate_compression_ratio;
use crate::types::SafePath;
use crate::types::SafeSymlink;
use crate::types::safe_path::ParentCheck;
use crate::types::safe_path::Resolved;

/// The declared sizes of one entry, as the validators consume them.
#[derive(Debug, Clone, Copy)]
pub struct EntrySize {
    uncompressed: Uncompressed,
    compressed: Option<Compressed>,
}

impl EntrySize {
    /// Pairs the declared sizes of one entry.
    #[must_use]
    pub const fn new(uncompressed: Uncompressed, compressed: Option<Compressed>) -> Self {
        Self {
            uncompressed,
            compressed,
        }
    }

    /// The declared uncompressed size.
    #[must_use]
    pub const fn uncompressed(&self) -> Uncompressed {
        self.uncompressed
    }

    /// The declared compressed size, when the format records one.
    #[must_use]
    pub const fn compressed(&self) -> Option<Compressed> {
        self.compressed
    }

    /// Checks the declared sizes against the configured compression-ratio
    /// limit; a no-op when the format records no compressed size.
    pub(crate) fn check_ratio(self, config: &SecurityConfig) -> Result<()> {
        if let Some(compressed) = self.compressed {
            validate_compression_ratio(compressed, self.uncompressed, config)?;
        }
        Ok(())
    }
}

/// A regular file whose path passed validation and the extension allowlist,
/// and whose quota is not yet reserved.
#[derive(Debug)]
pub struct PendingFile<P: ParentCheck = Resolved> {
    path: SafePath<P>,
    size: EntrySize,
    mode: Option<RawMode>,
}

impl<P: ParentCheck> PendingFile<P> {
    pub(super) const fn new(path: SafePath<P>, size: EntrySize, mode: Option<RawMode>) -> Self {
        Self { path, size, mode }
    }

    /// The validated destination-relative path.
    pub(crate) const fn path(&self) -> &SafePath<P> {
        &self.path
    }

    /// Reserves the file's size against `quota`, checks the ratio and
    /// sanitizes the mode.
    ///
    /// # Errors
    ///
    /// Returns the quota or ratio refusal.
    pub(super) fn admit(
        self,
        quota: &mut QuotaTracker,
        config: &SecurityConfig,
    ) -> Result<ValidatedFile<P>> {
        let permit = quota.reserve(self.size.uncompressed.0, config)?;
        self.size.check_ratio(config)?;
        Ok(ValidatedFile {
            path: self.path,
            permit,
            mode: self.mode.map(|m| sanitize_permissions(m, config)),
        })
    }
}

/// A regular file that passed path, quota and ratio validation.
#[derive(Debug)]
pub struct ValidatedFile<P: ParentCheck = Resolved> {
    path: SafePath<P>,
    permit: QuotaPermit,
    mode: Option<SanitizedMode>,
}

impl<P: ParentCheck> ValidatedFile<P> {
    /// Splits the proof into its path, the quota permit for the file's size
    /// and the sanitized permissions, when the format records them.
    pub(crate) fn into_parts(self) -> (SafePath<P>, QuotaPermit, Option<SanitizedMode>) {
        (self.path, self.permit, self.mode)
    }
}

/// A symlink entry that passed validation; the symlink carries its own
/// validated location.
#[derive(Debug)]
pub struct ValidatedSymlink<P: ParentCheck = Resolved> {
    /// The validated link and target.
    pub symlink: SafeSymlink<P>,
}

/// A hardlink entry that passed first-pass validation.
#[derive(Debug)]
pub struct ValidatedHardlink<P: ParentCheck = Resolved> {
    /// Validated location of the link.
    pub link: SafePath<P>,
    /// Validated target of the link.
    pub target: HardlinkTarget,
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
        EntrySize::new(Uncompressed(uncompressed), None)
    }

    #[test]
    fn a_file_carries_its_path_and_sanitized_mode() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let config = SecurityConfig::default();
        let mut core = ValidatorCore::new(&config);
        let ctx = core.context::<HostFs>();

        let file = core
            .validate_file_in(
                Path::new("a.txt"),
                sizes(3),
                Some(RawMode::new(0o4755)),
                &dest,
                &HostFs,
                &ctx,
            )
            .unwrap();

        let (path, _permit, mode) = file.into_parts();
        assert_eq!(path.as_path(), Path::new("a.txt"));
        assert_eq!(mode.unwrap().as_u32() & 0o6000, 0, "setuid is stripped");
    }

    #[test]
    fn a_refused_file_yields_no_proof() {
        let temp = TempDir::new().unwrap();
        let dest = DestDir::new(temp.path().to_path_buf()).unwrap();
        let config = SecurityConfig::default();
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
            .with_allow_hardlinks(true);
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
        assert_eq!(symlink.symlink.link().as_path(), Path::new("s"));
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
