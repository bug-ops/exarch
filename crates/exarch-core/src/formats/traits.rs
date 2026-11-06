//! Common traits for archive format handlers.

use std::path::Path;

use crate::ExtractionOptions;
use crate::ExtractionReport;
use crate::ProgressCallback;
use crate::Result;
#[cfg(test)]
use crate::VerificationOptions;
#[cfg(test)]
use crate::inspection::ArchiveManifest;
#[cfg(test)]
use crate::inspection::VerificationReport;

/// Supertrait that keeps [`ArchiveFormat`] implementable by this crate only.
pub(crate) mod sealed {
    /// Implemented by the format handlers of this crate.
    pub trait Sealed {}
}

/// Trait for archive format handlers.
///
/// Implemented by the handlers of this crate ([`TarArchive`], [`ZipArchive`],
/// [`SevenZArchive`]) and sealed: a new format is added in the crate, where its
/// detection, creation family and bindings are wired together.
///
/// A handle is opened under the [`SecurityConfig`](crate::SecurityConfig) whose
/// limits and policy every operation enforces, so the policy a ZIP census ran
/// under and the policy of the operation cannot differ.
///
/// Every operation consumes the handler: a forward-only reader (TAR) is valid
/// for exactly one pass, and the type system rejects a second one. The trait is
/// therefore used through generics, not `dyn`.
///
/// [`TarArchive`]: crate::formats::TarArchive
/// [`ZipArchive`]: crate::formats::ZipArchive
/// [`SevenZArchive`]: crate::formats::SevenZArchive
pub trait ArchiveFormat: sealed::Sealed {
    /// Extracts the archive to the specified directory.
    ///
    /// `progress` receives per-entry callbacks during extraction.
    ///
    /// # Errors
    ///
    /// Returns an error if extraction fails or security checks are violated.
    fn extract(
        self,
        output_dir: &Path,
        options: &ExtractionOptions,
        progress: &mut dyn ProgressCallback,
    ) -> Result<ExtractionReport>;

    /// Lists the archive contents without writing any files to disk.
    ///
    /// Returns a manifest of all entries with their metadata. Quota limits
    /// from the handle's config are applied to reject oversized archives early.
    ///
    /// # Errors
    ///
    /// Returns an error if the archive is corrupted, encrypted, or a quota
    /// limit is exceeded.
    #[cfg(test)]
    fn list(self) -> Result<ArchiveManifest>;

    /// Verifies the archive's integrity and security without extracting.
    ///
    /// Performs path-traversal, symlink, zip-bomb, quota, and permission
    /// checks. Security issues are collected in the returned report rather
    /// than propagated as errors, so callers get the complete picture.
    ///
    /// # Errors
    ///
    /// Returns an error only if the archive cannot be read at all (I/O
    /// failure, encryption). Individual security issues appear in the report.
    /// With integrity requested in `options`, TAR entry content that fails to
    /// decode is also an error.
    #[cfg(test)]
    fn verify(self, options: VerificationOptions) -> Result<VerificationReport>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestFormat;

    impl sealed::Sealed for TestFormat {}

    impl ArchiveFormat for TestFormat {
        fn extract(
            self,
            _output_dir: &Path,
            _options: &ExtractionOptions,
            _progress: &mut dyn ProgressCallback,
        ) -> Result<ExtractionReport> {
            Ok(ExtractionReport::new())
        }

        fn list(self) -> Result<ArchiveManifest> {
            use crate::formats::detect::ArchiveType;
            Ok(ArchiveManifest::new(ArchiveType::Tar))
        }

        fn verify(self, _options: VerificationOptions) -> Result<VerificationReport> {
            let config = crate::SecurityConfig::default();
            let manifest = self.list()?;
            Ok(crate::inspection::verify::verify_manifest(
                &manifest, &config, None,
            ))
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_trait_extract_returns_report() {
        let format = TestFormat;
        let temp = tempfile::TempDir::new().unwrap();
        let options = ExtractionOptions::default();
        let mut noop = crate::NoopProgress;
        let report = format.extract(temp.path(), &options, &mut noop).unwrap();
        assert_eq!(report.files_extracted, 0);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_trait_list_returns_empty_manifest() {
        let format = TestFormat;
        let manifest = format.list().unwrap();
        assert_eq!(manifest.total_entries(), 0);
        assert_eq!(manifest.total_size(), 0);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_trait_verify_returns_clean_report_for_empty_archive() {
        let format = TestFormat;
        let report = format
            .verify(crate::VerificationOptions::default())
            .unwrap();
        assert_eq!(report.total_entries(), 0);
        assert!(report.is_safe());
    }
}
