//! Common traits for archive format handlers.

use std::path::Path;

use crate::ExtractionOptions;
use crate::ExtractionReport;
use crate::ProgressCallback;
use crate::Result;
use crate::SecurityConfig;
use crate::VerificationOptions;
use crate::creation::CreationConfig;
use crate::creation::CreationReport;
use crate::inspection::ArchiveManifest;
use crate::inspection::VerificationReport;

/// Trait for archive format handlers.
///
/// Implementors provide extraction, listing, and verification for a single
/// archive format. Every new format must implement all three operations so that
/// adding a format requires touching one trait implementation only.
///
/// Every method takes the [`SecurityConfig`] whose limits and policy the
/// operation enforces; every limit in it is already a typed, positive value.
///
/// Every operation consumes the handler: a forward-only reader (TAR) is valid
/// for exactly one pass, and the type system rejects a second one. The trait is
/// therefore used through generics, not `dyn`.
pub trait ArchiveFormat {
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
        config: &SecurityConfig,
        options: &ExtractionOptions,
        progress: &mut dyn ProgressCallback,
    ) -> Result<ExtractionReport>;

    /// Lists the archive contents without writing any files to disk.
    ///
    /// Returns a manifest of all entries with their metadata. Quota limits
    /// from `config` are applied to reject oversized archives early.
    ///
    /// # Errors
    ///
    /// Returns an error if the archive is corrupted, encrypted, or a quota
    /// limit is exceeded.
    fn list(self, config: &SecurityConfig) -> Result<ArchiveManifest>;

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
    fn verify(
        self,
        config: &SecurityConfig,
        options: &VerificationOptions,
    ) -> Result<VerificationReport>;
}

/// Trait for archive creation format handlers.
///
/// Parallels [`ArchiveFormat`] for the write side. Each format that supports
/// creation implements this trait so that `create_archive_with_progress`
/// can dispatch through trait objects instead of a manual match expression.
///
/// # Examples
///
/// ```
/// use exarch_core::ProgressCallback;
/// use exarch_core::Result;
/// use exarch_core::creation::CreationConfig;
/// use exarch_core::creation::CreationReport;
/// use exarch_core::formats::traits::FormatCreator;
/// use std::path::Path;
///
/// struct NoopCreator;
///
/// impl FormatCreator for NoopCreator {
///     fn create(
///         &self,
///         _output: &Path,
///         _sources: &[&Path],
///         _config: &CreationConfig,
///         _progress: &mut dyn ProgressCallback,
///     ) -> Result<CreationReport> {
///         Ok(CreationReport::default())
///     }
/// }
///
/// fn create_via_trait(
///     creator: &dyn FormatCreator,
///     output: &Path,
///     sources: &[&Path],
///     config: &CreationConfig,
///     progress: &mut dyn ProgressCallback,
/// ) -> Result<CreationReport> {
///     creator.create(output, sources, config, progress)
/// }
///
/// let creator = NoopCreator;
/// let config = CreationConfig::default();
/// let mut noop = exarch_core::NoopProgress;
/// create_via_trait(&creator, Path::new("out.tar.gz"), &[], &config, &mut noop).unwrap();
/// ```
pub trait FormatCreator {
    /// Creates an archive at `output` from the given `sources`.
    ///
    /// # Errors
    ///
    /// Returns an error if source paths are invalid, I/O fails, or
    /// the compression configuration is unsupported.
    fn create(
        &self,
        output: &Path,
        sources: &[&Path],
        config: &CreationConfig,
        progress: &mut dyn ProgressCallback,
    ) -> Result<CreationReport>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestFormat;

    impl ArchiveFormat for TestFormat {
        fn extract(
            self,
            _output_dir: &Path,
            _config: &SecurityConfig,
            _options: &ExtractionOptions,
            _progress: &mut dyn ProgressCallback,
        ) -> Result<ExtractionReport> {
            Ok(ExtractionReport::new())
        }

        fn list(self, _config: &SecurityConfig) -> Result<ArchiveManifest> {
            use crate::formats::detect::ArchiveType;
            Ok(ArchiveManifest::new(ArchiveType::Tar))
        }

        fn verify(
            self,
            config: &SecurityConfig,
            _options: &VerificationOptions,
        ) -> Result<VerificationReport> {
            let manifest = self.list(config)?;
            Ok(crate::inspection::verify::verify_manifest(
                &manifest, config, None,
            ))
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_trait_extract_returns_report() {
        let format = TestFormat;
        let temp = tempfile::TempDir::new().unwrap();
        let config = SecurityConfig::default();
        let options = ExtractionOptions::default();
        let mut noop = crate::NoopProgress;
        let report = format
            .extract(temp.path(), &config, &options, &mut noop)
            .unwrap();
        assert_eq!(report.files_extracted, 0);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_trait_list_returns_empty_manifest() {
        let format = TestFormat;
        let config = SecurityConfig::default();
        let manifest = format.list(&config).unwrap();
        assert_eq!(manifest.total_entries(), 0);
        assert_eq!(manifest.total_size(), 0);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_trait_verify_returns_clean_report_for_empty_archive() {
        let format = TestFormat;
        let config = SecurityConfig::default();
        let report = format
            .verify(&config, &crate::VerificationOptions::default())
            .unwrap();
        assert_eq!(report.total_entries(), 0);
        assert!(report.is_safe());
    }
}
