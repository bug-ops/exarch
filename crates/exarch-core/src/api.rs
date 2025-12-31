//! High-level public API for archive extraction, creation, and inspection.

use std::path::Path;

use crate::ExtractionReport;
use crate::Result;
use crate::SecurityConfig;
use crate::creation::CreationConfig;
use crate::creation::CreationReport;
use crate::formats::detect::ArchiveType;
use crate::formats::detect::detect_format;
use crate::inspection::ArchiveManifest;
use crate::inspection::VerificationReport;

/// Extracts an archive to the specified output directory.
///
/// This is the main high-level API for extracting archives with security
/// validation. The archive format is automatically detected.
///
/// # Arguments
///
/// * `archive_path` - Path to the archive file
/// * `output_dir` - Directory where files will be extracted
/// * `config` - Security configuration for the extraction
///
/// # Errors
///
/// Returns an error if:
/// - Archive file cannot be opened
/// - Archive format is unsupported
/// - Security validation fails
/// - I/O operations fail
///
/// # Examples
///
/// ```no_run
/// use exarch_core::SecurityConfig;
/// use exarch_core::extract_archive;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = SecurityConfig::default();
/// let report = extract_archive("archive.tar.gz", "/tmp/output", &config)?;
/// println!("Extracted {} files", report.files_extracted);
/// # Ok(())
/// # }
/// ```
pub fn extract_archive<P: AsRef<Path>, Q: AsRef<Path>>(
    archive_path: P,
    output_dir: Q,
    config: &SecurityConfig,
) -> Result<ExtractionReport> {
    // TODO: Implement archive extraction
    let _archive_path = archive_path.as_ref();
    let _output_dir = output_dir.as_ref();
    let _config = config;

    // Placeholder implementation
    Ok(ExtractionReport::new())
}

/// Creates an archive from source files and directories.
///
/// Format is auto-detected from output file extension, or can be
/// explicitly set via `config.format`.
///
/// # Arguments
///
/// * `output_path` - Path to the output archive file
/// * `sources` - Source files and directories to include
/// * `config` - Creation configuration
///
/// # Errors
///
/// Returns an error if:
/// - Cannot determine archive format
/// - Source files don't exist
/// - I/O operations fail
/// - Configuration is invalid
///
/// # Examples
///
/// ```no_run
/// use exarch_core::create_archive;
/// use exarch_core::creation::CreationConfig;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = CreationConfig::default();
/// let report = create_archive("output.tar.gz", &["src/", "Cargo.toml"], &config)?;
/// println!("Created archive with {} files", report.files_added);
/// # Ok(())
/// # }
/// ```
pub fn create_archive<P: AsRef<Path>, Q: AsRef<Path>>(
    output_path: P,
    sources: &[Q],
    config: &CreationConfig,
) -> Result<CreationReport> {
    let output = output_path.as_ref();

    // Determine format from extension or config
    let format = determine_creation_format(output, config)?;

    // Dispatch to format-specific creator
    match format {
        ArchiveType::Tar => crate::creation::tar::create_tar(output, sources, config),
        ArchiveType::TarGz => crate::creation::tar::create_tar_gz(output, sources, config),
        ArchiveType::TarBz2 => crate::creation::tar::create_tar_bz2(output, sources, config),
        ArchiveType::TarXz => crate::creation::tar::create_tar_xz(output, sources, config),
        ArchiveType::TarZst => crate::creation::tar::create_tar_zst(output, sources, config),
        ArchiveType::Zip => crate::creation::zip::create_zip(output, sources, config),
    }
}

/// Lists archive contents without extracting.
///
/// Returns a manifest containing metadata for all entries in the archive.
/// No files are written to disk during this operation.
///
/// # Arguments
///
/// * `archive_path` - Path to archive file
/// * `config` - Security configuration (quota limits apply)
///
/// # Errors
///
/// Returns error if:
/// - Archive file cannot be opened
/// - Archive format is unsupported or corrupted
/// - Quota limits exceeded (file count, total size)
///
/// # Examples
///
/// ```no_run
/// use exarch_core::SecurityConfig;
/// use exarch_core::list_archive;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = SecurityConfig::default();
/// let manifest = list_archive("archive.tar.gz", &config)?;
///
/// println!("Archive contains {} files", manifest.total_entries);
/// for entry in manifest.entries {
///     println!("{}: {} bytes", entry.path.display(), entry.size);
/// }
/// # Ok(())
/// # }
/// ```
pub fn list_archive<P: AsRef<Path>>(
    archive_path: P,
    config: &SecurityConfig,
) -> Result<ArchiveManifest> {
    crate::inspection::list_archive(archive_path, config)
}

/// Verifies archive integrity and security without extracting.
///
/// Performs comprehensive validation:
/// - Integrity checks (structure, checksums)
/// - Security checks (path traversal, zip bombs, CVEs)
/// - Policy checks (file types, permissions)
///
/// # Arguments
///
/// * `archive_path` - Path to archive file
/// * `config` - Security configuration for validation
///
/// # Errors
///
/// Returns error if:
/// - Archive file cannot be opened
/// - Archive is severely corrupted (cannot read structure)
///
/// Security violations are reported in `VerificationReport.issues`,
/// not as errors.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::SecurityConfig;
/// use exarch_core::VerificationStatus;
/// use exarch_core::verify_archive;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = SecurityConfig::default();
/// let report = verify_archive("archive.tar.gz", &config)?;
///
/// if report.status == VerificationStatus::Pass {
///     println!("Archive is safe to extract");
/// } else {
///     eprintln!("Security issues found:");
///     for issue in report.issues {
///         eprintln!("  [{}] {}", issue.severity, issue.message);
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub fn verify_archive<P: AsRef<Path>>(
    archive_path: P,
    config: &SecurityConfig,
) -> Result<VerificationReport> {
    crate::inspection::verify_archive(archive_path, config)
}

/// Determines archive format from output path or config.
fn determine_creation_format(output: &Path, config: &CreationConfig) -> Result<ArchiveType> {
    // If format explicitly set in config, use it
    if let Some(format) = config.format {
        return Ok(format);
    }

    // Auto-detect from extension
    detect_format(output)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_extract_archive_placeholder() {
        let config = SecurityConfig::default();
        let result = extract_archive(
            PathBuf::from("test.tar"),
            PathBuf::from("/tmp/test"),
            &config,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_determine_creation_format_tar() {
        let config = CreationConfig::default();
        let path = PathBuf::from("archive.tar");
        let format = determine_creation_format(&path, &config).unwrap();
        assert_eq!(format, ArchiveType::Tar);
    }

    #[test]
    fn test_determine_creation_format_tar_gz() {
        let config = CreationConfig::default();
        let path = PathBuf::from("archive.tar.gz");
        let format = determine_creation_format(&path, &config).unwrap();
        assert_eq!(format, ArchiveType::TarGz);

        let path2 = PathBuf::from("archive.tgz");
        let format2 = determine_creation_format(&path2, &config).unwrap();
        assert_eq!(format2, ArchiveType::TarGz);
    }

    #[test]
    fn test_determine_creation_format_tar_bz2() {
        let config = CreationConfig::default();
        let path = PathBuf::from("archive.tar.bz2");
        let format = determine_creation_format(&path, &config).unwrap();
        assert_eq!(format, ArchiveType::TarBz2);
    }

    #[test]
    fn test_determine_creation_format_tar_xz() {
        let config = CreationConfig::default();
        let path = PathBuf::from("archive.tar.xz");
        let format = determine_creation_format(&path, &config).unwrap();
        assert_eq!(format, ArchiveType::TarXz);
    }

    #[test]
    fn test_determine_creation_format_tar_zst() {
        let config = CreationConfig::default();
        let path = PathBuf::from("archive.tar.zst");
        let format = determine_creation_format(&path, &config).unwrap();
        assert_eq!(format, ArchiveType::TarZst);
    }

    #[test]
    fn test_determine_creation_format_zip() {
        let config = CreationConfig::default();
        let path = PathBuf::from("archive.zip");
        let format = determine_creation_format(&path, &config).unwrap();
        assert_eq!(format, ArchiveType::Zip);
    }

    #[test]
    fn test_determine_creation_format_explicit() {
        let config = CreationConfig::default().with_format(Some(ArchiveType::TarGz));
        let path = PathBuf::from("archive.xyz");
        let format = determine_creation_format(&path, &config).unwrap();
        assert_eq!(format, ArchiveType::TarGz);
    }

    #[test]
    fn test_determine_creation_format_unknown() {
        let config = CreationConfig::default();
        let path = PathBuf::from("archive.rar");
        let result = determine_creation_format(&path, &config);
        assert!(result.is_err());
    }
}
