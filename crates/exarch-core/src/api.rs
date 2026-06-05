//! High-level public API for archive extraction, creation, and inspection.

use std::path::Path;

use crate::ArchiveError;
use crate::ExtractionReport;
use crate::NoopProgress;
use crate::ProgressCallback;
use crate::Result;
use crate::SecurityConfig;
use crate::config::ExtractionOptions;
use crate::creation::CreationConfig;
use crate::creation::CreationReport;
use crate::formats::detect::ArchiveType;
use crate::formats::detect::detect_format;
use crate::formats::detect::detect_format_from_extension;
use crate::formats::detect::is_zip_family_alias;
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
    let mut noop = NoopProgress;
    extract_archive_with_progress(archive_path, output_dir, config, &mut noop)
}

/// Extracts an archive with progress reporting.
///
/// Same as `extract_archive` but accepts a `ProgressCallback` for
/// real-time progress updates during extraction.
///
/// # Arguments
///
/// * `archive_path` - Path to the archive file
/// * `output_dir` - Directory where files will be extracted
/// * `config` - Security configuration for the extraction
/// * `progress` - Callback for progress updates
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
/// use exarch_core::NoopProgress;
/// use exarch_core::SecurityConfig;
/// use exarch_core::extract_archive_with_progress;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = SecurityConfig::default();
/// let mut progress = NoopProgress;
/// let report =
///     extract_archive_with_progress("archive.tar.gz", "/tmp/output", &config, &mut progress)?;
/// println!("Extracted {} files", report.files_extracted);
/// # Ok(())
/// # }
/// ```
pub fn extract_archive_with_progress<P: AsRef<Path>, Q: AsRef<Path>>(
    archive_path: P,
    output_dir: Q,
    config: &SecurityConfig,
    progress: &mut dyn ProgressCallback,
) -> Result<ExtractionReport> {
    let options = ExtractionOptions::default();
    extract_archive_with_options_and_progress(archive_path, output_dir, config, &options, progress)
}

fn extract_impl<P: AsRef<Path>, Q: AsRef<Path>>(
    archive_path: P,
    output_dir: Q,
    config: &SecurityConfig,
    options: &ExtractionOptions,
    progress: &mut dyn ProgressCallback,
) -> Result<ExtractionReport> {
    config.validate()?;

    let archive_path = archive_path.as_ref();
    let output_dir = output_dir.as_ref();

    // Detect archive format from file extension
    let format = detect_format(archive_path)?;

    // Dispatch to format-specific extraction
    match format {
        ArchiveType::Tar => {
            extract_tar_with_decoder(archive_path, output_dir, config, options, progress, Ok)
        }
        ArchiveType::TarGz => {
            extract_tar_with_decoder(archive_path, output_dir, config, options, progress, |r| {
                Ok(flate2::read::GzDecoder::new(r))
            })
        }
        ArchiveType::TarBz2 => {
            extract_tar_with_decoder(archive_path, output_dir, config, options, progress, |r| {
                Ok(bzip2::read::BzDecoder::new(r))
            })
        }
        ArchiveType::TarXz => {
            extract_tar_with_decoder(archive_path, output_dir, config, options, progress, |r| {
                Ok(xz2::read::XzDecoder::new(r))
            })
        }
        ArchiveType::TarZst => {
            extract_tar_with_decoder(archive_path, output_dir, config, options, progress, |r| {
                Ok(zstd::stream::read::Decoder::new(r)?)
            })
        }
        ArchiveType::Zip => extract_zip(archive_path, output_dir, config, options, progress),
        ArchiveType::SevenZ => extract_7z(archive_path, output_dir, config, options, progress),
    }
}

/// Extracts an archive with extraction options and optional progress reporting.
///
/// This is the canonical extraction implementation. All other
/// `extract_archive*` functions are thin wrappers that delegate here. Use this
/// directly when you need both [`ExtractionOptions`] (e.g., atomic mode) and a
/// progress callback.
///
/// # Arguments
///
/// * `archive_path` - Path to the archive file
/// * `output_dir` - Directory where files will be extracted
/// * `config` - Security configuration for the extraction
/// * `options` - Extraction behavior options (e.g., atomic mode)
/// * `progress` - Callback for progress updates
///
/// # Errors
///
/// Returns an error if:
/// - Archive file cannot be opened
/// - Archive format is unsupported
/// - Security validation fails
/// - I/O operations fail
/// - Atomic temp dir creation or rename fails
///
/// # Examples
///
/// ```no_run
/// use exarch_core::ExtractionOptions;
/// use exarch_core::NoopProgress;
/// use exarch_core::SecurityConfig;
/// use exarch_core::extract_archive_with_options_and_progress;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = SecurityConfig::default();
/// let options = ExtractionOptions::default().with_atomic(true);
/// let mut progress = NoopProgress;
/// let report = extract_archive_with_options_and_progress(
///     "archive.tar.gz",
///     "/tmp/output",
///     &config,
///     &options,
///     &mut progress,
/// )?;
/// println!("Extracted {} files", report.files_extracted);
/// # Ok(())
/// # }
/// ```
pub fn extract_archive_with_options_and_progress<P: AsRef<Path>, Q: AsRef<Path>>(
    archive_path: P,
    output_dir: Q,
    config: &SecurityConfig,
    options: &ExtractionOptions,
    progress: &mut dyn ProgressCallback,
) -> Result<ExtractionReport> {
    if options.atomic {
        extract_atomic(archive_path, output_dir, config, options, progress)
    } else {
        extract_impl(archive_path, output_dir, config, options, progress)
    }
}

/// Extracts an archive with extraction options (no progress reporting).
///
/// Convenience wrapper around [`extract_archive_with_options_and_progress`]
/// that passes a no-op progress callback. Use this when you need
/// [`ExtractionOptions`] but do not require progress updates.
///
/// # Errors
///
/// Returns an error if:
/// - Archive file cannot be opened
/// - Archive format is unsupported
/// - Security validation fails
/// - I/O operations fail
/// - Atomic temp dir creation or rename fails
///
/// # Examples
///
/// ```no_run
/// use exarch_core::ExtractionOptions;
/// use exarch_core::SecurityConfig;
/// use exarch_core::extract_archive_with_options;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = SecurityConfig::default();
/// let options = ExtractionOptions::default().with_atomic(true);
/// let report = extract_archive_with_options("archive.tar.gz", "/tmp/output", &config, &options)?;
/// println!("Extracted {} files", report.files_extracted);
/// # Ok(())
/// # }
/// ```
pub fn extract_archive_with_options<P: AsRef<Path>, Q: AsRef<Path>>(
    archive_path: P,
    output_dir: Q,
    config: &SecurityConfig,
    options: &ExtractionOptions,
) -> Result<ExtractionReport> {
    let mut noop = NoopProgress;
    extract_archive_with_options_and_progress(archive_path, output_dir, config, options, &mut noop)
}

fn extract_atomic<P: AsRef<Path>, Q: AsRef<Path>>(
    archive_path: P,
    output_dir: Q,
    config: &SecurityConfig,
    options: &ExtractionOptions,
    progress: &mut dyn ProgressCallback,
) -> Result<ExtractionReport> {
    let output_dir = output_dir.as_ref();

    // Canonicalize output_dir to resolve any symlinks in the path before
    // computing the parent, so temp dir lands on the same filesystem.
    // If output_dir doesn't exist yet, use its lexical parent.
    let canonical_output = if output_dir.exists() {
        output_dir.canonicalize().map_err(ArchiveError::Io)?
    } else {
        output_dir.to_path_buf()
    };

    let parent = canonical_output
        .parent()
        .ok_or_else(|| ArchiveError::InvalidConfiguration {
            reason: "output directory has no parent".into(),
        })?;

    std::fs::create_dir_all(parent).map_err(ArchiveError::Io)?;

    let temp_dir = tempfile::tempdir_in(parent).map_err(|e| {
        ArchiveError::Io(std::io::Error::new(
            e.kind(),
            format!(
                "failed to create temp directory in {}: {e}",
                parent.display()
            ),
        ))
    })?;

    let result = extract_impl(archive_path, temp_dir.path(), config, options, progress);

    match result {
        Ok(report) => {
            // Consume TempDir to prevent Drop cleanup, then rename.
            let temp_path = temp_dir.keep();
            std::fs::rename(&temp_path, output_dir).map_err(|e| {
                // Rename failed: clean up temp dir
                let _ = std::fs::remove_dir_all(&temp_path);
                // Map AlreadyExists to OutputExists for caller clarity
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    ArchiveError::OutputExists {
                        path: output_dir.to_path_buf(),
                    }
                } else {
                    ArchiveError::Io(std::io::Error::new(
                        e.kind(),
                        format!("failed to rename temp dir to {}: {e}", output_dir.display()),
                    ))
                }
            })?;

            Ok(report)
        }
        Err(e) => {
            // TempDir Drop runs here: cleans up temp dir automatically.
            Err(e)
        }
    }
}

/// Opens `archive_path`, wraps it in a `BufReader`, passes it to
/// `make_decoder`, and extracts the resulting TAR stream.
///
/// `make_decoder` builds a decoder (e.g. `GzDecoder`, `XzDecoder`) from the
/// buffered file reader. For uncompressed TAR pass `Ok` as the identity
/// closure. The closure may be fallible (e.g. zstd requires a constructor call
/// that can fail with an I/O error).
fn extract_tar_with_decoder<R, F>(
    archive_path: &Path,
    output_dir: &Path,
    config: &SecurityConfig,
    options: &ExtractionOptions,
    progress: &mut dyn ProgressCallback,
    make_decoder: F,
) -> Result<ExtractionReport>
where
    R: std::io::Read,
    F: FnOnce(std::io::BufReader<std::fs::File>) -> Result<R>,
{
    use crate::formats::TarArchive;
    use crate::formats::traits::ArchiveFormat;

    let file = std::fs::File::open(archive_path)?;
    let reader = std::io::BufReader::new(file);
    let decoder = make_decoder(reader)?;
    let mut archive = TarArchive::new(decoder);
    archive.extract(output_dir, config, options, progress)
}

fn extract_zip(
    archive_path: &Path,
    output_dir: &Path,
    config: &SecurityConfig,
    options: &ExtractionOptions,
    progress: &mut dyn ProgressCallback,
) -> Result<ExtractionReport> {
    use crate::formats::ZipArchive;
    use crate::formats::traits::ArchiveFormat;
    use std::fs::File;

    let file = File::open(archive_path)?;
    let mut archive = ZipArchive::new(file)?;
    archive.extract(output_dir, config, options, progress)
}

fn extract_7z(
    archive_path: &Path,
    output_dir: &Path,
    config: &SecurityConfig,
    options: &ExtractionOptions,
    progress: &mut dyn ProgressCallback,
) -> Result<ExtractionReport> {
    use crate::formats::SevenZArchive;
    use crate::formats::traits::ArchiveFormat;
    use std::fs::File;

    let file = File::open(archive_path)?;
    let mut archive = SevenZArchive::new(file)?;
    archive.extract(output_dir, config, options, progress)
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
    let mut noop = NoopProgress;
    create_archive_with_progress(output_path, sources, config, &mut noop)
}

/// Creates an archive with progress reporting.
///
/// Same as `create_archive` but accepts a `ProgressCallback` for
/// real-time progress updates during creation.
///
/// # Arguments
///
/// * `output_path` - Path to the output archive file
/// * `sources` - Source files and directories to include
/// * `config` - Creation configuration
/// * `progress` - Callback for progress updates
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
/// use exarch_core::NoopProgress;
/// use exarch_core::create_archive_with_progress;
/// use exarch_core::creation::CreationConfig;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = CreationConfig::default();
/// let mut progress = NoopProgress;
/// let report = create_archive_with_progress(
///     "output.tar.gz",
///     &["src/", "Cargo.toml"],
///     &config,
///     &mut progress,
/// )?;
/// println!("Created archive with {} files", report.files_added);
/// # Ok(())
/// # }
/// ```
pub fn create_archive_with_progress<P: AsRef<Path>, Q: AsRef<Path>>(
    output_path: P,
    sources: &[Q],
    config: &CreationConfig,
    progress: &mut dyn ProgressCallback,
) -> Result<CreationReport> {
    config.validate()?;

    let output = output_path.as_ref();

    // Block creation for the ZIP-family extensions (mirrors the 7z block
    // below). They're all ZIP underneath but add extra requirements -
    // signing (apk/aab/ipa/appx/msix), checksum manifests (whl), ordering
    // and stored-compression rules (epub), descriptor files
    // (war/ear/vsix/nbm) - which exarch doesn't produce. Silently emitting
    // a bare ZIP with one of these extensions would be misleading, so we
    // error instead. Callers who need the override can set
    // CreationConfig::format = Some(ArchiveType::Zip).
    if config.format.is_none() {
        reject_zip_family_creation(output)?;
    }

    // Determine format from extension or config
    let format = determine_creation_format(output, config)?;

    let source_refs: Vec<&Path> = sources.iter().map(AsRef::as_ref).collect();
    let creator = creator_for_format(format)?;
    creator.create(output, &source_refs, config, progress)
}

fn creator_for_format(
    format: ArchiveType,
) -> Result<Box<dyn crate::formats::traits::FormatCreator>> {
    match format {
        ArchiveType::Tar => Ok(Box::new(crate::creation::TarCreator)),
        ArchiveType::TarGz => Ok(Box::new(crate::creation::TarGzCreator)),
        ArchiveType::TarBz2 => Ok(Box::new(crate::creation::TarBz2Creator)),
        ArchiveType::TarXz => Ok(Box::new(crate::creation::TarXzCreator)),
        ArchiveType::TarZst => Ok(Box::new(crate::creation::TarZstCreator)),
        ArchiveType::Zip => Ok(Box::new(crate::creation::ZipCreator)),
        ArchiveType::SevenZ => Err(ArchiveError::InvalidConfiguration {
            reason: "7z archive creation is not supported".into(),
        }),
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

/// Rejects creation for ZIP-family extensions that aren't plain `.zip`.
///
/// See the call site in `create_archive_with_progress` for the rationale.
/// Returns `Ok(())` for anything else - `.zip`, tar variants, unknown
/// extensions (those get caught later by `detect_format`).
fn reject_zip_family_creation(output: &Path) -> Result<()> {
    let Some(ext) = output.extension().and_then(|e| e.to_str()) else {
        return Ok(());
    };
    if is_zip_family_alias(ext) {
        let ext_lower = ext.to_ascii_lowercase();
        return Err(ArchiveError::InvalidArchive(format!(
            "creation for .{ext_lower} isn't supported: the format is ZIP-based but \
             requires extra structure (signing, manifests, ordering) that exarch \
             doesn't produce. Use .zip, or set CreationConfig::format = Some(\
             exarch_core::formats::detect::ArchiveType::Zip) to override."
        )));
    }
    Ok(())
}

/// Determines archive format from output path or config.
///
/// Uses extension-only detection; magic-byte detection is intentionally
/// excluded so that a pre-existing output file with stale bytes cannot
/// override the caller's intended format.
fn determine_creation_format(output: &Path, config: &CreationConfig) -> Result<ArchiveType> {
    // If format explicitly set in config, use it
    if let Some(format) = config.format {
        return Ok(format);
    }

    // Auto-detect from extension only — never from magic bytes.
    detect_format_from_extension(output)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_extract_archive_nonexistent_file() {
        let config = SecurityConfig::default();
        let result = extract_archive(
            PathBuf::from("nonexistent_test.tar"),
            PathBuf::from("/tmp/test"),
            &config,
        );
        // Should fail because file doesn't exist
        assert!(result.is_err());
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

    #[test]
    fn test_determine_creation_format_ignores_stale_magic_bytes() {
        // Regression for C1: a pre-existing output file whose bytes match a
        // different format must not override the extension-derived format.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.zip");
        // Write gzip magic bytes into a file named .zip
        std::fs::write(&path, b"\x1f\x8b\x08\x00\x00\x00\x00\x00").unwrap();

        let config = CreationConfig::default();
        let format = determine_creation_format(&path, &config).unwrap();
        assert_eq!(
            format,
            ArchiveType::Zip,
            "creation format must follow extension, not stale on-disk magic bytes"
        );
    }

    #[test]
    fn test_extract_archive_7z_not_implemented() {
        let dest = tempfile::TempDir::new().unwrap();
        let path = PathBuf::from("test.7z");

        let result = extract_archive(&path, dest.path(), &SecurityConfig::default());

        assert!(result.is_err());
    }

    #[test]
    fn test_create_archive_invalid_compression_level_rejected_before_io() {
        let dest = tempfile::TempDir::new().unwrap();
        let archive_path = dest.path().join("output.tar.gz");
        let config = CreationConfig {
            compression_level: Some(15),
            ..CreationConfig::default()
        };
        let result = create_archive(&archive_path, &[] as &[&str], &config);
        assert!(
            matches!(
                result,
                Err(ArchiveError::InvalidCompressionLevel { level: 15 })
            ),
            "expected InvalidCompressionLevel, got {result:?}",
        );
        // Verify no I/O happened — output file must not exist
        assert!(!archive_path.exists(), "output file must not be created");
    }

    #[test]
    fn test_create_archive_zip_family_not_supported() {
        // Mirrors test_create_archive_7z_not_supported. Spot-checks a couple
        // of extensions rather than every one - the integration test
        // covers the full list.
        let dest = tempfile::TempDir::new().unwrap();
        for ext in ["apk", "whl", "EPUB"] {
            let archive_path = dest.path().join(format!("output.{ext}"));
            let result = create_archive(&archive_path, &[] as &[&str], &CreationConfig::default());
            assert!(
                matches!(result, Err(ArchiveError::InvalidArchive(_))),
                ".{ext} should be rejected, got {result:?}",
            );
        }
    }

    #[test]
    fn test_create_archive_zip_family_override_bypasses_guard() {
        // Explicit CreationConfig::format = Some(Zip) is the escape hatch -
        // skips the ZIP-family guard. Caller takes responsibility for the
        // resulting file not being spec-valid.
        let dest = tempfile::TempDir::new().unwrap();
        let src = dest.path().join("source.txt");
        std::fs::write(&src, b"hello").unwrap();
        let archive_path = dest.path().join("output.apk");
        let config = CreationConfig::default().with_format(Some(ArchiveType::Zip));
        let result = create_archive(&archive_path, &[&src], &config);
        assert!(
            result.is_ok(),
            "explicit format override should bypass the guard, got {result:?}",
        );
    }

    #[test]
    fn test_create_archive_7z_not_supported() {
        let dest = tempfile::TempDir::new().unwrap();
        let archive_path = dest.path().join("output.7z");

        let result = create_archive(&archive_path, &[] as &[&str], &CreationConfig::default());

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ArchiveError::InvalidConfiguration { .. }
        ));
    }

    #[test]
    fn test_extract_archive_with_options_and_progress_non_atomic_delegates_to_normal() {
        let dest = tempfile::TempDir::new().unwrap();
        let options = ExtractionOptions {
            atomic: false,
            skip_duplicates: true,
        };
        let result = extract_archive_with_options_and_progress(
            PathBuf::from("nonexistent.tar.gz"),
            dest.path(),
            &SecurityConfig::default(),
            &options,
            &mut NoopProgress,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_archive_with_options_delegates() {
        let dest = tempfile::TempDir::new().unwrap();
        let options = ExtractionOptions {
            atomic: false,
            skip_duplicates: true,
        };
        let result = extract_archive_with_options(
            PathBuf::from("nonexistent.tar.gz"),
            dest.path(),
            &SecurityConfig::default(),
            &options,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_atomic_success() {
        use crate::create_archive;
        use crate::creation::CreationConfig;

        // Create a valid tar.gz to extract
        let archive_dir = tempfile::TempDir::new().unwrap();
        let archive_path = archive_dir.path().join("test.tar.gz");

        // Create a simple archive with one file
        let src_dir = tempfile::TempDir::new().unwrap();
        std::fs::write(src_dir.path().join("hello.txt"), b"hello world").unwrap();
        create_archive(&archive_path, &[src_dir.path()], &CreationConfig::default()).unwrap();

        let parent = tempfile::TempDir::new().unwrap();
        let output_dir = parent.path().join("extracted");

        let options = ExtractionOptions {
            atomic: true,
            skip_duplicates: true,
        };
        let result = extract_archive_with_options(
            &archive_path,
            &output_dir,
            &SecurityConfig::default(),
            &options,
        );

        assert!(result.is_ok());
        assert!(output_dir.exists());
        // No temp dir remnants
        let temp_entries: Vec<_> = std::fs::read_dir(parent.path()).unwrap().collect();
        assert_eq!(
            temp_entries.len(),
            1,
            "Expected only the output dir, found temp remnants"
        );
    }

    #[test]
    fn test_extract_atomic_failure_cleans_up() {
        let parent = tempfile::TempDir::new().unwrap();
        let output_dir = parent.path().join("extracted");

        let options = ExtractionOptions {
            atomic: true,
            skip_duplicates: true,
        };
        let result = extract_archive_with_options(
            PathBuf::from("nonexistent_archive.tar.gz"),
            &output_dir,
            &SecurityConfig::default(),
            &options,
        );

        assert!(result.is_err());
        // Output dir must not exist
        assert!(!output_dir.exists());
        // No temp dir remnants in parent
        let temp_entries: Vec<_> = std::fs::read_dir(parent.path()).unwrap().collect();
        assert!(
            temp_entries.is_empty(),
            "Temp dir not cleaned up after failure"
        );
    }

    #[test]
    fn test_extract_atomic_output_already_exists_fails() {
        use crate::create_archive;
        use crate::creation::CreationConfig;

        let parent = tempfile::TempDir::new().unwrap();
        let output_dir = parent.path().join("extracted");
        std::fs::create_dir_all(&output_dir).unwrap();
        // Create a file in output_dir so it's non-empty (rename over non-empty dir
        // fails on most OSes)
        std::fs::write(output_dir.join("existing.txt"), b"old content").unwrap();

        let archive_dir = tempfile::TempDir::new().unwrap();
        let archive_path = archive_dir.path().join("test.tar.gz");
        let src_dir = tempfile::TempDir::new().unwrap();
        std::fs::write(src_dir.path().join("new.txt"), b"new content").unwrap();
        create_archive(&archive_path, &[src_dir.path()], &CreationConfig::default()).unwrap();

        let options = ExtractionOptions {
            atomic: true,
            skip_duplicates: true,
        };
        let result = extract_archive_with_options(
            &archive_path,
            &output_dir,
            &SecurityConfig::default(),
            &options,
        );

        // Should fail with OutputExists or Io (platform dependent rename semantics)
        assert!(result.is_err());
        // Output dir must still have old content (not corrupted)
        assert!(output_dir.join("existing.txt").exists());
    }

    // Regression test for issue #170: progress callback silently dropped
    #[test]
    fn test_progress_callback_invoked_during_extraction() {
        use crate::ProgressCallback;
        use std::path::Path;

        struct TrackingProgress {
            started: usize,
            completed: usize,
            finished: bool,
        }

        impl ProgressCallback for TrackingProgress {
            fn on_entry_start(&mut self, _path: &Path, _total: usize, _current: usize) {
                self.started += 1;
            }

            fn on_bytes_written(&mut self, _bytes: u64) {}

            fn on_entry_complete(&mut self, _path: &Path) {
                self.completed += 1;
            }

            fn on_complete(&mut self) {
                self.finished = true;
            }
        }

        let archive_dir = tempfile::TempDir::new().unwrap();
        let archive_path = archive_dir.path().join("test.tar.gz");
        let src_dir = tempfile::TempDir::new().unwrap();
        std::fs::write(src_dir.path().join("a.txt"), b"hello").unwrap();
        std::fs::write(src_dir.path().join("b.txt"), b"world").unwrap();
        create_archive(&archive_path, &[src_dir.path()], &CreationConfig::default()).unwrap();

        let dest = tempfile::TempDir::new().unwrap();
        let mut progress = TrackingProgress {
            started: 0,
            completed: 0,
            finished: false,
        };

        let report = extract_archive_with_progress(
            &archive_path,
            dest.path(),
            &SecurityConfig::default(),
            &mut progress,
        )
        .unwrap();

        assert!(report.files_extracted >= 2, "expected at least 2 files");
        assert!(progress.started >= 2, "on_entry_start not called");
        assert!(progress.completed >= 2, "on_entry_complete not called");
        assert!(progress.finished, "on_complete not called");
    }

    // Regression test for issue #170: ZIP format
    #[test]
    fn test_progress_callback_invoked_during_zip_extraction() {
        use crate::ProgressCallback;
        use std::path::Path;

        struct TrackingProgress {
            started: usize,
            completed: usize,
            finished: bool,
        }

        impl ProgressCallback for TrackingProgress {
            fn on_entry_start(&mut self, _path: &Path, _total: usize, _current: usize) {
                self.started += 1;
            }

            fn on_bytes_written(&mut self, _bytes: u64) {}

            fn on_entry_complete(&mut self, _path: &Path) {
                self.completed += 1;
            }

            fn on_complete(&mut self) {
                self.finished = true;
            }
        }

        let tmp = tempfile::TempDir::new().unwrap();
        let archive_path = tmp.path().join("test.zip");
        let src_dir = tempfile::TempDir::new().unwrap();
        std::fs::write(src_dir.path().join("x.txt"), b"foo").unwrap();
        std::fs::write(src_dir.path().join("y.txt"), b"bar").unwrap();
        let config = CreationConfig::default().with_format(Some(ArchiveType::Zip));
        create_archive(&archive_path, &[src_dir.path()], &config).unwrap();

        let dest = tempfile::TempDir::new().unwrap();
        let mut progress = TrackingProgress {
            started: 0,
            completed: 0,
            finished: false,
        };
        let report = extract_archive_with_progress(
            &archive_path,
            dest.path(),
            &SecurityConfig::default(),
            &mut progress,
        )
        .unwrap();

        assert!(report.files_extracted >= 2, "expected at least 2 files");
        assert!(progress.started >= 2, "on_entry_start not called for ZIP");
        assert!(
            progress.completed >= 2,
            "on_entry_complete not called for ZIP"
        );
        assert!(progress.finished, "on_complete not called for ZIP");
    }

    // Regression test for issue #170: 7z format
    #[test]
    fn test_progress_callback_invoked_during_sevenz_extraction() {
        use crate::ProgressCallback;
        use std::path::Path;

        struct TrackingProgress {
            started: usize,
            completed: usize,
            finished: bool,
        }

        impl ProgressCallback for TrackingProgress {
            fn on_entry_start(&mut self, _path: &Path, _total: usize, _current: usize) {
                self.started += 1;
            }

            fn on_bytes_written(&mut self, _bytes: u64) {}

            fn on_entry_complete(&mut self, _path: &Path) {
                self.completed += 1;
            }

            fn on_complete(&mut self) {
                self.finished = true;
            }
        }

        let fixture =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/simple.7z");

        let dest = tempfile::TempDir::new().unwrap();
        let mut progress = TrackingProgress {
            started: 0,
            completed: 0,
            finished: false,
        };
        let report = extract_archive_with_progress(
            &fixture,
            dest.path(),
            &SecurityConfig::default(),
            &mut progress,
        )
        .unwrap();

        assert!(
            report.files_extracted >= 1,
            "expected at least 1 file from simple.7z"
        );
        assert!(progress.started >= 1, "on_entry_start not called for 7z");
        assert!(
            progress.completed >= 1,
            "on_entry_complete not called for 7z"
        );
        assert!(progress.finished, "on_complete not called for 7z");
    }

    // Regression test for issue #304: on_bytes_written must be called with > 0
    // bytes when extracting non-empty files from TAR archives.
    #[test]
    fn test_on_bytes_written_called_for_tar() {
        use crate::ProgressCallback;
        use std::path::Path;

        struct ByteTracker {
            total: u64,
        }

        impl ProgressCallback for ByteTracker {
            fn on_entry_start(&mut self, _path: &Path, _total: usize, _current: usize) {}

            fn on_bytes_written(&mut self, bytes: u64) {
                self.total += bytes;
            }

            fn on_entry_complete(&mut self, _path: &Path) {}

            fn on_complete(&mut self) {}
        }

        let archive_dir = tempfile::TempDir::new().unwrap();
        let archive_path = archive_dir.path().join("test.tar.gz");
        let src_dir = tempfile::TempDir::new().unwrap();
        std::fs::write(src_dir.path().join("hello.txt"), b"hello world").unwrap();
        create_archive(&archive_path, &[src_dir.path()], &CreationConfig::default()).unwrap();

        let dest = tempfile::TempDir::new().unwrap();
        let mut progress = ByteTracker { total: 0 };
        let report = extract_archive_with_progress(
            &archive_path,
            dest.path(),
            &SecurityConfig::default(),
            &mut progress,
        )
        .unwrap();

        assert!(
            report.bytes_written > 0,
            "report.bytes_written must be > 0, got {}",
            report.bytes_written
        );
        assert!(
            progress.total > 0,
            "on_bytes_written must be called with > 0 bytes for TAR, got {}",
            progress.total
        );
    }

    // Regression test for issue #304: on_bytes_written must be called with > 0
    // bytes when extracting non-empty files from ZIP archives.
    #[test]
    fn test_on_bytes_written_called_for_zip() {
        use crate::ProgressCallback;
        use std::path::Path;

        struct ByteTracker {
            total: u64,
        }

        impl ProgressCallback for ByteTracker {
            fn on_entry_start(&mut self, _path: &Path, _total: usize, _current: usize) {}

            fn on_bytes_written(&mut self, bytes: u64) {
                self.total += bytes;
            }

            fn on_entry_complete(&mut self, _path: &Path) {}

            fn on_complete(&mut self) {}
        }

        let tmp = tempfile::TempDir::new().unwrap();
        let archive_path = tmp.path().join("test.zip");
        let src_dir = tempfile::TempDir::new().unwrap();
        std::fs::write(src_dir.path().join("data.txt"), b"hello world").unwrap();
        let config = CreationConfig::default().with_format(Some(ArchiveType::Zip));
        create_archive(&archive_path, &[src_dir.path()], &config).unwrap();

        let dest = tempfile::TempDir::new().unwrap();
        let mut progress = ByteTracker { total: 0 };
        let report = extract_archive_with_progress(
            &archive_path,
            dest.path(),
            &SecurityConfig::default(),
            &mut progress,
        )
        .unwrap();

        assert!(
            report.bytes_written > 0,
            "report.bytes_written must be > 0, got {}",
            report.bytes_written
        );
        assert!(
            progress.total > 0,
            "on_bytes_written must be called with > 0 bytes for ZIP, got {}",
            progress.total
        );
    }

    // Regression test for issue #304: on_bytes_written must be called with > 0
    // bytes when extracting non-empty files from 7z archives.
    #[test]
    fn test_on_bytes_written_called_for_sevenz() {
        use crate::ProgressCallback;
        use std::path::Path;

        struct ByteTracker {
            total: u64,
        }

        impl ProgressCallback for ByteTracker {
            fn on_entry_start(&mut self, _path: &Path, _total: usize, _current: usize) {}

            fn on_bytes_written(&mut self, bytes: u64) {
                self.total += bytes;
            }

            fn on_entry_complete(&mut self, _path: &Path) {}

            fn on_complete(&mut self) {}
        }

        let fixture =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/simple.7z");

        let dest = tempfile::TempDir::new().unwrap();
        let mut progress = ByteTracker { total: 0 };
        let report = extract_archive_with_progress(
            &fixture,
            dest.path(),
            &SecurityConfig::default(),
            &mut progress,
        )
        .unwrap();

        assert!(
            report.bytes_written > 0,
            "report.bytes_written must be > 0, got {}",
            report.bytes_written
        );
        assert!(
            progress.total > 0,
            "on_bytes_written must be called with > 0 bytes for 7z, got {}",
            progress.total
        );
    }

    // Regression test for BYTES-1: on_bytes_written must be called when TAR
    // hardlinks are extracted (copy path in create_hardlink).
    #[test]
    fn test_tar_hardlink_calls_on_bytes_written() {
        use crate::ProgressCallback;
        use crate::formats::TarArchive;
        use crate::formats::traits::ArchiveFormat;
        use std::io::Cursor;
        use std::path::Path;

        struct ByteTracker {
            total: u64,
        }

        impl ProgressCallback for ByteTracker {
            fn on_entry_start(&mut self, _path: &Path, _total: usize, _current: usize) {}

            fn on_bytes_written(&mut self, bytes: u64) {
                self.total += bytes;
            }

            fn on_entry_complete(&mut self, _path: &Path) {}

            fn on_complete(&mut self) {}
        }

        // Build a TAR with one regular file and one hardlink pointing to it.
        let content = b"hello hardlink";
        let tar_data = {
            let mut builder = tar::Builder::new(Vec::new());

            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder
                .append_data(&mut header, "original.txt", content.as_ref())
                .unwrap();

            let mut hdr = tar::Header::new_gnu();
            hdr.set_size(0);
            hdr.set_mode(0o644);
            hdr.set_entry_type(tar::EntryType::Link);
            hdr.set_link_name("original.txt").unwrap();
            hdr.set_cksum();
            builder
                .append_data(&mut hdr, "link.txt", std::io::empty())
                .unwrap();

            builder.into_inner().unwrap()
        };

        let temp = tempfile::TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = true;

        let mut archive = TarArchive::new(Cursor::new(tar_data));
        let mut progress = ByteTracker { total: 0 };
        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut progress,
            )
            .unwrap();

        // The hardlink copies the file content — bytes should be reported twice.
        let expected = (content.len() as u64) * 2;
        assert_eq!(
            progress.total, expected,
            "on_bytes_written must report bytes for both original and hardlink copy, \
             got {} (report.bytes_written={})",
            progress.total, report.bytes_written
        );
    }

    // Regression test for issue #305: on_entry_complete must be called even
    // when TAR extraction fails mid-entry due to a path traversal violation.
    #[test]
    fn test_tar_on_entry_complete_called_on_path_traversal_error() {
        use crate::ProgressCallback;
        use crate::formats::TarArchive;
        use crate::formats::traits::ArchiveFormat;
        use std::io::Cursor;
        use std::path::Path;

        struct SymmetryTracker {
            started: usize,
            completed: usize,
        }

        impl ProgressCallback for SymmetryTracker {
            fn on_entry_start(&mut self, _path: &Path, _total: usize, _current: usize) {
                self.started += 1;
            }

            fn on_bytes_written(&mut self, _bytes: u64) {}

            fn on_entry_complete(&mut self, _path: &Path) {
                self.completed += 1;
            }

            fn on_complete(&mut self) {}
        }

        // Build a minimal TAR with a path-traversal entry at raw bytes level
        // (bypassing the `tar` crate's sanitization).
        let tar_data = make_raw_tar_single(b"../../etc/passwd", b"evil");

        let temp = tempfile::TempDir::new().unwrap();
        let mut archive = TarArchive::new(Cursor::new(tar_data));
        let mut progress = SymmetryTracker {
            started: 0,
            completed: 0,
        };
        let result = archive.extract(
            temp.path(),
            &SecurityConfig::default(),
            &ExtractionOptions::default(),
            &mut progress,
        );

        assert!(result.is_err(), "traversal entry must be rejected");
        assert_eq!(
            progress.started, progress.completed,
            "on_entry_complete must be called for every on_entry_start, \
             even when extraction fails: started={}, completed={}",
            progress.started, progress.completed
        );
    }

    // Regression test for issue #305: on_entry_complete must be called even
    // when ZIP extraction fails mid-entry due to a path traversal violation.
    #[test]
    fn test_zip_on_entry_complete_called_on_path_traversal_error() {
        use crate::ProgressCallback;
        use crate::formats::ZipArchive;
        use crate::formats::traits::ArchiveFormat;
        use std::io::Cursor;
        use std::path::Path;

        struct SymmetryTracker {
            started: usize,
            completed: usize,
        }

        impl ProgressCallback for SymmetryTracker {
            fn on_entry_start(&mut self, _path: &Path, _total: usize, _current: usize) {
                self.started += 1;
            }

            fn on_bytes_written(&mut self, _bytes: u64) {}

            fn on_entry_complete(&mut self, _path: &Path) {
                self.completed += 1;
            }

            fn on_complete(&mut self) {}
        }

        // Build a ZIP with a traversal path using zip::ZipWriter.
        let zip_data = make_zip_with_traversal(b"../../etc/passwd", b"evil");

        let temp = tempfile::TempDir::new().unwrap();
        let mut archive = ZipArchive::new(Cursor::new(zip_data)).unwrap();
        let mut progress = SymmetryTracker {
            started: 0,
            completed: 0,
        };
        let result = archive.extract(
            temp.path(),
            &SecurityConfig::default(),
            &ExtractionOptions::default(),
            &mut progress,
        );

        assert!(result.is_err(), "traversal entry must be rejected");
        assert_eq!(
            progress.started, progress.completed,
            "on_entry_complete must be called for every on_entry_start in ZIP, \
             even when extraction fails: started={}, completed={}",
            progress.started, progress.completed
        );
    }

    // Builds a single-entry POSIX ustar TAR with an arbitrary raw path,
    // bypassing the `tar` crate's path sanitization.
    fn make_raw_tar_single(path: &[u8], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut header = [0u8; 512];

        let path_len = path.len().min(100);
        header[..path_len].copy_from_slice(&path[..path_len]);
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        let size_str = format!("{:011o}\0", data.len());
        header[124..136].copy_from_slice(size_str.as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar ");
        header[263..265].copy_from_slice(b" \0");
        header[148..156].copy_from_slice(b"        ");
        let checksum: u32 = header.iter().map(|&b| u32::from(b)).sum();
        let ck_str = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(ck_str.as_bytes());

        out.extend_from_slice(&header);
        out.extend_from_slice(data);
        let rem = data.len() % 512;
        if rem != 0 {
            out.extend(std::iter::repeat_n(0u8, 512 - rem));
        }
        out.extend(std::iter::repeat_n(0u8, 1024));
        out
    }

    // Builds a single-entry ZIP with a raw traversal path by writing the
    // local file header and central directory manually.
    #[allow(clippy::cast_possible_truncation)]
    fn make_zip_with_traversal(path: &[u8], data: &[u8]) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        let crc = crc32_ieee(data);
        let name_len = path.len() as u16;
        let content_len = data.len() as u32;

        let local_offset: u32 = 0;

        // Local file header
        buf.extend_from_slice(b"PK\x03\x04");
        buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
        buf.extend_from_slice(&0u16.to_le_bytes()); // flags
        buf.extend_from_slice(&0u16.to_le_bytes()); // compression: Stored
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&content_len.to_le_bytes());
        buf.extend_from_slice(&content_len.to_le_bytes());
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // extra field length
        buf.extend_from_slice(path);
        buf.extend_from_slice(data);

        let central_dir_offset = buf.len() as u32;

        // Central directory file header
        buf.extend_from_slice(b"PK\x01\x02");
        buf.extend_from_slice(&0x031eu16.to_le_bytes()); // version made by: Unix
        buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
        buf.extend_from_slice(&0u16.to_le_bytes()); // flags
        buf.extend_from_slice(&0u16.to_le_bytes()); // compression
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&content_len.to_le_bytes());
        buf.extend_from_slice(&content_len.to_le_bytes());
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // extra field len
        buf.extend_from_slice(&0u16.to_le_bytes()); // file comment len
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        buf.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        buf.extend_from_slice(&(0o100_644u32 << 16).to_le_bytes()); // external attrs
        buf.extend_from_slice(&local_offset.to_le_bytes());
        buf.extend_from_slice(path);

        let central_dir_size = (buf.len() as u32) - central_dir_offset;

        // End of central directory
        buf.extend_from_slice(b"PK\x05\x06");
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk number
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk with central dir
        buf.extend_from_slice(&1u16.to_le_bytes()); // entries on this disk
        buf.extend_from_slice(&1u16.to_le_bytes()); // total entries
        buf.extend_from_slice(&central_dir_size.to_le_bytes());
        buf.extend_from_slice(&central_dir_offset.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // comment length
        buf
    }

    // CRC-32 (IEEE 802.3) used to produce valid ZIP checksums in helpers above.
    fn crc32_ieee(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &byte in data {
            let mut val = crc ^ u32::from(byte);
            for _ in 0..8 {
                let mask = (val & 1).wrapping_neg();
                val = (val >> 1) ^ (0xEDB8_8320 & mask);
            }
            crc = val;
        }
        !crc
    }
}
