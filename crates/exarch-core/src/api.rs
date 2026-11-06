//! High-level public API for archive extraction, creation, and inspection.

use std::path::Path;

use crate::ArchiveError;
use crate::ArchiveReader;
use crate::CreateRequest;
use crate::EntrySink;
use crate::ExtractRequest;
use crate::ExtractionReport;
use crate::OutputFile;
use crate::OutputFormat;
use crate::ProgressCallback;
use crate::Result;
use crate::SecurityConfig;
use crate::config::ExtractionOptions;
use crate::creation::CreationConfig;
use crate::creation::CreationReport;
use crate::formats::SevenZArchive;
use crate::formats::ZipArchive;
use crate::formats::common::open_archive;
use crate::formats::compression::CompressionCodec;
use crate::formats::compression::DecoderLimits;
use crate::formats::detect::CreatableFormat;
use crate::formats::detect::FormatFamily;
use crate::formats::detect::detect_format;
use crate::formats::detect::detect_format_from_extension;
use crate::formats::detect::is_zip_family_alias;
use crate::formats::source_fault::TapSource;
use crate::inspection::ArchiveManifest;
use crate::inspection::VerificationReport;
use crate::inspection::integrity::TarTrailer;
use crate::reader::SeekableFormat;
use crate::reader::Source;
use crate::reader::tar_archive;
use crate::sink::SinkOptions;
use crate::sink::SinkReuse;
use crate::sink::SinkTarget;

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
    ExtractRequest::new(config).extract(archive_path, output_dir)
}

/// Extracts `archive_path` under a config that is already validated.
pub(crate) fn extract_validated<P: AsRef<Path>, Q: AsRef<Path>>(
    archive_path: P,
    output_dir: Q,
    config: &SecurityConfig,
    options: &ExtractionOptions,
    progress: &mut dyn ProgressCallback,
) -> Result<ExtractionReport> {
    let archive_path = archive_path.as_ref();
    let output_dir = output_dir.as_ref();

    // Detect archive format from file extension
    let format = detect_format(archive_path)?;

    // Dispatch to format-specific extraction
    match format.family() {
        FormatFamily::Tar(codec) => {
            extract_tar(archive_path, output_dir, config, options, progress, codec)
        }
        FormatFamily::Seekable(SeekableFormat::Zip) => {
            extract_zip(archive_path, output_dir, config, options, progress)
        }
        FormatFamily::Seekable(SeekableFormat::SevenZ) => {
            extract_7z(archive_path, output_dir, config, options, progress)
        }
    }
}

/// Opens `archive_path` as a TAR stream (decoded with `codec` when present)
/// and extracts it.
fn extract_tar(
    archive_path: &Path,
    output_dir: &Path,
    config: &SecurityConfig,
    options: &ExtractionOptions,
    progress: &mut dyn ProgressCallback,
    codec: Option<CompressionCodec>,
) -> Result<ExtractionReport> {
    use crate::formats::tar::open_tar_stream;

    let decoded = open_tar_stream(archive_path, codec, DecoderLimits::of(config))?;
    let trailer = TarTrailer::for_codec(codec);
    let source = decoded.source();
    extract_tar_stream(
        decoded.stream,
        source,
        trailer,
        output_dir,
        config,
        options,
        progress,
    )
}

/// Extracts a TAR stream that is already decoded; `source` meters its raw
/// input and `trailer` says how the bytes after the end-of-archive marker are
/// checked.
pub(crate) fn extract_tar_stream<R: std::io::Read>(
    stream: R,
    source: TapSource,
    trailer: TarTrailer,
    output_dir: &Path,
    config: &SecurityConfig,
    options: &ExtractionOptions,
    progress: &mut dyn ProgressCallback,
) -> Result<ExtractionReport> {
    use crate::formats::TarArchive;
    use crate::formats::traits::ArchiveFormat;

    TarArchive::with_source(stream, source, trailer, config).extract(output_dir, options, progress)
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
    let file = open_archive(archive_path)?;
    let archive = ZipArchive::for_extraction(file, config, options.decode_reuse)?;
    archive.extract(output_dir, options, progress)
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
    let file = open_archive(archive_path)?;
    let archive = SevenZArchive::new(file, config)?;
    archive.extract(output_dir, options, progress)
}

/// Creates an archive from source files and directories.
///
/// The format is detected from the output file extension; use
/// [`CreateRequest`] with an [`OutputFile`] to state it. An existing output
/// is replaced atomically once the archive is complete, and a failed creation
/// leaves the output as it was.
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
    CreateRequest::new(config).create(&OutputFile::replace(output_path.as_ref()), sources)
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
/// - Quota limits exceeded (file count, total size, single file size)
/// - Declared compressed sizes exceed the archive length
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
/// println!("Archive contains {} files", manifest.total_entries());
/// for entry in manifest.entries() {
///     println!("{}: {} bytes", entry.path.display(), entry.size());
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

/// Verifies archive security without extracting.
///
/// Performs metadata-only validation:
/// - Security checks (path traversal, zip bombs, CVEs)
/// - Policy checks (file types, permissions)
///
/// Payload integrity (checksums, decode-to-end) is not verified: the report's
/// `integrity_status` is
/// [`IntegrityStatus::Skipped`](crate::IntegrityStatus::Skipped);
/// use [`VerifyRequest`](crate::VerifyRequest) with `VerificationOptions` to
/// request it.
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
/// - Declared compressed sizes exceed the archive length
/// - An entry name is a path traversal (`..` component, or an absolute path
///   unless `allowed.absolute_paths` is set): the listing step rejects it with
///   [`ArchiveError::PathTraversal`] before a report exists
///
/// Other security violations are reported in `VerificationReport::issues`
/// instead: disallowed links, link targets that escape the destination,
/// quota and compression-ratio violations, NUL bytes, banned components and
/// unsafe permissions.
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
/// if report.status() == VerificationStatus::Pass {
///     println!("Archive is safe to extract");
/// } else {
///     eprintln!("Security issues found:");
///     for issue in report.issues() {
///         eprintln!("  [{}] {}", issue.severity(), issue.message());
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

/// [`extract_to_sink_with_progress`], with a ZIP archive's census output kept
/// within `reuse` when the sink is one that shares its memory limit.
pub(crate) fn extract_to_sink_reusing<S: EntrySink>(
    reader: ArchiveReader<'_>,
    sink: &mut S,
    config: &SecurityConfig,
    options: SinkOptions,
    progress: &mut dyn ProgressCallback,
    reuse: Option<SinkReuse>,
) -> Result<ExtractionReport> {
    match reader.into_source() {
        Source::Tar { stream, codec } => {
            let archive = tar_archive(stream, codec, config)?;
            let mut target = SinkTarget::new(sink, config);
            archive.extract_into(&mut target, config, options, progress)
        }
        Source::Seekable {
            reader,
            format: SeekableFormat::Zip,
        } => {
            let mut archive = match reuse {
                Some(reuse) => ZipArchive::for_sink(reader, config, &reuse)?,
                None => ZipArchive::for_extraction(reader, config, options.decode_reuse)?,
            };
            archive.check_structure(config)?.extract_with(
                |config| Ok(SinkTarget::new(sink, config)),
                options,
                progress,
            )
        }
        Source::Seekable {
            reader,
            format: SeekableFormat::SevenZ,
        } => {
            let mut archive = SevenZArchive::new(reader, config)?;
            archive.admit(config)?.extract_with(
                |config| Ok(SinkTarget::new(sink, config)),
                options,
                progress,
            )
        }
    }
}

/// Rejects creation for ZIP-family extensions that aren't plain `.zip`.
///
/// They're all ZIP underneath but add extra requirements - signing
/// (apk/aab/ipa/appx/msix), checksum manifests (whl), ordering and
/// stored-compression rules (epub), descriptor files (war/ear/vsix/nbm) - which
/// exarch doesn't produce. Silently emitting a bare ZIP with one of these
/// extensions would be misleading, so creation errors instead; a caller who
/// needs it states [`CreatableFormat::Zip`] on the [`OutputFile`].
///
/// Returns `Ok(())` for anything else - `.zip`, tar variants, unknown
/// extensions (those get caught later by `detect_format`).
fn reject_zip_family_creation(output: &Path) -> Result<()> {
    let Some(ext) = output.extension().and_then(|e| e.to_str()) else {
        return Ok(());
    };
    if is_zip_family_alias(ext) {
        let ext_lower = ext.to_ascii_lowercase();
        return Err(ArchiveError::unclassified(format!(
            "creation for .{ext_lower} isn't supported: the format is ZIP-based but \
             requires extra structure (signing, manifests, ordering) that exarch \
             doesn't produce. Use .zip, or state the format with \
             OutputFile::with_format(exarch_core::CreatableFormat::Zip) \
             to override."
        )));
    }
    Ok(())
}

/// Determines the archive format of `output`.
///
/// Extension-only detection; magic-byte detection is intentionally excluded so
/// that a pre-existing output file with stale bytes cannot override the
/// caller's intended format.
pub(crate) fn resolve_output_format(output: &OutputFile) -> Result<CreatableFormat> {
    match output.format() {
        OutputFormat::Explicit(format) => Ok(format),
        OutputFormat::FromExtension => {
            reject_zip_family_creation(output.path())?;
            CreatableFormat::try_from(detect_format_from_extension(output.path())?)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::NoopProgress;
    use crate::raw_zip::RawEntry;
    use crate::raw_zip::RawZip;
    use std::assert_matches;
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
        let path = PathBuf::from("archive.tar");
        let format = resolve_output_format(&OutputFile::replace(&path)).unwrap();
        assert_eq!(format, CreatableFormat::Tar);
    }

    #[test]
    fn test_determine_creation_format_tar_gz() {
        let path = PathBuf::from("archive.tar.gz");
        let format = resolve_output_format(&OutputFile::replace(&path)).unwrap();
        assert_eq!(format, CreatableFormat::TarGz);

        let path2 = PathBuf::from("archive.tgz");
        let format2 = resolve_output_format(&OutputFile::replace(&path2)).unwrap();
        assert_eq!(format2, CreatableFormat::TarGz);
    }

    #[test]
    fn test_determine_creation_format_tar_bz2() {
        let path = PathBuf::from("archive.tar.bz2");
        let format = resolve_output_format(&OutputFile::replace(&path)).unwrap();
        assert_eq!(format, CreatableFormat::TarBz2);
    }

    #[test]
    fn test_determine_creation_format_tar_xz() {
        let path = PathBuf::from("archive.tar.xz");
        let format = resolve_output_format(&OutputFile::replace(&path)).unwrap();
        assert_eq!(format, CreatableFormat::TarXz);
    }

    #[test]
    fn test_determine_creation_format_tar_zst() {
        let path = PathBuf::from("archive.tar.zst");
        let format = resolve_output_format(&OutputFile::replace(&path)).unwrap();
        assert_eq!(format, CreatableFormat::TarZst);
    }

    #[test]
    fn test_determine_creation_format_zip() {
        let path = PathBuf::from("archive.zip");
        let format = resolve_output_format(&OutputFile::replace(&path)).unwrap();
        assert_eq!(format, CreatableFormat::Zip);
    }

    #[test]
    fn test_determine_creation_format_explicit() {
        let path = PathBuf::from("archive.xyz");
        let output = OutputFile::replace(&path).with_format(CreatableFormat::TarGz);
        let format = resolve_output_format(&output).unwrap();
        assert_eq!(format, CreatableFormat::TarGz);
    }

    #[test]
    fn test_determine_creation_format_unknown() {
        let path = PathBuf::from("archive.rar");
        let result = resolve_output_format(&OutputFile::replace(&path));
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

        let format = resolve_output_format(&OutputFile::replace(&path)).unwrap();
        assert_eq!(
            format,
            CreatableFormat::Zip,
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
    fn test_create_archive_zip_family_not_supported() {
        // Mirrors test_create_archive_7z_not_supported. Spot-checks a couple
        // of extensions rather than every one - the integration test
        // covers the full list.
        let dest = tempfile::TempDir::new().unwrap();
        for ext in ["apk", "whl", "EPUB"] {
            let archive_path = dest.path().join(format!("output.{ext}"));
            let result = create_archive(&archive_path, &[] as &[&str], &CreationConfig::default());
            assert_matches!(
                result,
                Err(ArchiveError::InvalidArchive(_)),
                ".{ext} should be rejected, got {result:?}",
            );
        }
    }

    #[test]
    fn test_create_archive_zip_family_override_bypasses_guard() {
        // An explicit OutputFile format is the escape hatch -
        // skips the ZIP-family guard. Caller takes responsibility for the
        // resulting file not being spec-valid.
        let dest = tempfile::TempDir::new().unwrap();
        let src = dest.path().join("source.txt");
        std::fs::write(&src, b"hello").unwrap();
        let archive_path = dest.path().join("output.apk");
        let result = CreateRequest::new(&CreationConfig::default()).create(
            &OutputFile::replace(&archive_path).with_format(CreatableFormat::Zip),
            &[&src],
        );
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
        assert_matches!(
            result.unwrap_err(),
            ArchiveError::InvalidConfiguration { .. }
        );
    }

    #[test]
    fn test_extract_archive_with_options_and_progress_non_atomic_delegates_to_normal() {
        let dest = tempfile::TempDir::new().unwrap();
        let options = ExtractionOptions {
            staging: crate::Staging::InPlace,
            existing_files: crate::ExistingFiles::Skip,
            ..ExtractionOptions::default()
        };
        let result = ExtractRequest::new(&SecurityConfig::default())
            .with_options(options)
            .with_progress(&mut NoopProgress)
            .extract(PathBuf::from("nonexistent.tar.gz"), dest.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_archive_with_options_delegates() {
        let dest = tempfile::TempDir::new().unwrap();
        let options = ExtractionOptions {
            staging: crate::Staging::InPlace,
            existing_files: crate::ExistingFiles::Skip,
            ..ExtractionOptions::default()
        };
        let result = ExtractRequest::new(&SecurityConfig::default())
            .with_options(options)
            .extract(PathBuf::from("nonexistent.tar.gz"), dest.path());
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
            staging: crate::Staging::Atomic,
            existing_files: crate::ExistingFiles::Skip,
            ..ExtractionOptions::default()
        };
        let result = ExtractRequest::new(&SecurityConfig::default())
            .with_options(options)
            .extract(&archive_path, &output_dir);

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
            staging: crate::Staging::Atomic,
            existing_files: crate::ExistingFiles::Skip,
            ..ExtractionOptions::default()
        };
        let result = ExtractRequest::new(&SecurityConfig::default())
            .with_options(options)
            .extract(PathBuf::from("nonexistent_archive.tar.gz"), &output_dir);

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
        // Create a file in output_dir so it's non-empty (rename over non-empty
        // dir fails on most OSes)
        std::fs::write(output_dir.join("existing.txt"), b"old content").unwrap();

        let archive_dir = tempfile::TempDir::new().unwrap();
        let archive_path = archive_dir.path().join("test.tar.gz");
        let src_dir = tempfile::TempDir::new().unwrap();
        std::fs::write(src_dir.path().join("new.txt"), b"new content").unwrap();
        create_archive(&archive_path, &[src_dir.path()], &CreationConfig::default()).unwrap();

        let options = ExtractionOptions {
            staging: crate::Staging::Atomic,
            existing_files: crate::ExistingFiles::Skip,
            ..ExtractionOptions::default()
        };
        let result = ExtractRequest::new(&SecurityConfig::default())
            .with_options(options)
            .extract(&archive_path, &output_dir);

        // Should fail with OutputExists or Io (platform dependent rename
        // semantics)
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
            fn on_entry_start(&mut self, _path: &Path, _position: crate::EntryPosition) {
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

        let report = ExtractRequest::new(&SecurityConfig::default())
            .with_progress(&mut progress)
            .extract(&archive_path, dest.path())
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
            fn on_entry_start(&mut self, _path: &Path, _position: crate::EntryPosition) {
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
        create_archive(&archive_path, &[src_dir.path()], &CreationConfig::default()).unwrap();

        let dest = tempfile::TempDir::new().unwrap();
        let mut progress = TrackingProgress {
            started: 0,
            completed: 0,
            finished: false,
        };
        let report = ExtractRequest::new(&SecurityConfig::default())
            .with_progress(&mut progress)
            .extract(&archive_path, dest.path())
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
            fn on_entry_start(&mut self, _path: &Path, _position: crate::EntryPosition) {
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
        let report = ExtractRequest::new(&SecurityConfig::default())
            .with_progress(&mut progress)
            .extract(&fixture, dest.path())
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
            fn on_entry_start(&mut self, _path: &Path, _position: crate::EntryPosition) {}

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
        let report = ExtractRequest::new(&SecurityConfig::default())
            .with_progress(&mut progress)
            .extract(&archive_path, dest.path())
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
            fn on_entry_start(&mut self, _path: &Path, _position: crate::EntryPosition) {}

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
        create_archive(&archive_path, &[src_dir.path()], &CreationConfig::default()).unwrap();

        let dest = tempfile::TempDir::new().unwrap();
        let mut progress = ByteTracker { total: 0 };
        let report = ExtractRequest::new(&SecurityConfig::default())
            .with_progress(&mut progress)
            .extract(&archive_path, dest.path())
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
            fn on_entry_start(&mut self, _path: &Path, _position: crate::EntryPosition) {}

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
        let report = ExtractRequest::new(&SecurityConfig::default())
            .with_progress(&mut progress)
            .extract(&fixture, dest.path())
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
            fn on_entry_start(&mut self, _path: &Path, _position: crate::EntryPosition) {}

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
        config.allowed.hardlinks = crate::Admit::Allow;

        let archive = TarArchive::new(Cursor::new(tar_data), &config);
        let mut progress = ByteTracker { total: 0 };
        let report = archive
            .extract(temp.path(), &ExtractionOptions::default(), &mut progress)
            .unwrap();

        // The hardlink copies the file content — bytes should be reported
        // twice.
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
            fn on_entry_start(&mut self, _path: &Path, _position: crate::EntryPosition) {
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
        let archive = TarArchive::new(Cursor::new(tar_data), &SecurityConfig::default());
        let mut progress = SymmetryTracker {
            started: 0,
            completed: 0,
        };
        let result = archive.extract(temp.path(), &ExtractionOptions::default(), &mut progress);

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
            fn on_entry_start(&mut self, _path: &Path, _position: crate::EntryPosition) {
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
        let archive = ZipArchive::new(Cursor::new(zip_data), &SecurityConfig::default()).unwrap();
        let mut progress = SymmetryTracker {
            started: 0,
            completed: 0,
        };
        let result = archive.extract(temp.path(), &ExtractionOptions::default(), &mut progress);

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

    // Builds a single-entry ZIP whose name is written verbatim, so a traversal
    // path survives into the headers.
    fn make_zip_with_traversal(path: &[u8], data: &[u8]) -> Vec<u8> {
        let entry = RawEntry {
            name: path.to_vec(),
            date: 0,
            ..RawEntry::stored("", data)
        };
        RawZip::new(vec![entry]).build().bytes
    }
}
