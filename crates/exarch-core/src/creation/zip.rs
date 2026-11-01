//! ZIP archive creation.
//!
//! This module provides functions for creating ZIP archives with configurable
//! compression levels and security options.

use crate::ArchiveError;
use crate::CompressionRatio;
use crate::IoContext;
use crate::NoopProgress;
use crate::ProgressCallback;
use crate::Result;
use crate::SecurityConfig;
use crate::ZipBombDetails;
use crate::ZipBombScope;
use crate::config::Validated;
use crate::creation::config::CreationConfig;
use crate::creation::progress::ProgressTracker;
use crate::creation::report::CreationReport;
use crate::creation::walker::EntryType;
use crate::creation::walker::collect_entries;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::path::Path;
use zip::CompressionMethod;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

/// Creates a ZIP archive.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::creation::CreationConfig;
/// use exarch_core::creation::zip::create_zip;
/// use std::path::Path;
///
/// let config = CreationConfig::default().validate()?;
/// let report = create_zip(Path::new("output.zip"), &[Path::new("src")], &config)?;
/// println!("Added {} files", report.files_added);
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Source path does not exist
/// - Output file cannot be created
/// - I/O error during archive creation
pub fn create_zip<P: AsRef<Path>, Q: AsRef<Path>>(
    output: P,
    sources: &[Q],
    config: &CreationConfig<Validated>,
) -> Result<CreationReport> {
    create_zip_with_progress(output, sources, config, &mut NoopProgress)
}

/// Creates a ZIP archive with progress reporting.
///
/// This function provides real-time progress updates during archive creation
/// through callback functions. Useful for displaying progress bars or logging
/// in interactive applications.
///
/// # Parameters
///
/// - `output`: Path where the ZIP archive will be created
/// - `sources`: Slice of source paths to include in the archive
/// - `config`: Configuration controlling filtering, permissions, compression,
///   and archiving behavior
/// - `progress`: Mutable reference to a progress callback implementation
///
/// # Progress Callbacks
///
/// The `progress` callback receives four types of events:
///
/// 1. `on_entry_start`: Called before processing each file/directory
/// 2. `on_bytes_written`: Called for each chunk of data written (typically
///    every 64 KB)
/// 3. `on_entry_complete`: Called after successfully processing an entry
/// 4. `on_complete`: Called once when the entire archive is finished
///
/// Note: Callbacks are invoked frequently during large file processing. For
/// better performance with very large files, consider batching updates.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::ProgressCallback;
/// use exarch_core::creation::CreationConfig;
/// use exarch_core::creation::zip::create_zip_with_progress;
/// use std::path::Path;
///
/// struct SimpleProgress;
///
/// impl ProgressCallback for SimpleProgress {
///     fn on_entry_start(&mut self, path: &Path, total: usize, current: usize) {
///         println!("[{}/{}] Processing: {}", current, total, path.display());
///     }
///
///     fn on_bytes_written(&mut self, bytes: u64) {
///         // Called frequently - consider rate limiting
///     }
///
///     fn on_entry_complete(&mut self, path: &Path) {
///         println!("Completed: {}", path.display());
///     }
///
///     fn on_complete(&mut self) {
///         println!("Archive creation complete!");
///     }
/// }
///
/// let config = CreationConfig::default().validate()?;
/// let mut progress = SimpleProgress;
/// let report = create_zip_with_progress(
///     Path::new("output.zip"),
///     &[Path::new("src")],
///     &config,
///     &mut progress,
/// )?;
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Source path does not exist
/// - Output file cannot be created
/// - I/O error during archive creation
/// - File metadata cannot be read
pub fn create_zip_with_progress<P: AsRef<Path>, Q: AsRef<Path>>(
    output: P,
    sources: &[Q],
    config: &CreationConfig<Validated>,
    progress: &mut dyn ProgressCallback,
) -> Result<CreationReport> {
    let (file, readable) = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(output.as_ref())
    {
        Ok(file) => (file, true),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            (File::create(output.as_ref())?, false)
        }
        Err(e) => return Err(e.into()),
    };
    let (mut report, mut file) = write_zip(file, sources, config, progress)?;
    if readable {
        warn_on_extraction_ratio(&mut file, &mut report);
    }
    Ok(report)
}

/// Internal function that creates ZIP with any writer and progress reporting.
///
/// `out` must be positioned at offset 0: ZIP records absolute offsets, so an
/// archive appended to existing bytes would be corrupt. `bytes_compressed` is
/// the writer position after the archive is finished. The finished writer is
/// returned so a caller that can read it back may run
/// [`warn_on_extraction_ratio`].
pub(crate) fn write_zip<W: Write + Seek, P: AsRef<Path>>(
    mut out: W,
    sources: &[P],
    config: &CreationConfig<Validated>,
    progress: &mut dyn ProgressCallback,
) -> Result<(CreationReport, W)> {
    if out.stream_position()? != 0 {
        return Err(ArchiveError::InvalidConfiguration {
            reason: "ZIP output writer must be positioned at offset 0".into(),
        });
    }
    let mut zip = ZipWriter::new(out);
    let mut report = CreationReport::default();
    let start = std::time::Instant::now();

    // Configure ZIP file options with compression level. `compression_level`
    // is guaranteed to be `None` or `Some(1..=9)` by
    // `CreationConfig::validate`, so `Stored` (level 0) is unreachable
    // through the public API.
    let level = config.compression_level.unwrap_or(6);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .compression_level(Some(i64::from(level)));

    // Single-pass collection of entries (avoids double directory traversal)
    let entries = collect_entries(sources, config)?;
    let total_entries = entries.len();

    let mut tracker = ProgressTracker::new(progress, total_entries);

    let mut buffer = vec![0u8; 64 * 1024];

    for entry in &entries {
        match &entry.entry_type {
            EntryType::File => {
                tracker.on_entry_start(&entry.archive_path);
                add_file_to_zip_with_progress_and_buffer(
                    &mut zip,
                    &entry.path,
                    &entry.archive_path,
                    config,
                    &mut report,
                    &options,
                    tracker.callback(),
                    &mut buffer,
                )?;
                tracker.on_entry_complete(&entry.archive_path);
            }
            EntryType::Directory => {
                tracker.on_entry_start(&entry.archive_path);
                // Skip root directory entry (empty path becomes "/" which is
                // invalid)
                if !entry.archive_path.is_empty() {
                    let dir_path = format!("{}/", normalize_zip_path(&entry.archive_path)?);
                    zip.add_directory(&dir_path, options).map_err(|e| {
                        std::io::Error::other(IoContext::new(
                            "failed to add directory to zip archive",
                            e.to_string(),
                        ))
                    })?;
                    report.directories_added += 1;
                }
                tracker.on_entry_complete(&entry.archive_path);
            }
            EntryType::Symlink { .. } => {
                tracker.on_entry_start(&entry.archive_path);
                if config.follow_symlinks {
                    add_file_to_zip_with_progress_and_buffer(
                        &mut zip,
                        &entry.path,
                        &entry.archive_path,
                        config,
                        &mut report,
                        &options,
                        tracker.callback(),
                        &mut buffer,
                    )?;
                } else {
                    report.files_skipped = report.files_skipped.saturating_add(1);
                    report.add_warning(format!("Skipped symlink: {}", entry.path.display()));
                }
                tracker.on_entry_complete(&entry.archive_path);
            }
        }
    }

    // Finish writing ZIP
    let mut writer = zip.finish().map_err(|e| {
        std::io::Error::other(IoContext::new(
            "failed to finish zip archive",
            e.to_string(),
        ))
    })?;

    writer.flush()?;
    report.bytes_compressed = writer.stream_position()?;
    report.duration = start.elapsed();

    tracker.on_complete();

    Ok((report, writer))
}

/// Adds a warning to `report` when default extraction would refuse an entry of
/// the finished archive in `archive` as a zip bomb.
///
/// The ratio check applies to every ZIP entry, so highly compressible content
/// (logs, zero-filled data) written here round-trips only after the extraction
/// limit is raised; TAR archives of the same content are not affected. The
/// warning gives the number of affected entries and the smallest limit that
/// admits all of them. Writers that cannot be read back are not scanned.
///
/// The scan is a diagnostic on an archive that is already complete, so a
/// failure to read it back becomes a warning instead of an error.
pub(crate) fn warn_on_extraction_ratio<R: Read + Seek>(archive: R, report: &mut CreationReport) {
    match extraction_ratio_warning(archive) {
        Ok(Some(warning)) => report.add_warning(warning),
        Ok(None) => {}
        Err(e) => report.add_warning(format!(
            "could not check the ZIP entries against the default extraction ratio limit: {e}"
        )),
    }
}

fn extraction_ratio_warning<R: Read + Seek>(
    archive: R,
) -> std::result::Result<Option<String>, zip::result::ZipError> {
    let limit = SecurityConfig::default().max_compression_ratio;
    let mut zip = zip::ZipArchive::new(archive)?;

    let mut over_limit = 0usize;
    let mut highest = 0.0_f64;
    for index in 0..zip.len() {
        let entry = zip.by_index_raw(index)?;
        let details =
            ZipBombDetails::new(ZipBombScope::Entry, entry.compressed_size(), entry.size());
        if let CompressionRatio::Finite(ratio) = details.ratio()
            && ratio > limit
        {
            over_limit += 1;
            highest = highest.max(ratio);
        }
    }

    if over_limit == 0 {
        return Ok(None);
    }
    let noun = if over_limit == 1 { "entry" } else { "entries" };
    Ok(Some(format!(
        "ZIP archive has {over_limit} {noun} over the default extraction ratio limit of \
         {limit}x; default extraction refuses it as a zip bomb unless the maximum compression \
         ratio is at least {needed}",
        needed = highest.ceil(),
    )))
}

/// Adds a single file to the ZIP archive with progress reporting and reusable
/// buffer.
#[expect(
    clippy::too_many_arguments,
    reason = "arguments are threaded through from the caller; a parameter struct adds indirection"
)]
fn add_file_to_zip_with_progress_and_buffer<W: Write + Seek>(
    zip: &mut ZipWriter<W>,
    file_path: &Path,
    archive_path: &Path,
    config: &CreationConfig<Validated>,
    report: &mut CreationReport,
    options: &SimpleFileOptions,
    progress: &mut dyn ProgressCallback,
    buffer: &mut [u8],
) -> Result<()> {
    let mut file = File::open(file_path)?;
    let metadata = file.metadata()?;
    let size = metadata.len();

    // Check file size limit
    if let Some(max_size) = config.max_file_size
        && size > max_size
    {
        report.files_skipped = report.files_skipped.saturating_add(1);
        report.add_warning(format!(
            "Skipped file (too large): {} ({} bytes)",
            file_path.display(),
            size
        ));
        return Ok(());
    }

    // Configure options with permissions if needed
    let file_options = if config.preserve_permissions {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            options.unix_permissions(metadata.permissions().mode())
        }
        #[cfg(not(unix))]
        {
            *options
        }
    } else {
        *options
    };

    let archive_name = normalize_zip_path(archive_path)?;

    zip.start_file(&archive_name, file_options).map_err(|e| {
        std::io::Error::other(IoContext::new(
            "failed to start file in zip archive",
            e.to_string(),
        ))
    })?;

    // Copy file contents with progress tracking and reusable buffer
    let mut bytes_written = 0u64;
    loop {
        let bytes_read = file.read(buffer)?;
        if bytes_read == 0 {
            break;
        }
        zip.write_all(&buffer[..bytes_read])?;
        bytes_written += bytes_read as u64;
        progress.on_bytes_written(bytes_read as u64);
    }

    report.files_added += 1;
    report.bytes_written += bytes_written;

    Ok(())
}

/// Normalizes a path for ZIP archive format.
///
/// ZIP format requires forward slashes (/) as path separators, regardless
/// of platform. This function converts platform-specific paths to ZIP format.
fn normalize_zip_path(path: &Path) -> Result<String> {
    // Convert to string
    let path_str = path.to_str().ok_or_else(|| {
        ArchiveError::Io(std::io::Error::other(IoContext::new(
            "archive path is not valid UTF-8",
            path.display().to_string(),
        )))
    })?;

    // Replace backslashes with forward slashes (Windows)
    #[cfg(windows)]
    let normalized = path_str.replace('\\', "/");

    #[cfg(not(windows))]
    let normalized = path_str.to_string();

    Ok(normalized)
}

/// Format creator for ZIP archives.
pub struct ZipCreator;

impl crate::formats::traits::FormatCreator for ZipCreator {
    fn create(
        &self,
        output: &std::path::Path,
        sources: &[&std::path::Path],
        config: &CreationConfig<Validated>,
        progress: &mut dyn ProgressCallback,
    ) -> crate::Result<crate::creation::CreationReport> {
        create_zip_with_progress(output, sources, config, progress)
    }

    fn format_name(&self) -> &'static str {
        "zip"
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Allow unwrap in tests for brevity
mod tests {
    use super::*;
    use std::assert_matches;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_create_zip_single_file() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.zip");

        // Create source file
        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("test.txt"), "Hello ZIP").unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_include_hidden(true)
            .validate()
            .unwrap();

        let report = create_zip(&output, &[source_dir.path().join("test.txt")], &config).unwrap();

        assert_eq!(report.files_added, 1);
        assert!(report.bytes_written > 0);
        assert!(output.exists());
    }

    fn zip_report_for(content: &[u8]) -> CreationReport {
        let temp = TempDir::new().unwrap();
        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("data"), content).unwrap();
        let config = CreationConfig::default().validate().unwrap();
        create_zip(
            temp.path().join("out.zip"),
            &[source_dir.path().join("data")],
            &config,
        )
        .unwrap()
    }

    fn needed_ratio(warning: &str) -> f64 {
        warning.rsplit(' ').next().unwrap().parse().unwrap()
    }

    #[test]
    fn test_create_zip_warns_when_default_extraction_would_refuse_an_entry() {
        let report = zip_report_for(&[b'B'; 5000]);

        assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
        let warning = &report.warnings[0];
        assert!(warning.starts_with(
            "ZIP archive has 1 entry over the default extraction ratio limit of 100x"
        ));
        assert!(needed_ratio(warning) > 100.0);
    }

    #[test]
    fn test_create_zip_needed_ratio_admits_the_archive() {
        let temp = TempDir::new().unwrap();
        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("data"), [b'B'; 5000]).unwrap();
        let output = temp.path().join("out.zip");
        let config = CreationConfig::default().validate().unwrap();
        let report = create_zip(&output, &[source_dir.path().join("data")], &config).unwrap();
        let needed = needed_ratio(&report.warnings[0]);

        let dest = temp.path().join("dest");
        let admitting = crate::SecurityConfig::default().with_max_compression_ratio(needed);
        crate::api::extract_archive(&output, &dest, &admitting).unwrap();
        assert!(dest.join("data").exists());
    }

    #[test]
    fn test_ratio_scan_failure_degrades_to_a_warning() {
        let mut report = CreationReport::default();

        warn_on_extraction_ratio(std::io::Cursor::new(b"not a zip".to_vec()), &mut report);

        assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
        assert!(report.warnings[0].starts_with("could not check the ZIP entries"));
    }

    #[test]
    fn test_create_zip_no_ratio_warning_for_ordinary_content() {
        let report = zip_report_for(b"Hello ZIP");

        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    }

    #[test]
    fn test_create_zip_directory() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.zip");

        // Create source directory with multiple files
        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("file1.txt"), "content1").unwrap();
        fs::write(source_dir.path().join("file2.txt"), "content2").unwrap();
        fs::create_dir(source_dir.path().join("subdir")).unwrap();
        fs::write(source_dir.path().join("subdir/file3.txt"), "content3").unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_include_hidden(true)
            .validate()
            .unwrap();

        let report = create_zip(&output, &[source_dir.path()], &config).unwrap();

        // Should have exactly 3 files: file1.txt, file2.txt, subdir/file3.txt
        assert_eq!(report.files_added, 3);
        // Should have exactly 1 directory: subdir (root is omitted — empty
        // archive path is invalid in ZIP)
        assert_eq!(report.directories_added, 1);
        assert!(output.exists());
    }

    #[test]
    fn test_create_zip_compression() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.zip");

        // Create source file with repetitive content (compresses well)
        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("test.txt"), "a".repeat(1000)).unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_compression_level(9)
            .unwrap()
            .validate()
            .unwrap();

        let report = create_zip(&output, &[source_dir.path()], &config).unwrap();

        assert_eq!(report.files_added, 1);
        assert!(output.exists());

        // Verify it's a valid ZIP file (basic check)
        let data = fs::read(&output).unwrap();
        assert_eq!(&data[0..4], b"PK\x03\x04"); // ZIP local file header magic
    }

    #[test]
    fn test_create_zip_compression_levels() {
        let temp = TempDir::new().unwrap();

        // Create source with repetitive data (compresses well)
        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("test.txt"), "a".repeat(10000)).unwrap();

        // Test different compression levels (1-9 are valid)
        for level in [1, 6, 9] {
            let output = temp.path().join(format!("output_{level}.zip"));
            let config = CreationConfig::default()
                .with_exclude_patterns(vec![])
                .with_compression_level(level)
                .unwrap()
                .validate()
                .unwrap();

            let report = create_zip(&output, &[source_dir.path()], &config).unwrap();
            assert_eq!(report.files_added, 1);
            assert!(output.exists());
        }
    }

    #[test]
    fn test_create_zip_explicit_directories() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.zip");

        // Create source directory structure
        let source_dir = TempDir::new().unwrap();
        fs::create_dir(source_dir.path().join("dir1")).unwrap();
        fs::create_dir(source_dir.path().join("dir1/dir2")).unwrap();
        fs::write(source_dir.path().join("dir1/dir2/file.txt"), "content").unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_include_hidden(true)
            .validate()
            .unwrap();

        let report = create_zip(&output, &[source_dir.path()], &config).unwrap();

        assert!(report.directories_added >= 2); // dir1 and dir1/dir2
        assert!(output.exists());

        // Verify directories have trailing slash by reading archive
        let file = File::open(&output).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();

        let mut dir_entries = 0;
        for i in 0..archive.len() {
            let entry = archive.by_index(i).unwrap();
            if entry.is_dir() {
                dir_entries += 1;
                assert!(
                    entry.name().unwrap().ends_with('/'),
                    "Directory entry should end with /"
                );
            }
        }
        assert!(dir_entries >= 2, "Expected at least 2 directory entries");
    }

    #[cfg(unix)]
    #[test]
    fn test_create_zip_preserves_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.zip");

        // Create source file with specific permissions
        let source_dir = TempDir::new().unwrap();
        let file_path = source_dir.path().join("test.txt");
        fs::write(&file_path, "content").unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o755)).unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_preserve_permissions(true)
            .validate()
            .unwrap();

        let report = create_zip(&output, &[source_dir.path()], &config).unwrap();
        assert_eq!(report.files_added, 1);

        // Verify permissions in archive
        let file = File::open(&output).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();

        for i in 0..archive.len() {
            let entry = archive.by_index(i).unwrap();
            if entry.name().unwrap().contains("test.txt")
                && let Some(mode) = entry.unix_mode()
            {
                assert_eq!(mode & 0o777, 0o755, "Permissions should be preserved");
            }
        }
    }

    #[test]
    fn test_create_zip_report_statistics() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.zip");

        // Create source directory with known structure
        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("file1.txt"), "content1").unwrap();
        fs::write(source_dir.path().join("file2.txt"), "content2").unwrap();
        fs::create_dir(source_dir.path().join("subdir")).unwrap();
        fs::write(source_dir.path().join("subdir/file3.txt"), "content3").unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_include_hidden(true)
            .validate()
            .unwrap();

        let report = create_zip(&output, &[source_dir.path()], &config).unwrap();

        assert_eq!(report.files_added, 3);
        assert!(report.directories_added >= 1);
        assert_eq!(report.files_skipped, 0);
        assert!(!report.has_warnings());
        assert!(report.duration.as_nanos() > 0);
    }

    #[test]
    fn test_create_zip_roundtrip() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.zip");

        // Create source directory
        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("file1.txt"), "content1").unwrap();
        fs::create_dir(source_dir.path().join("subdir")).unwrap();
        fs::write(source_dir.path().join("subdir/file2.txt"), "content2").unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_include_hidden(true)
            .validate()
            .unwrap();

        // Create archive
        let report = create_zip(&output, &[source_dir.path()], &config).unwrap();
        assert!(report.files_added >= 2);

        // Extract and verify using zip crate
        let file = File::open(&output).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();

        let extract_dir = TempDir::new().unwrap();

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i).unwrap();
            let outpath = extract_dir.path().join(entry.name().unwrap().as_ref());

            if entry.is_dir() {
                fs::create_dir_all(&outpath).unwrap();
            } else {
                if let Some(parent) = outpath.parent() {
                    fs::create_dir_all(parent).unwrap();
                }
                let mut outfile = File::create(&outpath).unwrap();
                std::io::copy(&mut entry, &mut outfile).unwrap();
            }
        }

        // Verify extracted files match originals
        let extracted1 = fs::read_to_string(extract_dir.path().join("file1.txt")).unwrap();
        assert_eq!(extracted1, "content1");

        let extracted2 = fs::read_to_string(extract_dir.path().join("subdir/file2.txt")).unwrap();
        assert_eq!(extracted2, "content2");
    }

    #[test]
    fn test_create_zip_forward_slashes() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.zip");

        // Create source directory structure
        let source_dir = TempDir::new().unwrap();
        fs::create_dir(source_dir.path().join("dir1")).unwrap();
        fs::write(source_dir.path().join("dir1/file.txt"), "content").unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_include_hidden(true)
            .validate()
            .unwrap();

        create_zip(&output, &[source_dir.path()], &config).unwrap();

        // Verify paths use forward slashes
        let file = File::open(&output).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();

        for i in 0..archive.len() {
            let entry = archive.by_index(i).unwrap();
            let name = entry.name().unwrap();
            // ZIP paths should never contain backslashes
            assert!(
                !name.contains('\\'),
                "ZIP path should use forward slashes: {name}"
            );
            // Subdirectory paths should use forward slash
            if name.contains("dir1") && name.contains("file") {
                assert!(name.contains("dir1/file"), "Expected forward slash in path");
            }
        }
    }

    #[test]
    fn test_create_zip_source_not_found() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.zip");

        let config = CreationConfig::default().validate().unwrap();
        let result = create_zip(&output, &[Path::new("/nonexistent/path")], &config);

        assert!(result.is_err());
        assert_matches!(result.unwrap_err(), ArchiveError::SourceNotFound { .. });
    }

    #[test]
    fn test_normalize_zip_path() {
        // Basic path
        let path = Path::new("dir/file.txt");
        let normalized = normalize_zip_path(path).unwrap();
        assert_eq!(normalized, "dir/file.txt");

        // Single file
        let path = Path::new("file.txt");
        let normalized = normalize_zip_path(path).unwrap();
        assert_eq!(normalized, "file.txt");

        // Nested directories
        let path = Path::new("a/b/c/file.txt");
        let normalized = normalize_zip_path(path).unwrap();
        assert_eq!(normalized, "a/b/c/file.txt");
    }

    #[cfg(windows)]
    #[test]
    fn test_normalize_zip_path_windows() {
        // Windows path with backslashes
        let path = Path::new("dir\\file.txt");
        let normalized = normalize_zip_path(path).unwrap();
        assert_eq!(normalized, "dir/file.txt");

        // Nested with backslashes
        let path = Path::new("a\\b\\c\\file.txt");
        let normalized = normalize_zip_path(path).unwrap();
        assert_eq!(normalized, "a/b/c/file.txt");
    }

    #[test]
    fn test_create_zip_max_file_size() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.zip");

        // Create files with different sizes
        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("small.txt"), "tiny").unwrap(); // 4 bytes
        fs::write(source_dir.path().join("large.txt"), "a".repeat(1000)).unwrap(); // 1000 bytes

        // Set max file size to 100 bytes
        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_max_file_size(Some(100))
            .validate()
            .unwrap();

        let report = create_zip(&output, &[source_dir.path()], &config).unwrap();

        // Walker filters out large.txt, so only small.txt is added
        // No files are skipped at the ZIP level (walker already filtered)
        assert_eq!(report.files_added, 1);
        assert_eq!(report.files_skipped, 0);
    }

    #[cfg(unix)]
    #[test]
    fn test_create_zip_skips_symlinks() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.zip");

        // Create source with symlink
        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("target.txt"), "content").unwrap();
        std::os::unix::fs::symlink(
            source_dir.path().join("target.txt"),
            source_dir.path().join("link.txt"),
        )
        .unwrap();

        // Don't follow symlinks (default)
        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_include_hidden(true)
            .validate()
            .unwrap();

        let report = create_zip(&output, &[source_dir.path()], &config).unwrap();

        // Should add target.txt, skip link.txt
        assert_eq!(report.files_added, 1);
        assert_eq!(report.files_skipped, 1);
        assert!(report.has_warnings());

        let warning = &report.warnings[0];
        assert!(warning.contains("Skipped symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn test_create_zip_follow_symlinks_embeds_target_content() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.zip");

        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("target.txt"), "content").unwrap();
        std::os::unix::fs::symlink(
            source_dir.path().join("target.txt"),
            source_dir.path().join("link.txt"),
        )
        .unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_include_hidden(true)
            .with_follow_symlinks(true)
            .validate()
            .unwrap();

        let report = create_zip(&output, &[source_dir.path()], &config).unwrap();

        // Both target.txt and the followed link.txt must be written as regular
        // entries.
        assert_eq!(report.files_added, 2);
        assert_eq!(report.files_skipped, 0);
        assert!(!report.has_warnings());

        let file = File::open(&output).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        let mut entry = archive.by_name("link.txt").unwrap();
        let mut contents = String::new();
        entry.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "content");
    }

    #[test]
    fn test_create_zip_with_progress_callback() {
        #[derive(Debug, Default, Clone)]
        struct TestProgress {
            entries_started: Vec<String>,
            entries_completed: Vec<String>,
            bytes_written: u64,
            completed: bool,
        }

        impl ProgressCallback for TestProgress {
            fn on_entry_start(&mut self, path: &Path, _total: usize, _current: usize) {
                self.entries_started
                    .push(path.to_string_lossy().to_string());
            }

            fn on_bytes_written(&mut self, bytes: u64) {
                self.bytes_written += bytes;
            }

            fn on_entry_complete(&mut self, path: &Path) {
                self.entries_completed
                    .push(path.to_string_lossy().to_string());
            }

            fn on_complete(&mut self) {
                self.completed = true;
            }
        }

        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.zip");

        // Create source directory with multiple files
        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("file1.txt"), "content1").unwrap();
        fs::write(source_dir.path().join("file2.txt"), "content2").unwrap();
        fs::create_dir(source_dir.path().join("subdir")).unwrap();
        fs::write(source_dir.path().join("subdir/file3.txt"), "content3").unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_include_hidden(true)
            .validate()
            .unwrap();

        let mut progress = TestProgress::default();

        let report =
            create_zip_with_progress(&output, &[source_dir.path()], &config, &mut progress)
                .unwrap();

        // Verify report
        assert_eq!(report.files_added, 3);
        assert!(report.directories_added >= 1);

        // Verify callbacks were invoked
        assert!(
            progress.entries_started.len() >= 3,
            "Expected at least 3 entry starts, got {}",
            progress.entries_started.len()
        );
        assert!(
            progress.entries_completed.len() >= 3,
            "Expected at least 3 entry completions, got {}",
            progress.entries_completed.len()
        );
        assert!(
            progress.bytes_written > 0,
            "Expected bytes written > 0, got {}",
            progress.bytes_written
        );
        assert!(progress.completed, "Expected on_complete to be called");

        // Verify specific entries
        let has_file1 = progress
            .entries_started
            .iter()
            .any(|p| p.contains("file1.txt"));
        let has_file2 = progress
            .entries_started
            .iter()
            .any(|p| p.contains("file2.txt"));
        let has_file3 = progress
            .entries_started
            .iter()
            .any(|p| p.contains("file3.txt"));

        assert!(has_file1, "Expected file1.txt in progress callbacks");
        assert!(has_file2, "Expected file2.txt in progress callbacks");
        assert!(has_file3, "Expected file3.txt in progress callbacks");
    }
}
