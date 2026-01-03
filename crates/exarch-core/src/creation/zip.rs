//! ZIP archive creation.
//!
//! This module provides functions for creating ZIP archives with configurable
//! compression levels and security options.

use crate::ExtractionError;
use crate::ProgressCallback;
use crate::Result;
use crate::creation::config::CreationConfig;
use crate::creation::filters;
use crate::creation::report::CreationReport;
use crate::creation::walker::EntryType;
use crate::creation::walker::FilteredWalker;
use crate::creation::walker::collect_entries;
use std::fs::File;
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
/// let config = CreationConfig::default();
/// let report = create_zip(Path::new("output.zip"), &[Path::new("src")], &config)?;
/// println!("Added {} files", report.files_added);
/// # Ok::<(), exarch_core::ExtractionError>(())
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Source path does not exist
/// - Output file cannot be created
/// - I/O error during archive creation
#[allow(dead_code)] // Will be used by CLI
pub fn create_zip<P: AsRef<Path>, Q: AsRef<Path>>(
    output: P,
    sources: &[Q],
    config: &CreationConfig,
) -> Result<CreationReport> {
    let file = File::create(output.as_ref())?;
    create_zip_internal(file, sources, config)
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
/// let config = CreationConfig::default();
/// let mut progress = SimpleProgress;
/// let report = create_zip_with_progress(
///     Path::new("output.zip"),
///     &[Path::new("src")],
///     &config,
///     &mut progress,
/// )?;
/// # Ok::<(), exarch_core::ExtractionError>(())
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Source path does not exist
/// - Output file cannot be created
/// - I/O error during archive creation
/// - File metadata cannot be read
#[allow(dead_code)] // Will be used by CLI
pub fn create_zip_with_progress<P: AsRef<Path>, Q: AsRef<Path>>(
    output: P,
    sources: &[Q],
    config: &CreationConfig,
    progress: &mut dyn ProgressCallback,
) -> Result<CreationReport> {
    let file = File::create(output.as_ref())?;
    create_zip_internal_with_progress(file, sources, config, progress)
}

/// Internal function that creates ZIP with any writer and progress reporting.
fn create_zip_internal_with_progress<W: Write + Seek, P: AsRef<Path>>(
    writer: W,
    sources: &[P],
    config: &CreationConfig,
    progress: &mut dyn ProgressCallback,
) -> Result<CreationReport> {
    let mut zip = ZipWriter::new(writer);
    let mut report = CreationReport::default();
    let start = std::time::Instant::now();

    // Configure ZIP file options with compression level
    let options = if config.compression_level == Some(0) {
        SimpleFileOptions::default().compression_method(CompressionMethod::Stored)
    } else {
        let level = config.compression_level.unwrap_or(6);
        SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .compression_level(Some(i64::from(level)))
    };

    // Single-pass collection of entries (avoids double directory traversal)
    let entries = collect_entries(sources, config)?;
    let total_entries = entries.len();

    // Reusable buffer for file copying (fixes HIGH #2)
    let mut buffer = vec![0u8; 64 * 1024]; // 64 KB

    for (idx, entry) in entries.iter().enumerate() {
        let current_entry = idx + 1;

        match &entry.entry_type {
            EntryType::File => {
                progress.on_entry_start(&entry.archive_path, total_entries, current_entry);
                add_file_to_zip_with_progress_and_buffer(
                    &mut zip,
                    &entry.path,
                    &entry.archive_path,
                    config,
                    &mut report,
                    &options,
                    progress,
                    &mut buffer,
                )?;
                progress.on_entry_complete(&entry.archive_path);
            }
            EntryType::Directory => {
                progress.on_entry_start(&entry.archive_path, total_entries, current_entry);
                // Skip root directory entry (empty path becomes "/" which is invalid)
                if !entry.archive_path.as_os_str().is_empty() {
                    let dir_path = format!("{}/", normalize_zip_path(&entry.archive_path)?);
                    zip.add_directory(&dir_path, options).map_err(|e| {
                        std::io::Error::other(format!("failed to add directory: {e}"))
                    })?;
                    report.directories_added += 1;
                }
                progress.on_entry_complete(&entry.archive_path);
            }
            EntryType::Symlink { .. } => {
                progress.on_entry_start(&entry.archive_path, total_entries, current_entry);
                if !config.follow_symlinks {
                    report.files_skipped += 1;
                    report.add_warning(format!("Skipped symlink: {}", entry.path.display()));
                }
                progress.on_entry_complete(&entry.archive_path);
            }
        }
    }

    // Finish writing ZIP
    zip.finish()
        .map_err(|e| std::io::Error::other(format!("failed to finish ZIP archive: {e}")))?;

    report.duration = start.elapsed();

    progress.on_complete();

    Ok(report)
}

/// Internal function that creates ZIP with any writer.
///
/// Handles the core logic of walking sources and adding entries to the archive.
fn create_zip_internal<W: Write + Seek, P: AsRef<Path>>(
    writer: W,
    sources: &[P],
    config: &CreationConfig,
) -> Result<CreationReport> {
    let mut zip = ZipWriter::new(writer);
    let mut report = CreationReport::default();
    let start = std::time::Instant::now();

    // Configure ZIP file options with compression level
    let options = if config.compression_level == Some(0) {
        SimpleFileOptions::default().compression_method(CompressionMethod::Stored)
    } else {
        // Convert compression level (1-9) to zip crate level
        let level = config.compression_level.unwrap_or(6);
        SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .compression_level(Some(i64::from(level)))
    };

    for source in sources {
        let path = source.as_ref();

        // Validate source exists
        if !path.exists() {
            return Err(ExtractionError::SourceNotFound {
                path: path.to_path_buf(),
            });
        }

        // Walk directory or add single file
        if path.is_dir() {
            add_directory_to_zip(&mut zip, path, config, &mut report, &options)?;
        } else {
            // For single files, use filename as archive path
            let archive_path =
                filters::compute_archive_path(path, path.parent().unwrap_or(path), config)?;
            add_file_to_zip(&mut zip, path, &archive_path, config, &mut report, &options)?;
        }
    }

    // Finish writing ZIP
    zip.finish()
        .map_err(|e| std::io::Error::other(format!("failed to finish ZIP archive: {e}")))?;

    report.duration = start.elapsed();

    Ok(report)
}

/// Adds a directory tree to the ZIP archive using the walker.
fn add_directory_to_zip<W: Write + Seek>(
    zip: &mut ZipWriter<W>,
    dir: &Path,
    config: &CreationConfig,
    report: &mut CreationReport,
    options: &SimpleFileOptions,
) -> Result<()> {
    let walker = FilteredWalker::new(dir, config);

    for entry in walker.walk() {
        let entry = entry?;

        match entry.entry_type {
            EntryType::File => {
                add_file_to_zip(
                    zip,
                    &entry.path,
                    &entry.archive_path,
                    config,
                    report,
                    options,
                )?;
            }
            EntryType::Directory => {
                // ZIP requires explicit directory entries with trailing /
                let dir_path = format!("{}/", normalize_zip_path(&entry.archive_path)?);
                zip.add_directory(&dir_path, *options)
                    .map_err(|e| std::io::Error::other(format!("failed to add directory: {e}")))?;
                report.directories_added += 1;
            }
            EntryType::Symlink { .. } => {
                if !config.follow_symlinks {
                    // ZIP doesn't have native symlink support like TAR
                    // Skip symlinks when not following them
                    report.files_skipped += 1;
                    report.add_warning(format!("Skipped symlink: {}", entry.path.display()));
                }
            }
        }
    }

    Ok(())
}

/// Adds a single file to the ZIP archive.
fn add_file_to_zip<W: Write + Seek>(
    zip: &mut ZipWriter<W>,
    file_path: &Path,
    archive_path: &Path,
    config: &CreationConfig,
    report: &mut CreationReport,
    options: &SimpleFileOptions,
) -> Result<()> {
    let mut file = File::open(file_path)?;
    let metadata = file.metadata()?;
    let size = metadata.len();

    // Check file size limit
    if let Some(max_size) = config.max_file_size
        && size > max_size
    {
        report.files_skipped += 1;
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

    // Convert archive_path to ZIP format (forward slashes)
    let archive_name = normalize_zip_path(archive_path)?;

    zip.start_file(&archive_name, file_options)
        .map_err(|e| std::io::Error::other(format!("failed to start file in ZIP: {e}")))?;

    // Copy file contents with 64KB buffer for better throughput
    let mut buffer = vec![0u8; 64 * 1024]; // 64 KB
    let mut bytes_written = 0u64;
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        zip.write_all(&buffer[..bytes_read])?;
        bytes_written += bytes_read as u64;
    }

    report.files_added += 1;
    report.bytes_written += bytes_written;

    Ok(())
}

/// Adds a single file to the ZIP archive with progress reporting and reusable
/// buffer.
#[allow(clippy::too_many_arguments)]
fn add_file_to_zip_with_progress_and_buffer<W: Write + Seek>(
    zip: &mut ZipWriter<W>,
    file_path: &Path,
    archive_path: &Path,
    config: &CreationConfig,
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
        report.files_skipped += 1;
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

    zip.start_file(&archive_name, file_options)
        .map_err(|e| std::io::Error::other(format!("failed to start file in ZIP: {e}")))?;

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
        ExtractionError::Io(std::io::Error::other(format!(
            "path is not valid UTF-8: {}",
            path.display()
        )))
    })?;

    // Replace backslashes with forward slashes (Windows)
    #[cfg(windows)]
    let normalized = path_str.replace('\\', "/");

    #[cfg(not(windows))]
    let normalized = path_str.to_string();

    Ok(normalized)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Allow unwrap in tests for brevity
mod tests {
    use super::*;
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
            .with_include_hidden(true);

        let report = create_zip(&output, &[source_dir.path().join("test.txt")], &config).unwrap();

        assert_eq!(report.files_added, 1);
        assert!(report.bytes_written > 0);
        assert!(output.exists());
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
            .with_include_hidden(true);

        let report = create_zip(&output, &[source_dir.path()], &config).unwrap();

        // Should have exactly 3 files: file1.txt, file2.txt, subdir/file3.txt
        assert_eq!(report.files_added, 3);
        // Should have exactly 2 directories: root and subdir
        assert_eq!(report.directories_added, 2);
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
            .with_compression_level(9);

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
                .with_compression_level(level);

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
            .with_include_hidden(true);

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
                    entry.name().ends_with('/'),
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
            .with_preserve_permissions(true);

        let report = create_zip(&output, &[source_dir.path()], &config).unwrap();
        assert_eq!(report.files_added, 1);

        // Verify permissions in archive
        let file = File::open(&output).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();

        for i in 0..archive.len() {
            let entry = archive.by_index(i).unwrap();
            if entry.name().contains("test.txt")
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
            .with_include_hidden(true);

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
            .with_include_hidden(true);

        // Create archive
        let report = create_zip(&output, &[source_dir.path()], &config).unwrap();
        assert!(report.files_added >= 2);

        // Extract and verify using zip crate
        let file = File::open(&output).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();

        let extract_dir = TempDir::new().unwrap();

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i).unwrap();
            let outpath = extract_dir.path().join(entry.name());

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
            .with_include_hidden(true);

        create_zip(&output, &[source_dir.path()], &config).unwrap();

        // Verify paths use forward slashes
        let file = File::open(&output).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();

        for i in 0..archive.len() {
            let entry = archive.by_index(i).unwrap();
            let name = entry.name();
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

        let config = CreationConfig::default();
        let result = create_zip(&output, &[Path::new("/nonexistent/path")], &config);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ExtractionError::SourceNotFound { .. }
        ));
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
            .with_max_file_size(Some(100));

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
            .with_include_hidden(true);

        let report = create_zip(&output, &[source_dir.path()], &config).unwrap();

        // Should add target.txt, skip link.txt
        assert_eq!(report.files_added, 1);
        assert_eq!(report.files_skipped, 1);
        assert!(report.has_warnings());

        let warning = &report.warnings[0];
        assert!(warning.contains("Skipped symlink"));
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
            .with_include_hidden(true);

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
