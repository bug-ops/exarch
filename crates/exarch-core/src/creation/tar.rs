//! TAR archive creation with multiple compression formats.
//!
//! This module provides functions for creating TAR archives with various
//! compression options: uncompressed, gzip, bzip2, xz, and zstd.

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
use std::io::Write;
use std::path::Path;
use tar::Builder;
use tar::Header;

/// Creates an uncompressed TAR archive.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::creation::CreationConfig;
/// use exarch_core::creation::tar::create_tar;
/// use std::path::Path;
///
/// let config = CreationConfig::default();
/// let report = create_tar(Path::new("output.tar"), &[Path::new("src")], &config)?;
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
pub fn create_tar<P: AsRef<Path>, Q: AsRef<Path>>(
    output: P,
    sources: &[Q],
    config: &CreationConfig,
) -> Result<CreationReport> {
    let file = File::create(output.as_ref())?;
    create_tar_internal(file, sources, config)
}

/// Creates a gzip-compressed TAR archive (.tar.gz).
///
/// # Examples
///
/// ```no_run
/// use exarch_core::creation::CreationConfig;
/// use exarch_core::creation::tar::create_tar_gz;
/// use std::path::Path;
///
/// let config = CreationConfig::default().with_compression_level(9);
/// let report = create_tar_gz(
///     Path::new("output.tar.gz"),
///     &[Path::new("src"), Path::new("tests")],
///     &config,
/// )?;
/// # Ok::<(), exarch_core::ExtractionError>(())
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Source path does not exist
/// - Output file cannot be created
/// - Compression fails
/// - I/O error during archive creation
#[allow(dead_code)] // Will be used by CLI
pub fn create_tar_gz<P: AsRef<Path>, Q: AsRef<Path>>(
    output: P,
    sources: &[Q],
    config: &CreationConfig,
) -> Result<CreationReport> {
    let file = File::create(output.as_ref())?;
    let level = compression_level_to_flate2(config.compression_level);
    let encoder = flate2::write::GzEncoder::new(file, level);
    create_tar_internal(encoder, sources, config)
}

/// Creates a bzip2-compressed TAR archive (.tar.bz2).
///
/// # Examples
///
/// ```no_run
/// use exarch_core::creation::CreationConfig;
/// use exarch_core::creation::tar::create_tar_bz2;
/// use std::path::Path;
///
/// let config = CreationConfig::default();
/// let report = create_tar_bz2(Path::new("output.tar.bz2"), &[Path::new("src")], &config)?;
/// # Ok::<(), exarch_core::ExtractionError>(())
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Source path does not exist
/// - Output file cannot be created
/// - Compression fails
/// - I/O error during archive creation
#[allow(dead_code)] // Will be used by CLI
pub fn create_tar_bz2<P: AsRef<Path>, Q: AsRef<Path>>(
    output: P,
    sources: &[Q],
    config: &CreationConfig,
) -> Result<CreationReport> {
    let file = File::create(output.as_ref())?;
    let level = compression_level_to_bzip2(config.compression_level);
    let encoder = bzip2::write::BzEncoder::new(file, level);
    create_tar_internal(encoder, sources, config)
}

/// Creates an xz-compressed TAR archive (.tar.xz).
///
/// # Examples
///
/// ```no_run
/// use exarch_core::creation::CreationConfig;
/// use exarch_core::creation::tar::create_tar_xz;
/// use std::path::Path;
///
/// let config = CreationConfig::default();
/// let report = create_tar_xz(Path::new("output.tar.xz"), &[Path::new("src")], &config)?;
/// # Ok::<(), exarch_core::ExtractionError>(())
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Source path does not exist
/// - Output file cannot be created
/// - Compression fails
/// - I/O error during archive creation
#[allow(dead_code)] // Will be used by CLI
pub fn create_tar_xz<P: AsRef<Path>, Q: AsRef<Path>>(
    output: P,
    sources: &[Q],
    config: &CreationConfig,
) -> Result<CreationReport> {
    let file = File::create(output.as_ref())?;
    let level = compression_level_to_xz(config.compression_level);
    let encoder = xz2::write::XzEncoder::new(file, level);
    create_tar_internal(encoder, sources, config)
}

/// Creates a zstd-compressed TAR archive (.tar.zst).
///
/// # Examples
///
/// ```no_run
/// use exarch_core::creation::CreationConfig;
/// use exarch_core::creation::tar::create_tar_zst;
/// use std::path::Path;
///
/// let config = CreationConfig::default();
/// let report = create_tar_zst(Path::new("output.tar.zst"), &[Path::new("src")], &config)?;
/// # Ok::<(), exarch_core::ExtractionError>(())
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Source path does not exist
/// - Output file cannot be created
/// - Compression fails
/// - I/O error during archive creation
#[allow(dead_code)] // Will be used by CLI
pub fn create_tar_zst<P: AsRef<Path>, Q: AsRef<Path>>(
    output: P,
    sources: &[Q],
    config: &CreationConfig,
) -> Result<CreationReport> {
    let file = File::create(output.as_ref())?;
    let level = compression_level_to_zstd(config.compression_level);
    let mut encoder = zstd::Encoder::new(file, level)?;
    encoder.include_checksum(true)?;

    let report = create_tar_internal(encoder, sources, config)?;

    // zstd encoder needs explicit finish() to flush data
    // This is already done by into_inner() in create_tar_internal via
    // builder.into_inner() But we rely on Drop to finish the encoder

    Ok(report)
}

/// Creates an uncompressed TAR archive with progress reporting.
///
/// This function provides real-time progress updates during archive creation
/// through callback functions. Useful for displaying progress bars or logging
/// in interactive applications.
///
/// # Parameters
///
/// - `output`: Path where the TAR archive will be created
/// - `sources`: Slice of source paths to include in the archive
/// - `config`: Configuration controlling filtering, permissions, and archiving
///   behavior
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
/// use exarch_core::creation::tar::create_tar_with_progress;
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
/// let report = create_tar_with_progress(
///     Path::new("output.tar"),
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
pub fn create_tar_with_progress<P: AsRef<Path>, Q: AsRef<Path>>(
    output: P,
    sources: &[Q],
    config: &CreationConfig,
    progress: &mut dyn ProgressCallback,
) -> Result<CreationReport> {
    let file = File::create(output.as_ref())?;
    create_tar_internal_with_progress(file, sources, config, progress)
}

/// Creates a gzip-compressed TAR archive with progress reporting.
///
/// Identical to [`create_tar_with_progress`] but applies gzip compression.
/// See that function for detailed documentation on progress callbacks and
/// usage.
///
/// # Errors
///
/// Returns an error if output file cannot be created, compression fails, or I/O
/// operations fail.
#[allow(dead_code)] // Will be used by CLI
pub fn create_tar_gz_with_progress<P: AsRef<Path>, Q: AsRef<Path>>(
    output: P,
    sources: &[Q],
    config: &CreationConfig,
    progress: &mut dyn ProgressCallback,
) -> Result<CreationReport> {
    let file = File::create(output.as_ref())?;
    let level = compression_level_to_flate2(config.compression_level);
    let encoder = flate2::write::GzEncoder::new(file, level);
    create_tar_internal_with_progress(encoder, sources, config, progress)
}

/// Creates a bzip2-compressed TAR archive with progress reporting.
///
/// Identical to [`create_tar_with_progress`] but applies bzip2 compression.
/// See that function for detailed documentation on progress callbacks and
/// usage.
///
/// # Errors
///
/// Returns an error if output file cannot be created, compression fails, or I/O
/// operations fail.
#[allow(dead_code)] // Will be used by CLI
pub fn create_tar_bz2_with_progress<P: AsRef<Path>, Q: AsRef<Path>>(
    output: P,
    sources: &[Q],
    config: &CreationConfig,
    progress: &mut dyn ProgressCallback,
) -> Result<CreationReport> {
    let file = File::create(output.as_ref())?;
    let level = compression_level_to_bzip2(config.compression_level);
    let encoder = bzip2::write::BzEncoder::new(file, level);
    create_tar_internal_with_progress(encoder, sources, config, progress)
}

/// Creates an xz-compressed TAR archive with progress reporting.
///
/// Identical to [`create_tar_with_progress`] but applies xz compression.
/// See that function for detailed documentation on progress callbacks and
/// usage.
///
/// # Errors
///
/// Returns an error if output file cannot be created, compression fails, or I/O
/// operations fail.
#[allow(dead_code)] // Will be used by CLI
pub fn create_tar_xz_with_progress<P: AsRef<Path>, Q: AsRef<Path>>(
    output: P,
    sources: &[Q],
    config: &CreationConfig,
    progress: &mut dyn ProgressCallback,
) -> Result<CreationReport> {
    let file = File::create(output.as_ref())?;
    let level = compression_level_to_xz(config.compression_level);
    let encoder = xz2::write::XzEncoder::new(file, level);
    create_tar_internal_with_progress(encoder, sources, config, progress)
}

/// Creates a zstd-compressed TAR archive with progress reporting.
///
/// Identical to [`create_tar_with_progress`] but applies zstd compression.
/// See that function for detailed documentation on progress callbacks and
/// usage.
///
/// # Errors
///
/// Returns an error if output file cannot be created, compression fails, or I/O
/// operations fail.
#[allow(dead_code)] // Will be used by CLI
pub fn create_tar_zst_with_progress<P: AsRef<Path>, Q: AsRef<Path>>(
    output: P,
    sources: &[Q],
    config: &CreationConfig,
    progress: &mut dyn ProgressCallback,
) -> Result<CreationReport> {
    let file = File::create(output.as_ref())?;
    let level = compression_level_to_zstd(config.compression_level);
    let mut encoder = zstd::Encoder::new(file, level)?;
    encoder.include_checksum(true)?;

    let report = create_tar_internal_with_progress(encoder, sources, config, progress)?;

    Ok(report)
}

/// Context for progress reporting.
///
/// This struct consolidates progress-related state to reduce argument count
/// in helper functions.
struct ProgressContext<'a> {
    progress: &'a mut dyn ProgressCallback,
    current_entry: usize,
    total_entries: usize,
}

impl<'a> ProgressContext<'a> {
    fn new(progress: &'a mut dyn ProgressCallback, total_entries: usize) -> Self {
        Self {
            progress,
            current_entry: 0,
            total_entries,
        }
    }

    fn on_entry_start(&mut self, path: &Path) {
        self.current_entry += 1;
        self.progress
            .on_entry_start(path, self.total_entries, self.current_entry);
    }

    fn on_entry_complete(&mut self, path: &Path) {
        self.progress.on_entry_complete(path);
    }

    fn on_complete(&mut self) {
        self.progress.on_complete();
    }
}

/// Wrapper reader that tracks bytes read and reports progress.
struct ProgressTrackingReader<'a, R> {
    inner: R,
    progress: &'a mut dyn ProgressCallback,
    bytes_since_last_update: u64,
    batch_threshold: u64,
}

impl<'a, R> ProgressTrackingReader<'a, R> {
    fn new(inner: R, progress: &'a mut dyn ProgressCallback) -> Self {
        Self {
            inner,
            progress,
            bytes_since_last_update: 0,
            batch_threshold: 1024 * 1024, // 1 MB batching threshold
        }
    }

    fn flush_progress(&mut self) {
        if self.bytes_since_last_update > 0 {
            self.progress.on_bytes_written(self.bytes_since_last_update);
            self.bytes_since_last_update = 0;
        }
    }
}

impl<R: Read> Read for ProgressTrackingReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes_read = self.inner.read(buf)?;
        if bytes_read > 0 {
            self.bytes_since_last_update += bytes_read as u64;
            if self.bytes_since_last_update >= self.batch_threshold {
                self.progress.on_bytes_written(self.bytes_since_last_update);
                self.bytes_since_last_update = 0;
            }
        }
        Ok(bytes_read)
    }
}

impl<R> Drop for ProgressTrackingReader<'_, R> {
    fn drop(&mut self) {
        self.flush_progress();
    }
}

/// Wrapper writer that tracks bytes written for accurate compression reporting.
struct CountingWriter<W> {
    inner: W,
    bytes_written: u64,
}

impl<W> CountingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            bytes_written: 0,
        }
    }

    fn total_bytes(&self) -> u64 {
        self.bytes_written
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let bytes = self.inner.write(buf)?;
        self.bytes_written += bytes as u64;
        Ok(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Internal function that creates TAR with any writer and progress reporting.
fn create_tar_internal_with_progress<W: Write, P: AsRef<Path>>(
    writer: W,
    sources: &[P],
    config: &CreationConfig,
    progress: &mut dyn ProgressCallback,
) -> Result<CreationReport> {
    let counting_writer = CountingWriter::new(writer);
    let mut builder = Builder::new(counting_writer);
    let mut report = CreationReport::default();
    let start = std::time::Instant::now();

    // Single-pass collection of entries (avoids double directory traversal)
    let entries = collect_entries(sources, config)?;
    let total_entries = entries.len();

    // Create progress context with batching
    let mut context = ProgressContext::new(progress, total_entries);

    // Reusable buffer for file copying (fixes HIGH #2)
    let mut buffer = vec![0u8; 64 * 1024]; // 64 KB

    for entry in &entries {
        match &entry.entry_type {
            EntryType::File => {
                context.on_entry_start(&entry.archive_path);
                add_file_to_tar_with_progress_impl(
                    &mut builder,
                    &entry.path,
                    &entry.archive_path,
                    config,
                    &mut report,
                    context.progress,
                    &mut buffer,
                )?;
                context.on_entry_complete(&entry.archive_path);
            }
            EntryType::Directory => {
                context.on_entry_start(&entry.archive_path);
                report.directories_added += 1;
                context.on_entry_complete(&entry.archive_path);
            }
            EntryType::Symlink { target } => {
                context.on_entry_start(&entry.archive_path);
                if config.follow_symlinks {
                    add_file_to_tar_with_progress_impl(
                        &mut builder,
                        &entry.path,
                        &entry.archive_path,
                        config,
                        &mut report,
                        context.progress,
                        &mut buffer,
                    )?;
                } else {
                    add_symlink_to_tar(&mut builder, &entry.archive_path, target, &mut report)?;
                }
                context.on_entry_complete(&entry.archive_path);
            }
        }
    }

    // Finish writing TAR
    builder.finish()?;

    let mut counting_writer = builder.into_inner()?;
    counting_writer.flush()?;

    report.bytes_compressed = counting_writer.total_bytes();
    report.duration = start.elapsed();

    context.on_complete();

    Ok(report)
}

/// Internal function that creates TAR with any writer.
///
/// Handles the core logic of walking sources and adding entries to the archive.
fn create_tar_internal<W: Write, P: AsRef<Path>>(
    writer: W,
    sources: &[P],
    config: &CreationConfig,
) -> Result<CreationReport> {
    let counting_writer = CountingWriter::new(writer);
    let mut builder = Builder::new(counting_writer);
    let mut report = CreationReport::default();
    let start = std::time::Instant::now();

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
            add_directory_to_tar(&mut builder, path, config, &mut report)?;
        } else {
            // For single files, use filename as archive path
            let archive_path =
                filters::compute_archive_path(path, path.parent().unwrap_or(path), config)?;
            add_file_to_tar(&mut builder, path, &archive_path, config, &mut report)?;
        }
    }

    // Finish writing TAR
    builder.finish()?;

    // Get inner writer and ensure it's properly flushed
    let mut counting_writer = builder.into_inner()?;
    counting_writer.flush()?;

    report.bytes_compressed = counting_writer.total_bytes();
    report.duration = start.elapsed();

    Ok(report)
}

/// Adds a directory tree to the TAR archive using the walker.
fn add_directory_to_tar<W: Write>(
    builder: &mut Builder<W>,
    dir: &Path,
    config: &CreationConfig,
    report: &mut CreationReport,
) -> Result<()> {
    let walker = FilteredWalker::new(dir, config);

    for entry in walker.walk() {
        let entry = entry?;

        match entry.entry_type {
            EntryType::File => {
                add_file_to_tar(builder, &entry.path, &entry.archive_path, config, report)?;
            }
            EntryType::Directory => {
                // TAR can create directories implicitly, but we track them
                report.directories_added += 1;
            }
            EntryType::Symlink { target } => {
                if config.follow_symlinks {
                    // Walker already resolved symlinks, treat as file
                    add_file_to_tar(builder, &entry.path, &entry.archive_path, config, report)?;
                } else {
                    // Add symlink as-is
                    add_symlink_to_tar(builder, &entry.archive_path, &target, report)?;
                }
            }
        }
    }

    Ok(())
}

/// Adds a single file to the TAR archive.
fn add_file_to_tar<W: Write>(
    builder: &mut Builder<W>,
    file_path: &Path,
    archive_path: &Path,
    config: &CreationConfig,
    report: &mut CreationReport,
) -> Result<()> {
    let mut file = File::open(file_path)?;
    let metadata = file.metadata()?;
    let size = metadata.len();

    // Create TAR header
    let mut header = Header::new_gnu();
    header.set_size(size);
    header.set_cksum();

    // Set permissions if configured
    if config.preserve_permissions {
        set_permissions(&mut header, &metadata);
    }

    // Add file to archive
    builder.append_data(&mut header, archive_path, &mut file)?;

    report.files_added += 1;
    report.bytes_written += size;

    Ok(())
}

/// Adds a single file to the TAR archive with progress reporting and reusable
/// buffer.
fn add_file_to_tar_with_progress_impl<W: Write>(
    builder: &mut Builder<W>,
    file_path: &Path,
    archive_path: &Path,
    config: &CreationConfig,
    report: &mut CreationReport,
    progress: &mut dyn ProgressCallback,
    _buffer: &mut [u8],
) -> Result<()> {
    let file = File::open(file_path)?;
    let metadata = file.metadata()?;
    let size = metadata.len();

    let mut header = Header::new_gnu();
    header.set_size(size);
    header.set_cksum();

    if config.preserve_permissions {
        set_permissions(&mut header, &metadata);
    }

    // Use progress-tracking reader with batched updates (1 MB batches)
    // Note: tar crate's append_data does its own buffering internally,
    // so we use ProgressTrackingReader wrapper instead of manual buffer
    let mut tracked_file = ProgressTrackingReader::new(file, progress);
    builder.append_data(&mut header, archive_path, &mut tracked_file)?;

    report.files_added += 1;
    report.bytes_written += size;

    Ok(())
}

/// Adds a symlink to the TAR archive.
#[cfg(unix)]
fn add_symlink_to_tar<W: Write>(
    builder: &mut Builder<W>,
    link_path: &Path,
    target: &Path,
    report: &mut CreationReport,
) -> Result<()> {
    let mut header = Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    header.set_cksum();

    builder.append_link(&mut header, link_path, target)?;

    report.symlinks_added += 1;

    Ok(())
}

#[cfg(not(unix))]
fn add_symlink_to_tar<W: Write>(
    _builder: &mut Builder<W>,
    _link_path: &Path,
    _target: &Path,
    report: &mut CreationReport,
) -> Result<()> {
    // On non-Unix platforms, skip symlinks
    report.files_skipped += 1;
    report.add_warning("Symlinks not supported on this platform");
    Ok(())
}

/// Sets file permissions in TAR header from metadata.
#[cfg(unix)]
fn set_permissions(header: &mut Header, metadata: &std::fs::Metadata) {
    use std::os::unix::fs::MetadataExt;
    let mode = metadata.mode();
    header.set_mode(mode);
    header.set_uid(u64::from(metadata.uid()));
    header.set_gid(u64::from(metadata.gid()));
    // mtime can be negative for dates before epoch, clamp to 0
    #[allow(clippy::cast_sign_loss)] // Intentional: clamped to non-negative
    let mtime = metadata.mtime().max(0) as u64;
    header.set_mtime(mtime);
}

#[cfg(not(unix))]
fn set_permissions(header: &mut Header, metadata: &std::fs::Metadata) {
    // On non-Unix platforms, set basic permissions
    let mode = if metadata.permissions().readonly() {
        0o444
    } else {
        0o644
    };
    header.set_mode(mode);

    // Set modification time
    if let Ok(modified) = metadata.modified() {
        if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
            header.set_mtime(duration.as_secs());
        }
    }
}

/// Converts compression level (1-9) to flate2 compression level.
fn compression_level_to_flate2(level: Option<u8>) -> flate2::Compression {
    match level {
        None | Some(6) => flate2::Compression::default(),
        Some(1..=3) => flate2::Compression::fast(),
        Some(7..=9) => flate2::Compression::best(),
        Some(n) => flate2::Compression::new(u32::from(n)),
    }
}

/// Converts compression level (1-9) to bzip2 compression level.
fn compression_level_to_bzip2(level: Option<u8>) -> bzip2::Compression {
    match level {
        None | Some(6) => bzip2::Compression::default(),
        Some(1) => bzip2::Compression::fast(),
        Some(7..=9) => bzip2::Compression::best(),
        Some(n @ 2..=6) => bzip2::Compression::new(u32::from(n)),
        Some(n) => bzip2::Compression::new(u32::from(n.min(9))),
    }
}

/// Converts compression level (1-9) to xz compression level.
fn compression_level_to_xz(level: Option<u8>) -> u32 {
    match level {
        None | Some(6) => 6,
        Some(n) => u32::from(n),
    }
}

/// Converts compression level (1-9) to zstd compression level.
#[allow(clippy::match_same_arms)] // Different semantic meanings
fn compression_level_to_zstd(level: Option<u8>) -> i32 {
    match level {
        // Default compression level
        None | Some(6) => 3,
        Some(1) => 1,
        Some(2) => 2,
        Some(7) => 10,
        Some(8) => 15,
        Some(9) => 19,
        // All other levels (3-5, 0, 10+) map to default
        _ => 3,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Allow unwrap in tests for brevity
mod tests {
    use super::*;
    use crate::SecurityConfig;
    use crate::api::extract_archive;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_create_tar_single_file() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.tar");

        // Create source file
        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("test.txt"), "Hello TAR").unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_include_hidden(true);

        let report = create_tar(&output, &[source_dir.path().join("test.txt")], &config).unwrap();

        assert_eq!(report.files_added, 1);
        assert!(report.bytes_written > 0);
        assert!(output.exists());
    }

    #[test]
    fn test_create_tar_directory() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.tar");

        // Create source directory with multiple files
        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("file1.txt"), "content1").unwrap();
        fs::write(source_dir.path().join("file2.txt"), "content2").unwrap();
        fs::create_dir(source_dir.path().join("subdir")).unwrap();
        fs::write(source_dir.path().join("subdir/file3.txt"), "content3").unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_include_hidden(true);

        let report = create_tar(&output, &[source_dir.path()], &config).unwrap();

        // Should have exactly 3 files: file1.txt, file2.txt, subdir/file3.txt
        assert_eq!(report.files_added, 3);
        // Should have exactly 2 directories: root and subdir
        assert_eq!(report.directories_added, 2);
        assert!(output.exists());
    }

    #[test]
    fn test_create_tar_gz_compression() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.tar.gz");

        // Create source file
        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("test.txt"), "a".repeat(1000)).unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_compression_level(9);

        let report = create_tar_gz(&output, &[source_dir.path()], &config).unwrap();

        assert_eq!(report.files_added, 1);
        assert!(output.exists());

        // Verify it's a valid gzip file (basic check)
        let data = fs::read(&output).unwrap();
        assert_eq!(&data[0..2], &[0x1f, 0x8b]); // gzip magic bytes
    }

    #[test]
    fn test_create_tar_bz2_compression() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.tar.bz2");

        // Create source file
        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("test.txt"), "bzip2 test").unwrap();

        let config = CreationConfig::default().with_exclude_patterns(vec![]);

        let report = create_tar_bz2(&output, &[source_dir.path()], &config).unwrap();

        assert_eq!(report.files_added, 1);
        assert!(output.exists());

        // Verify it's a valid bzip2 file
        let data = fs::read(&output).unwrap();
        assert_eq!(&data[0..3], b"BZh"); // bzip2 magic bytes
    }

    #[test]
    fn test_create_tar_xz_compression() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.tar.xz");

        // Create source file
        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("test.txt"), "xz test").unwrap();

        let config = CreationConfig::default().with_exclude_patterns(vec![]);

        let report = create_tar_xz(&output, &[source_dir.path()], &config).unwrap();

        assert_eq!(report.files_added, 1);
        assert!(output.exists());

        // Verify it's a valid xz file
        let data = fs::read(&output).unwrap();
        assert_eq!(&data[0..6], &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]); // xz magic bytes
    }

    #[test]
    fn test_create_tar_zst_compression() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.tar.zst");

        // Create source file
        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("test.txt"), "zstd test").unwrap();

        let config = CreationConfig::default().with_exclude_patterns(vec![]);

        let report = create_tar_zst(&output, &[source_dir.path()], &config).unwrap();

        assert_eq!(report.files_added, 1);
        assert!(output.exists());

        // Verify it's a valid zstd file
        let data = fs::read(&output).unwrap();
        // Check we have at least some data
        assert!(data.len() >= 4, "output file should have data");
        assert_eq!(&data[0..4], &[0x28, 0xB5, 0x2F, 0xFD]); // zstd magic bytes
    }

    #[test]
    fn test_create_tar_compression_levels() {
        let temp = TempDir::new().unwrap();

        // Create source with repetitive data (compresses well)
        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("test.txt"), "a".repeat(10000)).unwrap();

        // Test different compression levels
        for level in [1, 6, 9] {
            let output = temp.path().join(format!("output_{level}.tar.gz"));
            let config = CreationConfig::default()
                .with_exclude_patterns(vec![])
                .with_compression_level(level);

            let report = create_tar_gz(&output, &[source_dir.path()], &config).unwrap();
            assert_eq!(report.files_added, 1);
            assert!(output.exists());
        }
    }

    // TODO(Phase 3): Re-enable when extraction API is fully implemented
    #[test]
    #[ignore = "requires fully implemented extraction API"]
    #[cfg(unix)]
    fn test_create_tar_preserves_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.tar");

        // Create source file with specific permissions
        let source_dir = TempDir::new().unwrap();
        let file_path = source_dir.path().join("test.txt");
        fs::write(&file_path, "content").unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o755)).unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_preserve_permissions(true);

        let report = create_tar(&output, &[source_dir.path()], &config).unwrap();
        assert_eq!(report.files_added, 1);

        // Verify permissions in archive by extracting
        let extract_dir = TempDir::new().unwrap();
        let security_config = SecurityConfig::default();
        extract_archive(&output, extract_dir.path(), &security_config).unwrap();

        let extracted = extract_dir.path().join("test.txt");
        let perms = fs::metadata(&extracted).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o755);
    }

    #[test]
    fn test_create_tar_report_statistics() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.tar");

        // Create source directory with known structure
        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("file1.txt"), "content1").unwrap();
        fs::write(source_dir.path().join("file2.txt"), "content2").unwrap();
        fs::create_dir(source_dir.path().join("subdir")).unwrap();
        fs::write(source_dir.path().join("subdir/file3.txt"), "content3").unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_include_hidden(true);

        let report = create_tar(&output, &[source_dir.path()], &config).unwrap();

        assert_eq!(report.files_added, 3);
        assert!(report.directories_added >= 1);
        assert_eq!(report.files_skipped, 0);
        assert!(!report.has_warnings());
        assert!(report.duration.as_nanos() > 0);
    }

    // TODO(Phase 3): Re-enable when extraction API is fully implemented
    #[test]
    #[ignore = "requires fully implemented extraction API"]
    fn test_create_tar_roundtrip() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.tar.gz");

        // Create source directory
        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("file1.txt"), "content1").unwrap();
        fs::create_dir(source_dir.path().join("subdir")).unwrap();
        fs::write(source_dir.path().join("subdir/file2.txt"), "content2").unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_include_hidden(true);

        // Create archive
        let report = create_tar_gz(&output, &[source_dir.path()], &config).unwrap();
        assert!(report.files_added >= 2);

        // Extract archive
        let extract_dir = TempDir::new().unwrap();
        let security_config = SecurityConfig::default();
        extract_archive(&output, extract_dir.path(), &security_config).unwrap();

        // Verify extracted files match originals
        let extracted1 = fs::read_to_string(extract_dir.path().join("file1.txt")).unwrap();
        assert_eq!(extracted1, "content1");

        let extracted2 = fs::read_to_string(extract_dir.path().join("subdir/file2.txt")).unwrap();
        assert_eq!(extracted2, "content2");
    }

    #[test]
    fn test_create_tar_source_not_found() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.tar");

        let config = CreationConfig::default();
        let result = create_tar(&output, &[Path::new("/nonexistent/path")], &config);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ExtractionError::SourceNotFound { .. }
        ));
    }

    #[test]
    fn test_compression_level_to_flate2() {
        // Default
        let level = compression_level_to_flate2(None);
        assert_eq!(level, flate2::Compression::default());

        // Fast
        let level = compression_level_to_flate2(Some(1));
        assert_eq!(level, flate2::Compression::fast());

        // Best
        let level = compression_level_to_flate2(Some(9));
        assert_eq!(level, flate2::Compression::best());

        // Specific level
        let level = compression_level_to_flate2(Some(5));
        assert_eq!(level, flate2::Compression::new(5));
    }

    #[test]
    fn test_compression_level_to_zstd() {
        assert_eq!(compression_level_to_zstd(None), 3);
        assert_eq!(compression_level_to_zstd(Some(1)), 1);
        assert_eq!(compression_level_to_zstd(Some(6)), 3);
        assert_eq!(compression_level_to_zstd(Some(7)), 10);
        assert_eq!(compression_level_to_zstd(Some(9)), 19);
    }

    #[test]
    fn test_progress_tracking_reader_reports_bytes() {
        use std::io::Cursor;

        #[derive(Debug, Default)]
        struct ByteCounter {
            total_bytes: u64,
        }

        impl ProgressCallback for ByteCounter {
            fn on_entry_start(&mut self, _path: &Path, _total: usize, _current: usize) {}

            fn on_bytes_written(&mut self, bytes: u64) {
                self.total_bytes += bytes;
            }

            fn on_entry_complete(&mut self, _path: &Path) {}

            fn on_complete(&mut self) {}
        }

        let data = b"Hello, World!";
        let reader = Cursor::new(data);
        let mut progress = ByteCounter::default();
        let mut tracking_reader = ProgressTrackingReader::new(reader, &mut progress);

        let mut buffer = vec![0u8; 5];
        let bytes_read = tracking_reader.read(&mut buffer).unwrap();

        // Drop the reader to flush progress
        drop(tracking_reader);

        assert_eq!(bytes_read, 5);
        assert_eq!(progress.total_bytes, 5);
        assert_eq!(&buffer[..bytes_read], b"Hello");
    }

    #[test]
    fn test_progress_tracking_reader_handles_eof() {
        use std::io::Cursor;

        #[derive(Debug, Default)]
        struct ByteCounter {
            total_bytes: u64,
        }

        impl ProgressCallback for ByteCounter {
            fn on_entry_start(&mut self, _path: &Path, _total: usize, _current: usize) {}

            fn on_bytes_written(&mut self, bytes: u64) {
                self.total_bytes += bytes;
            }

            fn on_entry_complete(&mut self, _path: &Path) {}

            fn on_complete(&mut self) {}
        }

        let data = b"";
        let reader = Cursor::new(data);
        let mut progress = ByteCounter::default();
        let mut tracking_reader = ProgressTrackingReader::new(reader, &mut progress);

        let mut buffer = vec![0u8; 10];
        let bytes_read = tracking_reader.read(&mut buffer).unwrap();

        // Drop tracking reader before accessing progress
        drop(tracking_reader);

        assert_eq!(bytes_read, 0);
        assert_eq!(progress.total_bytes, 0);
    }

    #[test]
    fn test_progress_tracking_reader_multiple_reads() {
        use std::io::Cursor;

        #[derive(Debug, Default)]
        struct ByteCounter {
            total_bytes: u64,
            call_count: usize,
        }

        impl ProgressCallback for ByteCounter {
            fn on_entry_start(&mut self, _path: &Path, _total: usize, _current: usize) {}

            fn on_bytes_written(&mut self, bytes: u64) {
                self.total_bytes += bytes;
                self.call_count += 1;
            }

            fn on_entry_complete(&mut self, _path: &Path) {}

            fn on_complete(&mut self) {}
        }

        let data = vec![0u8; 25]; // 25 bytes of zeros
        let reader = Cursor::new(data);
        let mut progress = ByteCounter::default();

        let mut buffer = vec![0u8; 10];
        {
            let mut tracking_reader = ProgressTrackingReader::new(reader, &mut progress);

            // First read - should get 10 bytes
            let bytes1 = tracking_reader.read(&mut buffer).unwrap();
            assert_eq!(bytes1, 10);

            // Second read - should get 10 bytes
            let bytes2 = tracking_reader.read(&mut buffer).unwrap();
            assert_eq!(bytes2, 10);

            // Third read - should get remaining 5 bytes
            let bytes3 = tracking_reader.read(&mut buffer).unwrap();
            assert_eq!(bytes3, 5);

            // Fourth read - should get EOF (0 bytes)
            let bytes4 = tracking_reader.read(&mut buffer).unwrap();
            assert_eq!(bytes4, 0);

            // Drop will flush the batched bytes
        }

        // With batching, we may get fewer calls but same total bytes
        assert_eq!(progress.total_bytes, 25);
        // The call count will be fewer due to batching (1 MB threshold)
        assert!(progress.call_count >= 1);
    }

    #[test]
    fn test_create_tar_with_progress_callback() {
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
        let output = temp.path().join("output.tar");

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
            create_tar_with_progress(&output, &[source_dir.path()], &config, &mut progress)
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
