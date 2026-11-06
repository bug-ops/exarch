//! TAR archive creation with multiple compression formats.
//!
//! This module provides functions for creating TAR archives with various
//! compression options: uncompressed, gzip, bzip2, xz, and zstd.

use crate::ProgressCallback;
use crate::Result;
#[cfg(not(unix))]
use crate::Skip;
#[cfg(not(unix))]
use crate::SkipKind;
use crate::creation::config::CreationConfig;
use crate::creation::progress::ProgressReader;
use crate::creation::progress::ProgressTracker;
use crate::creation::report::CreationReport;
use crate::creation::source::FaultSlotReader;
use crate::creation::source::copy_outcome;
use crate::creation::source::source_error;
use crate::creation::staged::ExcludedOutput;
use crate::creation::walker::Collected;
use crate::creation::walker::EntryType;
use crate::creation::walker::collect_entries;
use crate::formats::compression::CompressionCodec;
use crate::writer::CountingWriter;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use tar::Builder;
use tar::Header;

/// Writes a TAR archive, optionally compressed, into `out`.
///
/// `bytes_compressed` is the number of bytes that reached `out`, counted
/// below the encoder after it is finished and flushed.
pub(crate) fn write_tar<W: Write, P: AsRef<Path>>(
    out: W,
    codec: Option<CompressionCodec>,
    sources: &[P],
    config: &CreationConfig,
    excluded: &ExcludedOutput,
    progress: &mut dyn ProgressCallback,
) -> Result<CreationReport> {
    let counter = CountingWriter::new(out);
    let (mut report, mut counter) = if let Some(codec) = codec {
        let encoder = codec.encoder(counter, config.compression_level)?;
        let (report, encoder) =
            create_tar_internal_with_progress(encoder, sources, config, excluded, progress)?;
        (report, encoder.finish()?)
    } else {
        create_tar_internal_with_progress(counter, sources, config, excluded, progress)?
    };
    counter.flush()?;
    report.bytes_compressed = counter.bytes();
    Ok(report)
}

/// Internal function that creates TAR with any writer and progress reporting.
///
/// Returns `(report, writer)` so callers that wrap the writer (e.g. zstd
/// encoder) can finalize it after all TAR data has been flushed.
fn create_tar_internal_with_progress<W: Write, P: AsRef<Path>>(
    writer: W,
    sources: &[P],
    config: &CreationConfig,
    excluded: &ExcludedOutput,
    progress: &mut dyn ProgressCallback,
) -> Result<(CreationReport, W)> {
    let mut builder = Builder::new(writer);
    let mut report = CreationReport::default();
    let start = std::time::Instant::now();

    // Single-pass collection of entries (avoids double directory traversal)
    let Collected { entries, skipped } = collect_entries(sources, config, excluded)?;
    report.skipped = skipped;
    let total_entries = entries.len();

    let mut tracker = ProgressTracker::new(progress, total_entries);

    for entry in &entries {
        let mut guard = tracker.begin(&entry.archive_path);
        match &entry.entry_type {
            EntryType::File => add_file_to_tar_with_progress_impl(
                &mut builder,
                &entry.path,
                &entry.archive_path,
                config,
                &mut report,
                guard.progress_mut(),
            )?,
            EntryType::Directory => add_directory_to_tar(
                &mut builder,
                &entry.path,
                &entry.archive_path,
                config,
                &mut report,
            )?,
            EntryType::Symlink { target } => {
                if config.follow_symlinks {
                    add_file_to_tar_with_progress_impl(
                        &mut builder,
                        &entry.path,
                        &entry.archive_path,
                        config,
                        &mut report,
                        guard.progress_mut(),
                    )?;
                } else {
                    add_symlink_to_tar(&mut builder, &entry.archive_path, target, &mut report)?;
                }
            }
        }
        guard.complete();
        tracker.check_cancelled()?;
    }

    // Finish writing TAR
    builder.finish()?;

    let mut writer = builder.into_inner()?;
    writer.flush()?;

    report.duration = start.elapsed();

    tracker.on_complete();

    Ok((report, writer))
}

/// Adds a directory entry to the TAR archive.
fn add_directory_to_tar<W: Write>(
    builder: &mut Builder<W>,
    dir_path: &Path,
    archive_path: &Path,
    config: &CreationConfig,
    report: &mut CreationReport,
) -> Result<()> {
    let mut header = Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_size(0);

    if config.permissions.preserves() {
        let metadata = std::fs::metadata(dir_path).map_err(|e| source_error(dir_path, e))?;
        set_permissions(&mut header, &metadata);
    } else {
        // Deterministic, traversable default (mirrors tar-rs's
        // `HeaderMode::Deterministic` and the `zip` crate's directory
        // default) rather than the all-zero mode `Header::new_gnu()`
        // otherwise leaves behind, which produces directories the owner
        // cannot even traverse without a manual `chmod -R`.
        header.set_mode(0o755);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
    }

    header.set_cksum();
    builder.append_data(&mut header, archive_path, std::io::empty())?;

    report.directories_added += 1;

    Ok(())
}

/// Adds a single file to the TAR archive with progress reporting.
fn add_file_to_tar_with_progress_impl<W: Write>(
    builder: &mut Builder<W>,
    file_path: &Path,
    archive_path: &Path,
    config: &CreationConfig,
    report: &mut CreationReport,
    progress: &mut dyn ProgressCallback,
) -> Result<()> {
    let file = File::open(file_path).map_err(|e| source_error(file_path, e))?;
    let metadata = file.metadata().map_err(|e| source_error(file_path, e))?;
    let size = metadata.len();

    let mut header = Header::new_gnu();
    header.set_size(size);
    header.set_cksum();

    if config.permissions.preserves() {
        set_permissions(&mut header, &metadata);
    }

    let mut fault = None;
    let appended = {
        let mut tracked_file =
            ProgressReader::new(FaultSlotReader::new(file, &mut fault), progress);
        builder.append_data(&mut header, archive_path, &mut tracked_file)
    };
    copy_outcome(appended, fault, file_path)?;

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
    link_path: &Path,
    _target: &Path,
    report: &mut CreationReport,
) -> Result<()> {
    // On non-Unix platforms, skip symlinks
    report
        .skipped
        .record(Skip::new(SkipKind::SymlinkUnsupported, link_path))
}

/// Sets file permissions in TAR header from metadata.
#[cfg(unix)]
fn set_permissions(header: &mut Header, metadata: &std::fs::Metadata) {
    use std::os::unix::fs::MetadataExt;
    header.set_mode(metadata.mode() & 0o7777);
    header.set_uid(u64::from(metadata.uid()));
    header.set_gid(u64::from(metadata.gid()));
    // mtime can be negative for dates before epoch, clamp to 0
    #[expect(
        clippy::cast_sign_loss,
        reason = "the value is non-negative at this point"
    )]
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
    if let Ok(modified) = metadata.modified()
        && let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH)
    {
        header.set_mtime(duration.as_secs());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Allow unwrap in tests for brevity
mod tests {
    use super::*;
    use crate::ArchiveError;
    use crate::SecurityConfig;
    use crate::api::create_archive;
    use crate::api::extract_archive;
    use crate::creation::CompressionLevel;
    use crate::formats::detect::CreatableFormat;
    use std::assert_matches;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_create_tar_single_file() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.tar");

        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("test.txt"), "Hello TAR").unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_include_hidden(true);

        let report = create_archive(
            &output,
            &[source_dir.path().join("test.txt").as_path()],
            &config,
        )
        .unwrap();

        assert_eq!(report.files_added, 1);
        assert!(report.bytes_written > 0);
        assert!(output.exists());
    }

    #[test]
    fn test_create_tar_directory() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.tar");

        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("file1.txt"), "content1").unwrap();
        fs::write(source_dir.path().join("file2.txt"), "content2").unwrap();
        fs::create_dir(source_dir.path().join("subdir")).unwrap();
        fs::write(source_dir.path().join("subdir/file3.txt"), "content3").unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_include_hidden(true);

        let report = create_archive(&output, &[source_dir.path()], &config).unwrap();

        assert_eq!(report.files_added, 3);
        // Only "subdir" is counted; the archive root itself is skipped
        // (matches ZIP's root-skip behavior, see #400).
        assert_eq!(report.directories_added, 1);
        assert!(output.exists());
    }

    #[test]
    fn test_create_tar_gz_compression() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.tar.gz");

        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("test.txt"), "a".repeat(1000)).unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_compression_level(CompressionLevel::try_from(9u8).unwrap());

        let report = create_archive(&output, &[source_dir.path()], &config).unwrap();

        assert_eq!(report.files_added, 1);
        assert!(output.exists());

        let data = fs::read(&output).unwrap();
        assert_eq!(&data[0..2], &[0x1f, 0x8b]); // gzip magic bytes
    }

    #[test]
    fn test_create_tar_bz2_compression() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.tar.bz2");

        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("test.txt"), "bzip2 test").unwrap();

        let config = CreationConfig::default().with_exclude_patterns(vec![]);

        let report = create_archive(&output, &[source_dir.path()], &config).unwrap();

        assert_eq!(report.files_added, 1);
        assert!(output.exists());

        let data = fs::read(&output).unwrap();
        assert_eq!(&data[0..3], b"BZh"); // bzip2 magic bytes
    }

    #[test]
    fn test_create_tar_xz_compression() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.tar.xz");

        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("test.txt"), "xz test").unwrap();

        let config = CreationConfig::default().with_exclude_patterns(vec![]);

        let report = create_archive(&output, &[source_dir.path()], &config).unwrap();

        assert_eq!(report.files_added, 1);
        assert!(output.exists());

        let data = fs::read(&output).unwrap();
        assert_eq!(&data[0..6], &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]); // xz magic bytes
    }

    #[test]
    fn test_create_tar_zst_compression() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.tar.zst");

        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("test.txt"), "zstd test").unwrap();

        let config = CreationConfig::default().with_exclude_patterns(vec![]);

        let report = create_archive(&output, &[source_dir.path()], &config).unwrap();

        assert_eq!(report.files_added, 1);
        assert!(output.exists());

        let data = fs::read(&output).unwrap();
        assert!(data.len() >= 4, "output file should have data");
        assert_eq!(&data[0..4], &[0x28, 0xB5, 0x2F, 0xFD]); // zstd magic bytes
    }

    /// Regression test for #443: sweeps every tar compression backend
    /// (flate2, bzip2, liblzma, zstd) across the full 1-9 level range through
    /// the validated `create_archive` path. This is the test that would
    /// have caught the flate2 1.1.9 backend swap that panicked on
    /// out-of-range levels — a level-1-and-9-only sweep on tar.gz alone
    /// does not exercise `liblzma::Stream::new_easy_encoder`, one of the two
    /// confirmed panic sites, at any level but the default.
    #[test]
    fn test_create_tar_compression_levels() {
        let temp = TempDir::new().unwrap();

        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("test.txt"), "a".repeat(10000)).unwrap();

        for format in [
            CreatableFormat::TarGz,
            CreatableFormat::TarBz2,
            CreatableFormat::TarXz,
            CreatableFormat::TarZst,
        ] {
            for level in 1..=9u8 {
                let output = temp.path().join(format!("output_{format:?}_{level}.tar"));
                let config = CreationConfig::default()
                    .with_exclude_patterns(vec![])
                    .with_compression_level(CompressionLevel::try_from(level).unwrap());

                let report = crate::CreateRequest::new(&config)
                    .create(
                        &crate::OutputFile::replace(&output).with_format(format),
                        &[source_dir.path()],
                    )
                    .unwrap();
                assert_eq!(report.files_added, 1, "{format:?} level {level}");
                assert!(output.exists(), "{format:?} level {level}");
            }
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_create_tar_preserves_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.tar");

        let source_dir = TempDir::new().unwrap();
        let file_path = source_dir.path().join("test.txt");
        fs::write(&file_path, "content").unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o755)).unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_preserve_permissions(true);

        let report = create_archive(&output, &[source_dir.path()], &config).unwrap();
        assert_eq!(report.files_added, 1);

        let extract_dir = TempDir::new().unwrap();
        let security_config = SecurityConfig::default();
        extract_archive(&output, extract_dir.path(), &security_config).unwrap();

        let extracted = extract_dir.path().join("test.txt");
        let perms = fs::metadata(&extracted).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o755);
    }

    /// Regression test for impl-critic finding S1: with
    /// `preserve_permissions: false`, TAR directory entries used to inherit
    /// `Header::new_gnu()`'s zero-filled mode, producing directories mode
    /// `0o000` that the owner could not even traverse after extraction.
    #[test]
    #[cfg(unix)]
    fn test_create_tar_directory_mode_without_preserve_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.tar");

        let source_dir = TempDir::new().unwrap();
        let subdir = source_dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();
        // Give the source directory a mode that must NOT leak through, to
        // prove the archive uses the deterministic default rather than the
        // real (unpreserved) source mode.
        fs::set_permissions(&subdir, fs::Permissions::from_mode(0o700)).unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_preserve_permissions(false);

        let report = create_archive(&output, &[source_dir.path()], &config).unwrap();
        assert_eq!(report.directories_added, 1);

        let extract_dir = TempDir::new().unwrap();
        let security_config = SecurityConfig::default();
        extract_archive(&output, extract_dir.path(), &security_config).unwrap();

        let extracted = extract_dir.path().join("subdir");
        let mode = fs::metadata(&extracted).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o755,
            "directory entries without preserve_permissions must use a traversable \
             deterministic default, not mode 0"
        );
    }

    /// Regression test for #632: headers carry permission bits only, so
    /// `list` agrees with ZIP and system `tar`.
    #[test]
    #[cfg(unix)]
    fn test_create_tar_header_mode_has_no_file_type_bits() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.tar");
        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("a.txt"), "hello").unwrap();
        fs::create_dir(source_dir.path().join("sub")).unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_preserve_permissions(true);
        create_archive(&output, &[source_dir.path()], &config).unwrap();

        let mut archive = tar::Archive::new(fs::File::open(&output).unwrap());
        let modes: Vec<u32> = archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap().header().mode().unwrap())
            .collect();
        assert!(!modes.is_empty());
        assert!(modes.iter().all(|m| m & !0o7777 == 0), "{modes:?}");

        let manifest = crate::list_archive(&output, &SecurityConfig::default()).unwrap();
        assert!(
            manifest
                .entries()
                .iter()
                .all(|e| e.mode.is_none_or(|m| m.get() & !0o7777 == 0))
        );
    }

    #[test]
    fn test_create_tar_report_statistics() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.tar");

        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("file1.txt"), "content1").unwrap();
        fs::write(source_dir.path().join("file2.txt"), "content2").unwrap();
        fs::create_dir(source_dir.path().join("subdir")).unwrap();
        fs::write(source_dir.path().join("subdir/file3.txt"), "content3").unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_include_hidden(true);

        let report = create_archive(&output, &[source_dir.path()], &config).unwrap();

        assert_eq!(report.files_added, 3);
        assert!(report.directories_added >= 1);
        assert_eq!(report.files_skipped(), 0);
        assert!(!report.has_warnings());
        assert!(report.duration.as_nanos() > 0);
    }

    #[test]
    fn test_create_tar_roundtrip() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.tar.gz");

        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("file1.txt"), "content1").unwrap();
        fs::create_dir(source_dir.path().join("subdir")).unwrap();
        fs::write(source_dir.path().join("subdir/file2.txt"), "content2").unwrap();

        let config = CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_include_hidden(true);

        let report = create_archive(&output, &[source_dir.path()], &config).unwrap();
        assert!(report.files_added >= 2);

        let extract_dir = TempDir::new().unwrap();
        let security_config = SecurityConfig::default();
        extract_archive(&output, extract_dir.path(), &security_config).unwrap();

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
        let result = create_archive(&output, &[Path::new("/nonexistent/path")], &config);

        assert!(result.is_err());
        assert_matches!(result.unwrap_err(), ArchiveError::SourceNotFound { .. });
    }

    // NOTE: Progress tracking reader tests are now in creation/progress.rs

    /// Writer that fails with an I/O error after `fail_after` bytes have been
    /// written.
    struct FailWriter {
        written: usize,
        fail_after: usize,
    }

    impl FailWriter {
        fn new(fail_after: usize) -> Self {
            Self {
                written: 0,
                fail_after,
            }
        }
    }

    impl Write for FailWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.written >= self.fail_after {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "simulated write failure",
                ));
            }
            let allowed = (self.fail_after - self.written).min(buf.len());
            self.written += allowed;
            Ok(allowed)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Regression test for #226: verifies that errors from
    /// `zstd::Encoder::finish()` are propagated rather than silently
    /// swallowed via `Drop`.
    ///
    /// Uses a `FailWriter` that errors after a small number of bytes so that
    /// the zstd encoder's `finish()` call encounters an I/O failure.
    #[test]
    fn test_zstd_encoder_finish_error_propagated() {
        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("a.txt"), "hello").unwrap();

        let config = CreationConfig::default().with_exclude_patterns(vec![]);

        // Allow enough bytes for the zstd header but fail mid-stream so that
        // encoder.finish() must flush remaining data and hits the limit.
        let fail_writer = FailWriter::new(8);
        let level = config.compression_level.to_zstd();
        let mut encoder = zstd::Encoder::new(fail_writer, level).unwrap();
        encoder.include_checksum(true).unwrap();

        let mut noop = crate::NoopProgress;
        let result = create_tar_internal_with_progress(
            encoder,
            &[source_dir.path()],
            &config,
            &ExcludedOutput::none(),
            &mut noop,
        );

        // Either the internal write or encoder.finish() must surface an error.
        // We call finish() only if internal succeeded, mirroring the real code
        // path.
        let is_err = match result {
            Err(_) => true,
            Ok((_, enc)) => enc.finish().is_err(),
        };
        assert!(
            is_err,
            "expected an error from zstd encoder when underlying writer fails"
        );
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
            fn on_entry_start(&mut self, path: &Path, _position: crate::EntryPosition) {
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

        let report = crate::CreateRequest::new(&config)
            .with_progress(&mut progress)
            .create(&crate::OutputFile::replace(&output), &[source_dir.path()])
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

    /// Regression test for #226: `create_tar_with_progress` with zstd calls
    /// `encoder.finish()` and returns any I/O error it produces.
    ///
    /// The public function signature takes a `Path`, not a generic writer, so
    /// we verify the happy path here (`finish()` called, valid zstd output).
    /// The error-propagation path of `finish()` is covered by the
    /// internal-function test `test_zstd_encoder_finish_error_propagated`.
    #[test]
    fn test_create_tar_zst_with_progress_calls_finish() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output.tar.zst");

        let source_dir = TempDir::new().unwrap();
        fs::write(source_dir.path().join("test.txt"), "zstd progress finish").unwrap();

        let config = CreationConfig::default().with_exclude_patterns(vec![]);
        let mut noop = crate::NoopProgress;
        let report = crate::CreateRequest::new(&config)
            .with_progress(&mut noop)
            .create(
                &crate::OutputFile::replace(&output).with_format(CreatableFormat::TarZst),
                &[source_dir.path()],
            )
            .unwrap();

        assert_eq!(report.files_added, 1);
        assert!(output.exists());

        // A properly finished zstd frame starts with the zstd magic number.
        let data = fs::read(&output).unwrap();
        assert!(data.len() >= 4);
        assert_eq!(&data[0..4], &[0x28, 0xB5, 0x2F, 0xFD]);
    }
}
