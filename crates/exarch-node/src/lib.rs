//! Node.js bindings for exarch-core.
//!
//! This crate provides a JavaScript/TypeScript API for secure archive
//! extraction with built-in protection against path traversal, zip bombs,
//! symlink attacks, and other common vulnerabilities.
//!
//! # Installation
//!
//! ```bash
//! npm install @exarch/node
//! ```
//!
//! # Quick Start
//!
//! ```javascript
//! const { extractArchive, SecurityConfig } = require('@exarch/node');
//!
//! // Use secure defaults
//! const report = await extractArchive('archive.tar.gz', '/tmp/output');
//! console.log(`Extracted ${report.filesExtracted} files`);
//!
//! // Customize security settings
//! const config = new SecurityConfig()
//!   .maxFileSize(100 * 1024 * 1024)
//!   .allowSymlinks(true);
//! const report = await extractArchive('archive.tar.gz', '/tmp/output', config);
//! ```
//!
//! # Security
//!
//! This library uses a secure-by-default approach. All potentially dangerous
//! features are disabled by default and must be explicitly enabled. See
//! `SecurityConfig` for configuration options.
//!
//! # Repository
//!
//! <https://github.com/rabax/exarch>
//!
//! # License
//!
//! MIT OR Apache-2.0

// Allow trailing_empty_array from napi macro - this is expected behavior
#![allow(clippy::trailing_empty_array)]

use napi::bindgen_prelude::*;
use napi::threadsafe_function::ThreadsafeFunction;
use napi::threadsafe_function::ThreadsafeFunctionCallMode;
use napi_derive::napi;

mod config;
mod error;
mod report;
mod utils;

use config::CreationConfig;
use config::ExtractionOptions;
use config::SecurityConfig;
use error::convert_error;
use report::ArchiveManifest;
use report::CreationReport;
use report::ExtractionReport;
use report::VerificationReport;
use utils::validate_path;

/// Extract an archive to the specified directory (async).
///
/// This function provides secure archive extraction with configurable
/// security policies. By default, it uses a restrictive security
/// configuration that blocks symlinks, hardlinks, absolute paths, and
/// enforces resource quotas.
///
/// # Security Considerations
///
/// ## Thread Safety and TOCTOU
///
/// The extraction runs on a libuv thread pool worker thread. This creates
/// a Time-Of-Check-Time-Of-Use (TOCTOU) race condition where the archive
/// file could be modified between validation and extraction. This is an
/// accepted tradeoff for async performance. For untrusted archives, ensure
/// exclusive access to the archive file during extraction.
///
/// ## Input Validation
///
/// - Paths containing null bytes are rejected (security)
/// - Paths exceeding 4096 bytes are rejected (`DoS` prevention)
/// - All validation happens at the Node.js boundary before calling core library
///
/// # Arguments
///
/// * `archive_path` - Path to the archive file
/// * `output_dir` - Directory where files will be extracted
/// * `config` - Optional `SecurityConfig` (uses secure defaults if omitted)
///
/// # Returns
///
/// Promise resolving to `ExtractionReport` with extraction statistics
///
/// # Errors
///
/// Returns error for security violations or I/O errors. Error messages are
/// prefixed with error codes for discrimination in JavaScript:
///
/// - `PATH_TRAVERSAL`: Path traversal attempt detected
/// - `SYMLINK_ESCAPE`: Symlink points outside extraction directory
/// - `HARDLINK_ESCAPE`: Hardlink target outside extraction directory
/// - `ZIP_BOMB`: Potential zip bomb detected
/// - `INVALID_PERMISSIONS`: File permissions are invalid or unsafe
/// - `QUOTA_EXCEEDED`: Resource quota exceeded
/// - `SECURITY_VIOLATION`: Security policy violation
/// - `UNSUPPORTED_FORMAT`: Archive format not supported
/// - `INVALID_ARCHIVE`: Archive is corrupted
/// - `IO_ERROR`: I/O operation failed
///
/// # Examples
///
/// ```javascript
/// // Use secure defaults
/// const report = await extractArchive('archive.tar.gz', '/tmp/output');
/// console.log(`Extracted ${report.filesExtracted} files`);
///
/// // Customize security settings
/// const config = new SecurityConfig().setMaxFileSize(100 * 1024 * 1024);
/// const report = await extractArchive('archive.tar.gz', '/tmp/output', config);
///
/// // Customize extraction options
/// const opts = new ExtractionOptions().withSkipDuplicates(false);
/// const report = await extractArchive('archive.tar.gz', '/tmp/output', null, opts);
/// ```
#[napi]
#[allow(clippy::needless_pass_by_value, clippy::trailing_empty_array)]
pub async fn extract_archive(
    archive_path: String,
    output_dir: String,
    config: Option<&SecurityConfig>,
    options: Option<&ExtractionOptions>,
) -> Result<ExtractionReport> {
    // Validate paths at boundary
    // NOTE: Defense-in-depth - paths are validated here and again in core
    // library. This boundary validation catches issues early and provides
    // better error messages for Node.js users.
    validate_path(&archive_path)?;
    validate_path(&output_dir)?;

    // Get owned config/options - clone only when Some, use default otherwise
    let config_owned: exarch_core::SecurityConfig =
        config.map(|c| c.as_core().clone()).unwrap_or_default();
    let options_owned: exarch_core::ExtractionOptions =
        options.map(|o| o.as_core().clone()).unwrap_or_default();

    // Run extraction on tokio thread pool
    //
    // NAPI-RS with tokio_rt feature uses tokio runtime for async operations.
    // spawn_blocking is required because archive extraction does blocking I/O.
    // This moves the work to tokio's blocking thread pool rather than
    // blocking the Node.js event loop.
    //
    // NOTE: TOCTOU race condition - archive contents can change between
    // validation and extraction. This is an accepted limitation for async I/O.
    // For maximum security with untrusted archives, use extractArchiveSync()
    // or ensure exclusive file access (e.g., flock) during extraction.
    let report = tokio::task::spawn_blocking(move || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            exarch_core::extract_archive_with_options(
                &archive_path,
                &output_dir,
                &config_owned,
                &options_owned,
            )
            .map_err(convert_error)
        }))
        .map_err(|_| Error::from_reason("Internal panic during archive extraction"))
        .flatten()
    })
    .await
    .map_err(|e| Error::from_reason(format!("task join error: {e}")))
    .flatten()?;

    Ok(ExtractionReport::from(report))
}

/// Extract an archive to the specified directory (sync).
///
/// Synchronous version of `extractArchive`. Blocks the event loop until
/// extraction completes. Prefer the async version for most use cases.
///
/// # Arguments
///
/// * `archive_path` - Path to the archive file
/// * `output_dir` - Directory where files will be extracted
/// * `config` - Optional `SecurityConfig` (uses secure defaults if omitted)
///
/// # Returns
///
/// `ExtractionReport` with extraction statistics
///
/// # Errors
///
/// Returns error for security violations or I/O errors. See `extract_archive`
/// for error code documentation.
///
/// # Examples
///
/// ```javascript
/// // Use secure defaults
/// const report = extractArchiveSync('archive.tar.gz', '/tmp/output');
/// console.log(`Extracted ${report.filesExtracted} files`);
///
/// // Customize security settings
/// const config = new SecurityConfig().setMaxFileSize(100 * 1024 * 1024);
/// const report = extractArchiveSync('archive.tar.gz', '/tmp/output', config);
/// ```
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn extract_archive_sync(
    archive_path: String,
    output_dir: String,
    config: Option<&SecurityConfig>,
    options: Option<&ExtractionOptions>,
) -> Result<ExtractionReport> {
    // Validate paths at boundary
    // NOTE: Defense-in-depth - paths are validated here and again in core
    // library. This boundary validation catches issues early and provides
    // better error messages for Node.js users.
    validate_path(&archive_path)?;
    validate_path(&output_dir)?;

    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    let default_options = exarch_core::ExtractionOptions::default();
    let options_ref = options.map_or(&default_options, |o| o.as_core());

    // Run extraction synchronously with panic safety
    // CRITICAL: Never panic across FFI boundary
    let report = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        exarch_core::extract_archive_with_options(
            &archive_path,
            &output_dir,
            config_ref,
            options_ref,
        )
    }))
    .map_err(|_| Error::from_reason("Internal panic during archive extraction"))?
    .map_err(convert_error)?;

    Ok(ExtractionReport::from(report))
}

/// Create an archive from source files and directories (async).
///
/// # Arguments
///
/// * `output_path` - Path to output archive file
/// * `sources` - Array of source files/directories to include
/// * `config` - Optional `CreationConfig` (uses defaults if omitted)
///
/// # Returns
///
/// Promise resolving to `CreationReport` with creation statistics
///
/// # Errors
///
/// Returns error if path validation fails, archive creation fails, or I/O
/// errors occur.
///
/// # Examples
///
/// ```javascript
/// // Use defaults
/// const report = await createArchive('output.tar.gz', ['source_dir/']);
/// console.log(`Created archive with ${report.filesAdded} files`);
///
/// // Customize configuration
/// const config = new CreationConfig().compressionLevel(9);
/// const report = await createArchive('output.tar.gz', ['src/'], config);
/// ```
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub async fn create_archive(
    output_path: String,
    sources: Vec<String>,
    config: Option<&CreationConfig>,
) -> Result<CreationReport> {
    validate_path(&output_path)?;
    for source in &sources {
        validate_path(source)?;
    }

    // Get owned config - clone only when config is Some, use default otherwise
    let config_owned: exarch_core::creation::CreationConfig =
        config.map(|c| c.as_core().clone()).unwrap_or_default();

    let report = tokio::task::spawn_blocking(move || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let sources_refs: Vec<&str> = sources.iter().map(String::as_str).collect();
            exarch_core::create_archive(&output_path, &sources_refs, &config_owned)
                .map_err(convert_error)
        }))
        .map_err(|_| Error::from_reason("Internal panic during archive creation"))
        .flatten()
    })
    .await
    .map_err(|e| Error::from_reason(format!("task join error: {e}")))
    .flatten()?;

    Ok(CreationReport::from(report))
}

/// Create an archive from source files and directories (sync).
///
/// Synchronous version of `createArchive`. Blocks the event loop until
/// creation completes. Prefer the async version for most use cases.
///
/// # Arguments
///
/// * `output_path` - Path to output archive file
/// * `sources` - Array of source files/directories to include
/// * `config` - Optional `CreationConfig` (uses defaults if omitted)
///
/// # Returns
///
/// `CreationReport` with creation statistics
///
/// # Errors
///
/// Returns error if path validation fails, archive creation fails, or I/O
/// errors occur.
///
/// # Examples
///
/// ```javascript
/// // Use defaults
/// const report = createArchiveSync('output.tar.gz', ['source_dir/']);
/// console.log(`Created archive with ${report.filesAdded} files`);
/// ```
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn create_archive_sync(
    output_path: String,
    sources: Vec<String>,
    config: Option<&CreationConfig>,
) -> Result<CreationReport> {
    validate_path(&output_path)?;
    for source in &sources {
        validate_path(source)?;
    }

    let default_config = exarch_core::creation::CreationConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    let sources_refs: Vec<&str> = sources.iter().map(String::as_str).collect();

    let report = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        exarch_core::create_archive(&output_path, &sources_refs, config_ref)
    }))
    .map_err(|_| Error::from_reason("Internal panic during archive creation"))?
    .map_err(convert_error)?;

    Ok(CreationReport::from(report))
}

/// List archive contents without extracting (async).
///
/// # Arguments
///
/// * `archive_path` - Path to archive file
/// * `config` - Optional `SecurityConfig` (uses secure defaults if omitted)
///
/// # Returns
///
/// Promise resolving to `ArchiveManifest` with entry metadata
///
/// # Errors
///
/// Returns error if path validation fails, archive is invalid, or I/O errors
/// occur.
///
/// # Examples
///
/// ```javascript
/// const manifest = await listArchive('archive.tar.gz');
/// for (const entry of manifest.entries) {
///     console.log(`${entry.path}: ${entry.size} bytes`);
/// }
/// ```
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub async fn list_archive(
    archive_path: String,
    config: Option<&SecurityConfig>,
) -> Result<ArchiveManifest> {
    validate_path(&archive_path)?;

    // Get owned config - clone only when config is Some, use default otherwise
    let config_owned: exarch_core::SecurityConfig =
        config.map(|c| c.as_core().clone()).unwrap_or_default();

    let manifest = tokio::task::spawn_blocking(move || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            exarch_core::list_archive(&archive_path, &config_owned).map_err(convert_error)
        }))
        .map_err(|_| Error::from_reason("Internal panic during archive listing"))
        .flatten()
    })
    .await
    .map_err(|e| Error::from_reason(format!("task join error: {e}")))
    .flatten()?;

    Ok(ArchiveManifest::from(manifest))
}

/// List archive contents without extracting (sync).
///
/// Synchronous version of `listArchive`. Blocks the event loop until
/// listing completes. Prefer the async version for most use cases.
///
/// # Arguments
///
/// * `archive_path` - Path to archive file
/// * `config` - Optional `SecurityConfig` (uses secure defaults if omitted)
///
/// # Returns
///
/// `ArchiveManifest` with entry metadata
///
/// # Errors
///
/// Returns error if path validation fails, archive is invalid, or I/O errors
/// occur.
///
/// # Examples
///
/// ```javascript
/// const manifest = listArchiveSync('archive.tar.gz');
/// for (const entry of manifest.entries) {
///     console.log(`${entry.path}: ${entry.size} bytes`);
/// }
/// ```
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn list_archive_sync(
    archive_path: String,
    config: Option<&SecurityConfig>,
) -> Result<ArchiveManifest> {
    validate_path(&archive_path)?;

    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    let manifest = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        exarch_core::list_archive(&archive_path, config_ref)
    }))
    .map_err(|_| Error::from_reason("Internal panic during archive listing"))?
    .map_err(convert_error)?;

    Ok(ArchiveManifest::from(manifest))
}

/// Verify archive integrity and security (async).
///
/// # Arguments
///
/// * `archive_path` - Path to archive file
/// * `config` - Optional `SecurityConfig` (uses secure defaults if omitted)
///
/// # Returns
///
/// Promise resolving to `VerificationReport` with validation results
///
/// # Errors
///
/// Returns error if path validation fails, archive is invalid, or I/O errors
/// occur.
///
/// # Examples
///
/// ```javascript
/// const report = await verifyArchive('archive.tar.gz');
/// if (report.status === 'PASS') {
///     console.log('Archive is safe to extract');
/// } else {
///     for (const issue of report.issues) {
///         console.log(`[${issue.severity}] ${issue.message}`);
///     }
/// }
/// ```
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub async fn verify_archive(
    archive_path: String,
    config: Option<&SecurityConfig>,
) -> Result<VerificationReport> {
    validate_path(&archive_path)?;

    // Get owned config - clone only when config is Some, use default otherwise
    let config_owned: exarch_core::SecurityConfig =
        config.map(|c| c.as_core().clone()).unwrap_or_default();

    let report = tokio::task::spawn_blocking(move || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            exarch_core::verify_archive(&archive_path, &config_owned).map_err(convert_error)
        }))
        .map_err(|_| Error::from_reason("Internal panic during archive verification"))
        .flatten()
    })
    .await
    .map_err(|e| Error::from_reason(format!("task join error: {e}")))
    .flatten()?;

    Ok(VerificationReport::from(report))
}

/// Verify archive integrity and security (sync).
///
/// Synchronous version of `verifyArchive`. Blocks the event loop until
/// verification completes. Prefer the async version for most use cases.
///
/// # Arguments
///
/// * `archive_path` - Path to archive file
/// * `config` - Optional `SecurityConfig` (uses secure defaults if omitted)
///
/// # Returns
///
/// `VerificationReport` with validation results
///
/// # Errors
///
/// Returns error if path validation fails, archive is invalid, or I/O errors
/// occur.
///
/// # Examples
///
/// ```javascript
/// const report = verifyArchiveSync('archive.tar.gz');
/// if (report.status === 'PASS') {
///     console.log('Archive is safe to extract');
/// }
/// ```
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn verify_archive_sync(
    archive_path: String,
    config: Option<&SecurityConfig>,
) -> Result<VerificationReport> {
    validate_path(&archive_path)?;

    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    let report = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        exarch_core::verify_archive(&archive_path, config_ref)
    }))
    .map_err(|_| Error::from_reason("Internal panic during archive verification"))?
    .map_err(convert_error)?;

    Ok(VerificationReport::from(report))
}

/// Extract an archive to the specified directory with a progress callback
/// (async).
///
/// The `progress` callback is called once per entry with
/// `(path, total, current, bytesWritten)` where:
/// - `path` — entry path inside the archive
/// - `total` — total number of entries as `number` (0 for TAR-family formats
///   because the entry count is unknown until the stream is fully read)
/// - `current` — 1-based index of the current entry as `number`
/// - `bytesWritten` — cumulative bytes written to disk so far as `number`
///   (always 0 during extraction because the core library does not emit
///   byte-level progress events for extraction; only entry-level events fire)
///
/// Extraction runs on the tokio blocking thread pool. The progress callback is
/// dispatched back to the JavaScript thread via a threadsafe function.
///
/// # Arguments
///
/// * `archive_path` - Path to the archive file
/// * `output_dir` - Directory where files will be extracted
/// * `config` - Optional `SecurityConfig` (uses secure defaults if omitted)
/// * `options` - Optional `ExtractionOptions` (uses defaults if omitted)
/// * `progress` - Optional progress callback `(path: string, total: number,
///   current: number, bytesWritten: number) => void`
///
/// # Returns
///
/// Promise resolving to `ExtractionReport` with extraction statistics
///
/// # Errors
///
/// Returns error for security violations or I/O errors. Error messages are
/// prefixed with error codes for discrimination in JavaScript. See
/// `extractArchive` for the full list of error codes.
///
/// # Examples
///
/// ```javascript
/// const report = await extractArchiveWithProgress(
///   'archive.tar.gz',
///   '/tmp/output',
///   null,
///   null,
///   (path, total, current, bytesWritten) => {
///     console.log(`${current}/${total}: ${path}`);
///   },
/// );
/// console.log(`Extracted ${report.filesExtracted} files`);
/// ```
#[napi]
#[allow(clippy::needless_pass_by_value, clippy::trailing_empty_array)]
pub async fn extract_archive_with_progress(
    archive_path: String,
    output_dir: String,
    config: Option<&SecurityConfig>,
    options: Option<&ExtractionOptions>,
    progress: Option<ThreadsafeFunction<(String, i64, i64, i64)>>,
) -> Result<ExtractionReport> {
    validate_path(&archive_path)?;
    validate_path(&output_dir)?;

    let config_owned: exarch_core::SecurityConfig =
        config.map(|c| c.as_core().clone()).unwrap_or_default();
    let options_owned: exarch_core::ExtractionOptions =
        options.map(|o| o.as_core().clone()).unwrap_or_default();

    let report = tokio::task::spawn_blocking(move || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_extract_with_optional_progress(
                &archive_path,
                &output_dir,
                &config_owned,
                &options_owned,
                progress,
            )
            .map_err(convert_error)
        }))
        .map_err(|_| Error::from_reason("Internal panic during archive extraction with progress"))
        .flatten()
    })
    .await
    .map_err(|e| Error::from_reason(format!("task join error: {e}")))
    .flatten()?;

    Ok(ExtractionReport::from(report))
}

/// Runs `extract_archive_with_options_and_progress` routing to the JS callback
/// when present or to [`exarch_core::NoopProgress`] when absent.
fn run_extract_with_optional_progress(
    archive_path: &str,
    output_dir: &str,
    config: &exarch_core::SecurityConfig,
    options: &exarch_core::ExtractionOptions,
    progress: Option<ThreadsafeFunction<(String, i64, i64, i64)>>,
) -> exarch_core::Result<exarch_core::ExtractionReport> {
    progress.map_or_else(
        || {
            let mut noop = exarch_core::NoopProgress;
            exarch_core::extract_archive_with_options_and_progress(
                archive_path,
                output_dir,
                config,
                options,
                &mut noop,
            )
        },
        |tsfn| {
            let mut callback = NodeProgressAdapter::new(tsfn);
            exarch_core::extract_archive_with_options_and_progress(
                archive_path,
                output_dir,
                config,
                options,
                &mut callback,
            )
        },
    )
}

/// Adapter that calls a JavaScript progress callback from a Rust worker thread.
///
/// The JavaScript callback receives `(path: string, total: number, current:
/// number, bytesWritten: number)` where `bytesWritten` is the number of bytes
/// written **for the current entry so far** (starts at 0 when the entry begins,
/// grows as chunks are flushed to disk; always 0 during extraction because the
/// core library does not emit byte-level progress events for extraction).
struct NodeProgressAdapter {
    tsfn: ThreadsafeFunction<(String, i64, i64, i64)>,
    current_entry_bytes: i64,
    total: usize,
}

impl NodeProgressAdapter {
    fn new(tsfn: ThreadsafeFunction<(String, i64, i64, i64)>) -> Self {
        Self {
            tsfn,
            current_entry_bytes: 0,
            total: 0,
        }
    }
}

impl exarch_core::ProgressCallback for NodeProgressAdapter {
    fn on_entry_start(&mut self, path: &std::path::Path, total: usize, current: usize) {
        self.current_entry_bytes = 0;
        self.total = total;
        let path_str = path.to_string_lossy().into_owned();
        let total_i64 = i64::try_from(total).unwrap_or(i64::MAX);
        let current_i64 = i64::try_from(current).unwrap_or(i64::MAX);
        self.tsfn.call(
            Ok((path_str, total_i64, current_i64, self.current_entry_bytes)),
            ThreadsafeFunctionCallMode::NonBlocking,
        );
    }

    fn on_bytes_written(&mut self, bytes: u64) {
        self.current_entry_bytes = self.current_entry_bytes.saturating_add(bytes.cast_signed());
    }

    fn on_entry_complete(&mut self, _path: &std::path::Path) {}

    fn on_complete(&mut self) {}
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::uninlined_format_args,
    clippy::manual_string_new
)]
mod tests {
    use super::*;

    // CR-004: Path validation tests
    #[tokio::test]
    async fn test_extract_archive_rejects_null_byte_in_archive_path() {
        let result = extract_archive(
            "/tmp/test\0malicious.tar".to_string(),
            "/tmp/output".to_string(),
            None,
            None,
        )
        .await;

        assert!(result.is_err(), "should reject null bytes in archive path");
        assert!(
            result.unwrap_err().to_string().contains("null bytes"),
            "error message should mention null bytes"
        );
    }

    #[tokio::test]
    async fn test_extract_archive_rejects_null_byte_in_output_dir() {
        let result = extract_archive(
            "/tmp/test.tar".to_string(),
            "/tmp/output\0malicious".to_string(),
            None,
            None,
        )
        .await;

        assert!(result.is_err(), "should reject null bytes in output path");
        assert!(
            result.unwrap_err().to_string().contains("null bytes"),
            "error message should mention null bytes"
        );
    }

    #[tokio::test]
    async fn test_extract_archive_rejects_excessively_long_archive_path() {
        let long_path = "x".repeat(5000);
        let result = extract_archive(long_path, "/tmp/output".to_string(), None, None).await;

        assert!(result.is_err(), "should reject excessively long paths");
        assert!(
            result.unwrap_err().to_string().contains("maximum length"),
            "error message should mention length limit"
        );
    }

    #[tokio::test]
    async fn test_extract_archive_rejects_excessively_long_output_dir() {
        let long_path = "x".repeat(5000);
        let result = extract_archive("/tmp/test.tar".to_string(), long_path, None, None).await;

        assert!(result.is_err(), "should reject excessively long paths");
        assert!(
            result.unwrap_err().to_string().contains("maximum length"),
            "error message should mention length limit"
        );
    }

    #[tokio::test]
    async fn test_extract_archive_accepts_empty_paths() {
        // Empty paths should be accepted at boundary validation
        // Core library will handle actual path validation
        let result = extract_archive("".to_string(), "".to_string(), None, None).await;

        // If it fails, ensure it's not a boundary path validation error
        // (empty paths pass boundary validation; core handles semantic validation)
        if let Err(e) = result {
            let err_msg = e.to_string();
            assert!(
                !err_msg.contains("null bytes") && !err_msg.contains("maximum length"),
                "should not fail on boundary path validation, got: {}",
                err_msg
            );
        }
        // If it succeeds, boundary validation passed (which is what we're
        // testing)
    }

    #[test]
    fn test_extract_archive_sync_rejects_null_byte_in_archive_path() {
        let result = extract_archive_sync(
            "/tmp/test\0malicious.tar".to_string(),
            "/tmp/output".to_string(),
            None,
            None,
        );

        assert!(result.is_err(), "should reject null bytes in archive path");
        assert!(
            result.unwrap_err().to_string().contains("null bytes"),
            "error message should mention null bytes"
        );
    }

    #[test]
    fn test_extract_archive_sync_rejects_null_byte_in_output_dir() {
        let result = extract_archive_sync(
            "/tmp/test.tar".to_string(),
            "/tmp/output\0malicious".to_string(),
            None,
            None,
        );

        assert!(result.is_err(), "should reject null bytes in output path");
        assert!(
            result.unwrap_err().to_string().contains("null bytes"),
            "error message should mention null bytes"
        );
    }

    #[test]
    fn test_extract_archive_sync_rejects_excessively_long_archive_path() {
        let long_path = "x".repeat(5000);
        let result = extract_archive_sync(long_path, "/tmp/output".to_string(), None, None);

        assert!(result.is_err(), "should reject excessively long paths");
        assert!(
            result.unwrap_err().to_string().contains("maximum length"),
            "error message should mention length limit"
        );
    }

    #[test]
    fn test_extract_archive_sync_rejects_excessively_long_output_dir() {
        let long_path = "x".repeat(5000);
        let result = extract_archive_sync("/tmp/test.tar".to_string(), long_path, None, None);

        assert!(result.is_err(), "should reject excessively long paths");
        assert!(
            result.unwrap_err().to_string().contains("maximum length"),
            "error message should mention length limit"
        );
    }

    #[test]
    fn test_extract_archive_sync_accepts_valid_paths() {
        // Test that valid paths pass boundary validation
        // The actual extraction may succeed (empty archive) or fail (file not found)
        // but should NOT fail due to path validation
        let result = extract_archive_sync(
            "/tmp/valid_test_path.tar".to_string(),
            "/tmp/valid_output_path".to_string(),
            None,
            None,
        );

        // If it fails, ensure it's not a path validation error
        if let Err(e) = result {
            let err_msg = e.to_string();
            assert!(
                !err_msg.contains("null bytes") && !err_msg.contains("maximum length"),
                "should not fail on path validation, got: {}",
                err_msg
            );
        }
        // If it succeeds, path validation passed (which is what we're testing)
    }

    #[test]
    fn test_extract_archive_sync_accepts_relative_paths() {
        // Test that valid relative paths pass boundary validation
        let result = extract_archive_sync(
            "relative_test.tar".to_string(),
            "relative_output".to_string(),
            None,
            None,
        );

        // If it fails, ensure it's not a path validation error
        if let Err(e) = result {
            let err_msg = e.to_string();
            assert!(
                !err_msg.contains("null bytes") && !err_msg.contains("maximum length"),
                "should not fail on path validation for relative paths, got: {}",
                err_msg
            );
        }
        // If it succeeds, path validation passed (which is what we're testing)
    }

    #[test]
    fn test_extract_archive_sync_with_custom_config() {
        let mut config = SecurityConfig::new();
        config.set_max_file_size(1_000_000).unwrap();

        // Test that valid paths pass boundary validation with custom config
        let result = extract_archive_sync(
            "custom_test.tar".to_string(),
            "custom_output".to_string(),
            Some(&config),
            None,
        );

        // If it fails, ensure it's not a path validation error
        if let Err(e) = result {
            let err_msg = e.to_string();
            assert!(
                !err_msg.contains("null bytes") && !err_msg.contains("maximum length"),
                "should not fail on path validation, got: {}",
                err_msg
            );
        }
        // If it succeeds, path validation passed (which is what we're testing)
    }

    // CR-004: create_archive path validation tests
    #[tokio::test]
    async fn test_create_archive_rejects_null_byte_in_output_path() {
        let result = create_archive(
            "/tmp/output\0malicious.tar".to_string(),
            vec!["source/".to_string()],
            None,
        )
        .await;

        assert!(result.is_err(), "should reject null bytes in output path");
        assert!(
            result.unwrap_err().to_string().contains("null bytes"),
            "error message should mention null bytes"
        );
    }

    #[tokio::test]
    async fn test_create_archive_rejects_null_byte_in_source_path() {
        let result = create_archive(
            "/tmp/output.tar".to_string(),
            vec!["source\0malicious/".to_string()],
            None,
        )
        .await;

        assert!(result.is_err(), "should reject null bytes in source path");
        assert!(
            result.unwrap_err().to_string().contains("null bytes"),
            "error message should mention null bytes"
        );
    }

    #[tokio::test]
    async fn test_create_archive_rejects_excessively_long_output_path() {
        let long_path = "x".repeat(5000);
        let result = create_archive(long_path, vec!["source/".to_string()], None).await;

        assert!(result.is_err(), "should reject excessively long paths");
        assert!(
            result.unwrap_err().to_string().contains("maximum length"),
            "error message should mention length limit"
        );
    }

    #[tokio::test]
    async fn test_create_archive_rejects_excessively_long_source_path() {
        let long_path = "x".repeat(5000);
        let result = create_archive("/tmp/output.tar".to_string(), vec![long_path], None).await;

        assert!(result.is_err(), "should reject excessively long paths");
        assert!(
            result.unwrap_err().to_string().contains("maximum length"),
            "error message should mention length limit"
        );
    }

    #[tokio::test]
    async fn test_create_archive_accepts_empty_sources_array() {
        // Empty sources array should pass boundary validation
        // Core library will handle actual validation
        let result = create_archive("/tmp/output.tar".to_string(), vec![], None).await;

        // If it fails, ensure it's not a boundary path validation error
        if let Err(e) = result {
            let err_msg = e.to_string();
            assert!(
                !err_msg.contains("null bytes") && !err_msg.contains("maximum length"),
                "should not fail on boundary path validation, got: {}",
                err_msg
            );
        }
    }

    #[test]
    fn test_create_archive_sync_rejects_null_byte_in_output_path() {
        let result = create_archive_sync(
            "/tmp/output\0malicious.tar".to_string(),
            vec!["source/".to_string()],
            None,
        );

        assert!(result.is_err(), "should reject null bytes in output path");
        assert!(
            result.unwrap_err().to_string().contains("null bytes"),
            "error message should mention null bytes"
        );
    }

    #[test]
    fn test_create_archive_sync_rejects_null_byte_in_source_path() {
        let result = create_archive_sync(
            "/tmp/output.tar".to_string(),
            vec!["source\0malicious/".to_string()],
            None,
        );

        assert!(result.is_err(), "should reject null bytes in source path");
        assert!(
            result.unwrap_err().to_string().contains("null bytes"),
            "error message should mention null bytes"
        );
    }

    #[test]
    fn test_create_archive_sync_rejects_excessively_long_output_path() {
        let long_path = "x".repeat(5000);
        let result = create_archive_sync(long_path, vec!["source/".to_string()], None);

        assert!(result.is_err(), "should reject excessively long paths");
        assert!(
            result.unwrap_err().to_string().contains("maximum length"),
            "error message should mention length limit"
        );
    }

    #[test]
    fn test_create_archive_sync_rejects_excessively_long_source_path() {
        let long_path = "x".repeat(5000);
        let result = create_archive_sync("/tmp/output.tar".to_string(), vec![long_path], None);

        assert!(result.is_err(), "should reject excessively long paths");
        assert!(
            result.unwrap_err().to_string().contains("maximum length"),
            "error message should mention length limit"
        );
    }

    #[test]
    fn test_create_archive_sync_accepts_empty_sources_array() {
        // Empty sources array should pass boundary validation
        let result = create_archive_sync("/tmp/output.tar".to_string(), vec![], None);

        // If it fails, ensure it's not a boundary path validation error
        if let Err(e) = result {
            let err_msg = e.to_string();
            assert!(
                !err_msg.contains("null bytes") && !err_msg.contains("maximum length"),
                "should not fail on boundary path validation, got: {}",
                err_msg
            );
        }
    }

    // CR-004: list_archive path validation tests
    #[tokio::test]
    async fn test_list_archive_rejects_null_byte_in_archive_path() {
        let result = list_archive("/tmp/test\0malicious.tar".to_string(), None).await;

        assert!(result.is_err(), "should reject null bytes in archive path");
        assert!(
            result.unwrap_err().to_string().contains("null bytes"),
            "error message should mention null bytes"
        );
    }

    #[tokio::test]
    async fn test_list_archive_rejects_excessively_long_archive_path() {
        let long_path = "x".repeat(5000);
        let result = list_archive(long_path, None).await;

        assert!(result.is_err(), "should reject excessively long paths");
        assert!(
            result.unwrap_err().to_string().contains("maximum length"),
            "error message should mention length limit"
        );
    }

    #[test]
    fn test_list_archive_sync_rejects_null_byte_in_archive_path() {
        let result = list_archive_sync("/tmp/test\0malicious.tar".to_string(), None);

        assert!(result.is_err(), "should reject null bytes in archive path");
        assert!(
            result.unwrap_err().to_string().contains("null bytes"),
            "error message should mention null bytes"
        );
    }

    #[test]
    fn test_list_archive_sync_rejects_excessively_long_archive_path() {
        let long_path = "x".repeat(5000);
        let result = list_archive_sync(long_path, None);

        assert!(result.is_err(), "should reject excessively long paths");
        assert!(
            result.unwrap_err().to_string().contains("maximum length"),
            "error message should mention length limit"
        );
    }

    // CR-004: verify_archive path validation tests
    #[tokio::test]
    async fn test_verify_archive_rejects_null_byte_in_archive_path() {
        let result = verify_archive("/tmp/test\0malicious.tar".to_string(), None).await;

        assert!(result.is_err(), "should reject null bytes in archive path");
        assert!(
            result.unwrap_err().to_string().contains("null bytes"),
            "error message should mention null bytes"
        );
    }

    #[tokio::test]
    async fn test_verify_archive_rejects_excessively_long_archive_path() {
        let long_path = "x".repeat(5000);
        let result = verify_archive(long_path, None).await;

        assert!(result.is_err(), "should reject excessively long paths");
        assert!(
            result.unwrap_err().to_string().contains("maximum length"),
            "error message should mention length limit"
        );
    }

    #[test]
    fn test_verify_archive_sync_rejects_null_byte_in_archive_path() {
        let result = verify_archive_sync("/tmp/test\0malicious.tar".to_string(), None);

        assert!(result.is_err(), "should reject null bytes in archive path");
        assert!(
            result.unwrap_err().to_string().contains("null bytes"),
            "error message should mention null bytes"
        );
    }

    #[test]
    fn test_verify_archive_sync_rejects_excessively_long_archive_path() {
        let long_path = "x".repeat(5000);
        let result = verify_archive_sync(long_path, None);

        assert!(result.is_err(), "should reject excessively long paths");
        assert!(
            result.unwrap_err().to_string().contains("maximum length"),
            "error message should mention length limit"
        );
    }
}
