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

use napi::bindgen_prelude::*;
use napi_derive::napi;

mod config;
mod error;
mod report;
mod utils;

use config::SecurityConfig;
use error::convert_error;
use report::ExtractionReport;
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
/// const config = new SecurityConfig().maxFileSize(100 * 1024 * 1024);
/// const report = await extractArchive('archive.tar.gz', '/tmp/output', config);
/// ```
#[napi]
#[allow(clippy::needless_pass_by_value, clippy::trailing_empty_array)]
pub async fn extract_archive(
    archive_path: String,
    output_dir: String,
    config: Option<&SecurityConfig>,
) -> Result<ExtractionReport> {
    // Validate paths at boundary
    // NOTE: Defense-in-depth - paths are validated here and again in core
    // library. This boundary validation catches issues early and provides
    // better error messages for Node.js users.
    validate_path(&archive_path)?;
    validate_path(&output_dir)?;

    // Get config reference or use default
    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    // Use Arc to share config across thread boundary without cloning
    let config_arc = std::sync::Arc::new(config_ref.clone());

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
        exarch_core::extract_archive(&archive_path, &output_dir, &config_arc)
    })
    .await
    .map_err(|e| Error::from_reason(format!("task execution failed: {e}")))?
    .map_err(convert_error)?;

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
/// const config = new SecurityConfig().maxFileSize(100 * 1024 * 1024);
/// const report = extractArchiveSync('archive.tar.gz', '/tmp/output', config);
/// ```
#[napi]
#[allow(clippy::needless_pass_by_value)]
pub fn extract_archive_sync(
    archive_path: String,
    output_dir: String,
    config: Option<&SecurityConfig>,
) -> Result<ExtractionReport> {
    // Validate paths at boundary
    // NOTE: Defense-in-depth - paths are validated here and again in core
    // library. This boundary validation catches issues early and provides
    // better error messages for Node.js users.
    validate_path(&archive_path)?;
    validate_path(&output_dir)?;

    // Get config reference or use default
    let default_config = exarch_core::SecurityConfig::default();
    let config_ref = config.map_or(&default_config, |c| c.as_core());

    // Run extraction synchronously
    let report = exarch_core::extract_archive(&archive_path, &output_dir, config_ref)
        .map_err(convert_error)?;

    Ok(ExtractionReport::from(report))
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

    #[test]
    fn test_module_exports_functions() {
        // This test just ensures the module compiles and exports the expected
        // functions. Runtime tests would require actual archive files.
    }

    // CR-004: Path validation tests
    #[tokio::test]
    async fn test_extract_archive_rejects_null_byte_in_archive_path() {
        let result = extract_archive(
            "/tmp/test\0malicious.tar".to_string(),
            "/tmp/output".to_string(),
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
        let result = extract_archive(long_path, "/tmp/output".to_string(), None).await;

        assert!(result.is_err(), "should reject excessively long paths");
        assert!(
            result.unwrap_err().to_string().contains("maximum length"),
            "error message should mention length limit"
        );
    }

    #[tokio::test]
    async fn test_extract_archive_rejects_excessively_long_output_dir() {
        let long_path = "x".repeat(5000);
        let result = extract_archive("/tmp/test.tar".to_string(), long_path, None).await;

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
        let result = extract_archive("".to_string(), "".to_string(), None).await;

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
        let result = extract_archive_sync(long_path, "/tmp/output".to_string(), None);

        assert!(result.is_err(), "should reject excessively long paths");
        assert!(
            result.unwrap_err().to_string().contains("maximum length"),
            "error message should mention length limit"
        );
    }

    #[test]
    fn test_extract_archive_sync_rejects_excessively_long_output_dir() {
        let long_path = "x".repeat(5000);
        let result = extract_archive_sync("/tmp/test.tar".to_string(), long_path, None);

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
        config.max_file_size(1_000_000).unwrap();

        // Test that valid paths pass boundary validation with custom config
        let result = extract_archive_sync(
            "custom_test.tar".to_string(),
            "custom_output".to_string(),
            Some(&config),
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
}
