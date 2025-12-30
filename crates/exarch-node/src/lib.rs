//! Node.js bindings for exarch-core.

use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Extraction report returned to JavaScript.
#[napi(object)]
pub struct ExtractionReport {
    /// Number of files extracted.
    pub files_extracted: u32,
    /// Total bytes written.
    pub bytes_written: i64,
    /// Extraction duration in milliseconds.
    pub duration_ms: i64,
}

/// Extract an archive to the specified directory.
///
/// # Arguments
///
/// * `archive_path` - Path to the archive file
/// * `output_dir` - Directory where files will be extracted
///
/// # Returns
///
/// Object with extraction statistics
///
/// # Errors
///
/// Returns an error if extraction fails or security checks are violated.
#[napi]
#[allow(clippy::needless_pass_by_value)] // NAPI requires owned String
pub fn extract_archive(archive_path: String, output_dir: String) -> Result<ExtractionReport> {
    let config = exarch_core::SecurityConfig::default();

    match exarch_core::extract_archive(&archive_path, &output_dir, &config) {
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        Ok(report) => Ok(ExtractionReport {
            files_extracted: report.files_extracted as u32,
            bytes_written: report.bytes_written as i64,
            duration_ms: report.duration.as_millis() as i64,
        }),
        Err(e) => Err(Error::new(
            Status::GenericFailure,
            format!("Extraction failed: {e}"),
        )),
    }
}
