//! Output formatter trait for CLI results.

use anyhow::Result;
use exarch_core::ArchiveManifest;
use exarch_core::CreationReport;
use exarch_core::ExtractionReport;
use exarch_core::PartialWrites;
use exarch_core::PolicySetting;
use exarch_core::VerificationReport;
use serde::Serialize;
use std::path::Path;

/// Common output formatter trait
pub trait OutputFormatter {
    /// Format extraction result
    fn format_extraction_result(&mut self, report: &ExtractionReport) -> Result<()>;

    /// Format archive creation result
    fn format_creation_result(&mut self, output_path: &Path, report: &CreationReport)
    -> Result<()>;

    /// Format archive manifest (short format - paths only)
    fn format_manifest_short(&mut self, manifest: &ArchiveManifest) -> Result<()>;

    /// Format archive manifest (long format - detailed)
    fn format_manifest_long(
        &mut self,
        manifest: &ArchiveManifest,
        human_readable: bool,
    ) -> Result<()>;

    /// Format verification report
    fn format_verification_report(&mut self, report: &VerificationReport) -> Result<()>;

    /// Format error message for the given operation
    fn format_error(&mut self, operation: &str, error: &anyhow::Error);
}

/// Generic JSON output structure
#[derive(Debug, Serialize)]
pub struct JsonOutput<T> {
    pub operation: String,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonError>,
}

/// Serializes a [`PartialWrites`] as its stable identifier.
#[derive(Debug, Clone, Copy)]
pub struct JsonWrites(pub PartialWrites);

impl Serialize for JsonWrites {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0.as_str())
    }
}

/// Serializes a [`PolicySetting`] as its stable identifier.
#[derive(Debug, Clone, Copy)]
pub struct JsonPolicySetting(pub PolicySetting);

impl Serialize for JsonPolicySetting {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0.as_str())
    }
}

/// Partial extraction report included in error JSON when extraction was stopped
/// mid-archive.
#[derive(Debug, Serialize)]
pub struct JsonPartialReport {
    pub files_extracted: usize,
    pub directories_created: usize,
    pub symlinks_created: usize,
    pub bytes_written: u64,
    pub files_skipped: usize,
    pub warnings: Vec<String>,
    pub writes: JsonWrites,
}

/// Structured error object in JSON output
#[derive(Debug, Serialize)]
pub struct JsonError {
    pub kind: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_report: Option<JsonPartialReport>,
    /// Stable id of the `SecurityConfig` setting whose current value refused
    /// the entry; present only for a `SecurityViolation` a setting relaxes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relaxable_by: Option<JsonPolicySetting>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Success,
    #[allow(dead_code)]
    Error,
}

impl<T: Serialize> JsonOutput<T> {
    pub fn success(operation: impl Into<String>, data: T) -> Self {
        Self {
            operation: operation.into(),
            status: Status::Success,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(
        operation: impl Into<String>,
        kind: impl Into<String>,
        message: impl Into<String>,
    ) -> JsonOutput<()> {
        JsonOutput {
            operation: operation.into(),
            status: Status::Error,
            data: None,
            error: Some(JsonError {
                kind: kind.into(),
                message: message.into(),
                partial_report: None,
                relaxable_by: None,
            }),
        }
    }

    pub fn error_with_partial(
        operation: impl Into<String>,
        kind: impl Into<String>,
        message: impl Into<String>,
        partial_report: JsonPartialReport,
    ) -> JsonOutput<()> {
        JsonOutput {
            operation: operation.into(),
            status: Status::Error,
            data: None,
            error: Some(JsonError {
                kind: kind.into(),
                message: message.into(),
                partial_report: Some(partial_report),
                relaxable_by: None,
            }),
        }
    }
}

impl JsonOutput<()> {
    /// Records the setting that refused the entry on an error envelope.
    #[must_use]
    pub fn with_relaxable_by(mut self, setting: Option<PolicySetting>) -> Self {
        if let Some(error) = self.error.as_mut() {
            error.relaxable_by = setting.map(JsonPolicySetting);
        }
        self
    }
}
