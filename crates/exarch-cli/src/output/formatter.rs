//! Output formatter trait for CLI results.

use anyhow::Result;
use exarch_core::ExtractionReport;
use serde::Serialize;

/// Common output formatter trait
pub trait OutputFormatter {
    /// Format extraction result
    fn format_extraction_result(&self, report: &ExtractionReport) -> Result<()>;

    /// Format error message
    #[allow(dead_code)]
    fn format_error(&self, error: &anyhow::Error);

    /// Format success message
    #[allow(dead_code)]
    fn format_success(&self, message: &str);

    /// Format warning message
    fn format_warning(&self, message: &str);
}

/// Generic JSON output structure
#[derive(Debug, Serialize)]
pub struct JsonOutput<T> {
    pub operation: String,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
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

    #[allow(dead_code)]
    pub fn error(operation: impl Into<String>, error: impl Into<String>) -> JsonOutput<()> {
        JsonOutput {
            operation: operation.into(),
            status: Status::Error,
            data: None,
            error: Some(error.into()),
        }
    }
}
