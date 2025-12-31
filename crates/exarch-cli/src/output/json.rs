//! JSON output formatter for machine-readable results.

use super::formatter::JsonOutput;
use super::formatter::OutputFormatter;
use anyhow::Result;
use exarch_core::CreationReport;
use exarch_core::ExtractionReport;
use serde::Serialize;
use std::io::Write;
use std::io::{self};
use std::path::Path;

pub struct JsonFormatter;

impl JsonFormatter {
    fn output<T: Serialize>(value: &T) -> Result<()> {
        let json = serde_json::to_string_pretty(value)?;
        writeln!(io::stdout(), "{json}")?;
        Ok(())
    }
}

impl OutputFormatter for JsonFormatter {
    fn format_extraction_result(&self, report: &ExtractionReport) -> Result<()> {
        #[derive(Serialize)]
        struct ExtractionOutput {
            files_extracted: usize,
            directories_created: usize,
            symlinks_created: usize,
            bytes_written: u64,
            duration_ms: u128,
        }

        let data = ExtractionOutput {
            files_extracted: report.files_extracted,
            directories_created: report.directories_created,
            symlinks_created: report.symlinks_created,
            bytes_written: report.bytes_written,
            duration_ms: report.duration.as_millis(),
        };

        let output = JsonOutput::success("extract", data);
        Self::output(&output)
    }

    fn format_creation_result(&self, output_path: &Path, report: &CreationReport) -> Result<()> {
        #[derive(Serialize)]
        struct CreationOutput {
            output_path: String,
            files_added: usize,
            directories_added: usize,
            symlinks_added: usize,
            bytes_written: u64,
            bytes_compressed: u64,
            compression_ratio: f64,
            compression_percentage: f64,
            files_skipped: usize,
            duration_ms: u128,
            warnings: Vec<String>,
        }

        let data = CreationOutput {
            output_path: output_path.display().to_string(),
            files_added: report.files_added,
            directories_added: report.directories_added,
            symlinks_added: report.symlinks_added,
            bytes_written: report.bytes_written,
            bytes_compressed: report.bytes_compressed,
            compression_ratio: report.compression_ratio(),
            compression_percentage: report.compression_percentage(),
            files_skipped: report.files_skipped,
            duration_ms: report.duration.as_millis(),
            warnings: report.warnings.clone(),
        };

        let output = JsonOutput::success("create", data);
        Self::output(&output)
    }

    fn format_error(&self, error: &anyhow::Error) {
        let output = JsonOutput::<()>::error("unknown", format!("{error:?}"));
        let _ = Self::output(&output);
    }

    fn format_success(&self, message: &str) {
        #[derive(Serialize)]
        struct SuccessData {
            message: String,
        }

        let output = JsonOutput::success(
            "unknown",
            SuccessData {
                message: message.to_string(),
            },
        );
        let _ = Self::output(&output);
    }

    fn format_warning(&self, message: &str) {
        #[derive(Serialize)]
        struct WarningData {
            message: String,
        }

        let output = JsonOutput::success(
            "warning",
            WarningData {
                message: message.to_string(),
            },
        );
        let _ = Self::output(&output);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_json_formatter_output_structure() {
        #[derive(Serialize)]
        struct TestData {
            value: String,
        }

        let data = TestData {
            value: "test".to_string(),
        };

        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("\"value\""));
        assert!(json.contains("\"test\""));
    }
}
