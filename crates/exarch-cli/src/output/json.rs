//! JSON output formatter for machine-readable results.

use super::formatter::JsonOutput;
use super::formatter::OutputFormatter;
use anyhow::Result;
use exarch_core::ExtractionReport;
use serde::Serialize;
use std::io::Write;
use std::io::{self};

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
