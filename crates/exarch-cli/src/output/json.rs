//! JSON output formatter for machine-readable results.

use super::formatter::JsonOutput;
use super::formatter::OutputFormatter;
use anyhow::Result;
use exarch_core::ArchiveManifest;
use exarch_core::CreationReport;
use exarch_core::ExtractionReport;
use exarch_core::VerificationReport;
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

    fn format_manifest_short(&self, manifest: &ArchiveManifest) -> Result<()> {
        #[derive(Serialize)]
        struct ManifestEntry {
            path: String,
        }

        #[derive(Serialize)]
        struct ManifestOutput {
            format: String,
            total_entries: usize,
            entries: Vec<ManifestEntry>,
        }

        let entries = manifest
            .entries
            .iter()
            .map(|e| ManifestEntry {
                path: e.path.display().to_string(),
            })
            .collect();

        let data = ManifestOutput {
            format: format!("{:?}", manifest.format),
            total_entries: manifest.total_entries,
            entries,
        };

        let output = JsonOutput::success("list", data);
        Self::output(&output)
    }

    fn format_manifest_long(
        &self,
        manifest: &ArchiveManifest,
        _human_readable: bool,
    ) -> Result<()> {
        #[derive(Serialize)]
        struct ManifestEntry {
            path: String,
            entry_type: String,
            size: u64,
            compressed_size: Option<u64>,
            mode: Option<u32>,
            modified: Option<u64>,
        }

        #[derive(Serialize)]
        struct ManifestOutput {
            format: String,
            total_entries: usize,
            total_size: u64,
            entries: Vec<ManifestEntry>,
        }

        let entries = manifest
            .entries
            .iter()
            .map(|e| ManifestEntry {
                path: e.path.display().to_string(),
                entry_type: format!("{}", e.entry_type),
                size: e.size,
                compressed_size: e.compressed_size,
                mode: e.mode,
                modified: e.modified.and_then(|t| {
                    t.duration_since(std::time::UNIX_EPOCH)
                        .ok()
                        .map(|d| d.as_secs())
                }),
            })
            .collect();

        let data = ManifestOutput {
            format: format!("{:?}", manifest.format),
            total_entries: manifest.total_entries,
            total_size: manifest.total_size,
            entries,
        };

        let output = JsonOutput::success("list", data);
        Self::output(&output)
    }

    fn format_verification_report(&self, report: &VerificationReport) -> Result<()> {
        #[derive(Serialize)]
        struct VerificationIssue {
            severity: String,
            category: String,
            entry_path: Option<String>,
            message: String,
            context: Option<String>,
        }

        #[derive(Serialize)]
        struct VerificationOutput {
            status: String,
            integrity_status: String,
            security_status: String,
            total_entries: usize,
            suspicious_entries: usize,
            total_size: u64,
            format: String,
            issues: Vec<VerificationIssue>,
        }

        let issues = report
            .issues
            .iter()
            .map(|i| VerificationIssue {
                severity: format!("{}", i.severity),
                category: format!("{}", i.category),
                entry_path: i.entry_path.as_ref().map(|p| p.display().to_string()),
                message: i.message.clone(),
                context: i.context.clone(),
            })
            .collect();

        let data = VerificationOutput {
            status: format!("{}", report.status),
            integrity_status: format!("{}", report.integrity_status),
            security_status: format!("{}", report.security_status),
            total_entries: report.total_entries,
            suspicious_entries: report.suspicious_entries,
            total_size: report.total_size,
            format: format!("{:?}", report.format),
            issues,
        };

        let output = JsonOutput::success("verify", data);
        Self::output(&output)
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
