//! JSON output formatter for machine-readable results.

use super::formatter::JsonOutput;
use super::formatter::OutputFormatter;
use anyhow::Result;
use exarch_core::ArchiveManifest;
use exarch_core::CreationReport;
use exarch_core::ExtractionError;
use exarch_core::ExtractionReport;
use exarch_core::VerificationReport;
use serde::Serialize;
use std::io::Write;
use std::io::{self};
use std::path::Path;

fn extraction_error_kind(err: &ExtractionError) -> String {
    match err {
        ExtractionError::Io(_) => "IoError",
        ExtractionError::UnsupportedFormat => "UnsupportedFormat",
        ExtractionError::InvalidArchive(_) => "InvalidArchive",
        ExtractionError::PathTraversal { .. } => "PathTraversal",
        ExtractionError::SymlinkEscape { .. } => "SymlinkEscape",
        ExtractionError::HardlinkEscape { .. } => "HardlinkEscape",
        ExtractionError::ZipBomb { .. } => "ZipBomb",
        ExtractionError::InvalidPermissions { .. } => "InvalidPermissions",
        ExtractionError::QuotaExceeded { .. } => "QuotaExceeded",
        ExtractionError::SecurityViolation { .. } => "SecurityViolation",
        ExtractionError::SourceNotFound { .. } => "SourceNotFound",
        ExtractionError::SourceNotAccessible { .. } => "SourceNotAccessible",
        ExtractionError::OutputExists { .. } => "OutputExists",
        ExtractionError::InvalidCompressionLevel { .. } => "InvalidCompressionLevel",
        ExtractionError::UnknownFormat { .. } => "UnknownFormat",
        ExtractionError::InvalidConfiguration { .. } => "InvalidConfiguration",
    }
    .to_string()
}

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

    fn format_error(&self, operation: &str, error: &anyhow::Error) {
        let kind = error
            .chain()
            .find_map(|e| e.downcast_ref::<ExtractionError>())
            .map_or_else(|| "Error".to_string(), extraction_error_kind);
        let message = format!("{error:#}");
        let output = JsonOutput::<()>::error(operation, kind, message);
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
    use exarch_core::QuotaResource;
    use std::path::PathBuf;

    fn error_kind(err: &ExtractionError) -> String {
        extraction_error_kind(err)
    }

    #[test]
    fn test_json_error_output_structure() {
        let output = JsonOutput::<()>::error("extract", "ZipBomb", "zip bomb detected");
        let json = serde_json::to_string(&output).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["operation"], "extract");
        assert_eq!(v["status"], "error");
        assert_eq!(v["error"]["kind"], "ZipBomb");
        assert_eq!(v["error"]["message"], "zip bomb detected");
        assert!(v["data"].is_null());
    }

    #[test]
    fn test_json_error_no_data_field() {
        let output = JsonOutput::<()>::error("extract", "PathTraversal", "traversal attempt");
        let json = serde_json::to_string(&output).unwrap();
        // data field should be absent (skip_serializing_if = None)
        assert!(!json.contains("\"data\""));
    }

    #[test]
    fn test_extraction_error_kind_zip_bomb() {
        let err = ExtractionError::ZipBomb {
            compressed: 1000,
            uncompressed: 1_000_000,
            ratio: 1000.0,
        };
        assert_eq!(error_kind(&err), "ZipBomb");
    }

    #[test]
    fn test_extraction_error_kind_path_traversal() {
        let err = ExtractionError::PathTraversal {
            path: PathBuf::from("../etc/passwd"),
        };
        assert_eq!(error_kind(&err), "PathTraversal");
    }

    #[test]
    fn test_extraction_error_kind_symlink_escape() {
        let err = ExtractionError::SymlinkEscape {
            path: PathBuf::from("link"),
        };
        assert_eq!(error_kind(&err), "SymlinkEscape");
    }

    #[test]
    fn test_extraction_error_kind_hardlink_escape() {
        let err = ExtractionError::HardlinkEscape {
            path: PathBuf::from("hardlink"),
        };
        assert_eq!(error_kind(&err), "HardlinkEscape");
    }

    #[test]
    fn test_extraction_error_kind_quota_exceeded() {
        let err = ExtractionError::QuotaExceeded {
            resource: QuotaResource::FileCount {
                current: 11,
                max: 10,
            },
        };
        assert_eq!(error_kind(&err), "QuotaExceeded");
    }

    #[test]
    fn test_extraction_error_kind_invalid_archive() {
        let err = ExtractionError::InvalidArchive("corrupted header".to_string());
        assert_eq!(error_kind(&err), "InvalidArchive");
    }

    #[test]
    fn test_extraction_error_kind_io_error() {
        let err = ExtractionError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert_eq!(error_kind(&err), "IoError");
    }

    #[test]
    fn test_extraction_error_kind_unsupported_format() {
        let err = ExtractionError::UnsupportedFormat;
        assert_eq!(error_kind(&err), "UnsupportedFormat");
    }

    #[test]
    fn test_extraction_error_kind_security_violation() {
        let err = ExtractionError::SecurityViolation {
            reason: "denied".to_string(),
        };
        assert_eq!(error_kind(&err), "SecurityViolation");
    }

    #[test]
    fn test_format_error_downcasts_extraction_error() {
        // Verify that format_error correctly resolves the kind from an anyhow chain
        // containing an ExtractionError.
        let extraction_err = ExtractionError::ZipBomb {
            compressed: 100,
            uncompressed: 100_000,
            ratio: 1000.0,
        };
        let anyhow_err = anyhow::Error::new(extraction_err);

        // Downcast manually, same logic as format_error uses
        let kind = anyhow_err
            .chain()
            .find_map(|e| e.downcast_ref::<ExtractionError>())
            .map_or_else(|| "Error".to_string(), extraction_error_kind);

        assert_eq!(kind, "ZipBomb");
    }

    #[test]
    fn test_format_error_unknown_error_uses_generic_kind() {
        // A plain anyhow error with no ExtractionError in chain should use "Error" as
        // kind
        let anyhow_err = anyhow::anyhow!("something went wrong");

        let kind = anyhow_err
            .chain()
            .find_map(|e| e.downcast_ref::<ExtractionError>())
            .map_or_else(|| "Error".to_string(), extraction_error_kind);

        assert_eq!(kind, "Error");
    }
}
