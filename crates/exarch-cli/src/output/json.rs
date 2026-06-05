//! JSON output formatter for machine-readable results.

use super::formatter::JsonOutput;
use super::formatter::JsonPartialReport;
use super::formatter::OutputFormatter;
use crate::error::PartialExtractionContext;
use anyhow::Result;
use exarch_core::ArchiveError;
use exarch_core::ArchiveManifest;
use exarch_core::CreationReport;
use exarch_core::ExtractionReport;
use exarch_core::VerificationReport;
use serde::Serialize;
use std::io::Write;
use std::io::{self};
use std::path::Path;

fn extraction_error_kind(err: &ArchiveError) -> String {
    match err {
        ArchiveError::Io(_) => "IoError",
        ArchiveError::InvalidArchive(_) => "InvalidArchive",
        ArchiveError::PathTraversal { .. } => "PathTraversal",
        ArchiveError::SymlinkEscape { .. } => "SymlinkEscape",
        ArchiveError::HardlinkEscape { .. } => "HardlinkEscape",
        ArchiveError::ZipBomb { .. } => "ZipBomb",
        ArchiveError::InvalidPermissions { .. } => "InvalidPermissions",
        ArchiveError::QuotaExceeded { .. } => "QuotaExceeded",
        ArchiveError::SecurityViolation { .. } => "SecurityViolation",
        ArchiveError::SourceNotFound { .. } => "SourceNotFound",
        ArchiveError::SourceNotAccessible { .. } => "SourceNotAccessible",
        ArchiveError::OutputExists { .. } => "OutputExists",
        ArchiveError::InvalidCompressionLevel { .. } => "InvalidCompressionLevel",
        ArchiveError::UnknownFormat { .. } => "UnknownFormat",
        ArchiveError::InvalidConfiguration { .. } => "InvalidConfiguration",
        ArchiveError::PartialExtraction { source, .. } => return extraction_error_kind(source),
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
        let extraction_err = error.chain().find_map(|e| e.downcast_ref::<ArchiveError>());

        let kind = extraction_err.map_or_else(|| "Error".to_string(), extraction_error_kind);
        let message = format!("{error:#}");

        // PartialExtraction is converted by convert_extraction_error into a chain
        // of PartialExtractionContext → inner ArchiveError, so the partial
        // report is carried by PartialExtractionContext, not by ArchiveError.
        let partial_report = error
            .chain()
            .find_map(|e| e.downcast_ref::<PartialExtractionContext>())
            .map(|ctx| JsonPartialReport {
                files_extracted: ctx.report.files_extracted,
                directories_created: ctx.report.directories_created,
                symlinks_created: ctx.report.symlinks_created,
                bytes_written: ctx.report.bytes_written,
            });

        let output = if let Some(pr) = partial_report {
            JsonOutput::<()>::error_with_partial(operation, kind, message, pr)
        } else {
            JsonOutput::<()>::error(operation, kind, message)
        };
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
            #[serde(skip_serializing_if = "Option::is_none")]
            symlink_target: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            hardlink_target: Option<String>,
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
                symlink_target: e.symlink_target.as_ref().map(|p| p.display().to_string()),
                hardlink_target: e.hardlink_target.as_ref().map(|p| p.display().to_string()),
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

    fn error_kind(err: &ArchiveError) -> String {
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
        let err = ArchiveError::ZipBomb {
            compressed: 1000,
            uncompressed: 1_000_000,
            ratio: 1000.0,
        };
        assert_eq!(error_kind(&err), "ZipBomb");
    }

    #[test]
    fn test_extraction_error_kind_path_traversal() {
        let err = ArchiveError::PathTraversal {
            path: PathBuf::from("../etc/passwd"),
        };
        assert_eq!(error_kind(&err), "PathTraversal");
    }

    #[test]
    fn test_extraction_error_kind_symlink_escape() {
        let err = ArchiveError::SymlinkEscape {
            path: PathBuf::from("link"),
        };
        assert_eq!(error_kind(&err), "SymlinkEscape");
    }

    #[test]
    fn test_extraction_error_kind_hardlink_escape() {
        let err = ArchiveError::HardlinkEscape {
            path: PathBuf::from("hardlink"),
        };
        assert_eq!(error_kind(&err), "HardlinkEscape");
    }

    #[test]
    fn test_extraction_error_kind_quota_exceeded() {
        let err = ArchiveError::QuotaExceeded {
            resource: QuotaResource::FileCount {
                current: 11,
                max: 10,
            },
        };
        assert_eq!(error_kind(&err), "QuotaExceeded");
    }

    #[test]
    fn test_extraction_error_kind_invalid_archive() {
        let err = ArchiveError::InvalidArchive("corrupted header".to_string());
        assert_eq!(error_kind(&err), "InvalidArchive");
    }

    #[test]
    fn test_extraction_error_kind_io_error() {
        let err = ArchiveError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert_eq!(error_kind(&err), "IoError");
    }

    #[test]
    fn test_extraction_error_kind_unknown_format() {
        let err = ArchiveError::UnknownFormat {
            path: std::path::PathBuf::from("archive.rar"),
        };
        assert_eq!(error_kind(&err), "UnknownFormat");
    }

    #[test]
    fn test_extraction_error_kind_security_violation() {
        let err = ArchiveError::SecurityViolation {
            reason: "denied".to_string(),
        };
        assert_eq!(error_kind(&err), "SecurityViolation");
    }

    #[test]
    fn test_format_error_downcasts_extraction_error() {
        // Verify that format_error correctly resolves the kind from an anyhow chain
        // containing an ArchiveError.
        let extraction_err = ArchiveError::ZipBomb {
            compressed: 100,
            uncompressed: 100_000,
            ratio: 1000.0,
        };
        let anyhow_err = anyhow::Error::new(extraction_err);

        // Downcast manually, same logic as format_error uses
        let kind = anyhow_err
            .chain()
            .find_map(|e| e.downcast_ref::<ArchiveError>())
            .map_or_else(|| "Error".to_string(), extraction_error_kind);

        assert_eq!(kind, "ZipBomb");
    }

    #[test]
    fn test_format_error_unknown_error_uses_generic_kind() {
        // A plain anyhow error with no ArchiveError in chain should use "Error" as
        // kind
        let anyhow_err = anyhow::anyhow!("something went wrong");

        let kind = anyhow_err
            .chain()
            .find_map(|e| e.downcast_ref::<ArchiveError>())
            .map_or_else(|| "Error".to_string(), extraction_error_kind);

        assert_eq!(kind, "Error");
    }

    // Regression tests for issue #192: JSON error message must not duplicate text
    // that ArchiveError::Display already emits.

    #[test]
    fn test_json_message_quota_exceeded_no_duplication() {
        use crate::error::convert_extraction_error;
        use exarch_core::QuotaResource;
        use std::path::Path;

        let err = ArchiveError::QuotaExceeded {
            resource: QuotaResource::FileCount {
                current: 11,
                max: 10,
            },
        };
        // ArchiveError::Display emits "quota exceeded: file count (11 > 10)"
        let display_text = err.to_string();
        let anyhow_err = convert_extraction_error(err, Path::new("archive.tar.gz"), false);
        let message = format!("{anyhow_err:#}");

        // The context must NOT repeat the Display text verbatim
        let display_occurrences = message.matches(&display_text).count();
        assert!(
            display_occurrences <= 1,
            "JSON message duplicates ArchiveError display text ({display_occurrences} occurrences): {message}"
        );
    }

    #[test]
    fn test_json_message_zip_bomb_no_duplication() {
        use crate::error::convert_extraction_error;
        use std::path::Path;

        let compressed = 1_024_u64;
        let uncompressed = 1_024 * 1_024 * 150_u64;
        let ratio = 150.0_f64;
        let err = ArchiveError::ZipBomb {
            compressed,
            uncompressed,
            ratio,
        };
        // ArchiveError::Display emits the ratio info
        let display_text = err.to_string();
        let anyhow_err = convert_extraction_error(err, Path::new("bomb.zip"), false);
        let message = format!("{anyhow_err:#}");

        let display_occurrences = message.matches(&display_text).count();
        assert!(
            display_occurrences <= 1,
            "JSON message duplicates ArchiveError display text ({display_occurrences} occurrences): {message}"
        );
    }
}
