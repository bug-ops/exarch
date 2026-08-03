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
use std::io::Stdout;
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

/// JSON formatter writing envelopes to `W`. Defaults to process stdout;
/// tests can inject an in-memory writer via [`JsonFormatter::with_writer`]
/// to capture output.
pub struct JsonFormatter<W: Write = Stdout> {
    out: W,
}

impl JsonFormatter<Stdout> {
    /// Creates a formatter writing to the process stdout.
    #[must_use]
    pub fn stdout() -> Self {
        Self { out: io::stdout() }
    }
}

impl<W: Write> JsonFormatter<W> {
    /// Creates a formatter writing to the given writer.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn with_writer(out: W) -> Self {
        Self { out }
    }

    /// Returns a reference to the underlying writer.
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn writer(&self) -> &W {
        &self.out
    }

    fn output<T: Serialize>(&mut self, value: &T) -> Result<()> {
        let json = serde_json::to_string_pretty(value)?;
        writeln!(self.out, "{json}")?;
        Ok(())
    }
}

impl<W: Write> OutputFormatter for JsonFormatter<W> {
    fn format_extraction_result(&mut self, report: &ExtractionReport) -> Result<()> {
        #[derive(Serialize)]
        struct ExtractionOutput {
            files_extracted: usize,
            directories_created: usize,
            symlinks_created: usize,
            bytes_written: u64,
            files_skipped: usize,
            duration_ms: u128,
            warnings: Vec<String>,
        }

        let data = ExtractionOutput {
            files_extracted: report.files_extracted,
            directories_created: report.directories_created,
            symlinks_created: report.symlinks_created,
            bytes_written: report.bytes_written,
            files_skipped: report.files_skipped,
            duration_ms: report.duration.as_millis(),
            warnings: report.warnings.clone(),
        };

        let output = JsonOutput::success("extract", data);
        self.output(&output)
    }

    fn format_creation_result(
        &mut self,
        output_path: &Path,
        report: &CreationReport,
    ) -> Result<()> {
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
        self.output(&output)
    }

    fn format_error(&mut self, operation: &str, error: &anyhow::Error) {
        let extraction_err = error.chain().find_map(|e| e.downcast_ref::<ArchiveError>());

        let kind = extraction_err.map_or_else(|| "Error".to_string(), extraction_error_kind);
        let message = format!("{error:#}");

        // PartialExtraction is converted by convert_extraction_error into a
        // PartialExtractionContext attached via `.context()`, so the partial
        // report must be recovered with a direct top-level downcast: anyhow
        // sees through `.context()` layers for the context type itself, but
        // `.chain()` yields the wrapper's Display/Debug impl, never the
        // context value, so `.chain().find_map(downcast_ref)` never matches.
        let partial_report =
            error
                .downcast_ref::<PartialExtractionContext>()
                .map(|ctx| JsonPartialReport {
                    files_extracted: ctx.report.files_extracted,
                    directories_created: ctx.report.directories_created,
                    symlinks_created: ctx.report.symlinks_created,
                    bytes_written: ctx.report.bytes_written,
                    files_skipped: ctx.report.files_skipped,
                    warnings: ctx.report.warnings.clone(),
                });

        let output = if let Some(pr) = partial_report {
            JsonOutput::<()>::error_with_partial(operation, kind, message, pr)
        } else {
            JsonOutput::<()>::error(operation, kind, message)
        };
        let _ = self.output(&output);
    }

    fn format_manifest_short(&mut self, manifest: &ArchiveManifest) -> Result<()> {
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
        self.output(&output)
    }

    fn format_manifest_long(
        &mut self,
        manifest: &ArchiveManifest,
        _human_readable: bool,
    ) -> Result<()> {
        #[derive(Serialize)]
        struct ManifestEntry {
            path: String,
            entry_type: String,
            size: u64,
            #[serde(skip_serializing_if = "Option::is_none")]
            compressed_size: Option<u64>,
            #[serde(skip_serializing_if = "Option::is_none")]
            mode: Option<u32>,
            #[serde(skip_serializing_if = "Option::is_none")]
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
        self.output(&output)
    }

    fn format_verification_report(&mut self, report: &VerificationReport) -> Result<()> {
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
        self.output(&output)
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

    fn parsed(formatter: &JsonFormatter<Vec<u8>>) -> serde_json::Value {
        serde_json::from_slice(formatter.writer()).unwrap()
    }

    #[test]
    fn format_extraction_result_writes_success_envelope() {
        let mut f = JsonFormatter::with_writer(Vec::new());
        let report = ExtractionReport {
            files_extracted: 3,
            directories_created: 1,
            symlinks_created: 0,
            bytes_written: 2048,
            duration: std::time::Duration::from_secs(1),
            ..Default::default()
        };
        f.format_extraction_result(&report).unwrap();
        let v = parsed(&f);
        assert_eq!(v["operation"], "extract");
        assert_eq!(v["status"], "success");
        assert_eq!(v["data"]["files_extracted"], 3);
        assert_eq!(v["data"]["bytes_written"], 2048);
    }

    #[test]
    fn format_extraction_result_includes_warnings_and_files_skipped() {
        let mut f = JsonFormatter::with_writer(Vec::new());
        let report = ExtractionReport {
            files_extracted: 3,
            directories_created: 1,
            symlinks_created: 0,
            bytes_written: 2048,
            files_skipped: 2,
            duration: std::time::Duration::from_secs(1),
            warnings: vec!["skipped 2 entries with disallowed extensions".to_string()],
        };
        f.format_extraction_result(&report).unwrap();
        let v = parsed(&f);
        assert_eq!(v["data"]["files_skipped"], 2);
        assert_eq!(
            v["data"]["warnings"][0],
            "skipped 2 entries with disallowed extensions"
        );
    }

    #[test]
    fn format_creation_result_writes_success_envelope() {
        let mut f = JsonFormatter::with_writer(Vec::new());
        let report = CreationReport {
            files_added: 2,
            directories_added: 1,
            symlinks_added: 0,
            bytes_written: 1024,
            bytes_compressed: 0,
            duration: std::time::Duration::from_secs(1),
            ..Default::default()
        };
        f.format_creation_result(Path::new("out.tar.gz"), &report)
            .unwrap();
        let v = parsed(&f);
        assert_eq!(v["operation"], "create");
        assert_eq!(v["status"], "success");
        assert_eq!(v["data"]["output_path"], "out.tar.gz");
        assert_eq!(v["data"]["files_added"], 2);
    }

    #[test]
    fn format_error_writes_error_envelope() {
        let mut f = JsonFormatter::with_writer(Vec::new());
        let err = anyhow::anyhow!(ArchiveError::ZipBomb {
            compressed: 1000,
            uncompressed: 1_000_000,
            ratio: 1000.0,
        });
        f.format_error("extract", &err);
        let v = parsed(&f);
        assert_eq!(v["operation"], "extract");
        assert_eq!(v["status"], "error");
        assert_eq!(v["error"]["kind"], "ZipBomb");
    }

    #[test]
    fn format_error_writes_partial_report_with_skipped_and_warnings() {
        use crate::error::convert_extraction_error;
        use exarch_core::ExtractionReport;

        let mut f = JsonFormatter::with_writer(Vec::new());
        let inner = ArchiveError::HardlinkEscape {
            path: PathBuf::from("escaped"),
        };
        let report = ExtractionReport {
            files_extracted: 2,
            directories_created: 1,
            symlinks_created: 0,
            bytes_written: 512,
            duration: std::time::Duration::from_millis(0),
            files_skipped: 3,
            warnings: vec!["skipped disallowed extension".to_string()],
        };
        let err = ArchiveError::PartialExtraction {
            source: Box::new(inner),
            report,
        };
        let converted = convert_extraction_error(err, Path::new("archive.tar.gz"), false);
        f.format_error("extract", &converted);
        let v = parsed(&f);
        assert_eq!(v["error"]["partial_report"]["files_skipped"], 3);
        assert_eq!(
            v["error"]["partial_report"]["warnings"][0],
            "skipped disallowed extension"
        );
    }

    fn sample_manifest() -> ArchiveManifest {
        use exarch_core::ArchiveEntry;
        use exarch_core::ManifestEntryType;
        use exarch_core::formats::detect::ArchiveType;

        ArchiveManifest {
            format: ArchiveType::TarGz,
            total_entries: 1,
            total_size: 1024,
            entries: vec![ArchiveEntry {
                path: PathBuf::from("file.txt"),
                entry_type: ManifestEntryType::File,
                size: 1024,
                compressed_size: None,
                mode: Some(0o644),
                modified: None,
                symlink_target: None,
                hardlink_target: None,
            }],
        }
    }

    #[test]
    fn format_manifest_short_writes_paths_only() {
        let mut f = JsonFormatter::with_writer(Vec::new());
        f.format_manifest_short(&sample_manifest()).unwrap();
        let v = parsed(&f);
        assert_eq!(v["operation"], "list");
        assert_eq!(v["data"]["entries"][0]["path"], "file.txt");
        assert!(v["data"]["entries"][0].get("size").is_none());
    }

    #[test]
    fn format_manifest_long_writes_full_detail() {
        let mut f = JsonFormatter::with_writer(Vec::new());
        f.format_manifest_long(&sample_manifest(), true).unwrap();
        let v = parsed(&f);
        assert_eq!(v["data"]["entries"][0]["size"], 1024);
        assert_eq!(v["data"]["entries"][0]["entry_type"], "File");
        assert_eq!(v["data"]["total_size"], 1024);
    }

    #[test]
    fn format_verification_report_writes_full_report() {
        use exarch_core::CheckStatus;
        use exarch_core::VerificationStatus;
        use exarch_core::formats::detect::ArchiveType;

        let mut f = JsonFormatter::with_writer(Vec::new());
        let report = VerificationReport {
            status: VerificationStatus::Pass,
            integrity_status: CheckStatus::Pass,
            security_status: CheckStatus::Pass,
            total_entries: 5,
            suspicious_entries: 0,
            total_size: 4096,
            format: ArchiveType::TarGz,
            issues: vec![],
        };
        f.format_verification_report(&report).unwrap();
        let v = parsed(&f);
        assert_eq!(v["operation"], "verify");
        assert_eq!(v["data"]["total_entries"], 5);
    }
}
