//! JSON output formatter for machine-readable results.

use super::formatter::Envelope;
use super::formatter::JsonError;
use super::formatter::JsonExtractionCounts;
use super::formatter::JsonId;
use super::formatter::JsonKind;
use super::formatter::JsonPartialReport;
use super::formatter::JsonRefusal;
use super::formatter::JsonSkips;
use super::formatter::ManifestView;
use super::formatter::OutputFormatter;
use crate::error::PartialExtractionContext;
use crate::error::chain_hints;
use crate::error::raw;
use crate::operation::Operation;
use anyhow::Result;
use exarch_core::ArchiveError;
use exarch_core::ArchiveManifest;
use exarch_core::CreationReport;
use exarch_core::ExtractionReport;
use exarch_core::LinkTarget;
use exarch_core::ManifestEntryKind;
use exarch_core::VerificationReport;
use exarch_core::path_text;
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Stdout;
use std::io::Write;
use std::io::{self};
use std::path::Path;

/// A link entry's target as `--json` reports it: its state, with the path
/// only when the archive recorded one.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum JsonLinkTarget {
    Recorded {
        path: String,
    },
    Missing,
    Unread,
    Unreadable,
    Oversized {
        bytes: usize,
    },
    /// A state added to the `#[non_exhaustive]` core enum after this match
    /// was written; `every_link_target_state_has_a_dedicated_json_state`
    /// rejects it for every state that exists today.
    Unknown,
}

impl From<&LinkTarget> for JsonLinkTarget {
    fn from(target: &LinkTarget) -> Self {
        match target {
            LinkTarget::Recorded(path) => Self::Recorded {
                path: path_text(path),
            },
            LinkTarget::Missing => Self::Missing,
            LinkTarget::Unread => Self::Unread,
            LinkTarget::Unreadable => Self::Unreadable,
            LinkTarget::Oversized { bytes } => Self::Oversized { bytes: *bytes },
            _ => Self::Unknown,
        }
    }
}

/// The target state of a link entry; `None` for a file or directory.
fn link_target_of(kind: &ManifestEntryKind) -> Option<JsonLinkTarget> {
    match kind {
        ManifestEntryKind::Symlink { target } | ManifestEntryKind::Hardlink { target } => {
            Some(JsonLinkTarget::from(target))
        }
        _ => None,
    }
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
        match writeln!(self.out, "{json}") {
            Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Ok(()),
            written => written.map_err(Into::into),
        }
    }

    fn success<T: Serialize>(&mut self, operation: Operation, data: T) -> Result<()> {
        self.output(&Envelope::Success { operation, data })
    }
}

fn short_manifest(manifest: &ArchiveManifest) -> impl Serialize + use<> {
    #[derive(Serialize)]
    struct ManifestEntry {
        path: String,
    }

    #[derive(Serialize)]
    struct ManifestOutput {
        format: &'static str,
        total_entries: usize,
        entries: Vec<ManifestEntry>,
    }

    ManifestOutput {
        format: manifest.format().as_str(),
        total_entries: manifest.total_entries(),
        entries: manifest
            .entries()
            .iter()
            .map(|e| ManifestEntry {
                path: path_text(&e.path),
            })
            .collect(),
    }
}

fn long_manifest(manifest: &ArchiveManifest) -> impl Serialize + use<> {
    #[derive(Serialize)]
    struct ManifestEntry {
        path: String,
        entry_type: &'static str,
        size: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        compressed_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        mode: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        modified: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        link_target: Option<JsonLinkTarget>,
    }

    #[derive(Serialize)]
    struct ManifestOutput {
        format: &'static str,
        total_entries: usize,
        total_size: u64,
        entries: Vec<ManifestEntry>,
    }

    ManifestOutput {
        format: manifest.format().as_str(),
        total_entries: manifest.total_entries(),
        total_size: manifest.total_size(),
        entries: manifest
            .entries()
            .iter()
            .map(|e| ManifestEntry {
                path: path_text(&e.path),
                entry_type: e.kind.entry_type().as_str(),
                size: e.size(),
                compressed_size: e.compressed_size(),
                mode: e.mode.map(exarch_core::RawMode::get),
                modified: e.modified.and_then(|t| {
                    t.duration_since(std::time::UNIX_EPOCH)
                        .ok()
                        .map(|d| d.as_secs())
                }),
                link_target: link_target_of(&e.kind),
            })
            .collect(),
    }
}

impl<W: Write> OutputFormatter for JsonFormatter<W> {
    fn format_extraction_result(&mut self, report: &ExtractionReport) -> Result<()> {
        #[derive(Serialize)]
        struct ExtractionOutput {
            #[serde(flatten)]
            counts: JsonExtractionCounts,
            duration_ms: u128,
        }

        self.success(
            Operation::Extract,
            ExtractionOutput {
                counts: JsonExtractionCounts::from(report),
                duration_ms: report.duration.as_millis(),
            },
        )
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
            #[serde(flatten)]
            skips: JsonSkips,
            duration_ms: u128,
            warnings: Vec<String>,
        }

        self.success(
            Operation::Create,
            CreationOutput {
                output_path: output_path.display().to_string(),
                files_added: report.files_added,
                directories_added: report.directories_added,
                symlinks_added: report.symlinks_added,
                bytes_written: report.bytes_written,
                bytes_compressed: report.bytes_compressed,
                compression_ratio: report.compression_ratio(),
                compression_percentage: report.compression_percentage(),
                skips: JsonSkips::from(&report.skipped),
                duration_ms: report.duration.as_millis(),
                warnings: report.warnings.iter().map(ToString::to_string).collect(),
            },
        )
    }

    fn format_verification_failed(&mut self) {}

    fn format_error(&mut self, operation: Operation, error: &anyhow::Error) {
        let extraction_err = error.chain().find_map(|e| e.downcast_ref::<ArchiveError>());

        let ffi_kind = extraction_err.map(ArchiveError::ffi_kind);
        let kind = ffi_kind
            .as_ref()
            .map_or(JsonKind::Generic, |kind| JsonKind::Code(kind.code()));

        // The message and hints are the exact text: archive-derived parts are
        // escaped only when a terminal formatter renders them.
        let hints = chain_hints(error, raw);
        let mut json_error = JsonError::new(kind, format!("{error:#}"))
            .with_hint((!hints.is_empty()).then(|| hints.join("\n")));

        // `convert_error` makes the `PartialExtractionContext` the outermost
        // error, so the partial report is recovered with a top-level
        // downcast.
        if let Some(ctx) = error.downcast_ref::<PartialExtractionContext>() {
            json_error = json_error.with_partial(JsonPartialReport {
                counts: JsonExtractionCounts::from(&ctx.report),
                writes: JsonId(ctx.writes),
            });
        }
        if let Some(kind) = &ffi_kind {
            json_error = json_error.with_ffi_kind(kind);
        }
        let _ = self.output(&Envelope::<()>::Error {
            operation,
            error: json_error,
        });
    }

    fn format_manifest(&mut self, manifest: &ArchiveManifest, view: ManifestView) -> Result<()> {
        match view {
            ManifestView::Short => self.success(Operation::List, short_manifest(manifest)),
            ManifestView::Long(_) => self.success(Operation::List, long_manifest(manifest)),
        }
    }

    fn format_verification_report(&mut self, report: &VerificationReport) -> Result<()> {
        #[derive(Serialize)]
        struct VerificationIssue {
            severity: &'static str,
            category: &'static str,
            entry_path: Option<String>,
            message: String,
            /// The raw mode of an executable file or of an invalid-permissions
            /// refusal.
            #[serde(skip_serializing_if = "Option::is_none")]
            mode: Option<u32>,
            #[serde(flatten)]
            refusal: Option<JsonRefusal>,
        }

        #[derive(Serialize)]
        struct UnverifiedEntry {
            path: String,
            reason: &'static str,
        }

        #[derive(Serialize)]
        struct IntegrityGaps {
            counts: BTreeMap<&'static str, u64>,
            entries: Vec<UnverifiedEntry>,
            omitted: u64,
        }

        #[derive(Serialize)]
        struct VerificationOutput {
            status: &'static str,
            integrity_status: &'static str,
            integrity_gaps: Option<IntegrityGaps>,
            security_status: &'static str,
            total_entries: usize,
            suspicious_entries: usize,
            total_size: u64,
            format: &'static str,
            issues: Vec<VerificationIssue>,
        }

        let issues = report
            .issues()
            .iter()
            .map(|i| VerificationIssue {
                severity: i.severity().as_str(),
                category: i.category().as_str(),
                entry_path: i.entry_path().map(path_text),
                message: i.message(),
                mode: i.mode().map(exarch_core::RawMode::get),
                refusal: i.ffi_kind().map(JsonRefusal::from),
            })
            .collect();

        let data = VerificationOutput {
            status: report.status().as_str(),
            integrity_status: report.integrity_status().as_str(),
            integrity_gaps: report.integrity_gaps().map(|gaps| IntegrityGaps {
                counts: gaps
                    .counts()
                    .map(|(reason, count)| (reason.as_str(), count))
                    .collect(),
                entries: gaps
                    .entries()
                    .iter()
                    .map(|e| UnverifiedEntry {
                        path: path_text(e.path()),
                        reason: e.reason().as_str(),
                    })
                    .collect(),
                omitted: gaps.omitted(),
            }),
            security_status: report.security_status().as_str(),
            total_entries: report.total_entries(),
            suspicious_entries: report.suspicious_entries(),
            total_size: report.total_size(),
            format: report.format().as_str(),
            issues,
        };

        self.success(Operation::Verify, data)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::output::formatter::SizeUnits;
    use exarch_core::Compressed;
    use exarch_core::ErrorCode;
    use exarch_core::QuotaResource;
    use exarch_core::Uncompressed;
    use exarch_core::Violation;
    use std::path::PathBuf;

    struct FailingWriter(io::ErrorKind);

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(self.0.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(self.0.into())
        }
    }

    #[test]
    fn a_closed_stdout_is_not_a_failure() {
        let mut f = JsonFormatter::with_writer(FailingWriter(io::ErrorKind::BrokenPipe));
        assert!(
            f.format_manifest(&sample_manifest(), ManifestView::Short)
                .is_ok(),
            "a reader that stopped reading is not an error"
        );
    }

    #[test]
    fn other_write_failures_still_fail() {
        let mut f = JsonFormatter::with_writer(FailingWriter(io::ErrorKind::StorageFull));
        assert!(
            f.format_manifest(&sample_manifest(), ManifestView::Short)
                .is_err()
        );
    }

    fn extraction_error_kind(err: &ArchiveError) -> String {
        JsonKind::Code(err.ffi_kind().code()).name().to_string()
    }

    #[test]
    fn every_error_code_has_a_kind_name() {
        for &code in ErrorCode::ALL {
            assert_ne!(
                JsonKind::Code(code).name(),
                JsonKind::Generic.name(),
                "{code:?}"
            );
        }
    }

    fn error_kind(err: &ArchiveError) -> String {
        extraction_error_kind(err)
    }

    #[test]
    fn test_json_error_output_structure() {
        let output = Envelope::<()>::Error {
            operation: Operation::Extract,
            error: JsonError::new(JsonKind::Code(ErrorCode::ZipBomb), "zip bomb detected"),
        };
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
        let output = Envelope::<()>::Error {
            operation: Operation::Extract,
            error: JsonError::new(
                JsonKind::Code(ErrorCode::PathTraversal),
                "traversal attempt",
            ),
        };
        let json = serde_json::to_string(&output).unwrap();
        // data field should be absent (skip_serializing_if = None)
        assert!(!json.contains("\"data\""));
    }

    #[test]
    fn test_extraction_error_kind_zip_bomb() {
        let err = exarch_core::ArchiveError::ZipBomb(exarch_core::ZipBombDetails::new(
            exarch_core::ZipBombScope::Entry,
            Compressed(1000),
            Uncompressed(1_000_000),
        ));
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
        let err = ArchiveError::from(exarch_core::Malformation::SymlinkTargetNotUtf8);
        assert_eq!(error_kind(&err), "InvalidArchive");
    }

    #[test]
    fn test_extraction_error_kind_tar_ambiguity_is_invalid_archive() {
        let err = ArchiveError::TarAmbiguity(exarch_core::TarAmbiguity::ChecksumMismatch);
        assert_eq!(error_kind(&err), "InvalidArchive");
    }

    #[test]
    fn test_extraction_error_kind_tar_trailer_follows_the_old_kinds() {
        use exarch_core::TarTrailerRefusal;
        let over = ArchiveError::TarTrailer(TarTrailerRefusal::OverCap { cap: 1 << 20 });
        assert_eq!(error_kind(&over), "SecurityViolation");
        for refusal in [
            TarTrailerRefusal::Truncated,
            TarTrailerRefusal::Corrupt {
                cause: exarch_core::TrailerCorruption::Decoder,
                detail: "checksum mismatch".into(),
            },
        ] {
            assert_eq!(
                error_kind(&ArchiveError::TarTrailer(refusal)),
                "InvalidArchive"
            );
        }
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

    fn envelope_for(err: &ArchiveError) -> serde_json::Value {
        let kind = err.ffi_kind();
        let output = Envelope::<()>::Error {
            operation: Operation::Extract,
            error: JsonError::new(JsonKind::Code(kind.code()), "denied").with_ffi_kind(&kind),
        };
        serde_json::to_value(&output).unwrap()
    }

    #[test]
    fn test_error_envelope_reports_relaxable_by_only_when_set() {
        let relaxable = envelope_for(&ArchiveError::from(Violation::LinksNotAllowed(
            exarch_core::LinkKind::Symlink,
        )));
        assert_eq!(relaxable["error"]["relaxable_by"], "symlinks");
        assert_eq!(relaxable["error"]["sub_code"], "LINK_POLICY");

        let fixed = envelope_for(&ArchiveError::from(Violation::EncryptedArchive));
        assert!(fixed["error"].get("relaxable_by").is_none());
        assert_eq!(fixed["error"]["sub_code"], "ENCRYPTED");
    }

    #[test]
    fn test_error_envelope_reports_tar_sub_codes() {
        use exarch_core::TarTrailerRefusal;

        let ambiguity = envelope_for(&ArchiveError::TarAmbiguity(
            exarch_core::TarAmbiguity::ChecksumMismatch,
        ));
        assert_eq!(ambiguity["error"]["kind"], "InvalidArchive");
        assert_eq!(ambiguity["error"]["sub_code"], "TAR_AMBIGUITY");

        let truncated = envelope_for(&ArchiveError::TarTrailer(TarTrailerRefusal::Truncated));
        assert_eq!(truncated["error"]["kind"], "InvalidArchive");
        assert_eq!(truncated["error"]["sub_code"], "TAR_TRAILER");

        let over = envelope_for(&ArchiveError::TarTrailer(TarTrailerRefusal::OverCap {
            cap: 1 << 20,
        }));
        assert_eq!(over["error"]["kind"], "SecurityViolation");
        assert_eq!(over["error"]["sub_code"], "TAR_TRAILER");
        assert_eq!(over["error"]["relaxable_by"], "max_tar_metadata_bytes");

        let typed = envelope_for(&ArchiveError::from(
            exarch_core::Malformation::DuplicateEntry {
                path: PathBuf::from("a/b"),
            },
        ));
        assert_eq!(typed["error"]["kind"], "InvalidArchive");
        assert_eq!(typed["error"]["sub_code"], "DUPLICATE_ENTRY");
    }

    #[test]
    fn test_extraction_error_kind_security_violation() {
        let err = ArchiveError::from(Violation::EncryptedArchive);
        assert_eq!(error_kind(&err), "SecurityViolation");
    }

    #[test]
    fn test_format_error_downcasts_extraction_error() {
        // Verify that format_error correctly resolves the kind from an anyhow
        // chain containing an ArchiveError.
        let extraction_err = exarch_core::ArchiveError::ZipBomb(exarch_core::ZipBombDetails::new(
            exarch_core::ZipBombScope::Entry,
            Compressed(100),
            Uncompressed(100_000),
        ));
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
        // A plain anyhow error with no ArchiveError in chain should use "Error"
        // as kind
        let anyhow_err = anyhow::anyhow!("something went wrong");

        let kind = anyhow_err
            .chain()
            .find_map(|e| e.downcast_ref::<ArchiveError>())
            .map_or_else(|| "Error".to_string(), extraction_error_kind);

        assert_eq!(kind, "Error");
    }

    // Regression tests for issue #192: JSON error message must not duplicate
    // text that ArchiveError::Display already emits.

    #[test]
    fn test_json_message_quota_exceeded_no_duplication() {
        use crate::error::convert_error;
        use crate::operation::Operation;
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
        let anyhow_err = convert_error(Operation::Extract, err, Path::new("archive.tar.gz"));
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
        use crate::error::convert_error;
        use crate::operation::Operation;
        use std::path::Path;

        let err = ArchiveError::ZipBomb(exarch_core::ZipBombDetails::new(
            exarch_core::ZipBombScope::Entry,
            Compressed(1_024),
            Uncompressed(1_024 * 1_024 * 150),
        ));
        // ArchiveError::Display emits the ratio info
        let display_text = err.to_string();
        let anyhow_err = convert_error(Operation::Extract, err, Path::new("bomb.zip"));
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
        let report = {
            let mut r = exarch_core::ExtractionReport::new();
            r.files_extracted = 3;
            r.directories_created = 1;
            r.symlinks_created = 0;
            r.bytes_written = 2048;
            r.duration = std::time::Duration::from_secs(1);
            r
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
        let report = {
            let mut r = exarch_core::ExtractionReport::new();
            r.files_extracted = 3;
            r.directories_created = 1;
            r.symlinks_created = 0;
            r.bytes_written = 2048;
            r.skipped = crate::test_support::skips(2);
            r.duration = std::time::Duration::from_secs(1);
            r.warnings = vec![crate::test_support::extraction_warning(
                "skipped 2 entries with disallowed extensions",
            )];
            r
        };
        f.format_extraction_result(&report).unwrap();
        let v = parsed(&f);
        assert_eq!(v["data"]["files_skipped"], 2);
        assert!(
            v["data"]["warnings"][0]
                .as_str()
                .unwrap()
                .contains("skipped 2 entries with disallowed extensions")
        );
        assert_eq!(v["data"]["skipped_by_kind"]["duplicate"], 2);
        assert_eq!(v["data"]["skipped_sample"][0]["kind"], "duplicate");
    }

    #[test]
    fn format_creation_result_writes_success_envelope() {
        let mut f = JsonFormatter::with_writer(Vec::new());
        let report = {
            let mut r = exarch_core::CreationReport::new();
            r.files_added = 2;
            r.directories_added = 1;
            r.symlinks_added = 0;
            r.bytes_written = 1024;
            r.bytes_compressed = 0;
            r.duration = std::time::Duration::from_secs(1);
            r
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
        let err = anyhow::anyhow!(exarch_core::ArchiveError::ZipBomb(
            exarch_core::ZipBombDetails::new(
                exarch_core::ZipBombScope::Entry,
                Compressed(1000),
                Uncompressed(1_000_000)
            )
        ));
        f.format_error(Operation::Extract, &err);
        let v = parsed(&f);
        assert_eq!(v["operation"], "extract");
        assert_eq!(v["status"], "error");
        assert_eq!(v["error"]["kind"], "ZipBomb");
    }

    #[test]
    fn format_error_writes_partial_report_with_skipped_and_warnings() {
        use crate::error::convert_error;
        use crate::operation::Operation;

        let mut f = JsonFormatter::with_writer(Vec::new());
        let inner = ArchiveError::HardlinkEscape {
            path: PathBuf::from("escaped"),
        };
        let report = {
            let mut r = exarch_core::ExtractionReport::new();
            r.files_extracted = 2;
            r.directories_created = 1;
            r.symlinks_created = 0;
            r.bytes_written = 512;
            r.duration = std::time::Duration::from_millis(0);
            r.skipped = crate::test_support::skips(3);
            r.warnings = vec![crate::test_support::extraction_warning(
                "skipped disallowed extension",
            )];
            r
        };
        let err = ArchiveError::PartialExtraction(exarch_core::Partial::new(
            inner,
            report,
            exarch_core::PartialWrites::Kept,
        ));
        let converted = convert_error(Operation::Extract, err, Path::new("archive.tar.gz"));
        f.format_error(Operation::Extract, &converted);
        let v = parsed(&f);
        assert_eq!(v["error"]["partial_report"]["files_skipped"], 3);
        assert_eq!(v["error"]["partial_report"]["writes"], "kept");
        assert!(
            v["error"]["partial_report"]["warnings"][0]
                .as_str()
                .unwrap()
                .contains("skipped disallowed extension")
        );
    }

    fn sample_manifest() -> ArchiveManifest {
        use exarch_core::ArchiveEntry;
        use exarch_core::ArchiveType;
        use exarch_core::ManifestEntryKind;

        let mut entry = ArchiveEntry::new(
            PathBuf::from("file.txt"),
            ManifestEntryKind::File {
                size: exarch_core::Uncompressed(1024),
            },
        );
        entry.mode = Some(exarch_core::RawMode::new(0o644));
        let mut manifest = ArchiveManifest::new(ArchiveType::TarGz);
        manifest.add_entry(entry).unwrap();
        manifest
    }

    #[test]
    fn format_manifest_short_writes_paths_only() {
        let mut f = JsonFormatter::with_writer(Vec::new());
        f.format_manifest(&sample_manifest(), ManifestView::Short)
            .unwrap();
        let v = parsed(&f);
        assert_eq!(v["operation"], "list");
        assert_eq!(v["data"]["entries"][0]["path"], "file.txt");
        assert!(v["data"]["entries"][0].get("size").is_none());
    }

    #[test]
    fn format_manifest_long_writes_full_detail() {
        let mut f = JsonFormatter::with_writer(Vec::new());
        f.format_manifest(&sample_manifest(), ManifestView::Long(SizeUnits::Human))
            .unwrap();
        let v = parsed(&f);
        assert_eq!(v["data"]["entries"][0]["size"], 1024);
        assert_eq!(v["data"]["entries"][0]["entry_type"], "File");
        assert_eq!(v["data"]["total_size"], 1024);
    }

    #[test]
    fn format_verification_report_writes_full_report() {
        use exarch_core::ArchiveEntry;
        use exarch_core::ArchiveType;
        use exarch_core::ManifestEntryKind;

        let mut f = JsonFormatter::with_writer(Vec::new());
        let mut manifest = ArchiveManifest::new(ArchiveType::TarGz);
        for i in 0..5 {
            let path = PathBuf::from(format!("f{i}.txt"));
            manifest
                .add_entry(ArchiveEntry::new(
                    path,
                    ManifestEntryKind::File {
                        size: exarch_core::Uncompressed(0),
                    },
                ))
                .unwrap();
        }
        let report = VerificationReport::from_entry_issues(&manifest, |_| Vec::new());
        f.format_verification_report(&report).unwrap();
        let v = parsed(&f);
        assert_eq!(v["operation"], "verify");
        assert_eq!(v["data"]["total_entries"], 5);
    }

    #[test]
    fn envelope_wire_format_is_pinned() {
        let success = serde_json::to_value(Envelope::Success {
            operation: Operation::List,
            data: serde_json::json!({"n": 1}),
        })
        .unwrap();
        assert_eq!(
            success,
            serde_json::json!({"status": "success", "operation": "list", "data": {"n": 1}})
        );

        let error = serde_json::to_value(Envelope::<()>::Error {
            operation: Operation::Verify,
            error: JsonError::new(JsonKind::Generic, "boom"),
        })
        .unwrap();
        assert_eq!(
            error,
            serde_json::json!({
                "status": "error",
                "operation": "verify",
                "error": {"kind": "Error", "message": "boom"}
            })
        );
    }

    #[test]
    fn every_link_target_state_has_a_dedicated_json_state() {
        let samples = [
            LinkTarget::Recorded(PathBuf::from("t")),
            LinkTarget::Missing,
            LinkTarget::Unread,
            LinkTarget::Unreadable,
            LinkTarget::Oversized { bytes: 9 },
        ];
        let mut seen = Vec::new();
        for target in &samples {
            let json = JsonLinkTarget::from(target);
            assert_ne!(json, JsonLinkTarget::Unknown, "{target:?}");
            let value = serde_json::to_value(&json).unwrap();
            seen.push(value["state"].as_str().unwrap().to_owned());
        }
        seen.sort();
        seen.dedup();
        assert_eq!(
            seen.len(),
            samples.len(),
            "states must be distinct: {seen:?}"
        );
    }

    #[test]
    fn long_listing_reports_every_link_state_and_none_for_other_entries() {
        use exarch_core::ArchiveEntry;
        use exarch_core::ArchiveType;

        let mut manifest = ArchiveManifest::new(ArchiveType::SevenZ);
        let kinds = [
            (
                "plain",
                ManifestEntryKind::File {
                    size: exarch_core::Uncompressed(0),
                },
            ),
            (
                "rec",
                ManifestEntryKind::Symlink {
                    target: LinkTarget::Recorded(PathBuf::from("t")),
                },
            ),
            (
                "miss",
                ManifestEntryKind::Symlink {
                    target: LinkTarget::Missing,
                },
            ),
            (
                "big",
                ManifestEntryKind::Hardlink {
                    target: LinkTarget::Oversized { bytes: 5000 },
                },
            ),
        ];
        for (path, kind) in kinds {
            manifest
                .add_entry(ArchiveEntry::new(PathBuf::from(path), kind))
                .unwrap();
        }
        let mut f = JsonFormatter::with_writer(Vec::new());
        f.format_manifest(&manifest, ManifestView::Long(SizeUnits::Bytes))
            .unwrap();
        let v = parsed(&f);
        let entries = &v["data"]["entries"];
        assert!(entries[0].get("link_target").is_none());
        assert_eq!(
            entries[1]["link_target"],
            serde_json::json!({"state": "recorded", "path": "t"})
        );
        assert_eq!(
            entries[2]["link_target"],
            serde_json::json!({"state": "missing"})
        );
        assert_eq!(
            entries[3]["link_target"],
            serde_json::json!({"state": "oversized", "bytes": 5000})
        );
        assert!(entries[1].get("symlink_target").is_none());
    }

    #[test]
    fn partial_report_and_success_share_the_extraction_counters() {
        let mut f = JsonFormatter::with_writer(Vec::new());
        let report = {
            let mut r = exarch_core::ExtractionReport::new();
            r.files_extracted = 4;
            r.skipped = crate::test_support::skips(1);
            r
        };
        f.format_extraction_result(&report).unwrap();
        let v = parsed(&f);
        for key in [
            "files_extracted",
            "directories_created",
            "symlinks_created",
            "bytes_written",
            "files_skipped",
            "warnings",
            "duration_ms",
        ] {
            assert!(v["data"].get(key).is_some(), "{key}");
        }
    }

    #[test]
    fn error_message_keeps_archive_text_exact() {
        let mut f = JsonFormatter::with_writer(Vec::new());
        let err = crate::error::convert_error(
            Operation::Extract,
            ArchiveError::PathTraversal {
                path: PathBuf::from("a"),
            },
            Path::new("we\x1bird.tar"),
        );
        f.format_error(Operation::Extract, &err);
        let v = parsed(&f);
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap()
                .contains("we\x1bird.tar"),
            "{v}"
        );
    }
}
