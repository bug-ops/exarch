//! Output formatter trait for CLI results.

use crate::operation::Operation;
use anyhow::Result;
use exarch_core::ArchiveManifest;
use exarch_core::ConfigSetting;
use exarch_core::CreationReport;
use exarch_core::CreationWarning;
use exarch_core::Disposition;
use exarch_core::ErrorCode;
use exarch_core::ExtractionReport;
use exarch_core::ExtractionWarning;
use exarch_core::FfiKind;
use exarch_core::IoKind;
use exarch_core::MarkOutcome;
use exarch_core::PartialWrites;
use exarch_core::PolicySetting;
use exarch_core::SecurityConfig;
use exarch_core::SkipKind;
use exarch_core::Skips;
use exarch_core::SubCode;
use exarch_core::VerificationReport;
use exarch_core::VolumeIdentity;
use exarch_core::path_text;
use serde::Serialize;
use serde::Serializer;
use std::collections::BTreeMap;
use std::path::Path;

/// Units of the size column in the long manifest listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeUnits {
    /// Exact byte counts.
    Bytes,
    /// Binary units with one decimal (`1.5 KB`).
    Human,
}

/// How much of each manifest entry is listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestView {
    /// Paths only.
    Short,
    /// Type, mode, size and link target of every entry.
    Long(SizeUnits),
}

/// What the selection of a listing does to each entry, aligned with
/// `manifest.entries()`; empty when the selection is the default, which
/// leaves every entry extracted where it is named.
#[derive(Debug, Default)]
pub struct Dispositions(Vec<Option<Disposition>>);

impl Dispositions {
    /// No disposition for any entry.
    pub fn none() -> Self {
        Self::default()
    }

    /// The disposition of each entry of `manifest` under its own selection,
    /// on a destination volume that identifies landings as `volume` says.
    pub fn of(manifest: &ArchiveManifest, config: &SecurityConfig, volume: VolumeIdentity) -> Self {
        if manifest.selection().is_default() {
            return Self::none();
        }
        let mut judged = manifest.dispositions_on(config, volume).peekable();
        Self(
            manifest
                .entries()
                .iter()
                .map(|entry| {
                    judged
                        .next_if(|(candidate, _)| std::ptr::eq(*candidate, entry))
                        .map(|(_, disposition)| disposition)
                })
                .collect(),
        )
    }

    /// The disposition of the entry at `index`, when the selection judged it.
    pub fn get(&self, index: usize) -> Option<&Disposition> {
        self.0.get(index).and_then(Option::as_ref)
    }
}

/// Common output formatter trait
pub trait OutputFormatter {
    /// Format extraction result
    fn format_extraction_result(&mut self, report: &ExtractionReport) -> Result<()>;

    /// Format archive creation result
    fn format_creation_result(&mut self, output_path: &Path, report: &CreationReport)
    -> Result<()>;

    /// Format an archive manifest
    fn format_manifest(
        &mut self,
        manifest: &ArchiveManifest,
        view: ManifestView,
        dispositions: &Dispositions,
    ) -> Result<()>;

    /// Format verification report
    fn format_verification_report(&mut self, report: &VerificationReport) -> Result<()>;

    /// Format error message for the given operation
    fn format_error(&mut self, operation: Operation, error: &anyhow::Error);

    /// Reports a verification run whose report has `Fail` status.
    ///
    /// The report itself, already emitted, fully describes the failure, so a
    /// machine-readable formatter adds nothing: a second envelope would put
    /// two top-level JSON documents on stdout.
    fn format_verification_failed(&mut self);
}

/// The `--json` envelope: a success carries data and no error, a failure
/// carries an error and no data, and the two cannot be mixed.
///
/// The wire format is `{"status": "success" | "error", "operation": ..., ...}`.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Envelope<T> {
    /// The command ran to completion; `data` is its result.
    Success {
        /// The command that produced the result.
        operation: Operation,
        /// The command's result.
        data: T,
    },
    /// The command failed.
    Error {
        /// The command that failed.
        operation: Operation,
        /// What went wrong.
        error: JsonError,
    },
}

mod sealed {
    pub trait Sealed {}

    impl Sealed for exarch_core::PartialWrites {}
    impl Sealed for exarch_core::PolicySetting {}
    impl Sealed for exarch_core::SubCode {}
    impl Sealed for exarch_core::ConfigSetting {}
    impl Sealed for exarch_core::IoKind {}
}

/// A closed core enum whose `Display` is its stable identifier (`as_str`).
///
/// Sealed: only the core enums listed in `sealed` can be serialized as an id.
pub trait StableId: sealed::Sealed + std::fmt::Display {}

impl StableId for exarch_core::PartialWrites {}
impl StableId for exarch_core::PolicySetting {}
impl StableId for exarch_core::SubCode {}
impl StableId for exarch_core::ConfigSetting {}
impl StableId for exarch_core::IoKind {}

/// Serializes a closed core enum as its stable identifier.
#[derive(Debug, Clone, Copy)]
pub struct JsonId<T>(pub T);

impl<T: StableId> Serialize for JsonId<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

/// The category of an error object: a core error code, or the generic kind of
/// a failure that has no core error behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonKind {
    /// The code of the core error behind the failure.
    Code(ErrorCode),
    /// A CLI failure with no core error behind it.
    Generic,
}

impl JsonKind {
    /// The `PascalCase` name on the wire.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Generic => "Error",
            Self::Code(code) => match code {
                ErrorCode::IoError => "IoError",
                ErrorCode::SecurityViolation => "SecurityViolation",
                ErrorCode::InvalidArchive => "InvalidArchive",
                ErrorCode::PathTraversal => "PathTraversal",
                ErrorCode::SymlinkEscape => "SymlinkEscape",
                ErrorCode::HardlinkEscape => "HardlinkEscape",
                ErrorCode::ZipBomb => "ZipBomb",
                ErrorCode::ZipInconsistency => "ZipInconsistency",
                ErrorCode::InvalidPermissions => "InvalidPermissions",
                ErrorCode::QuotaExceeded => "QuotaExceeded",
                ErrorCode::SourceNotFound => "SourceNotFound",
                ErrorCode::SourceNotAccessible => "SourceNotAccessible",
                ErrorCode::OutputExists => "OutputExists",
                ErrorCode::InvalidCompressionLevel => "InvalidCompressionLevel",
                ErrorCode::UnknownFormat => "UnknownFormat",
                ErrorCode::InvalidConfiguration => "InvalidConfiguration",
                ErrorCode::Cancelled => "Cancelled",
                // Wildcard only for `#[non_exhaustive]`;
                // `every_error_code_has_a_kind_name` fails if it is ever taken.
                _ => "Error",
            },
        }
    }
}

impl Serialize for JsonKind {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.name())
    }
}

/// The finer discriminants an error or a refusal can carry besides its code:
/// what a script reads instead of parsing the message.
#[derive(Debug, Serialize)]
pub struct JsonDiscriminants {
    /// The finer classification of the failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_code: Option<JsonId<SubCode>>,
    /// The `SecurityConfig` setting whose value refused the entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relaxable_by: Option<JsonId<PolicySetting>>,
    /// The configuration setting or input that was refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setting: Option<JsonId<ConfigSetting>>,
    /// The I/O failure class of an `IoError`, the token the Python and Node
    /// bindings report as `io_kind`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_kind: Option<JsonId<IoKind>>,
}

impl From<&FfiKind> for JsonDiscriminants {
    fn from(kind: &FfiKind) -> Self {
        Self {
            sub_code: kind.sub_code().map(JsonId),
            relaxable_by: kind.relaxable_by().map(JsonId),
            setting: kind.setting().map(JsonId),
            io_kind: match kind {
                FfiKind::Io(kind) => Some(JsonId(IoKind::from(*kind))),
                _ => None,
            },
        }
    }
}

/// The typed discriminants of the refusal behind a verify issue: the same
/// code, sub-code and policy setting a failed extraction reports, so a script
/// need not parse the message.
#[derive(Debug, Serialize)]
pub struct JsonRefusal {
    /// The error code of the refusal.
    pub code: JsonKind,
    /// The sub-code, policy setting and configuration setting of the refusal.
    #[serde(flatten)]
    pub discriminants: JsonDiscriminants,
}

impl From<&FfiKind> for JsonRefusal {
    fn from(kind: &FfiKind) -> Self {
        Self {
            code: JsonKind::Code(kind.code()),
            discriminants: JsonDiscriminants::from(kind),
        }
    }
}

/// A host filesystem path in the `--json` envelope: one rule for every field
/// a script acts on (`output_path`, `leftover_path`, a backup `path`), apart
/// from archive entry names, which keep their injective `path_text` rendering.
///
/// A path that is valid UTF-8 is the exact string, so `rm -rf "$path"` finds
/// the directory even when its name holds a backslash. A path that is not
/// valid UTF-8 cannot be a JSON string without losing bytes, so only then is
/// it rendered with the injective `path_text` escape (`\xNN` for undecodable
/// bytes, `\x5C` for a backslash), which tells the two cases apart for the
/// reader but is no longer usable verbatim as a path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct HostPath(String);

impl From<&Path> for HostPath {
    fn from(path: &Path) -> Self {
        Self(path.to_str().map_or_else(|| path_text(path), str::to_owned))
    }
}

impl std::fmt::Display for HostPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One skipped entry in a report's bounded sample.
#[derive(Debug, Serialize)]
pub struct JsonSkip {
    /// The reason the entry was skipped, as the core names it.
    pub kind: &'static str,
    /// The entry's name, rendered injectively.
    pub path: String,
    /// The I/O failure class of an entry skipped because of one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_kind: Option<JsonId<IoKind>>,
}

/// What an operation left out: the total, exact counts per reason (only the
/// reasons that occurred) and a bounded sample of the individual entries.
#[derive(Debug, Serialize)]
pub struct JsonSkips {
    /// How many entries were skipped, for any reason.
    pub files_skipped: usize,
    /// How many were skipped for each reason that occurred.
    pub skipped_by_kind: BTreeMap<&'static str, usize>,
    /// A bounded sample of the skipped entries.
    pub skipped_sample: Vec<JsonSkip>,
}

impl From<&Skips> for JsonSkips {
    fn from(skips: &Skips) -> Self {
        Self {
            files_skipped: skips.total(),
            skipped_by_kind: SkipKind::ALL
                .iter()
                .filter(|kind| skips.count(**kind) > 0)
                .map(|kind| (kind.as_str(), skips.count(*kind)))
                .collect(),
            skipped_sample: skips
                .sample()
                .iter()
                .map(|skip| JsonSkip {
                    kind: skip.kind.as_str(),
                    path: path_text(&skip.path),
                    io_kind: skip.io_kind.map(JsonId),
                })
                .collect(),
        }
    }
}

/// One warning of a report, keyed by the core's stable `kind` token, with the
/// fields of its variant beside the display `message`.
#[derive(Debug, Serialize)]
pub struct JsonWarning {
    kind: &'static str,
    message: String,
    #[serde(flatten)]
    fields: Option<JsonWarningFields>,
}

/// The fields each warning variant carries, as the bindings report them.
#[derive(Debug, Serialize)]
#[serde(untagged)]
enum JsonWarningFields {
    Count {
        count: u64,
    },
    LeftoverBackup {
        path: HostPath,
        identity: &'static str,
        io_kind: JsonId<IoKind>,
        reason: String,
    },
    ZipRatio {
        entries: usize,
        limit: f64,
        needed_ratio: f64,
    },
    Reason {
        reason: String,
    },
    IoKind {
        io_kind: JsonId<IoKind>,
    },
}

impl From<&ExtractionWarning> for JsonWarning {
    fn from(warning: &ExtractionWarning) -> Self {
        let fields = match warning {
            ExtractionWarning::AntiItemsSkipped { count } => {
                Some(JsonWarningFields::Count { count: *count })
            }
            ExtractionWarning::BackupCleanupFailed {
                path,
                identity,
                io_kind,
                message,
            } => Some(JsonWarningFields::LeftoverBackup {
                path: HostPath::from(path.as_path()),
                identity: identity.as_str(),
                io_kind: JsonId(*io_kind),
                reason: message.to_string(),
            }),
            ExtractionWarning::RootAccessNarrowed { reason } => Some(JsonWarningFields::Reason {
                reason: reason.as_str().to_owned(),
            }),
            _ => None,
        };
        Self {
            kind: warning.kind().as_str(),
            message: warning.to_string(),
            fields,
        }
    }
}

impl From<&CreationWarning> for JsonWarning {
    fn from(warning: &CreationWarning) -> Self {
        let fields = match warning {
            CreationWarning::ZipRatioOverDefaultLimit {
                entries,
                limit,
                needed_ratio,
            } => Some(JsonWarningFields::ZipRatio {
                entries: *entries,
                limit: *limit,
                needed_ratio: *needed_ratio,
            }),
            CreationWarning::ZipRatioCheckFailed { reason } => Some(JsonWarningFields::Reason {
                reason: reason.clone(),
            }),
            CreationWarning::DirectoryNotSynced { io_kind } => Some(JsonWarningFields::IoKind {
                io_kind: JsonId(*io_kind),
            }),
            _ => None,
        };
        Self {
            kind: warning.kind().as_str(),
            message: warning.to_string(),
            fields,
        }
    }
}

/// What download-origin mark propagation did, as the `mark_propagation` field.
///
/// `state` is the core token of the outcome, so a state added to core appears
/// under its own name; the counts exist only for a propagated mark.
#[derive(Debug, Serialize)]
pub struct JsonMarkPropagation {
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    marked: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed: Option<usize>,
}

impl From<MarkOutcome> for JsonMarkPropagation {
    fn from(outcome: MarkOutcome) -> Self {
        let counts = match outcome {
            MarkOutcome::Propagated { marked, failed } => Some((marked, failed)),
            _ => None,
        };
        Self {
            state: outcome.state().as_str(),
            marked: counts.map(|(marked, _)| marked),
            failed: counts.map(|(_, failed)| failed),
        }
    }
}

/// The counters of an extraction, shared by a finished run and the partial
/// report of a stopped one.
#[derive(Debug, Serialize)]
pub struct JsonExtractionCounts {
    /// Files written.
    pub files_extracted: usize,
    /// Directories created.
    pub directories_created: usize,
    /// Symbolic links created.
    pub symlinks_created: usize,
    /// Bytes written to files.
    pub bytes_written: u64,
    /// What the run left out.
    #[serde(flatten)]
    pub skips: JsonSkips,
    /// What download-origin mark propagation did.
    pub mark_propagation: JsonMarkPropagation,
    /// The conditions of the run worth surfacing.
    pub warnings: Vec<JsonWarning>,
}

impl From<&ExtractionReport> for JsonExtractionCounts {
    fn from(report: &ExtractionReport) -> Self {
        Self {
            files_extracted: report.files_extracted,
            directories_created: report.directories_created,
            symlinks_created: report.symlinks_created,
            bytes_written: report.bytes_written,
            skips: JsonSkips::from(&report.skipped),
            mark_propagation: report.mark.into(),
            warnings: report.warnings.iter().map(JsonWarning::from).collect(),
        }
    }
}

/// Partial extraction report included in error JSON when extraction was stopped
/// mid-archive.
#[derive(Debug, Serialize)]
pub struct JsonPartialReport {
    /// What the stopped run had done.
    #[serde(flatten)]
    pub counts: JsonExtractionCounts,
    /// Whether those writes were kept, rolled back or never made.
    pub writes: JsonId<PartialWrites>,
}

/// Structured error object in JSON output
#[derive(Debug, Serialize)]
pub struct JsonError {
    /// The category of the failure.
    pub kind: JsonKind,
    /// The failure, stated once, without its advice.
    pub message: String,
    /// Advice for the reader, apart from the message; absent when there is
    /// none. Several hints are joined by newlines.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_report: Option<Box<JsonPartialReport>>,
    /// The archive-relative paths an occupied destination refused, for a
    /// `DestinationOccupied` error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conflicts: Option<Vec<String>>,
    /// A staging directory or reservation file the failed run left behind;
    /// what the user must clean up.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leftover_path: Option<HostPath>,
    /// `relaxable_by` is the stable id of the `SecurityConfig` setting whose
    /// current value refused the entry (only for a `SecurityViolation` a
    /// setting relaxes); `sub_code` the finer classification (always for a
    /// `SecurityViolation`, for a TAR `InvalidArchive`, absent otherwise);
    /// `setting` the configuration setting or input that was refused (only
    /// for an `InvalidConfiguration` that names one); `io_kind` the I/O
    /// failure class (only for an `IoError`).
    #[serde(flatten)]
    pub discriminants: Option<JsonDiscriminants>,
}

impl JsonError {
    /// An error of `kind` with `message` and nothing else.
    pub fn new(kind: JsonKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            hint: None,
            partial_report: None,
            conflicts: None,
            leftover_path: None,
            discriminants: None,
        }
    }

    /// Names the archive-relative paths an occupied destination refused.
    #[must_use]
    pub fn with_conflicts(mut self, conflicts: Vec<String>) -> Self {
        self.conflicts = Some(conflicts);
        self
    }

    /// Names the staging directory or reservation file the run left behind.
    #[must_use]
    pub fn with_leftover_path(mut self, path: Option<HostPath>) -> Self {
        self.leftover_path = path;
        self
    }

    /// Sets the advice that goes with the message, when there is any.
    #[must_use]
    pub fn with_hint(mut self, hint: Option<String>) -> Self {
        self.hint = hint;
        self
    }

    /// Attaches the report of a run that stopped part-way.
    #[must_use]
    pub fn with_partial(mut self, report: JsonPartialReport) -> Self {
        self.partial_report = Some(Box::new(report));
        self
    }

    /// Records the setting that refused the entry and the sub-code of the
    /// failure.
    #[must_use]
    pub fn with_ffi_kind(mut self, kind: &FfiKind) -> Self {
        self.discriminants = Some(JsonDiscriminants::from(kind));
        self
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use exarch_core::MarkState;
    use std::path::PathBuf;

    fn mark_outcome_of(state: MarkState) -> MarkOutcome {
        match state {
            MarkState::NotRequested => MarkOutcome::NotRequested,
            MarkState::UnsupportedPlatform => MarkOutcome::UnsupportedPlatform,
            MarkState::Unmarked => MarkOutcome::Unmarked,
            MarkState::Unreadable => MarkOutcome::Unreadable,
            MarkState::Propagated => MarkOutcome::Propagated {
                marked: 2,
                failed: 1,
            },
            _ => panic!("a mark state without a sample outcome: {state:?}"),
        }
    }

    #[test]
    fn every_mark_state_reports_its_core_token_in_json() {
        for &state in MarkState::ALL {
            let json =
                serde_json::to_value(JsonMarkPropagation::from(mark_outcome_of(state))).unwrap();
            assert_eq!(json["state"], state.as_str());
            let counted = state == MarkState::Propagated;
            assert_eq!(json.get("marked").is_some(), counted, "{state:?}");
            assert_eq!(json.get("failed").is_some(), counted, "{state:?}");
        }
    }

    #[test]
    fn a_propagated_mark_reports_its_counts() {
        let json = serde_json::to_value(JsonMarkPropagation::from(MarkOutcome::Propagated {
            marked: 2,
            failed: 1,
        }))
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({"state": "propagated", "marked": 2, "failed": 1})
        );
    }

    #[test]
    fn a_utf8_host_path_is_the_exact_string() {
        let json = serde_json::to_value(HostPath::from(Path::new("out/.exarch-a\\x5Cb"))).unwrap();
        assert_eq!(json, "out/.exarch-a\\x5Cb");
    }

    #[cfg(unix)]
    #[test]
    fn a_non_utf8_host_path_is_escaped_not_merged() {
        use std::os::unix::ffi::OsStrExt as _;

        let first = PathBuf::from(std::ffi::OsStr::from_bytes(b"out/\xff.tar"));
        let second = PathBuf::from(std::ffi::OsStr::from_bytes(b"out/\xfe.tar"));
        let render = |path: &Path| serde_json::to_value(HostPath::from(path)).unwrap();
        assert_eq!(render(&first), "out/\\xFF.tar");
        assert_ne!(render(&first), render(&second));
    }

    #[test]
    fn a_leftover_backup_warning_names_the_exact_host_path() {
        let warning = ExtractionWarning::BackupCleanupFailed {
            path: PathBuf::from("p/.exarch-backup-a\\b"),
            identity: exarch_core::BackupIdentity::Verified,
            io_kind: IoKind::Other,
            message: "x".into(),
        };
        let json = serde_json::to_value(JsonWarning::from(&warning)).unwrap();
        assert_eq!(json["path"], "p/.exarch-backup-a\\b");
    }

    #[test]
    fn a_narrowed_root_warning_carries_its_reason_token() {
        for reason in exarch_core::NarrowingReason::ALL {
            let warning = ExtractionWarning::RootAccessNarrowed { reason: *reason };
            let json = serde_json::to_value(JsonWarning::from(&warning)).unwrap();
            assert_eq!(json["kind"], "root_access_narrowed");
            assert_eq!(json["reason"], reason.as_str());
        }
    }
}
