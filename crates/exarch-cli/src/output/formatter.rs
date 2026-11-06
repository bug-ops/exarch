//! Output formatter trait for CLI results.

use crate::operation::Operation;
use anyhow::Result;
use exarch_core::ArchiveManifest;
use exarch_core::ConfigSetting;
use exarch_core::CreationReport;
use exarch_core::Disposition;
use exarch_core::ErrorCode;
use exarch_core::ExtractionReport;
use exarch_core::FfiKind;
use exarch_core::PartialWrites;
use exarch_core::PolicySetting;
use exarch_core::SecurityConfig;
use exarch_core::SkipKind;
use exarch_core::Skips;
use exarch_core::SubCode;
use exarch_core::VerificationReport;
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

    /// The disposition of each entry of `manifest` under its own selection.
    pub fn of(manifest: &ArchiveManifest, config: &SecurityConfig) -> Self {
        if manifest.selection().is_default() {
            return Self::none();
        }
        let mut judged = manifest.dispositions(config).peekable();
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
    Success {
        operation: Operation,
        data: T,
    },
    Error {
        operation: Operation,
        error: JsonError,
    },
}

mod sealed {
    pub trait Sealed {}

    impl Sealed for exarch_core::PartialWrites {}
    impl Sealed for exarch_core::PolicySetting {}
    impl Sealed for exarch_core::SubCode {}
    impl Sealed for exarch_core::ConfigSetting {}
}

/// A closed core enum whose `Display` is its stable identifier (`as_str`).
///
/// Sealed: only the core enums listed in `sealed` can be serialized as an id.
pub trait StableId: sealed::Sealed + std::fmt::Display {}

impl StableId for exarch_core::PartialWrites {}
impl StableId for exarch_core::PolicySetting {}
impl StableId for exarch_core::SubCode {}
impl StableId for exarch_core::ConfigSetting {}

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
    Code(ErrorCode),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_code: Option<JsonId<SubCode>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relaxable_by: Option<JsonId<PolicySetting>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setting: Option<JsonId<ConfigSetting>>,
}

impl From<&FfiKind> for JsonDiscriminants {
    fn from(kind: &FfiKind) -> Self {
        Self {
            sub_code: kind.sub_code().map(JsonId),
            relaxable_by: kind.relaxable_by().map(JsonId),
            setting: kind.setting().map(JsonId),
        }
    }
}

/// The typed discriminants of the refusal behind a verify issue: the same
/// code, sub-code and policy setting a failed extraction reports, so a script
/// need not parse the message.
#[derive(Debug, Serialize)]
pub struct JsonRefusal {
    pub code: JsonKind,
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

/// One skipped entry in a report's bounded sample.
#[derive(Debug, Serialize)]
pub struct JsonSkip {
    pub kind: &'static str,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_kind: Option<String>,
}

/// What an operation left out: the total, exact counts per reason (only the
/// reasons that occurred) and a bounded sample of the individual entries.
#[derive(Debug, Serialize)]
pub struct JsonSkips {
    pub files_skipped: usize,
    pub skipped_by_kind: BTreeMap<&'static str, usize>,
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
                    io_kind: skip.io_kind.map(|kind| kind.as_str().to_owned()),
                })
                .collect(),
        }
    }
}

/// The counters of an extraction, shared by a finished run and the partial
/// report of a stopped one.
#[derive(Debug, Serialize)]
pub struct JsonExtractionCounts {
    pub files_extracted: usize,
    pub directories_created: usize,
    pub symlinks_created: usize,
    pub bytes_written: u64,
    #[serde(flatten)]
    pub skips: JsonSkips,
    pub warnings: Vec<String>,
}

impl From<&ExtractionReport> for JsonExtractionCounts {
    fn from(report: &ExtractionReport) -> Self {
        Self {
            files_extracted: report.files_extracted,
            directories_created: report.directories_created,
            symlinks_created: report.symlinks_created,
            bytes_written: report.bytes_written,
            skips: JsonSkips::from(&report.skipped),
            warnings: report.warnings.iter().map(ToString::to_string).collect(),
        }
    }
}

/// Partial extraction report included in error JSON when extraction was stopped
/// mid-archive.
#[derive(Debug, Serialize)]
pub struct JsonPartialReport {
    #[serde(flatten)]
    pub counts: JsonExtractionCounts,
    pub writes: JsonId<PartialWrites>,
}

/// Structured error object in JSON output
#[derive(Debug, Serialize)]
pub struct JsonError {
    pub kind: JsonKind,
    pub message: String,
    /// Advice for the reader, apart from the message; absent when there is
    /// none. Several hints are joined by newlines.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_report: Option<JsonPartialReport>,
    /// The archive-relative paths an occupied destination refused, for a
    /// `DestinationOccupied` error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conflicts: Option<Vec<String>>,
    /// `relaxable_by` is the stable id of the `SecurityConfig` setting whose
    /// current value refused the entry (only for a `SecurityViolation` a
    /// setting relaxes); `sub_code` the finer classification (always for a
    /// `SecurityViolation`, for a TAR `InvalidArchive`, absent otherwise);
    /// `setting` the configuration setting or input that was refused (only
    /// for an `InvalidConfiguration` that names one).
    #[serde(flatten)]
    pub discriminants: Option<JsonDiscriminants>,
}

impl JsonError {
    pub fn new(kind: JsonKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            hint: None,
            partial_report: None,
            conflicts: None,
            discriminants: None,
        }
    }

    #[must_use]
    pub fn with_conflicts(mut self, conflicts: Vec<String>) -> Self {
        self.conflicts = Some(conflicts);
        self
    }

    #[must_use]
    pub fn with_hint(mut self, hint: Option<String>) -> Self {
        self.hint = hint;
        self
    }

    #[must_use]
    pub fn with_partial(mut self, report: JsonPartialReport) -> Self {
        self.partial_report = Some(report);
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
