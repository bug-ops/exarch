//! Node.js bindings for `ExtractionReport`.

use exarch_core::ExtractionReport as CoreReport;
use exarch_core::formats::detect::ArchiveType as CoreArchiveType;
use exarch_core::inspection::CheckStatus as CoreCheckStatus;
use exarch_core::inspection::IntegrityGaps as CoreIntegrityGaps;
use exarch_core::inspection::IntegrityStatus as CoreIntegrityStatus;
use exarch_core::inspection::IssueCategory as CoreIssueCategory;
use exarch_core::inspection::IssueSeverity as CoreIssueSeverity;
use exarch_core::inspection::ManifestEntryType as CoreManifestEntryType;
use exarch_core::inspection::UnverifiedReason as CoreUnverifiedReason;
use exarch_core::inspection::VerificationStatus as CoreVerificationStatus;
use napi::Error;
use napi::Result;
use napi_derive::napi;

use crate::CoreResult;
use crate::error::Failure;
use crate::error::IoKind;
use crate::utils::path_text;
use exarch_core::ArchiveError as CoreError;
use napi::bindgen_prelude::Either4;
use napi::bindgen_prelude::Either5;

pub fn saturating_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

pub fn saturating_i64(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

pub fn unknown_variant(what: &str, wire: &str) -> Error {
    Error::from_reason(format!(
        "exarch-node is older than exarch-core: unknown {what} '{wire}'"
    ))
}

/// Archive format.
// Values must equal `exarch_core::ArchiveType::as_str`.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveType {
    /// Uncompressed TAR.
    #[napi(value = "Tar")]
    Tar,
    /// Gzip-compressed TAR.
    #[napi(value = "TarGz")]
    TarGz,
    /// Bzip2-compressed TAR.
    #[napi(value = "TarBz2")]
    TarBz2,
    /// XZ-compressed TAR.
    #[napi(value = "TarXz")]
    TarXz,
    /// Zstd-compressed TAR.
    #[napi(value = "TarZst")]
    TarZst,
    /// ZIP.
    #[napi(value = "Zip")]
    Zip,
    /// 7z.
    #[napi(value = "SevenZ")]
    SevenZ,
}

impl TryFrom<CoreArchiveType> for ArchiveType {
    type Error = Error;

    fn try_from(value: CoreArchiveType) -> Result<Self> {
        Ok(match value {
            CoreArchiveType::Tar => Self::Tar,
            CoreArchiveType::TarGz => Self::TarGz,
            CoreArchiveType::TarBz2 => Self::TarBz2,
            CoreArchiveType::TarXz => Self::TarXz,
            CoreArchiveType::TarZst => Self::TarZst,
            CoreArchiveType::Zip => Self::Zip,
            CoreArchiveType::SevenZ => Self::SevenZ,
            other => return Err(unknown_variant("archive type", other.as_str())),
        })
    }
}

impl From<ArchiveType> for CoreArchiveType {
    fn from(value: ArchiveType) -> Self {
        match value {
            ArchiveType::Tar => Self::Tar,
            ArchiveType::TarGz => Self::TarGz,
            ArchiveType::TarBz2 => Self::TarBz2,
            ArchiveType::TarXz => Self::TarXz,
            ArchiveType::TarZst => Self::TarZst,
            ArchiveType::Zip => Self::Zip,
            ArchiveType::SevenZ => Self::SevenZ,
        }
    }
}

/// Manifest entry type.
// Values must equal `exarch_core::inspection::ManifestEntryType::as_str`.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestEntryType {
    /// Regular file.
    #[napi(value = "File")]
    File,
    /// Directory.
    #[napi(value = "Directory")]
    Directory,
    /// Symbolic link.
    #[napi(value = "Symlink")]
    Symlink,
    /// Hard link.
    #[napi(value = "Hardlink")]
    Hardlink,
}

impl From<CoreManifestEntryType> for ManifestEntryType {
    fn from(value: CoreManifestEntryType) -> Self {
        match value {
            CoreManifestEntryType::File => Self::File,
            CoreManifestEntryType::Directory => Self::Directory,
            CoreManifestEntryType::Symlink => Self::Symlink,
            CoreManifestEntryType::Hardlink => Self::Hardlink,
        }
    }
}

/// Overall verification status.
// Values must equal `exarch_core::inspection::VerificationStatus::as_str`.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    /// All checks passed.
    #[napi(value = "PASS")]
    Pass,
    /// One or more checks failed.
    #[napi(value = "FAIL")]
    Fail,
    /// Checks completed with warnings.
    #[napi(value = "WARNING")]
    Warning,
}

impl From<CoreVerificationStatus> for VerificationStatus {
    fn from(value: CoreVerificationStatus) -> Self {
        match value {
            CoreVerificationStatus::Pass => Self::Pass,
            CoreVerificationStatus::Fail => Self::Fail,
            CoreVerificationStatus::Warning => Self::Warning,
        }
    }
}

/// Status of a single check category.
// Values must equal `exarch_core::inspection::CheckStatus::as_str`.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    /// Check passed.
    #[napi(value = "OK")]
    Pass,
    /// Check failed.
    #[napi(value = "FAILED")]
    Fail,
    /// Check completed with warnings.
    #[napi(value = "WARNING")]
    Warning,
    /// Check was not performed.
    #[napi(value = "SKIPPED")]
    Skipped,
}

impl From<CoreCheckStatus> for CheckStatus {
    fn from(value: CoreCheckStatus) -> Self {
        match value {
            CoreCheckStatus::Pass => Self::Pass,
            CoreCheckStatus::Fail => Self::Fail,
            CoreCheckStatus::Warning => Self::Warning,
            CoreCheckStatus::Skipped => Self::Skipped,
        }
    }
}

/// Result of the payload integrity check.
// Values must equal `exarch_core::inspection::IntegrityStatus::as_str`.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityStatus {
    /// Every payload byte was decoded and every available checksum matched.
    #[napi(value = "OK")]
    Pass,
    /// A checksum or decoder error proved the payload corrupt.
    #[napi(value = "FAILED")]
    Fail,
    /// Part of the payload was not verified.
    #[napi(value = "INCOMPLETE")]
    Incomplete,
    /// The check was not requested.
    #[napi(value = "SKIPPED")]
    Skipped,
}

impl TryFrom<CoreIntegrityStatus> for IntegrityStatus {
    type Error = Error;

    fn try_from(value: CoreIntegrityStatus) -> Result<Self> {
        Ok(match value {
            CoreIntegrityStatus::Pass => Self::Pass,
            CoreIntegrityStatus::Fail => Self::Fail,
            CoreIntegrityStatus::Incomplete => Self::Incomplete,
            CoreIntegrityStatus::Skipped => Self::Skipped,
            other => return Err(unknown_variant("integrity status", other.as_str())),
        })
    }
}

/// Why part of the payload was not verified by the integrity check.
// Values must equal `exarch_core::inspection::UnverifiedReason::as_str`.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnverifiedReason {
    /// The decompression budget could not cover it.
    #[napi(value = "over_budget")]
    OverBudget,
    /// Quota, ratio or decoder-memory admission refused it.
    #[napi(value = "resource_limit")]
    ResourceLimit,
    /// A solid 7z block while solid archives are not allowed.
    #[napi(value = "solid_policy")]
    SolidPolicy,
    /// The stream outgrew its declared size.
    #[napi(value = "size_ceiling")]
    SizeCeiling,
    /// A 7z block checksum that the entries do not cover.
    #[napi(value = "uncovered_block_crc")]
    UncoveredBlockCrc,
    /// An unsupported or unparseable 7z coder.
    #[napi(value = "not_decodable")]
    NotDecodable,
    /// A TAR stream that ends without an end-of-archive marker.
    #[napi(value = "no_end_marker")]
    NoEndMarker,
    /// An entry dropped from the manifest because its path exceeds the host
    /// limits.
    #[napi(value = "path_too_long")]
    PathTooLong,
    /// The data-descriptor tail of a ZIP entry was not searched.
    #[napi(value = "descriptor_tail")]
    DescriptorTail,
}

impl TryFrom<CoreUnverifiedReason> for UnverifiedReason {
    type Error = Error;

    fn try_from(value: CoreUnverifiedReason) -> Result<Self> {
        Ok(match value {
            CoreUnverifiedReason::OverBudget => Self::OverBudget,
            CoreUnverifiedReason::ResourceLimit => Self::ResourceLimit,
            CoreUnverifiedReason::SolidPolicy => Self::SolidPolicy,
            CoreUnverifiedReason::SizeCeiling => Self::SizeCeiling,
            CoreUnverifiedReason::UncoveredBlockCrc => Self::UncoveredBlockCrc,
            CoreUnverifiedReason::NotDecodable => Self::NotDecodable,
            CoreUnverifiedReason::NoEndMarker => Self::NoEndMarker,
            CoreUnverifiedReason::PathTooLong => Self::PathTooLong,
            CoreUnverifiedReason::DescriptorTail => Self::DescriptorTail,
            other => return Err(unknown_variant("unverified reason", other.as_str())),
        })
    }
}

/// Number of items left unverified for one reason.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct UnverifiedCount {
    /// Why the items were not verified.
    pub reason: UnverifiedReason,
    /// Number of items.
    pub count: i64,
}

/// One entry the integrity check could not verify.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct UnverifiedEntry {
    /// Entry path inside the archive.
    pub path: String,
    /// Why the entry was not verified.
    pub reason: UnverifiedReason,
}

/// What a requested integrity check left unverified.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct IntegrityGaps {
    /// Unverified items per reason; reasons with no items are absent.
    pub counts: Vec<UnverifiedCount>,
    /// Unverified entries listed by path, up to a fixed cap (see `omitted`).
    pub entries: Vec<UnverifiedEntry>,
    /// Entries with a path that did not fit `entries`.
    pub omitted: i64,
}

impl TryFrom<&CoreIntegrityGaps> for IntegrityGaps {
    type Error = Error;

    fn try_from(gaps: &CoreIntegrityGaps) -> Result<Self> {
        Ok(Self {
            counts: gaps
                .counts()
                .map(|(reason, count)| {
                    Ok(UnverifiedCount {
                        reason: reason.try_into()?,
                        count: saturating_i64(count),
                    })
                })
                .collect::<Result<_>>()?,
            entries: gaps
                .entries()
                .iter()
                .map(|e| {
                    Ok(UnverifiedEntry {
                        path: path_text(e.path()),
                        reason: e.reason().try_into()?,
                    })
                })
                .collect::<Result<_>>()?,
            omitted: saturating_i64(gaps.omitted()),
        })
    }
}

/// Issue severity.
// Values must equal `exarch_core::inspection::IssueSeverity::as_str`.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueSeverity {
    /// Informational.
    #[napi(value = "INFO")]
    Info,
    /// Policy violation.
    #[napi(value = "LOW")]
    Low,
    /// Security concern.
    #[napi(value = "MEDIUM")]
    Medium,
    /// Exploitable security issue.
    #[napi(value = "HIGH")]
    High,
    /// CVE-level vulnerability.
    #[napi(value = "CRITICAL")]
    Critical,
}

impl From<CoreIssueSeverity> for IssueSeverity {
    fn from(value: CoreIssueSeverity) -> Self {
        match value {
            CoreIssueSeverity::Info => Self::Info,
            CoreIssueSeverity::Low => Self::Low,
            CoreIssueSeverity::Medium => Self::Medium,
            CoreIssueSeverity::High => Self::High,
            CoreIssueSeverity::Critical => Self::Critical,
        }
    }
}

/// Issue category.
// Values must equal `exarch_core::inspection::IssueCategory::as_str`.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueCategory {
    /// Path traversal attack.
    #[napi(value = "Path Traversal")]
    PathTraversal,
    /// Symlink escape attack.
    #[napi(value = "Symlink Escape")]
    SymlinkEscape,
    /// Hardlink escape attack.
    #[napi(value = "Hardlink Escape")]
    HardlinkEscape,
    /// Zip bomb (excessive compression).
    #[napi(value = "Zip Bomb")]
    ZipBomb,
    /// Invalid or unsafe permissions.
    #[napi(value = "Invalid Permissions")]
    InvalidPermissions,
    /// Quota exceeded (file count or size).
    #[napi(value = "Quota Exceeded")]
    QuotaExceeded,
    /// Entry rejected by the security policy.
    #[napi(value = "Security Policy")]
    SecurityPolicy,
    /// Invalid or corrupted archive.
    #[napi(value = "Invalid Archive")]
    InvalidArchive,
    /// Suspicious path or filename.
    #[napi(value = "Suspicious Path")]
    SuspiciousPath,
    /// Executable file detected.
    #[napi(value = "Executable File")]
    ExecutableFile,
    /// A checksum or decoder error proved the payload corrupt.
    #[napi(value = "Corrupt Data")]
    CorruptData,
    /// The integrity check could not cover part of the payload.
    #[napi(value = "Integrity Incomplete")]
    IntegrityIncomplete,
    /// ZIP local header disagrees with its central directory record.
    #[napi(value = "Header Mismatch")]
    HeaderMismatch,
    /// ZIP central directory repeats an entry name.
    #[napi(value = "Duplicate Entry")]
    DuplicateEntry,
    /// ZIP entry data ranges intersect.
    #[napi(value = "Overlapping Entries")]
    OverlappingEntries,
    /// ZIP entry that the central directory does not account for.
    #[napi(value = "Hidden Entry")]
    HiddenEntry,
    /// Two entry names the host filesystem treats as one.
    #[napi(value = "Name Collision")]
    NameCollision,
    /// Informational note that needs no action, such as skipped 7z anti-items.
    #[napi(value = "Archive Note")]
    ArchiveNote,
}

impl TryFrom<CoreIssueCategory> for IssueCategory {
    type Error = Error;

    fn try_from(value: CoreIssueCategory) -> Result<Self> {
        Ok(match value {
            CoreIssueCategory::PathTraversal => Self::PathTraversal,
            CoreIssueCategory::SymlinkEscape => Self::SymlinkEscape,
            CoreIssueCategory::HardlinkEscape => Self::HardlinkEscape,
            CoreIssueCategory::ZipBomb => Self::ZipBomb,
            CoreIssueCategory::InvalidPermissions => Self::InvalidPermissions,
            CoreIssueCategory::QuotaExceeded => Self::QuotaExceeded,
            CoreIssueCategory::SecurityPolicy => Self::SecurityPolicy,
            CoreIssueCategory::InvalidArchive => Self::InvalidArchive,
            CoreIssueCategory::SuspiciousPath => Self::SuspiciousPath,
            CoreIssueCategory::ExecutableFile => Self::ExecutableFile,
            CoreIssueCategory::CorruptData => Self::CorruptData,
            CoreIssueCategory::IntegrityIncomplete => Self::IntegrityIncomplete,
            CoreIssueCategory::HeaderMismatch => Self::HeaderMismatch,
            CoreIssueCategory::DuplicateEntry => Self::DuplicateEntry,
            CoreIssueCategory::OverlappingEntries => Self::OverlappingEntries,
            CoreIssueCategory::HiddenEntry => Self::HiddenEntry,
            CoreIssueCategory::NameCollision => Self::NameCollision,
            CoreIssueCategory::ArchiveNote => Self::ArchiveNote,
            other => return Err(unknown_variant("issue category", other.as_str())),
        })
    }
}

/// Why an entry was left out of an extraction or a creation.
// Generates the TypeScript union only; runtime values come from core's
// `SkipKind::as_str`, guarded by a unit test.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipKind {
    /// A pre-existing destination entry kept under the skip-duplicates policy.
    #[napi(value = "duplicate")]
    Duplicate,
    /// A file refused by the extension allowlist.
    #[napi(value = "extension_not_allowed")]
    ExtensionNotAllowed,
    /// An entry matched by a creation exclude pattern.
    #[napi(value = "excluded")]
    Excluded,
    /// A hidden entry left out by a creation configuration.
    #[napi(value = "hidden")]
    Hidden,
    /// A file larger than the creation file size limit.
    #[napi(value = "over_max_file_size")]
    OverMaxFileSize,
    /// A symlink that cannot be stored.
    #[napi(value = "symlink_unsupported")]
    SymlinkUnsupported,
    /// An entry that could not be read.
    #[napi(value = "unreadable")]
    Unreadable,
}

/// How many entries were skipped for one reason.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct SkipCount {
    /// Why the entries were skipped.
    #[napi(ts_type = "SkipKind")]
    pub kind: String,
    /// How many entries, saturated at `2^32 - 1`.
    pub count: u32,
}

/// One skipped entry.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct SkippedEntry {
    /// The entry path as the operation names it, rendered injectively: a
    /// backslash is `\x5C` and each invalid byte is `\xNN`.
    pub path: String,
    /// Why the entry was skipped.
    #[napi(ts_type = "SkipKind")]
    pub kind: String,
    /// The I/O failure behind an `'unreadable'` skip.
    pub io_kind: Option<IoKind>,
}

/// Everything an operation left out: exact counts per reason plus a bounded
/// sample of the individual entries.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct SkippedSummary {
    /// Exact count per reason; reasons with no skip are absent.
    pub counts: Vec<SkipCount>,
    /// The first skipped entries in the order they were skipped, at most 64.
    pub sample: Vec<SkippedEntry>,
}

impl From<&exarch_core::Skips> for SkippedSummary {
    fn from(skips: &exarch_core::Skips) -> Self {
        Self {
            counts: exarch_core::SkipKind::ALL
                .iter()
                .filter_map(|kind| {
                    let count = skips.count(*kind);
                    (count > 0).then(|| SkipCount {
                        kind: kind.as_str().to_owned(),
                        count: saturating_u32(count),
                    })
                })
                .collect(),
            sample: skips
                .sample()
                .iter()
                .map(|skip| SkippedEntry {
                    path: path_text(&skip.path),
                    kind: skip.kind.as_str().to_owned(),
                    io_kind: skip.io_kind.map(IoKind::from),
                })
                .collect(),
        }
    }
}

/// Report of an archive extraction operation.
///
/// Contains statistics and metadata about the extraction process.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct ExtractionReport {
    /// Number of files successfully extracted.
    pub files_extracted: u32,
    /// Number of directories created.
    pub directories_created: u32,
    /// Number of symlinks created.
    pub symlinks_created: u32,
    /// Total bytes written to disk.
    pub bytes_written: i64,
    /// Extraction duration in milliseconds.
    pub duration_ms: i64,
    /// Number of entries skipped, over all reasons.
    pub files_skipped: u32,
    /// The skipped entries by reason.
    pub skipped: SkippedSummary,
    /// Descriptions of conditions worth surfacing that are not skipped
    /// entries.
    pub warnings: Vec<String>,
}

impl From<CoreReport> for ExtractionReport {
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    fn from(report: CoreReport) -> Self {
        // Use saturating conversions to prevent silent wraparound on overflow
        // This ensures audit trails remain accurate even for very large
        // extractions
        Self {
            files_extracted: saturating_u32(report.files_extracted),
            directories_created: saturating_u32(report.directories_created),
            symlinks_created: saturating_u32(report.symlinks_created),
            bytes_written: saturating_i64(report.bytes_written),
            duration_ms: report.duration.as_millis().min(i64::MAX as u128) as i64,
            files_skipped: saturating_u32(report.files_skipped()),
            skipped: SkippedSummary::from(&report.skipped),
            warnings: report.warnings.iter().map(ToString::to_string).collect(),
        }
    }
}

/// Report of an archive creation operation.
///
/// Contains statistics and metadata about the creation process.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct CreationReport {
    /// Number of files added to the archive.
    pub files_added: u32,
    /// Number of directories added to the archive.
    pub directories_added: u32,
    /// Number of symlinks added to the archive.
    pub symlinks_added: u32,
    /// Total bytes written to the archive (uncompressed).
    pub bytes_written: i64,
    /// Total bytes in the final archive (compressed).
    pub bytes_compressed: i64,
    /// Duration of the creation operation in milliseconds.
    pub duration_ms: i64,
    /// Number of entries skipped, over all reasons (filters, size limit,
    /// unreadable entries, unsupported symlinks).
    pub files_skipped: u32,
    /// The skipped entries by reason.
    pub skipped: SkippedSummary,
    /// Warnings generated during creation.
    pub warnings: Vec<String>,
}

impl From<exarch_core::creation::CreationReport> for CreationReport {
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    fn from(report: exarch_core::creation::CreationReport) -> Self {
        Self {
            files_added: saturating_u32(report.files_added),
            directories_added: saturating_u32(report.directories_added),
            symlinks_added: saturating_u32(report.symlinks_added),
            bytes_written: saturating_i64(report.bytes_written),
            bytes_compressed: saturating_i64(report.bytes_compressed),
            duration_ms: report.duration.as_millis().min(i64::MAX as u128) as i64,
            files_skipped: saturating_u32(report.files_skipped()),
            skipped: SkippedSummary::from(&report.skipped),
            warnings: report.warnings.iter().map(ToString::to_string).collect(),
        }
    }
}

/// Complete manifest of archive contents.
///
/// Generated by `listArchive()`, contains metadata about all entries
/// without extracting them to disk.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct ArchiveManifest {
    /// All entries in the archive (files, dirs, symlinks, hardlinks).
    #[napi(ts_type = "Array<ArchiveEntry>")]
    pub entries: Vec<ArchiveEntry>,
    /// Total number of entries.
    pub total_entries: u32,
    /// Total uncompressed size in bytes.
    pub total_size: i64,
    /// Archive format.
    pub format: ArchiveType,
}

impl TryFrom<exarch_core::inspection::ArchiveManifest> for ArchiveManifest {
    type Error = Failure;

    fn try_from(manifest: exarch_core::inspection::ArchiveManifest) -> CoreResult<Self> {
        let total_entries = saturating_u32(manifest.total_entries());
        let total_size = saturating_i64(manifest.total_size());
        let format = ArchiveType::try_from(manifest.format()).map_err(Failure::Native)?;
        Ok(Self {
            entries: manifest
                .into_entries()
                .into_iter()
                .map(|entry| archive_entry(&entry))
                .collect::<CoreResult<_>>()?,
            total_entries,
            total_size,
            format,
        })
    }
}

/// How a link target is recorded.
///
/// Values must equal the `state` of the matching target interface.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkTargetState {
    /// The target as the archive stores it.
    #[napi(value = "recorded")]
    Recorded,
    /// The archive stores no target.
    #[napi(value = "missing")]
    Missing,
    /// The target was not read: a 7z target kept in compressed entry data.
    #[napi(value = "unread")]
    Unread,
    /// The target could not be read.
    #[napi(value = "unreadable")]
    Unreadable,
    /// The target exceeds the host's name limits; only its length is kept.
    #[napi(value = "oversized")]
    Oversized,
}

/// A link target the archive stores.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct RecordedLinkTarget {
    /// Always `'recorded'`.
    #[napi(ts_type = "'recorded'")]
    pub state: LinkTargetState,
    /// The target as the archive spells it.
    pub path: String,
}

/// A link whose archive stores no target.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct MissingLinkTarget {
    /// Always `'missing'`.
    #[napi(ts_type = "'missing'")]
    pub state: LinkTargetState,
}

/// A link target that was not read.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct UnreadLinkTarget {
    /// Always `'unread'`.
    #[napi(ts_type = "'unread'")]
    pub state: LinkTargetState,
}

/// A link target that could not be read.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct UnreadableLinkTarget {
    /// Always `'unreadable'`.
    #[napi(ts_type = "'unreadable'")]
    pub state: LinkTargetState,
}

/// A link target above the host's name limits.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct OversizedLinkTarget {
    /// Always `'oversized'`.
    #[napi(ts_type = "'oversized'")]
    pub state: LinkTargetState,
    /// Length of the stored target in bytes.
    pub bytes: i64,
}

type LinkTarget = Either5<
    RecordedLinkTarget,
    MissingLinkTarget,
    UnreadLinkTarget,
    UnreadableLinkTarget,
    OversizedLinkTarget,
>;

fn link_target(target: &exarch_core::inspection::LinkTarget) -> CoreResult<LinkTarget> {
    use exarch_core::inspection::LinkTarget as Core;

    Ok(match target {
        Core::Recorded(path) => Either5::A(RecordedLinkTarget {
            state: LinkTargetState::Recorded,
            path: utf8_path(path)?,
        }),
        Core::Missing => Either5::B(MissingLinkTarget {
            state: LinkTargetState::Missing,
        }),
        Core::Unread => Either5::C(UnreadLinkTarget {
            state: LinkTargetState::Unread,
        }),
        Core::Unreadable => Either5::D(UnreadableLinkTarget {
            state: LinkTargetState::Unreadable,
        }),
        Core::Oversized { bytes } => Either5::E(OversizedLinkTarget {
            state: LinkTargetState::Oversized,
            bytes: saturating_i64(u64::try_from(*bytes).unwrap_or(u64::MAX)),
        }),
        _ => return Err(Failure::Native(unknown_variant("link target", "unknown"))),
    })
}

/// The text of `path`, or the refusal a listing must raise: a lossy rendering
/// could merge two distinct entries into one name.
pub fn utf8_path(path: &std::path::Path) -> CoreResult<String> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        Failure::from(CoreError::from(
            exarch_core::Malformation::EntryPathNotUtf8 {
                path: path.to_path_buf(),
            },
        ))
    })
}

/// A regular file in a listing.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct ManifestFileEntry {
    /// Entry path (relative, as stored in archive).
    pub path: String,
    /// Always `'File'`.
    #[napi(ts_type = "'File'")]
    pub entry_type: ManifestEntryType,
    /// Uncompressed size in bytes.
    pub size: i64,
    /// Compressed size in bytes (if the format reports one).
    pub compressed_size: Option<i64>,
    /// File permissions (raw Unix mode).
    pub mode: Option<u32>,
    /// Modification time (milliseconds since Unix epoch).
    pub modified: Option<i64>,
}

/// A directory in a listing.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct ManifestDirectoryEntry {
    /// Entry path (relative, as stored in archive).
    pub path: String,
    /// Always `'Directory'`.
    #[napi(ts_type = "'Directory'")]
    pub entry_type: ManifestEntryType,
    /// Compressed size in bytes (if the format reports one).
    pub compressed_size: Option<i64>,
    /// File permissions (raw Unix mode).
    pub mode: Option<u32>,
    /// Modification time (milliseconds since Unix epoch).
    pub modified: Option<i64>,
}

/// A symbolic link in a listing.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct ManifestSymlinkEntry {
    /// Entry path (relative, as stored in archive).
    pub path: String,
    /// Always `'Symlink'`.
    #[napi(ts_type = "'Symlink'")]
    pub entry_type: ManifestEntryType,
    /// Compressed size in bytes (if the format reports one).
    pub compressed_size: Option<i64>,
    /// File permissions (raw Unix mode).
    pub mode: Option<u32>,
    /// Modification time (milliseconds since Unix epoch).
    pub modified: Option<i64>,
    /// The link target. A 7z target is `'unread'`: listing does not decode 7z
    /// entry data to read it.
    #[napi(ts_type = "LinkTarget")]
    pub target: LinkTarget,
}

/// A hard link in a listing.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct ManifestHardlinkEntry {
    /// Entry path (relative, as stored in archive).
    pub path: String,
    /// Always `'Hardlink'`.
    #[napi(ts_type = "'Hardlink'")]
    pub entry_type: ManifestEntryType,
    /// Compressed size in bytes (if the format reports one).
    pub compressed_size: Option<i64>,
    /// File permissions (raw Unix mode).
    pub mode: Option<u32>,
    /// Modification time (milliseconds since Unix epoch).
    pub modified: Option<i64>,
    /// The link target.
    #[napi(ts_type = "LinkTarget")]
    pub target: LinkTarget,
}

/// One entry of a listing, discriminated by `entryType`.
pub type ArchiveEntry =
    Either4<ManifestFileEntry, ManifestDirectoryEntry, ManifestSymlinkEntry, ManifestHardlinkEntry>;

/// The fields every entry kind carries.
struct EntryCommon {
    path: String,
    compressed_size: Option<i64>,
    mode: Option<u32>,
    modified: Option<i64>,
}

#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn entry_common(entry: &exarch_core::inspection::ArchiveEntry) -> CoreResult<EntryCommon> {
    Ok(EntryCommon {
        path: entry
            .utf8_path()
            .map_err(|malformation| Failure::from(CoreError::from(malformation)))?
            .to_owned(),
        compressed_size: entry.compressed_size().map(saturating_i64),
        mode: entry.mode.map(exarch_core::RawMode::get),
        modified: entry.modified.and_then(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
        }),
    })
}

fn archive_entry(entry: &exarch_core::inspection::ArchiveEntry) -> CoreResult<ArchiveEntry> {
    use exarch_core::inspection::ManifestEntryKind as Kind;

    let EntryCommon {
        path,
        compressed_size,
        mode,
        modified,
    } = entry_common(entry)?;
    Ok(match &entry.kind {
        Kind::File { .. } => Either4::A(ManifestFileEntry {
            path,
            entry_type: ManifestEntryType::File,
            size: saturating_i64(entry.size()),
            compressed_size,
            mode,
            modified,
        }),
        Kind::Directory => Either4::B(ManifestDirectoryEntry {
            path,
            entry_type: ManifestEntryType::Directory,
            compressed_size,
            mode,
            modified,
        }),
        Kind::Symlink { target } => Either4::C(ManifestSymlinkEntry {
            path,
            entry_type: ManifestEntryType::Symlink,
            compressed_size,
            mode,
            modified,
            target: link_target(target)?,
        }),
        Kind::Hardlink { target } => Either4::D(ManifestHardlinkEntry {
            path,
            entry_type: ManifestEntryType::Hardlink,
            compressed_size,
            mode,
            modified,
            target: link_target(target)?,
        }),
        _ => return Err(Failure::Native(unknown_variant("entry kind", "unknown"))),
    })
}

/// Result of archive verification.
///
/// Generated by `verifyArchive()`, contains the result of the security checks
/// performed without extracting files to disk.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct VerificationReport {
    /// Overall verification status.
    pub status: VerificationStatus,
    /// Integrity check result.
    pub integrity_status: IntegrityStatus,
    /// What the integrity check left unverified; absent unless the check was
    /// requested.
    pub integrity_gaps: Option<IntegrityGaps>,
    /// Security check result.
    pub security_status: CheckStatus,
    /// List of all issues found (sorted by severity).
    #[napi(ts_type = "Array<VerificationIssue>")]
    pub issues: Vec<VerificationIssue>,
    /// Total entries scanned.
    pub total_entries: u32,
    /// Entries flagged as suspicious.
    pub suspicious_entries: u32,
    /// Total uncompressed size.
    pub total_size: i64,
    /// Archive format.
    pub format: ArchiveType,
}

impl TryFrom<exarch_core::inspection::VerificationReport> for VerificationReport {
    type Error = Failure;

    fn try_from(
        report: exarch_core::inspection::VerificationReport,
    ) -> std::result::Result<Self, Failure> {
        let status = report.status().into();
        let integrity_status = report
            .integrity_status()
            .try_into()
            .map_err(Failure::Native)?;
        let integrity_gaps = report
            .integrity_gaps()
            .map(IntegrityGaps::try_from)
            .transpose()
            .map_err(Failure::Native)?;
        let security_status = report.security_status().into();
        let total_entries = saturating_u32(report.total_entries());
        let suspicious_entries = saturating_u32(report.suspicious_entries());
        let total_size = saturating_i64(report.total_size());
        let format = ArchiveType::try_from(report.format()).map_err(Failure::Native)?;
        Ok(Self {
            status,
            integrity_status,
            integrity_gaps,
            security_status,
            issues: report
                .into_issues()
                .into_iter()
                .map(VerificationIssue::try_from)
                .collect::<Result<_>>()
                .map_err(Failure::Native)?,
            total_entries,
            suspicious_entries,
            total_size,
            format,
        })
    }
}

/// Single verification issue.
///
/// `code`, `subCode`, `relaxableBy`, `setting` and `ioKind` are those of the
/// error a failed extraction would raise for the same finding, and pair as
/// they do on an error (`VerificationIssue` in `index.d.ts` is this object
/// intersected with the per-code pairing); a heuristic finding carries none.
#[napi(object, js_name = "VerificationIssueFields")]
#[derive(Debug, Clone)]
pub struct VerificationIssue {
    /// Issue severity level.
    pub severity: IssueSeverity,
    /// Issue category.
    pub category: IssueCategory,
    /// Entry path that triggered issue (if applicable); a path that is not
    /// valid UTF-8 or contains a backslash is rendered injectively: a backslash
    /// is `\x5C` and each invalid byte is `\xNN`.
    pub entry_path: Option<String>,
    /// Human-readable description.
    pub message: String,
    /// The `ErrorCode` extraction would fail with, for a refusal.
    #[napi(ts_type = "ErrorCode")]
    pub code: Option<String>,
    /// Finer classification of the refusal.
    #[napi(
        ts_type = "InvalidArchiveSubCode | SecurityViolationSubCode | QuotaSubCode | ZipBombSubCode"
    )]
    pub sub_code: Option<String>,
    /// The `SecurityConfig` setting that relaxes the refusal.
    #[napi(ts_type = "PolicySetting")]
    pub relaxable_by: Option<String>,
    /// The configuration setting an `INVALID_CONFIGURATION` refusal names.
    #[napi(ts_type = "ConfigSetting")]
    pub setting: Option<String>,
    /// The kind of an `IO_ERROR` refusal.
    pub io_kind: Option<IoKind>,
}

impl TryFrom<exarch_core::inspection::VerificationIssue> for VerificationIssue {
    type Error = Error;

    fn try_from(issue: exarch_core::inspection::VerificationIssue) -> Result<Self> {
        let kind = issue.ffi_kind();
        Ok(Self {
            severity: issue.severity().into(),
            category: issue.category().try_into()?,
            entry_path: issue.entry_path().map(path_text),
            message: issue.message(),
            code: kind.map(|kind| kind.code().as_str().to_owned()),
            sub_code: issue.sub_code().map(|code| code.as_str().to_owned()),
            relaxable_by: kind
                .and_then(exarch_core::FfiKind::relaxable_by)
                .map(|setting| setting.as_str().to_owned()),
            setting: kind
                .and_then(exarch_core::FfiKind::setting)
                .map(|setting| setting.as_str().to_owned()),
            io_kind: match kind {
                Some(exarch_core::FfiKind::Io(io_kind)) => Some(IoKind::from(*io_kind)),
                _ => None,
            },
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::assert_matches;

    fn skipped(count: usize) -> exarch_core::Skips {
        let mut skips = exarch_core::Skips::default();
        for i in 0..count {
            let skip = exarch_core::Skip::new(exarch_core::SkipKind::Duplicate, format!("f{i}"));
            assert!(skips.record(skip).is_ok());
        }
        skips
    }

    fn anti(count: u64) -> exarch_core::ExtractionWarning {
        exarch_core::ExtractionWarning::AntiItemsSkipped { count }
    }

    #[test]
    fn test_skipped_summary_carries_counts_sample_and_io_kind() {
        let mut skips = exarch_core::Skips::default();
        skips
            .record(exarch_core::Skip::new(
                exarch_core::SkipKind::Duplicate,
                "a",
            ))
            .unwrap();
        skips
            .record(exarch_core::Skip::new(
                exarch_core::SkipKind::Duplicate,
                "b",
            ))
            .unwrap();
        let mut unreadable = exarch_core::Skip::new(exarch_core::SkipKind::Unreadable, "c");
        unreadable.io_kind = Some(std::io::ErrorKind::PermissionDenied);
        skips.record(unreadable).unwrap();

        let summary = SkippedSummary::from(&skips);

        let counts: Vec<(&str, u32)> = summary
            .counts
            .iter()
            .map(|c| (c.kind.as_str(), c.count))
            .collect();
        assert_eq!(counts, [("duplicate", 2), ("unreadable", 1)]);
        assert_eq!(summary.sample.len(), 3);
        assert_eq!(summary.sample[2].kind, "unreadable");
        assert_eq!(summary.sample[2].io_kind, Some(IoKind::PermissionDenied));
        assert_eq!(summary.sample[0].io_kind, None);
    }

    use exarch_core::Compressed;
    use std::time::Duration;

    #[test]
    fn test_extraction_report_conversion() {
        let mut core_report = CoreReport::new();
        core_report.files_extracted = 10;
        core_report.directories_created = 5;
        core_report.symlinks_created = 2;
        core_report.bytes_written = 1024;
        core_report.duration = Duration::from_millis(500);
        core_report.skipped = skipped(1);
        core_report.add_warning(anti(1));

        let report = ExtractionReport::from(core_report);

        assert_eq!(report.files_extracted, 10);
        assert_eq!(report.directories_created, 5);
        assert_eq!(report.symlinks_created, 2);
        assert_eq!(report.bytes_written, 1024);
        assert_eq!(report.duration_ms, 500);
        assert_eq!(report.files_skipped, 1);
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.warnings[0], anti(1).to_string());
    }

    #[test]
    fn test_extraction_report_zero_values() {
        let core_report = CoreReport::new();
        let report = ExtractionReport::from(core_report);

        assert_eq!(report.files_extracted, 0);
        assert_eq!(report.directories_created, 0);
        assert_eq!(report.symlinks_created, 0);
        assert_eq!(report.bytes_written, 0);
        assert_eq!(report.files_skipped, 0);
        assert_eq!(report.warnings.len(), 0);
    }

    #[test]
    fn test_extraction_report_large_values() {
        let mut core_report = CoreReport::new();
        core_report.files_extracted = 100_000;
        core_report.directories_created = 50_000;
        core_report.bytes_written = 10_000_000_000; // 10 GB
        core_report.duration = Duration::from_hours(1);

        let report = ExtractionReport::from(core_report);

        assert_eq!(report.files_extracted, 100_000);
        assert_eq!(report.bytes_written, 10_000_000_000);
        assert_eq!(report.duration_ms, 3_600_000);
    }

    #[test]
    fn test_extraction_report_multiple_warnings() {
        let mut core_report = CoreReport::new();
        core_report.add_warning(anti(1));
        core_report.add_warning(anti(2));
        core_report.add_warning(anti(3));

        let report = ExtractionReport::from(core_report);

        assert_eq!(report.warnings.len(), 3);
        assert_eq!(report.warnings[0], anti(1).to_string());
        assert_eq!(report.warnings[1], anti(2).to_string());
        assert_eq!(report.warnings[2], anti(3).to_string());
    }

    #[test]
    fn test_extraction_report_duration_hours() {
        let mut core_report = CoreReport::new();
        core_report.duration = Duration::from_hours(2);

        let report = ExtractionReport::from(core_report);

        assert_eq!(
            report.duration_ms, 7_200_000,
            "2 hours should be 7,200,000 milliseconds"
        );
    }

    #[test]
    fn test_extraction_report_duration_zero() {
        let mut core_report = CoreReport::new();
        core_report.duration = Duration::from_secs(0);

        let report = ExtractionReport::from(core_report);

        assert_eq!(report.duration_ms, 0, "zero duration should be 0 ms");
    }

    #[test]
    fn test_extraction_report_duration_microseconds() {
        let mut core_report = CoreReport::new();
        core_report.duration = Duration::from_micros(1500); // 1.5 ms

        let report = ExtractionReport::from(core_report);

        assert_eq!(
            report.duration_ms, 1,
            "1500 microseconds should round to 1 millisecond"
        );
    }

    #[test]
    fn test_extraction_report_warnings_order_preserved() {
        let mut core_report = CoreReport::new();
        core_report.add_warning(anti(1));
        core_report.add_warning(anti(2));
        core_report.add_warning(anti(3));

        let report = ExtractionReport::from(core_report);

        assert_eq!(report.warnings.len(), 3, "should have 3 warnings");
        assert_eq!(
            report.warnings[0],
            anti(1).to_string(),
            "first warning should be at index 0"
        );
        assert_eq!(
            report.warnings[1],
            anti(2).to_string(),
            "second warning should be at index 1"
        );
        assert_eq!(
            report.warnings[2],
            anti(3).to_string(),
            "third warning should be at index 2"
        );
    }

    // CreationReport tests
    #[test]
    fn test_creation_report_conversion() {
        let mut core_report = exarch_core::creation::CreationReport::new();
        core_report.files_added = 10;
        core_report.directories_added = 5;
        core_report.symlinks_added = 2;
        core_report.bytes_written = 1024;
        core_report.bytes_compressed = 512;
        core_report.duration = std::time::Duration::from_millis(500);
        core_report.skipped = skipped(1);
        let warning = exarch_core::creation::CreationWarning::ZipRatioCheckFailed {
            reason: "Test warning".to_string(),
        };
        let expected = warning.to_string();
        core_report.add_warning(warning);

        let report = CreationReport::from(core_report);

        assert_eq!(report.files_added, 10);
        assert_eq!(report.directories_added, 5);
        assert_eq!(report.symlinks_added, 2);
        assert_eq!(report.bytes_written, 1024);
        assert_eq!(report.bytes_compressed, 512);
        assert_eq!(report.duration_ms, 500);
        assert_eq!(report.files_skipped, 1);
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.warnings[0], expected);
    }

    fn sized_entry(name: &str, size: u64) -> exarch_core::inspection::ArchiveEntry {
        exarch_core::inspection::ArchiveEntry::new(
            std::path::PathBuf::from(name),
            exarch_core::inspection::ManifestEntryKind::File {
                size: exarch_core::Uncompressed(size),
            },
        )
    }

    fn policy_issue() -> exarch_core::inspection::VerificationIssue {
        let error = exarch_core::ArchiveError::from(exarch_core::Violation::EncryptedArchive);
        exarch_core::inspection::VerificationIssue::from_error(&error, None)
    }

    // ArchiveEntry tests
    #[test]
    fn test_archive_entry_conversion() {
        use std::path::PathBuf;
        use std::time::UNIX_EPOCH;

        let mut core_entry = exarch_core::inspection::ArchiveEntry::new(
            PathBuf::from("test/file.txt"),
            exarch_core::inspection::ManifestEntryKind::File {
                size: exarch_core::Uncompressed(1024),
            },
        );
        core_entry.compression = exarch_core::EntryCompression::Entry(Compressed(512));
        core_entry.mode = Some(exarch_core::RawMode::new(0o644));
        core_entry.modified = Some(UNIX_EPOCH + std::time::Duration::from_secs(1000));

        let Either4::A(entry) = archive_entry(&core_entry).unwrap() else {
            panic!("a regular file converts to a file entry");
        };

        assert_eq!(entry.path, "test/file.txt");
        assert_eq!(entry.entry_type, ManifestEntryType::File);
        assert_eq!(entry.size, 1024);
        assert_eq!(entry.compressed_size, Some(512));
        assert_eq!(entry.mode, Some(0o644));
        assert_eq!(entry.modified, Some(1_000_000));
    }

    #[test]
    fn test_symlink_entry_carries_a_typed_target() {
        use exarch_core::inspection::LinkTarget as Core;
        use exarch_core::inspection::ManifestEntryKind;

        let entry = |target| {
            exarch_core::inspection::ArchiveEntry::new(
                std::path::PathBuf::from("ln"),
                ManifestEntryKind::Symlink { target },
            )
        };
        let Either4::C(recorded) = archive_entry(&entry(Core::Recorded("a/b".into()))).unwrap()
        else {
            panic!("a symlink converts to a symlink entry");
        };
        assert_matches!(
            recorded.target,
            Either5::A(RecordedLinkTarget { ref path, .. }) if path == "a/b"
        );
        let Either4::C(oversized) = archive_entry(&entry(Core::Oversized { bytes: 9000 })).unwrap()
        else {
            panic!("a symlink converts to a symlink entry");
        };
        assert_matches!(
            oversized.target,
            Either5::E(OversizedLinkTarget { bytes: 9000, .. })
        );
        let Either4::C(unread) = archive_entry(&entry(Core::Unread)).unwrap() else {
            panic!("a symlink converts to a symlink entry");
        };
        assert_matches!(unread.target, Either5::C(_));
    }

    #[cfg(unix)]
    #[test]
    fn test_non_utf8_entry_path_is_refused_not_rendered_lossily() {
        use std::os::unix::ffi::OsStrExt;

        let core_entry = exarch_core::inspection::ArchiveEntry::new(
            std::path::PathBuf::from(std::ffi::OsStr::from_bytes(b"a\xFFb")),
            exarch_core::inspection::ManifestEntryKind::Directory,
        );
        let failure = archive_entry(&core_entry).unwrap_err();
        assert_matches!(failure, Failure::Core(CoreError::InvalidArchive(_)));
    }

    // ArchiveManifest tests
    #[test]
    fn test_archive_manifest_conversion() {
        let mut core_manifest =
            exarch_core::inspection::ArchiveManifest::new(CoreArchiveType::TarGz);
        for i in 0..10 {
            core_manifest
                .add_entry(sized_entry(&format!("f{i}"), 500))
                .unwrap();
        }

        let manifest = ArchiveManifest::try_from(core_manifest).unwrap();

        assert_eq!(manifest.total_entries, 10);
        assert_eq!(manifest.total_size, 5000);
        assert_eq!(manifest.format, ArchiveType::TarGz);
    }

    // VerificationReport tests
    #[test]
    fn test_verification_report_conversion() {
        let mut core_manifest =
            exarch_core::inspection::ArchiveManifest::new(CoreArchiveType::TarGz);
        for i in 0..10 {
            core_manifest
                .add_entry(sized_entry(&format!("f{i}"), 500))
                .unwrap();
        }
        let core_report =
            exarch_core::inspection::VerificationReport::from_entry_issues(&core_manifest, |_| {
                Vec::new()
            });

        let report = VerificationReport::try_from(core_report).unwrap();

        assert_eq!(report.status, VerificationStatus::Pass);
        assert_eq!(report.integrity_status, IntegrityStatus::Skipped);
        assert_eq!(report.security_status, CheckStatus::Pass);
        assert_eq!(report.total_entries, 10);
        assert_eq!(report.suspicious_entries, 0);
        assert_eq!(report.total_size, 5000);
    }

    #[test]
    fn test_security_policy_issue_conversion_and_status() {
        let core_issue = policy_issue();

        let issue = VerificationIssue::try_from(core_issue).unwrap();
        assert_eq!(issue.category, IssueCategory::SecurityPolicy);

        let mut manifest = exarch_core::inspection::ArchiveManifest::new(
            exarch_core::formats::detect::ArchiveType::Tar,
        );
        manifest
            .add_entry(exarch_core::inspection::ArchiveEntry::new(
                std::path::PathBuf::from("link"),
                exarch_core::inspection::ManifestEntryKind::File {
                    size: exarch_core::Uncompressed(0),
                },
            ))
            .unwrap();
        let core_report =
            exarch_core::inspection::VerificationReport::from_entry_issues(&manifest, |_| {
                vec![policy_issue()]
            });
        let report = VerificationReport::try_from(core_report).unwrap();
        assert_eq!(report.security_status, CheckStatus::Fail);
    }

    // VerificationIssue tests
    #[test]
    fn test_verification_issue_conversion() {
        use std::path::PathBuf;

        let error = exarch_core::ArchiveError::PathTraversal {
            path: PathBuf::from("../etc/passwd"),
        };
        let core_issue = exarch_core::inspection::VerificationIssue::from_error(
            &error,
            Some(PathBuf::from("../etc/passwd")),
        );

        let issue = VerificationIssue::try_from(core_issue).unwrap();

        assert_eq!(issue.severity, IssueSeverity::Critical);
        assert_eq!(issue.category, IssueCategory::PathTraversal);
        assert_eq!(issue.entry_path, Some("../etc/passwd".to_string()));
        assert_eq!(issue.message, "Path traversal detected: ../etc/passwd");
        assert_eq!(issue.code.as_deref(), Some("PATH_TRAVERSAL"));
        assert_eq!(issue.sub_code, None);
        assert_eq!(issue.relaxable_by, None);
    }

    #[test]
    fn test_policy_refusal_issue_carries_sub_code_and_setting() {
        let issue = VerificationIssue::try_from(policy_issue()).unwrap();

        assert_eq!(issue.code.as_deref(), Some("SECURITY_VIOLATION"));
        assert_eq!(issue.sub_code.as_deref(), Some("ENCRYPTED"));
        assert_eq!(issue.relaxable_by, None);
    }

    #[test]
    fn test_heuristic_issue_carries_no_refusal_properties() {
        let issue = VerificationIssue::try_from(exarch_core::inspection::VerificationIssue::new(
            exarch_core::inspection::IssueSeverity::Low,
            exarch_core::Finding::Heuristic(exarch_core::Heuristic::SuspiciousExtension),
        ))
        .unwrap();

        assert_eq!(issue.code, None);
        assert_eq!(issue.sub_code, None);
        assert_eq!(issue.io_kind, None);
    }

    // CR-004: Overflow/saturating conversion tests
    #[test]
    fn test_extraction_report_saturates_files_extracted_at_u32_max() {
        let mut core_report = CoreReport::new();
        // Set to value > u32::MAX
        core_report.files_extracted = (u32::MAX as usize) + 1000;

        let report = ExtractionReport::from(core_report);

        assert_eq!(
            report.files_extracted,
            u32::MAX,
            "files_extracted should saturate to u32::MAX"
        );
    }

    #[test]
    fn test_extraction_report_saturates_bytes_written_at_i64_max() {
        let mut core_report = CoreReport::new();
        // Set to value > i64::MAX
        core_report.bytes_written = u64::MAX;

        let report = ExtractionReport::from(core_report);

        assert_eq!(
            report.bytes_written,
            i64::MAX,
            "bytes_written should saturate to i64::MAX"
        );
    }

    #[test]
    fn test_extraction_report_saturates_duration_ms_at_i64_max() {
        let mut core_report = CoreReport::new();
        // Create a very large duration that exceeds i64::MAX milliseconds
        // i64::MAX ms is about 292 million years, so use u64::MAX seconds
        core_report.duration = Duration::from_secs(u64::MAX);

        let report = ExtractionReport::from(core_report);

        assert_eq!(
            report.duration_ms,
            i64::MAX,
            "duration_ms should saturate to i64::MAX"
        );
    }

    #[test]
    fn test_creation_report_saturates_files_added_at_u32_max() {
        let mut core_report = exarch_core::creation::CreationReport::new();
        core_report.files_added = (u32::MAX as usize) + 1000;

        let report = CreationReport::from(core_report);

        assert_eq!(
            report.files_added,
            u32::MAX,
            "files_added should saturate to u32::MAX"
        );
    }

    #[test]
    fn test_creation_report_saturates_bytes_written_at_i64_max() {
        let mut core_report = exarch_core::creation::CreationReport::new();
        core_report.bytes_written = u64::MAX;

        let report = CreationReport::from(core_report);

        assert_eq!(
            report.bytes_written,
            i64::MAX,
            "bytes_written should saturate to i64::MAX"
        );
    }

    #[test]
    fn test_creation_report_saturates_bytes_compressed_at_i64_max() {
        let mut core_report = exarch_core::creation::CreationReport::new();
        core_report.bytes_compressed = u64::MAX;

        let report = CreationReport::from(core_report);

        assert_eq!(
            report.bytes_compressed,
            i64::MAX,
            "bytes_compressed should saturate to i64::MAX"
        );
    }

    #[test]
    fn test_saturating_u32_clamps_at_u32_max() {
        assert_eq!(saturating_u32(7), 7);
        assert_eq!(saturating_u32((u32::MAX as usize) + 1000), u32::MAX);
    }

    #[test]
    fn test_saturating_i64_clamps_at_i64_max() {
        assert_eq!(saturating_i64(7), 7);
        assert_eq!(saturating_i64(u64::MAX), i64::MAX);
    }

    #[test]
    fn test_archive_manifest_saturates_total_size_at_i64_max() {
        let mut core_manifest =
            exarch_core::inspection::ArchiveManifest::new(CoreArchiveType::TarGz);
        core_manifest
            .add_entry(sized_entry("big", u64::MAX))
            .unwrap();

        let manifest = ArchiveManifest::try_from(core_manifest).unwrap();

        assert_eq!(
            manifest.total_size,
            i64::MAX,
            "total_size should saturate to i64::MAX"
        );
    }

    #[test]
    fn test_archive_entry_saturates_size_at_i64_max() {
        let core_entry = sized_entry("test.txt", u64::MAX);

        let Either4::A(entry) = archive_entry(&core_entry).unwrap() else {
            panic!("a regular file converts to a file entry");
        };

        assert_eq!(entry.size, i64::MAX, "size should saturate to i64::MAX");
    }

    #[test]
    fn test_archive_entry_saturates_compressed_size_at_i64_max() {
        let mut core_entry = sized_entry("test.txt", 1024);
        core_entry.compression = exarch_core::EntryCompression::Entry(Compressed(u64::MAX));

        let Either4::A(entry) = archive_entry(&core_entry).unwrap() else {
            panic!("a regular file converts to a file entry");
        };

        assert_eq!(
            entry.compressed_size,
            Some(i64::MAX),
            "compressed_size should saturate to i64::MAX"
        );
    }

    fn assert_all_distinct<T: PartialEq + std::fmt::Debug>(values: &[T]) {
        for (i, a) in values.iter().enumerate() {
            assert!(
                values[i + 1..].iter().all(|b| a != b),
                "{a:?} is mapped from more than one core variant"
            );
        }
    }

    #[test]
    fn test_archive_type_try_from_covers_every_core_variant() {
        let mapped: Vec<_> = CoreArchiveType::ALL
            .iter()
            .map(|v| ArchiveType::try_from(*v).unwrap())
            .collect();
        assert_all_distinct(&mapped);
    }

    #[test]
    fn test_issue_category_try_from_covers_every_core_variant() {
        let mapped: Vec<_> = CoreIssueCategory::ALL
            .iter()
            .map(|v| IssueCategory::try_from(*v).unwrap())
            .collect();
        assert_all_distinct(&mapped);
    }

    #[test]
    fn test_integrity_status_try_from_covers_every_core_variant() {
        let mapped: Vec<_> = CoreIntegrityStatus::ALL
            .iter()
            .map(|v| IntegrityStatus::try_from(*v).unwrap())
            .collect();
        assert_all_distinct(&mapped);
    }

    #[test]
    fn test_unverified_reason_try_from_covers_every_core_variant() {
        let mapped: Vec<_> = CoreUnverifiedReason::ALL
            .iter()
            .map(|v| UnverifiedReason::try_from(*v).unwrap())
            .collect();
        assert_all_distinct(&mapped);
    }

    #[test]
    fn test_exhaustive_enum_from_is_injective() {
        assert_all_distinct(
            &CoreVerificationStatus::ALL
                .iter()
                .map(|v| VerificationStatus::from(*v))
                .collect::<Vec<_>>(),
        );
        assert_all_distinct(
            &CoreCheckStatus::ALL
                .iter()
                .map(|v| CheckStatus::from(*v))
                .collect::<Vec<_>>(),
        );
        assert_all_distinct(
            &CoreIssueSeverity::ALL
                .iter()
                .map(|v| IssueSeverity::from(*v))
                .collect::<Vec<_>>(),
        );
        assert_all_distinct(
            &CoreManifestEntryType::ALL
                .iter()
                .map(|v| ManifestEntryType::from(*v))
                .collect::<Vec<_>>(),
        );
    }

    fn union_line<T: Copy>(name: &str, all: &[T], as_str: fn(T) -> &'static str) -> String {
        let values: Vec<String> = all.iter().map(|v| format!("'{}'", as_str(*v))).collect();
        format!("export type {name} = {}", values.join(" | "))
    }

    #[test]
    fn test_index_d_ts_unions_match_core_enums() {
        let dts = include_str!("../index.d.ts");
        let expected = [
            union_line("ArchiveType", CoreArchiveType::ALL, CoreArchiveType::as_str),
            union_line(
                "IssueCategory",
                CoreIssueCategory::ALL,
                CoreIssueCategory::as_str,
            ),
            union_line(
                "IssueSeverity",
                CoreIssueSeverity::ALL,
                CoreIssueSeverity::as_str,
            ),
            union_line("CheckStatus", CoreCheckStatus::ALL, CoreCheckStatus::as_str),
            union_line(
                "IntegrityStatus",
                CoreIntegrityStatus::ALL,
                CoreIntegrityStatus::as_str,
            ),
            union_line(
                "UnverifiedReason",
                CoreUnverifiedReason::ALL,
                CoreUnverifiedReason::as_str,
            ),
            union_line(
                "ManifestEntryType",
                CoreManifestEntryType::ALL,
                CoreManifestEntryType::as_str,
            ),
            union_line(
                "VerificationStatus",
                CoreVerificationStatus::ALL,
                CoreVerificationStatus::as_str,
            ),
        ];
        for line in expected {
            assert!(
                dts.lines().any(|l| l == line),
                "index.d.ts out of sync with exarch-core, expected line:\n{line}"
            );
        }
    }
}
