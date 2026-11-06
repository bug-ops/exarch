//! Node.js bindings for `ExtractionReport`.

use exarch_core::ArchiveType as CoreArchiveType;
use exarch_core::BackupIdentity as CoreBackupIdentity;
use exarch_core::CheckStatus as CoreCheckStatus;
use exarch_core::CreatableFormat as CoreCreatableFormat;
use exarch_core::CreationWarning as CoreCreationWarning;
use exarch_core::Durability as CoreDurability;
use exarch_core::ExtractionReport as CoreReport;
use exarch_core::ExtractionWarning as CoreExtractionWarning;
use exarch_core::IntegrityGaps as CoreIntegrityGaps;
use exarch_core::IntegrityStatus as CoreIntegrityStatus;
use exarch_core::IssueCategory as CoreIssueCategory;
use exarch_core::IssueSeverity as CoreIssueSeverity;
use exarch_core::ManifestEntryType as CoreManifestEntryType;
use exarch_core::UnverifiedReason as CoreUnverifiedReason;
use exarch_core::VerificationStatus as CoreVerificationStatus;
use napi::Error;
use napi::Result;
use napi_derive::napi;

use crate::CoreResult;
use crate::error::Failure;
use crate::error::IoKind;
use crate::utils::path_text;
use crate::utils::utf8_path;
use exarch_core::ArchiveError as CoreError;
use exarch_core::sanitize_path_for_error;
use napi::bindgen_prelude::Either;
use napi::bindgen_prelude::Either3;
use napi::bindgen_prelude::Either4;
use napi::bindgen_prelude::Either5;

pub fn saturating_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Whole milliseconds of `duration`, clamped to `i64::MAX`.
pub fn saturating_millis(duration: std::time::Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
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

/// Archive format that can be created: `ArchiveType` without `'SevenZ'`.
// Values must equal `exarch_core::CreatableFormat::NAMES`.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreatableFormat {
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
}

impl From<CreatableFormat> for CoreCreatableFormat {
    fn from(value: CreatableFormat) -> Self {
        match value {
            CreatableFormat::Tar => Self::Tar,
            CreatableFormat::TarGz => Self::TarGz,
            CreatableFormat::TarBz2 => Self::TarBz2,
            CreatableFormat::TarXz => Self::TarXz,
            CreatableFormat::TarZst => Self::TarZst,
            CreatableFormat::Zip => Self::Zip,
        }
    }
}

/// Whether a created archive is flushed to stable storage before success is
/// reported.
///
/// `'synced'` (the default) flushes the file and its directory entry.
/// `'unsynced'` skips both and is faster, but after a crash or power loss a
/// replaced output can be empty or truncated and a new output can be empty,
/// and write-back errors (network filesystems, quotas, delayed allocation) are
/// not reported, so success does not prove the bytes reached the disk.
// Values must equal `exarch_core::Durability::NAMES`.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    /// Flush the file and its directory entry.
    #[napi(value = "synced")]
    Synced,
    /// Skip the flushes.
    #[napi(value = "unsynced")]
    Unsynced,
}

impl From<Durability> for CoreDurability {
    fn from(value: Durability) -> Self {
        match value {
            Durability::Synced => Self::Synced,
            Durability::Unsynced => Self::Unsynced,
        }
    }
}

/// Manifest entry type.
// Values must equal `exarch_core::ManifestEntryType::as_str`.
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
// Values must equal `exarch_core::VerificationStatus::as_str`.
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
// Values must equal `exarch_core::CheckStatus::as_str`.
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
// Values must equal `exarch_core::IntegrityStatus::as_str`.
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
// Values must equal `exarch_core::UnverifiedReason::as_str`.
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
// Values must equal `exarch_core::IssueSeverity::as_str`.
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
// Values must equal `exarch_core::IssueCategory::as_str`.
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
    /// An entry that the extraction selection leaves out.
    #[napi(value = "not_selected")]
    NotSelected,
    /// An entry whose whole path was removed by stripping leading components.
    #[napi(value = "stripped_away")]
    StrippedAway,
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

/// Class of an extraction warning.
// Values must equal `exarch_core::ExtractionWarningKind::as_str`.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractionWarningKind {
    /// 7z anti-items were skipped.
    #[napi(value = "anti_items_skipped")]
    AntiItemsSkipped,
    /// The backup of a replaced destination could not be removed.
    #[napi(value = "backup_cleanup_failed")]
    BackupCleanupFailed,
}

/// Whether the identity of a leftover backup was confirmed before its removal
/// failed.
// Values must equal `exarch_core::BackupIdentity::as_str`.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupIdentity {
    /// The path still names the backup that was created.
    #[napi(value = "verified")]
    Verified,
    /// The platform cannot confirm that the path still names the backup.
    #[napi(value = "unverified")]
    Unverified,
}

/// 7z anti-items, which mark deletions in an update archive, were not applied.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct AntiItemsSkippedWarning {
    /// Always `'anti_items_skipped'`.
    #[napi(ts_type = "'anti_items_skipped'")]
    pub kind: ExtractionWarningKind,
    /// The human-readable text.
    pub message: String,
    /// How many anti-items the archive holds, saturated at `2^53 - 1`.
    pub count: i64,
}

/// The backup of the original destination, kept for an atomic replacement,
/// could not be removed and must be cleaned up manually.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct BackupCleanupFailedWarning {
    /// Always `'backup_cleanup_failed'`.
    #[napi(ts_type = "'backup_cleanup_failed'")]
    pub kind: ExtractionWarningKind,
    /// The human-readable text, with the path redacted like an error message.
    pub message: String,
    /// Where the backup remains, redacted like an error message: the file
    /// name only in release builds.
    pub path: String,
    /// Whether the backup's identity was confirmed before the removal failed.
    pub identity: BackupIdentity,
    /// The kind of the removal failure.
    pub io_kind: IoKind,
}

type ExtractionWarning = Either<AntiItemsSkippedWarning, BackupCleanupFailedWarning>;

fn backup_identity(identity: CoreBackupIdentity) -> Result<BackupIdentity> {
    match identity {
        CoreBackupIdentity::Verified => Ok(BackupIdentity::Verified),
        CoreBackupIdentity::Unverified => Ok(BackupIdentity::Unverified),
        other => Err(unknown_variant("backup identity", other.as_str())),
    }
}

pub fn extraction_warning(warning: &CoreExtractionWarning) -> Result<ExtractionWarning> {
    match warning {
        CoreExtractionWarning::AntiItemsSkipped { count } => {
            Ok(Either::A(AntiItemsSkippedWarning {
                kind: ExtractionWarningKind::AntiItemsSkipped,
                message: warning.to_string(),
                count: saturating_i64(*count),
            }))
        }
        CoreExtractionWarning::BackupCleanupFailed {
            path,
            identity,
            io_kind,
            message,
        } => {
            let redacted = CoreExtractionWarning::BackupCleanupFailed {
                path: sanitize_path_for_error(path).into(),
                identity: *identity,
                io_kind: *io_kind,
                message: message.clone(),
            };
            Ok(Either::B(BackupCleanupFailedWarning {
                kind: ExtractionWarningKind::BackupCleanupFailed,
                message: redacted.to_string(),
                path: sanitize_path_for_error(path),
                identity: backup_identity(*identity)?,
                io_kind: IoKind::from(*io_kind),
            }))
        }
        other => Err(unknown_variant("extraction warning", other.kind().as_str())),
    }
}

/// Class of a creation warning.
// Values must equal `exarch_core::CreationWarningKind::as_str`.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreationWarningKind {
    /// Entries of a finished ZIP archive are over the default ratio limit.
    #[napi(value = "zip_ratio_over_default_limit")]
    ZipRatioOverDefaultLimit,
    /// The finished ZIP archive could not be read back for the ratio check.
    #[napi(value = "zip_ratio_check_failed")]
    ZipRatioCheckFailed,
    /// The directory that holds the archive could not be synced.
    #[napi(value = "directory_not_synced")]
    DirectoryNotSynced,
}

/// Default extraction would refuse entries of the finished ZIP archive as a
/// zip bomb.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct ZipRatioOverDefaultLimitWarning {
    /// Always `'zip_ratio_over_default_limit'`.
    #[napi(ts_type = "'zip_ratio_over_default_limit'")]
    pub kind: CreationWarningKind,
    /// The human-readable text.
    pub message: String,
    /// How many entries are over the limit, saturated at `2^32 - 1`.
    pub entries: u32,
    /// The default extraction ratio limit.
    pub limit: f64,
    /// The smallest ratio limit that admits every entry.
    pub needed_ratio: f64,
}

/// The finished ZIP archive could not be read back to check its entries.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct ZipRatioCheckFailedWarning {
    /// Always `'zip_ratio_check_failed'`.
    #[napi(ts_type = "'zip_ratio_check_failed'")]
    pub kind: CreationWarningKind,
    /// The human-readable text.
    pub message: String,
    /// Why the archive could not be read back.
    pub reason: String,
}

/// The archive was published, but its directory could not be synced.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct DirectoryNotSyncedWarning {
    /// Always `'directory_not_synced'`.
    #[napi(ts_type = "'directory_not_synced'")]
    pub kind: CreationWarningKind,
    /// The human-readable text.
    pub message: String,
    /// The kind of the sync failure.
    pub io_kind: IoKind,
}

type CreationWarning =
    Either3<ZipRatioOverDefaultLimitWarning, ZipRatioCheckFailedWarning, DirectoryNotSyncedWarning>;

fn creation_warning(warning: &CoreCreationWarning) -> Result<CreationWarning> {
    let message = warning.to_string();
    match warning {
        CoreCreationWarning::ZipRatioOverDefaultLimit {
            entries,
            limit,
            needed_ratio,
        } => Ok(Either3::A(ZipRatioOverDefaultLimitWarning {
            kind: CreationWarningKind::ZipRatioOverDefaultLimit,
            message,
            entries: saturating_u32(*entries),
            limit: *limit,
            needed_ratio: *needed_ratio,
        })),
        CoreCreationWarning::ZipRatioCheckFailed { reason } => {
            Ok(Either3::B(ZipRatioCheckFailedWarning {
                kind: CreationWarningKind::ZipRatioCheckFailed,
                message,
                reason: reason.clone(),
            }))
        }
        CoreCreationWarning::DirectoryNotSynced { io_kind } => {
            Ok(Either3::C(DirectoryNotSyncedWarning {
                kind: CreationWarningKind::DirectoryNotSynced,
                message,
                io_kind: IoKind::from(*io_kind),
            }))
        }
        other => Err(unknown_variant("creation warning", other.kind().as_str())),
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
    /// Conditions worth surfacing that are not skipped entries; branch on
    /// `kind`, `message` is the human-readable text.
    #[napi(ts_type = "Array<ExtractionWarning>")]
    pub warnings: Vec<ExtractionWarning>,
}

impl TryFrom<CoreReport> for ExtractionReport {
    type Error = Error;

    fn try_from(report: CoreReport) -> Result<Self> {
        // Use saturating conversions to prevent silent wraparound on overflow
        // This ensures audit trails remain accurate even for very large
        // extractions
        Ok(Self {
            files_extracted: saturating_u32(report.files_extracted),
            directories_created: saturating_u32(report.directories_created),
            symlinks_created: saturating_u32(report.symlinks_created),
            bytes_written: saturating_i64(report.bytes_written),
            duration_ms: saturating_millis(report.duration),
            files_skipped: saturating_u32(report.files_skipped()),
            skipped: SkippedSummary::from(&report.skipped),
            warnings: report
                .warnings
                .iter()
                .map(extraction_warning)
                .collect::<Result<_>>()?,
        })
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
    /// Conditions worth surfacing that are not skipped entries; branch on
    /// `kind`, `message` is the human-readable text.
    #[napi(ts_type = "Array<CreationWarning>")]
    pub warnings: Vec<CreationWarning>,
}

impl TryFrom<exarch_core::CreationReport> for CreationReport {
    type Error = Error;

    fn try_from(report: exarch_core::CreationReport) -> Result<Self> {
        Ok(Self {
            files_added: saturating_u32(report.files_added),
            directories_added: saturating_u32(report.directories_added),
            symlinks_added: saturating_u32(report.symlinks_added),
            bytes_written: saturating_i64(report.bytes_written),
            bytes_compressed: saturating_i64(report.bytes_compressed),
            duration_ms: saturating_millis(report.duration),
            files_skipped: saturating_u32(report.files_skipped()),
            skipped: SkippedSummary::from(&report.skipped),
            warnings: report
                .warnings
                .iter()
                .map(creation_warning)
                .collect::<Result<_>>()?,
        })
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
    /// What extraction would do with each entry validation accepts: where it
    /// lands, or why it is left out. The selection is the one the listing's
    /// `SecurityConfig` carried and that config supplies the limits and
    /// policies; an entry validation refuses is not reported.
    #[napi(ts_type = "Array<EntryDisposition>")]
    pub dispositions: Vec<EntryDisposition>,
}

impl ArchiveManifest {
    /// Converts a core manifest listed under `config`.
    ///
    /// # Errors
    ///
    /// Returns the failure of a conversion that cannot represent an entry, a
    /// path that is not valid UTF-8 or a value newer than this binding.
    pub fn from_core(
        manifest: exarch_core::ArchiveManifest,
        config: &exarch_core::SecurityConfig,
    ) -> CoreResult<Self> {
        let total_entries = saturating_u32(manifest.total_entries());
        let total_size = saturating_i64(manifest.total_size());
        let format = ArchiveType::try_from(manifest.format()).map_err(Failure::Native)?;
        let dispositions = manifest
            .dispositions(config)
            .map(|(entry, disposition)| entry_disposition(&entry.path, disposition))
            .collect::<CoreResult<_>>()?;
        Ok(Self {
            entries: manifest
                .into_entries()
                .into_iter()
                .map(|entry| archive_entry(&entry))
                .collect::<CoreResult<_>>()?,
            total_entries,
            total_size,
            format,
            dispositions,
        })
    }
}

/// Which way extraction goes with a listed entry.
// Values must equal the `kind` of the matching disposition interface.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispositionKind {
    /// The entry is written.
    #[napi(value = "extract")]
    Extract,
    /// The entry is validated but not written.
    #[napi(value = "skip")]
    Skip,
}

/// An entry that extraction writes.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct ExtractDisposition {
    /// Always `'extract'`.
    #[napi(ts_type = "'extract'")]
    pub kind: DispositionKind,
    /// The entry's path in the archive.
    pub path: String,
    /// Where it lands, relative to the destination, after any strip or
    /// flatten.
    pub landing: String,
}

/// An entry that is validated but not extracted.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct SkipDisposition {
    /// Always `'skip'`.
    #[napi(ts_type = "'skip'")]
    pub kind: DispositionKind,
    /// The entry's path in the archive.
    pub path: String,
    /// Why it is left out, for example `'not_selected'` or `'stripped_away'`.
    #[napi(ts_type = "SkipKind")]
    pub reason: String,
}

type EntryDisposition = Either<ExtractDisposition, SkipDisposition>;

fn entry_disposition(
    path: &std::path::Path,
    disposition: exarch_core::Disposition,
) -> CoreResult<EntryDisposition> {
    let path = utf8_path(path)?;
    match disposition {
        exarch_core::Disposition::Extract(landing) => Ok(Either::A(ExtractDisposition {
            kind: DispositionKind::Extract,
            path,
            landing: utf8_path(landing.as_path())?,
        })),
        exarch_core::Disposition::Skip(kind) => Ok(Either::B(SkipDisposition {
            kind: DispositionKind::Skip,
            path,
            reason: kind.as_str().to_owned(),
        })),
        _ => Err(Failure::Native(unknown_variant(
            "entry disposition",
            "unknown",
        ))),
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

fn link_target(target: &exarch_core::LinkTarget) -> CoreResult<LinkTarget> {
    use exarch_core::LinkTarget as Core;

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

fn entry_common(entry: &exarch_core::ArchiveEntry) -> CoreResult<EntryCommon> {
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
                .map(saturating_millis)
        }),
    })
}

fn archive_entry(entry: &exarch_core::ArchiveEntry) -> CoreResult<ArchiveEntry> {
    use exarch_core::ManifestEntryKind as Kind;

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

impl TryFrom<exarch_core::VerificationReport> for VerificationReport {
    type Error = Failure;

    fn try_from(report: exarch_core::VerificationReport) -> std::result::Result<Self, Failure> {
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
    /// The permission bits (raw archive mode) of an `'Invalid Permissions'`
    /// refusal or of an `'Executable File'` finding.
    pub mode: Option<u32>,
}

impl TryFrom<exarch_core::VerificationIssue> for VerificationIssue {
    type Error = Error;

    fn try_from(issue: exarch_core::VerificationIssue) -> Result<Self> {
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
            mode: issue.mode().map(exarch_core::RawMode::get),
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests assert by panicking"
)]
mod tests {
    use super::*;
    use crate::utils::union_line;
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

    fn extraction_message(warning: &ExtractionWarning) -> &str {
        match warning {
            Either::A(w) => &w.message,
            Either::B(w) => &w.message,
        }
    }

    fn creation_message(warning: &CreationWarning) -> &str {
        match warning {
            Either3::A(w) => &w.message,
            Either3::B(w) => &w.message,
            Either3::C(w) => &w.message,
        }
    }

    #[test]
    fn test_anti_items_warning_is_typed() {
        let warning = extraction_warning(&anti(3)).unwrap();
        let Either::A(typed) = warning else {
            panic!("expected the anti-items warning");
        };
        assert_eq!(typed.kind, ExtractionWarningKind::AntiItemsSkipped);
        assert_eq!(typed.count, 3);
        assert_eq!(typed.message, anti(3).to_string());
    }

    #[test]
    fn test_backup_cleanup_warning_is_typed_and_redacts_the_path_like_errors() {
        let core = exarch_core::ExtractionWarning::BackupCleanupFailed {
            path: std::path::PathBuf::from("/srv/internal/app/.backup-123"),
            identity: CoreBackupIdentity::Unverified,
            io_kind: exarch_core::IoKind::PermissionDenied,
            message: "denied".into(),
        };
        let Either::B(typed) = extraction_warning(&core).unwrap() else {
            panic!("expected the backup warning");
        };
        assert_eq!(typed.kind, ExtractionWarningKind::BackupCleanupFailed);
        assert_eq!(typed.identity, BackupIdentity::Unverified);
        assert_eq!(typed.io_kind, IoKind::PermissionDenied);
        assert_eq!(
            typed.path,
            exarch_core::sanitize_path_for_error(std::path::Path::new(
                "/srv/internal/app/.backup-123"
            ))
        );
        assert!(typed.path.ends_with(".backup-123"));
        assert!(typed.message.contains(&typed.path), "{}", typed.message);
        #[cfg(not(debug_assertions))]
        assert!(!typed.message.contains("internal"), "{}", typed.message);
    }

    #[test]
    fn test_creation_warnings_are_typed() {
        use exarch_core::CreationWarning as Core;
        let over = creation_warning(&Core::ZipRatioOverDefaultLimit {
            entries: 2,
            limit: 100.0,
            needed_ratio: 250.0,
        })
        .unwrap();
        let Either3::A(over) = over else {
            panic!("expected the ratio warning");
        };
        assert_eq!(over.kind, CreationWarningKind::ZipRatioOverDefaultLimit);
        assert_eq!(
            (over.entries, over.limit, over.needed_ratio),
            (2, 100.0, 250.0)
        );

        let failed = creation_warning(&Core::ZipRatioCheckFailed { reason: "r".into() }).unwrap();
        let Either3::B(failed) = failed else {
            panic!("expected the check-failed warning");
        };
        assert_eq!(failed.reason, "r");

        let synced = creation_warning(&Core::DirectoryNotSynced {
            io_kind: exarch_core::IoKind::PermissionDenied,
        })
        .unwrap();
        let Either3::C(synced) = synced else {
            panic!("expected the not-synced warning");
        };
        assert_eq!(synced.io_kind, IoKind::PermissionDenied);
    }

    #[test]
    fn test_warning_kind_mirrors_match_core() {
        let extraction: Vec<_> = [
            ExtractionWarningKind::AntiItemsSkipped,
            ExtractionWarningKind::BackupCleanupFailed,
        ]
        .into_iter()
        .map(|kind| match kind {
            ExtractionWarningKind::AntiItemsSkipped => "anti_items_skipped",
            ExtractionWarningKind::BackupCleanupFailed => "backup_cleanup_failed",
        })
        .collect();
        assert_eq!(extraction, exarch_core::ExtractionWarningKind::NAMES);

        let creation: Vec<_> = [
            CreationWarningKind::ZipRatioOverDefaultLimit,
            CreationWarningKind::ZipRatioCheckFailed,
            CreationWarningKind::DirectoryNotSynced,
        ]
        .into_iter()
        .map(|kind| match kind {
            CreationWarningKind::ZipRatioOverDefaultLimit => "zip_ratio_over_default_limit",
            CreationWarningKind::ZipRatioCheckFailed => "zip_ratio_check_failed",
            CreationWarningKind::DirectoryNotSynced => "directory_not_synced",
        })
        .collect();
        assert_eq!(creation, exarch_core::CreationWarningKind::NAMES);

        let identity =
            [BackupIdentity::Verified, BackupIdentity::Unverified].map(|identity| match identity {
                BackupIdentity::Verified => "verified",
                BackupIdentity::Unverified => "unverified",
            });
        assert_eq!(identity, CoreBackupIdentity::NAMES);
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
        unreadable.io_kind = Some(exarch_core::IoKind::PermissionDenied);
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

        let report = ExtractionReport::try_from(core_report).unwrap();

        assert_eq!(report.files_extracted, 10);
        assert_eq!(report.directories_created, 5);
        assert_eq!(report.symlinks_created, 2);
        assert_eq!(report.bytes_written, 1024);
        assert_eq!(report.duration_ms, 500);
        assert_eq!(report.files_skipped, 1);
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(extraction_message(&report.warnings[0]), anti(1).to_string());
    }

    #[test]
    fn test_extraction_report_zero_values() {
        let core_report = CoreReport::new();
        let report = ExtractionReport::try_from(core_report).unwrap();

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

        let report = ExtractionReport::try_from(core_report).unwrap();

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

        let report = ExtractionReport::try_from(core_report).unwrap();

        assert_eq!(report.warnings.len(), 3);
        assert_eq!(extraction_message(&report.warnings[0]), anti(1).to_string());
        assert_eq!(extraction_message(&report.warnings[1]), anti(2).to_string());
        assert_eq!(extraction_message(&report.warnings[2]), anti(3).to_string());
    }

    #[test]
    fn test_extraction_report_duration_hours() {
        let mut core_report = CoreReport::new();
        core_report.duration = Duration::from_hours(2);

        let report = ExtractionReport::try_from(core_report).unwrap();

        assert_eq!(
            report.duration_ms, 7_200_000,
            "2 hours should be 7,200,000 milliseconds"
        );
    }

    #[test]
    fn test_extraction_report_duration_zero() {
        let mut core_report = CoreReport::new();
        core_report.duration = Duration::from_secs(0);

        let report = ExtractionReport::try_from(core_report).unwrap();

        assert_eq!(report.duration_ms, 0, "zero duration should be 0 ms");
    }

    #[test]
    fn test_extraction_report_duration_microseconds() {
        let mut core_report = CoreReport::new();
        core_report.duration = Duration::from_micros(1500); // 1.5 ms

        let report = ExtractionReport::try_from(core_report).unwrap();

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

        let report = ExtractionReport::try_from(core_report).unwrap();

        assert_eq!(report.warnings.len(), 3, "should have 3 warnings");
        assert_eq!(
            extraction_message(&report.warnings[0]),
            anti(1).to_string(),
            "first warning should be at index 0"
        );
        assert_eq!(
            extraction_message(&report.warnings[1]),
            anti(2).to_string(),
            "second warning should be at index 1"
        );
        assert_eq!(
            extraction_message(&report.warnings[2]),
            anti(3).to_string(),
            "third warning should be at index 2"
        );
    }

    // CreationReport tests
    #[test]
    fn test_creation_report_conversion() {
        let mut core_report = exarch_core::CreationReport::new();
        core_report.files_added = 10;
        core_report.directories_added = 5;
        core_report.symlinks_added = 2;
        core_report.bytes_written = 1024;
        core_report.bytes_compressed = 512;
        core_report.duration = std::time::Duration::from_millis(500);
        core_report.skipped = skipped(1);
        let warning = exarch_core::CreationWarning::ZipRatioCheckFailed {
            reason: "Test warning".to_string(),
        };
        let expected = warning.to_string();
        core_report.add_warning(warning);

        let report = CreationReport::try_from(core_report).unwrap();

        assert_eq!(report.files_added, 10);
        assert_eq!(report.directories_added, 5);
        assert_eq!(report.symlinks_added, 2);
        assert_eq!(report.bytes_written, 1024);
        assert_eq!(report.bytes_compressed, 512);
        assert_eq!(report.duration_ms, 500);
        assert_eq!(report.files_skipped, 1);
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(creation_message(&report.warnings[0]), expected);
    }

    fn sized_entry(name: &str, size: u64) -> exarch_core::ArchiveEntry {
        exarch_core::ArchiveEntry::new(
            std::path::PathBuf::from(name),
            exarch_core::ManifestEntryKind::File {
                size: exarch_core::Uncompressed(size),
            },
        )
    }

    fn policy_issue() -> exarch_core::VerificationIssue {
        let error = exarch_core::ArchiveError::from(exarch_core::Violation::EncryptedArchive);
        exarch_core::VerificationIssue::from_error(&error, None)
    }

    // ArchiveEntry tests
    #[test]
    fn test_archive_entry_conversion() {
        use std::path::PathBuf;
        use std::time::UNIX_EPOCH;

        let mut core_entry = exarch_core::ArchiveEntry::new(
            PathBuf::from("test/file.txt"),
            exarch_core::ManifestEntryKind::File {
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
        use exarch_core::LinkTarget as Core;
        use exarch_core::ManifestEntryKind;

        let entry = |target| {
            exarch_core::ArchiveEntry::new(
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

        let core_entry = exarch_core::ArchiveEntry::new(
            std::path::PathBuf::from(std::ffi::OsStr::from_bytes(b"a\xFFb")),
            exarch_core::ManifestEntryKind::Directory,
        );
        let failure = archive_entry(&core_entry).unwrap_err();
        assert_matches!(failure, Failure::Core(CoreError::InvalidArchive(_)));
    }

    // ArchiveManifest tests
    #[test]
    fn test_manifest_dispositions_follow_the_selection_and_the_config_limits() {
        use exarch_core::EntrySelection;

        let selection = EntrySelection::default()
            .with_include(
                exarch_core::EntryPattern::parse_for(
                    exarch_core::ConfigSetting::EntryInclude,
                    "keep",
                )
                .unwrap(),
            )
            .with_rewrite(exarch_core::PathRewrite::Flatten);
        let mut core_manifest =
            exarch_core::ArchiveManifest::with_selection(CoreArchiveType::TarGz, selection);
        core_manifest
            .add_entry(sized_entry("keep/a/b.txt", 1))
            .unwrap();
        core_manifest
            .add_entry(sized_entry("other.txt", 1))
            .unwrap();

        let manifest =
            ArchiveManifest::from_core(core_manifest, &exarch_core::SecurityConfig::default())
                .unwrap();

        assert_eq!(manifest.total_entries, 2);
        assert_eq!(manifest.dispositions.len(), 2);
        let Either::A(extract) = &manifest.dispositions[0] else {
            panic!("the selected file extracts");
        };
        assert_eq!(extract.kind, DispositionKind::Extract);
        assert_eq!(
            (extract.path.as_str(), extract.landing.as_str()),
            ("keep/a/b.txt", "b.txt")
        );
        let Either::B(skip) = &manifest.dispositions[1] else {
            panic!("the other file is left out");
        };
        assert_eq!(skip.kind, DispositionKind::Skip);
        assert_eq!(
            (skip.path.as_str(), skip.reason.as_str()),
            ("other.txt", "not_selected")
        );
    }

    #[test]
    fn test_archive_manifest_conversion() {
        let mut core_manifest = exarch_core::ArchiveManifest::new(CoreArchiveType::TarGz);
        for i in 0..10 {
            core_manifest
                .add_entry(sized_entry(&format!("f{i}"), 500))
                .unwrap();
        }

        let manifest =
            ArchiveManifest::from_core(core_manifest, &exarch_core::SecurityConfig::default())
                .unwrap();

        assert_eq!(manifest.total_entries, 10);
        assert_eq!(manifest.total_size, 5000);
        assert_eq!(manifest.format, ArchiveType::TarGz);
    }

    // VerificationReport tests
    #[test]
    fn test_verification_report_conversion() {
        let mut core_manifest = exarch_core::ArchiveManifest::new(CoreArchiveType::TarGz);
        for i in 0..10 {
            core_manifest
                .add_entry(sized_entry(&format!("f{i}"), 500))
                .unwrap();
        }
        let core_report =
            exarch_core::VerificationReport::from_entry_issues(&core_manifest, |_| Vec::new());

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

        let mut manifest = exarch_core::ArchiveManifest::new(exarch_core::ArchiveType::Tar);
        manifest
            .add_entry(exarch_core::ArchiveEntry::new(
                std::path::PathBuf::from("link"),
                exarch_core::ManifestEntryKind::File {
                    size: exarch_core::Uncompressed(0),
                },
            ))
            .unwrap();
        let core_report =
            exarch_core::VerificationReport::from_entry_issues(&manifest, |_| vec![policy_issue()]);
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
        let core_issue = exarch_core::VerificationIssue::from_error(
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
    fn test_invalid_permissions_issue_carries_the_raw_mode() {
        let error = exarch_core::ArchiveError::InvalidPermissions {
            path: std::path::PathBuf::from("a"),
            mode: exarch_core::RawMode::new(0o4755),
        };
        let core_issue = exarch_core::VerificationIssue::from_error(&error, None);

        let issue = VerificationIssue::try_from(core_issue).unwrap();

        assert_eq!(issue.mode, Some(0o4755));
    }

    #[test]
    fn test_executable_heuristic_carries_the_raw_mode() {
        let issue = VerificationIssue::try_from(exarch_core::VerificationIssue::new(
            exarch_core::IssueSeverity::Low,
            exarch_core::Finding::Heuristic(exarch_core::Heuristic::ExecutableFile {
                mode: exarch_core::RawMode::new(0o755),
            }),
        ))
        .unwrap();

        assert_eq!(issue.mode, Some(0o755));
        assert_eq!(issue.code, None);
    }

    #[test]
    fn test_heuristic_issue_carries_no_refusal_properties() {
        let issue = VerificationIssue::try_from(exarch_core::VerificationIssue::new(
            exarch_core::IssueSeverity::Low,
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

        let report = ExtractionReport::try_from(core_report).unwrap();

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

        let report = ExtractionReport::try_from(core_report).unwrap();

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

        let report = ExtractionReport::try_from(core_report).unwrap();

        assert_eq!(
            report.duration_ms,
            i64::MAX,
            "duration_ms should saturate to i64::MAX"
        );
    }

    #[test]
    fn test_creation_report_saturates_files_added_at_u32_max() {
        let mut core_report = exarch_core::CreationReport::new();
        core_report.files_added = (u32::MAX as usize) + 1000;

        let report = CreationReport::try_from(core_report).unwrap();

        assert_eq!(
            report.files_added,
            u32::MAX,
            "files_added should saturate to u32::MAX"
        );
    }

    #[test]
    fn test_creation_report_saturates_bytes_written_at_i64_max() {
        let mut core_report = exarch_core::CreationReport::new();
        core_report.bytes_written = u64::MAX;

        let report = CreationReport::try_from(core_report).unwrap();

        assert_eq!(
            report.bytes_written,
            i64::MAX,
            "bytes_written should saturate to i64::MAX"
        );
    }

    #[test]
    fn test_creation_report_saturates_bytes_compressed_at_i64_max() {
        let mut core_report = exarch_core::CreationReport::new();
        core_report.bytes_compressed = u64::MAX;

        let report = CreationReport::try_from(core_report).unwrap();

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
        let mut core_manifest = exarch_core::ArchiveManifest::new(CoreArchiveType::TarGz);
        core_manifest
            .add_entry(sized_entry("big", u64::MAX))
            .unwrap();

        let manifest =
            ArchiveManifest::from_core(core_manifest, &exarch_core::SecurityConfig::default())
                .unwrap();

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
    fn test_creatable_format_maps_onto_every_core_variant() {
        let all = [
            CreatableFormat::Tar,
            CreatableFormat::TarGz,
            CreatableFormat::TarBz2,
            CreatableFormat::TarXz,
            CreatableFormat::TarZst,
            CreatableFormat::Zip,
        ];
        let mapped: Vec<_> = all.into_iter().map(CoreCreatableFormat::from).collect();
        assert_eq!(mapped, CoreCreatableFormat::ALL);
    }

    #[test]
    fn test_durability_maps_onto_every_core_variant() {
        let mapped: Vec<_> = [Durability::Synced, Durability::Unsynced]
            .into_iter()
            .map(CoreDurability::from)
            .collect();
        assert_eq!(mapped, CoreDurability::ALL);
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

    #[test]
    fn test_creatable_format_union_is_the_core_names() {
        let names: Vec<String> = CoreCreatableFormat::NAMES
            .iter()
            .map(|name| format!("'{name}'"))
            .collect();
        let line = format!("export type CreatableFormat = {}", names.join(" | "));
        assert!(
            include_str!("../index.d.ts").lines().any(|l| l == line),
            "index.d.ts out of sync with CreatableFormat::NAMES, expected:\n{line}"
        );
    }

    #[test]
    fn test_index_d_ts_unions_match_core_enums() {
        let dts = include_str!("../index.d.ts");
        let expected = [
            union_line("ArchiveType", CoreArchiveType::ALL, CoreArchiveType::as_str),
            union_line(
                "CreatableFormat",
                CoreCreatableFormat::ALL,
                CoreCreatableFormat::as_str,
            ),
            union_line("Durability", CoreDurability::ALL, CoreDurability::as_str),
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
                "ExtractionWarningKind",
                exarch_core::ExtractionWarningKind::ALL,
                exarch_core::ExtractionWarningKind::as_str,
            ),
            union_line(
                "CreationWarningKind",
                exarch_core::CreationWarningKind::ALL,
                exarch_core::CreationWarningKind::as_str,
            ),
            union_line(
                "BackupIdentity",
                CoreBackupIdentity::ALL,
                CoreBackupIdentity::as_str,
            ),
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
