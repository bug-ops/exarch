//! Node.js bindings for `ExtractionReport`.

use exarch_core::ArchiveType as CoreArchiveType;
use exarch_core::CheckStatus as CoreCheckStatus;
use exarch_core::CreatableFormat as CoreCreatableFormat;
use exarch_core::CreationWarning as CoreCreationWarning;
use exarch_core::Durability as CoreDurability;
use exarch_core::ExtractionReport as CoreReport;
use exarch_core::ExtractionWarning as CoreExtractionWarning;
use exarch_core::IntegrityGaps as CoreIntegrityGaps;
use exarch_core::IssueSeverity as CoreIssueSeverity;
#[cfg(test)]
use exarch_core::LinkTargetState as CoreLinkTargetState;
use exarch_core::ManifestEntryType as CoreManifestEntryType;
use exarch_core::VerificationStatus as CoreVerificationStatus;
#[cfg(test)]
use napi::Error;
use napi_derive::napi;

use crate::CoreResult;
use crate::error::Failure;
use crate::mirror::mirror_from_closed_core;
use crate::mirror::mirror_from_core;
use crate::mirror::mirror_into_core;
use crate::utils::path_text;
use crate::utils::utf8_path;
use exarch_core::ArchiveError as CoreError;
use napi::bindgen_prelude::Either4;
use napi::bindgen_prelude::Either5;
use napi::bindgen_prelude::Either6;

pub fn saturating_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// The largest integer a JavaScript number holds exactly, `2^53 - 1`.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Whole milliseconds of `duration`, clamped to [`MAX_SAFE_INTEGER`].
pub fn saturating_millis(duration: std::time::Duration) -> i64 {
    saturating_i64(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
}

/// Whole milliseconds of `time`, negative before the epoch, clamped to
/// plus or minus [`MAX_SAFE_INTEGER`].
pub fn signed_millis(time: exarch_core::UnixTime) -> i64 {
    let limit = i128::from(MAX_SAFE_INTEGER);
    i64::try_from(time.as_millis().clamp(-limit, limit)).unwrap_or_default()
}

/// An entry or item count as an exact JavaScript number.
///
/// A count above `2^53 - 1` would need more entries than any host can hold, so
/// the clamp cannot be observed and carries no flag.
pub fn saturating_usize(n: usize) -> i64 {
    saturating_i64(u64::try_from(n).unwrap_or(u64::MAX))
}

/// `n` as a JavaScript number, clamped to [`MAX_SAFE_INTEGER`] so the number is
/// exact. Byte sizes go through [`ByteSize`], which records the clamp.
pub fn saturating_i64(n: u64) -> i64 {
    i64::try_from(n.min(MAX_SAFE_INTEGER)).unwrap_or(i64::MAX)
}

/// A byte size as a JavaScript number, with whether it was clamped.
///
/// An archive declares its sizes, so a value above `2^53 - 1` is attacker
/// controlled; the flag keeps it apart from a real value of exactly
/// `2^53 - 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteSize {
    /// The size, at most `2^53 - 1`.
    pub value: i64,
    /// Whether the real size was above `2^53 - 1`.
    pub clamped: bool,
}

impl ByteSize {
    /// Converts `bytes`, clamping to `2^53 - 1`.
    pub fn new(bytes: u64) -> Self {
        Self {
            value: saturating_i64(bytes),
            clamped: bytes > MAX_SAFE_INTEGER,
        }
    }

    /// Converts a `usize` length.
    pub fn from_len(len: usize) -> Self {
        Self::new(u64::try_from(len).unwrap_or(u64::MAX))
    }

    /// Whether either of two sizes was clamped, for an object with two size
    /// fields.
    pub const fn either_clamped(self, other: Self) -> bool {
        self.clamped || other.clamped
    }
}

#[cfg(test)]
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

mirror_from_core!(
    ArchiveType,
    CoreArchiveType,
    "archive type",
    [Tar, TarGz, TarBz2, TarXz, TarZst, Zip, SevenZ]
);

mirror_into_core!(
    ArchiveType => CoreArchiveType,
    [Tar, TarGz, TarBz2, TarXz, TarZst, Zip, SevenZ]
);

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

mirror_into_core!(
    CreatableFormat => CoreCreatableFormat,
    [Tar, TarGz, TarBz2, TarXz, TarZst, Zip]
);

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

mirror_into_core!(
    Durability => CoreDurability,
    [Synced, Unsynced]
);

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

mirror_from_closed_core!(
    CoreManifestEntryType => ManifestEntryType,
    [File, Directory, Symlink, Hardlink]
);

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

mirror_from_closed_core!(
    CoreVerificationStatus => VerificationStatus,
    [Pass, Fail, Warning]
);

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

mirror_from_closed_core!(
    CoreCheckStatus => CheckStatus,
    [Pass, Fail, Warning, Skipped]
);

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

mirror_from_core!(
    IntegrityStatus,
    exarch_core::IntegrityStatus,
    "integrity status",
    [Pass, Fail, Incomplete, Skipped]
);

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

mirror_from_core!(
    UnverifiedReason,
    exarch_core::UnverifiedReason,
    "unverified reason",
    [
        OverBudget,
        ResourceLimit,
        SolidPolicy,
        SizeCeiling,
        UncoveredBlockCrc,
        NotDecodable,
        NoEndMarker,
        PathTooLong,
        DescriptorTail
    ]
);

/// Number of items left unverified for one reason.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct UnverifiedCount {
    /// Why the items were not verified: an `UnverifiedReason`, or a token newer
    /// than this binding.
    #[napi(ts_type = "UnverifiedReason | (string & {})")]
    pub reason: String,
    /// Number of items.
    pub count: i64,
}

/// One entry the integrity check could not verify.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct UnverifiedEntry {
    /// Entry path inside the archive.
    pub path: String,
    /// Why the entry was not verified: an `UnverifiedReason`, or a token newer
    /// than this binding.
    #[napi(ts_type = "UnverifiedReason | (string & {})")]
    pub reason: String,
}

/// What a requested integrity check left unverified.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct IntegrityGaps {
    /// Unverified items per reason; reasons with no items are absent. An
    /// array here; the Python binding exposes a dict keyed by the reason.
    pub counts: Vec<UnverifiedCount>,
    /// Unverified entries listed by path, up to a fixed cap (see `omitted`).
    pub entries: Vec<UnverifiedEntry>,
    /// Entries with a path that did not fit `entries`.
    pub omitted: i64,
    /// Total unverified items over all reasons.
    pub total: i64,
}

impl From<&CoreIntegrityGaps> for IntegrityGaps {
    fn from(gaps: &CoreIntegrityGaps) -> Self {
        Self {
            counts: gaps
                .counts()
                .map(|(reason, count)| UnverifiedCount {
                    reason: reason.as_str().to_owned(),
                    count: saturating_i64(count),
                })
                .collect(),
            entries: gaps
                .entries()
                .iter()
                .map(|e| UnverifiedEntry {
                    path: path_text(e.path()),
                    reason: e.reason().as_str().to_owned(),
                })
                .collect(),
            omitted: saturating_i64(gaps.omitted()),
            total: saturating_i64(gaps.total()),
        }
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

mirror_from_closed_core!(
    CoreIssueSeverity => IssueSeverity,
    [Info, Low, Medium, High, Critical]
);

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

mirror_from_core!(
    IssueCategory,
    exarch_core::IssueCategory,
    "issue category",
    [
        PathTraversal,
        SymlinkEscape,
        HardlinkEscape,
        ZipBomb,
        InvalidPermissions,
        QuotaExceeded,
        SecurityPolicy,
        InvalidArchive,
        SuspiciousPath,
        ExecutableFile,
        CorruptData,
        IntegrityIncomplete,
        HeaderMismatch,
        DuplicateEntry,
        OverlappingEntries,
        HiddenEntry,
        NameCollision,
        ArchiveNote
    ]
);

/// Why an entry was left out of an extraction or a creation.
// Values must equal `exarch_core::SkipKind::as_str`.
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

mirror_from_core!(
    SkipKind,
    exarch_core::SkipKind,
    "skip kind",
    [
        Duplicate,
        ExtensionNotAllowed,
        NotSelected,
        StrippedAway,
        Excluded,
        Hidden,
        OverMaxFileSize,
        SymlinkUnsupported,
        Unreadable
    ]
);

/// How many entries were skipped for one reason.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct SkipCount {
    /// Why the entries were skipped: a `SkipKind`, or a token newer than this
    /// binding.
    #[napi(ts_type = "SkipKind | (string & {})")]
    pub kind: String,
    /// How many entries.
    pub count: i64,
}

/// One skipped entry.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct SkippedEntry {
    /// The entry path as the operation names it, rendered injectively: a
    /// backslash is `\x5C` and each invalid byte is `\xNN`.
    pub path: String,
    /// Why the entry was skipped: a `SkipKind`, or a token newer than this
    /// binding.
    #[napi(ts_type = "SkipKind | (string & {})")]
    pub kind: String,
    /// The I/O failure behind an `'unreadable'` skip.
    #[napi(ts_type = "IoKind | (string & {})")]
    pub io_kind: Option<String>,
}

/// Everything an operation left out: exact counts per reason plus a bounded
/// sample of the individual entries.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct SkippedSummary {
    /// Exact count per reason; reasons with no skip are absent. An array
    /// here; the Python binding exposes a dict keyed by the reason.
    pub counts: Vec<SkipCount>,
    /// The first skipped entries in the order they were skipped, at most 64.
    pub sample: Vec<SkippedEntry>,
    /// Total skipped entries over all reasons.
    pub total: i64,
}

impl From<&exarch_core::Skips> for SkippedSummary {
    fn from(skips: &exarch_core::Skips) -> Self {
        Self {
            counts: skips
                .counts()
                .map(|(kind, count)| SkipCount {
                    kind: kind.as_str().to_owned(),
                    count: saturating_usize(count),
                })
                .collect(),
            sample: skips
                .sample()
                .iter()
                .map(|skip| SkippedEntry {
                    path: path_text(&skip.path),
                    kind: skip.kind.as_str().to_owned(),
                    io_kind: skip.io_kind.map(|kind| kind.as_str().to_owned()),
                })
                .collect(),
            total: saturating_usize(skips.total()),
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
    /// The published root of an atomic extraction gives less access than the
    /// destination it replaced.
    #[napi(value = "root_access_narrowed")]
    RootAccessNarrowed,
}

/// Why the published root of an atomic extraction gives less access than the
/// destination it replaced or filled.
// Values must equal `exarch_core::NarrowingReason::as_str`.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NarrowingReason {
    /// The destination's access control list could not be read in full.
    #[napi(value = "acl_unreadable")]
    AclUnreadable,
    /// The destination was no longer the directory that was pinned.
    #[napi(value = "destination_changed")]
    DestinationChanged,
    /// The list names a user or group the reading process cannot map.
    #[napi(value = "unmapped_id")]
    UnmappedId,
    /// The root belongs to another user or group than the destination.
    #[napi(value = "ownership_differs")]
    OwnershipDiffers,
    /// Writing the destination's list onto the root failed.
    #[napi(value = "acl_copy_failed")]
    AclCopyFailed,
    /// The root could not join the destination's group, so its group access
    /// and setgid bit were dropped.
    #[napi(value = "group_not_kept")]
    GroupNotKept,
    /// The destination belongs to another user, so its group and world write
    /// bits and setgid bit were dropped.
    #[napi(value = "foreign_write_dropped")]
    ForeignWriteDropped,
    /// The root could not take the destination's owner.
    #[napi(value = "owner_not_kept")]
    OwnerNotKept,
    /// The destination disappeared before its mode could be read.
    #[napi(value = "destination_vanished")]
    DestinationVanished,
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
    /// How many anti-items the archive holds.
    pub count: i64,
}

/// The published root of an atomic extraction gives less access than the
/// destination it replaced or filled; one warning is raised per reason.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct RootAccessNarrowedWarning {
    /// Always `'root_access_narrowed'`.
    #[napi(ts_type = "'root_access_narrowed'")]
    pub kind: ExtractionWarningKind,
    /// The human-readable text.
    pub message: String,
    /// Why the access was narrowed.
    #[napi(ts_type = "NarrowingReason | (string & {})")]
    pub reason: String,
}

/// An extraction warning of a kind newer than this binding.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct UnknownExtractionWarning {
    /// The warning's token, as core spells it.
    pub kind: String,
    /// The human-readable text.
    pub message: String,
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
    #[napi(ts_type = "BackupIdentity | (string & {})")]
    pub identity: String,
    /// The kind of the removal failure.
    #[napi(ts_type = "IoKind | (string & {})")]
    pub io_kind: String,
    /// The removal failure's text, redacted like an I/O error message.
    pub reason: String,
}

type ExtractionWarning = Either4<
    AntiItemsSkippedWarning,
    BackupCleanupFailedWarning,
    RootAccessNarrowedWarning,
    UnknownExtractionWarning,
>;

pub fn extraction_warning(warning: &CoreExtractionWarning) -> ExtractionWarning {
    let warning = warning.redacted();
    match &warning {
        CoreExtractionWarning::AntiItemsSkipped { count } => Either4::A(AntiItemsSkippedWarning {
            kind: ExtractionWarningKind::AntiItemsSkipped,
            message: warning.to_string(),
            count: saturating_i64(*count),
        }),
        CoreExtractionWarning::BackupCleanupFailed {
            path,
            identity,
            io_kind,
            message,
        } => Either4::B(BackupCleanupFailedWarning {
            kind: ExtractionWarningKind::BackupCleanupFailed,
            message: warning.to_string(),
            path: path.to_string_lossy().into_owned(),
            identity: identity.as_str().to_owned(),
            io_kind: io_kind.as_str().to_owned(),
            reason: message.to_string(),
        }),
        CoreExtractionWarning::RootAccessNarrowed { reason } => {
            Either4::C(RootAccessNarrowedWarning {
                kind: ExtractionWarningKind::RootAccessNarrowed,
                message: warning.to_string(),
                reason: reason.as_str().to_owned(),
            })
        }
        other => Either4::D(UnknownExtractionWarning {
            kind: other.kind().as_str().to_owned(),
            message: other.to_string(),
        }),
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
    /// How many entries are over the limit.
    pub entries: i64,
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
    #[napi(ts_type = "IoKind | (string & {})")]
    pub io_kind: String,
}

/// A creation warning of a kind newer than this binding.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct UnknownCreationWarning {
    /// The warning's token, as core spells it.
    pub kind: String,
    /// The human-readable text.
    pub message: String,
}

type CreationWarning = Either4<
    ZipRatioOverDefaultLimitWarning,
    ZipRatioCheckFailedWarning,
    DirectoryNotSyncedWarning,
    UnknownCreationWarning,
>;

fn creation_warning(warning: &CoreCreationWarning) -> CreationWarning {
    let warning = warning.redacted();
    let message = warning.to_string();
    match &warning {
        CoreCreationWarning::ZipRatioOverDefaultLimit {
            entries,
            limit,
            needed_ratio,
        } => Either4::A(ZipRatioOverDefaultLimitWarning {
            kind: CreationWarningKind::ZipRatioOverDefaultLimit,
            message,
            entries: saturating_usize(*entries),
            limit: *limit,
            needed_ratio: *needed_ratio,
        }),
        CoreCreationWarning::ZipRatioCheckFailed { reason } => {
            Either4::B(ZipRatioCheckFailedWarning {
                kind: CreationWarningKind::ZipRatioCheckFailed,
                message,
                reason: reason.clone(),
            })
        }
        CoreCreationWarning::DirectoryNotSynced { io_kind } => {
            Either4::C(DirectoryNotSyncedWarning {
                kind: CreationWarningKind::DirectoryNotSynced,
                message,
                io_kind: io_kind.as_str().to_owned(),
            })
        }
        other => Either4::D(UnknownCreationWarning {
            kind: other.kind().as_str().to_owned(),
            message,
        }),
    }
}

/// Report of an archive extraction operation.
///
/// Contains statistics and metadata about the extraction process.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct ExtractionReport {
    /// Number of files successfully extracted.
    pub files_extracted: i64,
    /// Number of directories created.
    pub directories_created: i64,
    /// Number of symlinks created.
    pub symlinks_created: i64,
    /// Total bytes written to disk.
    pub bytes_written: i64,
    /// `true` when `bytesWritten` exceeded `2^53 - 1` and was clamped to it.
    pub size_clamped: bool,
    /// Extraction duration in milliseconds.
    pub duration_ms: i64,
    /// Number of entries skipped, over all reasons.
    pub files_skipped: i64,
    /// The skipped entries by reason.
    pub skipped: SkippedSummary,
    /// What download-origin mark propagation did.
    #[napi(
        ts_type = "'not_requested' | 'unsupported_platform' | 'unmarked' | 'unreadable' | 'propagated' | (string & {})"
    )]
    pub mark_propagation: String,
    /// Files (and, on macOS, directories) that now carry the mark.
    pub marks_written: i64,
    /// Files (and directories) whose mark could not be written.
    pub marks_failed: i64,
    /// Conditions worth surfacing that are not skipped entries; branch on
    /// `kind`, `message` is the human-readable text.
    #[napi(ts_type = "Array<ExtractionWarning>")]
    pub warnings: Vec<ExtractionWarning>,
    /// Files, directories and symlinks extracted; skipped entries are not
    /// counted.
    pub total_items: i64,
    /// Whether any warning was raised.
    pub has_warnings: bool,
}

impl From<CoreReport> for ExtractionReport {
    fn from(report: CoreReport) -> Self {
        let bytes_written = ByteSize::new(report.bytes_written);
        Self {
            files_extracted: saturating_usize(report.files_extracted),
            directories_created: saturating_usize(report.directories_created),
            symlinks_created: saturating_usize(report.symlinks_created),
            bytes_written: bytes_written.value,
            size_clamped: bytes_written.clamped,
            duration_ms: saturating_millis(report.duration),
            files_skipped: saturating_usize(report.files_skipped()),
            skipped: SkippedSummary::from(&report.skipped),
            mark_propagation: report.mark.as_str().to_owned(),
            marks_written: saturating_usize(report.mark.marked()),
            marks_failed: saturating_usize(report.mark.failed()),
            warnings: report.warnings.iter().map(extraction_warning).collect(),
            total_items: saturating_usize(report.total_items()),
            has_warnings: report.has_warnings(),
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
    pub files_added: i64,
    /// Number of directories added to the archive.
    pub directories_added: i64,
    /// Number of symlinks added to the archive.
    pub symlinks_added: i64,
    /// Total bytes written to the archive (uncompressed).
    pub bytes_written: i64,
    /// Total bytes in the final archive (compressed).
    pub bytes_compressed: i64,
    /// `true` when `bytesWritten` or `bytesCompressed` exceeded `2^53 - 1` and
    /// was clamped to it.
    pub size_clamped: bool,
    /// Duration of the creation operation in milliseconds.
    pub duration_ms: i64,
    /// Number of entries skipped, over all reasons (filters, size limit,
    /// unreadable entries, unsupported symlinks).
    pub files_skipped: i64,
    /// The skipped entries by reason.
    pub skipped: SkippedSummary,
    /// Conditions worth surfacing that are not skipped entries; branch on
    /// `kind`, `message` is the human-readable text.
    #[napi(ts_type = "Array<CreationWarning>")]
    pub warnings: Vec<CreationWarning>,
    /// Files, directories and symlinks added; skipped entries are not
    /// counted.
    pub total_items: i64,
    /// Whether any warning was raised.
    pub has_warnings: bool,
    /// Uncompressed bytes divided by archive bytes; `0` when either is zero.
    pub compression_ratio: f64,
    /// Space saved, as a percentage of the uncompressed bytes.
    pub compression_percentage: f64,
}

impl From<exarch_core::CreationReport> for CreationReport {
    fn from(report: exarch_core::CreationReport) -> Self {
        let bytes_written = ByteSize::new(report.bytes_written);
        let bytes_compressed = ByteSize::new(report.bytes_compressed);
        Self {
            files_added: saturating_usize(report.files_added),
            directories_added: saturating_usize(report.directories_added),
            symlinks_added: saturating_usize(report.symlinks_added),
            bytes_written: bytes_written.value,
            bytes_compressed: bytes_compressed.value,
            size_clamped: bytes_written.either_clamped(bytes_compressed),
            duration_ms: saturating_millis(report.duration),
            files_skipped: saturating_usize(report.files_skipped()),
            skipped: SkippedSummary::from(&report.skipped),
            warnings: report.warnings.iter().map(creation_warning).collect(),
            total_items: saturating_usize(report.total_items()),
            has_warnings: report.has_warnings(),
            compression_ratio: report.compression_ratio(),
            compression_percentage: report.compression_percentage(),
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
    pub total_entries: i64,
    /// Total uncompressed size in bytes.
    pub total_size: i64,
    /// `true` when `totalSize` exceeded `2^53 - 1` and was clamped to it.
    pub size_clamped: bool,
    /// Archive format: an `ArchiveType`, or a token newer than this binding.
    #[napi(ts_type = "ArchiveType | (string & {})")]
    pub format: String,
    /// What extraction would do with each entry: where it lands, why it is
    /// left out, or that validation refuses it. The selection is the one the
    /// listing's `SecurityConfig` carried and that config supplies the limits
    /// and policies.
    #[napi(ts_type = "Array<EntryDisposition>")]
    pub dispositions: Vec<EntryDisposition>,
}

impl ArchiveManifest {
    /// Converts a core manifest listed under `config`, with dispositions for a
    /// destination volume that identifies landings as `volume` says.
    ///
    /// # Errors
    ///
    /// Returns the failure of a conversion that cannot represent an entry, a
    /// path that is not valid UTF-8 or a value newer than this binding.
    pub fn from_core(
        manifest: exarch_core::ArchiveManifest,
        config: &exarch_core::SecurityConfig,
        volume: exarch_core::VolumeIdentity,
    ) -> CoreResult<Self> {
        let total_entries = saturating_usize(manifest.total_entries());
        let total_size = ByteSize::new(manifest.total_size());
        let format = manifest.format().as_str().to_owned();
        let dispositions = manifest
            .dispositions_on(config, volume)
            .map(|(entry, disposition)| entry_disposition(&entry.path, disposition))
            .collect::<CoreResult<_>>()?;
        Ok(Self {
            entries: manifest
                .into_entries()
                .into_iter()
                .map(|entry| archive_entry(&entry))
                .collect::<CoreResult<_>>()?,
            total_entries,
            total_size: total_size.value,
            size_clamped: total_size.clamped,
            format,
            dispositions,
        })
    }
}

/// Which way extraction goes with a listed entry.
// Values must equal `exarch_core::DispositionKind::as_str`.
#[napi(string_enum)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispositionKind {
    /// The entry is written.
    #[napi(value = "extract")]
    Extract,
    /// The entry is validated but not written.
    #[napi(value = "skip")]
    Skip,
    /// The entry is refused by validation or policy, or cannot be placed.
    #[napi(value = "refuse")]
    Refuse,
}

mirror_from_core!(
    DispositionKind,
    exarch_core::DispositionKind,
    "disposition kind",
    [Extract, Skip, Refuse]
);

/// An entry that extraction writes.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct ExtractDisposition {
    /// Always `'extract'`.
    #[napi(ts_type = "'extract'")]
    pub action: DispositionKind,
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
    pub action: DispositionKind,
    /// The entry's path in the archive.
    pub path: String,
    /// Why it is left out, for example `'not_selected'` or `'stripped_away'`: a
    /// `SkipKind`, or a token newer than this binding.
    #[napi(ts_type = "SkipKind | (string & {})")]
    pub kind: String,
}

/// An entry that is refused by validation or policy, or cannot be placed.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct RefuseDisposition {
    /// Always `'refuse'`.
    #[napi(ts_type = "'refuse'")]
    pub action: DispositionKind,
    /// The entry's path in the archive.
    pub path: String,
}

/// A disposition of an action newer than this binding.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct UnknownDisposition {
    /// The action's token, as core spells it.
    pub action: String,
    /// The entry's path in the archive.
    pub path: String,
}

type EntryDisposition =
    Either4<ExtractDisposition, SkipDisposition, RefuseDisposition, UnknownDisposition>;

fn entry_disposition(
    path: &std::path::Path,
    disposition: exarch_core::Disposition,
) -> CoreResult<EntryDisposition> {
    let path = utf8_path(path)?;
    Ok(match disposition {
        exarch_core::Disposition::Extract(landing) => Either4::A(ExtractDisposition {
            action: DispositionKind::Extract,
            path,
            landing: utf8_path(landing.as_path())?,
        }),
        exarch_core::Disposition::Skip(kind) => Either4::B(SkipDisposition {
            action: DispositionKind::Skip,
            path,
            kind: kind.as_str().to_owned(),
        }),
        exarch_core::Disposition::Refuse => Either4::C(RefuseDisposition {
            action: DispositionKind::Refuse,
            path,
        }),
        other => Either4::D(UnknownDisposition {
            action: other.kind().as_str().to_owned(),
            path,
        }),
    })
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
    /// The target was not read: a 7z target kept in compressed entry data, left
    /// alone unless the listing was asked to read stored targets.
    #[napi(value = "unread")]
    Unread,
    /// The target could not be read.
    #[napi(value = "unreadable")]
    Unreadable,
    /// The target exceeds the host's name limits; only its length is kept.
    #[napi(value = "oversized")]
    Oversized,
}

mirror_from_core!(
    LinkTargetState,
    CoreLinkTargetState,
    "link target state",
    [Recorded, Missing, Unread, Unreadable, Oversized]
);

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
    /// `true` when `bytes` exceeded `2^53 - 1` and was clamped to it.
    pub size_clamped: bool,
}

/// A link target of a state newer than this binding.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct UnknownLinkTarget {
    /// The state's token, as core spells it.
    pub state: String,
}

type LinkTarget = Either6<
    RecordedLinkTarget,
    MissingLinkTarget,
    UnreadLinkTarget,
    UnreadableLinkTarget,
    OversizedLinkTarget,
    UnknownLinkTarget,
>;

fn link_target(target: &exarch_core::LinkTarget) -> CoreResult<LinkTarget> {
    use exarch_core::LinkTarget as Core;

    Ok(match target {
        Core::Recorded(path) => Either6::A(RecordedLinkTarget {
            state: LinkTargetState::Recorded,
            path: utf8_path(path)?,
        }),
        Core::Missing => Either6::B(MissingLinkTarget {
            state: LinkTargetState::Missing,
        }),
        Core::Unread => Either6::C(UnreadLinkTarget {
            state: LinkTargetState::Unread,
        }),
        Core::Unreadable => Either6::D(UnreadableLinkTarget {
            state: LinkTargetState::Unreadable,
        }),
        Core::Oversized { bytes } => {
            let bytes = ByteSize::from_len(*bytes);
            Either6::E(OversizedLinkTarget {
                state: LinkTargetState::Oversized,
                bytes: bytes.value,
                size_clamped: bytes.clamped,
            })
        }
        other => Either6::F(UnknownLinkTarget {
            state: other.state().as_str().to_owned(),
        }),
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
    /// `true` when a size field of this entry exceeded `2^53 - 1` and was
    /// clamped to it.
    pub size_clamped: bool,
    /// File permissions (raw Unix mode).
    pub mode: Option<u32>,
    /// Modification time in milliseconds since the Unix epoch, negative
    /// before it, clamped to `±(2^53 - 1)`. Absent only when the archive
    /// stores no time.
    pub modified: Option<i64>,
    /// Uncompressed size divided by the compressed size the entry owns; absent
    /// when none can be attributed to it (TAR, solid members, empty entries).
    pub compression_ratio: Option<f64>,
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
    /// `true` when a size field of this entry exceeded `2^53 - 1` and was
    /// clamped to it.
    pub size_clamped: bool,
    /// File permissions (raw Unix mode).
    pub mode: Option<u32>,
    /// Modification time in milliseconds since the Unix epoch, negative
    /// before it, clamped to `±(2^53 - 1)`. Absent only when the archive
    /// stores no time.
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
    /// `true` when a size field of this entry exceeded `2^53 - 1` and was
    /// clamped to it.
    pub size_clamped: bool,
    /// File permissions (raw Unix mode).
    pub mode: Option<u32>,
    /// Modification time in milliseconds since the Unix epoch, negative
    /// before it, clamped to `±(2^53 - 1)`. Absent only when the archive
    /// stores no time.
    pub modified: Option<i64>,
    /// The link target. A 7z target is `'unread'` unless the listing was asked
    /// to read stored targets.
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
    /// `true` when a size field of this entry exceeded `2^53 - 1` and was
    /// clamped to it.
    pub size_clamped: bool,
    /// File permissions (raw Unix mode).
    pub mode: Option<u32>,
    /// Modification time in milliseconds since the Unix epoch, negative
    /// before it, clamped to `±(2^53 - 1)`. Absent only when the archive
    /// stores no time.
    pub modified: Option<i64>,
    /// The link target.
    #[napi(ts_type = "LinkTarget")]
    pub target: LinkTarget,
}

/// An entry of a type newer than this binding.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct UnknownManifestEntry {
    /// Entry path (relative, as stored in archive).
    pub path: String,
    /// The entry type's token, as core spells it.
    pub entry_type: String,
}

/// One entry of a listing, discriminated by `entryType`.
pub type ArchiveEntry = Either5<
    ManifestFileEntry,
    ManifestDirectoryEntry,
    ManifestSymlinkEntry,
    ManifestHardlinkEntry,
    UnknownManifestEntry,
>;

/// The fields every entry kind carries.
struct EntryCommon {
    path: String,
    compressed_size: Option<ByteSize>,
    mode: Option<u32>,
    modified: Option<i64>,
}

fn entry_common(entry: &exarch_core::ArchiveEntry) -> CoreResult<EntryCommon> {
    Ok(EntryCommon {
        path: entry
            .utf8_path()
            .map_err(|malformation| Failure::from(CoreError::from(malformation)))?
            .to_owned(),
        compressed_size: entry.compressed_size().map(ByteSize::new),
        mode: entry.mode.map(exarch_core::RawMode::get),
        modified: entry
            .modified
            .map(|time| signed_millis(exarch_core::UnixTime::from(time))),
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
    let compressed = compressed_size.map(|size| size.value);
    let compressed_clamped = compressed_size.is_some_and(|size| size.clamped);
    Ok(match &entry.kind {
        Kind::File { .. } => {
            let size = ByteSize::new(entry.size());
            Either5::A(ManifestFileEntry {
                path,
                entry_type: ManifestEntryType::File,
                size: size.value,
                compressed_size: compressed,
                size_clamped: size.clamped || compressed_clamped,
                mode,
                modified,
                compression_ratio: entry.compression_ratio(),
            })
        }
        Kind::Directory => Either5::B(ManifestDirectoryEntry {
            path,
            entry_type: ManifestEntryType::Directory,
            compressed_size: compressed,
            size_clamped: compressed_clamped,
            mode,
            modified,
        }),
        Kind::Symlink { target } => Either5::C(ManifestSymlinkEntry {
            path,
            entry_type: ManifestEntryType::Symlink,
            compressed_size: compressed,
            size_clamped: compressed_clamped,
            mode,
            modified,
            target: link_target(target)?,
        }),
        Kind::Hardlink { target } => Either5::D(ManifestHardlinkEntry {
            path,
            entry_type: ManifestEntryType::Hardlink,
            compressed_size: compressed,
            size_clamped: compressed_clamped,
            mode,
            modified,
            target: link_target(target)?,
        }),
        other => Either5::E(UnknownManifestEntry {
            path,
            entry_type: other.entry_type().as_str().to_owned(),
        }),
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
    /// Integrity check result: an `IntegrityStatus`, or a token newer than this
    /// binding.
    #[napi(ts_type = "IntegrityStatus | (string & {})")]
    pub integrity_status: String,
    /// What the integrity check left unverified; absent unless the check was
    /// requested.
    pub integrity_gaps: Option<IntegrityGaps>,
    /// Security check result.
    pub security_status: CheckStatus,
    /// List of all issues found (sorted by severity).
    #[napi(ts_type = "Array<VerificationIssue>")]
    pub issues: Vec<VerificationIssue>,
    /// Total entries scanned.
    pub total_entries: i64,
    /// Entries flagged as suspicious.
    pub suspicious_entries: i64,
    /// Total uncompressed size.
    pub total_size: i64,
    /// `true` when `totalSize` exceeded `2^53 - 1` and was clamped to it.
    pub size_clamped: bool,
    /// Archive format: an `ArchiveType`, or a token newer than this binding.
    #[napi(ts_type = "ArchiveType | (string & {})")]
    pub format: String,
    /// Whether the archive is safe: `status` is `'PASS'`.
    pub is_safe: bool,
    /// Whether any issue is `'CRITICAL'`.
    pub has_critical_issues: bool,
}

impl From<exarch_core::VerificationReport> for VerificationReport {
    fn from(report: exarch_core::VerificationReport) -> Self {
        let total_size = ByteSize::new(report.total_size());
        Self {
            status: report.status().into(),
            integrity_status: report.integrity_status().as_str().to_owned(),
            integrity_gaps: report.integrity_gaps().map(IntegrityGaps::from),
            security_status: report.security_status().into(),
            total_entries: saturating_usize(report.total_entries()),
            suspicious_entries: saturating_usize(report.suspicious_entries()),
            total_size: total_size.value,
            size_clamped: total_size.clamped,
            format: report.format().as_str().to_owned(),
            is_safe: report.is_safe(),
            has_critical_issues: report.has_critical_issues(),
            issues: report
                .into_issues()
                .into_iter()
                .map(VerificationIssue::from)
                .collect(),
        }
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
    /// Issue category: an `IssueCategory`, or a token newer than this binding.
    #[napi(ts_type = "IssueCategory | (string & {})")]
    pub category: String,
    /// Entry path that triggered issue (if applicable); a path that is not
    /// valid UTF-8 or contains a backslash is rendered injectively: a backslash
    /// is `\x5C` and each invalid byte is `\xNN`.
    pub entry_path: Option<String>,
    /// Human-readable description.
    pub message: String,
    /// The `ErrorCode` extraction would fail with, for a refusal.
    #[napi(ts_type = "ErrorCode | (string & {})")]
    pub code: Option<String>,
    /// Finer classification of the refusal.
    #[napi(
        ts_type = "InvalidArchiveSubCode | SecurityViolationSubCode | QuotaSubCode | ZipBombSubCode | (string & {})"
    )]
    pub sub_code: Option<String>,
    /// The `SecurityConfig` setting that relaxes the refusal.
    #[napi(ts_type = "PolicySetting | (string & {})")]
    pub relaxable_by: Option<String>,
    /// The configuration setting an `INVALID_CONFIGURATION` refusal names.
    #[napi(ts_type = "ConfigSetting | (string & {})")]
    pub setting: Option<String>,
    /// The kind of an `IO_ERROR` refusal.
    #[napi(ts_type = "IoKind | (string & {})")]
    pub io_kind: Option<String>,
    /// The permission bits (raw archive mode) of an `'Invalid Permissions'`
    /// refusal or of an `'Executable File'` finding.
    pub mode: Option<u32>,
}

impl From<exarch_core::VerificationIssue> for VerificationIssue {
    fn from(issue: exarch_core::VerificationIssue) -> Self {
        let kind = issue.ffi_kind();
        Self {
            severity: issue.severity().into(),
            category: issue.category().as_str().to_owned(),
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
            io_kind: kind
                .and_then(exarch_core::FfiKind::io_kind)
                .map(|kind| exarch_core::IoKind::from(kind).as_str().to_owned()),
            mode: issue.mode().map(exarch_core::RawMode::get),
        }
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

    const MAX_SAFE: i64 = 9_007_199_254_740_991;

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
            Either4::A(w) => &w.message,
            Either4::B(w) => &w.message,
            Either4::C(w) => &w.message,
            Either4::D(w) => &w.message,
        }
    }

    fn creation_message(warning: &CreationWarning) -> &str {
        match warning {
            Either4::A(w) => &w.message,
            Either4::B(w) => &w.message,
            Either4::C(w) => &w.message,
            Either4::D(w) => &w.message,
        }
    }

    #[test]
    fn test_anti_items_warning_is_typed() {
        let warning = extraction_warning(&anti(3));
        let Either4::A(typed) = warning else {
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
            identity: exarch_core::BackupIdentity::Unverified,
            io_kind: exarch_core::IoKind::PermissionDenied,
            message: "denied".into(),
        };
        let Either4::B(typed) = extraction_warning(&core) else {
            panic!("expected the backup warning");
        };
        assert_eq!(typed.kind, ExtractionWarningKind::BackupCleanupFailed);
        assert_eq!(typed.identity, "unverified");
        assert_eq!(typed.io_kind, "PermissionDenied");
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
    fn test_narrowed_root_warning_is_typed_for_every_reason() {
        for reason in exarch_core::NarrowingReason::ALL {
            let core = exarch_core::ExtractionWarning::RootAccessNarrowed { reason: *reason };
            let Either4::C(typed) = extraction_warning(&core) else {
                panic!("expected the narrowed-root warning for {reason}");
            };
            assert_eq!(typed.kind, ExtractionWarningKind::RootAccessNarrowed);
            assert_eq!(typed.reason, reason.as_str());
            assert_eq!(typed.message, core.to_string());
        }
    }

    #[test]
    fn test_creation_warnings_are_typed() {
        use exarch_core::CreationWarning as Core;
        let over = creation_warning(&Core::ZipRatioOverDefaultLimit {
            entries: 2,
            limit: 100.0,
            needed_ratio: 250.0,
        });
        let Either4::A(over) = over else {
            panic!("expected the ratio warning");
        };
        assert_eq!(over.kind, CreationWarningKind::ZipRatioOverDefaultLimit);
        assert_eq!(
            (over.entries, over.limit, over.needed_ratio),
            (2, 100.0, 250.0)
        );

        let failed = creation_warning(&Core::ZipRatioCheckFailed { reason: "r".into() });
        let Either4::B(failed) = failed else {
            panic!("expected the check-failed warning");
        };
        assert_eq!(failed.reason, "r");

        let synced = creation_warning(&Core::DirectoryNotSynced {
            io_kind: exarch_core::IoKind::PermissionDenied,
        });
        let Either4::C(synced) = synced else {
            panic!("expected the not-synced warning");
        };
        assert_eq!(synced.io_kind, "PermissionDenied");
    }

    #[test]
    fn test_warning_kind_mirrors_match_core() {
        let extraction: Vec<_> = [
            ExtractionWarningKind::AntiItemsSkipped,
            ExtractionWarningKind::BackupCleanupFailed,
            ExtractionWarningKind::RootAccessNarrowed,
        ]
        .into_iter()
        .map(|kind| match kind {
            ExtractionWarningKind::AntiItemsSkipped => "anti_items_skipped",
            ExtractionWarningKind::BackupCleanupFailed => "backup_cleanup_failed",
            ExtractionWarningKind::RootAccessNarrowed => "root_access_narrowed",
        })
        .collect();
        assert_eq!(extraction, exarch_core::ExtractionWarningKind::NAMES);

        let narrowing = [
            NarrowingReason::AclUnreadable,
            NarrowingReason::DestinationChanged,
            NarrowingReason::UnmappedId,
            NarrowingReason::OwnershipDiffers,
            NarrowingReason::AclCopyFailed,
            NarrowingReason::GroupNotKept,
            NarrowingReason::ForeignWriteDropped,
            NarrowingReason::OwnerNotKept,
            NarrowingReason::DestinationVanished,
        ]
        .map(|reason| match reason {
            NarrowingReason::AclUnreadable => "acl_unreadable",
            NarrowingReason::DestinationChanged => "destination_changed",
            NarrowingReason::UnmappedId => "unmapped_id",
            NarrowingReason::OwnershipDiffers => "ownership_differs",
            NarrowingReason::AclCopyFailed => "acl_copy_failed",
            NarrowingReason::GroupNotKept => "group_not_kept",
            NarrowingReason::ForeignWriteDropped => "foreign_write_dropped",
            NarrowingReason::OwnerNotKept => "owner_not_kept",
            NarrowingReason::DestinationVanished => "destination_vanished",
        });
        assert_eq!(narrowing, exarch_core::NarrowingReason::NAMES);

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
        assert_eq!(identity, exarch_core::BackupIdentity::NAMES);
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

        let counts: Vec<(&str, i64)> = summary
            .counts
            .iter()
            .map(|c| (c.kind.as_str(), c.count))
            .collect();
        assert_eq!(counts, [("duplicate", 2), ("unreadable", 1)]);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.sample.len(), 3);
        assert_eq!(summary.sample[2].kind, "unreadable");
        assert_eq!(
            summary.sample[2].io_kind.as_deref(),
            Some("PermissionDenied")
        );
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
        assert_eq!(extraction_message(&report.warnings[0]), anti(1).to_string());
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
        assert_eq!(extraction_message(&report.warnings[0]), anti(1).to_string());
        assert_eq!(extraction_message(&report.warnings[1]), anti(2).to_string());
        assert_eq!(extraction_message(&report.warnings[2]), anti(3).to_string());
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

        let report = CreationReport::from(core_report);

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

        let Either5::A(entry) = archive_entry(&core_entry).unwrap() else {
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
    fn signed_millis_clamps_to_the_safe_integer_range() {
        use std::time::Duration;
        use std::time::UNIX_EPOCH;

        let far = Duration::from_secs(1 << 44);
        let after = UNIX_EPOCH.checked_add(far).unwrap();
        let before = UNIX_EPOCH.checked_sub(far).unwrap();
        let safe = i64::try_from(MAX_SAFE_INTEGER).unwrap();
        assert_eq!(signed_millis(exarch_core::UnixTime::from(after)), safe);
        assert_eq!(signed_millis(exarch_core::UnixTime::from(before)), -safe);
    }

    #[test]
    fn a_sub_millisecond_time_rounds_toward_negative_infinity_in_an_entry() {
        use std::time::Duration;
        use std::time::UNIX_EPOCH;

        let millis = |time| {
            let mut entry = exarch_core::ArchiveEntry::new(
                "f".into(),
                exarch_core::ManifestEntryKind::Directory,
            );
            entry.modified = Some(time);
            entry_common(&entry).unwrap().modified
        };
        assert_eq!(millis(UNIX_EPOCH - Duration::from_micros(1)), Some(-1));
        assert_eq!(millis(UNIX_EPOCH + Duration::from_micros(1500)), Some(1));
        assert_eq!(millis(UNIX_EPOCH - Duration::from_micros(1500)), Some(-2));
    }

    #[test]
    fn a_time_before_the_epoch_is_negative_milliseconds() {
        use std::time::Duration;
        use std::time::UNIX_EPOCH;

        let before = exarch_core::UnixTime::from(UNIX_EPOCH - Duration::from_secs(1000));
        assert_eq!(signed_millis(before), -1_000_000);
        let after = exarch_core::UnixTime::from(UNIX_EPOCH + Duration::from_secs(1000));
        assert_eq!(signed_millis(after), 1_000_000);
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
        let Either5::C(recorded) = archive_entry(&entry(Core::Recorded("a/b".into()))).unwrap()
        else {
            panic!("a symlink converts to a symlink entry");
        };
        assert_matches!(
            recorded.target,
            Either6::A(RecordedLinkTarget { ref path, .. }) if path == "a/b"
        );
        let Either5::C(oversized) = archive_entry(&entry(Core::Oversized { bytes: 9000 })).unwrap()
        else {
            panic!("a symlink converts to a symlink entry");
        };
        assert_matches!(
            oversized.target,
            Either6::E(OversizedLinkTarget { bytes: 9000, .. })
        );
        let Either5::C(unread) = archive_entry(&entry(Core::Unread)).unwrap() else {
            panic!("a symlink converts to a symlink entry");
        };
        assert_matches!(unread.target, Either6::C(_));
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

        let manifest = ArchiveManifest::from_core(
            core_manifest,
            &exarch_core::SecurityConfig::default(),
            exarch_core::VolumeIdentity::default(),
        )
        .unwrap();

        assert_eq!(manifest.total_entries, 2);
        assert_eq!(manifest.dispositions.len(), 2);
        let Either4::A(extract) = &manifest.dispositions[0] else {
            panic!("the selected file extracts");
        };
        assert_eq!(extract.action, DispositionKind::Extract);
        assert_eq!(
            (extract.path.as_str(), extract.landing.as_str()),
            ("keep/a/b.txt", "b.txt")
        );
        let Either4::B(skip) = &manifest.dispositions[1] else {
            panic!("the other file is left out");
        };
        assert_eq!(skip.action, DispositionKind::Skip);
        assert_eq!(
            (skip.path.as_str(), skip.kind.as_str()),
            ("other.txt", "not_selected")
        );
    }

    #[test]
    fn a_refused_disposition_maps_to_its_own_object() {
        let Either4::C(refused) = entry_disposition(
            std::path::Path::new("bad/x"),
            exarch_core::Disposition::Refuse,
        )
        .unwrap() else {
            panic!("refuse maps to the refuse object");
        };
        assert_eq!(refused.action, DispositionKind::Refuse);
        assert_eq!(refused.path, "bad/x");
    }

    #[test]
    fn test_archive_manifest_conversion() {
        let mut core_manifest = exarch_core::ArchiveManifest::new(CoreArchiveType::TarGz);
        for i in 0..10 {
            core_manifest
                .add_entry(sized_entry(&format!("f{i}"), 500))
                .unwrap();
        }

        let manifest = ArchiveManifest::from_core(
            core_manifest,
            &exarch_core::SecurityConfig::default(),
            exarch_core::VolumeIdentity::default(),
        )
        .unwrap();

        assert_eq!(manifest.total_entries, 10);
        assert_eq!(manifest.total_size, 5000);
        assert_eq!(manifest.format, "TarGz");
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

        let report = VerificationReport::from(core_report);

        assert_eq!(report.status, VerificationStatus::Pass);
        assert_eq!(report.integrity_status, "SKIPPED");
        assert_eq!(report.security_status, CheckStatus::Pass);
        assert_eq!(report.total_entries, 10);
        assert_eq!(report.suspicious_entries, 0);
        assert_eq!(report.total_size, 5000);
    }

    #[test]
    fn test_security_policy_issue_conversion_and_status() {
        let core_issue = policy_issue();

        let issue = VerificationIssue::from(core_issue);
        assert_eq!(issue.category, "Security Policy");

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
        let report = VerificationReport::from(core_report);
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

        let issue = VerificationIssue::from(core_issue);

        assert_eq!(issue.severity, IssueSeverity::Critical);
        assert_eq!(issue.category, "Path Traversal");
        assert_eq!(issue.entry_path, Some("../etc/passwd".to_string()));
        assert_eq!(issue.message, "Path traversal detected: ../etc/passwd");
        assert_eq!(issue.code.as_deref(), Some("PATH_TRAVERSAL"));
        assert!(issue.sub_code.is_none());
        assert_eq!(issue.relaxable_by, None);
    }

    #[test]
    fn test_policy_refusal_issue_carries_sub_code_and_setting() {
        let issue = VerificationIssue::from(policy_issue());

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

        let issue = VerificationIssue::from(core_issue);

        assert_eq!(issue.mode, Some(0o4755));
    }

    #[test]
    fn test_executable_heuristic_carries_the_raw_mode() {
        let issue = VerificationIssue::from(exarch_core::VerificationIssue::new(
            exarch_core::IssueSeverity::Low,
            exarch_core::Finding::Heuristic(exarch_core::Heuristic::ExecutableFile {
                mode: exarch_core::RawMode::new(0o755),
            }),
        ));

        assert_eq!(issue.mode, Some(0o755));
        assert_eq!(issue.code, None);
    }

    #[test]
    fn test_heuristic_issue_carries_no_refusal_properties() {
        let issue = VerificationIssue::from(exarch_core::VerificationIssue::new(
            exarch_core::IssueSeverity::Low,
            exarch_core::Finding::Heuristic(exarch_core::Heuristic::SuspiciousExtension),
        ));

        assert_eq!(issue.code, None);
        assert!(issue.sub_code.is_none());
        assert_eq!(issue.io_kind, None);
    }

    // CR-004: Overflow/saturating conversion tests
    #[test]
    fn test_extraction_report_counts_are_exact_beyond_u32() {
        let mut core_report = CoreReport::new();
        core_report.files_extracted = (u32::MAX as usize) + 1000;

        let report = ExtractionReport::from(core_report);

        assert_eq!(report.files_extracted, i64::from(u32::MAX) + 1000);
    }

    #[test]
    fn test_extraction_report_saturates_bytes_written_at_max_safe_integer() {
        let mut core_report = CoreReport::new();
        // Set to value > MAX_SAFE
        core_report.bytes_written = u64::MAX;

        let report = ExtractionReport::from(core_report);

        assert_eq!(
            report.bytes_written, MAX_SAFE,
            "bytes_written should saturate to MAX_SAFE"
        );
        assert!(report.size_clamped);
    }

    #[test]
    fn test_exact_size_is_not_flagged_as_clamped() {
        let mut core_report = CoreReport::new();
        core_report.bytes_written = MAX_SAFE as u64;

        let report = ExtractionReport::from(core_report);

        assert_eq!(report.bytes_written, MAX_SAFE);
        assert!(!report.size_clamped);
    }

    #[test]
    fn test_extraction_report_saturates_duration_ms_at_max_safe_integer() {
        let mut core_report = CoreReport::new();
        // Create a very large duration that exceeds MAX_SAFE milliseconds
        // MAX_SAFE ms is about 292 million years, so use u64::MAX seconds
        core_report.duration = Duration::from_secs(u64::MAX);

        let report = ExtractionReport::from(core_report);

        assert_eq!(
            report.duration_ms, MAX_SAFE,
            "duration_ms should saturate to MAX_SAFE"
        );
    }

    #[test]
    fn test_creation_report_counts_are_exact_beyond_u32() {
        let mut core_report = exarch_core::CreationReport::new();
        core_report.files_added = (u32::MAX as usize) + 1000;

        let report = CreationReport::from(core_report);

        assert_eq!(report.files_added, i64::from(u32::MAX) + 1000);
    }

    #[test]
    fn test_creation_report_saturates_bytes_written_at_max_safe_integer() {
        let mut core_report = exarch_core::CreationReport::new();
        core_report.bytes_written = u64::MAX;

        let report = CreationReport::from(core_report);

        assert_eq!(
            report.bytes_written, MAX_SAFE,
            "bytes_written should saturate to MAX_SAFE"
        );
    }

    #[test]
    fn test_creation_report_saturates_bytes_compressed_at_max_safe_integer() {
        let mut core_report = exarch_core::CreationReport::new();
        core_report.bytes_compressed = u64::MAX;

        let report = CreationReport::from(core_report);

        assert_eq!(
            report.bytes_compressed, MAX_SAFE,
            "bytes_compressed should saturate to MAX_SAFE"
        );
    }

    #[test]
    fn test_saturating_u32_clamps_at_u32_max() {
        assert_eq!(saturating_u32(7), 7);
        assert_eq!(saturating_u32((u32::MAX as usize) + 1000), u32::MAX);
    }

    #[test]
    fn test_byte_size_flags_only_a_real_clamp() {
        assert_eq!(
            ByteSize::new(7),
            ByteSize {
                value: 7,
                clamped: false
            }
        );
        assert_eq!(
            ByteSize::new(MAX_SAFE_INTEGER),
            ByteSize {
                value: MAX_SAFE,
                clamped: false
            }
        );
        assert_eq!(
            ByteSize::new(MAX_SAFE_INTEGER + 1),
            ByteSize {
                value: MAX_SAFE,
                clamped: true
            }
        );
    }

    #[test]
    fn test_saturating_i64_clamps_at_max_safe_integer() {
        assert_eq!(saturating_i64(7), 7);
        assert_eq!(saturating_i64(u64::MAX), MAX_SAFE);
    }

    #[test]
    fn test_archive_manifest_saturates_total_size_at_max_safe_integer() {
        let mut core_manifest = exarch_core::ArchiveManifest::new(CoreArchiveType::TarGz);
        core_manifest
            .add_entry(sized_entry("big", u64::MAX))
            .unwrap();

        let manifest = ArchiveManifest::from_core(
            core_manifest,
            &exarch_core::SecurityConfig::default(),
            exarch_core::VolumeIdentity::default(),
        )
        .unwrap();

        assert_eq!(
            manifest.total_size, MAX_SAFE,
            "total_size should saturate to MAX_SAFE"
        );
    }

    #[test]
    fn test_archive_entry_saturates_size_at_max_safe_integer() {
        let core_entry = sized_entry("test.txt", u64::MAX);

        let Either5::A(entry) = archive_entry(&core_entry).unwrap() else {
            panic!("a regular file converts to a file entry");
        };

        assert_eq!(entry.size, MAX_SAFE, "size should saturate to MAX_SAFE");
    }

    #[test]
    fn test_archive_entry_saturates_compressed_size_at_max_safe_integer() {
        let mut core_entry = sized_entry("test.txt", 1024);
        core_entry.compression = exarch_core::EntryCompression::Entry(Compressed(u64::MAX));

        let Either5::A(entry) = archive_entry(&core_entry).unwrap() else {
            panic!("a regular file converts to a file entry");
        };

        assert_eq!(
            entry.compressed_size,
            Some(MAX_SAFE),
            "compressed_size should saturate to MAX_SAFE"
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
        let mapped: Vec<_> = exarch_core::IssueCategory::ALL
            .iter()
            .map(|v| IssueCategory::try_from(*v).unwrap())
            .collect();
        assert_all_distinct(&mapped);
    }

    #[test]
    fn test_integrity_status_try_from_covers_every_core_variant() {
        let mapped: Vec<_> = exarch_core::IntegrityStatus::ALL
            .iter()
            .map(|v| IntegrityStatus::try_from(*v).unwrap())
            .collect();
        assert_all_distinct(&mapped);
    }

    #[test]
    fn test_unverified_reason_try_from_covers_every_core_variant() {
        let mapped: Vec<_> = exarch_core::UnverifiedReason::ALL
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
    fn test_mark_propagation_field_is_the_core_states_widened() {
        let mut union: Vec<String> = exarch_core::MarkState::NAMES
            .iter()
            .map(|name| format!("'{name}'"))
            .collect();
        union.push("(string & {})".to_owned());
        let line = format!("  markPropagation: {}", union.join(" | "));
        assert!(
            include_str!("../index.d.ts").lines().any(|l| l == line),
            "index.d.ts out of sync with MarkState::NAMES, expected:\n{line}"
        );
        let source = include_str!("report.rs");
        assert!(
            source.contains(&format!("ts_type = \"{}\"", union.join(" | "))),
            "the markPropagation ts_type is out of sync with MarkState::NAMES"
        );
    }

    #[test]
    fn every_core_link_target_state_has_a_mirror() {
        for core in CoreLinkTargetState::ALL {
            assert!(LinkTargetState::try_from(*core).is_ok(), "{core:?}");
        }
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
                exarch_core::IssueCategory::ALL,
                exarch_core::IssueCategory::as_str,
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
                "LinkTargetState",
                CoreLinkTargetState::ALL,
                CoreLinkTargetState::as_str,
            ),
            union_line(
                "BackupIdentity",
                exarch_core::BackupIdentity::ALL,
                exarch_core::BackupIdentity::as_str,
            ),
            union_line(
                "IntegrityStatus",
                exarch_core::IntegrityStatus::ALL,
                exarch_core::IntegrityStatus::as_str,
            ),
            union_line(
                "UnverifiedReason",
                exarch_core::UnverifiedReason::ALL,
                exarch_core::UnverifiedReason::as_str,
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
