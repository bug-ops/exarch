//! Node.js bindings for `ExtractionReport`.

use exarch_core::ExtractionReport as CoreReport;
use exarch_core::formats::detect::ArchiveType as CoreArchiveType;
use exarch_core::inspection::CheckStatus as CoreCheckStatus;
use exarch_core::inspection::IssueCategory as CoreIssueCategory;
use exarch_core::inspection::IssueSeverity as CoreIssueSeverity;
use exarch_core::inspection::ManifestEntryType as CoreManifestEntryType;
use exarch_core::inspection::VerificationStatus as CoreVerificationStatus;
use napi::Error;
use napi::Result;
use napi_derive::napi;

fn saturating_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn saturating_i64(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

fn unknown_variant(what: &str, wire: &str) -> Error {
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
    /// Invalid or corrupted archive.
    #[napi(value = "Invalid Archive")]
    InvalidArchive,
    /// Suspicious path or filename.
    #[napi(value = "Suspicious Path")]
    SuspiciousPath,
    /// Executable file detected.
    #[napi(value = "Executable File")]
    ExecutableFile,
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
            CoreIssueCategory::InvalidArchive => Self::InvalidArchive,
            CoreIssueCategory::SuspiciousPath => Self::SuspiciousPath,
            CoreIssueCategory::ExecutableFile => Self::ExecutableFile,
            other => return Err(unknown_variant("issue category", other.as_str())),
        })
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
    /// Number of files skipped due to security checks.
    pub files_skipped: u32,
    /// List of warning messages.
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
            files_skipped: saturating_u32(report.files_skipped),
            warnings: report.warnings,
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
    /// Number of files skipped (due to filters or errors).
    pub files_skipped: u32,
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
            files_skipped: saturating_u32(report.files_skipped),
            warnings: report.warnings,
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
    pub entries: Vec<ArchiveEntry>,
    /// Total number of entries.
    pub total_entries: u32,
    /// Total uncompressed size in bytes.
    pub total_size: i64,
    /// Archive format.
    pub format: ArchiveType,
}

impl TryFrom<exarch_core::inspection::ArchiveManifest> for ArchiveManifest {
    type Error = Error;

    fn try_from(manifest: exarch_core::inspection::ArchiveManifest) -> Result<Self> {
        let total_entries = saturating_u32(manifest.total_entries());
        let total_size = saturating_i64(manifest.total_size());
        let format = ArchiveType::try_from(manifest.format())?;
        Ok(Self {
            entries: manifest
                .into_entries()
                .into_iter()
                .map(ArchiveEntry::from)
                .collect(),
            total_entries,
            total_size,
            format,
        })
    }
}

/// Single entry in archive manifest.
///
/// Contains metadata about a file, directory, symlink, or hardlink
/// without extracting it to disk.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct ArchiveEntry {
    /// Entry path (relative, as stored in archive).
    pub path: String,
    /// Entry type.
    pub entry_type: ManifestEntryType,
    /// Uncompressed size in bytes (0 for directories).
    pub size: i64,
    /// Compressed size in bytes (if available, ZIP only).
    pub compressed_size: Option<i64>,
    /// File permissions (Unix mode).
    pub mode: Option<u32>,
    /// Modification time (milliseconds since Unix epoch).
    pub modified: Option<i64>,
    /// Symlink target (if `entry_type` is "Symlink").
    pub symlink_target: Option<String>,
    /// Hardlink target (if `entry_type` is "Hardlink").
    pub hardlink_target: Option<String>,
}

impl From<exarch_core::inspection::ArchiveEntry> for ArchiveEntry {
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    fn from(entry: exarch_core::inspection::ArchiveEntry) -> Self {
        Self {
            path: entry.path.to_string_lossy().into_owned(),
            entry_type: entry.entry_type.into(),
            size: saturating_i64(entry.size),
            compressed_size: entry.compressed_size.map(saturating_i64),
            mode: entry.mode,
            modified: entry.modified.and_then(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
            }),
            symlink_target: entry
                .symlink_target
                .map(|p| p.to_string_lossy().into_owned()),
            hardlink_target: entry
                .hardlink_target
                .map(|p| p.to_string_lossy().into_owned()),
        }
    }
}

/// Result of archive verification.
///
/// Generated by `verifyArchive()`, contains security and integrity checks
/// performed without extracting files to disk.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct VerificationReport {
    /// Overall verification status.
    pub status: VerificationStatus,
    /// Integrity check result.
    pub integrity_status: CheckStatus,
    /// Security check result.
    pub security_status: CheckStatus,
    /// List of all issues found (sorted by severity).
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
    type Error = Error;

    fn try_from(report: exarch_core::inspection::VerificationReport) -> Result<Self> {
        let status = report.status().into();
        let integrity_status = report.integrity_status().into();
        let security_status = report.security_status().into();
        let total_entries = saturating_u32(report.total_entries());
        let suspicious_entries = saturating_u32(report.suspicious_entries());
        let total_size = saturating_i64(report.total_size());
        let format = ArchiveType::try_from(report.format())?;
        Ok(Self {
            status,
            integrity_status,
            security_status,
            issues: report
                .into_issues()
                .into_iter()
                .map(VerificationIssue::try_from)
                .collect::<Result<_>>()?,
            total_entries,
            suspicious_entries,
            total_size,
            format,
        })
    }
}

/// Single verification issue.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct VerificationIssue {
    /// Issue severity level.
    pub severity: IssueSeverity,
    /// Issue category.
    pub category: IssueCategory,
    /// Entry path that triggered issue (if applicable).
    pub entry_path: Option<String>,
    /// Human-readable description.
    pub message: String,
    /// Optional context (compression ratio, target path, etc.).
    pub context: Option<String>,
}

impl TryFrom<exarch_core::inspection::VerificationIssue> for VerificationIssue {
    type Error = Error;

    fn try_from(issue: exarch_core::inspection::VerificationIssue) -> Result<Self> {
        Ok(Self {
            severity: issue.severity.into(),
            category: issue.category.try_into()?,
            entry_path: issue.entry_path.map(|p| p.to_string_lossy().into_owned()),
            message: issue.message,
            context: issue.context,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_extraction_report_conversion() {
        let mut core_report = CoreReport::new();
        core_report.files_extracted = 10;
        core_report.directories_created = 5;
        core_report.symlinks_created = 2;
        core_report.bytes_written = 1024;
        core_report.duration = Duration::from_millis(500);
        core_report.files_skipped = 1;
        core_report.add_warning("Test warning".to_string());

        let report = ExtractionReport::from(core_report);

        assert_eq!(report.files_extracted, 10);
        assert_eq!(report.directories_created, 5);
        assert_eq!(report.symlinks_created, 2);
        assert_eq!(report.bytes_written, 1024);
        assert_eq!(report.duration_ms, 500);
        assert_eq!(report.files_skipped, 1);
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.warnings[0], "Test warning");
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
        core_report.add_warning("Warning 1".to_string());
        core_report.add_warning("Warning 2".to_string());
        core_report.add_warning("Warning 3".to_string());

        let report = ExtractionReport::from(core_report);

        assert_eq!(report.warnings.len(), 3);
        assert_eq!(report.warnings[0], "Warning 1");
        assert_eq!(report.warnings[1], "Warning 2");
        assert_eq!(report.warnings[2], "Warning 3");
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
        core_report.add_warning("First warning".to_string());
        core_report.add_warning("Second warning".to_string());
        core_report.add_warning("Third warning".to_string());

        let report = ExtractionReport::from(core_report);

        assert_eq!(report.warnings.len(), 3, "should have 3 warnings");
        assert_eq!(
            report.warnings[0], "First warning",
            "first warning should be at index 0"
        );
        assert_eq!(
            report.warnings[1], "Second warning",
            "second warning should be at index 1"
        );
        assert_eq!(
            report.warnings[2], "Third warning",
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
        core_report.files_skipped = 1;
        core_report.add_warning("Test warning".to_string());

        let report = CreationReport::from(core_report);

        assert_eq!(report.files_added, 10);
        assert_eq!(report.directories_added, 5);
        assert_eq!(report.symlinks_added, 2);
        assert_eq!(report.bytes_written, 1024);
        assert_eq!(report.bytes_compressed, 512);
        assert_eq!(report.duration_ms, 500);
        assert_eq!(report.files_skipped, 1);
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.warnings[0], "Test warning");
    }

    fn sized_entry(name: &str, size: u64) -> exarch_core::inspection::ArchiveEntry {
        exarch_core::inspection::ArchiveEntry::new(
            std::path::PathBuf::from(name),
            exarch_core::inspection::ManifestEntryType::File,
            size,
        )
    }

    // ArchiveEntry tests
    #[test]
    fn test_archive_entry_conversion() {
        use std::path::PathBuf;
        use std::time::UNIX_EPOCH;

        let mut core_entry = exarch_core::inspection::ArchiveEntry::new(
            PathBuf::from("test/file.txt"),
            exarch_core::inspection::ManifestEntryType::File,
            1024,
        );
        core_entry.compressed_size = Some(512);
        core_entry.mode = Some(0o644);
        core_entry.modified = Some(UNIX_EPOCH + std::time::Duration::from_secs(1000));

        let entry = ArchiveEntry::from(core_entry);

        assert_eq!(entry.path, "test/file.txt");
        assert_eq!(entry.entry_type, ManifestEntryType::File);
        assert_eq!(entry.size, 1024);
        assert_eq!(entry.compressed_size, Some(512));
        assert_eq!(entry.mode, Some(0o644));
        assert_eq!(entry.modified, Some(1_000_000));
        assert_eq!(entry.symlink_target, None);
        assert_eq!(entry.hardlink_target, None);
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
        assert_eq!(report.integrity_status, CheckStatus::Skipped);
        assert_eq!(report.security_status, CheckStatus::Pass);
        assert_eq!(report.total_entries, 10);
        assert_eq!(report.suspicious_entries, 0);
        assert_eq!(report.total_size, 5000);
    }

    // VerificationIssue tests
    #[test]
    fn test_verification_issue_conversion() {
        use std::path::PathBuf;

        let mut core_issue = exarch_core::inspection::VerificationIssue::new(
            CoreIssueSeverity::Critical,
            CoreIssueCategory::PathTraversal,
            "Path traversal detected".to_string(),
        );
        core_issue.entry_path = Some(PathBuf::from("../etc/passwd"));
        core_issue.context = Some("Attempt to escape directory".to_string());

        let issue = VerificationIssue::try_from(core_issue).unwrap();

        assert_eq!(issue.severity, IssueSeverity::Critical);
        assert_eq!(issue.category, IssueCategory::PathTraversal);
        assert_eq!(issue.entry_path, Some("../etc/passwd".to_string()));
        assert_eq!(issue.message, "Path traversal detected");
        assert_eq!(
            issue.context,
            Some("Attempt to escape directory".to_string())
        );
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

        let entry = ArchiveEntry::from(core_entry);

        assert_eq!(entry.size, i64::MAX, "size should saturate to i64::MAX");
    }

    #[test]
    fn test_archive_entry_saturates_compressed_size_at_i64_max() {
        let mut core_entry = sized_entry("test.txt", 1024);
        core_entry.compressed_size = Some(u64::MAX);

        let entry = ArchiveEntry::from(core_entry);

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
}
