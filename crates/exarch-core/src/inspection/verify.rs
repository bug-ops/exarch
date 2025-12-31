//! Archive verification implementation.

use std::path::Path;
use std::path::PathBuf;

use crate::ExtractionError;
use crate::Result;
use crate::SecurityConfig;
use crate::inspection::list::list_archive;
use crate::inspection::manifest::ArchiveEntry;
use crate::inspection::manifest::ManifestEntryType;
use crate::inspection::report::CheckStatus;
use crate::inspection::report::IssueCategory;
use crate::inspection::report::IssueSeverity;
use crate::inspection::report::VerificationIssue;
use crate::inspection::report::VerificationReport;
use crate::inspection::report::VerificationStatus;
use crate::security::path::validate_path;
use crate::security::permissions::sanitize_permissions;
use crate::security::quota::QuotaTracker;
use crate::security::symlink::validate_symlink;
use crate::security::zipbomb::validate_compression_ratio;
use crate::types::DestDir;
use crate::types::EntryType;

/// Verifies archive integrity and security without extracting.
///
/// Performs comprehensive validation:
/// - Integrity checks (structure, checksums)
/// - Security checks (path traversal, zip bombs, CVEs)
/// - Policy checks (file types, permissions)
///
/// # Arguments
///
/// * `archive_path` - Path to archive file
/// * `config` - Security configuration for validation
///
/// # Errors
///
/// Returns error if:
/// - Archive file cannot be opened
/// - Archive is severely corrupted (cannot read structure)
///
/// Security violations are reported in `VerificationReport.issues`,
/// not as errors.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::SecurityConfig;
/// use exarch_core::VerificationStatus;
/// use exarch_core::verify_archive;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = SecurityConfig::default();
/// let report = verify_archive("archive.tar.gz", &config)?;
///
/// if report.status == VerificationStatus::Pass {
///     println!("Archive is safe to extract");
/// } else {
///     eprintln!("Security issues found:");
///     for issue in report.issues {
///         eprintln!("  [{}] {}", issue.severity, issue.message);
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub fn verify_archive<P: AsRef<Path>>(
    archive_path: P,
    config: &SecurityConfig,
) -> Result<VerificationReport> {
    let archive_path = archive_path.as_ref();

    // List archive to get all entries
    let manifest = list_archive(archive_path, config)?;

    // Collect security issues
    let mut issues = Vec::new();
    let mut suspicious_entries = 0;

    // Use temporary destination for validation
    let temp_dir = std::env::temp_dir().join("exarch-verify");
    std::fs::create_dir_all(&temp_dir)?;
    let temp_dest = DestDir::new(temp_dir)?;

    // Track quota during verification
    let mut quota_tracker = QuotaTracker::new();

    for entry in &manifest.entries {
        // Validate entry and collect issues
        let entry_issues = verify_entry(entry, config, &temp_dest, &mut quota_tracker);

        if !entry_issues.is_empty() {
            suspicious_entries += 1;
            issues.extend(entry_issues);
        }

        // Add heuristic checks
        let heuristic_issues = check_heuristics(entry);
        issues.extend(heuristic_issues);
    }

    // Sort issues by severity (critical first)
    issues.sort_by(|a, b| a.severity.cmp(&b.severity).reverse());

    // Determine overall status
    let status = determine_status(&issues);
    let security_status = determine_security_status(&issues);

    Ok(VerificationReport {
        status,
        integrity_status: CheckStatus::Pass,
        security_status,
        issues,
        total_entries: manifest.total_entries,
        suspicious_entries,
        total_size: manifest.total_size,
        format: manifest.format,
    })
}

fn verify_entry(
    entry: &ArchiveEntry,
    config: &SecurityConfig,
    dest: &DestDir,
    quota_tracker: &mut QuotaTracker,
) -> Vec<VerificationIssue> {
    let mut issues = Vec::new();

    // Convert ManifestEntryType to EntryType
    let entry_type = match entry.entry_type {
        ManifestEntryType::File => EntryType::File,
        ManifestEntryType::Directory => EntryType::Directory,
        ManifestEntryType::Symlink => EntryType::Symlink {
            target: entry.symlink_target.clone().unwrap_or_default(),
        },
        ManifestEntryType::Hardlink => EntryType::Hardlink {
            target: entry.hardlink_target.clone().unwrap_or_default(),
        },
    };

    // Path validation
    if let Err(e) = validate_path(&entry.path, dest, config) {
        issues.push(VerificationIssue::from_error(&e, Some(entry.path.clone())));
    }

    // Quota validation using record_file (combines all checks)
    if let Err(e) = quota_tracker.record_file(entry.size, config) {
        issues.push(VerificationIssue::from_error(&e, Some(entry.path.clone())));
    }

    // Compression ratio validation (zip bomb detection)
    if let Some(compressed_size) = entry.compressed_size
        && let Err(e) = validate_compression_ratio(compressed_size, entry.size, config)
    {
        issues.push(VerificationIssue::from_error(&e, Some(entry.path.clone())));
    }

    // Symlink validation
    if let EntryType::Symlink { ref target } = entry_type {
        // Safe path for link
        if let Ok(safe_link_path) = validate_path(&entry.path, dest, config)
            && let Err(e) = validate_symlink(&safe_link_path, target, dest, config)
        {
            issues.push(VerificationIssue::from_error(&e, Some(entry.path.clone())));
        }
    }

    // Hardlink validation (similar to symlink)
    if let EntryType::Hardlink { ref target } = entry_type
        && let Ok(safe_link_path) = validate_path(&entry.path, dest, config)
        && let Err(e) = validate_path(target, dest, config)
    {
        issues.push(VerificationIssue {
            severity: IssueSeverity::Critical,
            category: IssueCategory::HardlinkEscape,
            entry_path: Some(entry.path.clone()),
            message: format!(
                "Hardlink target escapes destination: {} -> {}",
                safe_link_path.as_path().display(),
                target.display()
            ),
            context: Some(e.to_string()),
        });
    }

    // Permission validation
    if let Some(mode) = entry.mode
        && let Err(e) = check_permissions(mode, config)
    {
        issues.push(VerificationIssue::from_error(&e, Some(entry.path.clone())));
    }

    issues
}

fn check_permissions(mode: u32, config: &SecurityConfig) -> Result<()> {
    // Use a dummy path for permission validation
    let dummy_path = Path::new("");
    let sanitized = sanitize_permissions(dummy_path, mode, config)?;
    if sanitized == mode {
        Ok(())
    } else {
        Err(ExtractionError::InvalidPermissions {
            path: PathBuf::new(),
            mode,
        })
    }
}

fn check_heuristics(entry: &ArchiveEntry) -> Vec<VerificationIssue> {
    let mut issues = Vec::new();

    // Executable file detection
    if let Some(mode) = entry.mode
        && mode & 0o111 != 0
        && entry.entry_type == ManifestEntryType::File
    {
        issues.push(VerificationIssue {
            severity: IssueSeverity::Low,
            category: IssueCategory::ExecutableFile,
            entry_path: Some(entry.path.clone()),
            message: format!("Executable file: {}", entry.path.display()),
            context: Some(format!("mode: {mode:#o}")),
        });
    }

    // Suspicious extension detection
    if is_suspicious_extension(&entry.path) {
        issues.push(VerificationIssue {
            severity: IssueSeverity::Info,
            category: IssueCategory::SuspiciousPath,
            entry_path: Some(entry.path.clone()),
            message: format!("Suspicious extension: {}", entry.path.display()),
            context: None,
        });
    }

    issues
}

fn is_suspicious_extension(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|s| s.to_str()),
        Some("exe" | "dll" | "sh" | "bat" | "cmd")
    )
}

fn determine_status(issues: &[VerificationIssue]) -> VerificationStatus {
    let has_critical = issues.iter().any(|i| i.severity == IssueSeverity::Critical);
    let has_high = issues.iter().any(|i| i.severity == IssueSeverity::High);
    let has_medium = issues.iter().any(|i| i.severity == IssueSeverity::Medium);

    if has_critical || has_high {
        VerificationStatus::Fail
    } else if has_medium {
        VerificationStatus::Warning
    } else {
        VerificationStatus::Pass
    }
}

fn determine_security_status(issues: &[VerificationIssue]) -> CheckStatus {
    let security_issues: Vec<_> = issues
        .iter()
        .filter(|i| {
            matches!(
                i.category,
                IssueCategory::PathTraversal
                    | IssueCategory::SymlinkEscape
                    | IssueCategory::HardlinkEscape
                    | IssueCategory::ZipBomb
                    | IssueCategory::InvalidPermissions
                    | IssueCategory::QuotaExceeded
            )
        })
        .collect();

    if security_issues.is_empty() {
        CheckStatus::Pass
    } else {
        let has_critical = security_issues
            .iter()
            .any(|i| i.severity == IssueSeverity::Critical || i.severity == IssueSeverity::High);

        if has_critical {
            CheckStatus::Fail
        } else {
            CheckStatus::Warning
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_determine_status_pass() {
        let issues = vec![];
        assert_eq!(determine_status(&issues), VerificationStatus::Pass);
    }

    #[test]
    fn test_determine_status_fail_critical() {
        let issues = vec![VerificationIssue {
            severity: IssueSeverity::Critical,
            category: IssueCategory::PathTraversal,
            entry_path: None,
            message: "Test".to_string(),
            context: None,
        }];
        assert_eq!(determine_status(&issues), VerificationStatus::Fail);
    }

    #[test]
    fn test_determine_status_fail_high() {
        let issues = vec![VerificationIssue {
            severity: IssueSeverity::High,
            category: IssueCategory::QuotaExceeded,
            entry_path: None,
            message: "Test".to_string(),
            context: None,
        }];
        assert_eq!(determine_status(&issues), VerificationStatus::Fail);
    }

    #[test]
    fn test_determine_status_warning() {
        let issues = vec![VerificationIssue {
            severity: IssueSeverity::Medium,
            category: IssueCategory::InvalidPermissions,
            entry_path: None,
            message: "Test".to_string(),
            context: None,
        }];
        assert_eq!(determine_status(&issues), VerificationStatus::Warning);
    }

    #[test]
    fn test_is_suspicious_extension() {
        assert!(is_suspicious_extension(Path::new("file.exe")));
        assert!(is_suspicious_extension(Path::new("file.dll")));
        assert!(is_suspicious_extension(Path::new("file.sh")));
        assert!(is_suspicious_extension(Path::new("file.bat")));
        assert!(!is_suspicious_extension(Path::new("file.txt")));
        assert!(!is_suspicious_extension(Path::new("file.rs")));
    }

    #[test]
    fn test_check_heuristics_executable() {
        let entry = crate::inspection::manifest::ArchiveEntry {
            path: PathBuf::from("test.sh"),
            entry_type: ManifestEntryType::File,
            size: 100,
            compressed_size: None,
            mode: Some(0o755),
            modified: None,
            symlink_target: None,
            hardlink_target: None,
        };

        let issues = check_heuristics(&entry);
        assert!(!issues.is_empty());
        assert!(
            issues
                .iter()
                .any(|i| i.category == IssueCategory::ExecutableFile)
        );
    }

    #[test]
    fn test_check_heuristics_suspicious_extension() {
        let entry = crate::inspection::manifest::ArchiveEntry {
            path: PathBuf::from("malware.exe"),
            entry_type: ManifestEntryType::File,
            size: 100,
            compressed_size: None,
            mode: Some(0o644),
            modified: None,
            symlink_target: None,
            hardlink_target: None,
        };

        let issues = check_heuristics(&entry);
        assert!(!issues.is_empty());
        assert!(
            issues
                .iter()
                .any(|i| i.category == IssueCategory::SuspiciousPath)
        );
    }

    #[test]
    fn test_verify_archive_safe() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let data = b"safe file content";
        let mut header = tar::Header::new_gnu();
        header.set_path("safe/file.txt").unwrap();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, &data[..]).unwrap();

        let archive_data = builder.into_inner().unwrap();
        temp_file.write_all(&archive_data).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let report = verify_archive(temp_file.path(), &config).unwrap();

        assert_eq!(
            report.status,
            VerificationStatus::Pass,
            "Safe archive should pass verification"
        );
        assert_eq!(report.total_entries, 1);
        assert_eq!(report.suspicious_entries, 0);
        assert!(
            report.issues.is_empty(),
            "Safe archive should have no issues"
        );
    }

    // Note: Full CVE regression tests for path traversal require real malicious
    // archives that cannot be created using the tar crate (it validates paths).
    // Those tests should be added in tests/cve/ directory with pre-built malicious
    // fixtures. This test verifies the workflow works with archives that tar
    // crate accepts.

    #[test]
    fn test_verify_archive_symlink_escape() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_path("evil_link").unwrap();
        header.set_size(0);
        header.set_mode(0o777);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("/etc/passwd").unwrap();
        header.set_cksum();
        builder.append(&header, &[][..]).unwrap();

        let archive_data = builder.into_inner().unwrap();
        temp_file.write_all(&archive_data).unwrap();
        temp_file.flush().unwrap();

        // Default config blocks ALL symlinks, so check that the issue is detected
        let config = SecurityConfig::default();
        let report = verify_archive(temp_file.path(), &config).unwrap();

        assert_eq!(
            report.status,
            VerificationStatus::Fail,
            "Symlink should fail verification with default config"
        );
        assert_eq!(report.total_entries, 1);
        assert_eq!(report.suspicious_entries, 1);
        assert!(!report.issues.is_empty(), "Should detect symlink");

        // Symlink is blocked by default config (SecurityViolation -> SuspiciousPath
        // category)
        let has_symlink_issue = report.issues.iter().any(|i| {
            matches!(i.category, IssueCategory::SuspiciousPath) && i.message.contains("symlink")
        });

        assert!(
            has_symlink_issue,
            "Should have symlink-related issue, got: {:?}",
            report.issues
        );
    }

    #[test]
    fn test_verify_archive_setuid_binary() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let data = b"fake binary";
        let mut header = tar::Header::new_gnu();
        header.set_path("bin/setuid_prog").unwrap();
        header.set_size(data.len() as u64);
        header.set_mode(0o4755);
        header.set_cksum();
        builder.append(&header, &data[..]).unwrap();

        let archive_data = builder.into_inner().unwrap();
        temp_file.write_all(&archive_data).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let report = verify_archive(temp_file.path(), &config).unwrap();

        assert!(
            !report.issues.is_empty(),
            "Should detect setuid permission issue"
        );
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.category == IssueCategory::InvalidPermissions),
            "Should have InvalidPermissions issue for setuid"
        );
    }

    #[test]
    fn test_verify_archive_executable_file() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let data = b"#!/bin/bash\necho 'hello'";
        let mut header = tar::Header::new_gnu();
        header.set_path("script.sh").unwrap();
        header.set_size(data.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder.append(&header, &data[..]).unwrap();

        let archive_data = builder.into_inner().unwrap();
        temp_file.write_all(&archive_data).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let report = verify_archive(temp_file.path(), &config).unwrap();

        assert!(!report.issues.is_empty(), "Should detect executable file");
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.category == IssueCategory::ExecutableFile),
            "Should have ExecutableFile issue"
        );
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.category == IssueCategory::SuspiciousPath),
            "Should have SuspiciousPath issue for .sh extension"
        );
    }
}
