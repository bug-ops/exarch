//! Archive verification implementation.

use std::path::Path;

use crate::ArchiveError;
use crate::Result;
use crate::SecurityConfig;
use crate::config::Validated;
use crate::inspection::list::list_archive;
use crate::inspection::manifest::ArchiveEntry;
use crate::inspection::manifest::ArchiveManifest;
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

/// Verifies an already-listed manifest against the security config.
///
/// Used by `ArchiveFormat::verify()` to avoid re-opening the archive.
/// Performs the same checks as `verify_archive` but starts from a manifest
/// produced by `ArchiveFormat::list()`.
pub(crate) fn verify_manifest(
    manifest: &ArchiveManifest,
    config: &SecurityConfig<Validated>,
) -> Result<VerificationReport> {
    let mut issues = Vec::new();
    let mut suspicious_entries = 0;

    let temp_dir = tempfile::TempDir::new()?;
    let temp_dest = DestDir::new(temp_dir.path())?;

    let mut quota_tracker = QuotaTracker::new();

    for entry in &manifest.entries {
        let entry_issues = verify_entry(entry, config, &temp_dest, &mut quota_tracker);
        let heuristic_issues = check_heuristics(entry);

        // Info/Low heuristics (e.g. suspicious extension) never flip `status`
        // away from `Pass`, so they historically weren't counted as
        // "suspicious". A Medium+ heuristic does flip `status`, so it must
        // count too, or the report becomes self-contradictory (Warning with
        // zero suspicious entries).
        let has_medium_plus_heuristic = heuristic_issues
            .iter()
            .any(|i| i.severity >= IssueSeverity::Medium);
        if !entry_issues.is_empty() || has_medium_plus_heuristic {
            suspicious_entries += 1;
        }

        issues.extend(entry_issues);
        issues.extend(heuristic_issues);
    }

    issues.sort_by(|a, b| a.severity.cmp(&b.severity).reverse());

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
/// Security violations are reported in `VerificationReport.issues`, not as
/// errors.
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
    let validated_config = config.clone().validate()?;
    let manifest = list_archive(archive_path, &listing_config_for_verify(config))?;
    verify_manifest(&manifest, &validated_config)
}

/// Returns a config variant for the pre-flight listing step that feeds
/// `verify_manifest`, with `max_file_size` relaxed to unlimited and the
/// list-level NUL-byte/link-target checks relaxed to defer to
/// `verify_entry`'s own equivalent checks.
///
/// `verify` is a read-only, report-based operation: an oversized entry,
/// a NUL byte in an entry path, or an empty/NUL/missing symlink or hardlink
/// target are all meant to surface as a `VerificationIssue` from
/// `verify_entry` (which re-checks the real `config` against every manifest
/// entry via `validate_path`/`validate_symlink`), not abort the listing step
/// before any report exists. `max_file_count` and `max_total_size` are left
/// untouched, matching prior behavior. See
/// `SecurityConfig::relaxed_for_verify_preflight`'s field doc for exactly
/// which `list_archive` checks this skips.
///
/// Generic over the validation typestate so it serves both callers: the
/// top-level [`verify_archive`] (still `Unvalidated`, feeds into
/// [`list_archive`] which validates internally) and the
/// [`ArchiveFormat`](crate::formats::traits::ArchiveFormat) trait's `verify()`
/// implementations (already `Validated`, feeds into `list()` which requires
/// it). Delegates to `SecurityConfig::as_relaxed_for_verify_preflight`, whose
/// docs justify why re-deriving a `Validated` result without calling
/// `validate()` again is sound.
pub(crate) fn listing_config_for_verify<State>(
    config: &SecurityConfig<State>,
) -> SecurityConfig<State> {
    config.as_relaxed_for_verify_preflight()
}

fn verify_entry(
    entry: &ArchiveEntry,
    config: &SecurityConfig<Validated>,
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

    // Path validation — result cached to avoid repeated syscalls for
    // symlink/hardlink checks
    let path_result = validate_path(&entry.path, dest, config);
    if let Err(ref e) = path_result {
        issues.push(VerificationIssue::from_error(e, Some(entry.path.clone())));
    }

    // Quota validation using reserve (combines all checks)
    if let Err(e) = quota_tracker.reserve(entry.size, config) {
        issues.push(VerificationIssue::from_error(&e, Some(entry.path.clone())));
    }

    // Compression ratio validation (zip bomb detection)
    if let Some(compressed_size) = entry.compressed_size
        && let Err(e) = validate_compression_ratio(compressed_size, entry.size, config)
    {
        issues.push(VerificationIssue::from_error(&e, Some(entry.path.clone())));
    }

    // Symlink validation
    if let EntryType::Symlink { ref target } = entry_type
        && let Ok(ref safe_link_path) = path_result
        && let Err(e) = validate_symlink(safe_link_path, target, dest, config)
    {
        issues.push(VerificationIssue::from_error(&e, Some(entry.path.clone())));
    }

    // Hardlink validation (similar to symlink)
    if let EntryType::Hardlink { ref target } = entry_type
        && let Ok(ref safe_link_path) = path_result
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
        && let Err(e) = check_permissions(&entry.path, mode, config)
    {
        issues.push(VerificationIssue::from_error(&e, Some(entry.path.clone())));
    }

    issues
}

fn check_permissions(path: &Path, mode: u32, config: &SecurityConfig<Validated>) -> Result<()> {
    let sanitized = sanitize_permissions(mode, config);
    if sanitized == mode {
        Ok(())
    } else {
        Err(ArchiveError::InvalidPermissions {
            path: path.to_path_buf(),
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

    // Non-UTF8 name detection: TAR entry names are stored byte-exact, so a
    // name that isn't valid UTF-8 is a portability risk — it extracts fine
    // on filesystems that accept arbitrary byte-string names (e.g. Linux
    // ext4/xfs/btrfs) but can fail on ones that require valid UTF-8 (e.g.
    // APFS, NTFS). This check is host-agnostic by design: `verify` is also
    // used to vet archives before shipping them to a different host, so the
    // warning must not depend on which filesystem happens to be running it.
    if entry.path.to_str().is_none() {
        issues.push(VerificationIssue {
            severity: IssueSeverity::Medium,
            category: IssueCategory::SuspiciousPath,
            entry_path: Some(entry.path.clone()),
            message: format!(
                "Entry name is not valid UTF-8; extraction may fail on filesystems that require \
                 UTF-8 names (e.g. APFS, NTFS): {}",
                entry.path.display()
            ),
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
    use crate::test_utils::tar_with_pax_nul_path;
    use std::assert_matches;
    use std::io::Write;
    use std::path::PathBuf;
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

    #[cfg(unix)]
    #[test]
    fn test_check_heuristics_non_utf8_name() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let entry = crate::inspection::manifest::ArchiveEntry {
            path: PathBuf::from(OsStr::from_bytes(b"weird-\xFF\xFE-name.txt")),
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
        assert!(issues.iter().any(|i| {
            i.category == IssueCategory::SuspiciousPath && i.severity == IssueSeverity::Medium
        }));
    }

    // False-positive guard for #528: a plain, valid-UTF8, non-suspicious
    // entry name must not trigger the new non-UTF8-name heuristic.
    #[test]
    fn test_check_heuristics_valid_utf8_name_no_warning() {
        let entry = crate::inspection::manifest::ArchiveEntry {
            path: PathBuf::from("safe/file.txt"),
            entry_type: ManifestEntryType::File,
            size: 100,
            compressed_size: None,
            mode: Some(0o644),
            modified: None,
            symlink_target: None,
            hardlink_target: None,
        };

        let issues = check_heuristics(&entry);
        assert!(
            issues.is_empty(),
            "valid UTF-8 name must not trigger any heuristic issue, got: {issues:?}"
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

    // Regression test: verify_archive() must report an oversized entry as a
    // graceful VerificationIssue (Fail status with an itemized report), not
    // abort with a bare error during its internal pre-flight list_archive()
    // call. Before listing_config_for_verify() existed, list_archive()
    // enforcing max_file_size (#396) made this scenario an Err with no
    // report, bypassing verify_entry's existing FileSize handling.
    #[test]
    fn test_verify_archive_oversized_entry_reports_issue_not_error() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let data = vec![0u8; 1000];
        let mut header = tar::Header::new_gnu();
        header.set_path("big.bin").unwrap();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, &data[..]).unwrap();

        let archive_data = builder.into_inner().unwrap();
        temp_file.write_all(&archive_data).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default().with_max_file_size(500);
        let report = verify_archive(temp_file.path(), &config)
            .expect("verify_archive must report oversized entries, not error out");

        assert_eq!(
            report.status,
            VerificationStatus::Fail,
            "oversized entry must fail verification via a report, not a hard error"
        );
        assert_eq!(report.suspicious_entries, 1);
        assert!(
            report.issues.iter().any(|i| {
                i.severity == IssueSeverity::High
                    && i.category == IssueCategory::QuotaExceeded
                    && i.message.contains("single file size")
            }),
            "expected a High-severity QuotaExceeded FileSize issue, got: {:?}",
            report.issues
        );
    }

    #[test]
    fn test_listing_config_for_verify_relaxes_max_file_size_and_preflight_checks() {
        let config = SecurityConfig::default()
            .with_max_file_size(1000)
            .with_max_total_size(2000)
            .with_max_file_count(3);
        let listing_config = listing_config_for_verify(&config);

        assert_eq!(listing_config.max_file_size, u64::MAX);
        assert_eq!(listing_config.max_total_size, config.max_total_size);
        assert_eq!(listing_config.max_file_count, config.max_file_count);
        assert!(
            listing_config.relaxed_for_verify_preflight,
            "verify's pre-flight listing pass must set relaxed_for_verify_preflight so \
             NUL-byte paths and empty/NUL/missing link targets defer to verify_entry's own \
             graceful checks instead of aborting list_archive"
        );
    }

    // Regression test for #430 follow-up (round 3): a NUL-byte entry path
    // must surface as a graceful VerificationIssue, not abort verify_archive
    // with a hard `Err`, matching verify's behavior before the list-level
    // NUL-byte check (this PR) existed. An earlier version of this test
    // pinned the opposite (hard-error) behavior, which a code-review pass
    // identified as a real regression: verify_entry's own validate_path
    // call (line ~156) already had a working graceful NUL-byte check via
    // SafePath::validate, and the list-level check was aborting before that
    // mechanism ever ran. `listing_config_for_verify` now also relaxes the
    // list-level NUL-byte check (see
    // `SecurityConfig::relaxed_for_verify_preflight`), restoring the original
    // graceful-report behavior — this test was rewritten (not just renamed) to
    // assert that restored behavior instead of the hard-error behavior it
    // previously pinned.
    #[test]
    fn test_verify_archive_nul_byte_path_reports_issue_not_error() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        temp_file
            .write_all(&tar_with_pax_nul_path(b"foo\0bar.txt", b"hello"))
            .unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let report = verify_archive(temp_file.path(), &config)
            .expect("verify_archive must report a NUL-byte entry path, not error out");

        assert_eq!(
            report.status,
            VerificationStatus::Fail,
            "NUL-byte entry path must fail verification via a report, not a hard error"
        );
        assert_eq!(report.suspicious_entries, 1);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.message.contains("null bytes")),
            "expected an issue mentioning null bytes, got: {:?}",
            report.issues
        );
    }

    // Regression test for #528: a TAR entry name that is not valid UTF-8 is
    // stored byte-exact in the manifest and may fail to extract on this
    // filesystem, but previously nothing in the verification pipeline
    // checked for it, so `verify` reported `Pass` for an archive that
    // `extract` would later fail on.
    //
    // Unix-only: the `tar` crate's `bytes2path` requires valid UTF-8 on
    // non-Unix targets (see `tar::header::bytes2path`), so on Windows
    // `entry.path()` itself errors out during listing and `verify_archive`
    // returns `Err` before ever reaching `check_heuristics` — a different,
    // pre-existing cross-platform divergence outside this fix's scope.
    #[cfg(unix)]
    #[test]
    fn test_verify_archive_non_utf8_name_reports_warning_not_pass() {
        use crate::test_utils::tar_with_nonutf8_name;

        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        temp_file
            .write_all(&tar_with_nonutf8_name(b"weird-\xFF\xFE-name.txt", b"hello"))
            .unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let report = verify_archive(temp_file.path(), &config)
            .expect("verify_archive must report a non-UTF8 entry name, not error out");

        assert_eq!(
            report.status,
            VerificationStatus::Warning,
            "non-UTF8 entry name must surface as a Warning, not silently Pass"
        );
        assert_eq!(
            report.suspicious_entries, 1,
            "a Medium+ heuristic issue must be reflected in suspicious_entries, \
             or the report is self-contradictory (Warning with 0 suspicious entries)"
        );
        assert!(
            report.issues.iter().any(|i| {
                i.category == IssueCategory::SuspiciousPath && i.message.contains("not valid UTF-8")
            }),
            "expected a SuspiciousPath issue mentioning UTF-8, got: {:?}",
            report.issues
        );
    }

    // Regression test for #430 follow-up (round 3, item 2): a hardlink entry
    // with no link target at all must still surface as a graceful
    // VerificationIssue from verify_archive, not the InvalidArchive hard
    // error that bare `list_archive` now raises (see
    // `test_list_tar_hardlink_missing_target_rejected` in
    // `inspection::list::tests`). `relaxed_for_verify_preflight` lets the
    // missing target through the pre-flight listing pass as `None`;
    // `verify_entry` then treats it as an empty target via
    // `unwrap_or_default()`, which `validate_path` rejects with its own
    // pre-existing "empty path not allowed" check.
    #[test]
    fn test_verify_archive_hardlink_missing_target_reports_issue_not_error() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_path("link").unwrap();
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Link);
        header.set_cksum();
        builder.append(&header, &[][..]).unwrap();

        let archive_data = builder.into_inner().unwrap();
        temp_file.write_all(&archive_data).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let report = verify_archive(temp_file.path(), &config)
            .expect("verify_archive must report a missing hardlink target, not error out");

        assert_eq!(
            report.status,
            VerificationStatus::Fail,
            "missing hardlink target must fail verification via a report, not a hard error"
        );
        assert_eq!(report.suspicious_entries, 1);
        assert!(
            report.issues.iter().any(|i| {
                i.category == IssueCategory::HardlinkEscape
                    && i.context
                        .as_deref()
                        .is_some_and(|c| c.contains("empty path not allowed"))
            }),
            "expected a HardlinkEscape issue citing the empty target, got: {:?}",
            report.issues
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
        assert_eq!(
            report.suspicious_entries, 0,
            "Info/Low-severity heuristic issues (executable, suspicious extension) must not \
             count toward suspicious_entries — only Medium+ issues do"
        );
    }

    #[test]
    fn verify_archive_rejects_invalid_security_config() {
        let config = SecurityConfig::default().with_max_path_depth(0);
        let result = crate::verify_archive("any.tar.gz", &config);
        assert_matches!(
            result,
            Err(crate::ArchiveError::InvalidConfiguration { .. }),
            "verify_archive must return InvalidConfiguration for zero max_path_depth"
        );
    }
}
